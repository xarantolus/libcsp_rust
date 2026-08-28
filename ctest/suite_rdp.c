#include <check.h>
#include <string.h>
#include <endian.h>

#include "clock.h"
#include "trace.h"

#include "csp/csp.h"
#include "csp/csp_id.h"
#include "csp/csp_iflist.h"
#include "csp/csp_interface.h"
#include "csp/csp_buffer.h"

#include "csp/autoconfig.h"

#if (CSP_USE_RDP)

#include "csp_conn.h"
#include "csp_rdp.h"
#include "csp_rdp_queue.h"

#define RDP_SYN 0x08
#define RDP_ACK 0x04
#define RDP_RST 0x01
#define RDP_EAK 0x02

/* rand_r() seeded with 1234567, truncated to 16 bits. Recorded, not derived: the
   point of the test is that the C produces a fixed number, so deriving it here would
   assert our arithmetic against itself. */
#define RDP_ISS_AT_1234567_MS 17867

#define TEST_ADDR 10
#define PEER_ADDR 11
#define TEST_PORT 12

typedef struct __attribute__((packed)) {
	uint8_t flags;
	uint16_t seq_nr;
	uint16_t ack_nr;
} test_rdp_header_t;

static unsigned int test_tx_count;
/* The RDP trailer of the last frame that left, which is the only place the handshake is
   observable: the state machine's own fields are how it is computed, not what a peer sees. */
static uint8_t tx_flags;
static uint16_t tx_seq;
static uint16_t tx_ack;
static uint16_t tx_payload_len;
/* Frames carrying RDP_RST, and when the first left and the last frame of any kind left, on
   the test clock. A count of frames cannot say whether the C reset the peer, or when it
   stopped talking. */
static unsigned int tx_rst_count;
static uint32_t tx_first_rst_ms;
static uint32_t tx_last_ms;

static int test_nexthop(csp_iface_t * iface, uint16_t via, csp_packet_t * packet, int from_me) {
	(void)iface; (void)via; (void)from_me;
	test_tx_count++;
	tx_last_ms = csp_get_ms();
	if (packet->length >= sizeof(test_rdp_header_t)) {
		tx_payload_len = (uint16_t)(packet->length - sizeof(test_rdp_header_t));
		const test_rdp_header_t * h =
			(const test_rdp_header_t *)&packet->data[tx_payload_len];
		tx_flags = h->flags;
		tx_seq = be16toh(h->seq_nr);
		tx_ack = be16toh(h->ack_nr);
		if (h->flags & 0x01) {
			if (tx_rst_count == 0) { tx_first_rst_ms = csp_get_ms(); }
			tx_rst_count++;
		}
	}
	csp_buffer_free(packet);
	return CSP_ERR_NONE;
}

static csp_iface_t test_if = {
	.addr = TEST_ADDR,
	.netmask = 14,
	.name = "test",
	.nexthop = test_nexthop,
	.is_default = 1,
};

static csp_socket_t test_sock;

static void setup_stack(void) {
	csp_init();
	csp_iflist_add(&test_if);
	memset(&test_sock, 0, sizeof(test_sock));
	csp_bind(&test_sock, TEST_PORT);
	csp_listen(&test_sock, 4);
	test_tx_count = 0;
	tx_flags = 0;
	tx_seq = 0;
	tx_ack = 0;
	tx_payload_len = 0;
	tx_rst_count = 0;
	tx_first_rst_ms = 0;
	tx_last_ms = 0;
}

static csp_packet_t * new_rdp_packet(void) {
	csp_packet_t * packet = csp_buffer_get(0);
	ck_assert_ptr_nonnull(packet);

	packet->id.pri = 2;
	packet->id.src = PEER_ADDR;
	packet->id.dst = TEST_ADDR;
	packet->id.dport = TEST_PORT;
	packet->id.sport = 40;
	packet->id.flags = CSP_FRDP;
	packet->length = 0;

	return packet;
}

static void put_header_and_route(csp_packet_t * packet, uint8_t flags, uint16_t seq, uint16_t ack) {
	test_rdp_header_t * header = (test_rdp_header_t *)&packet->data[packet->length];
	header->flags = flags;
	header->seq_nr = htobe16(seq);
	header->ack_nr = htobe16(ack);
	packet->length += sizeof(*header);

	csp_qfifo_write(packet, &test_if, NULL);
	csp_route_work();
}

/* Deliver a SYN carrying `words` option words; 6 is a complete block. */
static void send_syn_words(const uint32_t * opts, unsigned int words) {
	csp_packet_t * packet = new_rdp_packet();

	for (unsigned int i = 0; i < words; i++) {
		packet->data32[i] = htobe32(opts[i]);
	}
	packet->length = words * sizeof(uint32_t);

	put_header_and_route(packet, RDP_SYN, 1000, 0);
}

static void send_syn(const uint32_t opts[6]) {
	send_syn_words(opts, opts ? 6 : 0);
}

static const csp_conn_t * find_rdp_conn(void) {
	size_t count;
	const csp_conn_t * conns = csp_conn_get_array(&count);

	for (size_t i = 0; i < count; i++) {
		if ((conns[i].state == CONN_OPEN) && (conns[i].idin.flags & CSP_FRDP)) {
			return &conns[i];
		}
	}
	return NULL;
}

/* The peer's half of the handshake, completing the connection. */
static void ack_handshake(uint16_t iss) {
	put_header_and_route(new_rdp_packet(), RDP_ACK, 1001, iss);
}

/* What a peer learns from sending a malformed SYN: how many frames came back, what the
   first one carried, and whether the node went on to accept traffic on that connection.
   The connection table is how the C decides; the frames and the delivery are what the peer
   can see, so they are what is compared. */
static void malformed_syn_record(const char * name, unsigned int frames, uint8_t flags,
								 int accepted_after)
{
	if (!ctest_tracing()) {
		return;
	}
	ctest_trace_begin("rdp", name, "must_match");
	ctest_trace_obj_begin("observed");
	ctest_trace_int("frames_out", (int64_t)frames);
	ctest_trace_int("reply_flags", (int64_t)flags);
	ctest_trace_int("accepted_after", (int64_t)accepted_after);
	ctest_trace_obj_end();
	ctest_trace_end();
}

/* Did the node hand the application a connection? A rejected SYN must leave nothing to
   accept, however the rejection was spelled. */
static int syn_was_accepted(void)
{
	csp_conn_t * c = csp_accept(&test_sock, 0);
	if (c == NULL) {
		return 0;
	}
	csp_close(c);
	return 1;
}

START_TEST(test_rdp_syn_without_options_is_rejected)
{
	setup_stack();

	/* No option block on the wire: nothing may be adopted from the buffer. */
	send_syn(NULL);

	ck_assert_ptr_null(find_rdp_conn());
	/* The sender is told, rather than left waiting. */
	ck_assert_uint_ge(test_tx_count, 1);
	malformed_syn_record("a_syn_without_options_is_rejected", test_tx_count, tx_flags,
						 syn_was_accepted());
}
END_TEST

START_TEST(test_rdp_syn_with_partial_options_is_rejected)
{
	setup_stack();

	/* One word short of a complete block still walks off the end. */
	const uint32_t opts[5] = { 4, 10000, 1000, 1, 250 };
	send_syn_words(opts, 5);

	ck_assert_ptr_null(find_rdp_conn());
	malformed_syn_record("a_syn_with_partial_options_is_rejected", test_tx_count, tx_flags,
						 syn_was_accepted());
}
END_TEST

/* The operational consequence of the two cases above: a peer that keeps sending malformed
   SYNs must not be able to use up the connection table. `csp_rdp.c` frees the connection
   when it rejects the option block, so the table is exactly as it was and an honest peer
   still gets in. A node that kept the slot would be closed for business after
   CSP_CONN_MAX bad packets -- from a peer that never completed a handshake. */
START_TEST(test_rdp_malformed_syns_do_not_exhaust_the_table)
{
	setup_stack();

	/* Comfortably more than the table holds. */
	for (int i = 0; i < CSP_CONN_MAX * 3; i++) {
		send_syn(NULL);
	}
	ck_assert_ptr_null(find_rdp_conn());

	/* Now an honest peer. */
	const uint32_t valid[6] = { 3, 20000, 500, 1, 250, 2 };
	send_syn(valid);

	const csp_conn_t * conn = find_rdp_conn();
	const int opened = (conn != NULL);
	const int syn_ack = ((tx_flags & (RDP_SYN | RDP_ACK)) == (RDP_SYN | RDP_ACK));
	ck_assert_int_eq(opened, 1);
	ck_assert_int_eq(syn_ack, 1);

	if (ctest_tracing()) {
		ctest_trace_begin("rdp", "malformed_syns_do_not_exhaust_the_table", "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("bad_syns", CSP_CONN_MAX * 3);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("honest_peer_opened", opened);
		ctest_trace_int("honest_peer_got_syn_ack", syn_ack);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

START_TEST(test_rdp_syn_options_are_bounded_above)
{
	setup_stack();

	const uint32_t hostile[6] = {
		0xFFFFFFFF, /* window size     */
		0xFFFFFFFF, /* conn timeout    */
		0,          /* packet timeout  */
		0xFFFFFFFF, /* delayed acks    */
		0xFFFFFFFF, /* ack timeout     */
		0xFFFFFFFF, /* ack delay count */
	};
	send_syn(hostile);

	const csp_conn_t * conn = find_rdp_conn();
	ck_assert_ptr_nonnull(conn);

	ck_assert_uint_le(conn->rdp.window_size, CSP_RDP_MAX_WINDOW);
	ck_assert_uint_le(conn->rdp.conn_timeout, CSP_RDP_MAX_CONN_TIMEOUT);
	ck_assert_uint_le(conn->rdp.packet_timeout, CSP_RDP_MAX_PACKET_TIMEOUT);
	ck_assert_uint_ge(conn->rdp.packet_timeout, CSP_RDP_MIN_PACKET_TIMEOUT);
	ck_assert_uint_le(conn->rdp.ack_delay_count, conn->rdp.window_size);
	ck_assert_uint_le(conn->rdp.ack_timeout, conn->rdp.conn_timeout);
}
END_TEST

START_TEST(test_rdp_syn_options_are_bounded_below)
{
	setup_stack();

	/* Zero is as damaging as a huge value: a zero window stalls the sequence
	   arithmetic, and a zero timeout means retransmit as fast as the router runs. */
	const uint32_t zeroes[6] = { 0, 0, 0, 0, 0, 0 };
	send_syn(zeroes);

	const csp_conn_t * conn = find_rdp_conn();
	ck_assert_ptr_nonnull(conn);

	ck_assert_uint_ge(conn->rdp.window_size, 1);
	ck_assert_uint_ge(conn->rdp.conn_timeout, CSP_RDP_MIN_CONN_TIMEOUT);
	ck_assert_uint_ge(conn->rdp.packet_timeout, CSP_RDP_MIN_PACKET_TIMEOUT);
	ck_assert_uint_ge(conn->rdp.ack_timeout, CSP_RDP_MIN_ACK_TIMEOUT);
	ck_assert_uint_ge(conn->rdp.ack_delay_count, 1);
}
END_TEST

START_TEST(test_rdp_syn_keeps_valid_options)
{
	setup_stack();

	const uint32_t valid[6] = { 3, 20000, 500, 1, 250, 2 };
	send_syn(valid);

	const csp_conn_t * conn = find_rdp_conn();
	ck_assert_ptr_nonnull(conn);

	ck_assert_uint_eq(conn->rdp.window_size, 3);
	ck_assert_uint_eq(conn->rdp.conn_timeout, 20000);
	ck_assert_uint_eq(conn->rdp.packet_timeout, 500);
	ck_assert_uint_eq(conn->rdp.delayed_acks, 1);
	ck_assert_uint_eq(conn->rdp.ack_timeout, 250);
	ck_assert_uint_eq(conn->rdp.ack_delay_count, 2);
}
END_TEST

/* The initial send sequence number is rand_r() over a seed that csp_rdp.c re-reads
   from csp_get_ms() on every SYN, so it is a pure function of the clock rather than
   being random at all. Two consequences, and this test pins both:

   - for the oracle, every recorded exchange is reproducible;
   - for a flight node, an attacker who can estimate the peer's uptime to the
     millisecond can guess the sequence number a connection will open with. */
START_TEST(test_rdp_isn_is_a_function_of_the_clock)
{
	ctest_clock_set(1234567);
	setup_stack();

	const uint32_t opts[6] = { 3, 20000, 500, 1, 250, 2 };
	send_syn(opts);

	const csp_conn_t * conn = find_rdp_conn();
	ck_assert_ptr_nonnull(conn);
	ck_assert_uint_eq(conn->rdp.snd_iss, RDP_ISS_AT_1234567_MS);

	/* Recorded after the assertions, so a record only exists for a case the harness got
	   right.

	   The verdict was `c_only`, on the grounds that "the port takes the ISN as a parameter
	   rather than deriving it from a clock, so there is nothing here for it to match".
	   That stopped being true: `Router::initial_seq` derives it from `now_ms`, and the
	   only test of that was one the port wrote itself. It is `diverges` now -- both stacks
	   make the ISN a pure function of the clock and they compute different functions of it,
	   the C's being `rand_r` over a per-SYN seed and the port's a fixed mix, because a
	   sans-io core has no entropy source to do better with.

	   Only what a peer can see is recorded. `snd_nxt` and `snd_una` at this instant are
	   internal bookkeeping; the sequence number on the SYN is the ISN as the wire carries
	   it, and it is what the port can be compared on. The assertions above still check all
	   three inside the C. */
	ctest_trace_begin("rdp", "isn_is_a_function_of_the_clock", "diverges");
	ctest_trace_obj_begin("observed");
	ctest_trace_int("clock_ms", 1234567);
	ctest_trace_int("snd_iss", conn->rdp.snd_iss);
	ctest_trace_obj_end();
	ctest_trace_end();
}
END_TEST

/* Same clock, same number, whatever else the process has done first. */
START_TEST(test_rdp_isn_does_not_depend_on_history)
{
	ctest_clock_set(999);
	setup_stack();

	/* Burn a connection at a different clock value, then come back. */
	const uint32_t opts[6] = { 3, 20000, 500, 1, 250, 2 };
	send_syn(opts);
	ck_assert_ptr_nonnull(find_rdp_conn());
	csp_rdp_queue_flush(NULL);

	ctest_clock_set(1234567);
	csp_packet_t * packet = new_rdp_packet();
	packet->id.sport = 41; /* a different connection */
	for (unsigned int i = 0; i < 6; i++) {
		packet->data32[i] = htobe32(opts[i]);
	}
	packet->length = 6 * sizeof(uint32_t);
	put_header_and_route(packet, RDP_SYN, 1000, 0);

	const csp_conn_t * conn = NULL;
	size_t count;
	const csp_conn_t * conns = csp_conn_get_array(&count);
	for (size_t i = 0; i < count; i++) {
		if ((conns[i].state == CONN_OPEN) && (conns[i].idin.flags & CSP_FRDP) && (conns[i].idin.sport == 41)) {
			conn = &conns[i];
		}
	}
	ck_assert_ptr_nonnull(conn);
	ck_assert_uint_eq(conn->rdp.snd_iss, RDP_ISS_AT_1234567_MS);
}
END_TEST

START_TEST(test_rdp_delayed_acks_is_a_flag)
{
	setup_stack();

	/* Any non-zero value means "on"; it is not a count. */
	const uint32_t opts[6] = { 3, 20000, 500, 2, 250, 2 };
	send_syn(opts);

	const csp_conn_t * conn = find_rdp_conn();
	ck_assert_ptr_nonnull(conn);
	ck_assert_uint_eq(conn->rdp.delayed_acks, 1);

}
END_TEST

START_TEST(test_rdp_retransmits_are_limited)
{
	setup_stack();

	/* Longest connection lifetime and fastest retransmit the peer may ask for,
	   so the retransmit limit is what ends this, not the connection timeout. */
	const uint32_t opts[6] = { 4, CSP_RDP_MAX_CONN_TIMEOUT, 0, 1, 250, 2 };
	send_syn(opts);
	ck_assert_ptr_nonnull(find_rdp_conn());

	const unsigned int tx_after_syn = test_tx_count;
	/* What the original SYN/ACK carried, before any repeat. */
	const uint16_t first_seq = tx_seq;
	const uint16_t first_ack = tx_ack;

	/* The peer never acknowledges the SYN/ACK. Snapshotted at the first repeat: a repeat
	   carrying different sequence numbers is rejected by the peer and looks, from the
	   outside, exactly like no repeat at all -- so counting frames is not enough. */
	uint16_t repeat_seq = 0, repeat_ack = 0;
	uint8_t repeat_flags = 0;
	bool have_repeat = false;
	for (int i = 0; (i < 1000) && (find_rdp_conn() != NULL); i++) {
		csp_conn_check_timeouts();
		if (!have_repeat && test_tx_count > tx_after_syn) {
			repeat_seq = tx_seq;
			repeat_ack = tx_ack;
			repeat_flags = tx_flags;
			have_repeat = true;
		}
		ctest_clock_advance(20);
	}

	ck_assert_ptr_null(find_rdp_conn());

	/* Retransmissions of the SYN/ACK, plus the RST that closes it. Bounded on
	   both sides: giving up immediately is as wrong as never giving up. */
	const unsigned int sent = test_tx_count - tx_after_syn;
	ck_assert_uint_ge(sent, CSP_RDP_MAX_RETRANSMITS);
	ck_assert_uint_le(sent, CSP_RDP_MAX_RETRANSMITS + 2);

	if (ctest_tracing()) {
		/* Four assertions here and no record until now, so the port was never compared on
		   retransmission at all. A `SYN|ACK` that is lost and never repeated leaves the
		   peer waiting for a connection this node believes it opened; the frames below are
		   the only thing that tells it otherwise. */
		ctest_trace_begin("rdp", "an_unacknowledged_syn_ack_is_retransmitted_then_reset",
						  "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("max_retransmits", CSP_RDP_MAX_RETRANSMITS);
		ctest_trace_int("tick_ms", 20);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		/* At least one repeat, so the node did not simply give up. */
		ctest_trace_int("more_than_one_frame", sent > 1 ? 1 : 0);
		ctest_trace_int("at_least_max_retransmits", sent >= CSP_RDP_MAX_RETRANSMITS ? 1 : 0);
		/* And it stops: a node that retransmitted forever would never reach here. */
		ctest_trace_int("connection_gone", find_rdp_conn() == NULL ? 1 : 0);
		/* The repeat is the same frame: same flags, same sequence, same acknowledgement. */
		ctest_trace_int("repeat_is_syn_ack", repeat_flags == (RDP_SYN | RDP_ACK) ? 1 : 0);
		ctest_trace_int("repeat_seq_matches_first", repeat_seq == first_seq ? 1 : 0);
		ctest_trace_int("repeat_ack_matches_first", repeat_ack == first_ack ? 1 : 0);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

START_TEST(test_rdp_retransmit_count_resets_on_ack)
{
	setup_stack();

	/* Half-open, so the SYN/ACK stays queued and is retransmitted. */
	const uint32_t opts[6] = { 4, CSP_RDP_MAX_CONN_TIMEOUT, 0, 1, 250, 2 };
	send_syn(opts);
	ck_assert_ptr_nonnull(find_rdp_conn());

	/* Accumulate failed attempts, staying well under the limit. */
	const uint32_t target = 3;
	for (int i = 0; (i < 1000) && (find_rdp_conn() != NULL) &&
	                (find_rdp_conn()->rdp.retransmits < target); i++) {
		csp_conn_check_timeouts();
		ctest_clock_advance(20);
	}
	ck_assert_ptr_nonnull(find_rdp_conn());
	ck_assert_uint_ge(find_rdp_conn()->rdp.retransmits, target);

	/* The peer answers. Attempts already spent must not count against it. */
	ack_handshake(find_rdp_conn()->rdp.snd_iss);

	const csp_conn_t * conn = find_rdp_conn();
	ck_assert_ptr_nonnull(conn);
	ck_assert_int_eq(conn->rdp.state, RDP_OPEN);
	ck_assert_uint_eq(conn->rdp.retransmits, 0);
}
END_TEST

START_TEST(test_rdp_queue_flush_all_releases_buffers)
{
	setup_stack();

	const int free_before = csp_buffer_remaining();

	/* A half-open connection leaves its SYN/ACK on the RDP transmit queue. */
	const uint32_t opts[6] = { 4, 10000, 1000, 1, 250, 2 };
	send_syn(opts);
	ck_assert_ptr_nonnull(find_rdp_conn());
	ck_assert_int_lt(csp_buffer_remaining(), free_before);

	csp_rdp_queue_flush(NULL);

	ck_assert_int_eq(csp_buffer_remaining(), free_before);
}
END_TEST

START_TEST(test_rdp_queue_flush_all_releases_receive_buffers)
{
	setup_stack();

	const int free_before = csp_buffer_remaining();

	const uint32_t opts[6] = { 4, 10000, 1000, 1, 250, 2 };
	send_syn(opts);
	const csp_conn_t * conn = find_rdp_conn();
	ck_assert_ptr_nonnull(conn);
	const uint16_t iss = conn->rdp.snd_iss;
	ack_handshake(iss);

	/* Data ahead of the next expected sequence number is held on the RDP
	   receive queue until the gap is filled. */
	csp_packet_t * packet = new_rdp_packet();
	memcpy(packet->data, "payload", 7);
	packet->length = 7;
	put_header_and_route(packet, RDP_ACK, 1005, iss);
	ck_assert_int_lt(csp_buffer_remaining(), free_before);

	csp_rdp_queue_flush(NULL);

	ck_assert_int_eq(csp_buffer_remaining(), free_before);
}
END_TEST

/* A SYN arriving at a listening node is answered with SYN|ACK, on the wire.
 *
 * The whole suite drives the handshake -- every ack-policy case calls `open_conn` -- but
 * none of them ever looked at the frame it produces, only at `conn->rdp.state`. So the one
 * thing a peer can actually see about the handshake, the reply and its sequence numbers,
 * was measured nowhere.
 *
 * `csp_rdp_connect`/`csp_rdp_new_packet` answer a SYN with SYN|ACK carrying the node's own
 * initial send sequence number and acknowledging the peer's. The ISN is `rand_r` seeded
 * from `csp_get_ms()`, which the virtual clock pins, so it is reproducible.
 */
START_TEST(test_a_syn_is_answered_with_syn_ack)
{
	setup_stack();
	const uint32_t opts[6] = { 4, 20000, 1000, 0, 250, 2 };

	const unsigned int before = test_tx_count;
	send_syn(opts);

	/* Exactly one frame, and it is the SYN|ACK. */
	ck_assert_uint_eq(test_tx_count - before, 1);
	ck_assert_uint_eq(tx_flags, RDP_SYN | RDP_ACK);
	/* Acknowledges the peer's SYN, which carried seq 1000. */
	ck_assert_uint_eq(tx_ack, 1000);

	const csp_conn_t * conn = find_rdp_conn();
	ck_assert_ptr_nonnull(conn);
	/* The reply carries this node's own ISN. */
	ck_assert_uint_eq(tx_seq, conn->rdp.snd_iss);

	if (ctest_tracing()) {
		ctest_trace_begin("rdp", "a_syn_is_answered_with_syn_ack", "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("syn_seq", 1000);
		ctest_trace_int("clock_ms", CTEST_CLOCK_EPOCH_MS);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("frames", (int64_t)(test_tx_count - before));
		ctest_trace_int("flags", tx_flags);
		/* Not the raw sequence number: the C's ISN is rand_r() over the clock and the
		   port derives its own differently on purpose (see SCOPE). What both must agree
		   on is that the reply carries *this node's own* ISN rather than, say, echoing
		   the peer's -- which is the part a peer depends on. */
		ctest_trace_int("seq_is_own_iss", tx_seq == conn->rdp.snd_iss ? 1 : 0);
		ctest_trace_int("ack", tx_ack);
		/* Measured 0: the SYN|ACK carries the trailer only. The option block travels
		   in the SYN alone -- the answer echoes none of it back, so a peer learns the
		   accepted (clamped) options only by having its own clamped the same way. */
		ctest_trace_int("payload_len", tx_payload_len);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

/* The third leg: the peer's ACK completes the handshake and provokes no further frame.
 * A node that answered it would have both ends replying to each other forever. */
START_TEST(test_the_handshakes_final_ack_is_not_itself_answered)
{
	setup_stack();
	const uint32_t opts[6] = { 4, 20000, 1000, 0, 250, 2 };
	send_syn(opts);
	const csp_conn_t * conn = find_rdp_conn();
	ck_assert_ptr_nonnull(conn);

	const unsigned int before = test_tx_count;
	ack_handshake(conn->rdp.snd_iss);

	ck_assert_uint_eq(conn->rdp.state, RDP_OPEN);

	if (ctest_tracing()) {
		ctest_trace_begin("rdp", "the_handshakes_final_ack_is_not_itself_answered",
						  "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("syn_seq", 1000);
		ctest_trace_int("clock_ms", CTEST_CLOCK_EPOCH_MS);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("frames_after_final_ack", (int64_t)(test_tx_count - before));
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

/* --- the acknowledgement policy ---
 *
 * `csp_rdp_should_ack` has three conditions and `csp_rdp_check_ack` gates all of them
 * behind a fourth. All four are only observable as *whether an ACK reaches the wire*, which
 * is what these count -- the internal sequence numbers are not the behaviour, they are how
 * the behaviour is computed.
 *
 * Three things here were predicted from reading `csp_rdp.c` and are settled by measuring:
 * whether the C acknowledges when there is nothing to acknowledge, whether the delay count
 * fires at N or N+1 outstanding, and whether a full receive queue suppresses the ack.
 */

/* Open a connection with the given delayed-ack options and return it. */
static const csp_conn_t * open_conn(uint32_t delayed_acks, uint32_t ack_delay_count) {
	const uint32_t opts[6] = { 4, 20000, 1000, delayed_acks, 250, ack_delay_count };
	send_syn(opts);
	const csp_conn_t * conn = find_rdp_conn();
	ck_assert_ptr_nonnull(conn);
	ack_handshake(conn->rdp.snd_iss);
	ck_assert_int_eq(conn->rdp.state, RDP_OPEN);
	return conn;
}

/* Deliver one in-order data packet. `seq` continues from the handshake's 1000.
   The RDP header is a *trailer* in libcsp: put_header_and_route writes it at
   `data[length]`, so the payload goes in first and the header lands after it. */
static void deliver_data(uint16_t seq, uint16_t ack_nr) {
	csp_packet_t * packet = new_rdp_packet();
	packet->data[0] = 'x';
	packet->length = 1;
	put_header_and_route(packet, RDP_ACK, seq, ack_nr);
}

/* With delayed acks off, every packet is acknowledged as it arrives. */
START_TEST(test_without_delayed_acks_every_packet_is_acknowledged)
{
	setup_stack();
	const csp_conn_t * conn = open_conn(0, 2);

	const uint16_t iss = conn->rdp.snd_iss;
	unsigned int before = test_tx_count;
	/* The sequence each acknowledgement names, not just how many there were. An ack that
	   never advances is still an ack: the peer would retransmit everything after the first
	   packet, and a count alone cannot tell that apart from a healthy connection. */
	uint16_t acked[3] = { 0, 0, 0 };
	for (uint16_t i = 1; i <= 3; i++) {
		deliver_data((uint16_t)(1000 + i), iss);
		acked[i - 1] = tx_ack;
	}
	const unsigned int acks = test_tx_count - before;

	ck_assert_uint_eq(acks, 3);
	ck_assert_uint_eq(acked[0], 1001);
	ck_assert_uint_eq(acked[1], 1002);
	ck_assert_uint_eq(acked[2], 1003);

	if (ctest_tracing()) {
		ctest_trace_begin("rdp", "without_delayed_acks_every_packet_is_acknowledged", "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("delayed_acks", 0);
		ctest_trace_int("ack_delay_count", 2);
		ctest_trace_int("packets", 3);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("acks", (int64_t)acks);
		ctest_trace_arr_begin("acked");
		for (int k = 0; k < 3; k++) {
			ctest_trace_int(NULL, (int64_t)acked[k]);
		}
		ctest_trace_arr_end();
		ctest_trace_obj_end();
		ctest_trace_end();
	}
	(void)conn;
}
END_TEST

/* The delay count. `csp_rdp_should_ack` tests
 *
 *     csp_rdp_seq_after(rcv_cur, rcv_lsa + ack_delay_count)
 *
 * which is *strictly* after, so the ack fires once the outstanding count exceeds the
 * delay -- at count + 1, not at count. Measured rather than argued, because an
 * implementation using `>=` is off by exactly one packet and nothing else looks wrong. */
/* `csp_rdp.c:576` clamps the peer's proposed `ack_delay_count` to `conn->rdp.window_size`
   -- the window *it just negotiated*, not a compile-time maximum. Every other cadence test
   opens with `window_size = 4` and an `ack_delay_count` below it, so the clamp never fires
   and the relationship between the two is never exercised.

   Here a peer proposes a two-packet window and a delay count of 250. If the count is bound
   by the negotiated window it becomes 2 and acknowledgements resume at the window rate; if
   it were bound by anything larger the sender would wait far longer for one, on a window
   that only allows two packets in flight -- a stall a peer would see as a dead link. The
   cadence is the observable, and it is the only place the negotiated window shows up on
   the wire at all. */
/* `delayed_acks` is a flag, not a count: `csp_rdp.c` normalises any non-zero proposal to 1.
   `test_rdp_delayed_acks_is_a_flag` checks the field, which is how the C spells it; this
   checks what a peer sees. A receiver that read the value as a *count* would acknowledge on
   a different schedule, and the field assertion alone cannot tell the two apart. Proposed
   as 2 with a delay count of 2, so the cadence must match
   `the_delay_count_fires_one_packet_after_it`, which proposes 1. */
/* `ack_timeout` is the other half of delayed acknowledgement: when the delay *count* has
   not been reached, the acknowledgement still goes out once this much time has passed
   (`csp_rdp.c` checks it from `csp_rdp_check_timeouts`). Every existing record fixes it at
   the C helper's 250 ms, so whether the value a peer *proposes* is adopted was never
   measured -- a receiver that ignored it and kept its own default would acknowledge on a
   completely different schedule, and on a link with a long round trip that is the
   difference between a working transfer and a sender that keeps retransmitting.

   Proposed as 5000 against a default of 250, with one packet delivered so the delay count
   cannot be what fires. What is recorded is how long the peer waits. */
/* The last option a peer proposes that nothing measured: `conn_timeout`.
 *
 * It does **not** reap an established connection, which is what this test was written to
 * show and what the measurement contradicted. `csp_rdp_check_timeouts`'s CONNECTION TIMEOUT
 * branch is guarded by `conn->dest_socket != NULL`, and `dest_socket` is cleared the moment
 * the connection is *announced* to the socket -- `csp_rdp.c:695`, "remember that the
 * connection handle has been passed to userspace" -- not when the application accepts it.
 * So the branch only covers the window before announcement. Once the handshake completes,
 * `conn_timeout` no longer closes anything on this path; it survives as the CLOSE-WAIT
 * bound and as the upper bound on `ack_timeout`.
 *
 * Proposed as 3000 ms and then idled for 4000: libcsp keeps the connection and still
 * answers. A receiver that reaped it would drop a link that is merely quiet -- a telemetry
 * connection between passes -- and the peer would find its next packet unanswered. */
/* Teardown, which nothing measured: thirty tests in this suite and not one sends a RST.
 *
 * `csp_rdp.c` honours a reset only when it is *in sequence* -- `rx_header->seq_nr ==
 * conn->rdp.rcv_cur + 1`. Then it moves to CLOSE_WAIT and answers `ACK|RST`. An RST with any
 * other sequence number hits "RST out of sequence, keep connection open" and the connection
 * survives.
 *
 * That second half is a blind-reset defence: an attacker who can inject packets but cannot
 * guess the sequence number must not be able to drop a link with one spoofed frame. What is
 * recorded is what the peer sees -- the reply, and whether the connection still answers. */
/* `reply_flags` is only meaningful when a frame actually went out -- `tx_flags` holds the
   last frame sent *ever*, so reading it after a silent case reports the handshake's
   SYN|ACK. And the follow-up is recorded as flags, not as a bool: "something came back"
   cannot tell an ACK on a live connection from a RST on a dead one, which is the whole
   difference here. The top nibble is `csp_rdp_incr++ << 4`, which the receiver masks off,
   so it is masked here too. */
static void rst_record(const char * name, int in_sequence, unsigned int frames,
					   uint8_t reply_flags, uint8_t followup_flags) {
	if (!ctest_tracing()) {
		return;
	}
	ctest_trace_begin("rdp", name, "must_match");
	ctest_trace_obj_begin("input");
	ctest_trace_int("rst_in_sequence", in_sequence);
	ctest_trace_obj_end();
	ctest_trace_obj_begin("observed");
	ctest_trace_int("frames_after_rst", (int64_t)frames);
	ctest_trace_int("reply_flags", (int64_t)(frames ? (reply_flags & 0x0F) : 0));
	ctest_trace_int("followup_flags", (int64_t)(followup_flags & 0x0F));
	ctest_trace_obj_end();
	ctest_trace_end();
}

/* EAK -- the one RDP flag neither side had a test for. `csp-core` defines the constant and
   never reads it; libcsp acts on it twice.
 *
 * On receipt (`csp_rdp.c:712`) an EAK is treated as acknowledgement only: `snd_una` moves,
 * the retransmit counter resets, and then `goto discard_open` throws the packet away
 * *including any payload it carried*. A receiver that ignored the flag would hand that
 * payload to the application instead -- data the sender never meant as data.
 *
 * What is recorded is what the application got, and how many bytes. */
static void eak_record_verdict(const char * name, const char * verdict,
							   unsigned int delivered, unsigned int bytes,
							   uint8_t reply_flags, unsigned int frames) {
	if (!ctest_tracing()) {
		return;
	}
	ctest_trace_begin("rdp", name, verdict);
	ctest_trace_obj_begin("observed");
	ctest_trace_int("delivered", (int64_t)delivered);
	ctest_trace_int("delivered_bytes", (int64_t)bytes);
	ctest_trace_int("frames_back", (int64_t)frames);
	ctest_trace_int("reply_flags", (int64_t)(frames ? (reply_flags & 0x0F) : 0));
	ctest_trace_obj_end();
	ctest_trace_end();
}

static void eak_record(const char * name, unsigned int delivered, unsigned int bytes,
					   uint8_t reply_flags, unsigned int frames) {
	eak_record_verdict(name, "must_match", delivered, bytes, reply_flags, frames);
}

/* How much the application can collect from the accepted connection. */
static void drain_accepted(unsigned int * count, unsigned int * bytes) {
	*count = 0;
	*bytes = 0;
	csp_conn_t * accepted = csp_accept(&test_sock, 0);
	if (accepted == NULL) {
		return;
	}
	csp_packet_t * p;
	while ((p = csp_read(accepted, 0)) != NULL) {
		*bytes += p->length;
		(*count)++;
		csp_buffer_free(p);
	}
}

/* Reordering: does a gap-filling packet bring the one that overtook it with it?
 *
 * `csp_rdp.c:723` stores an out-of-sequence packet with `csp_rdp_rx_queue_add` and, once the
 * hole is filled, walks the queue delivering what it can. `csp-core::rdp::RxQueue` exists
 * with reorder tests -- including the sequence wrap -- and nothing calls it, so the port
 * drops the overtaking packet and the sender pays a round trip for it (SCOPE.md).
 *
 * `B` is sent first at rcv_cur+2, then `A` at rcv_cur+1. What the application reads, in
 * order, is the answer: "AB" if the queue works, "A" alone if the second packet was lost. */
static void deliver_byte(uint16_t seq, uint16_t ack_nr, char byte) {
	csp_packet_t * packet = new_rdp_packet();
	packet->data[0] = (uint8_t)byte;
	packet->length = 1;
	put_header_and_route(packet, RDP_ACK, seq, ack_nr);
}

/* The send side: what a peer sees when it never acknowledges the data this node sent.
 *
 * `csp_rdp_check_timeouts` walks the connection's transmit queue, retransmits every packet
 * whose `timestamp_tx + packet_timeout` has passed, and counts **one attempt per sweep**
 * rather than per packet. Past `CSP_RDP_MAX_RETRANSMITS` it closes the connection.
 *
 * `diverges`, and the reason is the C rather than the port. Measured: the total scales with
 * `conn_timeout`, not with `CSP_RDP_MAX_RETRANSMITS` -- 29 frames at a 20 s connection
 * timeout, 10 at 5 s. So "No progress after 10 retransmissions, closing" does not stop the
 * retransmitting; `csp_conn_close` on an *accepted* handle leaves the connection for the
 * application to close, `csp_conn_check_timeouts` keeps sweeping it, and only the CLOSE-WAIT
 * timeout finally ends it. The port stops when it says it stops: 12 frames, one initial and
 * eleven attempts. SCOPE.md carries the arithmetic. */
/* One packet, one `packet_timeout`, one repeat -- the part of retransmission both stacks
   agree on, and the part the give-up arithmetic does not reach. The total-frame record next
   door is a `diverges`, which cannot catch a send path that stops holding what it sent:
   breaking it leaves the two disagreeing either way. This one can. */
/* Three packets in a row, then the peer acknowledges them.
 *
 * Two functional questions in one exchange, neither of which a single-packet test can ask:
 * do consecutive sends take consecutive sequence numbers, and does an acknowledgement
 * actually release what it covers? `csp_rdp_check_timeouts` frees a queued packet whose
 * sequence is before `snd_una`; if that never happens the sender retransmits data the peer
 * already has, for as long as the connection lives. */
/* The send window's boundary: a peer that proposes a window of two must get two packets.
 *
 * Measured before this was written: `csp_send` returns for both of them and then, on the
 * third, never returns at all. `csp_rdp_send` loops `while (1)` around
 * `csp_bin_sem_wait(&conn->rdp.tx_wait, conn->rdp.conn_timeout)`, and its only exits are the
 * window opening -- which needs an acknowledgement from the router task -- or the state
 * becoming CLOSE_WAIT. In a single-threaded harness neither happens, so the call hangs; the
 * probe that established this was killed by libcheck's timeout.
 *
 * So the *boundary* is comparable and the overflow is not. This records the boundary: two
 * proposed, two on the wire, sequential. A receiver whose window arithmetic is off by one
 * would send one or three. */
START_TEST(test_a_window_of_two_admits_exactly_two)
{
	setup_stack();
	const uint32_t o[6] = { 2 /* window */, 20000, 1000, 0 /* immediate acks */, 250, 2 };
	send_syn(o);
	const csp_conn_t * conn = find_rdp_conn();
	ck_assert_ptr_nonnull(conn);
	ack_handshake(conn->rdp.snd_iss);
	const uint16_t iss = conn->rdp.snd_iss;
	csp_conn_t * accepted = csp_accept(&test_sock, 0);
	ck_assert_ptr_nonnull(accepted);

	const unsigned int before = test_tx_count;
	uint16_t seqs[2];
	for (int i = 0; i < 2; i++) {
		csp_packet_t * out = csp_buffer_get(0);
		ck_assert_ptr_nonnull(out);
		out->data[0] = (uint8_t)('a' + i);
		out->length = 1;
		csp_send(accepted, out);
		seqs[i] = tx_seq;
	}
	const unsigned int frames = test_tx_count - before;
	const int sequential = (seqs[0] == (uint16_t)(iss + 1)) &&
						   (seqs[1] == (uint16_t)(iss + 2));

	if (ctest_tracing()) {
		ctest_trace_begin("rdp", "a_window_of_two_admits_exactly_two", "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("window_size", 2);
		ctest_trace_int("offered", 2);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("frames", (int64_t)frames);
		ctest_trace_int("sequential", sequential);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

START_TEST(test_three_sends_are_sequential_and_an_ack_releases_them)
{
	setup_stack();
	const csp_conn_t * conn = open_conn(0 /* immediate acks */, 2);
	ack_handshake(conn->rdp.snd_iss);
	const uint16_t iss = conn->rdp.snd_iss;
	csp_conn_t * accepted = csp_accept(&test_sock, 0);
	ck_assert_ptr_nonnull(accepted);
	/* Buffer accounting, because "nothing was retransmitted" is also true of a node that
	   dropped the queue entry and leaked its buffer. Releasing on acknowledgement is the
	   only thing that gives the pool back. */
	const int free_before = csp_buffer_remaining();

	uint16_t seqs[3];
	for (int i = 0; i < 3; i++) {
		csp_packet_t * out = csp_buffer_get(0);
		ck_assert_ptr_nonnull(out);
		out->data[0] = (uint8_t)('a' + i);
		out->length = 1;
		csp_send(accepted, out);
		seqs[i] = tx_seq;
	}
	const int sequential = (seqs[0] == (uint16_t)(iss + 1)) &&
						   (seqs[1] == (uint16_t)(iss + 2)) &&
						   (seqs[2] == (uint16_t)(iss + 3));

	/* The peer acknowledges all three at once: ack_nr is the last one it took. */
	put_header_and_route(new_rdp_packet(), RDP_ACK, 1002, seqs[2]);

	/* Nothing may be retransmitted after that, however long we wait. */
	const unsigned int before = test_tx_count;
	for (int i = 0; i < 40; i++) {
		ctest_clock_advance(250);
		csp_conn_check_timeouts();
	}
	const unsigned int after_ack = test_tx_count - before;
	const int buffers_lost = free_before - csp_buffer_remaining();

	if (ctest_tracing()) {
		ctest_trace_begin("rdp", "three_sends_are_sequential_and_an_ack_releases_them",
						  "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("packets", 3);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("sequential", sequential);
		ctest_trace_int("frames_after_the_ack", (int64_t)after_ack);
		ctest_trace_int("buffers_lost", (int64_t)buffers_lost);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

START_TEST(test_one_retransmission_after_the_packet_timeout)
{
	setup_stack();
	const csp_conn_t * conn = open_conn(0 /* immediate acks */, 2);
	ack_handshake(conn->rdp.snd_iss);
	csp_conn_t * accepted = csp_accept(&test_sock, 0);
	ck_assert_ptr_nonnull(accepted);

	csp_packet_t * out = csp_buffer_get(0);
	ck_assert_ptr_nonnull(out);
	memcpy(out->data, "hello", 5);
	out->length = 5;
	csp_send(accepted, out);

	/* `packet_timeout` is 1000 ms; sweep just past it once. */
	const unsigned int before = test_tx_count;
	for (int i = 0; i < 5; i++) {
		ctest_clock_advance(250);
		csp_conn_check_timeouts();
	}
	const unsigned int repeats = test_tx_count - before;
	const uint8_t repeat_flags = tx_flags & 0x0F;
	const int repeat_carries_the_payload = (tx_payload_len == 5);

	if (ctest_tracing()) {
		ctest_trace_begin("rdp", "one_retransmission_after_the_packet_timeout", "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("packet_timeout", 1000);
		ctest_trace_int("swept_ms", 1250);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("repeats", (int64_t)repeats);
		ctest_trace_int("repeat_flags", (int64_t)repeat_flags);
		ctest_trace_int("repeat_carries_the_payload", repeat_carries_the_payload);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

START_TEST(test_unacknowledged_data_is_retransmitted_then_given_up_on)
{
	setup_stack();
	const csp_conn_t * conn = open_conn(0 /* immediate acks */, 2);
	ack_handshake(conn->rdp.snd_iss);
	ck_assert_int_eq(conn->rdp.state, RDP_OPEN);

	csp_conn_t * accepted = csp_accept(&test_sock, 0);
	ck_assert_ptr_nonnull(accepted);

	/* One packet out, never acknowledged. */
	const unsigned int before = test_tx_count;
	const uint32_t sent_at_ms = csp_get_ms();
	csp_packet_t * out = csp_buffer_get(0);
	ck_assert_ptr_nonnull(out);
	memcpy(out->data, "hello", 5);
	out->length = 5;
	csp_send(accepted, out);
	const unsigned int first_send = test_tx_count - before;
	/* What the data frame itself looks like. Absolute sequence numbers cannot be compared
	   -- the port does not reproduce `rand_r`, so the two ISNs differ by design (SCOPE.md)
	   -- but everything relative to the connection's own ISN can be, and it is what says
	   the trailer was framed at all. */
	const uint8_t data_flags = tx_flags & 0x0F;
	const int seq_is_iss_plus_one = (tx_seq == (uint16_t)(conn->rdp.snd_iss + 1));
	const int ack_is_rcv_cur = (tx_ack == conn->rdp.rcv_cur);
	const uint16_t data_payload_len = tx_payload_len;

	if (ctest_tracing()) {
		ctest_trace_begin("rdp", "a_sent_data_packet_carries_an_rdp_trailer", "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("payload_bytes", 5);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("frames", (int64_t)first_send);
		ctest_trace_int("flags", (int64_t)data_flags);
		ctest_trace_int("seq_is_iss_plus_one", seq_is_iss_plus_one);
		ctest_trace_int("ack_is_rcv_cur", ack_is_rcv_cur);
		ctest_trace_int("payload_len", (int64_t)data_payload_len);
		ctest_trace_obj_end();
		ctest_trace_end();
	}

	/* The peer stays silent. Sweep well past any plausible give-up point.
	   Counting frames, not connection-table state: after the C gives up it leaves the
	   connection for the application to close (`discard_close` wakes user-space rather
	   than freeing an accepted handle), so "is it still in the table" answers a different
	   question than "has it stopped transmitting". */
	for (int i = 0; i < 1000; i++) {
		ctest_clock_advance(250);
		csp_conn_check_timeouts();
	}
	const unsigned int total = test_tx_count - before;
	/* What the last frame was: giving up goes through csp_conn_close, whose reset is the
	   only thing that tells the peer. A count alone cannot see it. */
	const uint8_t last_flags = tx_flags & 0x0F;

	/* Another long stretch: anything sent here means it never gave up. */
	const unsigned int before_tail = test_tx_count;
	for (int i = 0; i < 1000; i++) {
		ctest_clock_advance(250);
		csp_conn_check_timeouts();
	}
	const unsigned int tail = test_tx_count - before_tail;

	if (ctest_tracing()) {
		ctest_trace_begin("rdp", "unacknowledged_data_is_retransmitted_then_given_up_on",
						  "diverges");
		ctest_trace_obj_begin("input");
		ctest_trace_int("packet_timeout", 1000);
		ctest_trace_int("tick_ms", 250);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("frames_on_first_send", (int64_t)first_send);
		ctest_trace_int("total_frames", (int64_t)total);
		ctest_trace_int("last_flags", (int64_t)last_flags);
		ctest_trace_int("rst_frames", (int64_t)tx_rst_count);
		ctest_trace_int("first_rst_ms_after_send",
						(int64_t)(tx_rst_count ? (tx_first_rst_ms - sent_at_ms) : 0));
		ctest_trace_int("last_frame_ms_after_send", (int64_t)(tx_last_ms - sent_at_ms));
		ctest_trace_int("frames_after_giving_up", (int64_t)tail);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

START_TEST(test_a_gap_filled_late_delivers_both_in_order)
{
	setup_stack();
	const csp_conn_t * conn = open_conn(0 /* immediate acks */, 2);
	const uint16_t iss = conn->rdp.snd_iss;
	const uint16_t base = conn->rdp.rcv_cur;

	deliver_byte((uint16_t)(base + 2), iss, 'B'); /* overtakes */
	deliver_byte((uint16_t)(base + 1), iss, 'A'); /* fills the gap */

	uint8_t got[8];
	unsigned int n = 0;
	csp_conn_t * accepted = csp_accept(&test_sock, 0);
	if (accepted != NULL) {
		csp_packet_t * p;
		while ((p = csp_read(accepted, 0)) != NULL) {
			for (uint16_t i = 0; (i < p->length) && (n < sizeof(got)); i++) {
				got[n++] = p->data[i];
			}
			csp_buffer_free(p);
		}
	}

	if (ctest_tracing()) {
		ctest_trace_begin("rdp", "a_gap_filled_late_delivers_both_in_order", "must_match");
		ctest_trace_obj_begin("observed");
		ctest_trace_int("delivered_bytes", (int64_t)n);
		ctest_trace_hex("delivered_body", got, n);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

START_TEST(test_an_eak_carries_no_data_to_the_application)
{
	setup_stack();
	const csp_conn_t * conn = open_conn(0 /* immediate acks */, 2);
	const uint16_t iss = conn->rdp.snd_iss;

	/* In sequence, with a payload, but flagged as an extended acknowledgement. */
	csp_packet_t * packet = new_rdp_packet();
	packet->data[0] = 'x';
	packet->data[1] = 'y';
	packet->length = 2;
	const unsigned int before = test_tx_count;
	put_header_and_route(packet, (uint8_t)(RDP_ACK | RDP_EAK),
						 (uint16_t)(conn->rdp.rcv_cur + 1), iss);
	const unsigned int frames = test_tx_count - before;

	unsigned int count, bytes;
	drain_accepted(&count, &bytes);
	eak_record("an_eak_carries_no_data_to_the_application", count, bytes, tx_flags, frames);
}
END_TEST

/* The other half: data that arrives with a gap. `csp_rdp.c:722` says "If message is not in
   sequence, send EACK and store packet". Measured, it stores and answers *nothing* -- the
   comment describes an EACK the code does not send on this path.
 *
 * The port holds it too, since the reorder queue was wired in -- so neither side answers
 * and neither delivers until the gap fills. */
START_TEST(test_out_of_sequence_data_is_answered_but_not_delivered)
{
	setup_stack();
	const csp_conn_t * conn = open_conn(0, 2);
	const uint16_t iss = conn->rdp.snd_iss;

	/* Skip one: the receiver expects rcv_cur+1 and gets rcv_cur+2. */
	csp_packet_t * packet = new_rdp_packet();
	packet->data[0] = 'z';
	packet->length = 1;
	const unsigned int before = test_tx_count;
	put_header_and_route(packet, RDP_ACK, (uint16_t)(conn->rdp.rcv_cur + 2), iss);
	const unsigned int frames = test_tx_count - before;

	unsigned int count, bytes;
	drain_accepted(&count, &bytes);
	eak_record("out_of_sequence_data_is_answered_but_not_delivered", count, bytes, tx_flags,
			   frames);
}
END_TEST

START_TEST(test_an_in_sequence_rst_is_answered)
{
	setup_stack();
	const csp_conn_t * conn = open_conn(0 /* immediate acks */, 2);
	const uint16_t iss = conn->rdp.snd_iss;

	/* In sequence: the next sequence number the receiver expects. */
	const uint16_t rst_seq = (uint16_t)(conn->rdp.rcv_cur + 1);
	unsigned int before = test_tx_count;
	put_header_and_route(new_rdp_packet(), RDP_RST, rst_seq, iss);
	const unsigned int frames = test_tx_count - before;
	const uint8_t flags = tx_flags;

	/* Does it still answer data afterwards? */
	before = test_tx_count;
	deliver_data((uint16_t)(rst_seq + 1), iss);
	const uint8_t followup = (test_tx_count > before) ? tx_flags : 0;

	rst_record("an_in_sequence_rst_is_answered", 1, frames, flags, followup);
}
END_TEST

START_TEST(test_an_out_of_sequence_rst_is_ignored)
{
	setup_stack();
	const csp_conn_t * conn = open_conn(0, 2);
	const uint16_t iss = conn->rdp.snd_iss;

	/* Far outside the window: what a blind injector would send. */
	const uint16_t rst_seq = (uint16_t)(conn->rdp.rcv_cur + 5000);
	unsigned int before = test_tx_count;
	put_header_and_route(new_rdp_packet(), RDP_RST, rst_seq, iss);
	const unsigned int frames = test_tx_count - before;
	const uint8_t flags = tx_flags;

	/* The connection must have survived it. */
	before = test_tx_count;
	deliver_data((uint16_t)(conn->rdp.rcv_cur + 1), iss);
	const uint8_t followup = (test_tx_count > before) ? tx_flags : 0;

	rst_record("an_out_of_sequence_rst_is_ignored", 0, frames, flags, followup);
}
END_TEST

START_TEST(test_a_proposed_conn_timeout_is_adopted)
{
	setup_stack();
	const uint32_t opts[6] = { 4, 3000 /* conn_timeout */, 1000, 0 /* immediate acks */,
							   250, 2 };
	send_syn(opts);
	const csp_conn_t * conn = find_rdp_conn();
	ck_assert_ptr_nonnull(conn);
	ack_handshake(conn->rdp.snd_iss);
	ck_assert_int_eq(conn->rdp.state, RDP_OPEN);
	const uint16_t iss = conn->rdp.snd_iss;

	/* Idle well past the proposed timeout, but well inside the default. */
	for (int i = 0; i < 16; i++) {
		ctest_clock_advance(250);
		csp_conn_check_timeouts();
	}

	/* Now the peer speaks. Does anything come back -- and what? An acknowledgement means
	   the connection survived the idle; a reset means the C closed it and is saying so.
	   The first version of this record counted frames only, and an RST counted as an
	   answer, which read as "the connection survived" for two days. */
	const unsigned int before = test_tx_count;
	deliver_data(1001, iss);
	const int answered = (test_tx_count > before);
	const uint8_t answer_flags = answered ? (tx_flags & 0x0F) : 0;

	if (ctest_tracing()) {
		ctest_trace_begin("rdp", "a_proposed_conn_timeout_is_adopted", "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("conn_timeout", 3000);
		ctest_trace_int("idled_ms", 4000);
		/* Immediate acknowledgement, so a missing answer means the connection is gone
		   rather than merely waiting for a delayed ack to come due. */
		ctest_trace_int("delayed_acks", 0);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("answered_after_idle", answered);
		ctest_trace_int("answer_flags", answer_flags);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

START_TEST(test_a_proposed_ack_timeout_is_adopted)
{
	setup_stack();
	const uint32_t opts[6] = { 4, 20000, 1000, 1 /* delayed */, 5000 /* ack_timeout */, 4 };
	send_syn(opts);
	const csp_conn_t * conn = find_rdp_conn();
	ck_assert_ptr_nonnull(conn);
	ack_handshake(conn->rdp.snd_iss);
	ck_assert_int_eq(conn->rdp.state, RDP_OPEN);

	/* One packet: well under the delay count, so only the timeout can produce an ack. */
	const unsigned int before = test_tx_count;
	deliver_data(1001, conn->rdp.snd_iss);
	const int acked_at_once = (test_tx_count > before);

	/* Advance until the acknowledgement appears, and report when. */
	uint32_t waited = 0;
	while ((test_tx_count == before) && (waited < 20000)) {
		ctest_clock_advance(250);
		waited += 250;
		csp_conn_check_timeouts();
	}
	const int acked = (test_tx_count > before);

	if (ctest_tracing()) {
		ctest_trace_begin("rdp", "a_proposed_ack_timeout_is_adopted", "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("ack_timeout", 5000);
		ctest_trace_int("delayed_acks", 1);
		ctest_trace_int("ack_delay_count", 4);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("acked_immediately", acked_at_once);
		ctest_trace_int("acked", acked);
		ctest_trace_int("waited_ms", (int64_t)waited);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

START_TEST(test_a_nonzero_delayed_acks_is_on_not_a_count)
{
	setup_stack();
	const uint32_t opts[6] = { 3, 20000, 500, 2 /* not 1 */, 250, 2 };
	send_syn(opts);
	const csp_conn_t * conn = find_rdp_conn();
	ck_assert_ptr_nonnull(conn);
	ack_handshake(conn->rdp.snd_iss);
	ck_assert_int_eq(conn->rdp.state, RDP_OPEN);

	const uint16_t iss = conn->rdp.snd_iss;
	unsigned int acks_at[5];
	const unsigned int before = test_tx_count;
	for (uint16_t i = 1; i <= 5; i++) {
		deliver_data((uint16_t)(1000 + i), iss);
		acks_at[i - 1] = test_tx_count - before;
	}

	if (ctest_tracing()) {
		ctest_trace_begin("rdp", "a_nonzero_delayed_acks_is_on_not_a_count", "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("delayed_acks", 2);
		ctest_trace_int("ack_delay_count", 2);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("normalised_to_on", conn->rdp.delayed_acks == 1);
		ctest_trace_arr_begin("acks_after_n_packets");
		for (int i = 0; i < 5; i++) {
			ctest_trace_int(NULL, (int64_t)acks_at[i]);
		}
		ctest_trace_arr_end();
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

START_TEST(test_a_delay_count_beyond_the_window_is_bound_by_it)
{
	setup_stack();
	const uint32_t opts[6] = { 2 /* window */, 20000, 1000, 1 /* delayed */, 250, 250 };
	send_syn(opts);
	const csp_conn_t * conn = find_rdp_conn();
	ck_assert_ptr_nonnull(conn);
	ack_handshake(conn->rdp.snd_iss);
	ck_assert_int_eq(conn->rdp.state, RDP_OPEN);

	const uint16_t iss = conn->rdp.snd_iss;
	unsigned int acks_at[5];
	const unsigned int before = test_tx_count;
	for (uint16_t i = 1; i <= 5; i++) {
		deliver_data((uint16_t)(1000 + i), iss);
		acks_at[i - 1] = test_tx_count - before;
	}

	if (ctest_tracing()) {
		ctest_trace_begin("rdp", "a_delay_count_beyond_the_window_is_bound_by_it",
						  "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("window_size", 2);
		ctest_trace_int("delayed_acks", 1);
		ctest_trace_int("ack_delay_count", 250);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_arr_begin("acks_after_n_packets");
		for (int i = 0; i < 5; i++) {
			ctest_trace_int(NULL, (int64_t)acks_at[i]);
		}
		ctest_trace_arr_end();
		ctest_trace_obj_end();
		ctest_trace_end();
	}

	/* A count of 250 left unbound would never acknowledge within five packets. */
	ck_assert_uint_gt(acks_at[4], 0);
}
END_TEST

START_TEST(test_the_delay_count_fires_one_packet_after_it)
{
	setup_stack();
	const csp_conn_t * conn = open_conn(1, 2);

	/* The clock does not move, so the ack timeout cannot be what triggers it. */
	const uint16_t iss = conn->rdp.snd_iss;
	unsigned int acks_at[5];
	unsigned int before = test_tx_count;
	for (uint16_t i = 1; i <= 5; i++) {
		deliver_data((uint16_t)(1000 + i), iss);
		acks_at[i - 1] = test_tx_count - before;
	}

	if (ctest_tracing()) {
		ctest_trace_begin("rdp", "the_delay_count_fires_one_packet_after_it", "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("delayed_acks", 1);
		ctest_trace_int("ack_delay_count", 2);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_arr_begin("acks_after_n_packets");
		for (int i = 0; i < 5; i++) {
			ctest_trace_int(NULL, (int64_t)acks_at[i]);
		}
		ctest_trace_arr_end();
		ctest_trace_obj_end();
		ctest_trace_end();
	}

	/* Nothing before the count is exceeded. */
	ck_assert_uint_eq(acks_at[0], 0);
	ck_assert_uint_eq(acks_at[1], 0);
	/* And something after. */
	ck_assert_uint_gt(acks_at[4], 0);
	(void)conn;
}
END_TEST

/* Nothing has arrived since the last acknowledgement, and delayed acks are off. The C's
   first condition returns true unconditionally, so it acknowledges anyway -- an ack for a
   sequence number the peer already knows about. */
START_TEST(test_an_ack_is_sent_even_with_nothing_to_acknowledge)
{
	setup_stack();
	const csp_conn_t * conn = open_conn(0, 2);

	unsigned int before = test_tx_count;
	csp_rdp_check_ack((csp_conn_t *)conn);
	const unsigned int acks = test_tx_count - before;

	if (ctest_tracing()) {
		/* The port refuses to send this one; SCOPE.md records why. */
		ctest_trace_begin("rdp", "an_ack_is_sent_even_with_nothing_to_acknowledge", "diverges");
		ctest_trace_obj_begin("input");
		ctest_trace_int("delayed_acks", 0);
		ctest_trace_int("packets_since_last_ack", 0);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("acks", (int64_t)acks);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
	ck_assert_uint_eq(acks, 1);
}
END_TEST

/* `csp_rdp_check_ack` opens with
 *
 *     if (abs(CSP_CONN_RXQUEUE_LEN - csp_queue_size(conn->rx_queue)) < window_size) return;
 *
 * — acknowledge only while there is room for a full window still to arrive. That is
 * receiver-side flow control: an unread connection stops inviting data instead of accepting
 * it and dropping it. Nothing in the port's `poll_ack` corresponds to it.
 *
 * Measured as the packet number at which acknowledgements stop, with the application never
 * reading. Nothing here inspects the queue; it counts frames.
 */
/* The receive-queue gate, made reachable.
 *
 * `csp_rdp_check_ack` opens with a check the acknowledgement conditions never see:
 *
 *     abs(CSP_CONN_RXQUEUE_LEN - csp_queue_size(conn->rx_queue)) < conn->rdp.window_size
 *
 * -- when the connection's receive queue has less spare room than a window, the C sends *no*
 * acknowledgement at all, whatever the delay count or the ack timeout say. That is deliberate
 * back-pressure: an application that has stopped reading makes the sender stop sending.
 *
 * `acks_stop_when_the_application_is_not_reading` records that it never fires, because it
 * cannot at those numbers: with `window_size` 4 the gate needs 13 packets queued, and 15
 * buffers cap an unread connection at 12. Proposing a window of 5 moves the threshold to 12,
 * which the pool can reach. This is the same test with the one number changed that makes the
 * branch reachable -- the port has no equivalent gate at all, so what this measures is
 * whether that matters at a size a node can actually hit.
 */
START_TEST(test_the_receive_queue_gate_stops_acknowledgements)
{
	setup_stack();
	/* Window 5 = CSP_RDP_MAX_WINDOW, so the C adopts it unclamped. */
	const uint32_t opts[6] = { 5, 20000, 1000, 0 /* immediate acks */, 250, 2 };
	send_syn(opts);
	const csp_conn_t * conn = find_rdp_conn();
	ck_assert_ptr_nonnull(conn);
	ack_handshake(conn->rdp.snd_iss);
	ck_assert_int_eq(conn->rdp.state, RDP_OPEN);
	ck_assert_uint_eq(conn->rdp.window_size, 5);

	const uint16_t iss = conn->rdp.snd_iss;
	unsigned int acks = 0, delivered = 0, first_unacked = 0;
	for (uint16_t i = 1; i <= CSP_CONN_RXQUEUE_LEN; i++) {
		/* Three spare: the packet being built, the acknowledgement it may provoke, and
		   one so `csp_buffer_get` cannot fail mid-loop. */
		if (csp_buffer_remaining() < 3) {
			break;
		}
		const unsigned int before = test_tx_count;
		deliver_data((uint16_t)(1000 + i), iss);
		delivered++;
		if (test_tx_count > before) {
			acks++;
		} else if (first_unacked == 0) {
			first_unacked = i;
		}
	}

	if (ctest_tracing()) {
		ctest_trace_begin("rdp", "the_receive_queue_gate_stops_acknowledgements", "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("window_size", 5);
		ctest_trace_int("rxqueue_len", CSP_CONN_RXQUEUE_LEN);
		ctest_trace_int("buffer_count", CSP_BUFFER_COUNT);
		ctest_trace_int("delivered", (int64_t)delivered);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("acks", (int64_t)acks);
		ctest_trace_int("first_unacked", (int64_t)first_unacked);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

START_TEST(test_acks_stop_when_the_application_is_not_reading)
{
	setup_stack();
	const csp_conn_t * conn = open_conn(0, 2);
	const uint16_t iss = conn->rdp.snd_iss;

	/* Deliver until the pool runs dry, never reading any of it. The bound is the buffer
	   pool, not the queue: CSP_BUFFER_COUNT is 15 and CSP_CONN_RXQUEUE_LEN is 16, so an
	   unread connection exhausts the node's buffers before its own queue is full. */
	unsigned int acks = 0;
	unsigned int last_acked_packet = 0;
	unsigned int delivered = 0;
	for (uint16_t i = 1; i <= CSP_CONN_RXQUEUE_LEN; i++) {
		if (csp_buffer_remaining() < 4) {
			break;
		}
		const unsigned int before = test_tx_count;
		deliver_data((uint16_t)(1000 + i), iss);
		delivered++;
		if (test_tx_count > before) {
			acks++;
			last_acked_packet = i;
		}
	}

	if (ctest_tracing()) {
		ctest_trace_begin("rdp", "acks_stop_when_the_application_is_not_reading", "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("delivered", (int64_t)delivered);
		ctest_trace_int("rxqueue_len", CSP_CONN_RXQUEUE_LEN);
		ctest_trace_int("buffer_count", CSP_BUFFER_COUNT);
		ctest_trace_int("window_size", (int64_t)conn->rdp.window_size);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("acks", (int64_t)acks);
		ctest_trace_int("last_acked_packet", (int64_t)last_acked_packet);
		ctest_trace_obj_end();
		ctest_trace_end();
	}

	ck_assert_uint_gt(delivered, 0);
	ck_assert_uint_gt(acks, 0);
	/* Whether the gate ever fires is what the recorded numbers say; asserting a specific
	   answer here would be asserting the reading this test exists to check. */
	ck_assert_uint_le(acks, delivered);
}
END_TEST

/* Data over an open connection reaches the application without its trailer.
 *
 * `csp_rdp_new_packet` removes the five-byte RDP header before the packet is queued, so
 * `csp_read` hands the application exactly what the peer sent. A node that queued the
 * packet unchanged would give every application five bytes of protocol state appended to
 * its message -- which parses as a slightly longer message rather than as an error, so
 * nothing would report it.
 */
START_TEST(test_data_reaches_the_application_without_the_rdp_trailer)
{
	setup_stack();
	const csp_conn_t * conn = open_conn(0, 2);
	const uint16_t iss = conn->rdp.snd_iss;

	csp_packet_t * packet = new_rdp_packet();
	memcpy(packet->data, "hello", 5);
	packet->length = 5;
	put_header_and_route(packet, RDP_ACK, 1001, iss);

	csp_conn_t * accepted = csp_accept(&test_sock, 0);
	ck_assert_ptr_nonnull(accepted);
	csp_packet_t * got = csp_read(accepted, 0);
	ck_assert_ptr_nonnull(got);

	ck_assert_uint_eq(got->length, 5);
	ck_assert_mem_eq(got->data, "hello", 5);

	if (ctest_tracing()) {
		ctest_trace_begin("rdp", "data_reaches_the_application_without_the_rdp_trailer",
						  "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("payload_bytes_sent", 5);
		ctest_trace_int("clock_ms", CTEST_CLOCK_EPOCH_MS);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("delivered_len", (int64_t)got->length);
		ctest_trace_hex("delivered", got->data, got->length);
		ctest_trace_obj_end();
		ctest_trace_end();
	}

	csp_buffer_free(got);
}
END_TEST

/* A hostile SYN cannot talk the node out of acknowledging.
 *
 * `csp_rdp_new_packet` clamps every option a peer proposes. The three
 * `rdp_syn_options_are_bounded_*` tests assert that with twenty `ck_assert`s between them
 * and **record nothing**, so the port's `decode_clamped` had never been compared against
 * libcsp at all -- it was verified by reading.
 *
 * Asserted here as what reaches the wire rather than as the connection's fields. An
 * unclamped `ack_delay_count` of 0xFFFFFFFF means the node waits four billion packets
 * before acknowledging, so the peer retransmits forever and the link stalls: the clamp is
 * only observable as acks appearing at all.
 */
START_TEST(test_a_hostile_syn_cannot_suppress_acknowledgement)
{
	setup_stack();

	const uint32_t hostile[6] = {
		0xFFFFFFFF, /* window size     */
		0xFFFFFFFF, /* conn timeout    */
		0,          /* packet timeout  */
		0xFFFFFFFF, /* delayed acks    */
		0xFFFFFFFF, /* ack timeout     */
		0xFFFFFFFF, /* ack delay count */
	};
	send_syn(hostile);
	const csp_conn_t * conn = find_rdp_conn();
	ck_assert_ptr_nonnull(conn);
	ack_handshake(conn->rdp.snd_iss);
	ck_assert_int_eq(conn->rdp.state, RDP_OPEN);

	const uint16_t iss = conn->rdp.snd_iss;
	const unsigned int before = test_tx_count;
	/* Comfortably more than any sane window, and far fewer than 0xFFFFFFFF.
	   Drained as they arrive: `csp_rdp_check_ack` stops acknowledging once the
	   connection's queue leaves less than a window of room, and that suppression -- a
	   separate, recorded divergence -- would otherwise dominate this test and hide what it
	   is about. Reading keeps the queue empty so the *clamp* is what decides. */
	csp_conn_t * accepted = csp_accept(&test_sock, 0);
	ck_assert_ptr_nonnull(accepted);
	for (uint16_t i = 1; i <= 12; i++) {
		deliver_data((uint16_t)(1000 + i), iss);
		csp_packet_t * p;
		while ((p = csp_read(accepted, 0)) != NULL) {
			csp_buffer_free(p);
		}
	}
	const unsigned int acks = test_tx_count - before;

	ck_assert_uint_gt(acks, 0);

	if (ctest_tracing()) {
		ctest_trace_begin("rdp", "a_hostile_syn_cannot_suppress_acknowledgement",
						  "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("proposed_ack_delay_count", -1);
		ctest_trace_int("proposed_window", -1);
		ctest_trace_int("packets", 12);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("acks", (int64_t)acks);
		ctest_trace_int("clamped_window", (int64_t)conn->rdp.window_size);
		ctest_trace_int("clamped_ack_delay_count", (int64_t)conn->rdp.ack_delay_count);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

/* --- SFP carried over RDP: the {SFP} x {RDP} cell ---
 *
 * Both protocols put their header at the **end** of the payload, and the send path stacks
 * them: `csp_sfp_send` appends the SFP header, then `csp_rdp_send` appends the RDP header
 * after it. So the wire carries `[body][sfp trailer][rdp trailer]` and the receiver must
 * strip them in that order -- RDP first, from the outside in.
 *
 * The SFP suite builds its packets by hand and calls `csp_sfp_recv_fp` directly, so the
 * path from the wire to the stream reader was never exercised at all; the RDP suite reads
 * plain bytes. This is the one case where both layers' length arithmetic has to agree, and
 * an off-by-one in either produces a fragment the reader rejects rather than a crash.
 */

typedef struct __attribute__((packed)) {
	uint32_t offset;
	uint32_t totalsize;
} sfp_trailer_t;

static uint8_t sfp_got[64];
static uint32_t sfp_got_len;

static int sfp_capture(const uint8_t * buffer, uint32_t size, uint32_t offset,
					   uint32_t totalsz, void * data) {
	(void)totalsz;
	(void)data;
	if (offset + size <= sizeof(sfp_got)) {
		memcpy(sfp_got + offset, buffer, size);
		if (offset + size > sfp_got_len) {
			sfp_got_len = offset + size;
		}
	}
	return CSP_ERR_NONE;
}

START_TEST(test_a_stream_fragment_survives_being_carried_over_rdp)
{
	setup_stack();
	memset(sfp_got, 0, sizeof(sfp_got));
	sfp_got_len = 0;

	const csp_conn_t * conn = open_conn(0, 2);
	const uint16_t iss = conn->rdp.snd_iss;

	/* [body][sfp trailer][rdp trailer], built in that order. */
	csp_packet_t * packet = new_rdp_packet();
	packet->id.flags |= CSP_FFRAG;
	memcpy(packet->data, "stream", 6);
	packet->length = 6;
	sfp_trailer_t * sfp = (sfp_trailer_t *)&packet->data[packet->length];
	sfp->offset = htobe32(0);
	sfp->totalsize = htobe32(6);
	packet->length += sizeof(*sfp);
	put_header_and_route(packet, RDP_ACK, 1001, iss);

	/* The application takes the connection and reads what arrived. */
	csp_conn_t * accepted = csp_accept(&test_sock, 0);
	ck_assert_ptr_nonnull(accepted);
	csp_packet_t * got = csp_read(accepted, 0);
	ck_assert_ptr_nonnull(got);

	/* RDP's trailer is gone; SFP's is still there. */
	ck_assert_uint_eq(got->length, 6 + sizeof(sfp_trailer_t));

	const csp_sfp_recv_t rx = { .write = sfp_capture };
	const int ret = csp_sfp_recv_fp(accepted, &rx, 0, got);

	ck_assert_int_eq(ret, CSP_ERR_NONE);
	ck_assert_uint_eq(sfp_got_len, 6);
	ck_assert_mem_eq(sfp_got, "stream", 6);

	if (ctest_tracing()) {
		ctest_trace_begin("rdp", "a_stream_fragment_survives_being_carried_over_rdp",
						  "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("body_bytes", 6);
		ctest_trace_int("clock_ms", CTEST_CLOCK_EPOCH_MS);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		/* What the application was handed after RDP, before SFP. */
		ctest_trace_int("after_rdp_len", (int64_t)(6 + sizeof(sfp_trailer_t)));
		ctest_trace_int("sfp_result", ret);
		ctest_trace_int("reassembled_len", (int64_t)sfp_got_len);
		ctest_trace_hex("reassembled", sfp_got, sfp_got_len);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

/* --- the client half of the handshake ---
 *
 * Every RDP test above has this node *answering* a peer's SYN. `csp_connect(.., CSP_O_RDP)`
 * is the other direction, and the port refuses it outright: `Node::connect` returns
 * `Error::Unsupported`, so `csp-core`'s `Event::Connect` is constructed nowhere outside its
 * own unit tests and the router's `Action::SendSyn` arm cannot be reached. Coverage is what
 * surfaced that -- the arm is dead code that reads like working client support.
 *
 * `csp_rdp_connect` puts the SYN on the wire and *then* blocks on a semaphore only the
 * router task can release, so in a single-threaded harness the frame is observable and the
 * call is not. The connection timeout is dropped to 50 ms first, because that wait is
 * real-time (a pthread condvar) rather than virtual: at the 20 s default this test would
 * sleep for forty seconds across its two attempts.
 *
 * What is recorded is the SYN itself -- the flags a peer sees, the sequence number, and the
 * six option words the C proposes -- which is exactly what a port implementing the client
 * has to reproduce. */
START_TEST(test_an_rdp_connect_puts_a_syn_on_the_wire)
{
	setup_stack();

	unsigned int w, ct, pt, da, at, adc;
	csp_rdp_get_opt(&w, &ct, &pt, &da, &at, &adc);
	csp_rdp_set_opt(w, 50 /* conn_timeout */, pt, da, at, adc);

	uint32_t opts[6] = { 0 };
	unsigned int syn_frames = 0;
	uint8_t syn_flags = 0;
	uint16_t syn_seq = 0, syn_ack = 0, syn_payload = 0;

	/* Capture the first frame only: the retry emits an identical second SYN. */
	csp_conn_t * conn = csp_connect(2, PEER_ADDR, TEST_PORT, 0, CSP_O_RDP);

	syn_frames = test_tx_count;
	syn_flags = tx_flags;
	syn_seq = tx_seq;
	syn_ack = tx_ack;
	syn_payload = tx_payload_len;

	/* No peer answered, so the C gives up and hands back nothing. */
	ck_assert_ptr_null(conn);
	ck_assert_uint_gt(syn_frames, 0);
	ck_assert_uint_eq(syn_flags, RDP_SYN);
	ck_assert_uint_eq(syn_payload, sizeof(opts));
	/* The sequence number is the ISN, and a SYN naming sequence 0 would be a machine that
	   never randomised it. The value itself is `rand_r`-derived and not something the port
	   reproduces, so it is asserted as a property rather than recorded. */
	ck_assert_uint_ne(syn_seq, 0);

	csp_rdp_set_opt(w, ct, pt, da, at, adc);

	if (ctest_tracing()) {
		ctest_trace_begin("rdp", "an_rdp_connect_puts_a_syn_on_the_wire", "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("clock_ms", CTEST_CLOCK_EPOCH_MS);
		ctest_trace_int("conn_timeout_ms", 50);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("syn_flags", syn_flags);
		ctest_trace_int("syn_ack", syn_ack);
		ctest_trace_int("option_bytes", syn_payload);
		/* `syn_seq` is deliberately absent. It is the ISN, which the C derives from
		   `rand_r(csp_get_ms())` and the port does not reproduce -- a recorded divergence,
		   covered on the C side by `isn_is_a_function_of_the_clock`. Including it would
		   force this record to `diverges` and stop it pinning the three fields that do have
		   to agree. It is asserted above as a property instead. */
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

/* The same cell, but with a transfer that does not fit in one fragment.
 *
 * The test above hands `csp_sfp_recv_fp` a packet that completes the transfer on the spot,
 * so the reassembly loop returns before reaching the `csp_read` at its bottom. That
 * `csp_read` is the only place the two layers are actually coupled: SFP pulls its next
 * fragment straight out of the connection queue that RDP is filling, in the middle of a
 * call, with no router step in between. Whether a fragment RDP has already accepted is
 * visible there is the question, and nothing had asked it -- a stream that stalls on its
 * second fragment looks exactly like a peer that stopped sending.
 *
 * Two fragments, both delivered before the reader starts, so this measures the coupling and
 * not the arrival order. */
START_TEST(test_a_multi_fragment_stream_reassembles_over_rdp)
{
	setup_stack();
	memset(sfp_got, 0, sizeof(sfp_got));
	sfp_got_len = 0;

	const csp_conn_t * conn = open_conn(0, 2);
	const uint16_t iss = conn->rdp.snd_iss;
	const uint16_t base = conn->rdp.rcv_cur;

	/* [body][sfp trailer][rdp trailer], in that order, for each half. */
	const char * bodies[2] = { "hello", "world" };
	for (unsigned int i = 0; i < 2; i++) {
		csp_packet_t * packet = new_rdp_packet();
		packet->id.flags |= CSP_FFRAG;
		memcpy(packet->data, bodies[i], 5);
		packet->length = 5;
		sfp_trailer_t * sfp = (sfp_trailer_t *)&packet->data[packet->length];
		sfp->offset = htobe32(i * 5);
		sfp->totalsize = htobe32(10);
		packet->length += sizeof(*sfp);
		put_header_and_route(packet, RDP_ACK, (uint16_t)(base + 1 + i), iss);
	}

	csp_conn_t * accepted = csp_accept(&test_sock, 0);
	ck_assert_ptr_nonnull(accepted);

	const csp_sfp_recv_t rx = { .write = sfp_capture };
	const int ret = csp_sfp_recv_fp(accepted, &rx, 0, NULL);

	if (ctest_tracing()) {
		ctest_trace_begin("rdp", "a_multi_fragment_stream_reassembles_over_rdp",
						  "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("fragments", 2);
		ctest_trace_int("totalsize", 10);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("sfp_result", ret);
		ctest_trace_int("reassembled_len", (int64_t)sfp_got_len);
		ctest_trace_hex("reassembled", sfp_got, sfp_got_len);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

Suite * rdp_suite(void)
{
	Suite * s;
	TCase * tc_syn;
	TCase * tc_tx;
	TCase * tc_queue;

	s = suite_create("RDP");

	tc_syn = tcase_create("syn");
	tcase_add_test(tc_syn, test_rdp_syn_without_options_is_rejected);
	tcase_add_test(tc_syn, test_rdp_syn_with_partial_options_is_rejected);
	tcase_add_test(tc_syn, test_rdp_malformed_syns_do_not_exhaust_the_table);
	tcase_add_test(tc_syn, test_rdp_syn_options_are_bounded_above);
	tcase_add_test(tc_syn, test_rdp_syn_options_are_bounded_below);
	tcase_add_test(tc_syn, test_rdp_syn_keeps_valid_options);
	tcase_add_test(tc_syn, test_rdp_delayed_acks_is_a_flag);
	tcase_add_test(tc_syn, test_rdp_isn_is_a_function_of_the_clock);
	tcase_add_test(tc_syn, test_rdp_isn_does_not_depend_on_history);
	suite_add_tcase(s, tc_syn);

	tc_tx = tcase_create("retransmit");
	/* No timeout override: these advance the clock rather than sleeping, so the
	   retransmit sequence they drive costs no wall-clock time at all. */
	tcase_add_test(tc_tx, test_rdp_retransmits_are_limited);
	tcase_add_test(tc_tx, test_rdp_retransmit_count_resets_on_ack);
	suite_add_tcase(s, tc_tx);

	TCase * tc_hs = tcase_create("handshake");
	tcase_add_test(tc_hs, test_a_syn_is_answered_with_syn_ack);
	tcase_add_test(tc_hs, test_the_handshakes_final_ack_is_not_itself_answered);
	tcase_add_test(tc_hs, test_data_reaches_the_application_without_the_rdp_trailer);
	tcase_add_test(tc_hs, test_a_stream_fragment_survives_being_carried_over_rdp);
	tcase_add_test(tc_hs, test_a_multi_fragment_stream_reassembles_over_rdp);
	tcase_add_test(tc_hs, test_an_rdp_connect_puts_a_syn_on_the_wire);
	tcase_add_test(tc_hs, test_a_hostile_syn_cannot_suppress_acknowledgement);
	suite_add_tcase(s, tc_hs);

	TCase * tc_ack = tcase_create("ack");
	tcase_add_test(tc_ack, test_without_delayed_acks_every_packet_is_acknowledged);
	tcase_add_test(tc_ack, test_a_window_of_two_admits_exactly_two);
	tcase_add_test(tc_ack, test_three_sends_are_sequential_and_an_ack_releases_them);
	tcase_add_test(tc_ack, test_one_retransmission_after_the_packet_timeout);
	tcase_add_test(tc_ack, test_unacknowledged_data_is_retransmitted_then_given_up_on);
	tcase_add_test(tc_ack, test_a_gap_filled_late_delivers_both_in_order);
	tcase_add_test(tc_ack, test_an_eak_carries_no_data_to_the_application);
	tcase_add_test(tc_ack, test_out_of_sequence_data_is_answered_but_not_delivered);
	tcase_add_test(tc_ack, test_an_in_sequence_rst_is_answered);
	tcase_add_test(tc_ack, test_an_out_of_sequence_rst_is_ignored);
	tcase_add_test(tc_ack, test_a_proposed_conn_timeout_is_adopted);
	tcase_add_test(tc_ack, test_a_proposed_ack_timeout_is_adopted);
	tcase_add_test(tc_ack, test_a_nonzero_delayed_acks_is_on_not_a_count);
	tcase_add_test(tc_ack, test_a_delay_count_beyond_the_window_is_bound_by_it);
	tcase_add_test(tc_ack, test_the_delay_count_fires_one_packet_after_it);
	tcase_add_test(tc_ack, test_an_ack_is_sent_even_with_nothing_to_acknowledge);
	tcase_add_test(tc_ack, test_acks_stop_when_the_application_is_not_reading);
	tcase_add_test(tc_ack, test_the_receive_queue_gate_stops_acknowledgements);
	suite_add_tcase(s, tc_ack);

	tc_queue = tcase_create("queue");
	tcase_add_test(tc_queue, test_rdp_queue_flush_all_releases_buffers);
	tcase_add_test(tc_queue, test_rdp_queue_flush_all_releases_receive_buffers);
	suite_add_tcase(s, tc_queue);

	return s;
}

#else /* !CSP_USE_RDP */

/* --- the acknowledgement policy ---
 *
 * `csp_rdp_should_ack` has three conditions and `csp_rdp_check_ack` gates all of them
 * behind a fourth. All four are only observable as *whether an ACK reaches the wire*, which
 * is what these count -- the internal sequence numbers are not the behaviour, they are how
 * the behaviour is computed.
 *
 * Three things here were predicted from reading `csp_rdp.c` and are settled by measuring:
 * whether the C acknowledges when there is nothing to acknowledge, whether the delay count
 * fires at N or N+1 outstanding, and whether a full receive queue suppresses the ack.
 */

/* Open a connection with the given delayed-ack options and return it. */
static const csp_conn_t * open_conn(uint32_t delayed_acks, uint32_t ack_delay_count) {
	const uint32_t opts[6] = { 4, 20000, 1000, delayed_acks, 250, ack_delay_count };
	send_syn(opts);
	const csp_conn_t * conn = find_rdp_conn();
	ck_assert_ptr_nonnull(conn);
	ack_handshake(conn->rdp.snd_iss);
	ck_assert_int_eq(conn->rdp.state, RDP_OPEN);
	return conn;
}

/* Deliver one in-order data packet. `seq` continues from the handshake's 1000.
   The RDP header is a *trailer* in libcsp: put_header_and_route writes it at
   `data[length]`, so the payload goes in first and the header lands after it. */
static void deliver_data(uint16_t seq, uint16_t ack_nr) {
	csp_packet_t * packet = new_rdp_packet();
	packet->data[0] = 'x';
	packet->length = 1;
	put_header_and_route(packet, RDP_ACK, seq, ack_nr);
}

/* With delayed acks off, every packet is acknowledged as it arrives. */
START_TEST(test_without_delayed_acks_every_packet_is_acknowledged)
{
	setup_stack();
	const csp_conn_t * conn = open_conn(0, 2);

	const uint16_t iss = conn->rdp.snd_iss;
	unsigned int before = test_tx_count;
	for (uint16_t i = 1; i <= 3; i++) {
		deliver_data((uint16_t)(1000 + i), iss);
	}
	const unsigned int acks = test_tx_count - before;

	ck_assert_uint_eq(acks, 3);

	if (ctest_tracing()) {
		ctest_trace_begin("rdp", "without_delayed_acks_every_packet_is_acknowledged", "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("delayed_acks", 0);
		ctest_trace_int("ack_delay_count", 2);
		ctest_trace_int("packets", 3);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("acks", (int64_t)acks);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
	(void)conn;
}
END_TEST

/* The delay count. `csp_rdp_should_ack` tests
 *
 *     csp_rdp_seq_after(rcv_cur, rcv_lsa + ack_delay_count)
 *
 * which is *strictly* after, so the ack fires once the outstanding count exceeds the
 * delay -- at count + 1, not at count. Measured rather than argued, because an
 * implementation using `>=` is off by exactly one packet and nothing else looks wrong. */
START_TEST(test_the_delay_count_fires_one_packet_after_it)
{
	setup_stack();
	const csp_conn_t * conn = open_conn(1, 2);

	/* The clock does not move, so the ack timeout cannot be what triggers it. */
	const uint16_t iss = conn->rdp.snd_iss;
	unsigned int acks_at[5];
	unsigned int before = test_tx_count;
	for (uint16_t i = 1; i <= 5; i++) {
		deliver_data((uint16_t)(1000 + i), iss);
		acks_at[i - 1] = test_tx_count - before;
	}

	if (ctest_tracing()) {
		ctest_trace_begin("rdp", "the_delay_count_fires_one_packet_after_it", "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("delayed_acks", 1);
		ctest_trace_int("ack_delay_count", 2);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_arr_begin("acks_after_n_packets");
		for (int i = 0; i < 5; i++) {
			ctest_trace_int(NULL, (int64_t)acks_at[i]);
		}
		ctest_trace_arr_end();
		ctest_trace_obj_end();
		ctest_trace_end();
	}

	/* Nothing before the count is exceeded. */
	ck_assert_uint_eq(acks_at[0], 0);
	ck_assert_uint_eq(acks_at[1], 0);
	/* And something after. */
	ck_assert_uint_gt(acks_at[4], 0);
	(void)conn;
}
END_TEST

/* Nothing has arrived since the last acknowledgement, and delayed acks are off. The C's
   first condition returns true unconditionally, so it acknowledges anyway -- an ack for a
   sequence number the peer already knows about. */
START_TEST(test_an_ack_is_sent_even_with_nothing_to_acknowledge)
{
	setup_stack();
	const csp_conn_t * conn = open_conn(0, 2);

	unsigned int before = test_tx_count;
	csp_rdp_check_ack((csp_conn_t *)conn);
	const unsigned int acks = test_tx_count - before;

	if (ctest_tracing()) {
		/* The port refuses to send this one; SCOPE.md records why. */
		ctest_trace_begin("rdp", "an_ack_is_sent_even_with_nothing_to_acknowledge", "diverges");
		ctest_trace_obj_begin("input");
		ctest_trace_int("delayed_acks", 0);
		ctest_trace_int("packets_since_last_ack", 0);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("acks", (int64_t)acks);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
	ck_assert_uint_eq(acks, 1);
}
END_TEST

/* `csp_rdp_check_ack` opens with
 *
 *     if (abs(CSP_CONN_RXQUEUE_LEN - csp_queue_size(conn->rx_queue)) < window_size) return;
 *
 * — acknowledge only while there is room for a full window still to arrive. That is
 * receiver-side flow control: an unread connection stops inviting data instead of accepting
 * it and dropping it. Nothing in the port's `poll_ack` corresponds to it.
 *
 * Measured as the packet number at which acknowledgements stop, with the application never
 * reading. Nothing here inspects the queue; it counts frames.
 */
START_TEST(test_acks_stop_when_the_application_is_not_reading)
{
	setup_stack();
	const csp_conn_t * conn = open_conn(0, 2);
	const uint16_t iss = conn->rdp.snd_iss;

	/* Deliver until the pool runs dry, never reading any of it. The bound is the buffer
	   pool, not the queue: CSP_BUFFER_COUNT is 15 and CSP_CONN_RXQUEUE_LEN is 16, so an
	   unread connection exhausts the node's buffers before its own queue is full. */
	unsigned int acks = 0;
	unsigned int last_acked_packet = 0;
	unsigned int delivered = 0;
	for (uint16_t i = 1; i <= CSP_CONN_RXQUEUE_LEN; i++) {
		if (csp_buffer_remaining() < 4) {
			break;
		}
		const unsigned int before = test_tx_count;
		deliver_data((uint16_t)(1000 + i), iss);
		delivered++;
		if (test_tx_count > before) {
			acks++;
			last_acked_packet = i;
		}
	}

	if (ctest_tracing()) {
		ctest_trace_begin("rdp", "acks_stop_when_the_application_is_not_reading", "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("delivered", (int64_t)delivered);
		ctest_trace_int("rxqueue_len", CSP_CONN_RXQUEUE_LEN);
		ctest_trace_int("buffer_count", CSP_BUFFER_COUNT);
		ctest_trace_int("window_size", (int64_t)conn->rdp.window_size);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("acks", (int64_t)acks);
		ctest_trace_int("last_acked_packet", (int64_t)last_acked_packet);
		ctest_trace_obj_end();
		ctest_trace_end();
	}

	ck_assert_uint_gt(delivered, 0);
	ck_assert_uint_gt(acks, 0);
	/* Whether the gate ever fires is what the recorded numbers say; asserting a specific
	   answer here would be asserting the reading this test exists to check. */
	ck_assert_uint_le(acks, delivered);
}
END_TEST

Suite * rdp_suite(void)
{
	return suite_create("RDP");
}

#endif
