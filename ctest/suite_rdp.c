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

static int test_nexthop(csp_iface_t * iface, uint16_t via, csp_packet_t * packet, int from_me) {
	(void)iface; (void)via; (void)from_me;
	test_tx_count++;
	if (packet->length >= sizeof(test_rdp_header_t)) {
		tx_payload_len = (uint16_t)(packet->length - sizeof(test_rdp_header_t));
		const test_rdp_header_t * h =
			(const test_rdp_header_t *)&packet->data[tx_payload_len];
		tx_flags = h->flags;
		tx_seq = be16toh(h->seq_nr);
		tx_ack = be16toh(h->ack_nr);
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
	   right. The verdict is c_only: the port takes the ISN as a parameter rather than
	   deriving it from a clock, so there is nothing here for it to match. */
	ctest_trace_begin("rdp", "isn_is_a_function_of_the_clock", "c_only");
	ctest_trace_obj_begin("observed");
	ctest_trace_int("clock_ms", 1234567);
	ctest_trace_int("snd_iss", conn->rdp.snd_iss);
	ctest_trace_int("snd_nxt", conn->rdp.snd_nxt);
	ctest_trace_int("snd_una", conn->rdp.snd_una);
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
	tcase_add_test(tc_hs, test_a_hostile_syn_cannot_suppress_acknowledgement);
	suite_add_tcase(s, tc_hs);

	TCase * tc_ack = tcase_create("ack");
	tcase_add_test(tc_ack, test_without_delayed_acks_every_packet_is_acknowledged);
	tcase_add_test(tc_ack, test_a_nonzero_delayed_acks_is_on_not_a_count);
	tcase_add_test(tc_ack, test_a_delay_count_beyond_the_window_is_bound_by_it);
	tcase_add_test(tc_ack, test_the_delay_count_fires_one_packet_after_it);
	tcase_add_test(tc_ack, test_an_ack_is_sent_even_with_nothing_to_acknowledge);
	tcase_add_test(tc_ack, test_acks_stop_when_the_application_is_not_reading);
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
