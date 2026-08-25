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

static int test_nexthop(csp_iface_t * iface, uint16_t via, csp_packet_t * packet, int from_me) {
	(void)iface; (void)via; (void)from_me;
	test_tx_count++;
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

START_TEST(test_rdp_syn_without_options_is_rejected)
{
	setup_stack();

	/* No option block on the wire: nothing may be adopted from the buffer. */
	send_syn(NULL);

	ck_assert_ptr_null(find_rdp_conn());
	/* The sender is told, rather than left waiting. */
	ck_assert_uint_ge(test_tx_count, 1);
}
END_TEST

START_TEST(test_rdp_syn_with_partial_options_is_rejected)
{
	setup_stack();

	/* One word short of a complete block still walks off the end. */
	const uint32_t opts[5] = { 4, 10000, 1000, 1, 250 };
	send_syn_words(opts, 5);

	ck_assert_ptr_null(find_rdp_conn());
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

	/* The peer never acknowledges the SYN/ACK. */
	for (int i = 0; (i < 1000) && (find_rdp_conn() != NULL); i++) {
		csp_conn_check_timeouts();
		ctest_clock_advance(20);
	}

	ck_assert_ptr_null(find_rdp_conn());

	/* Retransmissions of the SYN/ACK, plus the RST that closes it. Bounded on
	   both sides: giving up immediately is as wrong as never giving up. */
	const unsigned int sent = test_tx_count - tx_after_syn;
	ck_assert_uint_ge(sent, CSP_RDP_MAX_RETRANSMITS);
	ck_assert_uint_le(sent, CSP_RDP_MAX_RETRANSMITS + 2);
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

	tc_queue = tcase_create("queue");
	tcase_add_test(tc_queue, test_rdp_queue_flush_all_releases_buffers);
	tcase_add_test(tc_queue, test_rdp_queue_flush_all_releases_receive_buffers);
	suite_add_tcase(s, tc_queue);

	return s;
}

#else /* !CSP_USE_RDP */

Suite * rdp_suite(void)
{
	return suite_create("RDP");
}

#endif
