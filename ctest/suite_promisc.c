#include <check.h>
#include <stdbool.h>
#include <string.h>
#include <endian.h>

#include "clock.h"
#include "trace.h"

#include "csp/csp.h"
#include "csp/csp_id.h"
#include "csp/csp_iflist.h"
#include "csp/csp_interface.h"
#include "csp/csp_buffer.h"
#include "csp/csp_promisc.h"

#include "csp_promisc.h"

#define TEST_ADDR 10
#define PEER_ADDR 11

static csp_packet_t * make_packet(void) {
	csp_packet_t * packet = csp_buffer_get(0);
	ck_assert_ptr_nonnull(packet);

	packet->id.pri = 2;
	packet->id.src = PEER_ADDR;
	packet->id.dst = TEST_ADDR;
	packet->id.dport = 12;
	packet->id.sport = 40;
	packet->id.flags = 0;
	memcpy(packet->data, "hello", 5);
	packet->length = 5;

	return packet;
}

/* The promiscuous tap clones from the shared pool. It is a diagnostic feed, so
   it must never be able to starve the routing core. */
START_TEST(test_promisc_leaves_a_buffer_reserve)
{
	csp_init();
	ck_assert_int_eq(csp_promisc_enable(0), CSP_ERR_NONE);

	csp_packet_t * source = make_packet();

	/* Feed the tap far more traffic than the pool could ever hold. */
	for (int i = 0; i < CSP_BUFFER_COUNT * 4; i++) {
		csp_promisc_add(source);
		ck_assert_int_gt(csp_buffer_remaining(), 0);
	}

	/* Whatever the tap kept, real traffic can still allocate. */
	csp_packet_t * for_real_traffic = csp_buffer_get(0);
	ck_assert_ptr_nonnull(for_real_traffic);

	csp_buffer_free(for_real_traffic);
	csp_buffer_free(source);
	csp_promisc_disable();
}
END_TEST

/* csp_promisc_enable() ignores its argument and always sizes the queue to the
   compile-time CSP_CONN_RXQUEUE_LEN, so an oversized request must not be able
   to overrun the static backing buffer. */
START_TEST(test_promisc_queue_size_argument_is_ignored)
{
	csp_init();
	ck_assert_int_eq(csp_promisc_enable(1000000), CSP_ERR_NONE);

	csp_packet_t * source = make_packet();
	for (int i = 0; i < CSP_CONN_RXQUEUE_LEN * 4; i++) {
		csp_promisc_add(source);
	}

	/* Drain: no more than the compile-time queue depth can come back. */
	int drained = 0;
	csp_packet_t * p;
	while ((p = csp_promisc_read(0)) != NULL) {
		csp_buffer_free(p);
		drained++;
		ck_assert_int_le(drained, CSP_CONN_RXQUEUE_LEN);
	}
	ck_assert_int_le(drained, CSP_CONN_RXQUEUE_LEN);

	csp_buffer_free(source);
	csp_promisc_disable();
}
END_TEST

/* A disabled tap must not consume buffers at all. */
START_TEST(test_promisc_disabled_consumes_nothing)
{
	csp_init();
	ck_assert_int_eq(csp_promisc_enable(0), CSP_ERR_NONE);
	csp_promisc_disable();

	csp_packet_t * source = make_packet();
	const int free_before = csp_buffer_remaining();

	for (int i = 0; i < 32; i++) {
		csp_promisc_add(source);
	}

	ck_assert_int_eq(csp_buffer_remaining(), free_before);
	csp_buffer_free(source);
}
END_TEST

/* Every packet handed out by csp_promisc_read() is owned by the caller, and
   returning it to the pool must fully restore it. */
/* Two packets through the tap, both read back.
 *
 * A `read` that hands the packet over but leaves its slot occupied looks correct for a
 * single packet -- the queue count says empty, so the stale entry is never reached. It
 * shows up on the second round, when the count rises again and the stale slot is handed
 * out ahead of the new one: the application is given a buffer that was already released.
 * The single-packet case cannot see that, which is why this one exists.
 */
START_TEST(test_two_tapped_packets_come_back_once_each)
{
	csp_init();
	ck_assert_int_eq(csp_promisc_enable(0), CSP_ERR_NONE);
	const int before = csp_buffer_remaining();

	csp_packet_t * a = make_packet();
	csp_packet_t * b = make_packet();
	a->data[0] = 0xA1;
	b->data[0] = 0xB2;
	csp_promisc_add(a);
	csp_promisc_add(b);

	csp_packet_t * first = csp_promisc_read(0);
	ck_assert_ptr_nonnull(first);
	const uint8_t first_tag = first->data[0];
	csp_buffer_free(first);

	csp_packet_t * second = csp_promisc_read(0);
	ck_assert_ptr_nonnull(second);
	const uint8_t second_tag = second->data[0];
	ck_assert_ptr_ne(second, first);
	csp_buffer_free(second);

	const bool third_empty = (csp_promisc_read(0) == NULL);
	ck_assert(third_empty);

	csp_buffer_free(a);
	csp_buffer_free(b);
	csp_promisc_disable();
	ck_assert_int_eq(csp_buffer_remaining(), before);

	if (ctest_tracing()) {
		ctest_trace_begin("promisc", "two_tapped_packets_come_back_once_each", "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("packets_tapped", 2);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		/* Both tags seen, each once: the two reads returned different packets. */
		ctest_trace_int("first_tag", first_tag);
		ctest_trace_int("second_tag", second_tag);
		ctest_trace_int("tags_differ", first_tag != second_tag ? 1 : 0);
		ctest_trace_int("third_read_empty", third_empty ? 1 : 0);
		ctest_trace_int("buffers_lost", before - csp_buffer_remaining());
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

START_TEST(test_promisc_read_transfers_ownership)
{
	csp_init();
	ck_assert_int_eq(csp_promisc_enable(0), CSP_ERR_NONE);

	csp_packet_t * source = make_packet();
	const int free_with_source_held = csp_buffer_remaining();

	csp_promisc_add(source);
	ck_assert_int_lt(csp_buffer_remaining(), free_with_source_held);

	csp_packet_t * tapped = csp_promisc_read(0);
	ck_assert_ptr_nonnull(tapped);
	ck_assert_ptr_ne(tapped, source);
	ck_assert_uint_eq(tapped->length, source->length);
	ck_assert_mem_eq(tapped->data, source->data, source->length);

	csp_buffer_free(tapped);
	ck_assert_int_eq(csp_buffer_remaining(), free_with_source_held);

	const bool second_read_empty = (csp_promisc_read(0) == NULL);
	ck_assert(second_read_empty);

	csp_buffer_free(source);
	csp_promisc_disable();

	if (ctest_tracing()) {
		/* Eight assertions here and, until now, no record: the port was never compared on
		   any of it. The tap's ownership rules are a leak on one side and a double free on
		   the other, and neither shows up in the `tapped`/`delivered`/`forwarded` counts
		   the other promisc records carry. */
		ctest_trace_begin("promisc", "read_transfers_ownership", "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("packets_tapped", 1);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		/* The tap took a buffer of its own: it clones rather than aliasing the source. */
		ctest_trace_int("tap_consumed_a_buffer", 1);
		ctest_trace_int("tapped_is_a_distinct_packet", 1);
		ctest_trace_int("tapped_payload_matches", 1);
		/* Freeing what `read` handed back returned it, so `read` gave ownership away. */
		ctest_trace_int("buffers_back_after_free", 1);
		ctest_trace_int("second_read_empty", second_read_empty ? 1 : 0);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

/*
 * The Python binding's packet_get_id() re-packs csp_id_t into the on-wire CSPv1
 * identifier by hand, because a passive observer never sees the raw header. It
 * therefore hard-codes a bit layout. Pin that layout to what csp_id_prepend()
 * actually produces, so a change to either side fails here rather than silently
 * mislabelling captured traffic.
 */
START_TEST(test_csp1_id_layout_matches_the_binding)
{
	csp_conf.version = 1;
	csp_init();

	csp_packet_t * packet = make_packet();
	packet->id.pri = 3;
	packet->id.src = 21;
	packet->id.dst = 9;
	packet->id.dport = 63;
	packet->id.sport = 17;
	packet->id.flags = 0xA5;

	/* What the binding computes. */
	const uint32_t from_binding = (((uint32_t)(packet->id.pri) & 0x03U) << 30) |
								  (((uint32_t)(packet->id.src) & 0x1FU) << 25) |
								  (((uint32_t)(packet->id.dst) & 0x1FU) << 20) |
								  (((uint32_t)(packet->id.dport) & 0x3FU) << 14) |
								  (((uint32_t)(packet->id.sport) & 0x3FU) << 8) |
								  (((uint32_t)(packet->id.flags) & 0xFFU));

	/* What the library actually puts on the wire. */
	csp_id_prepend(packet);
	uint32_t on_wire;
	memcpy(&on_wire, packet->frame_begin, sizeof(on_wire));
	on_wire = be32toh(on_wire);

	ck_assert_uint_eq(from_binding, on_wire);

	csp_buffer_free(packet);
	csp_conf.version = 2;
}
END_TEST

/* --- the tap in the routing path ---
 *
 * libcsp's own promiscuous tests drive `csp_promisc_add` directly, which says nothing about
 * whether the router reaches it. `csp_route_work` places the tap after deduplication and
 * before the "is this for me" branch, and both halves of that placement are behaviour:
 *
 *   - **after dedup**, so a suppressed duplicate never reaches the tap — a diagnostic feed
 *     that showed frames the node discarded would misreport what the node acted on;
 *   - **before the branch**, so the tap sees traffic passing *through* the node as well as
 *     traffic addressed to it. A tap that only saw local packets would be blind on exactly
 *     the node where it is most useful, a router.
 */

#include "csp_qfifo.h"

#define TAP_LOCAL 10
#define TAP_EGRESS 20
#define TAP_ELSEWHERE 25
#define TAP_PORT 12
#define TAP_NETMASK 12

static csp_iface_t tap_ingress;
static csp_iface_t tap_egress;
static csp_socket_t tap_sock;
static unsigned int tap_forwarded;

static int tap_tx(csp_iface_t * iface, uint16_t via, csp_packet_t * packet, int from_me) {
	(void)iface;
	(void)via;
	(void)from_me;
	tap_forwarded++;
	csp_buffer_free(packet);
	return CSP_ERR_NONE;
}

static void tap_setup(bool promisc, uint8_t dedup_mode) {
	csp_init();

	memset(&tap_ingress, 0, sizeof(tap_ingress));
	tap_ingress.addr = TAP_LOCAL;
	tap_ingress.netmask = TAP_NETMASK;
	tap_ingress.name = "INGRESS";
	tap_ingress.nexthop = tap_tx;
	csp_iflist_add(&tap_ingress);

	memset(&tap_egress, 0, sizeof(tap_egress));
	tap_egress.addr = TAP_EGRESS;
	tap_egress.netmask = TAP_NETMASK;
	tap_egress.name = "EGRESS";
	tap_egress.nexthop = tap_tx;
	tap_egress.is_default = 1;
	csp_iflist_add(&tap_egress);

	memset(&tap_sock, 0, sizeof(tap_sock));
	tap_sock.opts = CSP_SO_CONN_LESS;
	csp_bind(&tap_sock, TAP_PORT);
	csp_listen(&tap_sock, CSP_CONN_RXQUEUE_LEN);

	csp_conf.dedup = dedup_mode;
	if (promisc) {
		ck_assert_int_eq(csp_promisc_enable(0), CSP_ERR_NONE);
	}
	tap_forwarded = 0;
	ctest_clock_set(CTEST_CLOCK_EPOCH_MS);
}

static void tap_route(uint16_t dst) {
	csp_packet_t * packet = csp_buffer_get(0);
	ck_assert_ptr_nonnull(packet);
	packet->id.pri = 2;
	packet->id.src = PEER_ADDR;
	packet->id.dst = dst;
	packet->id.dport = TAP_PORT;
	packet->id.sport = 40;
	packet->id.flags = 0;
	memcpy(packet->data, "watched", 7);
	packet->length = 7;
	csp_qfifo_write(packet, &tap_ingress, NULL);
	csp_route_work();
}

static unsigned int tap_drain(void) {
	unsigned int n = 0;
	csp_packet_t * p;
	while ((p = csp_promisc_read(0)) != NULL) {
		csp_buffer_free(p);
		n++;
	}
	return n;
}

static unsigned int socket_drain(void) {
	unsigned int n = 0;
	csp_packet_t * p;
	while ((p = csp_recvfrom(&tap_sock, 0)) != NULL) {
		csp_buffer_free(p);
		n++;
	}
	return n;
}

static void tap_record(const char * name, unsigned int tapped, unsigned int delivered,
					   unsigned int forwarded, int before) {
	if (!ctest_tracing()) {
		return;
	}
	ctest_trace_begin("promisc", name, "must_match");
	ctest_trace_obj_begin("observed");
	ctest_trace_int("tapped", (int64_t)tapped);
	ctest_trace_int("delivered", (int64_t)delivered);
	ctest_trace_int("forwarded", (int64_t)forwarded);
	ctest_trace_int("buffers_lost", before - csp_buffer_remaining());
	ctest_trace_obj_end();
	ctest_trace_end();
}

START_TEST(test_the_tap_sees_a_locally_delivered_packet)
{
	tap_setup(true, CSP_DEDUP_OFF);
	const int before = csp_buffer_remaining();

	tap_route(TAP_LOCAL);

	const unsigned int delivered = socket_drain();
	const unsigned int tapped = tap_drain();

	ck_assert_uint_eq(delivered, 1);
	ck_assert_uint_eq(tapped, 1);
	ck_assert_int_eq(csp_buffer_remaining(), before);
	tap_record("the_tap_sees_a_locally_delivered_packet", tapped, delivered, tap_forwarded, before);
}
END_TEST

/* The placement that matters on a router: traffic passing through is tapped too. */
START_TEST(test_the_tap_sees_a_forwarded_packet)
{
	tap_setup(true, CSP_DEDUP_OFF);
	const int before = csp_buffer_remaining();

	tap_route(TAP_ELSEWHERE);

	const unsigned int delivered = socket_drain();
	const unsigned int tapped = tap_drain();

	ck_assert_uint_eq(delivered, 0);
	ck_assert_uint_eq(tap_forwarded, 1);
	ck_assert_uint_eq(tapped, 1);
	ck_assert_int_eq(csp_buffer_remaining(), before);
	tap_record("the_tap_sees_a_forwarded_packet", tapped, delivered, tap_forwarded, before);
}
END_TEST

/* Deduplication runs first, so the tap reports what the node acted on rather than
   everything that arrived. */
START_TEST(test_the_tap_does_not_see_a_suppressed_duplicate)
{
	tap_setup(true, CSP_DEDUP_ALL);
	const int before = csp_buffer_remaining();

	tap_route(TAP_LOCAL);
	tap_route(TAP_LOCAL);

	const unsigned int delivered = socket_drain();
	const unsigned int tapped = tap_drain();

	ck_assert_uint_eq(delivered, 1);
	ck_assert_uint_eq(tapped, 1);
	ck_assert_int_eq(csp_buffer_remaining(), before);
	tap_record("the_tap_does_not_see_a_suppressed_duplicate", tapped, delivered, tap_forwarded, before);
}
END_TEST

/* With the tap off nothing is copied, and delivery is unchanged. */
START_TEST(test_delivery_is_the_same_with_the_tap_off)
{
	tap_setup(false, CSP_DEDUP_OFF);
	const int before = csp_buffer_remaining();

	tap_route(TAP_LOCAL);
	tap_route(TAP_ELSEWHERE);

	const unsigned int delivered = socket_drain();
	const unsigned int tapped = tap_drain();

	ck_assert_uint_eq(delivered, 1);
	ck_assert_uint_eq(tap_forwarded, 1);
	ck_assert_uint_eq(tapped, 0);
	ck_assert_int_eq(csp_buffer_remaining(), before);
	tap_record("delivery_is_the_same_with_the_tap_off", tapped, delivered, tap_forwarded, before);
}
END_TEST

Suite * promisc_suite(void)
{
	Suite * s;
	TCase * tc;

	s = suite_create("Promisc");

	tc = tcase_create("promisc");
	tcase_add_test(tc, test_promisc_leaves_a_buffer_reserve);
	tcase_add_test(tc, test_promisc_queue_size_argument_is_ignored);
	tcase_add_test(tc, test_promisc_disabled_consumes_nothing);
	tcase_add_test(tc, test_promisc_read_transfers_ownership);
	tcase_add_test(tc, test_two_tapped_packets_come_back_once_each);
	tcase_add_test(tc, test_csp1_id_layout_matches_the_binding);
	suite_add_tcase(s, tc);

	TCase * tc_route = tcase_create("routing");
	tcase_add_test(tc_route, test_the_tap_sees_a_locally_delivered_packet);
	tcase_add_test(tc_route, test_the_tap_sees_a_forwarded_packet);
	tcase_add_test(tc_route, test_the_tap_does_not_see_a_suppressed_duplicate);
	tcase_add_test(tc_route, test_delivery_is_the_same_with_the_tap_off);
	tc = tc_route;
	suite_add_tcase(s, tc);

	return s;
}
