/* Deduplication: what the C actually suppresses, per mode.
 *
 * `csp_conf.dedup` is four-valued and `csp_route.c:238` combines it with `is_to_me`, so
 * the two middle modes are the whole point:
 *
 *     CSP_DEDUP_FWD       deduplicate only what is being routed onward
 *     CSP_DEDUP_INCOMING  deduplicate only what is addressed to this node
 *
 * The port had a single bool, which can only express OFF and ALL. These tests are what
 * says so — the bool was written from a reading of `csp_dedup.c`, which does not mention
 * the mode at all because the mode lives in the caller.
 *
 * Everything here needs the virtual clock: the window is 100 ms wide (`CSP_DEDUP_WINDOW_MS`),
 * so a real-clock test would be asserting that a machine ran fast enough.
 */
#include <check.h>
#include <string.h>

#include "clock.h"
#include "trace.h"

#include "csp/csp.h"
#include "csp/csp_buffer.h"
#include "csp/csp_id.h"
#include "csp/csp_iflist.h"
#include "csp/csp_interface.h"

#include "csp_qfifo.h"

#define LOCAL_ADDR 10  /* the address this node answers to */
#define EGRESS_ADDR 20 /* the interface a forwarded packet leaves by */
#define ELSEWHERE 25   /* some other node: not us, so it gets forwarded */
#define PEER_ADDR 11
#define TEST_PORT 12

/* v2 has 14 address bits. 8 network bits puts LOCAL_ADDR and ELSEWHERE in the same
   subnet as each other but keeps EGRESS out of it, which is what gives split horizon
   something to distinguish. */
#define NETMASK 12

static unsigned int forwarded_count;

static int capture_tx(csp_iface_t * iface, uint16_t via, csp_packet_t * packet, int from_me) {
	(void)iface;
	(void)via;
	(void)from_me;
	forwarded_count++;
	csp_buffer_free(packet);
	return CSP_ERR_NONE;
}

static csp_iface_t ingress_if;
static csp_iface_t egress_if;
static csp_socket_t sock;

static void setup_stack(unsigned int dedup_mode) {
	csp_init();

	memset(&ingress_if, 0, sizeof(ingress_if));
	ingress_if.addr = LOCAL_ADDR;
	ingress_if.netmask = NETMASK;
	ingress_if.name = "INGRESS";
	ingress_if.nexthop = capture_tx;
	csp_iflist_add(&ingress_if);

	memset(&egress_if, 0, sizeof(egress_if));
	egress_if.addr = EGRESS_ADDR;
	egress_if.netmask = NETMASK;
	egress_if.name = "EGRESS";
	egress_if.nexthop = capture_tx;
	egress_if.is_default = 1;
	csp_iflist_add(&egress_if);

	/* Connection-less, so "what the application received" is one csp_recvfrom away and
	   no connection state sits between the router and the answer. */
	memset(&sock, 0, sizeof(sock));
	sock.opts = CSP_SO_CONN_LESS;
	csp_bind(&sock, TEST_PORT);
	/* Needed even for a connection-less socket: csp_listen is what creates rx_queue, and
	   the conn-less delivery path enqueues straight onto it. */
	csp_listen(&sock, CSP_CONN_RXQUEUE_LEN);

	/* Read live by csp_route_work, so setting it after csp_init is fine — and necessary,
	   since csp_init clamps an out-of-range value to OFF. */
	csp_conf.dedup = (uint8_t)dedup_mode;

	forwarded_count = 0;
	ctest_clock_set(CTEST_CLOCK_EPOCH_MS);
}

/* Route one packet with the given destination. Byte-identical every time it is called
   with the same arguments, which is what makes the second one a duplicate. */
static void route_packet(uint16_t dst) {
	csp_packet_t * packet = csp_buffer_get(0);
	ck_assert_ptr_nonnull(packet);

	packet->id.pri = 2;
	packet->id.src = PEER_ADDR;
	packet->id.dst = dst;
	packet->id.dport = TEST_PORT;
	packet->id.sport = 40;
	packet->id.flags = 0;
	memcpy(packet->data, "identical", 9);
	packet->length = 9;

	csp_qfifo_write(packet, &ingress_if, NULL);
	csp_route_work();
}

/* How many packets the application can actually collect. */
static unsigned int drain_socket(void) {
	unsigned int n = 0;
	csp_packet_t * p;
	while ((p = csp_recvfrom(&sock, 0)) != NULL) {
		csp_buffer_free(p);
		n++;
	}
	return n;
}

/* Two identical packets to us, and two identical packets through us, under one mode.
   Recorded rather than asserted piecemeal, so the shape of the answer is one table. */
static void measure(unsigned int mode, const char * mode_name,
					unsigned int * delivered, unsigned int * forwarded) {
	setup_stack(mode);

	route_packet(LOCAL_ADDR);
	route_packet(LOCAL_ADDR);
	*delivered = drain_socket();

	route_packet(ELSEWHERE);
	route_packet(ELSEWHERE);
	*forwarded = forwarded_count;

	if (ctest_tracing()) {
		ctest_trace_begin("dedup", mode_name, "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("mode", (int64_t)mode);
		ctest_trace_int("pairs", 2);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("delivered_of_two", (int64_t)*delivered);
		ctest_trace_int("forwarded_of_two", (int64_t)*forwarded);
		/* The ingress interface's own drop counter. `csp_route_work` bumps it for every
		   packet deduplication discards (csp_route.c:244), which is the only place a
		   dropped duplicate is visible per link -- the driver never sees it, because the
		   packet has already left the driver. A record carrying only the delivered and
		   forwarded counts cannot tell a node that counts from one that does not. */
		ctest_trace_int("ingress_drop", (int64_t)ingress_if.drop);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}

START_TEST(test_dedup_off_suppresses_nothing)
{
	unsigned int delivered, forwarded;
	measure(CSP_DEDUP_OFF, "off_suppresses_nothing", &delivered, &forwarded);

	ck_assert_uint_eq(delivered, 2);
	ck_assert_uint_eq(forwarded, 2);
}
END_TEST

/* The mode a mesh wants: kill the loop, leave commands alone. */
START_TEST(test_dedup_fwd_suppresses_only_forwarded)
{
	unsigned int delivered, forwarded;
	measure(CSP_DEDUP_FWD, "fwd_suppresses_only_forwarded", &delivered, &forwarded);

	ck_assert_uint_eq(delivered, 2);
	ck_assert_uint_eq(forwarded, 1);
}
END_TEST

/* The opposite, and the one to be careful with: a ground station retransmitting an
   identical command inside the window loses the retransmission. */
START_TEST(test_dedup_incoming_suppresses_only_local)
{
	unsigned int delivered, forwarded;
	measure(CSP_DEDUP_INCOMING, "incoming_suppresses_only_local", &delivered, &forwarded);

	ck_assert_uint_eq(delivered, 1);
	ck_assert_uint_eq(forwarded, 2);
}
END_TEST

START_TEST(test_dedup_all_suppresses_both)
{
	unsigned int delivered, forwarded;
	measure(CSP_DEDUP_ALL, "all_suppresses_both", &delivered, &forwarded);

	ck_assert_uint_eq(delivered, 1);
	ck_assert_uint_eq(forwarded, 1);
}
END_TEST

/* Past the window the second copy is new again, so deduplication is a window and not a
   memory. 100 ms is CSP_DEDUP_WINDOW_MS; the clock makes this exact rather than racy. */
START_TEST(test_dedup_window_expires)
{
	setup_stack(CSP_DEDUP_ALL);

	route_packet(LOCAL_ADDR);
	ctest_clock_advance(101);
	route_packet(LOCAL_ADDR);

	ck_assert_uint_eq(drain_socket(), 2);
}
END_TEST

/* Inside the window it is still a duplicate, which is what pins the boundary above as a
   boundary rather than as "any advance re-admits it". */
START_TEST(test_dedup_inside_the_window_still_suppresses)
{
	setup_stack(CSP_DEDUP_ALL);

	route_packet(LOCAL_ADDR);
	ctest_clock_advance(99);
	route_packet(LOCAL_ADDR);

	ck_assert_uint_eq(drain_socket(), 1);
}
END_TEST

/* A different payload is a different frame, however close together they arrive. Without
   this the tests above would also pass on an implementation that dropped every second
   packet. */
START_TEST(test_dedup_does_not_suppress_a_different_packet)
{
	setup_stack(CSP_DEDUP_ALL);

	route_packet(LOCAL_ADDR);

	csp_packet_t * packet = csp_buffer_get(0);
	ck_assert_ptr_nonnull(packet);
	packet->id.pri = 2;
	packet->id.src = PEER_ADDR;
	packet->id.dst = LOCAL_ADDR;
	packet->id.dport = TEST_PORT;
	packet->id.sport = 40;
	packet->id.flags = 0;
	memcpy(packet->data, "different", 9);
	packet->length = 9;
	csp_qfifo_write(packet, &ingress_if, NULL);
	csp_route_work();

	ck_assert_uint_eq(drain_socket(), 2);
}
END_TEST

Suite * dedup_suite(void)
{
	Suite * s = suite_create("Dedup");

	TCase * tc_mode = tcase_create("mode");
	tcase_add_test(tc_mode, test_dedup_off_suppresses_nothing);
	tcase_add_test(tc_mode, test_dedup_fwd_suppresses_only_forwarded);
	tcase_add_test(tc_mode, test_dedup_incoming_suppresses_only_local);
	tcase_add_test(tc_mode, test_dedup_all_suppresses_both);
	suite_add_tcase(s, tc_mode);

	TCase * tc_window = tcase_create("window");
	tcase_add_test(tc_window, test_dedup_window_expires);
	tcase_add_test(tc_window, test_dedup_inside_the_window_still_suppresses);
	tcase_add_test(tc_window, test_dedup_does_not_suppress_a_different_packet);
	suite_add_tcase(s, tc_window);

	return s;
}
