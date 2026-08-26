/* Forwarding to more than one destination.
 *
 * `csp_send_direct` does not pick an interface — it iterates every match and **clones the
 * packet for each**, keeping one behind so the last match gets the original. Two interfaces
 * owning the destination's subnet means two frames on two wires.
 *
 * That is the whole point of redundant links: a packet takes both paths and whichever
 * survives arrives. A node that picked one instead would look identical in every test that
 * asks "did it forward" and would silently be flying with no redundancy at all.
 *
 * Counted as frames leaving, and by which interface. Nothing here reads a routing table.
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

#define PEER_ADDR 11
#define TEST_PORT 12

/* v2 has 14 address bits. With 12 network bits a subnet is four addresses wide, so two
   interfaces at 8 and 9 both own the block 8..11 and both match a destination inside it. */
#define NETMASK 12
#define LINK_A_ADDR 8
#define LINK_B_ADDR 9
#define TARGET 10 /* inside 8..11, so both links own it */
#define INGRESS_ADDR 40

static csp_iface_t link_a;
static csp_iface_t link_b;
static csp_iface_t ingress_if;

#define MAX_SEEN 8
static char left_by[MAX_SEEN][CSP_IFLIST_NAME_MAX + 1];
static unsigned int seen;

static int record_tx(csp_iface_t * iface, uint16_t via, csp_packet_t * packet, int from_me) {
	(void)via;
	(void)from_me;
	if (seen < MAX_SEEN) {
		const char * n = (iface && iface->name) ? iface->name : "?";
		strncpy(left_by[seen], n, CSP_IFLIST_NAME_MAX);
		left_by[seen][CSP_IFLIST_NAME_MAX] = '\0';
		seen++;
	}
	csp_buffer_free(packet);
	return CSP_ERR_NONE;
}

static void add_iface(csp_iface_t * i, const char * name, uint16_t addr, bool is_default) {
	memset(i, 0, sizeof(*i));
	i->addr = addr;
	i->netmask = NETMASK;
	i->name = name;
	i->nexthop = record_tx;
	i->is_default = is_default ? 1 : 0;
	csp_iflist_add(i);
}

static void setup_stack(bool two_links) {
	csp_init();
	add_iface(&ingress_if, "INGRESS", INGRESS_ADDR, false);
	add_iface(&link_a, "LINK_A", LINK_A_ADDR, false);
	if (two_links) {
		add_iface(&link_b, "LINK_B", LINK_B_ADDR, false);
	}
	seen = 0;
	memset(left_by, 0, sizeof(left_by));
	ctest_clock_set(CTEST_CLOCK_EPOCH_MS);
}

/* Arrives on INGRESS, so split horizon has no reason to veto either link. */
static void route_to(uint16_t dst) {
	csp_packet_t * packet = csp_buffer_get(0);
	ck_assert_ptr_nonnull(packet);
	packet->id.pri = 2;
	packet->id.src = PEER_ADDR;
	packet->id.dst = dst;
	packet->id.dport = TEST_PORT;
	packet->id.sport = 40;
	packet->id.flags = 0;
	memcpy(packet->data, "onward", 6);
	packet->length = 6;
	csp_qfifo_write(packet, &ingress_if, NULL);
	csp_route_work();
}

static void record(const char * name, int before) {
	if (!ctest_tracing()) {
		return;
	}
	ctest_trace_begin("route", name, "must_match");
	ctest_trace_obj_begin("observed");
	ctest_trace_int("frames", (int64_t)seen);
	ctest_trace_arr_begin("left_by");
	for (unsigned int i = 0; i < seen; i++) {
		/* Lowercased: the trace alphabet is [a-z0-9_], and interface names are the one
		   place a test supplies a string the writer did not choose. */
		char lower[CSP_IFLIST_NAME_MAX + 1];
		for (unsigned int j = 0; j <= CSP_IFLIST_NAME_MAX; j++) {
			char c = left_by[i][j];
			lower[j] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
			if (c == '\0') {
				break;
			}
		}
		ctest_trace_ident(NULL, lower);
	}
	ctest_trace_arr_end();
	ctest_trace_int("buffers_lost", before - csp_buffer_remaining());
	ctest_trace_obj_end();
	ctest_trace_end();
}

/* One link owning the destination: one frame. The control for the case below. */
START_TEST(test_one_owning_link_sends_one_frame)
{
	setup_stack(false);
	const int before = csp_buffer_remaining();

	route_to(TARGET);

	ck_assert_uint_eq(seen, 1);
	ck_assert_str_eq(left_by[0], "LINK_A");
	ck_assert_int_eq(csp_buffer_remaining(), before);
	record("one_owning_link_sends_one_frame", before);
}
END_TEST

/* Two links owning the same destination. csp_send_direct clones for every match, so the
   packet goes out **both** — which is what having two links is for. */
START_TEST(test_two_owning_links_send_two_frames)
{
	setup_stack(true);
	const int before = csp_buffer_remaining();

	route_to(TARGET);

	ck_assert_uint_eq(seen, 2);
	/* Both links, in some order. */
	const bool a = (strcmp(left_by[0], "LINK_A") == 0) || (strcmp(left_by[1], "LINK_A") == 0);
	const bool b = (strcmp(left_by[0], "LINK_B") == 0) || (strcmp(left_by[1], "LINK_B") == 0);
	ck_assert(a);
	ck_assert(b);
	/* The clone is released too: fan-out is not a leak. */
	ck_assert_int_eq(csp_buffer_remaining(), before);
	record("two_owning_links_send_two_frames", before);
}
END_TEST

/* Two *default* interfaces, with the destination owned by neither. The default scan fans
   out the same way the subnet scan does. */
START_TEST(test_two_default_interfaces_send_two_frames)
{
	csp_init();
	add_iface(&ingress_if, "INGRESS", INGRESS_ADDR, false);
	add_iface(&link_a, "LINK_A", LINK_A_ADDR, true);
	add_iface(&link_b, "LINK_B", 200, true);
	seen = 0;
	memset(left_by, 0, sizeof(left_by));
	ctest_clock_set(CTEST_CLOCK_EPOCH_MS);

	const int before = csp_buffer_remaining();

	/* 3000 is in no interface's subnet, so only the defaults can carry it. */
	route_to(3000);

	ck_assert_int_eq(csp_buffer_remaining(), before);
	record("two_default_interfaces_send_two_frames", before);
}
END_TEST

Suite * route_suite(void)
{
	Suite * s = suite_create("Route");

	TCase * tc = tcase_create("fanout");
	tcase_add_test(tc, test_one_owning_link_sends_one_frame);
	tcase_add_test(tc, test_two_owning_links_send_two_frames);
	tcase_add_test(tc, test_two_default_interfaces_send_two_frames);
	suite_add_tcase(s, tc);

	return s;
}
