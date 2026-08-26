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

#include "csp/csp_rtable.h"

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
/* The destination each frame actually carried. csp_send_direct rewrites it for a routed
   broadcast, so the dst that leaves is not always the dst that arrived. */
static uint16_t dst_on_wire[MAX_SEEN];
static unsigned int seen;

static int record_tx(csp_iface_t * iface, uint16_t via, csp_packet_t * packet, int from_me) {
	(void)via;
	(void)from_me;
	if (seen < MAX_SEEN) {
		const char * n = (iface && iface->name) ? iface->name : "?";
		strncpy(left_by[seen], n, CSP_IFLIST_NAME_MAX);
		left_by[seen][CSP_IFLIST_NAME_MAX] = '\0';
		dst_on_wire[seen] = packet->id.dst;
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
	memset(dst_on_wire, 0, sizeof(dst_on_wire));
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
	/* Every forwarding record carries the destination each frame left with, not only the
	   ones written to be about broadcast. The rewrite is invisible in the interface name
	   and the payload, so a record without this field describes a node that rewrote the
	   destination and one that did not equally well. */
	ctest_trace_arr_begin("dst_on_wire");
	for (unsigned int i = 0; i < seen; i++) {
		ctest_trace_int(NULL, (int64_t)dst_on_wire[i]);
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

/* A routed broadcast is rewritten on the way out.
 *
 * LINK_A is 8/12, so with 14 host bits it owns 8..11 and 11 is its broadcast address. A
 * packet addressed to 11 arriving from elsewhere matches LINK_A's subnet, and
 * `convert_broadcast` then rewrites the destination to `csp_id_get_max_nodeid()` (16383)
 * *before* the frame is built -- "rewrite routed broadcast (L3) to local (L2) when arriving
 * at the interface".
 *
 * This is observable on the wire and nowhere else: the interface it left by is unchanged,
 * the payload is unchanged, only the destination field differs. A node that skipped the
 * rewrite would pass every test that asks "did it forward" and would put an address on the
 * wire that a peer on a differently-masked subnet does not recognise as broadcast.
 */
START_TEST(test_a_routed_broadcast_leaves_as_the_local_broadcast)
{
	setup_stack(false);
	const int before = csp_buffer_remaining();

	/* 11 = LINK_A's subnet broadcast (8..11), and not LINK_A's own address. */
	route_to(11);

	ck_assert_uint_eq(seen, 1);
	ck_assert_str_eq(left_by[0], "LINK_A");
	/* Arrived addressed to 11, left addressed to the maximum node id. */
	ck_assert_uint_eq(dst_on_wire[0], 16383);

	record("a_routed_broadcast_leaves_as_the_local_broadcast", before);

}
END_TEST

/* The control: an ordinary unicast inside the same subnet is not rewritten. Without this
   the test above would also pass on a node that rewrote every destination. */
START_TEST(test_an_ordinary_destination_is_not_rewritten)
{
	setup_stack(false);
	const int before = csp_buffer_remaining();

	route_to(TARGET); /* 10: inside 8..11, but not the broadcast */

	ck_assert_uint_eq(seen, 1);
	ck_assert_uint_eq(dst_on_wire[0], TARGET);

	record("an_ordinary_destination_is_not_rewritten", before);

}
END_TEST

/* Two interfaces owning the same destination, where it is the broadcast address of only
 * one of them.
 *
 * LINK_A is 8/12 (owns 8..11, broadcast 11). LINK_C is 8/11 (owns 8..15, broadcast 15).
 * A packet to 11 matches both subnets, but 11 is broadcast only for LINK_A.
 *
 * `csp_send_direct` keeps **one** `idout_copy` across the whole loop and `convert_broadcast`
 * only ever writes to it, never clears it. So whether the second interface sees a rewritten
 * destination depends on what the first one did. This measures which, because the answer
 * decides whether the rewrite is per-egress-interface or sticky for the rest of the fan-out.
 */
START_TEST(test_a_broadcast_rewrite_carries_to_the_other_interface)
{
	csp_init();
	add_iface(&ingress_if, "INGRESS", INGRESS_ADDR, false);
	add_iface(&link_a, "LINK_A", LINK_A_ADDR, false);
	/* Same address, one bit wider: owns 8..15, so 11 is inside it but is not its
	   broadcast. */
	memset(&link_b, 0, sizeof(link_b));
	link_b.addr = LINK_A_ADDR;
	link_b.netmask = NETMASK - 1;
	link_b.name = "LINK_C";
	link_b.nexthop = record_tx;
	csp_iflist_add(&link_b);

	seen = 0;
	memset(left_by, 0, sizeof(left_by));
	memset(dst_on_wire, 0, sizeof(dst_on_wire));
	ctest_clock_set(CTEST_CLOCK_EPOCH_MS);
	const int before = csp_buffer_remaining();

	route_to(11);

	ck_assert_uint_eq(seen, 2);

	record("a_broadcast_rewrite_carries_to_the_other_interface", before);
}
END_TEST

/* Forwarding through the routing table rather than a subnet match.
 *
 * `csp_send_direct` reaches the table only when no interface owns the destination, and it
 * does **not** call `convert_broadcast` there -- the rewrite is in the subnet loop alone.
 * So a table-routed destination goes out exactly as it arrived.
 *
 * The other route cases all leave by a subnet or a default interface, so nothing measured
 * what the table path puts on the wire; a node that rewrote the destination there matched
 * every record.
 */
START_TEST(test_a_table_routed_destination_leaves_unchanged)
{
	setup_stack(false);
	/* 3000 is in no interface's subnet, so only the table can carry it. */
	ck_assert_int_eq(csp_rtable_set(3000, csp_id_get_host_bits(), &link_a, CSP_NO_VIA_ADDRESS),
					 CSP_ERR_NONE);
	const int before = csp_buffer_remaining();

	route_to(3000);

	ck_assert_uint_eq(seen, 1);
	ck_assert_str_eq(left_by[0], "LINK_A");
	ck_assert_uint_eq(dst_on_wire[0], 3000);

	record("a_table_routed_destination_leaves_unchanged", before);
}
END_TEST

/* An application send to an address a local interface's subnet owns.
 *
 * `csp_send_direct` tries local subnets **before** the routing table and before the
 * defaults, and a subnet match returns immediately. So a node with a default interface and
 * no route for the destination still sends it out the interface that owns it.
 *
 * Nothing measured this: every existing case reaches the wire through the routing table or
 * a default, so a node that skipped the subnet step entirely reproduced all of them and
 * would quietly put locally-attached traffic on the wrong link -- or, with no default
 * configured, fail to send it at all.
 */
START_TEST(test_a_local_subnet_beats_the_default_interface)
{
	csp_init();
	/* LINK_A owns 8..11. DEFAULT owns only itself but is marked default. */
	add_iface(&link_a, "LINK_A", LINK_A_ADDR, false);
	add_iface(&ingress_if, "DEFAULT", INGRESS_ADDR, true);

	seen = 0;
	memset(left_by, 0, sizeof(left_by));
	memset(dst_on_wire, 0, sizeof(dst_on_wire));
	ctest_clock_set(CTEST_CLOCK_EPOCH_MS);
	const int before = csp_buffer_remaining();

	csp_packet_t * packet = csp_buffer_get(0);
	ck_assert_ptr_nonnull(packet);
	memcpy(packet->data, "onward", 6);
	packet->length = 6;
	/* from_me: routed_from is NULL inside csp_send_direct. */
	csp_sendto(2, TARGET, TEST_PORT, 40, 0, packet);

	ck_assert_uint_eq(seen, 1);
	ck_assert_str_eq(left_by[0], "LINK_A");

	record("a_local_subnet_beats_the_default_interface", before);
}
END_TEST

/* The send-path twin of a_routed_broadcast_leaves_as_the_local_broadcast.
 *
 * `convert_broadcast` is not gated on `from_me`, so an application sending to a subnet
 * broadcast gets the same rewrite a forwarded one does. Only the forwarded direction was
 * measured, and the two are separate code paths in the port.
 */
START_TEST(test_an_application_send_to_a_broadcast_is_rewritten_too)
{
	csp_init();
	add_iface(&link_a, "LINK_A", LINK_A_ADDR, false);

	seen = 0;
	memset(left_by, 0, sizeof(left_by));
	memset(dst_on_wire, 0, sizeof(dst_on_wire));
	ctest_clock_set(CTEST_CLOCK_EPOCH_MS);
	const int before = csp_buffer_remaining();

	csp_packet_t * packet = csp_buffer_get(0);
	ck_assert_ptr_nonnull(packet);
	memcpy(packet->data, "onward", 6);
	packet->length = 6;
	csp_sendto(2, 11, TEST_PORT, 40, 0, packet); /* 11 = LINK_A's broadcast */

	ck_assert_uint_eq(seen, 1);
	ck_assert_str_eq(left_by[0], "LINK_A");
	ck_assert_uint_eq(dst_on_wire[0], 16383);

	record("an_application_send_to_a_broadcast_is_rewritten_too", before);
}
END_TEST

Suite * route_suite(void)
{
	Suite * s = suite_create("Route");

	TCase * tc = tcase_create("fanout");
	tcase_add_test(tc, test_one_owning_link_sends_one_frame);
	tcase_add_test(tc, test_two_owning_links_send_two_frames);
	tcase_add_test(tc, test_two_default_interfaces_send_two_frames);
	tcase_add_test(tc, test_a_routed_broadcast_leaves_as_the_local_broadcast);
	tcase_add_test(tc, test_an_ordinary_destination_is_not_rewritten);
	tcase_add_test(tc, test_a_broadcast_rewrite_carries_to_the_other_interface);
	tcase_add_test(tc, test_a_table_routed_destination_leaves_unchanged);
	tcase_add_test(tc, test_a_local_subnet_beats_the_default_interface);
	tcase_add_test(tc, test_an_application_send_to_a_broadcast_is_rewritten_too);
	suite_add_tcase(s, tc);

	return s;
}
