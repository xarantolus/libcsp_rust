/* The connection table under pressure: what an application gets when it runs out, and
 * whether the node gets it back.
 *
 * A node has `CSP_CONN_MAX` connections and no way to make more. Every packet from a new
 * peer wants one, so a node talking to more peers than it has slots is the ordinary case,
 * not the exceptional one — and what matters is that running out costs nothing permanent.
 * `csp_route_deliver_connection` frees the packet when `csp_conn_new` returns NULL.
 *
 * Everything here is counted as connections the application could accept and buffers the
 * node still has. Neither is an internal detail: one is what the application sees, the other
 * is whether the node survives the next packet.
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

#include "csp_conn.h"
#include "csp_qfifo.h"

#define LOCAL_ADDR 10
#define TEST_PORT 12
#define NETMASK 12

static csp_iface_t ingress_if;
static csp_socket_t sock;

static int discard_tx(csp_iface_t * iface, uint16_t via, csp_packet_t * packet, int from_me) {
	(void)iface;
	(void)via;
	(void)from_me;
	csp_buffer_free(packet);
	return CSP_ERR_NONE;
}

static void setup_stack(void) {
	csp_init();

	memset(&ingress_if, 0, sizeof(ingress_if));
	ingress_if.addr = LOCAL_ADDR;
	ingress_if.netmask = NETMASK;
	ingress_if.name = "INGRESS";
	ingress_if.nexthop = discard_tx;
	ingress_if.is_default = 1;
	csp_iflist_add(&ingress_if);

	/* Connection-oriented: each distinct peer port becomes its own connection, which is
	   what makes the table the scarce resource. */
	memset(&sock, 0, sizeof(sock));
	csp_bind(&sock, TEST_PORT);
	csp_listen(&sock, CSP_CONN_RXQUEUE_LEN);

	ctest_clock_set(CTEST_CLOCK_EPOCH_MS);
}

/* One packet from a distinct peer port, so it cannot match an existing connection. */
static bool deliver_from(uint8_t sport) {
	csp_packet_t * packet = csp_buffer_get(0);
	if (packet == NULL) {
		return false;
	}
	packet->id.pri = 2;
	packet->id.src = 11;
	packet->id.dst = LOCAL_ADDR;
	packet->id.dport = TEST_PORT;
	packet->id.sport = sport;
	packet->id.flags = 0;
	memcpy(packet->data, "hi", 2);
	packet->length = 2;

	csp_qfifo_write(packet, &ingress_if, NULL);
	csp_route_work();
	return true;
}

/* How many connections the application can actually take, draining each. */
static unsigned int accept_all(void) {
	unsigned int n = 0;
	csp_conn_t * conn;
	while ((conn = csp_accept(&sock, 0)) != NULL) {
		csp_packet_t * p;
		while ((p = csp_read(conn, 0)) != NULL) {
			csp_buffer_free(p);
		}
		csp_close(conn);
		n++;
	}
	return n;
}

/* More peers than the node has slots. The surplus is refused, and refusing costs nothing:
   every buffer comes back. */
START_TEST(test_running_out_of_connections_costs_no_buffers)
{
	setup_stack();
	const int before = csp_buffer_remaining();

	/* Deliberately more than CSP_CONN_MAX, bounded by the pool since each accepted
	   connection holds its packet until read. */
	unsigned int offered = 0;
	for (uint8_t sport = 40; sport < 40 + (CSP_CONN_MAX * 2); sport++) {
		if (csp_buffer_remaining() < 2) {
			break;
		}
		if (!deliver_from(sport)) {
			break;
		}
		offered++;
	}

	const unsigned int accepted = accept_all();

	/* Every buffer is back: the refused packets were freed, and the accepted ones were
	   read and closed. A node that leaked one buffer per refused peer would run itself
	   out of memory by being talked to. */
	ck_assert_int_eq(csp_buffer_remaining(), before);
	ck_assert_uint_gt(offered, accepted);
	ck_assert_uint_gt(accepted, 0);

	if (ctest_tracing()) {
		ctest_trace_begin("conn", "running_out_of_connections_costs_no_buffers", "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("conn_max", CSP_CONN_MAX);
		ctest_trace_int("buffer_count", CSP_BUFFER_COUNT);
		ctest_trace_int("offered", (int64_t)offered);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("accepted", (int64_t)accepted);
		ctest_trace_int("buffers_lost", before - csp_buffer_remaining());
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

/* A closed connection is reusable. Without this the table is a one-shot resource and a node
   stops answering new peers after CSP_CONN_MAX of them have ever connected — which looks
   exactly like a leak but is not one. */
START_TEST(test_a_closed_connection_can_be_used_again)
{
	setup_stack();
	const int before = csp_buffer_remaining();

	unsigned int total = 0;
	/* Several rounds, each filling and draining the table. If slots were not returned the
	   later rounds would accept nothing. */
	unsigned int per_round[3];
	for (int round = 0; round < 3; round++) {
		for (uint8_t i = 0; i < CSP_CONN_MAX; i++) {
			if (csp_buffer_remaining() < 2) {
				break;
			}
			deliver_from((uint8_t)(40 + i));
		}
		per_round[round] = accept_all();
		total += per_round[round];
	}

	ck_assert_uint_gt(per_round[0], 0);
	/* The point: the last round is as productive as the first. */
	ck_assert_uint_eq(per_round[2], per_round[0]);
	ck_assert_int_eq(csp_buffer_remaining(), before);

	if (ctest_tracing()) {
		ctest_trace_begin("conn", "a_closed_connection_can_be_used_again", "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("conn_max", CSP_CONN_MAX);
		ctest_trace_int("buffer_count", CSP_BUFFER_COUNT);
		ctest_trace_int("rounds", 3);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("accepted_total", (int64_t)total);
		ctest_trace_arr_begin("accepted_per_round");
		for (int i = 0; i < 3; i++) {
			ctest_trace_int(NULL, (int64_t)per_round[i]);
		}
		ctest_trace_arr_end();
		ctest_trace_int("buffers_lost", before - csp_buffer_remaining());
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

/* A second packet from a peer already holding a connection joins it rather than consuming
   another slot. Otherwise a single chatty peer would exhaust the table on its own. */
START_TEST(test_a_second_packet_reuses_the_same_connection)
{
	setup_stack();

	deliver_from(40);
	deliver_from(40);

	csp_conn_t * conn = csp_accept(&sock, 0);
	ck_assert_ptr_nonnull(conn);

	unsigned int packets = 0;
	csp_packet_t * p;
	while ((p = csp_read(conn, 0)) != NULL) {
		csp_buffer_free(p);
		packets++;
	}
	csp_close(conn);

	/* Both packets on one connection... */
	ck_assert_uint_eq(packets, 2);
	/* ...and no second connection waiting. */
	ck_assert_ptr_null(csp_accept(&sock, 0));

	if (ctest_tracing()) {
		ctest_trace_begin("conn", "a_second_packet_reuses_the_same_connection", "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("packets_from_one_peer", 2);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("connections", 1);
		ctest_trace_int("packets_on_it", (int64_t)packets);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

/* A connection is offered to the application **once**, however many packets arrive on it.
 * `csp_route_deliver_connection` posts it to the socket and immediately nulls
 * `dest_socket` with the comment "Ensure that this connection will not be posted to this
 * socket again".
 *
 * The accept backlog is a fixed array. A node that re-posted a connection per packet would
 * let one chatty peer fill it with copies of itself, and every *other* peer's new
 * connection would then have nowhere to be announced — one peer starving the rest without
 * sending anything unusual.
 */
START_TEST(test_a_connection_is_offered_to_the_application_only_once)
{
	setup_stack();

	/* First packet: the connection appears. */
	deliver_from(40);
	csp_conn_t * conn = csp_accept(&sock, 0);
	ck_assert_ptr_nonnull(conn);
	csp_packet_t * p = csp_read(conn, 0);
	ck_assert_ptr_nonnull(p);
	csp_buffer_free(p);

	/* More packets on the same connection, with the application already holding it. */
	unsigned int extra_offers = 0;
	for (int i = 0; i < 3; i++) {
		deliver_from(40);
		if (csp_accept(&sock, 0) != NULL) {
			extra_offers++;
		}
	}

	/* Drain and close. */
	while ((p = csp_read(conn, 0)) != NULL) {
		csp_buffer_free(p);
	}
	csp_close(conn);

	ck_assert_uint_eq(extra_offers, 0);

	if (ctest_tracing()) {
		ctest_trace_begin("conn", "a_connection_is_offered_to_the_application_only_once",
						  "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("packets_after_accept", 3);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("extra_offers", (int64_t)extra_offers);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

Suite * conn_suite(void)
{
	Suite * s = suite_create("Conn");

	TCase * tc = tcase_create("table");
	tcase_add_test(tc, test_running_out_of_connections_costs_no_buffers);
	tcase_add_test(tc, test_a_closed_connection_can_be_used_again);
	tcase_add_test(tc, test_a_second_packet_reuses_the_same_connection);
	tcase_add_test(tc, test_a_connection_is_offered_to_the_application_only_once);
	suite_add_tcase(s, tc);

	return s;
}
