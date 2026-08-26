/* SFP delivery, and what happens when the shape is wrong.
 *
 * A CSP port can receive two shapes: a plain datagram, or a stream of SFP fragments. Which
 * one arrived is on the wire, in the `CSP_FFRAG` flag, per packet — so an application that
 * reads one shape can be handed the other by any peer.
 *
 * `csp_sfp_header_remove` returns NULL the moment `CSP_FFRAG` is clear, and
 * `csp_sfp_recv_fp` responds by **freeing the packet** and returning `CSP_ERR_SFP` (-103),
 * the same code it uses for a corrupt fragment. A perfectly valid datagram is destroyed and
 * the caller is told the stream was malformed. `SCOPE.md` records this as a deliberate
 * divergence; these tests are what make it a measurement.
 */
#include <check.h>
#include <endian.h>
#include <string.h>

#include "clock.h"
#include "trace.h"

#include "csp/csp.h"
#include "csp/csp_buffer.h"
#include "csp/csp_id.h"
#include "csp/csp_iflist.h"
#include "csp/csp_interface.h"
#include "csp/csp_sfp.h"

#include "csp_conn.h"

#define LOCAL_ADDR 10
#define PEER_ADDR 11
#define TEST_PORT 12
#define NETMASK 12

typedef struct __attribute__((packed)) {
	uint32_t offset;
	uint32_t totalsize;
} sfp_header_t;

static csp_iface_t ingress_if;
static csp_socket_t sock;

/* What the application's write callback received. */
static uint8_t got[256];
static uint32_t got_len;
static unsigned int writes;

static int capture_write(const uint8_t * buffer, uint32_t size, uint32_t offset,
						 uint32_t totalsz, void * data) {
	(void)totalsz;
	(void)data;
	writes++;
	if (offset + size <= sizeof(got)) {
		memcpy(got + offset, buffer, size);
		if (offset + size > got_len) {
			got_len = offset + size;
		}
	}
	return CSP_ERR_NONE;
}

static const csp_sfp_recv_t receiver = { .write = capture_write };

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

	memset(&sock, 0, sizeof(sock));
	csp_bind(&sock, TEST_PORT);
	csp_listen(&sock, CSP_CONN_RXQUEUE_LEN);

	memset(got, 0, sizeof(got));
	got_len = 0;
	writes = 0;
	ctest_clock_set(CTEST_CLOCK_EPOCH_MS);
}

/* A packet as it would arrive from a peer. `frag` decides the shape. */
static csp_packet_t * make_packet(bool frag, const char * body, size_t len,
								  uint32_t offset, uint32_t totalsize) {
	csp_packet_t * packet = csp_buffer_get(0);
	ck_assert_ptr_nonnull(packet);
	packet->id.pri = 2;
	packet->id.src = PEER_ADDR;
	packet->id.dst = LOCAL_ADDR;
	packet->id.dport = TEST_PORT;
	packet->id.sport = 40;
	packet->id.flags = frag ? CSP_FFRAG : 0;
	memcpy(packet->data, body, len);
	packet->length = (uint16_t)len;

	if (frag) {
		sfp_header_t * h = (sfp_header_t *)&packet->data[packet->length];
		h->offset = htobe32(offset);
		h->totalsize = htobe32(totalsize);
		packet->length += sizeof(*h);
	}
	return packet;
}

/* A connection to hand csp_sfp_recv_fp, matching what would be accepted on TEST_PORT. */
static csp_conn_t * open_conn(void) {
	csp_conn_t * conn = csp_conn_allocate(CONN_SERVER);
	ck_assert_ptr_nonnull(conn);
	csp_id_t idin = { .pri = 2, .src = PEER_ADDR, .dst = LOCAL_ADDR,
					  .dport = TEST_PORT, .sport = 40, .flags = 0 };
	csp_id_t idout = { .pri = 2, .src = LOCAL_ADDR, .dst = PEER_ADDR,
					   .dport = 40, .sport = TEST_PORT, .flags = 0 };
	csp_conn_init(); /* idempotent; queues already exist */
	conn->idin = idin;
	conn->idout = idout;
	conn->state = CONN_OPEN;
	conn->type = CONN_SERVER;
	conn->opts = 0;
	return conn;
}

/* --- the shape that matches --- */

START_TEST(test_a_single_fragment_stream_is_delivered)
{
	setup_stack();
	const int before = csp_buffer_remaining();
	csp_conn_t * conn = open_conn();

	csp_packet_t * p = make_packet(true, "hello", 5, 0, 5);
	int ret = csp_sfp_recv_fp(conn, &receiver, 0, p);

	ck_assert_int_eq(ret, CSP_ERR_NONE);
	ck_assert_uint_eq(got_len, 5);
	ck_assert_mem_eq(got, "hello", 5);
	ck_assert_int_eq(csp_buffer_remaining(), before);

	if (ctest_tracing()) {
		ctest_trace_begin("sfp", "a_single_fragment_stream_is_delivered", "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_bool("frag_flag", true);
		ctest_trace_hex("body", (const uint8_t *)"hello", 5);
		ctest_trace_int("offset", 0);
		ctest_trace_int("totalsize", 5);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("ret", ret);
		ctest_trace_int("delivered_bytes", (int64_t)got_len);
		/* The C never hands a refused packet back, so this is 0 in every case here. It is
		   recorded on all of them anyway: a record whose fields differ from the replay's
		   compares unequal for free, which would make a `diverges` verdict pass without
		   ever looking at a value. */
		ctest_trace_int("recovered", 0);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

/* --- the shape that does not --- */

/* A plain datagram handed to a stream reader. The packet is well-formed and its payload is
   intact; the C frees it and reports CSP_ERR_SFP, which is also what it reports for a
   corrupt fragment. The caller cannot tell "you used the wrong reader" from "the peer sent
   rubbish", and either way the data is gone. */
START_TEST(test_a_plain_datagram_given_to_the_stream_reader_is_destroyed)
{
	setup_stack();
	const int before = csp_buffer_remaining();
	csp_conn_t * conn = open_conn();

	csp_packet_t * p = make_packet(false, "hello", 5, 0, 0);
	int ret = csp_sfp_recv_fp(conn, &receiver, 0, p);

	ck_assert_int_ne(ret, CSP_ERR_NONE);
	/* Nothing reached the application... */
	ck_assert_uint_eq(writes, 0);
	ck_assert_uint_eq(got_len, 0);
	/* ...and the packet is not available to try again with: it was freed. */
	ck_assert_int_eq(csp_buffer_remaining(), before);

	if (ctest_tracing()) {
		ctest_trace_begin("sfp", "a_plain_datagram_given_to_the_stream_reader_is_destroyed",
						  "diverges");
		ctest_trace_obj_begin("input");
		ctest_trace_bool("frag_flag", false);
		ctest_trace_hex("body", (const uint8_t *)"hello", 5);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("ret", ret);
		ctest_trace_int("delivered_bytes", (int64_t)got_len);
		ctest_trace_int("recovered", 0);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

/* The mismatch in the other direction, and the one an application hits without opting into
   anything: a peer sends a fragmented transfer, the receiver reads the connection with the
   ordinary datagram call. Nothing in `csp_route.c` looks at `CSP_FFRAG` -- the flag is read
   only inside `csp_sfp.c` -- so the packet is delivered like any other and the reader gets
   the body *with the 8-byte SFP header still on the end*, and no indication of it. This
   drives the real router and reads through the real socket, so it is the node's behaviour,
   not the helper's. */
START_TEST(test_a_fragment_read_as_a_datagram_keeps_the_sfp_header)
{
	setup_stack();
	const int before = csp_buffer_remaining();

	csp_packet_t * p = make_packet(true, "hello", 5, 0, 5);
	const uint16_t on_the_wire = p->length;
	csp_qfifo_write(p, &ingress_if, NULL);
	csp_route_work();

	csp_conn_t * conn = csp_accept(&sock, 0);
	ck_assert_ptr_nonnull(conn);
	csp_packet_t * got_p = csp_read(conn, 0);
	ck_assert_ptr_nonnull(got_p);

	/* The whole thing, trailer included. */
	ck_assert_uint_eq(got_p->length, on_the_wire);
	ck_assert_uint_eq(got_p->length, 5 + sizeof(sfp_header_t));
	const int flag_visible = (got_p->id.flags & CSP_FFRAG) != 0;

	uint8_t body[64];
	const uint16_t body_len = got_p->length > sizeof(body) ? sizeof(body) : got_p->length;
	memcpy(body, got_p->data, body_len);

	csp_buffer_free(got_p);
	csp_close(conn);
	ck_assert_int_eq(csp_buffer_remaining(), before);

	if (ctest_tracing()) {
		ctest_trace_begin("sfp", "a_fragment_read_as_a_datagram_keeps_the_sfp_header",
						  "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_bool("frag_flag", true);
		ctest_trace_hex("body", (const uint8_t *)"hello", 5);
		ctest_trace_int("totalsize", 5);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("delivered", 1);
		ctest_trace_int("delivered_len", (int64_t)body_len);
		ctest_trace_hex("delivered_body", body, body_len);
		ctest_trace_int("frag_flag_visible", flag_visible);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

/* The same error code the wrong-shape case produces, from a genuinely corrupt stream. This
   is what makes the previous test a problem rather than a curiosity: an application cannot
   distinguish them. */
START_TEST(test_a_corrupt_fragment_reports_the_same_error_as_a_wrong_shape)
{
	setup_stack();
	csp_conn_t * conn = open_conn();

	/* Offset past the declared total: a fragment that cannot belong to this transfer. */
	csp_packet_t * p = make_packet(true, "hello", 5, 99, 5);
	int corrupt_ret = csp_sfp_recv_fp(conn, &receiver, 0, p);

	setup_stack();
	conn = open_conn();
	p = make_packet(false, "hello", 5, 0, 0);
	int wrong_shape_ret = csp_sfp_recv_fp(conn, &receiver, 0, p);

	ck_assert_int_eq(corrupt_ret, wrong_shape_ret);

	if (ctest_tracing()) {
		/* The port distinguishes these two; SCOPE deviation 3 says why. */
		ctest_trace_begin("sfp", "a_corrupt_fragment_reports_the_same_error_as_a_wrong_shape",
						  "diverges");
		ctest_trace_obj_begin("observed");
		ctest_trace_int("corrupt_ret", corrupt_ret);
		ctest_trace_int("wrong_shape_ret", wrong_shape_ret);
		ctest_trace_bool("indistinguishable", corrupt_ret == wrong_shape_ret);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

/* A fragment whose header says it starts somewhere other than where the reassembly is. */
START_TEST(test_a_fragment_at_the_wrong_offset_is_refused)
{
	setup_stack();
	const int before = csp_buffer_remaining();
	csp_conn_t * conn = open_conn();

	csp_packet_t * p = make_packet(true, "world", 5, 5, 10);
	int ret = csp_sfp_recv_fp(conn, &receiver, 0, p);

	ck_assert_int_ne(ret, CSP_ERR_NONE);
	ck_assert_uint_eq(got_len, 0);
	ck_assert_int_eq(csp_buffer_remaining(), before);

	if (ctest_tracing()) {
		ctest_trace_begin("sfp", "a_fragment_at_the_wrong_offset_is_refused", "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_bool("frag_flag", true);
		ctest_trace_hex("body", (const uint8_t *)"world", 5);
		ctest_trace_int("offset", 5);
		ctest_trace_int("totalsize", 10);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("ret", ret);
		ctest_trace_int("delivered_bytes", (int64_t)got_len);
		ctest_trace_int("recovered", 0);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

/* A transfer declaring no bytes at all. It would look complete on arrival while carrying
   nothing, so it is refused rather than delivered as an empty message. */
START_TEST(test_a_zero_total_transfer_is_refused)
{
	setup_stack();
	csp_conn_t * conn = open_conn();

	csp_packet_t * p = make_packet(true, "hello", 5, 0, 0);
	int ret = csp_sfp_recv_fp(conn, &receiver, 0, p);

	ck_assert_int_ne(ret, CSP_ERR_NONE);
	ck_assert_uint_eq(got_len, 0);

	if (ctest_tracing()) {
		ctest_trace_begin("sfp", "a_zero_total_transfer_is_refused", "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_bool("frag_flag", true);
		ctest_trace_hex("body", (const uint8_t *)"hello", 5);
		ctest_trace_int("offset", 0);
		ctest_trace_int("totalsize", 0);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("ret", ret);
		ctest_trace_int("delivered_bytes", (int64_t)got_len);
		ctest_trace_int("recovered", 0);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

/* --- more than one fragment ---
 *
 * Every test above hands `csp_sfp_recv_fp` a single packet, so the do/while that actually
 * reassembles a transfer -- the `csp_read` at the bottom of the loop, the running
 * `data_offset`, the cross-fragment total check -- has never been executed against the C.
 * That is the whole of SFP; one fragment is the case where reassembly does nothing.
 */

/* Put a follow-on fragment where the reassembly loop's `csp_read` will find it. */
static void enqueue_fragment(csp_conn_t * conn, const char * body, size_t len,
							 uint32_t offset, uint32_t totalsize) {
	csp_packet_t * p = make_packet(true, body, len, offset, totalsize);
	ck_assert_int_eq(csp_conn_enqueue_packet(conn, p), CSP_ERR_NONE);
}

/* The fragments an input carries, traced identically by all three cases below. */
static void trace_fragments(const char * const * bodies, const uint32_t * offsets,
							const uint32_t * totals, size_t n) {
	ctest_trace_arr_begin("fragments");
	for (size_t i = 0; i < n; i++) {
		ctest_trace_obj_begin(NULL);
		ctest_trace_hex("body", (const uint8_t *)bodies[i], strlen(bodies[i]));
		ctest_trace_int("offset", (int64_t)offsets[i]);
		ctest_trace_int("totalsize", (int64_t)totals[i]);
		ctest_trace_obj_end();
	}
	ctest_trace_arr_end();
}

START_TEST(test_a_two_fragment_transfer_is_reassembled)
{
	setup_stack();
	const int before = csp_buffer_remaining();
	csp_conn_t * conn = open_conn();

	enqueue_fragment(conn, "world", 5, 5, 10);
	csp_packet_t * first = make_packet(true, "hello", 5, 0, 10);
	int ret = csp_sfp_recv_fp(conn, &receiver, 0, first);

	ck_assert_int_eq(ret, CSP_ERR_NONE);
	ck_assert_uint_eq(got_len, 10);
	ck_assert_mem_eq(got, "helloworld", 10);
	ck_assert_uint_eq(writes, 2);
	ck_assert_int_eq(csp_buffer_remaining(), before);

	if (ctest_tracing()) {
		static const char * bodies[] = { "hello", "world" };
		static const uint32_t offsets[] = { 0, 5 };
		static const uint32_t totals[] = { 10, 10 };
		ctest_trace_begin("sfp", "a_two_fragment_transfer_is_reassembled", "must_match");
		ctest_trace_obj_begin("input");
		trace_fragments(bodies, offsets, totals, 2);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("ret", ret);
		ctest_trace_int("writes", (int64_t)writes);
		ctest_trace_hex("assembled", got, got_len);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

/* A transfer whose later fragments never arrive.
 *
 * `csp_sfp_recv_fp` seeds `error = CSP_ERR_TIMEDOUT`, but every accepted fragment
 * overwrites it with the return of `user->write` -- and a successful write returns
 * `CSP_ERR_NONE`. When `csp_read` then comes back NULL the do/while ends and the function
 * falls into `error:`, returning whatever `error` last held. Whether that means half a
 * message is reported like a whole one is what this measures.
 */
START_TEST(test_a_transfer_that_stops_early_still_reports_its_last_write)
{
	setup_stack();
	const int before = csp_buffer_remaining();
	csp_conn_t * conn = open_conn();

	/* Ten bytes promised, five delivered, nothing queued behind it. */
	csp_packet_t * first = make_packet(true, "hello", 5, 0, 10);
	int ret = csp_sfp_recv_fp(conn, &receiver, 0, first);

	ck_assert_uint_eq(got_len, 5);
	ck_assert_uint_eq(writes, 1);
	ck_assert_int_eq(csp_buffer_remaining(), before);

	if (ctest_tracing()) {
		static const char * bodies[] = { "hello" };
		static const uint32_t offsets[] = { 0 };
		static const uint32_t totals[] = { 10 };
		ctest_trace_begin("sfp", "a_transfer_that_stops_early_still_reports_its_last_write",
						  "diverges");
		ctest_trace_obj_begin("input");
		trace_fragments(bodies, offsets, totals, 1);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("ret", ret);
		ctest_trace_int("writes", (int64_t)writes);
		ctest_trace_hex("assembled", got, got_len);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

/* The total is re-read from every fragment and must not change mid-transfer. Only
   reachable with two fragments, so nothing has exercised it. */
START_TEST(test_a_second_fragment_that_changes_the_total_is_refused)
{
	setup_stack();
	const int before = csp_buffer_remaining();
	csp_conn_t * conn = open_conn();

	enqueue_fragment(conn, "world", 5, 5, 99);
	csp_packet_t * first = make_packet(true, "hello", 5, 0, 10);
	int ret = csp_sfp_recv_fp(conn, &receiver, 0, first);

	ck_assert_int_eq(ret, CSP_ERR_SFP);
	/* The first fragment was already handed to the application before the second one was
	   seen, so a refused transfer still leaves a partial message with the caller. */
	ck_assert_uint_eq(got_len, 5);
	ck_assert_uint_eq(writes, 1);
	ck_assert_int_eq(csp_buffer_remaining(), before);

	if (ctest_tracing()) {
		static const char * bodies[] = { "hello", "world" };
		static const uint32_t offsets[] = { 0, 5 };
		static const uint32_t totals[] = { 10, 99 };
		ctest_trace_begin("sfp", "a_second_fragment_that_changes_the_total_is_refused",
						  "must_match");
		ctest_trace_obj_begin("input");
		trace_fragments(bodies, offsets, totals, 2);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("ret", ret);
		ctest_trace_int("writes", (int64_t)writes);
		ctest_trace_hex("assembled", got, got_len);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

/* The largest payload a fragment may carry, per option set.
 *
 * This is what decides how a message is cut up, so an MTU one byte too large produces
 * packets the peer's buffer cannot hold and one byte too small silently wastes a byte per
 * fragment on a link that is metered in bytes. The port's own test carried these four
 * numbers with a comment saying they were captured from `csp_sfp_opts_max_mtu` -- a
 * provenance claim with nothing behind it. Recorded here so they are measured.
 */
START_TEST(test_the_fragment_mtu_for_each_option_set)
{
	setup_stack();

	const uint32_t plain = csp_sfp_opts_max_mtu(0);
	const uint32_t rdp = csp_sfp_opts_max_mtu(CSP_O_RDP);
	const uint32_t crc = csp_sfp_opts_max_mtu(CSP_O_CRC32);
	const uint32_t hmac = csp_sfp_opts_max_mtu(CSP_O_HMAC);
	const uint32_t all = csp_sfp_opts_max_mtu(CSP_O_RDP | CSP_O_CRC32 | CSP_O_HMAC);

	/* Every option only ever subtracts. */
	ck_assert_uint_lt(rdp, plain);
	ck_assert_uint_lt(crc, plain);
	ck_assert_uint_lt(hmac, plain);
	ck_assert_uint_lt(all, rdp);

	if (ctest_tracing()) {
		ctest_trace_begin("sfp", "the_fragment_mtu_for_each_option_set", "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_int("buffer_size", CSP_BUFFER_SIZE);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("plain", (int64_t)plain);
		ctest_trace_int("rdp", (int64_t)rdp);
		ctest_trace_int("crc32", (int64_t)crc);
		ctest_trace_int("hmac", (int64_t)hmac);
		ctest_trace_int("all_three", (int64_t)all);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

Suite * sfp_suite(void)
{
	Suite * s = suite_create("SFP");

	TCase * tc = tcase_create("shape");
	tcase_add_test(tc, test_a_single_fragment_stream_is_delivered);
	tcase_add_test(tc, test_a_plain_datagram_given_to_the_stream_reader_is_destroyed);
	tcase_add_test(tc, test_a_fragment_read_as_a_datagram_keeps_the_sfp_header);
	tcase_add_test(tc, test_a_corrupt_fragment_reports_the_same_error_as_a_wrong_shape);
	tcase_add_test(tc, test_a_fragment_at_the_wrong_offset_is_refused);
	tcase_add_test(tc, test_a_zero_total_transfer_is_refused);
	tcase_add_test(tc, test_a_two_fragment_transfer_is_reassembled);
	tcase_add_test(tc, test_a_transfer_that_stops_early_still_reports_its_last_write);
	tcase_add_test(tc, test_a_second_fragment_that_changes_the_total_is_refused);
	tcase_add_test(tc, test_the_fragment_mtu_for_each_option_set);
	suite_add_tcase(s, tc);

	return s;
}
