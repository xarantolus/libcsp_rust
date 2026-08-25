/* CMP served by a real node: which requests get an answer, and what the answer looks like.
 *
 * The thing worth measuring here is the **length contract**, because it is per-code and it
 * is not obvious from the message definitions:
 *
 *   - `IDENT` and `CLOCK` check the request against `sizeof(the whole reply)`. A client
 *     that sends a bare two-byte header gets **no reply at all** — `csp_cmp_handler`
 *     returns `CSP_ERR_INVAL` and `csp_service_handler` discards the packet without
 *     answering. The caller waits for its timeout and learns nothing.
 *   - `IF_STATS` checks only as far as `offsetof(msg, tx)`, so a request carrying just the
 *     interface name is enough.
 *
 * libcsp's own client always sends the full size (`csp_cmp_ident` passes
 * `sizeof(struct csp_cmp_ident_msg)`), which is why the asymmetry never bites there.
 *
 * Nothing here asserts the build date or time: `CSP_REPRODUCIBLE_BUILDS` is 0 in the
 * canonical configuration, so `csp_cmp_ident_handler` fills them from `__DATE__` and
 * `__TIME__` and they change with every rebuild. They are checked for being non-empty and
 * kept out of the corpus, so regeneration stays byte-stable.
 */
#include <check.h>
#include <stddef.h>
#include <string.h>

#include "clock.h"
#include "trace.h"

#include "csp/csp.h"
#include "csp/csp_buffer.h"
#include "csp/csp_cmp.h"
#include "csp/csp_id.h"
#include "csp/csp_iflist.h"
#include "csp/csp_interface.h"

#include "csp_qfifo.h"

#define LOCAL_ADDR 10
#define PEER_ADDR 11
#define NETMASK 12

#define TEST_HOSTNAME "oracle-node"
#define TEST_MODEL "ctest-model"
#define TEST_REVISION "rev-1"

static csp_iface_t ingress_if;
static csp_socket_t sock;

/* The request the last helper actually sent, so the replay drives from it. */
static uint8_t sent[CSP_BUFFER_SIZE];
static size_t sent_len;

/* The last reply the node put on the wire — what a peer would see. */
static uint8_t reply[CSP_BUFFER_SIZE];
static int reply_len;
static unsigned int reply_count;

static int capture_tx(csp_iface_t * iface, uint16_t via, csp_packet_t * packet, int from_me) {
	(void)iface;
	(void)via;
	(void)from_me;
	reply_count++;
	reply_len = packet->length;
	if (reply_len > (int)sizeof(reply)) {
		reply_len = (int)sizeof(reply);
	}
	memcpy(reply, packet->data, (size_t)reply_len);
	csp_buffer_free(packet);
	return CSP_ERR_NONE;
}

static void setup_stack(void) {
	csp_init();

	/* These are `const char *` in csp_conf_t, not arrays: point them at our literals
	   rather than copying into whatever they already point at. */
	csp_conf.hostname = TEST_HOSTNAME;
	csp_conf.model = TEST_MODEL;
	csp_conf.revision = TEST_REVISION;

	memset(&ingress_if, 0, sizeof(ingress_if));
	ingress_if.addr = LOCAL_ADDR;
	ingress_if.netmask = NETMASK;
	ingress_if.name = "INGRESS";
	ingress_if.nexthop = capture_tx;
	ingress_if.is_default = 1;
	csp_iflist_add(&ingress_if);

	/* libcsp does not serve CMP by itself: csp_service_handler is called by the
	   application from its own receive loop (examples/csp_server.c:77). Binding port 0 and
	   handing it what arrives is what a server does. */
	memset(&sock, 0, sizeof(sock));
	sock.opts = CSP_SO_CONN_LESS;
	csp_bind(&sock, CSP_CMP);
	csp_listen(&sock, CSP_CONN_RXQUEUE_LEN);

	reply_len = 0;
	reply_count = 0;
	ctest_clock_set(CTEST_CLOCK_EPOCH_MS);
}

/* Drain port 0 into the service handler, as a server would. */
static void serve(void) {
	csp_packet_t * p;
	while ((p = csp_recvfrom(&sock, 0)) != NULL) {
		csp_service_handler(p);
	}
}

/* Send `len` bytes of CMP body to port 0 and let the node answer if it wants to.
   `body` supplies type and code; the rest is zero. */
static void request(const uint8_t * body, size_t len) {
	csp_packet_t * packet = csp_buffer_get(0);
	ck_assert_ptr_nonnull(packet);

	packet->id.pri = 2;
	packet->id.src = PEER_ADDR;
	packet->id.dst = LOCAL_ADDR;
	packet->id.dport = CSP_CMP;
	packet->id.sport = 40;
	packet->id.flags = 0;
	memset(packet->data, 0, len);
	memcpy(packet->data, body, len);
	packet->length = (uint16_t)len;
	sent_len = len > sizeof(sent) ? sizeof(sent) : len;
	memcpy(sent, packet->data, sent_len);

	csp_qfifo_write(packet, &ingress_if, NULL);
	csp_route_work();
	serve();
}

/* A request of `len` bytes carrying just a type and a code. */
static void request_of(uint8_t type, uint8_t code, size_t len) {
	uint8_t body[2] = {type, code};
	ck_assert_uint_ge(len, sizeof(body));

	csp_packet_t * packet = csp_buffer_get(0);
	ck_assert_ptr_nonnull(packet);
	packet->id.pri = 2;
	packet->id.src = PEER_ADDR;
	packet->id.dst = LOCAL_ADDR;
	packet->id.dport = CSP_CMP;
	packet->id.sport = 40;
	packet->id.flags = 0;
	memset(packet->data, 0, len);
	memcpy(packet->data, body, sizeof(body));
	packet->length = (uint16_t)len;
	sent_len = len > sizeof(sent) ? sizeof(sent) : len;
	memcpy(sent, packet->data, sent_len);

	csp_qfifo_write(packet, &ingress_if, NULL);
	csp_route_work();
	serve();
}

static void record(const char * name) {
	if (!ctest_tracing()) {
		return;
	}
	ctest_trace_begin("cmp", name, "must_match");
	ctest_trace_obj_begin("input");
	ctest_trace_hex("request", sent, sent_len);
	ctest_trace_obj_end();
	ctest_trace_obj_begin("observed");
	ctest_trace_int("replies", (int64_t)reply_count);
	ctest_trace_int("reply_len", (int64_t)(reply_count ? reply_len : 0));
	ctest_trace_int("reply_type", reply_count ? reply[0] : -1);
	ctest_trace_int("reply_code", reply_count ? reply[1] : -1);
	ctest_trace_obj_end();
	ctest_trace_end();
}

/* --- dispatch --- */

/* A reply arriving where a request belongs is not answered: answering would let two nodes
   bounce a CMP message between them forever. */
START_TEST(test_a_reply_is_not_answered)
{
	setup_stack();
	request_of(CSP_CMP_REPLY, CSP_CMP_IDENT, sizeof(struct csp_cmp_ident_msg));

	ck_assert_uint_eq(reply_count, 0);
	record("a_reply_is_not_answered");
}
END_TEST

START_TEST(test_an_unknown_code_is_not_answered)
{
	setup_stack();
	request_of(CSP_CMP_REQUEST, 99, 64);

	ck_assert_uint_eq(reply_count, 0);
	record("an_unknown_code_is_not_answered");
}
END_TEST

/* One byte is not even a CMP header, and the handler checks before reading the code. */
START_TEST(test_a_packet_shorter_than_the_header_is_not_answered)
{
	setup_stack();
	uint8_t one = CSP_CMP_REQUEST;
	request(&one, 1);

	ck_assert_uint_eq(reply_count, 0);
	record("a_packet_shorter_than_the_header_is_not_answered");
}
END_TEST

/* --- IDENT --- */

/* The trap. A two-byte IDENT request is a well-formed CMP header asking a legal question,
   and the node says nothing at all. */
START_TEST(test_a_bare_ident_request_gets_no_reply)
{
	setup_stack();
	request_of(CSP_CMP_REQUEST, CSP_CMP_IDENT, 2);

	ck_assert_uint_eq(reply_count, 0);
	record("a_bare_ident_request_gets_no_reply");
}
END_TEST

/* The same question, asked in a buffer big enough to hold the answer. */
START_TEST(test_a_full_size_ident_request_is_answered)
{
	setup_stack();
	request_of(CSP_CMP_REQUEST, CSP_CMP_IDENT, sizeof(struct csp_cmp_ident_msg));

	ck_assert_uint_eq(reply_count, 1);
	ck_assert_int_eq(reply_len, (int)sizeof(struct csp_cmp_ident_msg));

	const struct csp_cmp_ident_msg * msg = (const struct csp_cmp_ident_msg *)reply;
	ck_assert_uint_eq(msg->type, CSP_CMP_REPLY);
	ck_assert_uint_eq(msg->code, CSP_CMP_IDENT);
	ck_assert_str_eq(msg->hostname, TEST_HOSTNAME);
	ck_assert_str_eq(msg->model, TEST_MODEL);
	ck_assert_str_eq(msg->revision, TEST_REVISION);
	/* Build date and time come from __DATE__/__TIME__ and change every rebuild, so only
	   their presence is asserted and they stay out of the corpus. */
	ck_assert_uint_gt(strlen(msg->date), 0);
	ck_assert_uint_gt(strlen(msg->time), 0);

	record("a_full_size_ident_request_is_answered");
}
END_TEST

/* One byte short is still short. The boundary is the whole reply, not "enough to be
   recognisable". */
START_TEST(test_an_ident_request_one_byte_short_gets_no_reply)
{
	setup_stack();
	request_of(CSP_CMP_REQUEST, CSP_CMP_IDENT, sizeof(struct csp_cmp_ident_msg) - 1);

	ck_assert_uint_eq(reply_count, 0);
	record("an_ident_request_one_byte_short_gets_no_reply");
}
END_TEST

/* --- IF_STATS --- */

/* Unlike IDENT, this one checks only as far as the interface name, so a request that
   carries the name and nothing else is answered with the full statistics block. */
START_TEST(test_if_stats_answers_a_name_only_request)
{
	setup_stack();

	uint8_t body[offsetof(struct csp_cmp_if_stats_msg, tx)];
	memset(body, 0, sizeof(body));
	body[0] = CSP_CMP_REQUEST;
	body[1] = CSP_CMP_IF_STATS;
	strncpy((char *)&body[2], "INGRESS", CSP_CMP_ROUTE_IFACE_LEN - 1);
	request(body, sizeof(body));

	ck_assert_uint_eq(reply_count, 1);
	ck_assert_int_eq(reply_len, (int)sizeof(struct csp_cmp_if_stats_msg));
	ck_assert_uint_eq(reply[0], CSP_CMP_REPLY);
	ck_assert_uint_eq(reply[1], CSP_CMP_IF_STATS);

	record("if_stats_answers_a_name_only_request");
}
END_TEST

START_TEST(test_if_stats_for_an_unknown_interface_gets_no_reply)
{
	setup_stack();

	uint8_t body[offsetof(struct csp_cmp_if_stats_msg, tx)];
	memset(body, 0, sizeof(body));
	body[0] = CSP_CMP_REQUEST;
	body[1] = CSP_CMP_IF_STATS;
	strncpy((char *)&body[2], "NOSUCHIF", CSP_CMP_ROUTE_IFACE_LEN - 1);
	request(body, sizeof(body));

	ck_assert_uint_eq(reply_count, 0);
	record("if_stats_for_an_unknown_interface_gets_no_reply");
}
END_TEST

/* --- CLOCK --- */

START_TEST(test_a_bare_clock_request_gets_no_reply)
{
	setup_stack();
	request_of(CSP_CMP_REQUEST, CSP_CMP_CLOCK, 2);

	ck_assert_uint_eq(reply_count, 0);
	record("a_bare_clock_request_gets_no_reply");
}
END_TEST

START_TEST(test_a_full_size_clock_request_is_answered)
{
	setup_stack();
	request_of(CSP_CMP_REQUEST, CSP_CMP_CLOCK, sizeof(struct csp_cmp_clock_msg));

	ck_assert_uint_eq(reply_count, 1);
	ck_assert_int_eq(reply_len, (int)sizeof(struct csp_cmp_clock_msg));
	ck_assert_uint_eq(reply[0], CSP_CMP_REPLY);
	ck_assert_uint_eq(reply[1], CSP_CMP_CLOCK);

	record("a_full_size_clock_request_is_answered");
}
END_TEST

/* The smallest request length that gets an answer, found by sweeping rather than read off
   the struct definitions — the point is what the node does, and IDENT and CLOCK are the two
   codes whose answer is surprising. Both are side-effect-free, so sweeping them is safe;
   ROUTE_SET and POKE change state and are covered by their own cases. */
static size_t smallest_answered_length(uint8_t code) {
	for (size_t len = 2; len <= 200; len++) {
		setup_stack();
		request_of(CSP_CMP_REQUEST, code, len);
		if (reply_count == 1) {
			return len;
		}
	}
	return 0;
}

START_TEST(test_the_minimum_request_length_is_the_whole_reply)
{
	const size_t ident = smallest_answered_length(CSP_CMP_IDENT);
	const size_t clock = smallest_answered_length(CSP_CMP_CLOCK);

	/* Not "a header plus something" — the request buffer has to be as big as the reply the
	   node intends to write back into it. A client that sends only what it knows gets
	   nothing and cannot tell why. */
	ck_assert_uint_eq(ident, sizeof(struct csp_cmp_ident_msg));
	ck_assert_uint_eq(clock, sizeof(struct csp_cmp_clock_msg));

	if (ctest_tracing()) {
		ctest_trace_begin("cmp", "the_minimum_request_length_is_the_whole_reply", "must_match");
		ctest_trace_obj_begin("observed");
		ctest_trace_int("ident_min", (int64_t)ident);
		ctest_trace_int("clock_min", (int64_t)clock);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

Suite * cmp_suite(void)
{
	Suite * s = suite_create("CMP");

	TCase * tc_dispatch = tcase_create("dispatch");
	tcase_add_test(tc_dispatch, test_a_reply_is_not_answered);
	tcase_add_test(tc_dispatch, test_an_unknown_code_is_not_answered);
	tcase_add_test(tc_dispatch, test_a_packet_shorter_than_the_header_is_not_answered);
	suite_add_tcase(s, tc_dispatch);

	TCase * tc_len = tcase_create("length");
	tcase_add_test(tc_len, test_a_bare_ident_request_gets_no_reply);
	tcase_add_test(tc_len, test_a_full_size_ident_request_is_answered);
	tcase_add_test(tc_len, test_an_ident_request_one_byte_short_gets_no_reply);
	tcase_add_test(tc_len, test_if_stats_answers_a_name_only_request);
	tcase_add_test(tc_len, test_if_stats_for_an_unknown_interface_gets_no_reply);
	tcase_add_test(tc_len, test_a_bare_clock_request_gets_no_reply);
	tcase_add_test(tc_len, test_a_full_size_clock_request_is_answered);
	tcase_add_test(tc_len, test_the_minimum_request_length_is_the_whole_reply);
	suite_add_tcase(s, tc_len);

	return s;
}
