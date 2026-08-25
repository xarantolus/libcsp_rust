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
#include <endian.h>
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
#include "hooks.h"

#define LOCAL_ADDR 10
#define PEER_ADDR 11
#define NETMASK 12

#define TEST_HOSTNAME "oracle-node"
#define TEST_MODEL "ctest-model"
#define TEST_REVISION "rev-1"

static csp_iface_t ingress_if;
/* A second interface that is not the default, so "the route CMP installed was used" is
   distinguishable from "the packet fell through to the default". */
static csp_iface_t routed_if;
static csp_socket_t sock;

/* The request the last helper actually sent, so the replay drives from it. */
static uint8_t sent[CSP_BUFFER_SIZE];
static size_t sent_len;

/* The last reply the node put on the wire — what a peer would see. */
static uint8_t reply[CSP_BUFFER_SIZE];
static int reply_len;
static unsigned int reply_count;
/* Which interface the last frame left by — the only way to tell a route apart from a
   default without reading the routing table. */
static char left_by[CSP_IFLIST_NAME_MAX + 1];

static int capture_tx(csp_iface_t * iface, uint16_t via, csp_packet_t * packet, int from_me) {
	(void)via;
	(void)from_me;
	reply_count++;
	if (iface != NULL && iface->name != NULL) {
		strncpy(left_by, iface->name, sizeof(left_by) - 1);
		left_by[sizeof(left_by) - 1] = '\0';
	}
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

	memset(&routed_if, 0, sizeof(routed_if));
	routed_if.addr = 40;
	routed_if.netmask = NETMASK;
	routed_if.name = "ROUTED";
	routed_if.nexthop = capture_tx;
	csp_iflist_add(&routed_if);

	/* libcsp does not serve CMP by itself: csp_service_handler is called by the
	   application from its own receive loop (examples/csp_server.c:77). Binding port 0 and
	   handing it what arrives is what a server does. */
	memset(&sock, 0, sizeof(sock));
	sock.opts = CSP_SO_CONN_LESS;
	csp_bind(&sock, CSP_CMP);
	csp_listen(&sock, CSP_CONN_RXQUEUE_LEN);

	reply_len = 0;
	reply_count = 0;
	left_by[0] = '\0';
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

	/* Snapshotted before the request, because the handler fills the block before the reply
	   is transmitted -- so the tx it reports is the count as of *asking*, not as of the
	   answer arriving. A node can never report the packet carrying its own report. */
	const uint32_t tx_at_ask = ingress_if.tx;
	const uint32_t txbytes_at_ask = ingress_if.txbytes;

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

/* --- PEEK and POKE ---
 *
 * hooks.c overrides the __weak csp_cmp_memcpy with a bounds-checked stub, so the only
 * memory these can touch is ctest_peek_region, addressed from CTEST_PEEK_BASE. The real
 * default is a bare memcpy: a node built with CMP and no override answers a peek from any
 * address and a poke to any address.
 */

#define PEEK_PATTERN_AT(i) ((uint8_t)(0xA0 + ((i) & 0x0f)))

static void fill_region(void) {
	uint8_t * region = ctest_peek_region();
	for (int i = 0; i < CTEST_PEEK_REGION_LEN; i++) {
		region[i] = PEEK_PATTERN_AT(i);
	}
}

/* Build a PEEK/POKE request. `total` is the number of bytes actually sent, which is
   deliberately separate from `len` — the C checks only that `total >= 7`, so a request can
   declare more data than it carries. */
static void peek_request(uint8_t code, uint32_t addr, uint8_t len, size_t total, uint8_t fill) {
	uint8_t body[CSP_BUFFER_SIZE];
	memset(body, fill, sizeof(body));
	body[0] = CSP_CMP_REQUEST;
	body[1] = code;
	body[2] = (uint8_t)(addr >> 24);
	body[3] = (uint8_t)(addr >> 16);
	body[4] = (uint8_t)(addr >> 8);
	body[5] = (uint8_t)addr;
	body[6] = len;
	request(body, total);
}

START_TEST(test_peek_returns_the_bytes_at_the_address)
{
	setup_stack();
	fill_region();

	const uint8_t len = 4;
	peek_request(CSP_CMP_PEEK, CTEST_PEEK_BASE + 16, len, CMP_PEEK_SIZE(len), 0x00);

	ck_assert_uint_eq(reply_count, 1);
	ck_assert_int_eq(reply_len, (int)CMP_PEEK_SIZE(len));
	/* The data sits at packed offset 7, right after type/code/addr/len. */
	for (int i = 0; i < len; i++) {
		ck_assert_uint_eq(reply[7 + i], PEEK_PATTERN_AT(16 + i));
	}

	record("peek_returns_the_bytes_at_the_address");
}
END_TEST

/* The declared reply length is CMP_PEEK_SIZE(len) = 10 + len, but the handler writes only
   `len` bytes at offset 7. Three bytes are therefore declared and never written by this
   exchange.

   What is in them depends entirely on what was already in the pooled buffer, and *that*
   depends on CSP_BUFFER_ZERO_CLEAR — which is why this test asserts the condition rather
   than the folklore. Here the request was sent full-size, so the tail holds the
   requester's own bytes coming back. */
START_TEST(test_the_peek_tail_echoes_the_requesters_own_bytes)
{
	setup_stack();
	fill_region();

	const uint8_t len = 4;
	peek_request(CSP_CMP_PEEK, CTEST_PEEK_BASE, len, CMP_PEEK_SIZE(len), 0x5A);

	ck_assert_uint_eq(reply_count, 1);
	ck_assert_int_eq(reply_len, (int)CMP_PEEK_SIZE(len));
	for (int i = 7 + len; i < reply_len; i++) {
		ck_assert_uint_eq(reply[i], 0x5A);
	}

	record("the_peek_tail_echoes_the_requesters_own_bytes");
}
END_TEST

/* The interesting case: a request carrying only the seven bytes the length check demands,
   declaring four bytes of data. The reply is still 14 bytes long, so bytes 11..14 were
   never written by either side of this exchange — they are whatever the buffer held. */
START_TEST(test_the_peek_tail_when_the_request_did_not_cover_it)
{
	setup_stack();
	fill_region();

	const uint8_t len = 4;
	peek_request(CSP_CMP_PEEK, CTEST_PEEK_BASE, len, 7, 0x00);

	ck_assert_uint_eq(reply_count, 1);
	ck_assert_int_eq(reply_len, (int)CMP_PEEK_SIZE(len));

	/* Recorded, not predicted. With CSP_BUFFER_ZERO_CLEAR the pool hands out cleared
	   buffers and these are zero; without it they are the previous user's bytes. */
	if (ctest_tracing()) {
		ctest_trace_begin("cmp", "the_peek_tail_when_the_request_did_not_cover_it", "must_match");
		ctest_trace_obj_begin("input");
		ctest_trace_hex("request", sent, sent_len);
		/* A build setting, so it belongs with the inputs: it is what the answer depends
		   on, not part of the answer. */
		ctest_trace_int("buffer_zero_clear", CSP_BUFFER_ZERO_CLEAR);
		ctest_trace_obj_end();
		ctest_trace_obj_begin("observed");
		ctest_trace_int("reply_len", reply_len);
		ctest_trace_hex("tail", &reply[7 + len], (size_t)reply_len - (7 + len));
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

#if !CSP_BUFFER_ZERO_CLEAR
/* The other half of the tail question, reachable only when the pool does not clear what it
   hands out. A previous packet's bytes are still in the buffer, and the three bytes the
   reply declares but never writes hand them straight back to whoever asked.

   Run with `just ctest-noclear`. In the canonical configuration this compiles out, because
   there the tail is zeros and asserting otherwise would be asserting folklore. */
START_TEST(test_the_peek_tail_leaks_the_previous_packet_when_the_pool_is_not_cleared)
{
	setup_stack();
	fill_region();

	/* Stamp every buffer in the pool, so whichever one the peek gets has been used before.
	   One allocate-and-free is not enough: the free list is a queue, so the next get comes
	   back with a different, never-used buffer. */
	for (int round = 0; round < 3; round++) {
		csp_packet_t * held[CSP_BUFFER_COUNT];
		int n = 0;
		for (; n < CSP_BUFFER_COUNT; n++) {
			held[n] = csp_buffer_get(0);
			if (held[n] == NULL) {
				break;
			}
			memset(held[n]->data, 0xC7, CSP_BUFFER_SIZE - 16);
		}
		ck_assert_int_gt(n, 0);
		for (int i = 0; i < n; i++) {
			csp_buffer_free(held[i]);
		}
	}

	/* Now the seven-byte minimum, declaring four bytes of data. */
	reply_count = 0;
	peek_request(CSP_CMP_PEEK, CTEST_PEEK_BASE, 4, 7, 0x00);

	ck_assert_uint_eq(reply_count, 1);
	ck_assert_int_eq(reply_len, (int)CMP_PEEK_SIZE(4));

	int leaked = 0;
	for (int i = 7 + 4; i < reply_len; i++) {
		if (reply[i] == 0xC7) {
			leaked++;
		}
	}
	ck_assert_int_gt(leaked, 0);
}
END_TEST
#endif

/* CSP_CMP_PEEK_MAX_LEN is 200 and the handler refuses above it — before calling memcpy,
   which is the only thing keeping a 255-byte read inside the packet buffer. */
START_TEST(test_peek_refuses_more_than_the_maximum)
{
	setup_stack();
	fill_region();

	peek_request(CSP_CMP_PEEK, CTEST_PEEK_BASE, CSP_CMP_PEEK_MAX_LEN + 1, 220, 0x00);

	ck_assert_uint_eq(reply_count, 0);
	record("peek_refuses_more_than_the_maximum");
}
END_TEST

/* An address the override refuses. The handler propagates the error, so the node answers
   nothing — a peek that fails is indistinguishable from a node that is not listening. */
START_TEST(test_peek_outside_the_permitted_window_gets_no_reply)
{
	setup_stack();
	fill_region();

	peek_request(CSP_CMP_PEEK, 0xDEAD0000, 4, CMP_PEEK_SIZE(4), 0x00);

	ck_assert_uint_eq(reply_count, 0);
	record("peek_outside_the_permitted_window_gets_no_reply");
}
END_TEST

START_TEST(test_poke_writes_the_bytes_at_the_address)
{
	setup_stack();
	fill_region();

	const uint8_t len = 4;
	uint8_t body[CSP_BUFFER_SIZE];
	memset(body, 0, sizeof(body));
	body[0] = CSP_CMP_REQUEST;
	body[1] = CSP_CMP_POKE;
	body[2] = 0;
	body[3] = 0;
	body[4] = (uint8_t)((CTEST_PEEK_BASE + 32) >> 8);
	body[5] = (uint8_t)(CTEST_PEEK_BASE + 32);
	body[6] = len;
	for (int i = 0; i < len; i++) {
		body[7 + i] = (uint8_t)(0xE0 + i);
	}
	request(body, CMP_POKE_SIZE(len));

	ck_assert_uint_eq(reply_count, 1);
	for (int i = 0; i < len; i++) {
		ck_assert_uint_eq(ctest_peek_region()[32 + i], (uint8_t)(0xE0 + i));
	}
	/* Neighbours untouched. */
	ck_assert_uint_eq(ctest_peek_region()[31], PEEK_PATTERN_AT(31));
	ck_assert_uint_eq(ctest_peek_region()[32 + len], PEEK_PATTERN_AT(32 + len));

	record("poke_writes_the_bytes_at_the_address");
}
END_TEST

/* POKE has a second length check that PEEK does not: the request has to actually carry the
   bytes it says it is writing. Without it the node would write whatever followed the packet
   into the target address. */
START_TEST(test_poke_refuses_to_write_bytes_the_request_did_not_carry)
{
	setup_stack();
	fill_region();

	/* Declares 64 bytes, sends the seven-byte minimum. */
	peek_request(CSP_CMP_POKE, CTEST_PEEK_BASE, 64, 7, 0x00);

	ck_assert_uint_eq(reply_count, 0);
	/* And nothing was written. */
	for (int i = 0; i < CTEST_PEEK_REGION_LEN; i++) {
		ck_assert_uint_eq(ctest_peek_region()[i], PEEK_PATTERN_AT(i));
	}

	record("poke_refuses_to_write_bytes_the_request_did_not_carry");
}
END_TEST

/* --- ROUTE_SET ---
 *
 * The question a test should ask is not "is there a table entry" but "does a packet for
 * that destination now leave by the named interface". These send a packet afterwards and
 * look at which wire it came out of.
 */

#define ROUTE_TARGET 200

/* Send a packet to ROUTE_TARGET and report the interface it left by, or "" for nothing. */
static const char * where_does_it_go(void) {
	left_by[0] = '\0';
	reply_count = 0;

	csp_packet_t * packet = csp_buffer_get(0);
	ck_assert_ptr_nonnull(packet);
	packet->id.pri = 2;
	packet->id.src = PEER_ADDR;
	packet->id.dst = ROUTE_TARGET;
	packet->id.dport = 20;
	packet->id.sport = 40;
	packet->id.flags = 0;
	memcpy(packet->data, "onward", 6);
	packet->length = 6;

	/* Injected as if from INGRESS. With no matching route the default (INGRESS) is where
	   it goes, so a route pointing at ROUTED is visibly different from no route at all —
	   which is the whole point of using a non-default interface as the target. */
	csp_qfifo_write(packet, &ingress_if, NULL);
	csp_route_work();
	return left_by;
}

static void route_set_v2(uint16_t dest, uint16_t via, uint16_t netmask, const char * iface) {
	uint8_t body[sizeof(struct csp_cmp_route_set_v2_msg)];
	memset(body, 0, sizeof(body));
	body[0] = CSP_CMP_REQUEST;
	body[1] = CSP_CMP_ROUTE_SET_V2;
	body[2] = (uint8_t)(dest >> 8);
	body[3] = (uint8_t)dest;
	body[4] = (uint8_t)(via >> 8);
	body[5] = (uint8_t)via;
	body[6] = (uint8_t)(netmask >> 8);
	body[7] = (uint8_t)netmask;
	strncpy((char *)&body[8], iface, CSP_CMP_ROUTE_IFACE_LEN - 1);
	request(body, sizeof(body));
}

START_TEST(test_route_set_v2_installs_a_route_that_is_used)
{
	setup_stack();

	/* Before: no route matches, so it falls through to the default -- which is the
	   interface it arrived on, and split horizon refuses to send it straight back. So
	   nothing goes anywhere, and "somewhere" afterwards is unambiguous. */
	ck_assert_str_eq(where_does_it_go(), "");

	route_set_v2(ROUTE_TARGET, 0, 14, "ROUTED");
	ck_assert_uint_eq(reply_count, 1);
	ck_assert_uint_eq(reply[0], CSP_CMP_REPLY);
	ck_assert_uint_eq(reply[1], CSP_CMP_ROUTE_SET_V2);
	/* Recorded here, not at the end: where_does_it_go() sends another frame and the
	   capture holds only the last one. Recording afterwards put "onward" in the corpus as
	   though it were the CMP reply. */
	record("route_set_v2_installs_a_route_that_is_used");

	/* After: the packet leaves by the interface the request named, not the default. */
	ck_assert_str_eq(where_does_it_go(), "ROUTED");
}
END_TEST

/* An interface the node does not have. The handler looks it up before touching the table,
   so nothing is installed and nothing is answered. */
START_TEST(test_route_set_v2_for_an_unknown_interface_changes_nothing)
{
	setup_stack();

	route_set_v2(ROUTE_TARGET, 0, 14, "NOSUCHIF");

	ck_assert_uint_eq(reply_count, 0);
	record("route_set_v2_for_an_unknown_interface_changes_nothing");

	/* Still nowhere, so no route was installed. */
	ck_assert_str_eq(where_does_it_go(), "");
}
END_TEST

START_TEST(test_route_set_v2_one_byte_short_changes_nothing)
{
	setup_stack();

	uint8_t body[sizeof(struct csp_cmp_route_set_v2_msg) - 1];
	memset(body, 0, sizeof(body));
	body[0] = CSP_CMP_REQUEST;
	body[1] = CSP_CMP_ROUTE_SET_V2;
	body[2] = (uint8_t)(ROUTE_TARGET >> 8);
	body[3] = (uint8_t)ROUTE_TARGET;
	body[7] = 14;
	strncpy((char *)&body[8], "ROUTED", 6);
	request(body, sizeof(body));

	ck_assert_uint_eq(reply_count, 0);
	record("route_set_v2_one_byte_short_changes_nothing");

	ck_assert_str_eq(where_does_it_go(), "");
}
END_TEST

/* The v1 form: single-byte addresses, and the netmask is not on the wire at all — the
   handler uses csp_id_get_host_bits() for it. */
START_TEST(test_route_set_v1_installs_a_route_that_is_used)
{
	setup_stack();

	uint8_t body[sizeof(struct csp_cmp_route_set_v1_msg)];
	memset(body, 0, sizeof(body));
	body[0] = CSP_CMP_REQUEST;
	body[1] = CSP_CMP_ROUTE_SET_V1;
	body[2] = ROUTE_TARGET;
	body[3] = 0;
	strncpy((char *)&body[4], "ROUTED", CSP_CMP_ROUTE_IFACE_LEN - 1);
	request(body, sizeof(body));

	ck_assert_uint_eq(reply_count, 1);
	ck_assert_uint_eq(reply[1], CSP_CMP_ROUTE_SET_V1);
	record("route_set_v1_installs_a_route_that_is_used");

	ck_assert_str_eq(where_does_it_go(), "ROUTED");
}
END_TEST

/* --- IF_STATS values --- */

/* The reply has to carry the counters, not just be the right shape. Traffic is driven
   first so they are non-zero: a test against an all-zero block would pass on an
   implementation that never filled it in. */
START_TEST(test_if_stats_reports_counters_that_moved)
{
	setup_stack();

	/* Three packets in on INGRESS, so rx and rxbytes are both non-zero. */
	for (int i = 0; i < 3; i++) {
		(void)where_does_it_go();
	}
	ck_assert_uint_gt(ingress_if.rx, 0);

	/* Snapshotted before the request, because the handler fills the block before the reply
	   is transmitted -- so the tx it reports is the count as of *asking*, not as of the
	   answer arriving. A node can never report the packet carrying its own report. */
	const uint32_t tx_at_ask = ingress_if.tx;
	const uint32_t txbytes_at_ask = ingress_if.txbytes;

	uint8_t body[offsetof(struct csp_cmp_if_stats_msg, tx)];
	memset(body, 0, sizeof(body));
	body[0] = CSP_CMP_REQUEST;
	body[1] = CSP_CMP_IF_STATS;
	strncpy((char *)&body[2], "INGRESS", CSP_CMP_ROUTE_IFACE_LEN - 1);
	request(body, sizeof(body));

	ck_assert_uint_eq(reply_count, 1);
	ck_assert_int_eq(reply_len, (int)sizeof(struct csp_cmp_if_stats_msg));

	const struct csp_cmp_if_stats_msg * msg = (const struct csp_cmp_if_stats_msg *)reply;
	ck_assert_str_eq(msg->interface, "INGRESS");
	/* Compared against the interface itself rather than a hardcoded number, so the test
	   does not have to know how libcsp counts -- only that the reply carries what the
	   interface holds, and that it is not zero. */
	ck_assert_uint_gt(be32toh(msg->rx), 0);
	ck_assert_uint_eq(be32toh(msg->rx), ingress_if.rx);
	ck_assert_uint_eq(be32toh(msg->rxbytes), ingress_if.rxbytes);
	ck_assert_uint_eq(be32toh(msg->tx), tx_at_ask);
	ck_assert_uint_eq(be32toh(msg->txbytes), txbytes_at_ask);
	/* And the reply's own transmission is not in it. */
	ck_assert_uint_eq(ingress_if.tx, tx_at_ask + 1);

	record("if_stats_reports_counters_that_moved");
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

	TCase * tc_route = tcase_create("route_set");
	tcase_add_test(tc_route, test_route_set_v2_installs_a_route_that_is_used);
	tcase_add_test(tc_route, test_route_set_v2_for_an_unknown_interface_changes_nothing);
	tcase_add_test(tc_route, test_route_set_v2_one_byte_short_changes_nothing);
	tcase_add_test(tc_route, test_route_set_v1_installs_a_route_that_is_used);
	tcase_add_test(tc_route, test_if_stats_reports_counters_that_moved);
	suite_add_tcase(s, tc_route);

	TCase * tc_mem = tcase_create("peek_poke");
	tcase_add_test(tc_mem, test_peek_returns_the_bytes_at_the_address);
	tcase_add_test(tc_mem, test_the_peek_tail_echoes_the_requesters_own_bytes);
	tcase_add_test(tc_mem, test_the_peek_tail_when_the_request_did_not_cover_it);
	tcase_add_test(tc_mem, test_peek_refuses_more_than_the_maximum);
	tcase_add_test(tc_mem, test_peek_outside_the_permitted_window_gets_no_reply);
	tcase_add_test(tc_mem, test_poke_writes_the_bytes_at_the_address);
	tcase_add_test(tc_mem, test_poke_refuses_to_write_bytes_the_request_did_not_carry);
#if !CSP_BUFFER_ZERO_CLEAR
	tcase_add_test(tc_mem, test_the_peek_tail_leaks_the_previous_packet_when_the_pool_is_not_cleared);
#endif
	suite_add_tcase(s, tc_mem);

	return s;
}
