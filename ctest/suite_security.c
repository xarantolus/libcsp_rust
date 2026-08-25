/* The endpoint's security policy: what `csp_route_security_check` accepts, what it
 * refuses, and which counter it charges.
 *
 * Three things here are worth having a test for rather than a reading:
 *
 *   1. **The counter split.** A CRC32 failure and a missing-but-required CRC32 charge
 *      `iface->rx_error`; the HMAC equivalents charge `iface->autherr`. They are different
 *      operational signals — one is a corrupt link, the other is an unauthenticated peer —
 *      and a port that merged them would lose the distinction silently.
 *   2. **The prohibitions do nothing.** `CSP_SO_HMACPROHIB` and `CSP_SO_RDPPROHIB` are
 *      read nowhere in `src/`; `CSP_SO_CRC32PROHIB` is read only by `csp_connect`, where
 *      it clears the *request* on an outgoing connection. No prohibition is enforced
 *      against a received packet, so a socket that prohibits authentication still accepts
 *      an authenticated one. These tests pin that, because "the option exists" reads as
 *      "the option works".
 *   3. **Order.** CRC32 is checked before HMAC, so a packet that fails both is reported as
 *      a CRC32 failure and charged to `rx_error`.
 */
#include <check.h>
#include <string.h>

#include "clock.h"
#include "trace.h"

#include "csp/csp.h"
#include "csp/csp_buffer.h"
#include "csp/csp_crc32.h"
#include "csp/csp_id.h"
#include "csp/csp_iflist.h"
#include "csp/csp_interface.h"
#include "csp/crypto/csp_hmac.h"

#include "csp/autoconfig.h"
#include "csp_qfifo.h"

#define LOCAL_ADDR 10
#define PEER_ADDR 11
#define TEST_PORT 12
#define NETMASK 12

static const char HMAC_KEY[] = "unit-test-key";

static csp_iface_t ingress_if;
static csp_socket_t sock;

/* What one packet's journey through the policy looked like. */
struct outcome {
	unsigned int delivered;
	/* Bytes the application actually got. Without this the accepting cases cannot tell a
	   verified packet from an unchecked one: both deliver, and only the *length* shows
	   whether the trailer was verified and removed. */
	unsigned int delivered_bytes;
	uint32_t rx_error;
	uint32_t autherr;
};

/* The inputs the last route_packet() actually used, so the record carries the scenario and
   not just its answer. A replay that re-declares the inputs on its own side can silently
   drift into testing something else and still pass. */
static struct {
	uint32_t socket_opts;
	uint8_t flags;
	int trailer;
	bool corrupt;
} used;

static void setup_stack(uint32_t socket_opts) {
	used.socket_opts = socket_opts;
	csp_init();

	memset(&ingress_if, 0, sizeof(ingress_if));
	ingress_if.addr = LOCAL_ADDR;
	ingress_if.netmask = NETMASK;
	ingress_if.name = "INGRESS";
	csp_iflist_add(&ingress_if);

	memset(&sock, 0, sizeof(sock));
	sock.opts = CSP_SO_CONN_LESS | socket_opts;
	csp_bind(&sock, TEST_PORT);
	csp_listen(&sock, CSP_CONN_RXQUEUE_LEN);

	csp_hmac_set_key(HMAC_KEY, (uint32_t)strlen(HMAC_KEY));
	ctest_clock_set(CTEST_CLOCK_EPOCH_MS);
}

/* Options for the trailer to attach, independent of the flags to advertise, so a test can
   claim a protection the packet does not carry. */
#define TRAILER_NONE 0
#define TRAILER_CRC32 1
#define TRAILER_HMAC 2
/* Both, in the order csp_send_direct appends them: MAC first, then the checksum over it
   (csp_io.c:250-271). This is the layering, and it is the case a receiver gets wrong by
   unwrapping innermost-first. */
#define TRAILER_HMAC_THEN_CRC32 3

static struct outcome route_packet(uint8_t flags, int trailer, bool corrupt) {
	used.flags = flags;
	used.trailer = trailer;
	used.corrupt = corrupt;

	csp_packet_t * packet = csp_buffer_get(0);
	ck_assert_ptr_nonnull(packet);

	packet->id.pri = 2;
	packet->id.src = PEER_ADDR;
	packet->id.dst = LOCAL_ADDR;
	packet->id.dport = TEST_PORT;
	packet->id.sport = 40;
	packet->id.flags = flags;
	memcpy(packet->data, "payload", 7);
	packet->length = 7;

	if (trailer == TRAILER_CRC32) {
		ck_assert_int_eq(csp_crc32_append(packet), CSP_ERR_NONE);
	} else if (trailer == TRAILER_HMAC) {
		ck_assert_int_eq(csp_hmac_append(packet, false), CSP_ERR_NONE);
	} else if (trailer == TRAILER_HMAC_THEN_CRC32) {
		ck_assert_int_eq(csp_hmac_append(packet, false), CSP_ERR_NONE);
		ck_assert_int_eq(csp_crc32_append(packet), CSP_ERR_NONE);
	}

	/* Damage the trailer, not the payload: the point is a check that fails, and a
	   corrupted payload would also change what the application compares. */
	if (corrupt) {
		packet->data[packet->length - 1] ^= 0xFF;
	}

	csp_qfifo_write(packet, &ingress_if, NULL);
	csp_route_work();

	struct outcome out = {0, 0, ingress_if.rx_error, ingress_if.autherr};
	csp_packet_t * p;
	while ((p = csp_recvfrom(&sock, 0)) != NULL) {
		out.delivered_bytes += p->length;
		csp_buffer_free(p);
		out.delivered++;
	}
	return out;
}

static void record(const char * name, const char * verdict, struct outcome o) {
	if (!ctest_tracing()) {
		return;
	}
	ctest_trace_begin("security", name, verdict);
	ctest_trace_obj_begin("input");
	ctest_trace_int("socket_opts", (int64_t)used.socket_opts);
	ctest_trace_int("flags", (int64_t)used.flags);
	ctest_trace_ident("trailer", used.trailer == TRAILER_CRC32 ? "crc32"
	                             : used.trailer == TRAILER_HMAC ? "hmac"
	                             : used.trailer == TRAILER_HMAC_THEN_CRC32 ? "hmac_then_crc32"
	                                                                       : "none");
	ctest_trace_bool("corrupt", used.corrupt);
	ctest_trace_obj_end();
	ctest_trace_obj_begin("observed");
	ctest_trace_int("delivered", (int64_t)o.delivered);
	ctest_trace_int("delivered_bytes", (int64_t)o.delivered_bytes);
	ctest_trace_int("rx_error", (int64_t)o.rx_error);
	ctest_trace_int("autherr", (int64_t)o.autherr);
	ctest_trace_obj_end();
	ctest_trace_end();
}

/* --- protections that are carried and verify --- */

START_TEST(test_plain_packet_with_no_policy_is_accepted)
{
	setup_stack(0);
	struct outcome o = route_packet(0, TRAILER_NONE, false);

	ck_assert_uint_eq(o.delivered, 1);
	ck_assert_uint_eq(o.rx_error, 0);
	ck_assert_uint_eq(o.autherr, 0);
	record("plain_packet_with_no_policy_is_accepted", "must_match", o);
}
END_TEST

START_TEST(test_a_valid_checksum_is_accepted)
{
	setup_stack(CSP_SO_CRC32REQ);
	struct outcome o = route_packet(CSP_FCRC32, TRAILER_CRC32, false);

	ck_assert_uint_eq(o.delivered, 1);
	ck_assert_uint_eq(o.rx_error, 0);
	record("a_valid_checksum_is_accepted", "must_match", o);
}
END_TEST

START_TEST(test_a_valid_mac_is_accepted)
{
	setup_stack(CSP_SO_HMACREQ);
	struct outcome o = route_packet(CSP_FHMAC, TRAILER_HMAC, false);

	ck_assert_uint_eq(o.delivered, 1);
	ck_assert_uint_eq(o.autherr, 0);
	record("a_valid_mac_is_accepted", "must_match", o);
}
END_TEST

/* The trailer is stripped before the application sees the packet, or every consumer would
   have to know which protections were negotiated to find the end of its own data. */
START_TEST(test_the_checksum_is_stripped_before_delivery)
{
	setup_stack(CSP_SO_CRC32REQ);

	csp_packet_t * packet = csp_buffer_get(0);
	ck_assert_ptr_nonnull(packet);
	packet->id.pri = 2;
	packet->id.src = PEER_ADDR;
	packet->id.dst = LOCAL_ADDR;
	packet->id.dport = TEST_PORT;
	packet->id.sport = 40;
	packet->id.flags = CSP_FCRC32;
	memcpy(packet->data, "payload", 7);
	packet->length = 7;
	ck_assert_int_eq(csp_crc32_append(packet), CSP_ERR_NONE);
	ck_assert_uint_eq(packet->length, 11);

	csp_qfifo_write(packet, &ingress_if, NULL);
	csp_route_work();

	csp_packet_t * got = csp_recvfrom(&sock, 0);
	ck_assert_ptr_nonnull(got);
	ck_assert_uint_eq(got->length, 7);
	ck_assert_mem_eq(got->data, "payload", 7);
	csp_buffer_free(got);
}
END_TEST

/* --- protections that fail --- */

START_TEST(test_a_bad_checksum_is_refused_as_a_receive_error)
{
	setup_stack(0);
	struct outcome o = route_packet(CSP_FCRC32, TRAILER_CRC32, true);

	ck_assert_uint_eq(o.delivered, 0);
	ck_assert_uint_eq(o.rx_error, 1);
	ck_assert_uint_eq(o.autherr, 0);
	record("a_bad_checksum_is_refused_as_a_receive_error", "must_match", o);
}
END_TEST

START_TEST(test_a_bad_mac_is_refused_as_an_authentication_error)
{
	setup_stack(0);
	struct outcome o = route_packet(CSP_FHMAC, TRAILER_HMAC, true);

	ck_assert_uint_eq(o.delivered, 0);
	ck_assert_uint_eq(o.autherr, 1);
	ck_assert_uint_eq(o.rx_error, 0);
	record("a_bad_mac_is_refused_as_an_authentication_error", "must_match", o);
}
END_TEST

/* --- protections that are required and absent --- */

START_TEST(test_a_required_checksum_that_is_absent_is_refused)
{
	setup_stack(CSP_SO_CRC32REQ);
	struct outcome o = route_packet(0, TRAILER_NONE, false);

	ck_assert_uint_eq(o.delivered, 0);
	ck_assert_uint_eq(o.rx_error, 1);
	ck_assert_uint_eq(o.autherr, 0);
	record("a_required_checksum_that_is_absent_is_refused", "must_match", o);
}
END_TEST

START_TEST(test_a_required_mac_that_is_absent_is_refused)
{
	setup_stack(CSP_SO_HMACREQ);
	struct outcome o = route_packet(0, TRAILER_NONE, false);

	ck_assert_uint_eq(o.delivered, 0);
	ck_assert_uint_eq(o.autherr, 1);
	ck_assert_uint_eq(o.rx_error, 0);
	record("a_required_mac_that_is_absent_is_refused", "must_match", o);
}
END_TEST

START_TEST(test_required_reliability_that_is_absent_is_refused)
{
	setup_stack(CSP_SO_RDPREQ);
	struct outcome o = route_packet(0, TRAILER_NONE, false);

	ck_assert_uint_eq(o.delivered, 0);
	/* Reliability is charged to rx_error, not autherr: it is not an authentication
	   question. */
	ck_assert_uint_eq(o.rx_error, 1);
	ck_assert_uint_eq(o.autherr, 0);
	record("required_reliability_that_is_absent_is_refused", "must_match", o);
}
END_TEST

/* Both protections at once, which is what a node that cares about its link would use.
   The checksum is the outer trailer and covers the MAC, so a receiver has to strip it
   before the MAC can be verified over the right bytes. */
START_TEST(test_both_protections_together_are_accepted)
{
	setup_stack(CSP_SO_CRC32REQ | CSP_SO_HMACREQ);
	struct outcome o = route_packet(CSP_FCRC32 | CSP_FHMAC, TRAILER_HMAC_THEN_CRC32, false);

	ck_assert_uint_eq(o.delivered, 1);
	ck_assert_uint_eq(o.rx_error, 0);
	ck_assert_uint_eq(o.autherr, 0);
	record("both_protections_together_are_accepted", "must_match", o);
}
END_TEST

/* Damaging the outer checksum is a checksum failure, not an authentication one: the MAC
   is never reached. */
START_TEST(test_a_damaged_outer_checksum_is_not_an_authentication_failure)
{
	setup_stack(CSP_SO_CRC32REQ | CSP_SO_HMACREQ);
	struct outcome o = route_packet(CSP_FCRC32 | CSP_FHMAC, TRAILER_HMAC_THEN_CRC32, true);

	ck_assert_uint_eq(o.delivered, 0);
	ck_assert_uint_eq(o.rx_error, 1);
	ck_assert_uint_eq(o.autherr, 0);
	record("a_damaged_outer_checksum_is_not_an_authentication_failure", "must_match", o);
}
END_TEST

/* --- order --- */

/* A packet that fails the checksum *and* carries an unverifiable MAC is reported as a
   checksum failure, because CRC32 is checked first and the function returns. An operator
   reading the counters sees a corrupt link, not an attack. */
START_TEST(test_checksum_is_checked_before_authentication)
{
	setup_stack(CSP_SO_CRC32REQ | CSP_SO_HMACREQ);
	struct outcome o = route_packet(CSP_FCRC32 | CSP_FHMAC, TRAILER_CRC32, true);

	ck_assert_uint_eq(o.delivered, 0);
	ck_assert_uint_eq(o.rx_error, 1);
	ck_assert_uint_eq(o.autherr, 0);
	record("checksum_is_checked_before_authentication", "must_match", o);
}
END_TEST

/* --- the flag drives verification, the policy only drives "must be present" --- */

/* No option is set, so nothing is *required* — but the packet claims a MAC, and a claimed
   MAC is always verified. Otherwise an attacker could turn verification off by setting a
   flag. */
START_TEST(test_a_claimed_mac_is_verified_even_when_not_required)
{
	setup_stack(0);
	struct outcome o = route_packet(CSP_FHMAC, TRAILER_HMAC, true);

	ck_assert_uint_eq(o.delivered, 0);
	ck_assert_uint_eq(o.autherr, 1);
	record("a_claimed_mac_is_verified_even_when_not_required", "must_match", o);
}
END_TEST

START_TEST(test_a_claimed_checksum_is_verified_even_when_not_required)
{
	setup_stack(0);
	struct outcome o = route_packet(CSP_FCRC32, TRAILER_CRC32, false);

	ck_assert_uint_eq(o.delivered, 1);
	ck_assert_uint_eq(o.rx_error, 0);
	record("a_claimed_checksum_is_verified_even_when_not_required", "must_match", o);
}
END_TEST

/* --- the prohibitions, which do nothing --- */

/* `CSP_SO_HMACPROHIB` is read nowhere in src/. A socket that prohibits authentication
   accepts an authenticated packet exactly as if the option were absent. */
START_TEST(test_prohibiting_authentication_does_not_refuse_it)
{
	setup_stack(CSP_SO_HMACPROHIB);
	struct outcome o = route_packet(CSP_FHMAC, TRAILER_HMAC, false);

	ck_assert_uint_eq(o.delivered, 1);
	ck_assert_uint_eq(o.autherr, 0);
	record("prohibiting_authentication_does_not_refuse_it", "must_match", o);
}
END_TEST

/* `CSP_SO_CRC32PROHIB` is read only by csp_connect, on the outgoing side. */
START_TEST(test_prohibiting_a_checksum_does_not_refuse_it)
{
	setup_stack(CSP_SO_CRC32PROHIB);
	struct outcome o = route_packet(CSP_FCRC32, TRAILER_CRC32, false);

	ck_assert_uint_eq(o.delivered, 1);
	ck_assert_uint_eq(o.rx_error, 0);
	record("prohibiting_a_checksum_does_not_refuse_it", "must_match", o);
}
END_TEST

/* `CSP_SO_RDPPROHIB` is read nowhere at all — not even by csp_connect. */
START_TEST(test_prohibiting_reliability_does_not_refuse_it)
{
	setup_stack(CSP_SO_RDPPROHIB);
	struct outcome o = route_packet(0, TRAILER_NONE, false);

	ck_assert_uint_eq(o.delivered, 1);
	ck_assert_uint_eq(o.rx_error, 0);
	record("prohibiting_reliability_does_not_refuse_it", "must_match", o);
}
END_TEST

/* Requiring and prohibiting the same protection is not a contradiction the policy
   notices: the requirement is enforced and the prohibition is ignored. */
START_TEST(test_requiring_and_prohibiting_authentication_enforces_the_requirement)
{
	setup_stack(CSP_SO_HMACREQ | CSP_SO_HMACPROHIB);
	struct outcome o = route_packet(0, TRAILER_NONE, false);

	ck_assert_uint_eq(o.delivered, 0);
	ck_assert_uint_eq(o.autherr, 1);
	record("requiring_and_prohibiting_authentication_enforces_the_requirement", "must_match", o);
}
END_TEST

Suite * security_suite(void)
{
	Suite * s = suite_create("Security");

	TCase * tc_ok = tcase_create("honoured");
	tcase_add_test(tc_ok, test_plain_packet_with_no_policy_is_accepted);
	tcase_add_test(tc_ok, test_a_valid_checksum_is_accepted);
	tcase_add_test(tc_ok, test_a_valid_mac_is_accepted);
	tcase_add_test(tc_ok, test_the_checksum_is_stripped_before_delivery);
	tcase_add_test(tc_ok, test_a_bad_checksum_is_refused_as_a_receive_error);
	tcase_add_test(tc_ok, test_a_bad_mac_is_refused_as_an_authentication_error);
	tcase_add_test(tc_ok, test_a_required_checksum_that_is_absent_is_refused);
	tcase_add_test(tc_ok, test_a_required_mac_that_is_absent_is_refused);
	tcase_add_test(tc_ok, test_required_reliability_that_is_absent_is_refused);
	suite_add_tcase(s, tc_ok);

	TCase * tc_both = tcase_create("layering");
	tcase_add_test(tc_both, test_both_protections_together_are_accepted);
	tcase_add_test(tc_both, test_a_damaged_outer_checksum_is_not_an_authentication_failure);
	suite_add_tcase(s, tc_both);

	TCase * tc_order = tcase_create("order");
	tcase_add_test(tc_order, test_checksum_is_checked_before_authentication);
	tcase_add_test(tc_order, test_a_claimed_mac_is_verified_even_when_not_required);
	tcase_add_test(tc_order, test_a_claimed_checksum_is_verified_even_when_not_required);
	suite_add_tcase(s, tc_order);

	TCase * tc_prohib = tcase_create("prohibitions");
	tcase_add_test(tc_prohib, test_prohibiting_authentication_does_not_refuse_it);
	tcase_add_test(tc_prohib, test_prohibiting_a_checksum_does_not_refuse_it);
	tcase_add_test(tc_prohib, test_prohibiting_reliability_does_not_refuse_it);
	tcase_add_test(tc_prohib, test_requiring_and_prohibiting_authentication_enforces_the_requirement);
	suite_add_tcase(s, tc_prohib);

	return s;
}
