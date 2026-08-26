#include <check.h>
#include "csp/csp.h"
#include "csp/csp_id.h"
#include "csp/crypto/csp_hmac.h"
#include "csp_buffer_private.h"

#include "trace.h"

/* The tag is the wire. `csp_hmac_append` writes four bytes a peer must reproduce exactly, and
   `include_header` decides which span they cover -- get that wrong on one side and every
   packet on an authenticated link fails, with nothing to say why. libcsp's own expected
   values are the oracle; this hands them to the port. The key is the zeroed static
   `csp_hmac_key`, never set here, so both sides authenticate under an all-zero key. */
static void hmac_record_hdr(const char * name, int include_header, const uint8_t * tagged,
							uint16_t tagged_len, int verified, const uint8_t * recovered,
							uint16_t recovered_len, const uint8_t * header,
							uint16_t header_len) {
	if (!ctest_tracing()) {
		return;
	}
	ctest_trace_begin("hmac", name, "must_match");
	ctest_trace_obj_begin("input");
	ctest_trace_int("include_header", include_header);
	ctest_trace_hex("payload", (const uint8_t *)"abc", 3);
	if (header_len) {
		ctest_trace_hex("header", header, header_len);
	}
	ctest_trace_obj_end();
	ctest_trace_obj_begin("observed");
	ctest_trace_hex("tagged", tagged, tagged_len);
	ctest_trace_int("verified", verified);
	/* What the caller gets back, not `packet->length`. On the include-header path
	   `csp_hmac_verify` decrements only `frame_length`, so `length` still counts the four
	   MAC bytes and an application reading `data[0..length]` sees them as payload. That is
	   a real libcsp trap (SCOPE.md), but it is bookkeeping the port's slice-returning API
	   cannot reproduce, and comparing it would invent a divergence rather than find one. */
	ctest_trace_hex("recovered", recovered, recovered_len);
	ctest_trace_obj_end();
	ctest_trace_end();
}

static void hmac_record(const char * name, int include_header, const uint8_t * tagged,
						uint16_t tagged_len, int verified, const uint8_t * recovered,
						uint16_t recovered_len) {
	hmac_record_hdr(name, include_header, tagged, tagged_len, verified, recovered,
					recovered_len, NULL, 0);
}

START_TEST(test_hmac_append_no_header)
{
	uint8_t test_data[] = {0x61, 0x62, 0x63}; /* abc */
	uint8_t expected[] = {0x61, 0x62, 0x63, 0x9b, 0x4a, 0x91, 0x8f};
	csp_packet_t * packet;

	csp_init();

	packet = csp_buffer_get_always();
	memcpy(packet->data, test_data, sizeof(test_data));
	packet->length = sizeof(test_data);

	csp_hmac_append(packet, false);
	ck_assert_mem_eq(packet->data, expected, sizeof(expected));

	uint8_t tagged[16];
	const uint16_t tagged_len = packet->length;
	memcpy(tagged, packet->data, tagged_len);

	const int verified = (csp_hmac_verify(packet, false) == CSP_ERR_NONE);
	ck_assert_mem_eq(packet->data, test_data, sizeof(test_data));

	hmac_record("a_mac_over_the_payload_only", 0, tagged, tagged_len, verified, packet->data,
				packet->length);
}
END_TEST

START_TEST(test_hmac_append_include_header)
{
	uint8_t test_data[] = {0x61, 0x62, 0x63}; /* abc */
	uint8_t expected[] = {0x61, 0x62, 0x63, 0x3c, 0xc7, 0x49, 0x8b};
	csp_packet_t * packet;

	csp_init();

	packet = csp_buffer_get_always();

	csp_id_prepend(packet);

	memcpy(packet->data, test_data, sizeof(test_data));
	packet->length += sizeof(test_data);
	packet->frame_length += sizeof(test_data);

	csp_hmac_append(packet, true);
	ck_assert_mem_eq(packet->data, expected, sizeof(expected));

	uint8_t tagged[16];
	const uint16_t tagged_len = packet->length;
	memcpy(tagged, packet->data, tagged_len);

	const int verified = (csp_hmac_verify(packet, true) == CSP_ERR_NONE);
	ck_assert_mem_eq(packet->data, test_data, sizeof(test_data));

	/* The header bytes the MAC covered, so the replay authenticates the same span. */
	/* The exact span the MAC covered: `csp_hmac_append` hashes `frame_begin` for
	   `frame_length` bytes, so the replay must authenticate header-then-payload over the
	   same bytes. Taken from `csp_id_get_header_size()` rather than derived from the two
	   lengths -- `csp_hmac_verify` decrements only `frame_length` on this path, so any
	   arithmetic mixing the two is wrong by four. */
	hmac_record_hdr("a_mac_over_the_header_and_payload", 1, tagged, tagged_len, verified,
					packet->frame_begin + csp_id_get_header_size(),
					(uint16_t)(packet->frame_length - csp_id_get_header_size()),
					packet->frame_begin, (uint16_t)csp_id_get_header_size());
}
END_TEST

Suite * hmac_suite(void)
{
	Suite *s;
	TCase *tc_hmac;

	s = suite_create("HMAC");

	tc_hmac = tcase_create("append");
	tcase_add_test(tc_hmac, test_hmac_append_no_header);
	tcase_add_test(tc_hmac, test_hmac_append_include_header);
	suite_add_tcase(s, tc_hmac);

	return s;
}
