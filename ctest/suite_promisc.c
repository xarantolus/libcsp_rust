#include <check.h>
#include <string.h>
#include <endian.h>

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

	ck_assert_ptr_null(csp_promisc_read(0));

	csp_buffer_free(source);
	csp_promisc_disable();
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
	tcase_add_test(tc, test_csp1_id_layout_matches_the_binding);
	suite_add_tcase(s, tc);

	return s;
}
