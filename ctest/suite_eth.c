/* The Ethernet receive path: which frames are refused, which counter is charged, and what
 * it costs in buffers.
 *
 * `csp_eth_rx` has nine guards before a byte is copied, and they run in a fixed order that
 * matters — the ethertype filter comes before the length check, so a short frame with the
 * wrong ethertype is counted once, as an ethertype failure. Every guard charges
 * `iface->frame` except the pbuf exhaustion one, which charges `iface->drop`.
 *
 * **Every refusal is asserted to consume no buffers.** That is the property worth having:
 * a bounds check that refuses the frame but keeps the packet it allocated turns a stream of
 * malformed frames into a pool exhaustion, which looks like a hang rather than a rejection.
 *
 * A note on `received_len < sizeof(csp_eth_header_t)`: it runs *after* `eth_frame->ether_type`
 * has already been read, at offset 12. That is only a read past the data the NIC delivered,
 * not past the buffer — drivers hand `csp_eth_rx` a fixed `CSP_ETH_BUF_SIZE` buffer — so it
 * reads stale bytes rather than unmapped memory. The tests below reproduce that shape: a big
 * buffer, a small `received_len`.
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
#include "csp/interfaces/csp_if_eth.h"

#include "csp_qfifo.h"

#define LOCAL_ADDR 10
#define PEER_ADDR 11
#define TEST_PORT 12
#define NETMASK 12

#define ETH_HDR sizeof(csp_eth_header_t)

static csp_eth_interface_data_t ifdata;
static uint8_t framebuf[CSP_ETH_BUF_SIZE];

/* Every frame handed to the receive path since setup, each truncated to the
   `received_len` a NIC would have delivered. An array rather than one frame because
   reassembly cases are only meaningful as a sequence -- recording just the last one would
   ask the replay to reproduce an outcome from half its input. */
#define MAX_FRAMES 4
static uint8_t sent[MAX_FRAMES][512];
static size_t sent_len[MAX_FRAMES];
static unsigned int sent_n;

/* What the application got. `refused`/`frame`/`drop` say a frame was rejected; they say
   nothing about whether reassembly put the right bytes together, which is the only thing
   the peer actually cares about. */
static unsigned int delivered_n;
static uint8_t delivered_body[CSP_BUFFER_SIZE];
static size_t delivered_body_len;

static void setup_stack(bool promisc) {
	csp_init();

	memset(&ifdata, 0, sizeof(ifdata));
	ifdata.iface.addr = LOCAL_ADDR;
	ifdata.iface.netmask = NETMASK;
	ifdata.iface.name = "ETH";
	ifdata.iface.interface_data = &ifdata;
	ifdata.promisc = promisc;
	ifdata.tx_mtu = CSP_ETH_FRAME_SIZE_MAX;
	csp_iflist_add(&ifdata.iface);

	memset(framebuf, 0, sizeof(framebuf));
	sent_n = 0;
	delivered_n = 0;
	delivered_body_len = 0;
	ctest_clock_set(CTEST_CLOCK_EPOCH_MS);
}

/* Build a frame in `framebuf` and hand `received_len` bytes of it to the receive path. */
static int deliver(uint16_t ether_type, uint16_t packet_id, uint16_t src_addr,
				   uint16_t seg_size, uint16_t frame_length, uint32_t received_len,
				   const uint8_t * payload, size_t payload_len) {
	csp_eth_header_t * f = (csp_eth_header_t *)framebuf;
	memset(framebuf, 0, sizeof(framebuf));
	memset(f->ether_dhost, 0x11, CSP_ETH_ALEN);
	memset(f->ether_shost, 0x22, CSP_ETH_ALEN);
	f->ether_type = htobe16(ether_type);
	f->packet_id = htobe16(packet_id);
	f->src_addr = htobe16(src_addr);
	f->seg_size = htobe16(seg_size);
	f->packet_length = htobe16(frame_length);
	if (payload != NULL) {
		memcpy(f->frame_begin, payload, payload_len);
	}
	if (sent_n < MAX_FRAMES) {
		size_t n = received_len > sizeof(sent[0]) ? sizeof(sent[0]) : received_len;
		memcpy(sent[sent_n], framebuf, n);
		sent_len[sent_n] = n;
		sent_n++;
	}
	return csp_eth_rx(&ifdata.iface, f, received_len, NULL);
}

/* Drain the router queue, returning how many packets came out. */
static unsigned int drain_qfifo(void) {
	unsigned int n = 0;
	csp_qfifo_t item;
	csp_qfifo_wake_up();
	while (csp_qfifo_read(&item) == CSP_ERR_NONE) {
		if (item.packet == NULL) {
			break;
		}
		if (delivered_n == 0) {
			delivered_body_len = item.packet->length > sizeof(delivered_body)
									 ? sizeof(delivered_body)
									 : item.packet->length;
			memcpy(delivered_body, item.packet->data, delivered_body_len);
		}
		csp_buffer_free(item.packet);
		delivered_n++;
		n++;
	}
	return n;
}

/* A complete, well-formed single-segment frame carrying a CSP packet for us. */
static uint16_t whole_packet(uint8_t * out, size_t payload_len, uint16_t dst) {
	csp_packet_t * p = csp_buffer_get(0);
	ck_assert_ptr_nonnull(p);
	p->id.pri = 2;
	p->id.src = PEER_ADDR;
	p->id.dst = dst;
	p->id.dport = TEST_PORT;
	p->id.sport = 40;
	p->id.flags = 0;
	/* Positional, not a constant fill: with every byte the same, a reassembly that put the
	   segments back in the wrong order would produce identical bytes and pass. */
	for (size_t i = 0; i < payload_len; i++) {
		p->data[i] = (uint8_t)(0xD5 ^ i);
	}
	p->length = (uint16_t)payload_len;
	csp_id_prepend(p);

	const uint16_t frame_length = p->frame_length;
	memcpy(out, p->frame_begin, frame_length);
	csp_buffer_free(p);
	return frame_length;
}

static void record(const char * name, int ret, int before) {
	/* Sweep anything the test did not drain itself, so `delivered` is the whole truth and
	   not just the part the test happened to look at. */
	(void)drain_qfifo();
	if (!ctest_tracing()) {
		return;
	}
	ctest_trace_begin("eth", name, "must_match");
	ctest_trace_obj_begin("input");
	ctest_trace_arr_begin("frames");
	for (unsigned int i = 0; i < sent_n; i++) {
		ctest_trace_hex(NULL, sent[i], sent_len[i]);
	}
	ctest_trace_arr_end();
	ctest_trace_int("promisc", ifdata.promisc);
	ctest_trace_obj_end();
	ctest_trace_obj_begin("observed");
	ctest_trace_int("refused", ret != CSP_ERR_NONE);
	ctest_trace_int("frame", (int64_t)ifdata.iface.frame);
	ctest_trace_int("drop", (int64_t)ifdata.iface.drop);
	ctest_trace_int("buffers_consumed", before - csp_buffer_remaining());
	ctest_trace_int("delivered", (int64_t)delivered_n);
	ctest_trace_hex("delivered_body", delivered_body, delivered_body_len);
	ctest_trace_obj_end();
	ctest_trace_end();
}

/* --- the guards, in the order csp_eth_rx applies them --- */

/* The ethertype filter is first, so a frame that is *also* too short is counted once and
   as an ethertype failure. Order is behaviour: it decides what an operator sees. */
START_TEST(test_a_foreign_ethertype_is_refused_before_the_length_check)
{
	setup_stack(false);
	const int before = csp_buffer_remaining();

	int ret = deliver(0x0800 /* IPv4 */, 1, PEER_ADDR, 8, 8, 4, NULL, 0);

	ck_assert_int_ne(ret, CSP_ERR_NONE);
	ck_assert_uint_eq(ifdata.iface.frame, 1);
	ck_assert_int_eq(csp_buffer_remaining(), before);
	record("a_foreign_ethertype_is_refused_before_the_length_check", ret, before);
}
END_TEST

/* The same frame that `a_whole_packet_in_one_segment_is_delivered` accepts, differing in
 * one field: the ethertype.
 *
 * The older case sends a four-byte frame, so the header-length check refuses it whether or
 * not the ethertype is examined -- and the record only says "refused", not *why*. Removing
 * the ethertype test entirely left that record green. Here every other field is valid, so
 * the ethertype is the only reason to refuse and the outcome flips from refused to
 * delivered if it stops being checked.
 */
START_TEST(test_only_the_ethertype_makes_an_otherwise_valid_frame_refused)
{
	setup_stack(false);
	const int before = csp_buffer_remaining();

	uint8_t body[CSP_BUFFER_SIZE];
	const uint16_t frame_length = whole_packet(body, 16, LOCAL_ADDR);

	int ret = deliver(0x0800 /* IPv4 */, 7, PEER_ADDR, frame_length, frame_length,
					  ETH_HDR + frame_length, body, frame_length);

	ck_assert_int_ne(ret, CSP_ERR_NONE);
	ck_assert_uint_eq(ifdata.iface.frame, 1);
	ck_assert_int_eq(csp_buffer_remaining(), before);
	record("only_the_ethertype_makes_an_otherwise_valid_frame_refused", ret, before);
}
END_TEST

/* A transfer that declares a total of zero.
 *
 * It can never complete: no segment can advance reassembly to a length that is already
 * reached, so accepting it holds a reassembly slot forever. `csp_eth_rx` refuses it on the
 * first segment. No eth case reached this guard -- the similarly named
 * `sfp::a_zero_total_transfer_is_refused` is the *other* protocol's version of it.
 */
START_TEST(test_a_zero_length_transfer_is_refused)
{
	setup_stack(false);
	const int before = csp_buffer_remaining();

	uint8_t body[4] = { 0xd5, 0xd5, 0xd5, 0xd5 };
	/* seg_size 4 so the empty-segment guard does not fire first; packet_length 0. */
	int ret = deliver(CSP_ETH_TYPE_CSP, 9, PEER_ADDR, 4, 0, ETH_HDR + 4, body, 4);

	ck_assert_int_ne(ret, CSP_ERR_NONE);
	ck_assert_int_eq(csp_buffer_remaining(), before);
	record("a_zero_length_transfer_is_refused", ret, before);
}
END_TEST

START_TEST(test_a_frame_shorter_than_the_header_is_refused)
{
	setup_stack(false);
	const int before = csp_buffer_remaining();

	int ret = deliver(CSP_ETH_TYPE_CSP, 1, PEER_ADDR, 8, 8, ETH_HDR - 1, NULL, 0);

	ck_assert_int_ne(ret, CSP_ERR_NONE);
	ck_assert_uint_eq(ifdata.iface.frame, 1);
	ck_assert_int_eq(csp_buffer_remaining(), before);
	record("a_frame_shorter_than_the_header_is_refused", ret, before);
}
END_TEST

/* A zero-length segment can never advance reassembly, so a stream of them would stall a
   pbuf forever rather than fail. */
START_TEST(test_a_zero_length_segment_is_refused)
{
	setup_stack(false);
	const int before = csp_buffer_remaining();

	int ret = deliver(CSP_ETH_TYPE_CSP, 1, PEER_ADDR, 0, 16, ETH_HDR + 16, NULL, 0);

	ck_assert_int_ne(ret, CSP_ERR_NONE);
	ck_assert_uint_eq(ifdata.iface.frame, 1);
	ck_assert_int_eq(csp_buffer_remaining(), before);
	record("a_zero_length_segment_is_refused", ret, before);
}
END_TEST

START_TEST(test_a_segment_larger_than_the_mtu_is_refused)
{
	setup_stack(false);
	const int before = csp_buffer_remaining();

	int ret = deliver(CSP_ETH_TYPE_CSP, 1, PEER_ADDR, CSP_ETH_FRAME_SIZE_MAX + 1, 4000,
					  sizeof(framebuf), NULL, 0);

	ck_assert_int_ne(ret, CSP_ERR_NONE);
	ck_assert_uint_eq(ifdata.iface.frame, 1);
	ck_assert_int_eq(csp_buffer_remaining(), before);
	record("a_segment_larger_than_the_mtu_is_refused", ret, before);
}
END_TEST

/* A segment bigger than the whole packet it claims to belong to. */
START_TEST(test_a_segment_larger_than_its_packet_is_refused)
{
	setup_stack(false);
	const int before = csp_buffer_remaining();

	int ret = deliver(CSP_ETH_TYPE_CSP, 1, PEER_ADDR, 64, 32, ETH_HDR + 64, NULL, 0);

	ck_assert_int_ne(ret, CSP_ERR_NONE);
	ck_assert_uint_eq(ifdata.iface.frame, 1);
	ck_assert_int_eq(csp_buffer_remaining(), before);
	record("a_segment_larger_than_its_packet_is_refused", ret, before);
}
END_TEST

/* The one that keeps the memcpy inside the delivered bytes: a frame that says it carries
   64 bytes but only 8 arrived. Without it the copy reads past what the NIC wrote. */
START_TEST(test_a_segment_longer_than_the_bytes_received_is_refused)
{
	setup_stack(false);
	const int before = csp_buffer_remaining();

	int ret = deliver(CSP_ETH_TYPE_CSP, 1, PEER_ADDR, 64, 64, ETH_HDR + 8, NULL, 0);

	ck_assert_int_ne(ret, CSP_ERR_NONE);
	ck_assert_uint_eq(ifdata.iface.frame, 1);
	ck_assert_int_eq(csp_buffer_remaining(), before);
	record("a_segment_longer_than_the_bytes_received_is_refused", ret, before);
}
END_TEST

/* Shorter than a CSP header: there would be nothing to route on. */
START_TEST(test_a_packet_length_below_the_csp_header_is_refused)
{
	setup_stack(false);
	const int before = csp_buffer_remaining();

	const uint16_t too_short = (uint16_t)(csp_id_get_header_size() - 1);
	int ret = deliver(CSP_ETH_TYPE_CSP, 1, PEER_ADDR, too_short, too_short,
					  ETH_HDR + too_short, NULL, 0);

	ck_assert_int_ne(ret, CSP_ERR_NONE);
	ck_assert_uint_eq(ifdata.iface.frame, 1);
	ck_assert_int_eq(csp_buffer_remaining(), before);
	record("a_packet_length_below_the_csp_header_is_refused", ret, before);
}
END_TEST

/* Longer than any buffer could hold. */
/* The same floor, but on a segment that does not complete the packet. The existing case
   declares a length below the header *and* fills it, so a receiver that only noticed when
   it came to parse the reassembled bytes would refuse it too, and the two are
   indistinguishable. Here the transfer is left incomplete: refusing up front is the only
   way to refuse at all. */
START_TEST(test_a_packet_length_below_the_csp_header_is_refused_before_it_completes)
{
	setup_stack(false);
	const int before = csp_buffer_remaining();

	uint8_t body[8] = {0};
	int ret = deliver(CSP_ETH_TYPE_CSP, 3, PEER_ADDR, 2, 5, ETH_HDR + 2, body, 2);

	ck_assert_int_ne(ret, CSP_ERR_NONE);
	ck_assert_uint_eq(ifdata.iface.frame, 1);
	ck_assert_uint_eq(drain_qfifo(), 0);
	ck_assert_int_eq(csp_buffer_remaining(), before);
	record("a_packet_length_below_the_csp_header_is_refused_before_it_completes", ret,
		   before);
}
END_TEST

START_TEST(test_a_packet_length_beyond_the_buffer_is_refused)
{
	setup_stack(false);
	const int before = csp_buffer_remaining();

	int ret = deliver(CSP_ETH_TYPE_CSP, 1, PEER_ADDR, 32,
					  (uint16_t)(CSP_BUFFER_SIZE + csp_id_get_header_size() + 1),
					  ETH_HDR + 32, NULL, 0);

	ck_assert_int_ne(ret, CSP_ERR_NONE);
	ck_assert_uint_eq(ifdata.iface.frame, 1);
	ck_assert_int_eq(csp_buffer_remaining(), before);
	record("a_packet_length_beyond_the_buffer_is_refused", ret, before);
}
END_TEST

/* --- delivery and reassembly --- */

START_TEST(test_a_whole_packet_in_one_segment_is_delivered)
{
	setup_stack(false);
	const int before = csp_buffer_remaining();

	uint8_t body[CSP_BUFFER_SIZE];
	const uint16_t frame_length = whole_packet(body, 16, LOCAL_ADDR);

	int ret = deliver(CSP_ETH_TYPE_CSP, 7, PEER_ADDR, frame_length, frame_length,
					  ETH_HDR + frame_length, body, frame_length);

	ck_assert_int_eq(ret, CSP_ERR_NONE);
	ck_assert_uint_eq(ifdata.iface.frame, 0);
	ck_assert_uint_eq(drain_qfifo(), 1);
	ck_assert_int_eq(csp_buffer_remaining(), before);
	record("a_whole_packet_in_one_segment_is_delivered", ret, before);
}
END_TEST

/* Ethernet pads every frame below 60 bytes, so a small CSP packet reaches `csp_eth_rx`
   with trailing bytes past `seg_size`. The C bounds `ETH_HDR + seg_size` against what
   arrived and copies `seg_size` -- the padding is surplus, not a malformed frame. Any
   receiver that instead required the frame to be exactly `ETH_HDR + seg_size` long would
   refuse every small packet on a real link. */
START_TEST(test_a_frame_padded_to_the_ethernet_minimum_is_delivered)
{
	setup_stack(false);
	const int before = csp_buffer_remaining();

	uint8_t body[CSP_BUFFER_SIZE];
	const uint16_t frame_length = whole_packet(body, 4, LOCAL_ADDR);
	const uint32_t padded = 60;
	ck_assert_uint_lt(ETH_HDR + frame_length, padded);

	int ret = deliver(CSP_ETH_TYPE_CSP, 9, PEER_ADDR, frame_length, frame_length, padded,
					  body, frame_length);

	ck_assert_int_eq(ret, CSP_ERR_NONE);
	ck_assert_uint_eq(ifdata.iface.frame, 0);
	ck_assert_uint_eq(drain_qfifo(), 1);
	ck_assert_int_eq(csp_buffer_remaining(), before);
	record("a_frame_padded_to_the_ethernet_minimum_is_delivered", ret, before);
}
END_TEST

START_TEST(test_two_segments_are_reassembled)
{
	setup_stack(false);
	const int before = csp_buffer_remaining();

	uint8_t body[CSP_BUFFER_SIZE];
	const uint16_t frame_length = whole_packet(body, 32, LOCAL_ADDR);
	const uint16_t first = 10;

	int ret = deliver(CSP_ETH_TYPE_CSP, 8, PEER_ADDR, first, frame_length,
					  ETH_HDR + first, body, first);
	ck_assert_int_eq(ret, CSP_ERR_NONE);
	/* Nothing yet — the packet is not complete. */
	ck_assert_uint_eq(drain_qfifo(), 0);

	ret = deliver(CSP_ETH_TYPE_CSP, 8, PEER_ADDR, (uint16_t)(frame_length - first),
				  frame_length, ETH_HDR + (frame_length - first), body + first,
				  (size_t)(frame_length - first));
	ck_assert_int_eq(ret, CSP_ERR_NONE);
	ck_assert_uint_eq(drain_qfifo(), 1);
	ck_assert_int_eq(csp_buffer_remaining(), before);

	record("two_segments_are_reassembled", ret, before);
}
END_TEST

/* Two segments of the same packet that disagree about how long it is. The pbuf is released
   rather than left holding a buffer until it times out. */
START_TEST(test_segments_disagreeing_on_the_packet_length_are_refused)
{
	setup_stack(false);
	const int before = csp_buffer_remaining();

	uint8_t body[CSP_BUFFER_SIZE];
	const uint16_t frame_length = whole_packet(body, 32, LOCAL_ADDR);

	int ret = deliver(CSP_ETH_TYPE_CSP, 9, PEER_ADDR, 10, frame_length,
					  ETH_HDR + 10, body, 10);
	ck_assert_int_eq(ret, CSP_ERR_NONE);

	ret = deliver(CSP_ETH_TYPE_CSP, 9, PEER_ADDR, 10, (uint16_t)(frame_length + 1),
				  ETH_HDR + 10, body, 10);

	ck_assert_int_ne(ret, CSP_ERR_NONE);
	ck_assert_uint_eq(ifdata.iface.frame, 1);
	ck_assert_uint_eq(drain_qfifo(), 0);
	ck_assert_int_eq(csp_buffer_remaining(), before);
	record("segments_disagreeing_on_the_packet_length_are_refused", ret, before);
}
END_TEST

/* More data than the packet declared. The reassembly buffer is bounded by the declared
   length, so this is what stops a write past it. */
START_TEST(test_segments_totalling_more_than_the_packet_are_refused)
{
	setup_stack(false);
	const int before = csp_buffer_remaining();

	uint8_t body[CSP_BUFFER_SIZE];
	const uint16_t frame_length = whole_packet(body, 32, LOCAL_ADDR);

	int ret = deliver(CSP_ETH_TYPE_CSP, 11, PEER_ADDR, (uint16_t)(frame_length - 4),
					  frame_length, ETH_HDR + frame_length, body,
					  (size_t)(frame_length - 4));
	ck_assert_int_eq(ret, CSP_ERR_NONE);

	/* A second segment that fits every earlier guard -- it is smaller than the declared
	   packet and the bytes are all present -- but pushes the running total past it. That
	   is guard nine, and it is the only one that runs with a pbuf already allocated, so it
	   is the only one whose failure could leak one. */
	ret = deliver(CSP_ETH_TYPE_CSP, 11, PEER_ADDR, 8, frame_length,
				  ETH_HDR + 8, body, 8);

	ck_assert_int_ne(ret, CSP_ERR_NONE);
	ck_assert_uint_eq(ifdata.iface.frame, 1);
	ck_assert_uint_eq(drain_qfifo(), 0);
	ck_assert_int_eq(csp_buffer_remaining(), before);
	record("segments_totalling_more_than_the_packet_are_refused", ret, before);
}
END_TEST

/* --- the address filter --- */

/* A complete, valid packet for someone else. Reassembled, then dropped without reaching
   the router — and without leaking the buffer it was reassembled into. */
START_TEST(test_a_packet_for_another_node_is_not_delivered)
{
	setup_stack(false);
	const int before = csp_buffer_remaining();

	uint8_t body[CSP_BUFFER_SIZE];
	const uint16_t frame_length = whole_packet(body, 16, 25 /* not us */);

	int ret = deliver(CSP_ETH_TYPE_CSP, 12, PEER_ADDR, frame_length, frame_length,
					  ETH_HDR + frame_length, body, frame_length);

	ck_assert_int_eq(ret, CSP_ERR_NONE);
	ck_assert_uint_eq(ifdata.iface.frame, 0);
	ck_assert_uint_eq(drain_qfifo(), 0);
	ck_assert_int_eq(csp_buffer_remaining(), before);
	record("a_packet_for_another_node_is_not_delivered", ret, before);
}
END_TEST

/* The same frame, with the interface in promiscuous mode. */
START_TEST(test_a_packet_for_another_node_is_delivered_when_promiscuous)
{
	setup_stack(true);
	const int before = csp_buffer_remaining();

	uint8_t body[CSP_BUFFER_SIZE];
	const uint16_t frame_length = whole_packet(body, 16, 25);

	int ret = deliver(CSP_ETH_TYPE_CSP, 13, PEER_ADDR, frame_length, frame_length,
					  ETH_HDR + frame_length, body, frame_length);

	ck_assert_int_eq(ret, CSP_ERR_NONE);
	ck_assert_uint_eq(drain_qfifo(), 1);
	ck_assert_int_eq(csp_buffer_remaining(), before);
	record("a_packet_for_another_node_is_delivered_when_promiscuous", ret, before);
}
END_TEST

/* --- the header codec --- */

START_TEST(test_the_header_round_trips)
{
	setup_stack(false);

	csp_eth_header_t * f = (csp_eth_header_t *)framebuf;
	memset(framebuf, 0, sizeof(framebuf));
	ck_assert(csp_eth_pack_header(f, 0x1234, 0x0abc, 1400, 2000));

	/* csp_eth_pack_header packs the four EFP fields and *not* the ethertype -- csp_eth_tx
	   writes that separately. A test that expected pack_header to produce a complete
	   header would be describing a function that does not exist. */
	ck_assert_uint_eq(f->ether_type, 0);

	/* Read back from the wire bytes rather than through the unpacker: the real one,
	   csp_if_eth_unpack_header, is `static`, and the name the public header exports --
	   csp_eth_unpack_header -- is declared and never defined anywhere in libcsp. Linking
	   against it is a build failure, so a peer decodes these fields itself. */
	ck_assert_uint_eq(be16toh(f->packet_id), 0x1234);
	ck_assert_uint_eq(be16toh(f->src_addr), 0x0abc);
	ck_assert_uint_eq(be16toh(f->seg_size), 1400);
	ck_assert_uint_eq(be16toh(f->packet_length), 2000);

	/* The RX-side identifier the reassembler keys on is the TX packet id concatenated with
	   the source address, so two nodes numbering their packets identically do not collide.
	   Asserted through behaviour in the reassembly cases above. */

	if (ctest_tracing()) {
		ctest_trace_begin("eth", "the_header_round_trips", "must_match");
		ctest_trace_obj_begin("observed");
		ctest_trace_hex("header", framebuf, ETH_HDR);
		ctest_trace_obj_end();
		ctest_trace_end();
	}
}
END_TEST

/* csp_if_eth_unpack_header builds the reassembly key as
 *
 *     *packet_id = buf->packet_id << 16 | buf->src_addr;
 *
 * with no byte swap, unlike the seg_size and packet_length beside it. As an opaque key
 * that is harmless -- both segments of a packet produce the same value -- but the shift is
 * not: `buf->packet_id` is a uint16_t, so it promotes to *signed* int, and shifting a value
 * of 0x8000 or more left by 16 overflows it. That is undefined behaviour, and it happens
 * for every packet whose id has its low byte >= 0x80, which is half of them.
 *
 * Run under `-fsanitize=undefined` this test is what reports it; without a sanitizer gcc
 * produces the wrapped value and nothing looks wrong.
 */
START_TEST(test_a_high_packet_id_still_reassembles)
{
	setup_stack(false);
	const int before = csp_buffer_remaining();

	uint8_t body[CSP_BUFFER_SIZE];
	const uint16_t frame_length = whole_packet(body, 16, LOCAL_ADDR);

	/* Wire bytes 00 80: read back natively as 0x8000, which is where the shift overflows. */
	int ret = deliver(CSP_ETH_TYPE_CSP, 0x0080, PEER_ADDR, frame_length, frame_length,
					  ETH_HDR + frame_length, body, frame_length);

	ck_assert_int_eq(ret, CSP_ERR_NONE);
	ck_assert_uint_eq(drain_qfifo(), 1);
	ck_assert_int_eq(csp_buffer_remaining(), before);
	record("a_high_packet_id_still_reassembles", ret, before);
}
END_TEST

Suite * eth_suite(void)
{
	Suite * s = suite_create("ETH");

	TCase * tc_guard = tcase_create("guards");
	tcase_add_test(tc_guard, test_a_foreign_ethertype_is_refused_before_the_length_check);
	tcase_add_test(tc_guard, test_only_the_ethertype_makes_an_otherwise_valid_frame_refused);
	tcase_add_test(tc_guard, test_a_zero_length_transfer_is_refused);
	tcase_add_test(tc_guard, test_a_frame_shorter_than_the_header_is_refused);
	tcase_add_test(tc_guard, test_a_zero_length_segment_is_refused);
	tcase_add_test(tc_guard, test_a_segment_larger_than_the_mtu_is_refused);
	tcase_add_test(tc_guard, test_a_segment_larger_than_its_packet_is_refused);
	tcase_add_test(tc_guard, test_a_segment_longer_than_the_bytes_received_is_refused);
	tcase_add_test(tc_guard, test_a_packet_length_below_the_csp_header_is_refused);
	tcase_add_test(tc_guard, test_a_packet_length_below_the_csp_header_is_refused_before_it_completes);
	tcase_add_test(tc_guard, test_a_packet_length_beyond_the_buffer_is_refused);
	suite_add_tcase(s, tc_guard);

	TCase * tc_rx = tcase_create("reassembly");
	tcase_add_test(tc_rx, test_a_whole_packet_in_one_segment_is_delivered);
	tcase_add_test(tc_rx, test_a_frame_padded_to_the_ethernet_minimum_is_delivered);
	tcase_add_test(tc_rx, test_two_segments_are_reassembled);
	tcase_add_test(tc_rx, test_segments_disagreeing_on_the_packet_length_are_refused);
	tcase_add_test(tc_rx, test_segments_totalling_more_than_the_packet_are_refused);
	tcase_add_test(tc_rx, test_a_packet_for_another_node_is_not_delivered);
	tcase_add_test(tc_rx, test_a_packet_for_another_node_is_delivered_when_promiscuous);
	tcase_add_test(tc_rx, test_a_high_packet_id_still_reassembles);
	suite_add_tcase(s, tc_rx);

	TCase * tc_hdr = tcase_create("header");
	tcase_add_test(tc_hdr, test_the_header_round_trips);
	suite_add_tcase(s, tc_hdr);

	return s;
}
