/*
 * Golden-vector generator.
 *
 * Drives the real libcsp API and records what actually lands on the wire, so the
 * Rust ports are diffed against observed behaviour rather than against a reading
 * of the source. Output is committed to vectors/ and the Rust tests need no C.
 *
 * Every vector is a tab-separated triple:
 *
 *     <kind>\t<input description>\t<output hex>
 *
 * Determinism matters: anything time- or counter-dependent is reset before use.
 * RDP is deliberately absent — its initial sequence number is not deterministic,
 * so it is covered by a trace differential test instead.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <csp/csp.h>
#include <csp/csp_id.h>
#include <csp/csp_buffer.h>
#include <csp/csp_interface.h>
#include <csp/csp_iflist.h>
#include <csp/csp_rtable.h>
#include <csp/csp_crc32.h>
#include <csp/csp_sfp.h>
#include <csp/csp_cmp.h>
#include <csp/crypto/csp_hmac.h>
#include <csp/crypto/csp_sha1.h>
#include <csp/interfaces/csp_if_can.h>
#include <csp/interfaces/csp_if_kiss.h>

static FILE * out;

static void emit(const char * kind, const char * desc, const uint8_t * data, size_t len) {
	fprintf(out, "%s\t%s\t", kind, desc);
	for (size_t i = 0; i < len; i++) {
		fprintf(out, "%02x", data[i]);
	}
	fprintf(out, "\n");
}

/* Payload lengths are ambiguous -- the table has two distinct 1-byte entries -- so the
 * vectors record the payload bytes themselves and are self-describing. */
static void hexify(char * dst, size_t dstsz, const uint8_t * data, size_t len) {
	size_t o = 0;
	for (size_t i = 0; i < len && o + 3 < dstsz; i++) {
		o += (size_t)snprintf(dst + o, dstsz - o, "%02x", data[i]);
	}
	dst[o] = '\0';
}

static void emit_u32(const char * kind, const char * desc, uint32_t v) {
	uint8_t b[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
	emit(kind, desc, b, 4);
}

/* ------------------------------------------------------------------ */
/* Capture interface: records the full frame each packet turns into.   */
/* ------------------------------------------------------------------ */

#define CAP_MAX 64
static struct {
	uint8_t frame[CSP_BUFFER_SIZE + 16];
	uint16_t len;
} cap[CAP_MAX];
static int cap_n;

static void cap_reset(void) { cap_n = 0; }

static int cap_tx(csp_iface_t * iface, uint16_t via, csp_packet_t * packet, int from_me) {
	(void)iface; (void)via; (void)from_me;
	/* A nexthop is handed an UNFRAMED packet: frame_begin/frame_length are only
	 * valid after the interface prepends the header itself. csp_kiss_tx and
	 * csp_can_tx both do this. Skipping it captures zero-length frames. */
	csp_id_prepend(packet);
	/* The nexthop owns the packet on success, so it must free it. */
	if (cap_n < CAP_MAX) {
		uint16_t n = packet->frame_length;
		if (n > sizeof(cap[0].frame)) n = sizeof(cap[0].frame);
		memcpy(cap[cap_n].frame, packet->frame_begin, n);
		cap[cap_n].len = n;
		cap_n++;
	}
	csp_buffer_free(packet);
	return CSP_ERR_NONE;
}

static csp_iface_t cap_if = {
	.name = "CAP",
	.nexthop = cap_tx,
	.addr = 0,
	.netmask = 0,
	.is_default = 1,
};

/* ------------------------------------------------------------------ */
/* CAN capture: records (id, dlc, data) per CFP frame.                 */
/* ------------------------------------------------------------------ */

#define CANCAP_MAX 128
static struct { uint32_t id; uint8_t dlc; uint8_t data[8]; } cancap[CANCAP_MAX];
static int cancap_n;

static int can_tx_capture(void * driver_data, uint32_t id, const uint8_t * data,
                          uint8_t dlc, const csp_packet_t * packet) {
	(void)driver_data; (void)packet;
	if (cancap_n < CANCAP_MAX) {
		cancap[cancap_n].id = id;
		cancap[cancap_n].dlc = dlc;
		memset(cancap[cancap_n].data, 0, 8);
		if (dlc <= 8 && data) memcpy(cancap[cancap_n].data, data, dlc);
		cancap_n++;
	}
	return CSP_ERR_NONE;
}

static csp_can_interface_data_t can_ifdata;
static csp_iface_t can_if = { .name = "CAN", .interface_data = &can_ifdata };

/* ------------------------------------------------------------------ */
/* KISS capture: records the raw framed byte stream.                   */
/* ------------------------------------------------------------------ */

#define KISSCAP_MAX 2048
static uint8_t kisscap[KISSCAP_MAX];
static size_t kisscap_n;

static int kiss_tx_capture(void * driver_data, const uint8_t * data, size_t len) {
	(void)driver_data;
	for (size_t i = 0; i < len && kisscap_n < KISSCAP_MAX; i++) {
		kisscap[kisscap_n++] = data[i];
	}
	return CSP_ERR_NONE;
}

static csp_kiss_interface_data_t kiss_ifdata;
static csp_iface_t kiss_if = { .name = "KISS", .interface_data = &kiss_ifdata };

/* ------------------------------------------------------------------ */

static const uint8_t PAYLOADS[][24] = {
	{0},
	{0x00},
	{0x41},
	{0x48, 0x65, 0x6c, 0x6c, 0x6f},
	{0xde, 0xad, 0xbe, 0xef},
	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
	 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14},
};
static const size_t PAYLOAD_LENS[] = {0, 1, 1, 5, 4, 8, 20};
#define N_PAYLOADS (sizeof(PAYLOAD_LENS) / sizeof(PAYLOAD_LENS[0]))

struct id_case { uint8_t pri, flags; uint16_t src, dst; uint8_t sport, dport; };

/* Chosen to exercise field boundaries: zero, max-for-v1 (5-bit addr, 6-bit port),
 * and values that only fit in v2 (14-bit addr). */
static const struct id_case ID_CASES[] = {
	{0, 0x00,     0,     0,  0,  0},
	{1, 0x00,     1,     2, 10, 20},
	{2, 0x00,     8,    11, 48, 24},
	{3, 0x00,    31,    31, 63, 63},
	{2, 0x01,     1,     8, 10, 20},   /* CRC32 */
	{2, 0x02,     1,     8, 10, 20},   /* RDP */
	{2, 0x08,     1,     8, 10, 20},   /* HMAC */
	{2, 0x10,     1,     8, 10, 20},   /* FRAG */
	{2, 0x1b,    31,    31, 63, 63},   /* all flags */
	{0, 0x00,  1000,  2000, 40, 50},   /* v2-only addresses */
	{3, 0x00, 16383, 16383, 63, 63},   /* v2 max */
};
#define N_ID_CASES (sizeof(ID_CASES) / sizeof(ID_CASES[0]))

static void set_id(csp_packet_t * p, const struct id_case * c) {
	csp_id_clear(&p->id);
	p->id.pri = c->pri;
	p->id.flags = c->flags;
	p->id.src = c->src;
	p->id.dst = c->dst;
	p->id.sport = c->sport;
	p->id.dport = c->dport;
}

/* ---- 1. Header codec, both wire versions ---- */
static void gen_id(int version) {
	for (size_t ci = 0; ci < N_ID_CASES; ci++) {
		const struct id_case * c = &ID_CASES[ci];
		/* v1 has 5-bit addresses and 6-bit ports; skip what cannot be encoded. */
		if (version == 1 && (c->src > 31 || c->dst > 31)) continue;
		for (size_t pi = 0; pi < N_PAYLOADS; pi++) {
			csp_packet_t * p = csp_buffer_get(0);
			if (!p) { fprintf(stderr, "buffer pool exhausted\n"); exit(1); }
			set_id(p, c);
			p->length = (uint16_t)PAYLOAD_LENS[pi];
			memcpy(p->data, PAYLOADS[pi], PAYLOAD_LENS[pi]);
			csp_id_prepend(p);
			char phex[64];
			hexify(phex, sizeof(phex), PAYLOADS[pi], PAYLOAD_LENS[pi]);
			char desc[200];
			snprintf(desc, sizeof(desc),
			         "v=%d,pri=%u,src=%u,dst=%u,sport=%u,dport=%u,flags=0x%02x,payload=%s",
			         version, c->pri, c->src, c->dst, c->sport, c->dport, c->flags, phex);
			char kind[16];
			snprintf(kind, sizeof(kind), "id_v%d", version);
			emit(kind, desc, p->frame_begin, p->frame_length);
			csp_buffer_free(p);
		}
	}
}

/* ---- 2. Header parameters derived from the version ---- */
static void gen_id_params(int v) {
	{
		char desc[64];
		snprintf(desc, sizeof(desc), "v=%d", v);
		emit_u32("id_host_bits", desc, (uint32_t)csp_id_get_host_bits());
		emit_u32("id_max_nodeid", desc, (uint32_t)csp_id_get_max_nodeid());
		emit_u32("id_max_port", desc, (uint32_t)csp_id_get_max_port());
		emit_u32("id_header_size", desc, (uint32_t)csp_id_get_header_size());
		for (uint32_t a = 0; a < 5; a++) {
			uint16_t addr = (uint16_t)(a == 4 ? csp_id_get_max_nodeid() : a);
			snprintf(desc, sizeof(desc), "v=%d,addr=%u", v, addr);
			emit_u32("id_is_broadcast", desc, csp_id_is_broadcast(addr, &cap_if) ? 1u : 0u);
		}
	}
}

/* ---- 3. CRC32-C ---- */
static void gen_crc32(void) {
	for (size_t pi = 0; pi < N_PAYLOADS; pi++) {
		char phex[64];
		hexify(phex, sizeof(phex), PAYLOADS[pi], PAYLOAD_LENS[pi]);
		char desc[96];
		snprintf(desc, sizeof(desc), "payload=%s", phex);
		emit_u32("crc32", desc, csp_crc32_memory(PAYLOADS[pi], (uint32_t)PAYLOAD_LENS[pi]));
	}
	static const char * strs[] = {"", "a", "abc", "message digest",
	                              "abcdefghijklmnopqrstuvwxyz",
	                              "The quick brown fox jumps over the lazy dog"};
	for (size_t i = 0; i < sizeof(strs) / sizeof(strs[0]); i++) {
		char desc[96];
		snprintf(desc, sizeof(desc), "str=\"%s\"", strs[i]);
		emit_u32("crc32", desc, csp_crc32_memory(strs[i], (uint32_t)strlen(strs[i])));
	}
}

/* ---- 4. SHA-1 ---- */
static void gen_sha1(void) {
	static const char * strs[] = {"", "a", "abc", "message digest",
	                              "abcdefghijklmnopqrstuvwxyz",
	                              "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	                              "The quick brown fox jumps over the lazy dog"};
	for (size_t i = 0; i < sizeof(strs) / sizeof(strs[0]); i++) {
		uint8_t digest[20];
		csp_sha1_memory(strs[i], (uint32_t)strlen(strs[i]), digest);
		char desc[96];
		snprintf(desc, sizeof(desc), "str=\"%s\"", strs[i]);
		emit("sha1", desc, digest, sizeof(digest));
	}
	/* Block-boundary cases: 55, 56, 64, 65 bytes of 'x' exercise the padding path. */
	static const size_t lens[] = {55, 56, 63, 64, 65, 119, 120, 128};
	for (size_t i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
		uint8_t buf[128];
		memset(buf, 'x', lens[i]);
		uint8_t digest[20];
		csp_sha1_memory(buf, (uint32_t)lens[i], digest);
		char desc[64];
		snprintf(desc, sizeof(desc), "x*%zu", lens[i]);
		emit("sha1", desc, digest, sizeof(digest));
	}
}

/* ---- 5. HMAC-SHA1, truncated to 4 bytes as libcsp does ---- */
static void gen_hmac(void) {
	static const struct { const char * key; const char * data; } cases[] = {
		{"", ""},
		{"key", "The quick brown fox jumps over the lazy dog"},
		{"secret", "abc"},
		{"0123456789abcdef", "hello world"},
		/* Longer than the 64-byte block, so the key gets hashed first. */
		{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123", "abc"},
	};
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		/* csp_hmac_memory writes the FULL 20-byte SHA-1 digest, not CSP_HMAC_LENGTH
		 * bytes -- its out parameter is an unsized uint8_t*, so passing a 4-byte
		 * buffer (the obvious reading of CSP_HMAC_LENGTH) overflows the stack.
		 * Only the first 4 bytes are what gets appended to a packet. */
		uint8_t mac[CSP_SHA1_DIGESTSIZE];
		memset(mac, 0, sizeof(mac));
		int rc = csp_hmac_memory(cases[i].key, (uint32_t)strlen(cases[i].key),
		                         cases[i].data, (uint32_t)strlen(cases[i].data), mac);
		char desc[192];
		snprintf(desc, sizeof(desc), "key=\"%s\",data=\"%s\"", cases[i].key, cases[i].data);
		if (rc != CSP_ERR_NONE) {
			/* An empty key is rejected (keylen < 1) and the out buffer is left
			 * untouched -- record the refusal, not the uninitialised bytes. */
			char d2[224];
			snprintf(d2, sizeof(d2), "%s,rc=%d", desc, rc);
			emit("hmac_err", d2, NULL, 0);
			continue;
		}
		emit("hmac_full", desc, mac, CSP_SHA1_DIGESTSIZE);
		emit("hmac", desc, mac, CSP_HMAC_LENGTH);
	}
}

/* ---- 6. CFP: CAN fragmentation, both wire versions ---- */
static void gen_cfp(int version) {
	static const size_t lens[] = {0, 1, 7, 8, 9, 16, 100, 200};
	for (size_t li = 0; li < sizeof(lens) / sizeof(lens[0]); li++) {
		cancap_n = 0;
		/* Reset so the CFP id counter is identical on every run. */
		atomic_store(&can_ifdata.cfp_packet_counter, 0);
		csp_packet_t * p = csp_buffer_get(0);
		if (!p) { fprintf(stderr, "buffer pool exhausted\n"); exit(1); }
		csp_id_clear(&p->id);
		p->id.pri = 2; p->id.src = 1; p->id.dst = 8;
		p->id.sport = 10; p->id.dport = 20; p->id.flags = 0;
		p->length = (uint16_t)lens[li];
		for (size_t i = 0; i < lens[li]; i++) p->data[i] = (uint8_t)(i & 0xff);
		if (can_if.nexthop(&can_if, 8, p, 1) != CSP_ERR_NONE) {
			fprintf(stderr, "can tx failed for len=%zu\n", lens[li]);
			continue;
		}
		for (int f = 0; f < cancap_n; f++) {
			uint8_t rec[13];
			rec[0] = (uint8_t)(cancap[f].id >> 24);
			rec[1] = (uint8_t)(cancap[f].id >> 16);
			rec[2] = (uint8_t)(cancap[f].id >> 8);
			rec[3] = (uint8_t)cancap[f].id;
			rec[4] = cancap[f].dlc;
			memcpy(&rec[5], cancap[f].data, 8);
			char desc[80], kind[16];
			snprintf(desc, sizeof(desc), "v=%d,len=%zu,frame=%d/%d",
			         version, lens[li], f, cancap_n);
			snprintf(kind, sizeof(kind), "cfp_v%d", version);
			emit(kind, desc, rec, sizeof(rec));
		}
	}
}

/* ---- 7. KISS framing, including the escape cases ---- */
static void gen_kiss(int version) {
	/* 0xC0 (FEND) and 0xDB (FESC) must be escaped; a payload of each pins that. */
	static const uint8_t p_esc[] = {0xc0, 0xdb, 0xc0, 0xdb};
	static const uint8_t p_plain[] = {0x41, 0x42, 0x43};
	static const struct { const uint8_t * d; size_t n; const char * label; } cases[] = {
		{NULL, 0, "empty"},
		{p_plain, sizeof(p_plain), "abc"},
		{p_esc, sizeof(p_esc), "escapes"},
	};
	for (size_t ci = 0; ci < sizeof(cases) / sizeof(cases[0]); ci++) {
		kisscap_n = 0;
		csp_packet_t * p = csp_buffer_get(0);
		if (!p) { fprintf(stderr, "buffer pool exhausted\n"); exit(1); }
		csp_id_clear(&p->id);
		p->id.pri = 2; p->id.src = 1; p->id.dst = 8;
		p->id.sport = 10; p->id.dport = 20; p->id.flags = 0;
		p->length = (uint16_t)cases[ci].n;
		if (cases[ci].d) memcpy(p->data, cases[ci].d, cases[ci].n);
		if (csp_kiss_tx(&kiss_if, 8, p, 1) != CSP_ERR_NONE) {
			fprintf(stderr, "kiss tx failed\n");
			continue;
		}
		char desc[80], kind[16];
		snprintf(desc, sizeof(desc), "v=%d,payload=%s", version, cases[ci].label);
		snprintf(kind, sizeof(kind), "kiss_v%d", version);
		emit(kind, desc, kisscap, kisscap_n);
	}
}

/* ---- 8. SFP fragmentation ---- */
struct sfp_src { const uint8_t * data; uint32_t len; };

static int sfp_read(uint8_t * buffer, uint32_t size, uint32_t offset, void * data) {
	struct sfp_src * s = data;
	if (offset + size > s->len) return CSP_ERR_INVAL;
	memcpy(buffer, s->data + offset, size);
	return CSP_ERR_NONE;
}

static void gen_sfp(int version) {
	static uint8_t big[900];
	for (size_t i = 0; i < sizeof(big); i++) big[i] = (uint8_t)(i * 7);

	static const uint32_t totals[] = {1, 10, 100, 250, 500, 900};
	static const uint32_t mtus[] = {32, 100, 200};
	for (size_t ti = 0; ti < sizeof(totals) / sizeof(totals[0]); ti++) {
		for (size_t mi = 0; mi < sizeof(mtus) / sizeof(mtus[0]); mi++) {
			cap_reset();
			csp_conn_t * conn = csp_connect(CSP_PRIO_NORM, 8, 20, 1000, CSP_O_NONE);
			if (!conn) { fprintf(stderr, "sfp: connect failed\n"); return; }
			struct sfp_src src = {big, totals[ti]};
			csp_sfp_read_t reader = {.read = sfp_read, .data = &src};
			int rc = csp_sfp_send(conn, &reader, totals[ti], mtus[mi], 1000);
			char desc[96], kind[16];
			snprintf(kind, sizeof(kind), "sfp_v%d", version);
			if (rc != CSP_ERR_NONE) {
				snprintf(desc, sizeof(desc), "v=%d,total=%u,mtu=%u,rc=%d",
				         version, totals[ti], mtus[mi], rc);
				emit(kind, desc, NULL, 0);
			} else {
				for (int f = 0; f < cap_n; f++) {
					snprintf(desc, sizeof(desc), "v=%d,total=%u,mtu=%u,frag=%d/%d",
					         version, totals[ti], mtus[mi], f, cap_n);
					emit(kind, desc, cap[f].frame, cap[f].len);
				}
			}
			csp_close(conn);
		}
	}
	/* MTU accounting is what keeps the appended headers in range, so pin it. */
	static const uint32_t optsets[] = {
		CSP_O_NONE, CSP_O_RDP, CSP_O_CRC32, CSP_O_HMAC,
		CSP_O_RDP | CSP_O_CRC32, CSP_O_RDP | CSP_O_CRC32 | CSP_O_HMAC,
	};
	for (size_t i = 0; i < sizeof(optsets) / sizeof(optsets[0]); i++) {
		char desc[64];
		snprintf(desc, sizeof(desc), "opts=0x%x", optsets[i]);
		emit_u32("sfp_max_mtu", desc, csp_sfp_opts_max_mtu(optsets[i]));
	}
}

/* ---- 9. Built-in service replies, captured off the wire ---- */
static void gen_services(int version) {
	static const uint8_t svc[] = {
		CSP_CMP, CSP_PING, CSP_PS, CSP_MEMFREE, CSP_REBOOT, CSP_BUF_FREE, CSP_UPTIME,
	};
	for (size_t i = 0; i < sizeof(svc) / sizeof(svc[0]); i++) {
		/* Reboot/shutdown would actually reboot via the hook; skip. */
		if (svc[i] == CSP_REBOOT) continue;
		cap_reset();
		csp_packet_t * p = csp_buffer_get(0);
		if (!p) { fprintf(stderr, "buffer pool exhausted\n"); exit(1); }
		csp_id_clear(&p->id);
		p->id.pri = 2; p->id.src = 8; p->id.dst = 1;
		p->id.sport = 40; p->id.dport = svc[i]; p->id.flags = 0;
		p->length = 4;
		memcpy(p->data, "ping", 4);
		csp_service_handler(p);
		char desc[80], kind[16];
		snprintf(kind, sizeof(kind), "service_v%d", version);
		snprintf(desc, sizeof(desc), "v=%d,port=%u,replies=%d", version, svc[i], cap_n);
		/* Uptime and memfree carry live values; record only the shape. */
		emit(kind, desc, NULL, 0);
	}
}

/*
 * One process per wire version, on purpose.
 *
 * csp_conf.version must not change after csp_init(): host_bits (5 for v1,
 * 14 for v2) is baked into the routing and broadcast maths at init time, so
 * flipping the version afterwards misroutes every packet into the qfifo,
 * where nothing drains it. Measured: v1 sends 18/18 clean, then the same
 * sends under a switched-to-v2 config leak one buffer per fragment until the
 * pool is empty and everything returns CSP_ERR_NOMEM.
 *
 * The Rust port makes this unrepresentable by making the version an immutable
 * field of the Csp value.
 */
int main(int argc, char ** argv) {
	int version = (argc > 1) ? atoi(argv[1]) : 1;
	/* No default path. It used to be "vectors/vectors.tsv", and the file that run produced
	   sat in the tree for months, loaded by nothing -- `csp-core/tests/vectors.rs` reads
	   v1.tsv and v2.tsv -- while COMPARISON.md counted its 412 lines as evidence. */
	const char * path = (argc > 2) ? argv[2] : NULL;
	if ((version != 1 && version != 2) || path == NULL) {
		fprintf(stderr, "usage: %s <1|2> <outfile>\n", argv[0]);
		return 2;
	}
	out = fopen(path, "w");
	if (!out) { perror("fopen"); return 1; }

	fprintf(out, "# libcsp golden vectors, CSP wire version %d\n", version);
	fprintf(out, "# generated by oracle/gen_vectors.c against the libcsp submodule\n");
	fprintf(out, "# format: kind\\tinput-description\\toutput-hex\n");

	csp_conf.version = (uint8_t)version;
	csp_conf.hostname = "oracle";
	csp_conf.model = "vectors";
	csp_conf.revision = "1";
	csp_init();

	csp_iflist_add(&cap_if);
	csp_rtable_set(0, 0, &cap_if, CSP_NO_VIA_ADDRESS);

	can_ifdata.tx_func = can_tx_capture;
	can_ifdata.pbufs = NULL;
	atomic_store(&can_ifdata.cfp_packet_counter, 0);
	csp_can_add_interface(&can_if);

	kiss_ifdata.tx_func = kiss_tx_capture;
	csp_kiss_add_interface(&kiss_if);

	int start = csp_buffer_remaining();
	gen_id(version);
	gen_id_params(version);
	if (version == 1) {
		/* Version-independent; emit once so the vector file has no duplicates. */
		gen_crc32();
		gen_sha1();
		gen_hmac();
	}
	gen_cfp(version);
	gen_kiss(version);
	gen_sfp(version);
	gen_services(version);

	int end = csp_buffer_remaining();
	fclose(out);
	if (start != end) {
		fprintf(stderr, "LEAK: v%d buffers %d -> %d\n", version, start, end);
		return 1;
	}
	fprintf(stderr, "wrote %s (v%d, no leak: %d buffers)\n", path, version, end);
	return 0;
}
