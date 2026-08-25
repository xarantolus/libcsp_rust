/*
 * Thin C shim exposing the libcsp entry points the differential tests compare against.
 *
 * Kept deliberately small: it does nothing but call libcsp and copy results out, so a
 * disagreement is a disagreement between the two implementations, not between the
 * implementations and this file.
 */
#include <string.h>
#include <stdint.h>

#include <csp/csp.h>
#include <csp/csp_id.h>
#include <csp/csp_crc32.h>
#include <csp/crypto/csp_sha1.h>
#include <csp/crypto/csp_hmac.h>

/* csp_id_* dispatch on the global csp_conf.version. */
void shim_set_version(int v) {
	csp_conf.version = (uint8_t)v;
}

/*
 * Encode a header. Returns the header size, or -1 if the version is bad.
 *
 * NOTE: libcsp masks nothing on encode -- an out-of-range field is shifted straight into
 * its neighbour. That is deliberate here: the fuzzer needs to see what the C actually
 * produces, including for inputs the Rust refuses.
 */
int shim_id_encode(uint8_t pri, uint8_t flags, uint16_t src, uint16_t dst,
                   uint8_t dport, uint8_t sport, uint8_t *out) {
	csp_packet_t packet;
	memset(&packet, 0, sizeof(packet));
	packet.id.pri = pri;
	packet.id.flags = flags;
	packet.id.src = src;
	packet.id.dst = dst;
	packet.id.dport = dport;
	packet.id.sport = sport;
	packet.length = 0;
	packet.frame_begin = packet.data;

	csp_id_prepend(&packet);

	int n = csp_id_get_header_size();
	memcpy(out, packet.frame_begin, (size_t)n);
	return n;
}

/* Decode a header into the six fields. */
void shim_id_decode(const uint8_t *data, uint8_t *pri, uint8_t *flags,
                    uint16_t *src, uint16_t *dst, uint8_t *dport, uint8_t *sport) {
	csp_id_t id = csp_id_extract(data);
	*pri = id.pri;
	*flags = id.flags;
	*src = id.src;
	*dst = id.dst;
	*dport = id.dport;
	*sport = id.sport;
}

int shim_header_size(void) { return csp_id_get_header_size(); }
unsigned int shim_host_bits(void) { return csp_id_get_host_bits(); }
unsigned int shim_max_nodeid(void) { return csp_id_get_max_nodeid(); }
unsigned int shim_max_port(void) { return csp_id_get_max_port(); }

int shim_is_broadcast(uint16_t addr, uint16_t iface_addr, uint16_t iface_netmask) {
	csp_iface_t ifc;
	memset(&ifc, 0, sizeof(ifc));
	ifc.addr = iface_addr;
	ifc.netmask = iface_netmask;
	return csp_id_is_broadcast(addr, &ifc);
}

uint32_t shim_crc32(const uint8_t *data, uint32_t len) {
	return csp_crc32_memory(data, len);
}

void shim_sha1(const uint8_t *data, uint32_t len, uint8_t *out20) {
	csp_sha1_memory(data, len, out20);
}

/*
 * Returns 0 on success. `out` must be 20 bytes: csp_hmac_memory writes the FULL digest
 * even though CSP_HMAC_LENGTH is 4, which is a buffer overflow waiting for any caller who
 * reads the constant and sizes accordingly.
 */
int shim_hmac(const uint8_t *key, uint32_t keylen,
              const uint8_t *data, uint32_t datalen, uint8_t *out20) {
	return csp_hmac_memory(key, keylen, data, datalen, out20);
}

/* --- CFP identifier packing, straight from the csp_if_can.h macros --- */
#include <csp/interfaces/csp_if_can.h>

uint32_t shim_cfp1_make(uint16_t src, uint16_t dst, uint32_t type,
                        uint32_t remain, uint16_t ident) {
	return (CFP_MAKE_SRC(src) | CFP_MAKE_DST(dst) | CFP_MAKE_TYPE(type) |
	        CFP_MAKE_REMAIN(remain) | CFP_MAKE_ID(ident));
}

void shim_cfp1_parse(uint32_t id, uint16_t *src, uint16_t *dst, uint32_t *type,
                     uint32_t *remain, uint16_t *ident) {
	*src = (uint16_t)CFP_SRC(id);
	*dst = (uint16_t)CFP_DST(id);
	*type = CFP_TYPE(id);
	*remain = CFP_REMAIN(id);
	*ident = (uint16_t)CFP_ID(id);
}

/* ---- CFP2: the CAN identifier layout for CSP v2 ---- */

uint32_t shim_cfp2_make(uint16_t pri, uint16_t dst, uint16_t sender,
                        uint16_t sc, uint16_t fc, uint16_t begin, uint16_t end) {
	return (((uint32_t)(pri & CFP2_PRIO_MASK) << CFP2_PRIO_OFFSET) |
	        ((uint32_t)(dst & CFP2_DST_MASK) << CFP2_DST_OFFSET) |
	        ((uint32_t)(sender & CFP2_SENDER_MASK) << CFP2_SENDER_OFFSET) |
	        ((uint32_t)(sc & CFP2_SC_MASK) << CFP2_SC_OFFSET) |
	        ((uint32_t)(fc & CFP2_FC_MASK) << CFP2_FC_OFFSET) |
	        ((uint32_t)(begin & CFP2_BEGIN_MASK) << CFP2_BEGIN_OFFSET) |
	        ((uint32_t)(end & CFP2_END_MASK) << CFP2_END_OFFSET));
}

void shim_cfp2_parse(uint32_t id, uint16_t *pri, uint16_t *dst, uint16_t *sender,
                     uint16_t *sc, uint16_t *fc, uint16_t *begin, uint16_t *end) {
	*pri    = (uint16_t)((id >> CFP2_PRIO_OFFSET) & CFP2_PRIO_MASK);
	*dst    = (uint16_t)((id >> CFP2_DST_OFFSET) & CFP2_DST_MASK);
	*sender = (uint16_t)((id >> CFP2_SENDER_OFFSET) & CFP2_SENDER_MASK);
	*sc     = (uint16_t)((id >> CFP2_SC_OFFSET) & CFP2_SC_MASK);
	*fc     = (uint16_t)((id >> CFP2_FC_OFFSET) & CFP2_FC_MASK);
	*begin  = (uint16_t)((id >> CFP2_BEGIN_OFFSET) & CFP2_BEGIN_MASK);
	*end    = (uint16_t)((id >> CFP2_END_OFFSET) & CFP2_END_MASK);
}

/* ---- routing table: parse a text table and look addresses up in it ---- */

#include <csp/csp_rtable.h>

/*
 * Parse `text` into the C's routing table and report what it did.
 *
 * Returns csp_rtable_load's result. The table is cleared first so each call is
 * independent.
 */
int shim_rtable_load(const char *text) {
	csp_rtable_clear();
	return csp_rtable_load(text);
}

/* Validate without installing. */
int shim_rtable_check(const char *text) {
	return csp_rtable_check(text);
}

/*
 * Look `addr` up in the table loaded by shim_rtable_load.
 *
 * Writes the interface name into `name` (at least 16 bytes) and the via address into
 * `via`. Returns 1 if a route was found, 0 if not.
 */
int shim_rtable_lookup(uint16_t addr, char *name, uint16_t *via) {
	csp_route_t *r = csp_rtable_find_route(addr);
	if (r == NULL) {
		return 0;
	}
	name[0] = '\0';
	if (r->iface != NULL && r->iface->name != NULL) {
		strncpy(name, r->iface->name, 15);
		name[15] = '\0';
	}
	*via = r->via;
	return 1;
}

/* ---- interface registration, so route tables have something to name ---- */

#include <csp/csp_iflist.h>

/* Static storage: csp_iflist_add keeps the pointer, so these must outlive every call. */
static csp_iface_t shim_ifaces[4];
static char shim_iface_names[4][CSP_IFLIST_NAME_MAX + 1];
static int shim_iface_count = 0;

/*
 * Register an interface under `name`. Returns 0 on success, -1 if full.
 *
 * Interfaces are never removed: csp_iflist_remove exists but the tests only ever add the
 * same fixed set once, before any table is parsed.
 */
int shim_add_iface(const char *name, uint16_t addr, uint16_t netmask) {
	if (shim_iface_count >= 4) {
		return -1;
	}
	int i = shim_iface_count++;
	strncpy(shim_iface_names[i], name, CSP_IFLIST_NAME_MAX);
	shim_iface_names[i][CSP_IFLIST_NAME_MAX] = '\0';
	memset(&shim_ifaces[i], 0, sizeof(shim_ifaces[i]));
	shim_ifaces[i].name = shim_iface_names[i];
	shim_ifaces[i].addr = addr;
	shim_ifaces[i].netmask = netmask;
	csp_iflist_add(&shim_ifaces[i]);
	return 0;
}

int shim_iface_registered(const char *name) {
	return csp_iflist_get_by_name(name) != NULL;
}

/* ---- KISS framing: drive the real RX state machine ---- */

#include <csp/interfaces/csp_if_kiss.h>
#include <csp/csp_buffer.h>
#include <csp/csp_id.h>

static csp_iface_t shim_kiss_iface;
static csp_kiss_interface_data_t shim_kiss_data;
static uint8_t shim_kiss_out[CSP_BUFFER_SIZE];
static int shim_kiss_out_len = -1;
static int shim_kiss_frames = 0;

static uint8_t shim_kiss_id[6];
static int shim_kiss_id_len = 0;

/*
 * csp_kiss_rx hands finished frames to csp_qfifo_write. Overriding it here captures the
 * result instead of routing it, which is the only way to see what the state machine
 * produced without linking the whole router.
 *
 * Note what the C's KISS layer has already done by this point: de-escaped the stream,
 * dropped the TNC command byte, and run csp_id_strip. So the packet is a *parsed* CSP
 * packet, not a framing result -- `data`/`length` is the payload and the header has been
 * consumed. That layering is why this shim reports the payload and the re-encoded id
 * rather than raw frame bytes.
 */
void csp_qfifo_write(csp_packet_t *packet, csp_iface_t *iface, void *pxTaskWoken) {
	(void)iface;
	(void)pxTaskWoken;
	if (packet == NULL) {
		return;
	}
	shim_kiss_frames++;
	int n = (int)packet->length;
	if (n > (int)sizeof(shim_kiss_out)) {
		n = (int)sizeof(shim_kiss_out);
	}
	memcpy(shim_kiss_out, packet->data, (size_t)n);
	shim_kiss_out_len = n;

	/* Re-encode the parsed id so the caller can compare it without a second binding. */
	csp_id_prepend(packet);
	shim_kiss_id_len = (int)csp_id_get_header_size();
	memcpy(shim_kiss_id, packet->frame_begin, (size_t)shim_kiss_id_len);

	csp_buffer_free(packet);
}

int shim_kiss_last_id(uint8_t *out) {
	memcpy(out, shim_kiss_id, (size_t)shim_kiss_id_len);
	return shim_kiss_id_len;
}

/*
 * csp_buffer.c calls this, and its only definition lives in csp_io.c -- which would drag
 * in the router, the connection table and the promiscuous tap. It is a memset by another
 * name and nothing under test depends on it, so it is provided here instead.
 */
void csp_id_clear(csp_id_t *target) {
	target->pri = 0;
	target->dst = 0;
	target->src = 0;
	target->dport = 0;
	target->sport = 0;
	target->flags = 0;
}

void shim_kiss_reset(void) {
	/* csp_init would do this; the tests never call it, so the pool starts empty. */
	static int pool_ready = 0;
	if (!pool_ready) {
		csp_buffer_init();
		pool_ready = 1;
	}
	/*
	 * A stream that ends mid-frame leaves a buffer held in rx_packet. Zeroing the struct
	 * without freeing it leaks one buffer per call, and csp_buffer_get_always blocks once
	 * the pool is empty -- so the harness hangs rather than failing.
	 */
	if (shim_kiss_data.rx_packet != NULL) {
		csp_buffer_free(shim_kiss_data.rx_packet);
		shim_kiss_data.rx_packet = NULL;
	}
	memset(&shim_kiss_iface, 0, sizeof(shim_kiss_iface));
	memset(&shim_kiss_data, 0, sizeof(shim_kiss_data));
	shim_kiss_iface.name = "KISSDIFF";
	shim_kiss_iface.interface_data = &shim_kiss_data;
	shim_kiss_out_len = -1;
	shim_kiss_frames = 0;
	shim_kiss_id_len = 0;
}

/*
 * Feed `len` bytes to the decoder.
 *
 * Returns the number of complete frames it produced. The last frame's bytes are copied
 * into `out` and its length returned via `out_len` (-1 if no frame completed).
 */
int shim_kiss_feed(const uint8_t *buf, uint32_t len, uint8_t *out, int *out_len) {
	csp_kiss_rx(&shim_kiss_iface, buf, len, NULL);
	if (shim_kiss_out_len >= 0) {
		memcpy(out, shim_kiss_out, (size_t)shim_kiss_out_len);
	}
	*out_len = shim_kiss_out_len;
	return shim_kiss_frames;
}

uint32_t shim_kiss_rx_errors(void) { return shim_kiss_iface.rx_error; }
uint32_t shim_kiss_drops(void) { return shim_kiss_iface.drop; }
uint32_t shim_kiss_frame_errors(void) { return shim_kiss_iface.frame; }
