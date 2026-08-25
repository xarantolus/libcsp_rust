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
