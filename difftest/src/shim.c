/*
 * Thin C shim exposing the libcsp entry points the differential tests compare against.
 *
 * Kept deliberately small: it does nothing but call libcsp and copy results out, so a
 * disagreement is a disagreement between the two implementations, not between the
 * implementations and this file.
 */
#include <endian.h>
#include <pthread.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include <csp/csp.h>
#include <csp/csp_id.h>
#include <csp/csp_crc32.h>
#include <csp/crypto/csp_sha1.h>
#include <csp/crypto/csp_hmac.h>
#include <csp/csp_sfp.h>
#include <csp/csp_cmp.h>
#include <csp/csp_hooks.h>
#include <csp/interfaces/csp_if_lo.h>
#include <csp/interfaces/csp_if_i2c.h>

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

/*
 * The same, through `csp_id_prepend_fixup_cspv1`.
 *
 * `csp_id1_prepend(packet, true)` swaps `htobe32` for `htole32` (`csp_id.c:57`), so a v1
 * header comes out in the *host's* byte order rather than network order. At v2 the fixup
 * path is `csp_id2_prepend` unchanged. Compiled only when
 * `CSP_FIXUP_V1_ZMQ_LITTLE_ENDIAN` is set, which the canonical build does.
 *
 * Its one caller in libcsp is `csp_if_zmqhub.c`, which is out of scope -- this exists so
 * that "not the same as `csp_id_prepend`" is a measurement rather than a reading of the
 * `#if`.
 */
int shim_id_encode_fixup(uint8_t pri, uint8_t flags, uint16_t src, uint16_t dst,
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

	csp_id_prepend_fixup_cspv1(&packet);

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

/*
 * `csp_rtable_save` on whatever `shim_rtable_load` last installed.
 *
 * The text a ground tool reads back off a node. `csp_rtable_save_route`
 * (`csp_rtable_stdio.c:80`) omits the netmask when it equals the host-bit width, omits the
 * via when there is none, skips the loopback interface, and joins entries with a comma --
 * none of which the port's per-route formatter had ever been compared against.
 *
 * Returns the length written, or a negative libcsp error.
 */
int shim_rtable_save(char *out, int maxlen) {
	int rc = csp_rtable_save(out, (size_t)maxlen);
	if (rc != CSP_ERR_NONE) { return rc; }
	return (int)strlen(out);
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
#include "csp_qfifo.h"
/* The connection struct is opaque in the public header; the reset below needs its
   `state` field and libcsp's own `csp_conn_get_array` test hook. */
#include "csp_conn.h"
#include "csp_rdp_queue.h"
#include <csp/csp_id.h>

static csp_iface_t shim_kiss_iface;
static csp_kiss_interface_data_t shim_kiss_data;
static uint8_t shim_kiss_out[CSP_BUFFER_SIZE];
static int shim_kiss_out_len = -1;
static int shim_kiss_frames = 0;

static uint8_t shim_kiss_id[6];
static int shim_kiss_id_len = 0;

/*
 * Drain whatever csp_kiss_rx pushed into the real qfifo.
 *
 * Earlier this overrode csp_qfifo_write. Now the whole node is linked, so the real queue
 * is used and drained here -- one less place where the harness and the library could
 * disagree about what "a frame arrived" means.
 */
static void shim_kiss_drain(void) {
	/*
	 * csp_qfifo_read blocks for FIFO_TIMEOUT (100 ms with RDP) on an empty queue, which is
	 * far too slow to call in a loop. csp_qfifo_wake_up enqueues a {NULL, NULL} sentinel --
	 * the library's own testing hook -- so every real packet returns immediately and the
	 * sentinel marks the end.
	 */
	csp_qfifo_wake_up();
	csp_qfifo_t input;
	while (csp_qfifo_read(&input) == CSP_ERR_NONE) {
		csp_packet_t *packet = input.packet;
		if (packet == NULL) {
			break;  /* sentinel */
		}
		shim_kiss_frames++;
		int n = (int)packet->length;
		if (n > (int)sizeof(shim_kiss_out)) {
			n = (int)sizeof(shim_kiss_out);
		}
		memcpy(shim_kiss_out, packet->data, (size_t)n);
		shim_kiss_out_len = n;
		csp_id_prepend(packet);
		shim_kiss_id_len = (int)csp_id_get_header_size();
		memcpy(shim_kiss_id, packet->frame_begin, (size_t)shim_kiss_id_len);
		csp_buffer_free(packet);
	}
}

int shim_kiss_last_id(uint8_t *out) {
	memcpy(out, shim_kiss_id, (size_t)shim_kiss_id_len);
	return shim_kiss_id_len;
}

/*
 * csp_init exactly once, whoever asks first.
 *
 * Both the KISS decoder and the node harness need it: the decoder allocates from the
 * buffer pool and now drains the real qfifo, and the qfifo handle is only created by
 * csp_init. Calling it twice would leak port bindings (SCOPE.md deviation 2), so this is
 * the single place it happens.
 */
static int shim_csp_ready = 0;
static void shim_ensure_init(void) {
	if (!shim_csp_ready) {
		csp_init();
		shim_csp_ready = 1;
	}
}

void shim_kiss_reset(void) {
	shim_ensure_init();
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
	shim_kiss_drain();
	if (shim_kiss_out_len >= 0) {
		memcpy(out, shim_kiss_out, (size_t)shim_kiss_out_len);
	}
	*out_len = shim_kiss_out_len;
	return shim_kiss_frames;
}

uint32_t shim_kiss_rx_errors(void) { return shim_kiss_iface.rx_error; }
uint32_t shim_kiss_drops(void) { return shim_kiss_iface.drop; }
uint32_t shim_kiss_frame_errors(void) { return shim_kiss_iface.frame; }

/* =====================================================================
 * Node harness: a real C node, driven only at its observable boundary.
 *
 * Everything here is deliberately behaviour-level. The harness can inject a frame,
 * turn the router crank, read what the application received, and read what went out
 * on the wire. It never inspects a connection's internals, a queue index or a
 * refcount -- if a test needs one of those to pass, it is testing the C's
 * implementation rather than CSP, and the Rust port is entitled to differ.
 *
 * csp_init is called exactly once. Re-initialising leaks port bindings
 * (SCOPE.md deviation 2: csp_port.c has no csp_port_init and relies on .bss), which
 * is why libcsp's own suite forks per test. Here one node is set up and reused.
 * ===================================================================== */

#define SHIM_TX_MAX   16
#define SHIM_FRAME_MAX 300

static csp_iface_t  shim_node_iface;   /* ingress: where injected frames arrive */
static csp_iface_t  shim_node_iface_c;  /* a third subnet, so a routing-table entry can
                                         * point somewhere the local-subnet rule would
                                         * not have chosen -- which is how the two
                                         * precedence levels become distinguishable */
static csp_iface_t  shim_node_iface_b;  /* egress: a different subnet, so a forwarded
                                         * packet has somewhere to go. With one interface
                                         * split horizon vetoes forwarding and the C
                                         * correctly drops the packet. */
static uint8_t      shim_tx_buf[SHIM_TX_MAX][SHIM_FRAME_MAX];
static int          shim_tx_len[SHIM_TX_MAX];
static const char * shim_tx_if[SHIM_TX_MAX];   /* which interface each frame left by */
static uint16_t     shim_tx_via[SHIM_TX_MAX];  /* and the next hop it was given */
static int          shim_tx_n = 0;
static int          shim_node_ready = 0;

/* Capture nexthop: record the framed bytes, free the packet, report success. */
static int shim_node_tx_fn(csp_iface_t *iface, uint16_t via, csp_packet_t *packet, int from_me) {
	(void)from_me;
	csp_id_prepend(packet);
	if (shim_tx_n < SHIM_TX_MAX) {
		int n = (int)packet->frame_length;
		if (n > SHIM_FRAME_MAX) { n = SHIM_FRAME_MAX; }
		memcpy(shim_tx_buf[shim_tx_n], packet->frame_begin, (size_t)n);
		shim_tx_len[shim_tx_n] = n;
		shim_tx_if[shim_tx_n]  = iface ? iface->name : "?";
		shim_tx_via[shim_tx_n] = via;
		shim_tx_n++;
	}
	csp_buffer_free(packet);
	return CSP_ERR_NONE;
}

/*
 * Bring up a node at `address` on wire version `version`, with one capture interface
 * that is the default route. Idempotent: the first call wins, later calls only check
 * the parameters still match.
 */
int shim_node_init(int version, uint16_t address, uint16_t netmask, uint16_t egress, uint16_t third) {
	if (shim_node_ready) {
		return (csp_conf.version == (uint8_t)version && shim_node_iface.addr == address) ? 0 : -1;
	}
	/* No global node address in libcsp 2.x: "is it for me" is decided by
	 * csp_iflist_get_by_addr, so the interface address below IS the node address. */
	csp_conf.version = (uint8_t)version;
	shim_ensure_init();

	/* The two interfaces must land in different subnets or split horizon vetoes
	 * forwarding. What netmask achieves that depends on the wire version: v1 has 5 host
	 * bits and v2 has 14, so the caller supplies it rather than the shim assuming v1. */
	memset(&shim_node_iface, 0, sizeof(shim_node_iface));
	shim_node_iface.name    = "INGRESS";
	shim_node_iface.addr    = address;
	shim_node_iface.netmask = netmask;
	shim_node_iface.nexthop = shim_node_tx_fn;
	csp_iflist_add(&shim_node_iface);

	memset(&shim_node_iface_b, 0, sizeof(shim_node_iface_b));
	shim_node_iface_b.name    = "EGRESS";
	shim_node_iface_b.addr    = egress;
	shim_node_iface_b.netmask = netmask;
	shim_node_iface_b.nexthop = shim_node_tx_fn;
	shim_node_iface_b.is_default = 1;
	csp_iflist_add(&shim_node_iface_b);

	memset(&shim_node_iface_c, 0, sizeof(shim_node_iface_c));
	shim_node_iface_c.name    = "ROUTED";
	shim_node_iface_c.addr    = third;
	shim_node_iface_c.netmask = netmask;
	shim_node_iface_c.nexthop = shim_node_tx_fn;
	csp_iflist_add(&shim_node_iface_c);

	shim_node_ready = 1;
	return 0;
}

/* Forget captured egress. Does not touch connections -- that is the node's business. */
void shim_node_clear_tx(void) { shim_tx_n = 0; }

int shim_node_tx_count(void) { return shim_tx_n; }

int shim_node_tx_get(int i, uint8_t *out) {
	if (i < 0 || i >= shim_tx_n) { return -1; }
	memcpy(out, shim_tx_buf[i], (size_t)shim_tx_len[i]);
	return shim_tx_len[i];
}

/* Name of the interface frame `i` left by, and the via it carried. */
int shim_node_tx_iface(int i, uint8_t *name, uint16_t *via) {
	if (i < 0 || i >= shim_tx_n) { return -1; }
	const char *n = shim_tx_if[i] ? shim_tx_if[i] : "?";
	size_t len = strlen(n);
	if (len > 15) { len = 15; }
	memcpy(name, n, len);
	*via = shim_tx_via[i];
	return (int)len;
}

/* Install a routing-table entry on the C node. iface: 0=INGRESS 1=EGRESS 2=ROUTED. */
int shim_node_route(uint16_t address, int netmask, int iface, uint16_t via) {
	csp_iface_t *target = iface == 0 ? &shim_node_iface
	                    : iface == 1 ? &shim_node_iface_b
	                                 : &shim_node_iface_c;
	return csp_rtable_set(address, netmask, target, via);
}

/* Hand a complete on-the-wire frame to the node, as a driver would. */
int shim_node_inject(const uint8_t *frame, uint32_t len) {
	csp_packet_t *packet = csp_buffer_get(0);
	if (packet == NULL) { return -1; }
	int hdr = csp_id_setup_rx(packet);
	(void)hdr;
	if (len > (uint32_t)(sizeof(packet->data) + 8)) { csp_buffer_free(packet); return -1; }
	memcpy(packet->frame_begin, frame, len);
	packet->frame_length = (uint16_t)len;
	if (csp_id_strip(packet) != 0) { csp_buffer_free(packet); return -2; }
	csp_qfifo_write(packet, &shim_node_iface, NULL);
	return 0;
}

/*
 * Turn the router crank until the queue is empty, using the wake-up sentinel so an
 * empty queue costs nothing. Returns how many packets the router consumed.
 */
int shim_node_pump(void) {
	int n = 0;
	csp_qfifo_wake_up();
	while (csp_route_work() == CSP_ERR_NONE) { n++; }
	return n;
}

/* --- the default-interface convenience ----------------------------------- */

/*
 * `csp_iflist_check_dfl`: if no interface is marked default, mark every one except the
 * loopback (`csp_iflist.c:148`).
 *
 * Nothing in libcsp calls it. It is declared in `csp_iflist.h`, documented in the RST, and
 * grepping the whole tree finds the definition and no caller -- `csp_init` registers
 * loopback and touches `is_default` on nothing. So a stock C node has **no** default
 * interface unless its application says so, either by setting the field or by calling this.
 *
 * These two entry points make both of its branches reachable: the early return when
 * something is already default, and the sweep when nothing is. Clearing is not a libcsp
 * operation -- it writes the same public struct field an application sets -- and it exists
 * because the harness's own EGRESS is registered as a default.
 */
void shim_iflist_check_dfl(void) {
	csp_iflist_check_dfl();
}

void shim_iflist_clear_dfl(void) {
	shim_node_iface.is_default = 0;
	shim_node_iface_b.is_default = 0;
	shim_node_iface_c.is_default = 0;
	csp_if_lo.is_default = 0;
}

/* Whether the named interface is currently a default-route target. -1 if unknown. */
int shim_iface_is_default(const char *name) {
	csp_iface_t *i = csp_iflist_get_by_name(name);
	return i ? (int)i->is_default : -1;
}

/* --- the Ethernet ARP table ---------------------------------------------- */

#include <csp/interfaces/csp_if_eth.h>

/*
 * `csp_eth_arp_set_addr` / `csp_eth_arp_get_addr` decide the destination MAC of every
 * outgoing Ethernet frame, and neither harness had ever called them.
 *
 * Two rules worth measuring rather than reading: `set` **returns without updating** when an
 * entry for that CSP address already exists (`csp_if_eth.c:101`, "Already set"), and `get`
 * falls back to the broadcast MAC for an address it has never heard of
 * (`csp_if_eth.c:133`). A third follows from `arp_alloc`: the array is a bump allocator with
 * no eviction, so after ARP_MAX_ENTRIES distinct addresses nothing new is ever learned.
 *
 * The table is a file-scope list with no reset, so a test must use fresh CSP addresses
 * rather than expect to start empty.
 */
void shim_arp_set(uint16_t csp_addr, const uint8_t *mac) {
	uint8_t copy[6];
	memcpy(copy, mac, sizeof(copy));
	csp_eth_arp_set_addr(copy, csp_addr);
}

void shim_arp_get(uint16_t csp_addr, uint8_t *mac_out) {
	csp_eth_arp_get_addr(mac_out, csp_addr);
}

/* --- CMP memory access, bounded ------------------------------------------ */

/*
 * `csp_cmp_memcpy`, `csp_cmp_memread64` and `csp_cmp_memwrite64` are `__weak` in libcsp
 * (`csp_cmp_mem.c:21`), and the defaults are bare memcpys from whatever address the request
 * carries. A peek at a made-up address on a POSIX host segfaults, so the tests would be
 * testing the harness's luck. These strong definitions bound it to one region, which is what
 * `ctest/` does for the 32-bit codes and what nothing did for the 64-bit ones.
 */
#define SHIM_MEM_LEN 256
static uint8_t shim_mem[SHIM_MEM_LEN];

/* The address the region answers to, chosen high enough to be obviously not a real one. */
#define SHIM_MEM_BASE 0x0000BEEF00000000ULL

static int shim_mem_slice(uint64_t addr, size_t size, uint8_t **out) {
	if (addr < SHIM_MEM_BASE) { return CSP_ERR_INVAL; }
	uint64_t off = addr - SHIM_MEM_BASE;
	if (off > SHIM_MEM_LEN || size > SHIM_MEM_LEN - off) { return CSP_ERR_INVAL; }
	*out = shim_mem + off;
	return CSP_ERR_NONE;
}

int csp_cmp_memcpy(csp_memptr_t to, csp_const_memptr_t from, size_t size) {
	uint8_t *region;
	/* Exactly one of the two is an address from the request; the other is packet storage. */
	if (shim_mem_slice((uint64_t)(uintptr_t)from, size, &region) == CSP_ERR_NONE) {
		memcpy(to, region, size);
		return CSP_ERR_NONE;
	}
	if (shim_mem_slice((uint64_t)(uintptr_t)to, size, &region) == CSP_ERR_NONE) {
		memcpy(region, (const void *)from, size);
		return CSP_ERR_NONE;
	}
	return CSP_ERR_INVAL;
}

int csp_cmp_memread64(csp_const_memptr_t to, csp_memptr64_t from, size_t size) {
	uint8_t *region;
	int rc = shim_mem_slice(from, size, &region);
	if (rc != CSP_ERR_NONE) { return rc; }
	memcpy((void *)(uintptr_t)to, region, size);
	return CSP_ERR_NONE;
}

int csp_cmp_memwrite64(csp_memptr64_t to, csp_memptr_t from, size_t size) {
	uint8_t *region;
	int rc = shim_mem_slice(to, size, &region);
	if (rc != CSP_ERR_NONE) { return rc; }
	memcpy(region, from, size);
	return CSP_ERR_NONE;
}

/* The base address the peek/poke region answers to. */
uint64_t shim_mem_base(void) { return SHIM_MEM_BASE; }

/* Fill the region with `i * step + seed`, so a peek reply names the offset it came from. */
void shim_mem_fill(uint8_t seed, uint8_t step) {
	for (int i = 0; i < SHIM_MEM_LEN; i++) {
		shim_mem[i] = (uint8_t)(seed + (uint8_t)i * step);
	}
}

/* Read `len` bytes of the region back out, so a poke is observable. */
int shim_mem_read(uint32_t off, uint8_t *out, int len) {
	if (off > SHIM_MEM_LEN || len < 0 || (size_t)len > SHIM_MEM_LEN - off) { return -1; }
	memcpy(out, shim_mem + off, (size_t)len);
	return len;
}

/* --- what the application receives -------------------------------------- */

/* Must cover CSP_PORT_MAX_BIND; a port above this returned -1 and silently bound nothing. */
#define SHIM_PORTS 64
static csp_socket_t shim_sockets[SHIM_PORTS];
static int          shim_bound[SHIM_PORTS];

/*
 * Bind a port the way every surveyed consumer does: one socket, then accept.
 * Binding twice on the same port is a no-op rather than an error, so a test can
 * declare the ports it needs without tracking what an earlier case bound (the C
 * cannot unbind -- see SCOPE.md deviation 2).
 */
/* `csp_socket_close` on the socket bound to `port`: the port stops listening. */
int shim_node_unbind(uint8_t port) {
	if (port >= SHIM_PORTS || !shim_bound[port]) { return -1; }
	int r = csp_socket_close(&shim_sockets[port]);
	shim_bound[port] = 0;
	return r;
}

int shim_node_bind(uint8_t port) {
	if (port >= SHIM_PORTS) { return -1; }
	if (shim_bound[port]) { return 0; }
	memset(&shim_sockets[port], 0, sizeof(shim_sockets[port]));
	int rb = csp_bind(&shim_sockets[port], port);
	int rl = csp_listen(&shim_sockets[port], 4);
	if (rb != CSP_ERR_NONE) { return -10 + rb; }
	if (rl != CSP_ERR_NONE) { return -20 + rl; }
	shim_bound[port] = 1;
	return 0;
}

/*
 * The catch-all socket, bound with `csp_bind(sock, CSP_ANY)`.
 *
 * libcsp keeps it in a slot of its own past the port array (`csp_port.c:30`) and reaches
 * it only when the packet's own port has no socket, so a specific bind wins. It is a
 * separate socket here for the same reason it is in libcsp: which socket a delivery
 * arrives on is the whole question.
 */
static csp_socket_t shim_any_socket;
static int          shim_any_bound;

int shim_node_bind_any(void) {
	if (shim_any_bound) { return 0; }
	memset(&shim_any_socket, 0, sizeof(shim_any_socket));
	int rb = csp_bind(&shim_any_socket, CSP_ANY);
	int rl = csp_listen(&shim_any_socket, 4);
	if (rb != CSP_ERR_NONE) { return -10 + rb; }
	if (rl != CSP_ERR_NONE) { return -20 + rl; }
	shim_any_bound = 1;
	return 0;
}

/*
 * A connection-less socket -- `csp_bind` on a socket carrying `CSP_SO_CONN_LESS`.
 *
 * `csp_route_deliver_conn_less` (`csp_route.c:132`) puts the **packet** straight on the
 * socket's queue and creates no connection at all, which is the whole difference: a
 * conn-less server consumes nothing from the connection pool no matter how many peers
 * write to it. `csp_accept` refuses such a socket; `csp_recvfrom` is the only way in.
 */
static csp_socket_t shim_cl_socket;
static int          shim_cl_bound;

int shim_node_bind_conn_less(uint8_t port) {
	if (shim_cl_bound) { return 0; }
	memset(&shim_cl_socket, 0, sizeof(shim_cl_socket));
	shim_cl_socket.opts = CSP_SO_CONN_LESS;
	int rb = csp_bind(&shim_cl_socket, port);
	int rl = csp_listen(&shim_cl_socket, 4);
	if (rb != CSP_ERR_NONE) { return -10 + rb; }
	if (rl != CSP_ERR_NONE) { return -20 + rl; }
	shim_cl_bound = 1;
	return 0;
}

/* Take one packet off the conn-less socket. Returns 1 on a packet, 0 if none is waiting. */
int shim_node_recvfrom(uint16_t *src, uint16_t *dst, uint8_t *dport, uint8_t *sport,
                       uint8_t *out, int *out_len) {
	if (!shim_cl_bound) { return 0; }
	csp_packet_t *packet = csp_recvfrom(&shim_cl_socket, 0);
	if (packet == NULL) { return 0; }
	*src   = packet->id.src;
	*dst   = packet->id.dst;
	*dport = packet->id.dport;
	*sport = packet->id.sport;
	int n = (int)packet->length;
	memcpy(out, packet->data, (size_t)n);
	*out_len = n;
	csp_buffer_free(packet);
	return 1;
}

/* Close the catch-all socket, which is how libcsp releases a bind (`csp_port.c:138`). */
int shim_node_unbind_any(void) {
	if (!shim_any_bound) { return 0; }
	csp_dbg_errno = 0;
	csp_socket_close(&shim_any_socket);
	shim_any_bound = 0;
	return (int)csp_dbg_errno;
}

/* Shared by the per-port and catch-all readers: one accept, one read, then close. */
static int shim_take_one(csp_socket_t *sock, uint16_t *src, uint16_t *dst, uint8_t *dport,
                         uint8_t *sport, uint8_t *out, int *out_len) {
	csp_conn_t *conn = csp_accept(sock, 0);
	if (conn == NULL) { return 0; }
	csp_packet_t *packet = csp_read(conn, 0);
	if (packet == NULL) { csp_close(conn); return 0; }

	*src   = csp_conn_src(conn);
	*dst   = csp_conn_dst(conn);
	*dport = csp_conn_dport(conn);
	*sport = csp_conn_sport(conn);
	int n = (int)packet->length;
	memcpy(out, packet->data, (size_t)n);
	*out_len = n;

	csp_buffer_free(packet);
	csp_close(conn);
	return 1;
}

/*
 * Take one delivered message off `port`, if there is one.
 *
 * Reports the connection identity the application would see and the payload, which
 * together are the entire observable result of a delivery. Returns 1 on a message,
 * 0 if nothing is waiting.
 */
int shim_node_recv(uint8_t port, uint16_t *src, uint16_t *dst, uint8_t *dport,
                   uint8_t *sport, uint8_t *out, int *out_len) {
	if (port >= SHIM_PORTS || !shim_bound[port]) { return 0; }
	return shim_take_one(&shim_sockets[port], src, dst, dport, sport, out, out_len);
}

/* The same, off the catch-all. `dport` is what says which port it was addressed to. */
int shim_node_recv_any(uint16_t *src, uint16_t *dst, uint8_t *dport, uint8_t *sport,
                       uint8_t *out, int *out_len) {
	if (!shim_any_bound) { return 0; }
	return shim_take_one(&shim_any_socket, src, dst, dport, sport, out, out_len);
}

/*
 * Serve one request on `port` the way a real node's service task does: accept, read,
 * and hand the packet to `csp_service_handler`, which answers with
 * `csp_sendto_reply(packet, packet, CSP_O_SAME)` -- so the reply lands in the captured
 * egress like any other frame.
 *
 * This is what makes the *client* direction testable at all. Every node-level case before
 * it drove the server direction: a frame in, a delivery or a forward out. Nothing had a
 * real C node answer a request the port had sent, which is why the port shipped for months
 * with every reply to every connection it opened silently dropped.
 *
 * Returns 1 if a request was served, 0 if nothing was waiting.
 */
/*
 * A connection this port accepted and is holding open, per port. `shim_node_serve` and
 * `shim_node_recv` both `csp_close` when they are done, which on an RDP connection sends
 * the peer an RST -- correct, but it makes a multi-step exchange impossible.
 */
static csp_conn_t * shim_held[SHIM_PORTS];

/*
 * Let the C node *originate* data on a connection a peer opened to it.
 *
 * Every other node-level exchange has the port sending and the C receiving. This is the
 * other direction: the C accepts, keeps the connection, and calls `csp_send` on it -- so
 * for an RDP connection the bytes go out through `csp_rdp_send`, sequenced and held for
 * retransmission by libcsp itself. What comes back to the port is a real C peer's data,
 * which it then has to deliver and acknowledge.
 *
 * `csp_rdp_send` blocks when the send window is full. It is called here only with an open
 * window, so it returns; a test that queued more than `window_size` without letting the
 * port acknowledge would hang, which is the C's threading model and not something the
 * harness can paper over.
 *
 * Returns 1 if it sent, 0 if there was no connection to send on.
 */
int shim_node_send_on(uint8_t port, const uint8_t *body, int len) {
	if (port >= SHIM_PORTS || !shim_bound[port]) { return 0; }
	if (shim_held[port] == NULL) {
		shim_held[port] = csp_accept(&shim_sockets[port], 0);
	}
	if (shim_held[port] == NULL) { return 0; }
	/* Drain whatever the peer sent, so the connection is not holding buffers. */
	csp_packet_t *in;
	while ((in = csp_read(shim_held[port], 0)) != NULL) { csp_buffer_free(in); }

	csp_packet_t *out = csp_buffer_get(0);
	if (out == NULL) { return 0; }
	if (len > (int)sizeof(out->data)) { csp_buffer_free(out); return 0; }
	memcpy(out->data, body, (size_t)len);
	out->length = (uint16_t)len;
	/* `csp_send` returns void: it takes ownership and reports nothing, so "did it go out"
	   can only be answered by looking at the wire -- which is what the caller does. */
	csp_send(shim_held[port], out);
	return 1;
}

/*
 * Close a connection held by `shim_node_send_on`.
 *
 * On an RDP connection this starts the close *handshake* rather than finishing it:
 * `csp_conn_close` returns early when `csp_rdp_close` reports `CSP_ERR_AGAIN`
 * (`csp_conn.c:230`), before both the receive-queue flush and `csp_rdp_queue_flush`. So
 * anything held for retransmission stays held until the peer answers -- which is why the
 * caller gets the frames back, to feed them to the peer and let the close complete.
 */
void shim_node_release(uint8_t port) {
	if (port < SHIM_PORTS && shim_held[port] != NULL) {
		csp_close(shim_held[port]);
		shim_held[port] = NULL;
	}
	csp_qfifo_wake_up();
	while (csp_route_work() == CSP_ERR_NONE) { }
}

int shim_node_serve(uint8_t port) {
	if (port >= SHIM_PORTS || !shim_bound[port]) { return 0; }
	csp_conn_t *conn = csp_accept(&shim_sockets[port], 0);
	if (conn == NULL) { return 0; }
	csp_packet_t *packet = csp_read(conn, 0);
	if (packet == NULL) { csp_close(conn); return 0; }
	/* Ownership passes to the handler: it either replies with the packet or frees it. */
	csp_service_handler(packet);
	csp_close(conn);
	return 1;
}

/*
 * Set `csp_conf.dedup`, which decides *which* traffic the C deduplicates: off, forwarded
 * only, incoming only, or both (`csp_route.c:238`). Both stacks default to off, so the
 * interesting comparison only exists once it is switched on.
 */
void shim_node_set_dedup(int mode) { csp_conf.dedup = (uint8_t)mode; }

/*
 * The promiscuous tap: enable it, and drain what it saw.
 *
 * `csp_promisc_add` sits at `csp_route.c:252` -- *after* the deduplication check and
 * *before* the `is_to_me` branch -- so the tap sees forwarded traffic as well as traffic
 * for this node, and does not see a frame deduplication already suppressed. Both of those
 * are orderings a port can get wrong while every individual piece works.
 */
int shim_node_promisc_enable(void) { return csp_promisc_enable(16); }

/* Take one tapped packet, if any. Returns its payload length, or -1 when the tap is empty. */
int shim_node_promisc_read(uint8_t * out, uint16_t * dst) {
	csp_packet_t * p = csp_promisc_read(0);
	if (p == NULL) { return -1; }
	int n = (int)p->length;
	memcpy(out, p->data, (size_t)n);
	*dst = p->id.dst;
	csp_buffer_free(p);
	return n;
}

/*
 * Accept and close every connection waiting on `port`, draining each. Returns how many
 * connections the application could actually take.
 *
 * This is the observable that matters when the table runs out: not how many slots exist,
 * but how many peers the application can still serve, and whether refusing the rest costs
 * anything permanent.
 */
int shim_node_accept_count(uint8_t port) {
	if (port >= SHIM_PORTS || !shim_bound[port]) { return 0; }
	int n = 0;
	csp_conn_t * conn;
	while ((conn = csp_accept(&shim_sockets[port], 0)) != NULL) {
		csp_packet_t * p;
		while ((p = csp_read(conn, 0)) != NULL) { csp_buffer_free(p); }
		csp_close(conn);
		n++;
	}
	return n;
}

/* --- the C node's clock ---------------------------------------------------
 *
 * `arch/posix/csp_time.c` is left out of the build so these win. libcsp reads the clock for
 * RDP's retransmission and acknowledgement timers and for connection expiry, and with the
 * wall clock those are only reachable by sleeping for whole seconds. Driven from a test they
 * are reachable by assignment, which is what makes "does the C ever free this?" answerable.
 */
static uint32_t shim_now_ms = 100000u;

void shim_clock_set(uint32_t ms) { shim_now_ms = ms; }
void shim_clock_advance(uint32_t ms) { shim_now_ms += ms; }
uint32_t csp_get_ms(void) { return shim_now_ms; }
uint32_t csp_get_ms_isr(void) { return shim_now_ms; }
uint32_t csp_get_s(void) { return shim_now_ms / 1000u; }
uint32_t csp_get_s_isr(void) { return shim_now_ms / 1000u; }

/* Run libcsp's periodic connection maintenance: RDP timers and idle expiry. */
void shim_node_check_timeouts(void) {
	csp_conn_check_timeouts();
	csp_qfifo_wake_up();
	while (csp_route_work() == CSP_ERR_NONE) { }
}

/* Buffers currently free, so a test can assert the node leaks nothing. */
int shim_node_buf_free(void) { return csp_buffer_remaining(); }

/* How many connections the C node holds open, via libcsp's own test hook. */
int shim_node_open_conns(void) {
	size_t n = 0;
	const csp_conn_t *arr = csp_conn_get_array(&n);
	int open = 0;
	for (size_t i = 0; i < n; i++) { if (arr[i].state == CONN_OPEN) { open++; } }
	return open;
}

/*
 * Hold buffers out of the pool, so a rule gated on `csp_buffer_remaining()` -- the
 * promiscuous tap's reserve, `csp_promisc.c:59` -- is reachable by allocation rather than by
 * traffic. Returns how many are held after the call.
 */
#define SHIM_HOLD_MAX 32
static csp_packet_t *shim_held_bufs[SHIM_HOLD_MAX];
static int           shim_held_n;

int shim_buffers_hold(int n) {
	while (n-- > 0 && shim_held_n < SHIM_HOLD_MAX) {
		csp_packet_t *p = csp_buffer_get(0);
		if (p == NULL) { break; }
		shim_held_bufs[shim_held_n++] = p;
	}
	return shim_held_n;
}

void shim_buffers_release(void) {
	while (shim_held_n > 0) { csp_buffer_free(shim_held_bufs[--shim_held_n]); }
}

/* Counters on the capture interface, so a test can see which path a packet took. */
void shim_node_counters(uint32_t *rx, uint32_t *tx, uint32_t *drop, uint32_t *rx_error,
                        uint32_t *tx_error, uint32_t *autherr) {
	*rx = shim_node_iface.rx;         *tx = shim_node_iface.tx;
	*drop = shim_node_iface.drop;     *rx_error = shim_node_iface.rx_error;
	*tx_error = shim_node_iface.tx_error; *autherr = shim_node_iface.autherr;
}
int shim_node_iface_registered(void) { return csp_iflist_get_by_addr(shim_node_iface.addr) != NULL; }

/* --- SFP: what a real C application makes of a stream the port sent -------- */

/*
 * Reassemble a stream on `port` with libcsp's own `csp_sfp_recv_fp`.
 *
 * This is the piece that turns "the port emits plausible fragments" into "a real C node's
 * application receives the bytes". Everything the port's SFP path was checked against
 * before was either its own unit tests or `ctest/suite_sfp.c`, and the latter hands
 * hand-built packets straight to `csp_sfp_recv_fp` on a hand-opened connection -- no
 * header on a wire, no routing, no bound port. So nothing established that frames leaving
 * the port are ones the C would route to an application and reassemble.
 *
 * `timeout` is 0 throughout: every fragment is injected and pumped before this is called,
 * so they are already on the connection's receive queue and `csp_read` returns them
 * without blocking. A blocking read here would hang the harness, which has no router
 * thread to fill the queue behind it.
 *
 * Returns the reassembled length, or a negative libcsp error.
 */
static uint8_t shim_sfp_buf[4096];
static uint32_t shim_sfp_len;

static int shim_sfp_write(const uint8_t *buffer, uint32_t size, uint32_t offset,
                          uint32_t totalsz, void *data) {
	(void)totalsz; (void)data;
	if ((uint64_t)offset + size > sizeof(shim_sfp_buf)) { return CSP_ERR_NOMEM; }
	memcpy(&shim_sfp_buf[offset], buffer, size);
	if (offset + size > shim_sfp_len) { shim_sfp_len = offset + size; }
	return CSP_ERR_NONE;
}

int shim_node_sfp_recv(uint8_t port, uint8_t *out, int maxlen) {
	if (port >= SHIM_PORTS || !shim_bound[port]) { return -100; }
	if (shim_held[port] == NULL) {
		shim_held[port] = csp_accept(&shim_sockets[port], 0);
	}
	if (shim_held[port] == NULL) { return -101; }

	shim_sfp_len = 0;
	const csp_sfp_recv_t rx = { .data = NULL, .write = shim_sfp_write };
	int ret = csp_sfp_recv_fp(shim_held[port], &rx, 0, NULL);
	if (ret != CSP_ERR_NONE) { return ret; }
	if ((int)shim_sfp_len > maxlen) { return -102; }
	memcpy(out, shim_sfp_buf, shim_sfp_len);
	return (int)shim_sfp_len;
}

/* --- the C as a client of the port's services ----------------------------- */

/*
 * A connection the C node opened, held so the reply can be read off it.
 *
 * Every node-level exchange before this had the C *answering*: a frame in, a delivery or a
 * forward or a service reply out. `shim_node_send_on` inverted the data direction but on a
 * connection the peer had opened. Nothing had the C be the one that connects -- so the
 * port's reply path, the one that has to find the asking connection on a real peer, had
 * never been asked a question by a real C client.
 */
static csp_conn_t * shim_client_conn;

/*
 * `csp_connect` + `csp_send` to `dst:dport`. Frames land in the tx capture.
 *
 * `opts` is 0, so `csp_connect` does not block -- only an RDP connect waits on the router
 * task's semaphore, and there is no router task here.
 *
 * Returns 1 on success, 0 if no connection or buffer was available.
 */
int shim_node_client_send(uint16_t dst, uint8_t dport, const uint8_t *body, int len) {
	if (shim_client_conn == NULL) {
		shim_client_conn = csp_connect(2, dst, dport, 0, 0);
	}
	if (shim_client_conn == NULL) { return 0; }

	csp_packet_t *out = csp_buffer_get(0);
	if (out == NULL) { return 0; }
	if (len > (int)sizeof(out->data)) { csp_buffer_free(out); return 0; }
	memcpy(out->data, body, (size_t)len);
	out->length = (uint16_t)len;
	csp_send(shim_client_conn, out);
	return 1;
}

/*
 * Several client connections at once, so the source ports libcsp hands out are observable.
 *
 * `csp_conn_init` sets `conn->sport_outgoing = CSP_PORT_MAX_BIND + 1 + i` **once**, per
 * slot (`csp_conn.c:58`), and `csp_connect` copies it into `idout.sport`. So an outgoing
 * source port is a property of the slot, not of a counter: two connections that are open at
 * the same time can never share one. `csp_conn_find_existing` leans on exactly that --
 * "Outgoing connections are uniquely defined by the source port", so for a client
 * connection it matches on the incoming dport alone.
 *
 * Each call sends one byte so the port that reaches the wire is what gets reported, rather
 * than a field read out of the connection struct.
 */
#define SHIM_CONNS 8
static csp_conn_t * shim_conns[SHIM_CONNS];

/* Open a client connection in `slot` and send one byte. Returns the sport on the wire. */
int shim_conn_open(int slot, uint16_t dst, uint8_t dport) {
	if (slot < 0 || slot >= SHIM_CONNS) { return -1; }
	if (shim_conns[slot] != NULL) { return -2; }
	shim_conns[slot] = csp_connect(2, dst, dport, 0, 0);
	if (shim_conns[slot] == NULL) { return -3; }

	csp_packet_t *out = csp_buffer_get(0);
	if (out == NULL) { return -4; }
	out->data[0] = 0x2a;
	out->length = 1;
	shim_node_clear_tx();
	csp_send(shim_conns[slot], out);
	shim_node_pump();
	if (shim_tx_n < 1) { return -5; }

	/* The sport is read back off the captured frame, not off the connection. */
	csp_id_t id = csp_id_extract(shim_tx_buf[0]);
	return (int)id.sport;
}

void shim_conn_close(int slot) {
	if (slot < 0 || slot >= SHIM_CONNS) { return; }
	if (shim_conns[slot] != NULL) {
		csp_close(shim_conns[slot]);
		shim_conns[slot] = NULL;
	}
}

/*
 * `csp_send_prio` on the same held connection, so what it leaves behind is observable.
 *
 * `csp_io.c:322` is two lines: `conn->idout.pri = prio; csp_send(conn, packet);`. The write
 * is to the *connection*, not the packet, so the next ordinary `csp_send` on it carries the
 * new priority too. A caller raising the priority of one urgent frame silently raises every
 * frame after it. Nothing in either harness had ever called it.
 *
 * `prio` is the CSP priority, 0 (critical) to 3 (low). Returns 1 on success, 0 if no
 * connection or buffer was available.
 */
int shim_node_client_send_prio(uint8_t prio, uint16_t dst, uint8_t dport,
                               const uint8_t *body, int len) {
	if (shim_client_conn == NULL) {
		shim_client_conn = csp_connect(2, dst, dport, 0, 0);
	}
	if (shim_client_conn == NULL) { return 0; }

	csp_packet_t *out = csp_buffer_get(0);
	if (out == NULL) { return 0; }
	if (len > (int)sizeof(out->data)) { csp_buffer_free(out); return 0; }
	memcpy(out->data, body, (size_t)len);
	out->length = (uint16_t)len;
	csp_send_prio(prio, shim_client_conn, out);
	return 1;
}

/*
 * Read one reply off the connection the C opened, as `csp_transaction` would.
 *
 * Returns 1 and the payload if something was waiting, 0 otherwise.
 */
int shim_node_client_read(uint8_t *out, int *out_len) {
	if (shim_client_conn == NULL) { return 0; }
	csp_packet_t *packet = csp_read(shim_client_conn, 0);
	if (packet == NULL) { return 0; }
	int n = (int)packet->length;
	memcpy(out, packet->data, (size_t)n);
	*out_len = n;
	csp_buffer_free(packet);
	return 1;
}

void shim_node_client_close(void) {
	if (shim_client_conn != NULL) { csp_close(shim_client_conn); shim_client_conn = NULL; }
}

/*
 * Build a CMP request exactly as libcsp lays one out.
 *
 * `csp_cmp_ident` and friends fill a `struct csp_cmp_message` and send `sizeof` the
 * relevant member, so the request the port must accept is two bytes of header followed by
 * the *reply-sized* body -- padding libcsp requires and a hand-written request would omit.
 * Taking the size from the C struct is the point: a transcription of the layout into Rust
 * would be the thing under test, not the oracle.
 */
int shim_cmp_build_ident_request(uint8_t *out) {
	struct csp_cmp_ident_msg msg;
	memset(&msg, 0, sizeof(msg));
	msg.type = CSP_CMP_REQUEST;
	msg.code = CSP_CMP_IDENT;
	memcpy(out, &msg, sizeof(msg));
	return (int)sizeof(msg);
}

/*
 * Parse a CMP IDENT reply with the C's own struct, the way a C application does.
 *
 * Returns 1 if the reply is a well-formed IDENT of the right size, 0 otherwise; the three
 * strings are what `csp_cmp_ident` would hand its caller.
 */
int shim_cmp_parse_ident_reply(const uint8_t *buf, int len,
                               char *hostname, char *model, char *revision) {
	if (len != (int)sizeof(struct csp_cmp_ident_msg)) { return 0; }
	struct csp_cmp_ident_msg msg;
	memcpy(&msg, buf, sizeof(msg));
	if (msg.type != CSP_CMP_REPLY || msg.code != CSP_CMP_IDENT) { return 0; }
	memcpy(hostname, msg.hostname, sizeof(msg.hostname));
	memcpy(model, msg.model, sizeof(msg.model));
	memcpy(revision, msg.revision, sizeof(msg.revision));
	return 1;
}

/* --- system hooks: recorded, never performed ------------------------------ */

/*
 * `arch/posix/csp_system.c` is left out of this build (see `build.rs`). Its reboot hook
 * really reboots, and its memfree hook reports the host's free RAM, which is not a number
 * two implementations can be compared on.
 *
 * Recording instead is what lets a test ask the two questions that matter about the reboot
 * service: was it reached, and does the magic word actually gate it.
 */
static int shim_rebooted;
static int shim_shut_down;
static uint32_t shim_memfree = 0x00100000u;
static unsigned int shim_ps_entries;

int  shim_service_rebooted(void)  { return shim_rebooted; }
int  shim_service_shut_down(void) { return shim_shut_down; }
void shim_service_hooks_reset(void) {
	shim_rebooted = 0;
	shim_shut_down = 0;
	shim_memfree = 0x00100000u;
	shim_ps_entries = 0;
}
void shim_set_memfree(uint32_t bytes) { shim_memfree = bytes; }
void shim_set_ps_entries(unsigned int n) { shim_ps_entries = n; }

uint32_t csp_memfree_hook(void) { return shim_memfree; }
unsigned int csp_ps_hook(csp_packet_t *packet) { (void)packet; return shim_ps_entries; }
void csp_reboot_hook(void) { shim_rebooted = 1; }
void csp_shutdown_hook(void) { shim_shut_down = 1; }

/* --- the bridge ----------------------------------------------------------- */

/*
 * `csp_bridge_work` is not the router with a different destination: it is a separate
 * forwarding path that consults no routing table, applies no split horizon, rewrites no
 * address, and deduplicates *unconditionally* -- `csp_bridge.c:45` calls
 * `csp_dedup_is_duplicate` without consulting `csp_conf.dedup`, because a bridge is exactly
 * where a frame can loop.
 *
 * `csp_bridge.c` was in neither this build nor `ctest`'s, so none of that had ever been
 * observed; it was all read.
 */
static csp_iface_t *shim_iface_by_index(int i) {
	return i == 0 ? &shim_node_iface
	     : i == 1 ? &shim_node_iface_b
	              : &shim_node_iface_c;
}

void shim_bridge_set(int a, int b) {
	csp_bridge_set_interfaces(shim_iface_by_index(a), shim_iface_by_index(b));
}

/* Hand a frame to the node as if it had arrived on interface `iface`. */
int shim_node_inject_on(int iface, const uint8_t *frame, uint32_t len) {
	csp_packet_t *packet = csp_buffer_get(0);
	if (packet == NULL) { return -1; }
	csp_id_setup_rx(packet);
	if (len > (uint32_t)(sizeof(packet->data) + 8)) { csp_buffer_free(packet); return -1; }
	memcpy(packet->frame_begin, frame, len);
	packet->frame_length = (uint16_t)len;
	if (csp_id_strip(packet) != 0) { csp_buffer_free(packet); return -2; }
	csp_qfifo_write(packet, shim_iface_by_index(iface), NULL);
	return 0;
}

/*
 * One turn of the bridge crank -- exactly one, which is how the C's own loop calls it.
 *
 * Deliberately no `csp_qfifo_wake_up()` here, unlike `shim_node_pump`. That posts a NULL
 * sentinel so `csp_route_work` returns on an empty queue; `csp_bridge_work` reads the
 * sentinel as its packet, prints "Packet of router queue item is NULL" and consumes the
 * turn. With it in, every result in this harness was shifted one step behind the frame
 * that caused it -- and the first case still looked right, which is what made it
 * convincing. The caller injects exactly one frame per step, so the queue is never empty
 * and `csp_qfifo_read` returns without blocking.
 */
void shim_bridge_work(void) {
	csp_bridge_work();
}

/* --- CAN: fragmentation and reassembly, by the real csp_if_can.c ----------- */

/*
 * Until now every CFP comparison expanded the header's macros in this file and compared bit
 * layouts. That is the identifier; it is not the interface. `csp_can_rx` reassembles into a
 * pbuf taken from a fixed pool, keyed by sender, and gives up on a pbuf that has gone quiet
 * -- and `csp_can_tx` decides how a packet is cut into 8-byte frames. None of it had run.
 */
static csp_iface_t                shim_can_iface;
static csp_can_interface_data_t   shim_can_data;
static int                        shim_can_ready;

#define SHIM_CAN_MAX 64
static uint32_t shim_can_id[SHIM_CAN_MAX];
static uint8_t  shim_can_dat[SHIM_CAN_MAX][8];
static uint8_t  shim_can_dlc[SHIM_CAN_MAX];
static int      shim_can_n;

/* Capture driver: record the CAN frame instead of putting it on a bus. */
static int shim_can_tx_fn(void *driver_data, uint32_t id, const uint8_t *data, uint8_t dlc,
                          const csp_packet_t *packet) {
	(void)driver_data;
	/* This fork's `csp_can_driver_tx_t` passes the originating packet as a fifth argument;
	   upstream's does not. Matching the typedef exactly matters -- an incompatible function
	   pointer is undefined behaviour, not a warning to wave through. */
	(void)packet;
	if (shim_can_n < SHIM_CAN_MAX) {
		shim_can_id[shim_can_n] = id;
		shim_can_dlc[shim_can_n] = dlc;
		memcpy(shim_can_dat[shim_can_n], data, dlc > 8 ? 8 : dlc);
		shim_can_n++;
	}
	return CSP_ERR_NONE;
}

int shim_can_init(uint16_t address, uint16_t netmask) {
	if (shim_can_ready) { return 0; }
	shim_ensure_init();
	memset(&shim_can_data, 0, sizeof(shim_can_data));
	shim_can_data.tx_func = shim_can_tx_fn;
	memset(&shim_can_iface, 0, sizeof(shim_can_iface));
	shim_can_iface.name = "CAN";
	shim_can_iface.addr = address;
	shim_can_iface.netmask = netmask;
	shim_can_iface.interface_data = &shim_can_data;
	shim_can_iface.driver_data = NULL;
	if (csp_can_add_interface(&shim_can_iface) != CSP_ERR_NONE) { return -1; }
	shim_can_ready = 1;
	return 0;
}

void shim_can_clear(void) { shim_can_n = 0; }
int  shim_can_count(void) { return shim_can_n; }

int shim_can_get(int i, uint32_t *id, uint8_t *data) {
	if (i < 0 || i >= shim_can_n) { return -1; }
	*id = shim_can_id[i];
	memcpy(data, shim_can_dat[i], shim_can_dlc[i]);
	return shim_can_dlc[i];
}

/* Fragment a CSP packet the way the C does, into the capture above. */
int shim_can_send(uint16_t dst, uint8_t dport, uint8_t sport, const uint8_t *body, int len) {
	csp_packet_t *packet = csp_buffer_get(0);
	if (packet == NULL) { return -1; }
	if (len > (int)sizeof(packet->data)) { csp_buffer_free(packet); return -1; }
	memset(&packet->id, 0, sizeof(packet->id));
	packet->id.pri = 2;
	packet->id.src = shim_can_iface.addr;
	packet->id.dst = dst;
	packet->id.dport = dport;
	packet->id.sport = sport;
	memcpy(packet->data, body, (size_t)len);
	packet->length = (uint16_t)len;
	csp_id_prepend(packet);
	/* Through `nexthop`, which is what the router calls. `csp_can_tx` is declared in
	   `csp_if_can.h` and defined nowhere in this fork: `csp_can_add_interface` installs
	   the static `csp_can1_tx` or `csp_can2_tx` depending on the wire version, so calling
	   the documented entry point does not link. */
	return shim_can_iface.nexthop(&shim_can_iface, CSP_NO_VIA_ADDRESS, packet, 1);
}

/*
 * Feed one CAN frame to `csp_can_rx` and return what the C reported.
 *
 * Whether a packet came out of it is not asked here: the caller pumps the router and reads
 * the bound port, so the answer is "what the application received" rather than anything
 * about a queue.
 *
 * `timestamp_rx` is 0 throughout -- the pbuf's last-used stamp comes from `csp_get_ms()`,
 * which this shim controls, so the reassembly timeout is reachable by assignment rather
 * than by waiting.
 */
int shim_can_rx(uint32_t id, const uint8_t *data, uint8_t dlc) {
	return csp_can_rx(&shim_can_iface, id, data, dlc, 0, NULL);
}

/* --- the C's service *client*: what csp_reboot actually puts on the wire ---- */

/*
 * `csp_services.c` holds the twelve client-side entry points an application calls --
 * `csp_ping`, `csp_reboot`, `csp_memfree` and the rest. Nothing else in libcsp calls them
 * and, until now, neither did this harness: they were the largest cluster of built-but-never-
 * invoked C in the tree. So the port's `csp::client` was compared against the C's *server*
 * and against its own round trip, never against the C's client.
 *
 * Most of them block in `csp_transaction_w_opts` waiting for a reply. `csp_reboot` and
 * `csp_shutdown` do not: `csp_transaction_persistent` returns straight after `csp_send` when
 * `inlen == 0` (`csp_io.c`). They are also the two that matter most -- a magic word the port
 * got wrong would mean "reboot the satellite" silently does nothing, and a round trip inside
 * the port would pass because both halves share the constant.
 *
 * Returns the number of frames captured.
 */
int shim_client_reboot(uint16_t dst, int shutdown_instead) {
	shim_node_clear_tx();
	if (shutdown_instead) {
		csp_shutdown(dst);
	} else {
		csp_reboot(dst);
	}
	shim_node_pump();
	return shim_tx_n;
}

/*
 * The rest of `csp_services.c`'s client, with a zero timeout.
 *
 * The previous round of this stopped at `csp_reboot`/`csp_shutdown`, on the grounds that the
 * other ten "block in csp_transaction_w_opts". They do not have to: the timeout is a
 * parameter, `csp_read` passes it to `csp_queue_dequeue`, and `pthread_queue_dequeue` with 0
 * builds a deadline of *now* and returns immediately. So the request still goes out and the
 * reply-wait costs nothing -- which is all that is needed to compare what the C's client puts
 * on the wire against what the port's builds.
 *
 * `kind`: 0 ping, 1 memfree, 2 buf_free, 3 uptime, 4 ps. Returns frames captured.
 */
int shim_client_request(int kind, uint16_t dst, unsigned int size, uint8_t opts) {
	shim_node_clear_tx();
	switch (kind) {
		case 0: (void)csp_ping(dst, 0, size, opts); break;
		case 1: csp_memfree(dst, 0); break;
		case 2: csp_buf_free(dst, 0); break;
		case 3: csp_uptime(dst, 0); break;
		case 4: csp_ps(dst, 0); break;
		case 5: csp_ping_noreply(dst); break;
		case 6: {
			/* `csp_cmp` writes its reply back over the request buffer, so the caller hands
			   it one sized for the reply. IDENT is the largest of the fixed-size codes. */
			struct csp_cmp_ident_msg msg;
			memset(&msg, 0, sizeof(msg));
			(void)csp_cmp(dst, 0, CSP_CMP_IDENT, (int)sizeof(msg), &msg);
			break;
		}
		default: return -1;
	}
	shim_node_pump();
	return shim_tx_n;
}

/*
 * Drive `csp_transaction_persistent` with a reply already waiting, so its reply-length rule
 * is observable.
 *
 * The `csp_get_*` clients all funnel through this and none of them was reachable before: with
 * no reply on the queue the transaction times out and never reaches the length check. Here
 * the connection is opened first, a reply addressed to its own source port is injected and
 * routed onto it, and only then does the transaction run -- so the `csp_read` inside it
 * returns immediately.
 *
 * Returns what the transaction returned: the reply length, or 0 for "refused".
 */
/*
 * The same, with the connection opened under `opts` and the reply carrying `reply_flags`.
 *
 * `csp_route.c:288` checks a reply against `conn->opts` -- the options `csp_connect` stored
 * on *this* connection (`csp_conn.c:320`) -- not against anything node-wide. So a connection
 * opened with `CSP_O_CRC32` refuses an unchecksummed reply while one opened with `0` takes it,
 * and only a client that asked for a protection can show the difference. A `reply_flags` of
 * `CSP_FCRC32` appends the checksum the way `csp_sendto_reply(.., CSP_O_SAME)` would.
 */
int shim_client_transaction_opts(uint16_t dst, uint8_t dport, uint32_t opts, uint8_t reply_flags,
                                 const uint8_t *reply, int reply_len,
                                 int inlen, uint8_t *out, int *out_len) {
	csp_conn_t *conn = csp_connect(CSP_PRIO_NORM, dst, dport, 0, opts);
	if (conn == NULL) { return -1; }

	/* A reply comes back with the ports swapped, from the node we addressed. */
	csp_packet_t *p = csp_buffer_get(0);
	if (p == NULL) { csp_close(conn); return -1; }
	memset(&p->id, 0, sizeof(p->id));
	p->id.pri = CSP_PRIO_NORM;
	p->id.src = dst;
	p->id.dst = shim_node_iface.addr;
	/* The connection's *incoming* destination port is the ephemeral one `csp_connect`
	   allocated (`conn->idin.dport = conn->sport_outgoing`). `csp_conn_sport` returns
	   `idin.sport`, which is the remote port we dialled -- addressing the reply there routes
	   it to a port nothing is listening on, and the transaction times out looking like a
	   length refusal. */
	p->id.dport = conn->idin.dport;
	p->id.sport = dport;
	if (reply_len > (int)sizeof(p->data)) { csp_buffer_free(p); csp_close(conn); return -1; }
	memcpy(p->data, reply, (size_t)reply_len);
	p->length = (uint16_t)reply_len;
	p->id.flags = reply_flags;
	if (reply_flags & CSP_FCRC32) { csp_crc32_append(p); }
	csp_id_prepend(p);

	uint8_t frame[SHIM_FRAME_MAX];
	int n = p->frame_length > SHIM_FRAME_MAX ? SHIM_FRAME_MAX : p->frame_length;
	memcpy(frame, p->frame_begin, (size_t)n);
	csp_buffer_free(p);

	shim_node_clear_tx();
	shim_node_inject(frame, (uint32_t)n);
	shim_node_pump();

	uint8_t buf[256];
	memset(buf, 0, sizeof(buf));
	int ret = csp_transaction_persistent(conn, 0, NULL, 0, buf, inlen);
	if (ret > 0) {
		int m = ret > 256 ? 256 : ret;
		memcpy(out, buf, (size_t)m);
		*out_len = m;
	} else {
		*out_len = 0;
	}
	csp_close(conn);
	return ret;
}

int shim_client_transaction(uint16_t dst, uint8_t dport, const uint8_t *reply, int reply_len,
                            int inlen, uint8_t *out, int *out_len) {
	return shim_client_transaction_opts(dst, dport, 0, 0, reply, reply_len, inlen, out, out_len);
}

/* --- address aliases: a second address the node answers to ------------------ */

/*
 * `csp_route.c:236` folds `csp_addr_is_alias(packet->id.dst)` into the is-it-for-me
 * decision, alongside "any interface's address" and "the ingress interface's broadcast".
 * The port folds aliases into `IfList::find_by_addr` instead, and nothing had ever compared
 * the two: no harness named an alias, no corpus record, no differential test. It was a
 * reading of `csp_iflist.c` deciding whether a command addressed to a node's second address
 * is delivered or forwarded back out.
 *
 * The list is global in the C and the entries must outlive the call, so they are static here.
 */
#define SHIM_ALIAS_MAX 4
static csp_alias_t shim_aliases[SHIM_ALIAS_MAX];
static int shim_alias_n;

int shim_node_add_alias(uint16_t addr, int iface) {
	if (shim_alias_n >= SHIM_ALIAS_MAX) { return -1; }
	csp_alias_t *a = &shim_aliases[shim_alias_n];
	memset(a, 0, sizeof(*a));
	a->addr = addr;
	a->iface = shim_iface_by_index(iface);
	if (csp_alias_add(a) != 0) { return -2; }
	shim_alias_n++;
	return 0;
}

int shim_node_is_alias(uint16_t addr) { return csp_addr_is_alias(addr); }

/* --- SFP the other way: fragments a real csp_sfp_send produced --------------- */

/*
 * Every SFP comparison so far runs one of two ways: the port fragments and
 * `csp_sfp_recv_fp` reassembles (`node_sfp.rs`), or hand-built `make_packet` fragments go
 * into the port's reassembler (the `sfp::` corpus records). `csp_sfp_send` itself had never
 * executed -- it appears in this tree exactly once, in a comment. So the decision a real
 * libcsp sender makes about *how to cut a message up* had never produced a byte, and the
 * port's reassembler had never seen its output.
 *
 * That is the same asymmetry `node_can.rs` covers in both directions.
 */
static const uint8_t *shim_sfp_src;
static uint32_t shim_sfp_src_len;

static int shim_sfp_read(uint8_t *buffer, uint32_t size, uint32_t offset, void *data) {
	(void)data;
	if ((uint64_t)offset + size > shim_sfp_src_len) { return CSP_ERR_INVAL; }
	memcpy(buffer, shim_sfp_src + offset, size);
	return CSP_ERR_NONE;
}

/*
 * Fragment `body` with libcsp's own `csp_sfp_send` and leave the frames in the tx capture.
 *
 * Returns the number of frames, or a negative libcsp error. `mtu` is the payload budget per
 * fragment; `csp_sfp_send` refuses one above `csp_sfp_conn_max_mtu`.
 */
int shim_sfp_send(uint16_t dst, uint8_t dport, const uint8_t *body, int len, uint32_t mtu) {
	csp_conn_t *conn = csp_connect(CSP_PRIO_NORM, dst, dport, 0, 0);
	if (conn == NULL) { return -1; }

	shim_sfp_src = body;
	shim_sfp_src_len = (uint32_t)len;
	const csp_sfp_read_t reader = { .data = NULL, .read = shim_sfp_read };

	shim_node_clear_tx();
	int ret = csp_sfp_send(conn, &reader, (uint32_t)len, mtu, 0);
	shim_node_pump();
	csp_close(conn);
	if (ret != CSP_ERR_NONE) { return -100 + ret; }
	return shim_tx_n;
}

/*
 * The same, but on the connection this node is already holding for `port` — which after a
 * handshake is a real RDP connection a peer opened to it.
 *
 * `csp_sfp_send` appends its trailer and hands each fragment to `csp_send`, which on an RDP
 * connection appends a *second* trailer at `data[length]`. Only the port's sending order had
 * ever been checked, by a C node stripping it (`node_sfp_rdp.rs`). Nothing had made the port
 * strip two trailers off a fragment a real libcsp sender produced, and getting that order
 * wrong is silent: the reassembler reads the RDP header as part of the SFP offset and the
 * stream never completes.
 *
 * Returns the frame count, a negative libcsp error, or 0 if no connection was held.
 */
int shim_node_sfp_send_on(uint8_t port, const uint8_t *body, int len, uint32_t mtu) {
	if (port >= SHIM_PORTS || !shim_bound[port]) { return 0; }
	if (shim_held[port] == NULL) {
		shim_held[port] = csp_accept(&shim_sockets[port], 0);
	}
	if (shim_held[port] == NULL) { return 0; }
	/* Drain whatever the peer sent, so the connection is not holding buffers. */
	csp_packet_t *in;
	while ((in = csp_read(shim_held[port], 0)) != NULL) { csp_buffer_free(in); }

	shim_sfp_src = body;
	shim_sfp_src_len = (uint32_t)len;
	const csp_sfp_read_t reader = { .data = NULL, .read = shim_sfp_read };

	shim_node_clear_tx();
	int ret = csp_sfp_send(shim_held[port], &reader, (uint32_t)len, mtu, 0);
	shim_node_pump();
	if (ret != CSP_ERR_NONE) { return -100 + ret; }
	return shim_tx_n;
}

/* --- the C as the RDP *initiator* ------------------------------------------- */

/*
 * Every RDP comparison in this harness has the port opening the connection and the C
 * answering from its router. That leaves the port's *responder* path -- receive a SYN from a
 * real libcsp, answer SYN|ACK, take the third leg -- never driven by a real initiator. On a
 * satellite that is the direction that flies: ground opens the connection, the flight node
 * answers.
 *
 * `csp_rdp_connect` sends the SYN and then blocks on `tx_wait` until the router task
 * releases it (`csp_rdp.c:836`). This harness has no router task, so `csp_connect` runs on a
 * thread of its own and the caller turns the crank from the main thread -- which is exactly
 * the division of labour libcsp is written for.
 *
 * Only the SYN is emitted from the connect thread, and the main thread does not touch the tx
 * capture until it has appeared, so the two never write it at once.
 */
static pthread_t    shim_rdp_thread;
static csp_conn_t * shim_rdp_conn;
static volatile int shim_rdp_result;
static int          shim_rdp_running;
static uint16_t     shim_rdp_dst;
static uint8_t      shim_rdp_dport;

static void * shim_rdp_connect_thread(void * arg) {
	(void)arg;
	csp_conn_t * c = csp_connect(CSP_PRIO_NORM, shim_rdp_dst, shim_rdp_dport, 0, CSP_SO_RDPREQ);
	shim_rdp_conn = c;
	shim_rdp_result = (c != NULL) ? 1 : 0;
	return NULL;
}

/*
 * Begin a real `csp_connect(..., CSP_SO_RDPREQ)` and return how many frames it put on the
 * wire -- one SYN, which the caller feeds to the peer. Negative on failure to start.
 */
int shim_rdp_connect_start(uint16_t dst, uint8_t dport) {
	if (shim_rdp_running) { return -2; }
	shim_rdp_dst = dst;
	shim_rdp_dport = dport;
	shim_rdp_conn = NULL;
	shim_rdp_result = -1;
	shim_node_clear_tx();
	if (pthread_create(&shim_rdp_thread, NULL, shim_rdp_connect_thread, NULL) != 0) { return -1; }
	shim_rdp_running = 1;
	/* The SYN is on the wire before `csp_rdp_connect` blocks; bounded so a libcsp that
	   never sends one fails the test rather than hanging it. */
	for (int i = 0; i < 3000 && shim_tx_n == 0 && shim_rdp_result < 0; i++) { usleep(1000); }
	return shim_tx_n;
}

/*
 * Wait for `csp_connect` to return and report whether libcsp opened the connection.
 *
 * 1 = open, 0 = libcsp gave up. This is the assertion the whole exercise is for: a real
 * initiator's own verdict on the handshake the port answered with.
 */
int shim_rdp_connect_join(void) {
	if (!shim_rdp_running) { return -1; }
	pthread_join(shim_rdp_thread, NULL);
	shim_rdp_running = 0;
	return shim_rdp_result;
}

/* Send one datagram on that connection, and return the frames it produced. */
int shim_rdp_initiator_send(const uint8_t * body, int len) {
	if (shim_rdp_conn == NULL) { return 0; }
	csp_packet_t * out = csp_buffer_get(0);
	if (out == NULL) { return 0; }
	if (len > (int)sizeof(out->data)) { csp_buffer_free(out); return 0; }
	memcpy(out->data, body, (size_t)len);
	out->length = (uint16_t)len;
	shim_node_clear_tx();
	csp_send(shim_rdp_conn, out);
	shim_node_pump();
	return shim_tx_n;
}

/* Close it, and pump so the teardown reaches the wire. */
void shim_rdp_initiator_close(void) {
	if (shim_rdp_conn != NULL) {
		csp_close(shim_rdp_conn);
		shim_rdp_conn = NULL;
	}
	shim_node_pump();
}

/* --- libcsp's own CMP client, unmodified ------------------------------------ */

/*
 * `node_cmp_server.rs` builds a CMP request by filling libcsp's struct and sends it with a
 * hand-rolled client. That leaves libcsp's *real* entry point -- `csp_cmp_if_stats` and its
 * siblings, which all funnel through `csp_cmp` -> `csp_transaction_w_opts` -- never called
 * by either harness. Three things live only on that path:
 *
 *   - `csp_cmp` sends with **CSP_O_CRC32** (`csp_services.c:218`), so the request carries a
 *     checksum and the reply is expected to carry one back. A reply without it is dropped by
 *     the client's own router and the operator sees a timeout, not an error.
 *   - `csp_transaction_persistent` refuses a reply whose length is not exactly the struct's
 *     (`csp_io.c:352`).
 *   - `csp_cmp` turns "no reply" into `CSP_ERR_TIMEDOUT` (`csp_services.c:219`).
 *
 * `csp_read` blocks, so the call runs on its own thread and the caller drives the exchange,
 * exactly as for `shim_rdp_connect_start`.
 */
static pthread_t              shim_cmp_thread;
static volatile int           shim_cmp_result;
static int                    shim_cmp_running;
static uint16_t               shim_cmp_node;
static struct csp_cmp_message shim_cmp_msg;

static void * shim_cmp_thread_fn(void * arg) {
	(void)arg;
	shim_cmp_result = csp_cmp_if_stats(shim_cmp_node, 5000, &shim_cmp_msg);
	return NULL;
}

/*
 * Begin a real `csp_cmp_if_stats` against `node`, asking about `ifname`.
 *
 * Returns how many frames the client put on the wire (one request), or negative on failure
 * to start.
 */
int shim_cmp_if_stats_start(uint16_t node, const char * ifname) {
	if (shim_cmp_running) { return -2; }
	memset(&shim_cmp_msg, 0, sizeof(shim_cmp_msg));
	strncpy(shim_cmp_msg.if_stats.interface, ifname,
			sizeof(shim_cmp_msg.if_stats.interface) - 1);
	shim_cmp_node = node;
	shim_cmp_result = -1000;
	shim_node_clear_tx();
	if (pthread_create(&shim_cmp_thread, NULL, shim_cmp_thread_fn, NULL) != 0) { return -1; }
	shim_cmp_running = 1;
	/* The request is on the wire before `csp_read` blocks. Bounded, so a client that
	   sends nothing fails the test rather than hanging it. */
	for (int i = 0; i < 3000 && shim_tx_n == 0 && shim_cmp_result == -1000; i++) { usleep(1000); }
	return shim_tx_n;
}

/*
 * Wait for `csp_cmp_if_stats` to return and copy out the message it filled.
 *
 * Returns libcsp's own status: `CSP_ERR_NONE` (0) only if a reply arrived, survived the
 * client's router, and was exactly `sizeof(struct csp_cmp_if_stats_msg)` bytes.
 */
int shim_cmp_if_stats_join(uint8_t * out, int maxlen) {
	if (!shim_cmp_running) { return -1000; }
	pthread_join(shim_cmp_thread, NULL);
	shim_cmp_running = 0;
	int n = (int)sizeof(struct csp_cmp_if_stats_msg);
	if (out != NULL && maxlen >= n) { memcpy(out, &shim_cmp_msg, (size_t)n); }
	return shim_cmp_result;
}

/* --- libcsp's own CMP clock client ------------------------------------------ */

/*
 * `csp_cmp_clock` is the highest-consequence code the port serves and no real client had
 * ever run it. Setting a satellite's clock wrong is not a lost packet: every timestamp in
 * the telemetry, every scheduled window and every propagated ephemeris is wrong afterwards,
 * and nothing on the ground says so.
 *
 * `csp_cmp_clock_handler` sets only when `tv_sec` is non-zero, reads back regardless, and
 * then returns the *set* result -- so a refused set builds a reply and discards it
 * (`csp_service_handler` drops a non-zero return). A peer that asked to set the clock and
 * got silence learns the set failed; one that got a timestamp back would read it as
 * confirmation. That difference is only visible to a client that waits.
 */
static pthread_t              shim_clk_thread;
static int                    shim_clk_running;
static uint16_t               shim_clk_node;
static volatile int           shim_clk_status;
static struct csp_cmp_message shim_clk_msg;

static void * shim_clk_thread_fn(void * arg) {
	(void)arg;
	shim_clk_status = csp_cmp_clock(shim_clk_node, 5000, &shim_clk_msg);
	return NULL;
}

/*
 * Begin a real `csp_cmp_clock` against `node`, proposing `tv_sec`/`tv_nsec`.
 *
 * A `tv_sec` of zero is how libcsp asks to *read* the clock without setting it.
 * Returns how many frames the request put on the wire.
 */
int shim_cmp_clock_start(uint16_t node, uint32_t tv_sec, uint32_t tv_nsec) {
	if (shim_clk_running) { return -2; }
	memset(&shim_clk_msg, 0, sizeof(shim_clk_msg));
	shim_clk_msg.clock.tv_sec = htobe32(tv_sec);
	shim_clk_msg.clock.tv_nsec = htobe32(tv_nsec);
	shim_clk_node = node;
	shim_clk_status = -1000;
	shim_node_clear_tx();
	if (pthread_create(&shim_clk_thread, NULL, shim_clk_thread_fn, NULL) != 0) { return -1; }
	shim_clk_running = 1;
	for (int i = 0; i < 3000 && shim_tx_n == 0 && shim_clk_status == -1000; i++) { usleep(1000); }
	return shim_tx_n;
}

/* Wait for it, and hand back the timestamp libcsp decoded. */
int shim_cmp_clock_join(uint32_t * tv_sec, uint32_t * tv_nsec) {
	if (!shim_clk_running) { return -1000; }
	pthread_join(shim_clk_thread, NULL);
	shim_clk_running = 0;
	if (tv_sec != NULL) { *tv_sec = be32toh(shim_clk_msg.clock.tv_sec); }
	if (tv_nsec != NULL) { *tv_nsec = be32toh(shim_clk_msg.clock.tv_nsec); }
	return shim_clk_status;
}

/* --- libcsp's own service clients, with a real timeout ---------------------- */

/*
 * `shim_client_request` above calls each of `csp_services.c`'s clients with a **zero**
 * timeout, so the request reaches the wire and the client gives up immediately. That
 * compares the request bytes and nothing else: no libcsp service client had ever received
 * and interpreted a reply the port produced.
 *
 * That is the direction an operator is in. `csp_ping` returns the round trip or -1 after
 * checking the echo byte by byte; `csp_get_memfree`, `csp_get_buf_free` and `csp_get_uptime`
 * demand a reply of exactly four bytes, run it through `be32toh`, and hand back
 * `CSP_ERR_TIMEDOUT` for anything else -- so a reply of the wrong length, the wrong byte
 * order or without the checksum they all request reads on the ground as a node that did not
 * answer.
 *
 * `csp_read` blocks, so the client runs on its own thread and the caller drives the
 * exchange, as for `shim_rdp_connect_start`.
 */
enum { SHIM_SVC_PING = 0, SHIM_SVC_MEMFREE, SHIM_SVC_BUFFREE, SHIM_SVC_UPTIME };

static pthread_t    shim_svc_thread;
static int          shim_svc_running;
static int          shim_svc_kind;
static uint16_t     shim_svc_dst;
static unsigned int shim_svc_size;
static uint8_t      shim_svc_opts;
static volatile int shim_svc_status;
static uint32_t     shim_svc_value;

static void * shim_svc_thread_fn(void * arg) {
	(void)arg;
	uint32_t v = 0;
	int st;
	switch (shim_svc_kind) {
		case SHIM_SVC_PING:    st = csp_ping(shim_svc_dst, 5000, shim_svc_size, shim_svc_opts); break;
		case SHIM_SVC_MEMFREE: st = csp_get_memfree(shim_svc_dst, 5000, &v); break;
		case SHIM_SVC_BUFFREE: st = csp_get_buf_free(shim_svc_dst, 5000, &v); break;
		case SHIM_SVC_UPTIME:  st = csp_get_uptime(shim_svc_dst, 5000, &v); break;
		default: st = -99; break;
	}
	shim_svc_value = v;
	shim_svc_status = st;
	return NULL;
}

/*
 * Begin one of libcsp's service clients against `dst` and return how many frames its
 * request put on the wire. `size` and `opts` apply to `csp_ping` only.
 */
int shim_service_start(int kind, uint16_t dst, unsigned int size, uint8_t opts) {
	if (shim_svc_running) { return -2; }
	shim_svc_kind = kind;
	shim_svc_dst = dst;
	shim_svc_size = size;
	shim_svc_opts = opts;
	shim_svc_value = 0;
	shim_svc_status = -1000;
	shim_node_clear_tx();
	if (pthread_create(&shim_svc_thread, NULL, shim_svc_thread_fn, NULL) != 0) { return -1; }
	shim_svc_running = 1;
	/* The request is on the wire before `csp_read` blocks; bounded so a client that sends
	   nothing fails the test rather than hanging it. */
	for (int i = 0; i < 3000 && shim_tx_n == 0 && shim_svc_status == -1000; i++) { usleep(1000); }
	return shim_tx_n;
}

/*
 * Wait for the client to return. The status is libcsp's own -- elapsed milliseconds or -1
 * for `csp_ping`, `CSP_ERR_NONE`/`CSP_ERR_TIMEDOUT` for the others -- and `*value` carries
 * the number the `csp_get_*` family decoded.
 */
int shim_service_join(uint32_t * value) {
	if (!shim_svc_running) { return -1000; }
	pthread_join(shim_svc_thread, NULL);
	shim_svc_running = 0;
	if (value != NULL) { *value = shim_svc_value; }
	return shim_svc_status;
}

/* --- I2C: the bus address csp_i2c_tx picks --------------------------------- */

/*
 * `csp_if_i2c.c` was in neither build. Its loopback and its `csp_id_prepend` are what every
 * interface does and the port's generic `Interface` already matched; two things are specific
 * to I2C and the port had neither: the physical address is masked to seven bits, and a frame
 * under four bytes is refused before `csp_id_strip` runs.
 *
 * The driver callback records `packet->cfpid`, which is where `csp_i2c_tx` puts the address
 * it chose. Returns that address, or -1 if the packet never reached the driver (loopback).
 */
static int shim_i2c_addr = -1;

static int shim_i2c_tx_fn(void *driver_data, csp_packet_t *frame) {
	(void)driver_data;
	shim_i2c_addr = (int)frame->cfpid;
	csp_buffer_free(frame);
	return CSP_ERR_NONE;
}

static csp_iface_t              shim_i2c_iface;
static csp_i2c_interface_data_t shim_i2c_data;
static int                      shim_i2c_ready;

int shim_i2c_init(uint16_t address) {
	if (shim_i2c_ready) { return 0; }
	shim_ensure_init();
	memset(&shim_i2c_data, 0, sizeof(shim_i2c_data));
	shim_i2c_data.tx_func = shim_i2c_tx_fn;
	memset(&shim_i2c_iface, 0, sizeof(shim_i2c_iface));
	shim_i2c_iface.name = "I2C";
	shim_i2c_iface.addr = address;
	shim_i2c_iface.netmask = 14;
	shim_i2c_iface.interface_data = &shim_i2c_data;
	if (csp_i2c_add_interface(&shim_i2c_iface) != CSP_ERR_NONE) { return -1; }
	shim_i2c_ready = 1;
	return 0;
}

/* Send one packet through `csp_i2c_tx`; returns the bus address it used, or -1. */
int shim_i2c_tx(uint16_t dst, uint16_t via) {
	csp_packet_t *p = csp_buffer_get(0);
	if (p == NULL) { return -2; }
	memset(&p->id, 0, sizeof(p->id));
	p->id.pri = 2;
	p->id.src = shim_i2c_iface.addr;
	p->id.dst = dst;
	p->id.dport = 10;
	p->id.sport = 40;
	memcpy(p->data, "i2c", 3);
	p->length = 3;

	shim_i2c_addr = -1;
	if (shim_i2c_iface.nexthop(&shim_i2c_iface, via, p, 1) != CSP_ERR_NONE) { return -3; }
	return shim_i2c_addr;
}

/* Hand `len` bytes to `csp_i2c_rx`; returns 1 if it routed the frame, 0 if it refused. */
int shim_i2c_rx(const uint8_t *frame, uint32_t len) {
	csp_packet_t *p = csp_buffer_get(0);
	if (p == NULL) { return -1; }
	csp_id_setup_rx(p);
	if (len > sizeof(p->data)) { csp_buffer_free(p); return -1; }
	memcpy(p->frame_begin, frame, len);
	p->frame_length = (uint16_t)len;

	uint32_t before = shim_i2c_iface.frame;
	csp_i2c_rx(&shim_i2c_iface, p, NULL);
	if (shim_i2c_iface.frame > before) { return 0; }
	/* It was routed: drain so the buffer comes back. */
	csp_qfifo_wake_up();
	while (csp_route_work() == CSP_ERR_NONE) { }
	return 1;
}

/* --- libcsp's own ROUTE_SET_V2, PEEK and POKE clients ------------------------ */

/*
 * Measured after the CLOCK work: of the nine CMP codes, IDENT had a hand-rolled client,
 * IF_STATS and CLOCK the real one, PEEK_V2 a real `csp_transaction`. ROUTE_SET_V2 and the
 * 32-bit PEEK/POKE had nothing on the client side at all -- and ROUTE_SET is the code by
 * which ground rewrites a satellite's routing table. One runner, three fillers: each filler
 * lays the struct out exactly as a C application does (host fields through htobe*), and
 * the thread calls libcsp's own inline entry point for that code, nothing else.
 */
static pthread_t              shim_rsp_thread;
static int                    shim_rsp_running;
static int                    shim_rsp_code;
static uint16_t               shim_rsp_node;
static volatile int           shim_rsp_status;
static struct csp_cmp_message shim_rsp_msg;

static void * shim_rsp_thread_fn(void * arg) {
	(void)arg;
	switch (shim_rsp_code) {
		case CSP_CMP_ROUTE_SET_V2: shim_rsp_status = csp_cmp_route_set_v2(shim_rsp_node, 5000, &shim_rsp_msg); break;
		case CSP_CMP_PEEK:         shim_rsp_status = csp_cmp_peek(shim_rsp_node, 5000, &shim_rsp_msg); break;
		case CSP_CMP_POKE:         shim_rsp_status = csp_cmp_poke(shim_rsp_node, 5000, &shim_rsp_msg); break;
		default:                   shim_rsp_status = -999; break;
	}
	return NULL;
}

static int shim_rsp_launch(int code, uint16_t node) {
	if (shim_rsp_running) { return -2; }
	shim_rsp_code = code;
	shim_rsp_node = node;
	shim_rsp_status = -1000;
	shim_node_clear_tx();
	if (pthread_create(&shim_rsp_thread, NULL, shim_rsp_thread_fn, NULL) != 0) { return -1; }
	shim_rsp_running = 1;
	for (int i = 0; i < 3000 && shim_tx_n == 0 && shim_rsp_status == -1000; i++) { usleep(1000); }
	return shim_tx_n;
}

/* Begin a real `csp_cmp_route_set_v2`. Returns how many frames the request put on the wire. */
int shim_cmp_route_set_v2_start(uint16_t node, uint16_t dest, uint16_t netmask, uint16_t via,
								const char * ifname) {
	if (shim_rsp_running) { return -2; }
	memset(&shim_rsp_msg, 0, sizeof(shim_rsp_msg));
	shim_rsp_msg.route_set_v2.dest_node = htobe16(dest);
	shim_rsp_msg.route_set_v2.next_hop_via = htobe16(via);
	shim_rsp_msg.route_set_v2.netmask = htobe16(netmask);
	strncpy(shim_rsp_msg.route_set_v2.interface, ifname,
			sizeof(shim_rsp_msg.route_set_v2.interface) - 1);
	return shim_rsp_launch(CSP_CMP_ROUTE_SET_V2, node);
}

/* Begin a real `csp_cmp_peek` for `len` bytes at the 32-bit `addr`. */
int shim_cmp_peek_start(uint16_t node, uint32_t addr, uint8_t len) {
	if (shim_rsp_running) { return -2; }
	memset(&shim_rsp_msg, 0, sizeof(shim_rsp_msg));
	shim_rsp_msg.peek.addr = htobe32(addr);
	shim_rsp_msg.peek.len = len;
	return shim_rsp_launch(CSP_CMP_PEEK, node);
}

/* Begin a real `csp_cmp_poke` writing `data` at the 32-bit `addr`. */
int shim_cmp_poke_start(uint16_t node, uint32_t addr, const uint8_t * data, uint8_t len) {
	if (shim_rsp_running) { return -2; }
	if (len > CSP_CMP_POKE_MAX_LEN) { return -3; }
	memset(&shim_rsp_msg, 0, sizeof(shim_rsp_msg));
	shim_rsp_msg.poke.addr = htobe32(addr);
	shim_rsp_msg.poke.len = len;
	memcpy(shim_rsp_msg.poke.data, data, len);
	return shim_rsp_launch(CSP_CMP_POKE, node);
}

/*
 * Wait for the client and copy the message it holds -- the reply, written over the
 * request by `csp_cmp` -- out as raw packed bytes. Returns libcsp's own status.
 */
int shim_cmp_raw_join(uint8_t * out, int maxlen) {
	if (!shim_rsp_running) { return -1000; }
	pthread_join(shim_rsp_thread, NULL);
	shim_rsp_running = 0;
	/* The union's unpacked members pad it past the sum of its fields; copy what fits. */
	int n = (int)sizeof(shim_rsp_msg);
	if (n > maxlen) { n = maxlen; }
	if (out != NULL && n > 0) { memcpy(out, &shim_rsp_msg, (size_t)n); }
	return shim_rsp_status;
}
