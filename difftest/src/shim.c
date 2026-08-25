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
#include "csp_qfifo.h"
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
/* Address of the egress interface. Must not collide with any dst a test forwards to,
 * or csp_iflist_get_by_addr makes the packet "to me" instead of forwarding it. */
#define SHIM_EGRESS_ADDR 20

static csp_iface_t  shim_node_iface;   /* ingress: where injected frames arrive */
static csp_iface_t  shim_node_iface_b;  /* egress: a different subnet, so a forwarded
                                         * packet has somewhere to go. With one interface
                                         * split horizon vetoes forwarding and the C
                                         * correctly drops the packet. */
static uint8_t      shim_tx_buf[SHIM_TX_MAX][SHIM_FRAME_MAX];
static int          shim_tx_len[SHIM_TX_MAX];
static int          shim_tx_n = 0;
static int          shim_node_ready = 0;

/* Capture nexthop: record the framed bytes, free the packet, report success. */
static int shim_node_tx_fn(csp_iface_t *iface, uint16_t via, csp_packet_t *packet, int from_me) {
	(void)iface; (void)via; (void)from_me;
	csp_id_prepend(packet);
	if (shim_tx_n < SHIM_TX_MAX) {
		int n = (int)packet->frame_length;
		if (n > SHIM_FRAME_MAX) { n = SHIM_FRAME_MAX; }
		memcpy(shim_tx_buf[shim_tx_n], packet->frame_begin, (size_t)n);
		shim_tx_len[shim_tx_n] = n;
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
int shim_node_init(int version, uint16_t address) {
	if (shim_node_ready) {
		return (csp_conf.version == (uint8_t)version && shim_node_iface.addr == address) ? 0 : -1;
	}
	/* No global node address in libcsp 2.x: "is it for me" is decided by
	 * csp_iflist_get_by_addr, so the interface address below IS the node address. */
	csp_conf.version = (uint8_t)version;
	shim_ensure_init();

	/* netmask 2 on a 5-host-bit v1 address puts A on 8..15 and B on 16..23, so the two
	 * are genuinely different subnets and is_same_subnet does not merge them. */
	memset(&shim_node_iface, 0, sizeof(shim_node_iface));
	shim_node_iface.name    = "INGRESS";
	shim_node_iface.addr    = address;
	shim_node_iface.netmask = 2;
	shim_node_iface.nexthop = shim_node_tx_fn;
	csp_iflist_add(&shim_node_iface);

	memset(&shim_node_iface_b, 0, sizeof(shim_node_iface_b));
	shim_node_iface_b.name    = "EGRESS";
	shim_node_iface_b.addr    = SHIM_EGRESS_ADDR;
	shim_node_iface_b.netmask = 2;
	shim_node_iface_b.nexthop = shim_node_tx_fn;
	shim_node_iface_b.is_default = 1;
	csp_iflist_add(&shim_node_iface_b);

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
 * Take one delivered message off `port`, if there is one.
 *
 * Reports the connection identity the application would see and the payload, which
 * together are the entire observable result of a delivery. Returns 1 on a message,
 * 0 if nothing is waiting.
 */
int shim_node_recv(uint8_t port, uint16_t *src, uint16_t *dst, uint8_t *dport,
                   uint8_t *sport, uint8_t *out, int *out_len) {
	if (port >= SHIM_PORTS || !shim_bound[port]) { return 0; }
	csp_conn_t *conn = csp_accept(&shim_sockets[port], 0);
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

/* Buffers currently free, so a test can assert the node leaks nothing. */
int shim_node_buf_free(void) { return csp_buffer_remaining(); }

/* Counters on the capture interface, so a test can see which path a packet took. */
void shim_node_counters(uint32_t *rx, uint32_t *tx, uint32_t *drop, uint32_t *rx_error,
                        uint32_t *tx_error, uint32_t *autherr) {
	*rx = shim_node_iface.rx;         *tx = shim_node_iface.tx;
	*drop = shim_node_iface.drop;     *rx_error = shim_node_iface.rx_error;
	*tx_error = shim_node_iface.tx_error; *autherr = shim_node_iface.autherr;
}
int shim_node_iface_registered(void) { return csp_iflist_get_by_addr(shim_node_iface.addr) != NULL; }
