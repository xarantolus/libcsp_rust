//! Differential testing against the C libcsp.
//!
//! Links the real C library and exposes the same entry points as [`csp_core`], so a test
//! can run both on identical bytes and compare. **Dev-only** — this crate is never a
//! dependency of `csp-core` or `csp`, which is the whole point of the port.
//!
//! The 510 golden vectors check the inputs someone thought of. This checks the ones nobody
//! did.
//!
//! # Where the two are *expected* to differ
//!
//! Several divergences are deliberate (see `SCOPE.md`). A differential test must assert
//! the **divergence**, not equality, or a regression back toward C behaviour would pass:
//!
//! - `Id::encode` refuses an out-of-range field; the C shifts it into its neighbour.
//! - `hmac::mac` refuses an empty key; the C returns an error and leaves the output
//!   untouched, which a caller ignoring the return value reads as a MAC.
//!
//! Everything else must agree byte for byte.

#![allow(clippy::missing_safety_doc)]

use core::ffi::{c_int, c_uint};

unsafe extern "C" {
    fn shim_set_version(v: c_int);
    fn shim_id_encode(
        pri: u8,
        flags: u8,
        src: u16,
        dst: u16,
        dport: u8,
        sport: u8,
        out: *mut u8,
    ) -> c_int;
    fn shim_id_encode_fixup(
        pri: u8,
        flags: u8,
        src: u16,
        dst: u16,
        dport: u8,
        sport: u8,
        out: *mut u8,
    ) -> c_int;
    fn shim_id_decode(
        data: *const u8,
        pri: *mut u8,
        flags: *mut u8,
        src: *mut u16,
        dst: *mut u16,
        dport: *mut u8,
        sport: *mut u8,
    );
    fn shim_header_size() -> c_int;
    fn shim_host_bits() -> u32;
    fn shim_max_nodeid() -> u32;
    fn shim_max_port() -> u32;
    fn shim_is_broadcast(addr: u16, iface_addr: u16, iface_netmask: u16) -> c_int;
    fn shim_crc32(data: *const u8, len: u32) -> u32;
    fn shim_sha1(data: *const u8, len: u32, out20: *mut u8);
    fn shim_cfp1_make(src: u16, dst: u16, kind: u32, remain: u32, ident: u16) -> u32;
    fn shim_cfp1_parse(
        id: u32,
        src: *mut u16,
        dst: *mut u16,
        kind: *mut u32,
        remain: *mut u32,
        ident: *mut u16,
    );
    fn shim_hmac(
        key: *const u8,
        keylen: u32,
        data: *const u8,
        datalen: u32,
        out20: *mut u8,
    ) -> c_int;
    fn shim_cfp2_make(
        pri: u16,
        dst: u16,
        sender: u16,
        sc: u16,
        fc: u16,
        begin: u16,
        end: u16,
    ) -> u32;
    #[allow(clippy::too_many_arguments)]
    fn shim_cfp2_parse(
        id: u32,
        pri: *mut u16,
        dst: *mut u16,
        sender: *mut u16,
        sc: *mut u16,
        fc: *mut u16,
        begin: *mut u16,
        end: *mut u16,
    );
    fn shim_rtable_load(text: *const u8) -> c_int;
    fn shim_rtable_check(text: *const u8) -> c_int;
    fn shim_rtable_save(out: *mut u8, maxlen: c_int) -> c_int;
    fn shim_rtable_lookup(addr: u16, name: *mut u8, via: *mut u16) -> c_int;
    fn shim_add_iface(name: *const u8, addr: u16, netmask: u16) -> c_int;
    fn shim_iface_registered(name: *const u8) -> c_int;
    fn shim_kiss_reset();
    fn shim_kiss_feed(buf: *const u8, len: u32, out: *mut u8, out_len: *mut c_int) -> c_int;
    fn shim_kiss_rx_errors() -> u32;
    fn shim_kiss_last_id(out: *mut u8) -> c_int;
    fn shim_kiss_drops() -> u32;
    fn shim_kiss_frame_errors() -> u32;
    fn shim_node_init(version: c_int, address: u16, netmask: u16, egress: u16, third: u16)
        -> c_int;
    fn shim_node_bind(port: u8) -> c_int;
    fn shim_node_inject(frame: *const u8, len: u32) -> c_int;
    fn shim_node_pump() -> c_int;
    fn shim_node_serve(port: u8) -> c_int;
    fn shim_node_send_on(port: u8, body: *const u8, len: c_int) -> c_int;
    fn shim_node_release(port: u8);
    fn shim_node_set_dedup(mode: c_int);
    fn shim_node_sfp_recv(port: u8, out: *mut u8, maxlen: c_int) -> c_int;
    fn shim_node_client_send(dst: u16, dport: u8, body: *const u8, len: c_int) -> c_int;
    fn shim_conn_open(slot: c_int, dst: u16, dport: u8) -> c_int;
    fn shim_conn_close(slot: c_int);
    fn shim_node_client_send_prio(
        prio: u8,
        dst: u16,
        dport: u8,
        body: *const u8,
        len: c_int,
    ) -> c_int;
    fn shim_node_client_read(out: *mut u8, out_len: *mut c_int) -> c_int;
    fn shim_node_client_close();
    fn shim_iflist_check_dfl();
    fn shim_iflist_clear_dfl();
    fn shim_iface_is_default(name: *const u8) -> c_int;
    fn shim_arp_set(csp_addr: u16, mac: *const u8);
    fn shim_arp_get(csp_addr: u16, mac_out: *mut u8);
    fn shim_mem_base() -> u64;
    fn shim_mem_fill(seed: u8, step: u8);
    fn shim_mem_read(off: u32, out: *mut u8, len: c_int) -> c_int;
    fn shim_cmp_build_ident_request(out: *mut u8) -> c_int;
    fn shim_cmp_parse_ident_reply(
        buf: *const u8,
        len: c_int,
        hostname: *mut u8,
        model: *mut u8,
        revision: *mut u8,
    ) -> c_int;
    fn shim_service_rebooted() -> c_int;
    fn shim_service_shut_down() -> c_int;
    fn shim_service_hooks_reset();
    fn shim_set_memfree(bytes: u32);
    fn shim_set_ps_entries(n: u32);
    fn shim_bridge_set(a: c_int, b: c_int);
    fn shim_bridge_work();
    fn shim_node_inject_on(iface: c_int, frame: *const u8, len: u32) -> c_int;
    fn shim_client_reboot(dst: u16, shutdown_instead: c_int) -> c_int;
    fn shim_client_request(kind: c_int, dst: u16, size: u32, opts: u8) -> c_int;
    #[allow(clippy::too_many_arguments)]
    fn shim_client_transaction(
        dst: u16,
        dport: u8,
        reply: *const u8,
        reply_len: c_int,
        inlen: c_int,
        out: *mut u8,
        out_len: *mut c_int,
    ) -> c_int;
    #[allow(clippy::too_many_arguments)]
    fn shim_client_transaction_opts(
        dst: u16,
        dport: u8,
        opts: u32,
        reply_flags: u8,
        reply: *const u8,
        reply_len: c_int,
        inlen: c_int,
        out: *mut u8,
        out_len: *mut c_int,
    ) -> c_int;
    fn shim_sfp_send(dst: u16, dport: u8, body: *const u8, len: c_int, mtu: u32) -> c_int;
    fn shim_node_sfp_send_on(port: u8, body: *const u8, len: c_int, mtu: u32) -> c_int;
    fn shim_rdp_connect_start(dst: u16, dport: u8) -> c_int;
    fn shim_rdp_connect_join() -> c_int;
    fn shim_rdp_initiator_send(body: *const u8, len: c_int) -> c_int;
    fn shim_rdp_initiator_close();
    fn shim_cmp_if_stats_start(node: u16, ifname: *const u8) -> c_int;
    fn shim_cmp_if_stats_join(out: *mut u8, maxlen: c_int) -> c_int;
    fn shim_service_start(kind: c_int, dst: u16, size: c_uint, opts: u8) -> c_int;
    fn shim_service_join(value: *mut u32) -> c_int;
    fn shim_cmp_clock_start(node: u16, tv_sec: u32, tv_nsec: u32) -> c_int;
    fn shim_cmp_clock_join(tv_sec: *mut u32, tv_nsec: *mut u32) -> c_int;
    fn shim_cmp_route_set_v2_start(
        node: u16,
        dest: u16,
        netmask: u16,
        via: u16,
        ifname: *const u8,
    ) -> c_int;
    fn shim_cmp_peek_start(node: u16, addr: u32, len: u8) -> c_int;
    fn shim_cmp_poke_start(node: u16, addr: u32, data: *const u8, len: u8) -> c_int;
    fn shim_cmp_raw_join(out: *mut u8, maxlen: c_int) -> c_int;
    fn shim_i2c_init(address: u16) -> c_int;
    fn shim_i2c_tx(dst: u16, via: u16) -> c_int;
    fn shim_i2c_rx(frame: *const u8, len: u32) -> c_int;
    fn shim_node_add_alias(addr: u16, iface: c_int) -> c_int;
    fn shim_node_is_alias(addr: u16) -> c_int;
    fn shim_can_init(address: u16, netmask: u16) -> c_int;
    fn shim_can_clear();
    fn shim_can_count() -> c_int;
    fn shim_can_get(i: c_int, id: *mut u32, data: *mut u8) -> c_int;
    fn shim_can_send(dst: u16, dport: u8, sport: u8, body: *const u8, len: c_int) -> c_int;
    fn shim_can_rx(id: u32, data: *const u8, dlc: u8) -> c_int;
    fn shim_node_accept_count(port: u8) -> c_int;
    fn shim_clock_set(ms: u32);
    fn shim_clock_advance(ms: u32);
    fn shim_node_check_timeouts();
    fn shim_node_promisc_enable() -> c_int;
    fn shim_node_promisc_read(out: *mut u8, dst: *mut u16) -> c_int;
    fn shim_node_clear_tx();
    fn shim_node_tx_count() -> c_int;
    fn shim_node_tx_get(i: c_int, out: *mut u8) -> c_int;
    #[allow(clippy::too_many_arguments)]
    fn shim_node_recv(
        port: u8,
        src: *mut u16,
        dst: *mut u16,
        dport: *mut u8,
        sport: *mut u8,
        out: *mut u8,
        out_len: *mut c_int,
    ) -> c_int;
    fn shim_node_bind_conn_less(port: u8) -> c_int;
    fn shim_node_recvfrom(
        src: *mut u16,
        dst: *mut u16,
        dport: *mut u8,
        sport: *mut u8,
        out: *mut u8,
        out_len: *mut c_int,
    ) -> c_int;
    fn shim_node_bind_any() -> c_int;
    fn shim_node_unbind_any() -> c_int;
    fn shim_node_recv_any(
        src: *mut u16,
        dst: *mut u16,
        dport: *mut u8,
        sport: *mut u8,
        out: *mut u8,
        out_len: *mut c_int,
    ) -> c_int;
    fn shim_node_buf_free() -> c_int;
    fn shim_node_unbind(port: u8) -> c_int;
    fn shim_node_read_count(port: u8) -> c_int;
    fn shim_node_read_held(port: u8) -> c_int;
    fn shim_hmac_set_key(key: *const u8, keylen: u32) -> c_int;
    fn shim_node_held_active(port: u8) -> c_int;
    fn shim_node_open_conns() -> c_int;
    fn shim_buffers_hold(n: c_int) -> c_int;
    fn shim_buffers_release();
    fn shim_node_counters(
        rx: *mut u32,
        tx: *mut u32,
        drop: *mut u32,
        rx_error: *mut u32,
        tx_error: *mut u32,
        autherr: *mut u32,
    );
    fn shim_node_iface_registered() -> c_int;
    fn shim_node_tx_iface(i: c_int, name: *mut u8, via: *mut u16) -> c_int;
    fn shim_node_route(address: u16, netmask: c_int, iface: c_int, via: u16) -> c_int;
}

/// Install a routing-table entry on the C node. `iface`: 0=INGRESS, 1=EGRESS, 2=ROUTED.
pub fn c_node_route(address: u16, netmask: i32, iface: i32, via: u16) -> i32 {
    // SAFETY: the shim maps `iface` onto one of its three static interfaces.
    unsafe { shim_node_route(address, netmask, iface, via) }
}

/// Capture-interface counters: (rx, tx, drop, rx_error, tx_error, autherr).
pub fn c_node_counters() -> (u32, u32, u32, u32, u32, u32) {
    let (mut a, mut b, mut c, mut d, mut e, mut f) = (0, 0, 0, 0, 0, 0);
    // SAFETY: six live stack slots, all written by the shim.
    unsafe { shim_node_counters(&mut a, &mut b, &mut c, &mut d, &mut e, &mut f) }
    (a, b, c, d, e, f)
}

/// Whether the C node's own address resolves through the interface list.
pub fn c_node_iface_registered() -> bool {
    // SAFETY: one lookup, no arguments.
    unsafe { shim_node_iface_registered() != 0 }
}

/// What a CSP node did with a frame, described only in terms an application or a peer
/// could observe.
///
/// Deliberately no internal state: no queue depths, no connection-table indices, no
/// refcounts. If a test needs one of those to pass it is pinning an implementation, and
/// the port is entitled to differ.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NodeOutcome {
    /// Frames the node put on the wire, in order, as complete framed bytes.
    pub tx: Vec<Vec<u8>>,
    /// For each frame, the interface name it left by and the next hop it was given.
    /// Both are observable at the driver boundary — a real driver uses `via` to address
    /// its link-layer peer.
    pub tx_via: Vec<(String, u16)>,
    /// Messages the application received: (port, src, dst, dport, sport, payload).
    pub delivered: Vec<Delivered>,
}

/// One message an application received.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct Delivered {
    pub port: u8,
    pub src: u16,
    pub dst: u16,
    pub dport: u8,
    pub sport: u8,
    pub payload: Vec<u8>,
}

/// Bring the C node up with two interfaces in different subnets.
///
/// Idempotent, and it has to be: `csp_conf.version` is init-only (SCOPE.md deviation 18),
/// so one process gets one node at one wire version. Testing the other version means a
/// second test binary, which is why `node_v2.rs` exists alongside `diff.rs`.
pub fn c_node_init(
    version: csp_core::Version,
    address: u16,
    netmask: u16,
    egress: u16,
    third: u16,
) -> bool {
    let v = match version {
        csp_core::Version::V1 => 1,
        csp_core::Version::V2 => 2,
    };
    // SAFETY: calls csp_init once behind an internal guard; callers hold `LOCK`.
    unsafe { shim_node_init(v, address, netmask, egress, third) == 0 }
}

/// Bind a port on the C node.
pub fn c_node_bind(port: u8) -> i32 {
    // SAFETY: bounded by SHIM_PORTS on the C side, which returns -1 rather than indexing.
    unsafe { shim_node_bind(port) }
}

/// Bind `CSP_ANY` on the C node — libcsp's catch-all, which receives every port that has
/// no socket of its own. Read what it gets with [`c_node_recv_any`].
pub fn c_node_bind_any() -> i32 {
    // SAFETY: no arguments; idempotent behind a flag on the C side. Callers hold `LOCK`.
    unsafe { shim_node_bind_any() }
}

/// Run `csp_iflist_check_dfl` on the C node's interfaces.
pub fn c_iflist_check_dfl() {
    // SAFETY: no arguments; walks libcsp's own interface list. Callers hold `LOCK`.
    unsafe { shim_iflist_check_dfl() }
}

/// Clear `is_default` on every interface the harness registered, including loopback.
///
/// Not a libcsp operation — it writes the same public struct field an application sets — and
/// it exists so the "nothing is default yet" branch of `csp_iflist_check_dfl` is reachable
/// at all: the harness registers EGRESS as a default.
pub fn c_iflist_clear_dfl() {
    // SAFETY: writes a public field of the shim's own static interfaces. Callers hold `LOCK`.
    unsafe { shim_iflist_clear_dfl() }
}

/// Whether the named C interface is a default-route target. `None` if there is no such one.
pub fn c_iface_is_default(name: &str) -> Option<bool> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: `c` is NUL-terminated and outlives the call. Callers hold `LOCK`.
    match unsafe { shim_iface_is_default(c.as_ptr() as *const u8) } {
        n if n < 0 => None,
        n => Some(n != 0),
    }
}

/// Teach libcsp's Ethernet ARP table that `csp_addr` lives at `mac`.
pub fn c_arp_set(csp_addr: u16, mac: [u8; 6]) {
    // SAFETY: `mac` is six bytes, which is what the shim copies. Callers hold `LOCK`.
    unsafe { shim_arp_set(csp_addr, mac.as_ptr()) }
}

/// The MAC libcsp would address a frame for `csp_addr` to.
pub fn c_arp_get(csp_addr: u16) -> [u8; 6] {
    let mut mac = [0u8; 6];
    // SAFETY: the shim writes exactly six bytes. Callers hold `LOCK`.
    unsafe { shim_arp_get(csp_addr, mac.as_mut_ptr()) }
    mac
}

/// The base address libcsp's CMP peek/poke region answers to in this harness.
pub fn c_mem_base() -> u64 {
    // SAFETY: returns a constant. Callers hold `LOCK`.
    unsafe { shim_mem_base() }
}

/// Fill that region with `seed + i * step`, so a peek reply names the offset it came from.
pub fn c_mem_fill(seed: u8, step: u8) {
    // SAFETY: writes only the shim's own static array. Callers hold `LOCK`.
    unsafe { shim_mem_fill(seed, step) }
}

/// Read `len` bytes of the region back, so a poke is observable. `None` if out of range.
pub fn c_mem_read(off: u32, len: usize) -> Option<Vec<u8>> {
    let mut out = vec![0u8; len];
    // SAFETY: the shim bounds-checks `off`/`len` against its own array.
    let n = unsafe { shim_mem_read(off, out.as_mut_ptr(), len as c_int) };
    if n < 0 {
        return None;
    }
    out.truncate(n as usize);
    Some(out)
}

/// Bind `port` on the C node as a **connection-less** socket (`CSP_SO_CONN_LESS`).
pub fn c_node_bind_conn_less(port: u8) -> i32 {
    // SAFETY: one static socket on the C side, bound at most once. Callers hold `LOCK`.
    unsafe { shim_node_bind_conn_less(port) }
}

/// Take everything waiting on the connection-less socket, after pumping the router.
pub fn c_node_recvfrom() -> Vec<Delivered> {
    let mut out = Vec::new();
    // SAFETY: the payload buffer is sized for the largest packet the C can deliver, and the
    // shim writes at most `length` bytes into it. Callers hold `LOCK`.
    unsafe {
        shim_node_pump();
        loop {
            let (mut src, mut dst) = (0u16, 0u16);
            let (mut dport, mut sport) = (0u8, 0u8);
            let mut payload = vec![0u8; 512];
            let mut n: c_int = 0;
            if shim_node_recvfrom(
                &mut src,
                &mut dst,
                &mut dport,
                &mut sport,
                payload.as_mut_ptr(),
                &mut n,
            ) == 0
            {
                break;
            }
            payload.truncate(n as usize);
            out.push(Delivered {
                port: dport,
                src,
                dst,
                dport,
                sport,
                payload,
            });
        }
    }
    out
}

/// Release the C node's catch-all with `csp_socket_close`. Returns `csp_dbg_errno`.
pub fn c_node_unbind_any() -> i32 {
    // SAFETY: no arguments; a no-op when nothing is bound. Callers hold `LOCK`.
    unsafe { shim_node_unbind_any() }
}

/// Take everything waiting on the catch-all socket, after pumping the router.
///
/// `dport` on each item is what says which port the packet was addressed to — the catch-all
/// is one socket for all of them.
pub fn c_node_recv_any() -> Vec<Delivered> {
    let mut out = Vec::new();
    // SAFETY: the payload buffer is sized for the largest packet the C can deliver, and
    // the shim writes at most `length` bytes into it. Callers hold `LOCK`.
    unsafe {
        shim_node_pump();
        loop {
            let (mut src, mut dst) = (0u16, 0u16);
            let (mut dport, mut sport) = (0u8, 0u8);
            let mut payload = vec![0u8; 512];
            let mut n: c_int = 0;
            if shim_node_recv_any(
                &mut src,
                &mut dst,
                &mut dport,
                &mut sport,
                payload.as_mut_ptr(),
                &mut n,
            ) == 0
            {
                break;
            }
            payload.truncate(n as usize);
            out.push(Delivered {
                port: dport,
                src,
                dst,
                dport,
                sport,
                payload,
            });
        }
    }
    out
}

/// Feed `frame` to a real C node acting as a *server*, let its built-in service handler
/// answer, and hand back the frames it put on the wire.
///
/// `port` must be one of libcsp's well-known services (`CSP_PING` = 1, `CSP_UPTIME` = 6,
/// ...) and must already be bound. The reply is produced by `csp_service_handler` +
/// `csp_sendto_reply`, i.e. by libcsp itself and not by the harness.
///
/// This is the only way to exercise the port as a *client*: everything else in this file
/// drives the server direction, which is how every reply to every connection the port
/// opened stayed silently dropped for months.
pub fn c_node_serve(frame: &[u8], port: u8) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    // SAFETY: buffers are sized for the largest frame the C can emit and the shim
    // bounds-checks its own indices. Callers hold `LOCK`.
    unsafe {
        shim_node_clear_tx();
        shim_node_inject(frame.as_ptr(), frame.len() as u32);
        shim_node_pump();
        while shim_node_serve(port) == 1 {}
        shim_node_pump();
        for i in 0..shim_node_tx_count() {
            let mut buf = vec![0u8; 512];
            let n = shim_node_tx_get(i, buf.as_mut_ptr());
            if n > 0 {
                buf.truncate(n as usize);
                frames.push(buf);
            }
        }
    }
    frames
}

/// Have the C node **originate** data on a connection a peer opened to it, and hand back
/// the frames it put on the wire.
///
/// The other direction from everything else here: the C accepts, keeps the connection, and
/// calls `csp_send` on it, so an RDP connection's bytes are sequenced by libcsp itself.
/// What comes back is a real C peer's data for the port to deliver and acknowledge.
pub fn c_node_send_on(port: u8, body: &[u8]) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    // SAFETY: `body` is a valid slice for the call; the shim bounds-checks `port` and the
    // length against its own buffers. Callers hold `LOCK`.
    unsafe {
        shim_node_clear_tx();
        if shim_node_send_on(port, body.as_ptr(), body.len() as c_int) != 1 {
            return frames;
        }
        shim_node_pump();
        for i in 0..shim_node_tx_count() {
            let mut buf = vec![0u8; 512];
            let n = shim_node_tx_get(i, buf.as_mut_ptr());
            if n > 0 {
                buf.truncate(n as usize);
                frames.push(buf);
            }
        }
    }
    frames
}

/// Inject `frames` in order, then have the C node's application reassemble them as a stream.
///
/// Returns `Ok(bytes)` — what `csp_sfp_recv_fp` handed the application — or `Err(code)` with
/// libcsp's own error. This is the only path that asks whether the fragments the port emits
/// are ones a *real C node* routes to a bound port and reassembles: `ctest/suite_sfp.c`
/// hands hand-built packets straight to `csp_sfp_recv_fp` on a hand-opened connection, with
/// no header on a wire and no routing, so it cannot answer that question.
pub fn c_node_sfp_recv(frames: &[Vec<u8>], port: u8) -> Result<Vec<u8>, i32> {
    let mut out = vec![0u8; 4096];
    // SAFETY: every pointer is a valid slice for the call; the shim bounds-checks `port`
    // and the reassembled length against `maxlen`. Callers hold `LOCK`.
    let n = unsafe {
        for f in frames {
            shim_node_inject(f.as_ptr(), f.len() as u32);
        }
        shim_node_pump();
        shim_node_sfp_recv(port, out.as_mut_ptr(), out.len() as c_int)
    };
    if n < 0 {
        return Err(n);
    }
    out.truncate(n as usize);
    Ok(out)
}

/// A CMP IDENT request laid out by libcsp's own `struct csp_cmp_ident_msg`.
///
/// Taken from the C struct rather than written out here on purpose: libcsp sends `sizeof`
/// the *reply* member for a request, so the padding is part of what the port has to accept,
/// and a transcription of the layout into Rust would put the thing under test on both sides
/// of the comparison.
pub fn c_cmp_ident_request() -> Vec<u8> {
    let mut out = vec![0u8; 256];
    // SAFETY: `out` is far larger than `sizeof(struct csp_cmp_ident_msg)`.
    let n = unsafe { shim_cmp_build_ident_request(out.as_mut_ptr()) };
    out.truncate(n as usize);
    out
}

/// The C node opens a connection to `dst:dport`, sends `body`, and returns the frames.
///
/// The direction nothing else covers: every other node-level exchange has the C answering,
/// or originating on a connection the *peer* opened. Here the C is the one that connects,
/// so the port's reply has to find a connection a real C client is waiting on.
pub fn c_node_client_send(dst: u16, dport: u8, body: &[u8]) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    // SAFETY: `body` is valid for the call and the shim bounds-checks it against its own
    // packet buffer. Callers hold `LOCK`.
    unsafe {
        shim_node_clear_tx();
        if shim_node_client_send(dst, dport, body.as_ptr(), body.len() as c_int) != 1 {
            return frames;
        }
        shim_node_pump();
        for i in 0..shim_node_tx_count() {
            let mut buf = vec![0u8; 512];
            let n = shim_node_tx_get(i, buf.as_mut_ptr());
            if n > 0 {
                buf.truncate(n as usize);
                frames.push(buf);
            }
        }
    }
    frames
}

/// Open a client connection on the C node in `slot`, send one byte, and report the source
/// port that reached the wire. Negative on failure.
pub fn c_conn_open(slot: i32, dst: u16, dport: u8) -> i32 {
    // SAFETY: the shim bounds-checks `slot` against its own array. Callers hold `LOCK`.
    unsafe { shim_conn_open(slot, dst, dport) }
}

/// Close the connection in `slot`.
pub fn c_conn_close(slot: i32) {
    // SAFETY: same bound, and closing an empty slot is a no-op. Callers hold `LOCK`.
    unsafe { shim_conn_close(slot) }
}

/// The same, but through `csp_send_prio` with `prio`.
///
/// Uses the *same held connection* as [`c_node_client_send`], which is the point: what the
/// call leaves behind on that connection is only visible in what the next plain send does.
pub fn c_node_client_send_prio(prio: u8, dst: u16, dport: u8, body: &[u8]) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    // SAFETY: same bounds and buffers as `c_node_client_send`. Callers hold `LOCK`.
    unsafe {
        shim_node_clear_tx();
        if shim_node_client_send_prio(prio, dst, dport, body.as_ptr(), body.len() as c_int) != 1 {
            return frames;
        }
        shim_node_pump();
        for i in 0..shim_node_tx_count() {
            let mut buf = vec![0u8; 512];
            let n = shim_node_tx_get(i, buf.as_mut_ptr());
            if n > 0 {
                buf.truncate(n as usize);
                frames.push(buf);
            }
        }
    }
    frames
}

/// Inject `frame` and read what the C client's application gets off its own connection.
pub fn c_node_client_recv(frame: &[u8]) -> Option<Vec<u8>> {
    let mut out = vec![0u8; 512];
    let mut len: c_int = 0;
    // SAFETY: both pointers are valid for the call; the shim copies at most one packet's
    // payload, which cannot exceed `out`. Callers hold `LOCK`.
    let got = unsafe {
        shim_node_inject(frame.as_ptr(), frame.len() as u32);
        shim_node_pump();
        shim_node_client_read(out.as_mut_ptr(), &mut len)
    };
    if got != 1 {
        return None;
    }
    out.truncate(len as usize);
    Some(out)
}

/// Close the C client's connection.
pub fn c_node_client_close() {
    // SAFETY: idempotent on the C side. Callers hold `LOCK`.
    unsafe { shim_node_client_close() }
}

/// Parse a CMP IDENT reply with the C's own struct, as a C application would.
///
/// `None` if the C would not recognise it: wrong size, wrong type byte, or wrong code.
pub fn c_cmp_parse_ident(reply: &[u8]) -> Option<(String, String, String)> {
    let (mut h, mut m, mut r) = ([0u8; 64], [0u8; 64], [0u8; 64]);
    // SAFETY: the three out buffers are larger than the struct's corresponding fields
    // (CSP_HOSTNAME_LEN, CSP_MODEL_LEN, CSP_CMP_IDENT_REV_LEN are all well under 64).
    let ok = unsafe {
        shim_cmp_parse_ident_reply(
            reply.as_ptr(),
            reply.len() as c_int,
            h.as_mut_ptr(),
            m.as_mut_ptr(),
            r.as_mut_ptr(),
        )
    };
    if ok != 1 {
        return None;
    }
    let cstr = |b: &[u8]| {
        String::from_utf8_lossy(&b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())])
            .into_owned()
    };
    Some((cstr(&h), cstr(&m), cstr(&r)))
}

/// Whether the C node's reboot / shutdown hook was reached, since the last reset.
///
/// The real posix hooks reboot the machine, so this build supplies recording ones instead
/// (see `build.rs`). Without that, "does the magic word gate the reboot service" is a
/// question no test could safely ask.
pub fn c_service_rebooted() -> (bool, bool) {
    // SAFETY: two reads of a static int, no arguments. Callers hold `LOCK`.
    unsafe { (shim_service_rebooted() != 0, shim_service_shut_down() != 0) }
}

/// Clear the recorded hooks and restore the fixed MEMFREE value.
pub fn c_service_hooks_reset() {
    // SAFETY: writes only the shim's own statics. Callers hold `LOCK`.
    unsafe { shim_service_hooks_reset() }
}

/// What the C node reports for MEMFREE, so the two stacks can be given the same number.
pub fn c_set_memfree(bytes: u32) {
    // SAFETY: writes one static. Callers hold `LOCK`.
    unsafe { shim_set_memfree(bytes) }
}

/// What `csp_ps_hook` returns — the C's PS handler replies only if this is non-zero.
pub fn c_set_ps_entries(n: u32) {
    // SAFETY: writes one static. Callers hold `LOCK`.
    unsafe { shim_set_ps_entries(n) }
}

/// Point the C's bridge at two of the node's interfaces. 0=INGRESS, 1=EGRESS, 2=ROUTED.
pub fn c_bridge_set(a: i32, b: i32) {
    // SAFETY: the shim maps each index onto one of its three static interfaces.
    unsafe { shim_bridge_set(a, b) }
}

/// Inject `frame` as if it arrived on `iface`, run one bridge step, and return what left.
///
/// `csp_bridge_work` is a forwarding path of its own: no routing table, no split horizon,
/// no address rewrite, and dedup applied whatever `csp_conf.dedup` says. Each returned entry
/// is (interface name, framed bytes) — which wire the frame reached and what was on it.
pub fn c_bridge_step(iface: i32, frame: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    // SAFETY: `frame` is valid for the call; the shim bounds-checks it against a packet
    // buffer and the capture array is fixed-size. Callers hold `LOCK`.
    unsafe {
        shim_node_clear_tx();
        if shim_node_inject_on(iface, frame.as_ptr(), frame.len() as u32) != 0 {
            return out;
        }
        shim_bridge_work();
        for i in 0..shim_node_tx_count() {
            let mut buf = vec![0u8; 512];
            let n = shim_node_tx_get(i, buf.as_mut_ptr());
            let mut name = [0u8; 32];
            let mut via: u16 = 0;
            shim_node_tx_iface(i, name.as_mut_ptr(), &mut via);
            if n > 0 {
                buf.truncate(n as usize);
                let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
                out.push((String::from_utf8_lossy(&name[..end]).into_owned(), buf));
            }
        }
    }
    out
}

/// Run `csp_transaction_persistent` with `reply` already queued on the connection.
///
/// Returns `(ret, bytes)` — what the transaction returned, and what it copied out. `ret == 0`
/// is the C's "refused"; the `csp_get_*` clients turn that into a failure with no value.
pub fn c_client_transaction(dst: u16, dport: u8, reply: &[u8], inlen: i32) -> (i32, Vec<u8>) {
    let mut out = vec![0u8; 256];
    let mut n: c_int = 0;
    // SAFETY: `reply` is valid for the call and bounds-checked on the C side; `out` is 256
    // bytes and the shim copies at most that. Callers hold `LOCK`.
    let ret = unsafe {
        shim_client_transaction(
            dst,
            dport,
            reply.as_ptr(),
            reply.len() as c_int,
            inlen,
            out.as_mut_ptr(),
            &mut n,
        )
    };
    out.truncate(n as usize);
    (ret, out)
}

/// [`c_client_transaction`] with the connection opened under `opts` and the queued reply
/// carrying `reply_flags` (a `CRC32` flag gets its checksum appended, as a real peer's
/// `csp_sendto_reply(.., CSP_O_SAME)` would).
///
/// This is how the C's **per-connection** policy is observed: `csp_route.c:288` checks a
/// reply against `conn->opts`, the options `csp_connect` stored on this very connection.
pub fn c_client_transaction_opts(
    dst: u16,
    dport: u8,
    opts: u32,
    reply_flags: u8,
    reply: &[u8],
    inlen: i32,
) -> (i32, Vec<u8>) {
    let mut out = vec![0u8; 256];
    let mut n: c_int = 0;
    // SAFETY: as `c_client_transaction`. Callers hold `LOCK`.
    let ret = unsafe {
        shim_client_transaction_opts(
            dst,
            dport,
            opts,
            reply_flags,
            reply.as_ptr(),
            reply.len() as c_int,
            inlen,
            out.as_mut_ptr(),
            &mut n,
        )
    };
    out.truncate(n as usize);
    (ret, out)
}

/// Bring up a real `csp_if_i2c` interface with a capturing driver.
pub fn c_i2c_init(address: u16) -> bool {
    // SAFETY: idempotent; the shim owns the interface and its data block for the process.
    unsafe { shim_i2c_init(address) == 0 }
}

/// The bus address `csp_i2c_tx` chose for a packet, or `None` if it never reached the driver.
///
/// `csp_i2c_tx` writes it into `packet->cfpid`, so this is the number a real driver would
/// put on the wire — seven bits of it.
pub fn c_i2c_bus_addr(dst: u16, via: u16) -> Option<u8> {
    // SAFETY: no arguments beyond two integers; the shim owns the packet it allocates.
    let n = unsafe { shim_i2c_tx(dst, via) };
    if n < 0 {
        None
    } else {
        Some(n as u8)
    }
}

/// Whether `csp_i2c_rx` routed a frame of this length, or counted it as a framing error.
pub fn c_i2c_accepts(frame: &[u8]) -> bool {
    // SAFETY: `frame` is valid for the call and bounds-checked on the C side.
    unsafe { shim_i2c_rx(frame.as_ptr(), frame.len() as u32) == 1 }
}

/// Fragment `body` with libcsp's own `csp_sfp_send`, and return the frames it emitted.
///
/// `Err(code)` carries libcsp's error — `CSP_ERR_MTU` for an `mtu` above what the connection
/// allows, which is the one refusal this entry point can produce.
pub fn c_sfp_send(dst: u16, dport: u8, body: &[u8], mtu: u32) -> Result<Vec<Vec<u8>>, i32> {
    let mut frames = Vec::new();
    // SAFETY: `body` outlives the call — the shim's read callback only reads it during
    // `csp_sfp_send`. Callers hold `LOCK`.
    let n = unsafe { shim_sfp_send(dst, dport, body.as_ptr(), body.len() as c_int, mtu) };
    if n < 0 {
        return Err(n);
    }
    // SAFETY: the capture array is fixed-size and bounds-checked on the C side.
    unsafe {
        for i in 0..shim_node_tx_count() {
            let mut buf = vec![0u8; 512];
            let k = shim_node_tx_get(i, buf.as_mut_ptr());
            if k > 0 {
                buf.truncate(k as usize);
                frames.push(buf);
            }
        }
    }
    Ok(frames)
}

/// Fragment `body` with `csp_sfp_send` on the connection the C node already holds for
/// `port`, and return the frames it emitted.
///
/// After an RDP handshake that connection is a real RDP connection, so each fragment leaves
/// carrying **two** trailers — SFP's, then RDP's. `c_sfp_send` opens a plain connection and
/// therefore only ever produces one.
///
/// `Err(code)` carries libcsp's error; `Err(0)` means there was no connection to send on.
pub fn c_node_sfp_send_on(port: u8, body: &[u8], mtu: u32) -> Result<Vec<Vec<u8>>, i32> {
    // SAFETY: `body` outlives the call — the shim's read callback only reads it during
    // `csp_sfp_send`. Callers hold `LOCK`.
    let n = unsafe { shim_node_sfp_send_on(port, body.as_ptr(), body.len() as c_int, mtu) };
    if n <= 0 {
        return Err(n);
    }
    let mut frames = Vec::new();
    // SAFETY: the capture array is fixed-size and bounds-checked on the C side.
    unsafe {
        for i in 0..shim_node_tx_count() {
            let mut buf = vec![0u8; 512];
            let k = shim_node_tx_get(i, buf.as_mut_ptr());
            if k > 0 {
                buf.truncate(k as usize);
                frames.push(buf);
            }
        }
    }
    Ok(frames)
}

/// Read whatever the shim last captured on the wire.
fn captured_frames() -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    // SAFETY: the capture array is fixed-size and bounds-checked on the C side.
    unsafe {
        for i in 0..shim_node_tx_count() {
            let mut buf = vec![0u8; 512];
            let k = shim_node_tx_get(i, buf.as_mut_ptr());
            if k > 0 {
                buf.truncate(k as usize);
                frames.push(buf);
            }
        }
    }
    frames
}

/// Begin a real `csp_connect(..., CSP_SO_RDPREQ)` on the C node and return its SYN.
///
/// `csp_rdp_connect` blocks until a router task answers, so the call runs on its own thread
/// and the caller drives the exchange. Finish with [`c_rdp_connect_join`].
pub fn c_rdp_connect_start(dst: u16, dport: u8) -> Vec<Vec<u8>> {
    // SAFETY: the shim owns the thread and the connection for the life of the exchange.
    let n = unsafe { shim_rdp_connect_start(dst, dport) };
    assert!(n >= 0, "the C node could not start an RDP connect: {n}");
    captured_frames()
}

/// libcsp's own verdict on the handshake: `true` if `csp_connect` returned a connection.
pub fn c_rdp_connect_join() -> bool {
    // SAFETY: joins the thread started above; a no-op if none is running.
    unsafe { shim_rdp_connect_join() == 1 }
}

/// Send one datagram on the C initiator's connection and return the frames it produced.
pub fn c_rdp_initiator_send(body: &[u8]) -> Vec<Vec<u8>> {
    // SAFETY: `body` is only read during the call. Callers hold `LOCK`.
    let n = unsafe { shim_rdp_initiator_send(body.as_ptr(), body.len() as c_int) };
    if n <= 0 {
        return Vec::new();
    }
    captured_frames()
}

/// Close the C initiator's connection.
pub fn c_rdp_initiator_close() {
    // SAFETY: idempotent on the C side.
    unsafe { shim_rdp_initiator_close() }
}

/// What libcsp's `struct csp_cmp_if_stats_msg` carries back, host-order.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CIfStats {
    pub interface: String,
    pub tx: u32,
    pub rx: u32,
    pub tx_error: u32,
    pub rx_error: u32,
    pub drop: u32,
    pub autherr: u32,
    pub frame: u32,
    pub txbytes: u32,
    pub rxbytes: u32,
    pub irq: u32,
}

/// Begin a real `csp_cmp_if_stats` on the C node and return the request it put on the wire.
///
/// This is libcsp's own client entry point, not a request this repository composed: it sends
/// with `CSP_O_CRC32` and checks the reply's length itself. `csp_read` blocks, so the call
/// runs on its own thread; finish with [`c_cmp_if_stats_join`].
pub fn c_cmp_if_stats_start(node: u16, ifname: &str) -> Vec<Vec<u8>> {
    let name = std::ffi::CString::new(ifname).expect("no interior nul");
    // SAFETY: `name` outlives the call; the shim copies it before returning.
    let n = unsafe { shim_cmp_if_stats_start(node, name.as_ptr().cast()) };
    assert!(
        n >= 0,
        "the C client could not start a CMP transaction: {n}"
    );
    captured_frames()
}

/// libcsp's own verdict on the port's IF_STATS reply, and the message it parsed.
///
/// `Err(code)` is libcsp's error — `CSP_ERR_TIMEDOUT` covers both "no reply" and "a reply
/// the client's own router threw away", which is what a missing CRC32 looks like.
pub fn c_cmp_if_stats_join() -> Result<CIfStats, i32> {
    let mut buf = [0u8; 128];
    // SAFETY: `buf` is larger than the struct; the shim bounds-checks against `maxlen`.
    let status = unsafe { shim_cmp_if_stats_join(buf.as_mut_ptr(), buf.len() as c_int) };
    if status != 0 {
        return Err(status);
    }
    let name_end = buf[2..2 + 11].iter().position(|&b| b == 0).unwrap_or(11);
    let be = |i: usize| {
        u32::from_be_bytes([
            buf[13 + i * 4],
            buf[14 + i * 4],
            buf[15 + i * 4],
            buf[16 + i * 4],
        ])
    };
    Ok(CIfStats {
        interface: String::from_utf8_lossy(&buf[2..2 + name_end]).into_owned(),
        tx: be(0),
        rx: be(1),
        tx_error: be(2),
        rx_error: be(3),
        drop: be(4),
        autherr: be(5),
        frame: be(6),
        txbytes: be(7),
        rxbytes: be(8),
        irq: be(9),
    })
}

/// Which of `csp_services.c`'s clients to run, for [`c_service_start`].
#[derive(Debug, Clone, Copy)]
pub enum CService {
    /// `csp_ping`, with a payload size and connection options.
    Ping { size: u32, opts: u8 },
    /// `csp_get_memfree`.
    MemFree,
    /// `csp_get_buf_free`.
    BufFree,
    /// `csp_get_uptime`.
    Uptime,
}

/// Begin one of libcsp's own service clients and return the request it put on the wire.
///
/// Unlike [`c_client_request`], this one waits for a reply: `csp_ping` checks the echo byte
/// by byte, and the `csp_get_*` family demands exactly four big-endian bytes. `csp_read`
/// blocks, so the client runs on its own thread; finish with [`c_service_join`].
pub fn c_service_start(svc: CService, dst: u16) -> Vec<Vec<u8>> {
    let (kind, size, opts) = match svc {
        CService::Ping { size, opts } => (0, size, opts),
        CService::MemFree => (1, 0, 0),
        CService::BufFree => (2, 0, 0),
        CService::Uptime => (3, 0, 0),
    };
    // SAFETY: the shim owns the thread for the life of the exchange.
    let n = unsafe { shim_service_start(kind, dst, size as c_uint, opts) };
    assert!(n >= 0, "the C client could not start: {n}");
    captured_frames()
}

/// libcsp's own verdict: `(status, value)`.
///
/// `status` is elapsed milliseconds or `-1` for `csp_ping`, and `CSP_ERR_NONE` (0) or
/// `CSP_ERR_TIMEDOUT` (-3) for the rest; `value` is the number the `csp_get_*` family
/// decoded, zero for a ping.
pub fn c_service_join() -> (i32, u32) {
    let mut v = 0u32;
    // SAFETY: joins the thread started above; a no-op if none is running.
    let status = unsafe { shim_service_join(&mut v) };
    (status, v)
}

/// Begin a real `csp_cmp_clock` against `node` and return the request it put on the wire.
///
/// A `tv_sec` of zero is how libcsp asks to read the clock without setting it. `csp_read`
/// blocks, so the client runs on its own thread; finish with [`c_cmp_clock_join`].
pub fn c_cmp_clock_start(node: u16, tv_sec: u32, tv_nsec: u32) -> Vec<Vec<u8>> {
    // SAFETY: the shim owns the thread and the message for the life of the exchange.
    let n = unsafe { shim_cmp_clock_start(node, tv_sec, tv_nsec) };
    assert!(
        n >= 0,
        "the C client could not start a CMP clock request: {n}"
    );
    captured_frames()
}

/// libcsp's verdict and the timestamp it decoded: `Ok((tv_sec, tv_nsec))` or its error.
pub fn c_cmp_clock_join() -> Result<(u32, u32), i32> {
    let (mut s, mut ns) = (0u32, 0u32);
    // SAFETY: joins the thread started above; a no-op if none is running.
    let status = unsafe { shim_cmp_clock_join(&mut s, &mut ns) };
    if status != 0 {
        return Err(status);
    }
    Ok((s, ns))
}

/// What libcsp's `struct csp_cmp_route_set_v2_msg` carries back, host-order.
#[derive(Debug, PartialEq, Eq)]
pub struct CRouteSet {
    pub dest: u16,
    pub netmask: u16,
    pub via: u16,
    pub interface: String,
}

/// Begin a real `csp_cmp_route_set_v2` against `node` and return the request it put on the
/// wire. `csp_read` blocks, so the client runs on its own thread; finish with
/// [`c_cmp_route_set_v2_join`].
pub fn c_cmp_route_set_v2_start(
    node: u16,
    dest: u16,
    netmask: u16,
    via: u16,
    ifname: &str,
) -> Vec<Vec<u8>> {
    let name = std::ffi::CString::new(ifname).expect("no interior nul");
    // SAFETY: `name` outlives the call; the shim copies it before returning.
    let n = unsafe { shim_cmp_route_set_v2_start(node, dest, netmask, via, name.as_ptr().cast()) };
    assert!(
        n >= 0,
        "the C client could not start a CMP route_set request: {n}"
    );
    captured_frames()
}

/// Larger than `sizeof(struct csp_cmp_message)`, which is 210 -- the union's unpacked
/// members pad it past the 207 its fields sum to. The shim copies what fits.
const C_CMP_MESSAGE_LEN: usize = 256;

fn c_cmp_raw_join() -> Result<[u8; C_CMP_MESSAGE_LEN], i32> {
    let mut buf = [0u8; C_CMP_MESSAGE_LEN];
    // SAFETY: `buf` is exactly the struct's size; the shim bounds-checks against `maxlen`.
    let status = unsafe { shim_cmp_raw_join(buf.as_mut_ptr(), buf.len() as c_int) };
    if status != 0 {
        return Err(status);
    }
    Ok(buf)
}

/// libcsp's verdict on the port's ROUTE_SET_V2 reply and the fields it decoded.
pub fn c_cmp_route_set_v2_join() -> Result<CRouteSet, i32> {
    let b = c_cmp_raw_join()?;
    let name_end = b[8..8 + 11].iter().position(|&x| x == 0).unwrap_or(11);
    Ok(CRouteSet {
        dest: u16::from_be_bytes([b[2], b[3]]),
        via: u16::from_be_bytes([b[4], b[5]]),
        netmask: u16::from_be_bytes([b[6], b[7]]),
        interface: String::from_utf8_lossy(&b[8..8 + name_end]).into_owned(),
    })
}

/// Begin a real `csp_cmp_peek` (32-bit address) and return the request it put on the wire.
pub fn c_cmp_peek_start(node: u16, addr: u32, len: u8) -> Vec<Vec<u8>> {
    // SAFETY: the shim owns the thread and the message for the life of the exchange.
    let n = unsafe { shim_cmp_peek_start(node, addr, len) };
    assert!(n >= 0, "the C client could not start a CMP peek: {n}");
    captured_frames()
}

/// Begin a real `csp_cmp_poke` (32-bit address) and return the request it put on the wire.
pub fn c_cmp_poke_start(node: u16, addr: u32, data: &[u8]) -> Vec<Vec<u8>> {
    let len = u8::try_from(data.len()).expect("a poke is at most 200 bytes");
    // SAFETY: the shim copies `data` before returning.
    let n = unsafe { shim_cmp_poke_start(node, addr, data.as_ptr(), len) };
    assert!(n >= 0, "the C client could not start a CMP poke: {n}");
    captured_frames()
}

/// libcsp's verdict on a PEEK/POKE reply: the address bytes **as they sit in the struct**
/// (a C node hands them back host-order, the port big-endian -- see `node_cmp_peek_v2.rs`)
/// and the `len` data bytes.
pub fn c_cmp_peek_join() -> Result<([u8; 4], Vec<u8>), i32> {
    let b = c_cmp_raw_join()?;
    let len = b[6] as usize;
    Ok(([b[2], b[3], b[4], b[5]], b[7..7 + len].to_vec()))
}

/// Give the C node a second address it answers to. 0=INGRESS, 1=EGRESS, 2=ROUTED.
///
/// The alias list is global in libcsp and its entries must outlive the call, so the shim
/// owns them. Idempotent only in the sense that adding the same address twice adds two
/// entries — as it does in the C.
pub fn c_node_add_alias(addr: u16, iface: i32) -> bool {
    // SAFETY: the shim owns the static alias entries for the life of the process.
    unsafe { shim_node_add_alias(addr, iface) == 0 }
}

/// Whether libcsp considers `addr` one of this node's aliases.
pub fn c_node_is_alias(addr: u16) -> bool {
    // SAFETY: one list walk, no arguments beyond the address.
    unsafe { shim_node_is_alias(addr) != 0 }
}

/// Which member of `csp_services.c`'s client to drive.
#[derive(Debug, Clone, Copy)]
#[allow(missing_docs)]
pub enum CClient {
    Ping = 0,
    MemFree = 1,
    BufFree = 2,
    Uptime = 3,
    Ps = 4,
    PingNoReply = 5,
    Cmp = 6,
}

/// What one of libcsp's blocking service clients puts on the wire, with a zero timeout.
///
/// The reply-wait costs nothing at `timeout = 0` — `pthread_queue_dequeue` builds a deadline
/// of now — so the request is observable even though no reply will come. `size` is only read
/// for `Ping`.
pub fn c_client_request(kind: CClient, dst: u16, size: u32, opts: u8) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    // SAFETY: the shim owns the capture array and bounds-checks its indices. Callers hold `LOCK`.
    unsafe {
        if shim_client_request(kind as c_int, dst, size, opts) <= 0 {
            return frames;
        }
        for i in 0..shim_node_tx_count() {
            let mut buf = vec![0u8; 512];
            let n = shim_node_tx_get(i, buf.as_mut_ptr());
            if n > 0 {
                buf.truncate(n as usize);
                frames.push(buf);
            }
        }
    }
    frames
}

/// What libcsp's own `csp_reboot` / `csp_shutdown` put on the wire, framed.
///
/// These two are the only members of `csp_services.c` that do not block: with no reply
/// expected, `csp_transaction_persistent` returns straight after the send.
pub fn c_client_reboot(dst: u16, shutdown_instead: bool) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    // SAFETY: the shim owns the capture array and bounds-checks its indices. The reboot
    // hook in this build records rather than rebooting (see `build.rs`). Callers hold `LOCK`.
    unsafe {
        if shim_client_reboot(dst, i32::from(shutdown_instead)) <= 0 {
            return frames;
        }
        for i in 0..shim_node_tx_count() {
            let mut buf = vec![0u8; 512];
            let n = shim_node_tx_get(i, buf.as_mut_ptr());
            if n > 0 {
                buf.truncate(n as usize);
                frames.push(buf);
            }
        }
    }
    frames
}

/// Bring up a real `csp_if_can` interface on the C node, with a capturing driver.
pub fn c_can_init(address: u16, netmask: u16) -> bool {
    // SAFETY: idempotent; the shim owns the interface and its data block for the process.
    unsafe { shim_can_init(address, netmask) == 0 }
}

/// One CAN frame: the 29-bit identifier and up to 8 data bytes.
pub type CanFrame = (u32, Vec<u8>);

/// Have the C fragment a CSP packet into CAN frames, and return them in order.
///
/// This is `csp_can_tx` — the real one. Every CFP comparison before this expanded the
/// header's identifier macros inside `shim.c` and compared bit layouts; none of them ran a
/// line of `csp_if_can.c`.
pub fn c_can_send(dst: u16, dport: u8, sport: u8, body: &[u8]) -> Vec<CanFrame> {
    let mut out = Vec::new();
    // SAFETY: `body` is valid for the call and bounds-checked against a packet buffer on
    // the C side; the capture array is fixed-size. Callers hold `LOCK`.
    unsafe {
        shim_can_clear();
        if shim_can_send(dst, dport, sport, body.as_ptr(), body.len() as c_int) != 0 {
            return out;
        }
        for i in 0..shim_can_count() {
            let mut id: u32 = 0;
            let mut data = vec![0u8; 8];
            let n = shim_can_get(i, &mut id, data.as_mut_ptr());
            if n >= 0 {
                data.truncate(n as usize);
                out.push((id, data));
            }
        }
    }
    out
}

/// Everything the C's CAN interface has transmitted since the last drain, in order.
///
/// Router-originated frames -- an RDP `SYN|ACK`, an acknowledgement, a service reply --
/// leave through `csp_can2_tx` like anything else routed to a CAN peer, and land in the
/// same capture `c_can_send` reads.
pub fn c_can_drain() -> Vec<CanFrame> {
    let mut out = Vec::new();
    // SAFETY: the capture array is fixed-size and bounds-checked. Callers hold `LOCK`.
    unsafe {
        for i in 0..shim_can_count() {
            let mut id: u32 = 0;
            let mut data = vec![0u8; 8];
            let n = shim_can_get(i, &mut id, data.as_mut_ptr());
            if n >= 0 {
                data.truncate(n as usize);
                out.push((id, data));
            }
        }
        shim_can_clear();
    }
    out
}

/// Turn the C router's crank until its queue is empty. `c_can_rx` only queues.
pub fn c_node_pump() -> i32 {
    // SAFETY: runs libcsp's router on its own queue. Callers hold `LOCK`.
    unsafe { shim_node_pump() }
}

/// Feed one CAN frame to the C's `csp_can_rx`. Returns libcsp's own return code.
///
/// Whether a packet came out is answered by pumping the router and reading the bound port,
/// not by looking at a queue.
pub fn c_can_rx(frame: &CanFrame) -> i32 {
    // SAFETY: the data slice is valid for the call and its length is passed as the DLC.
    unsafe { shim_can_rx(frame.0, frame.1.as_ptr(), frame.1.len() as u8) }
}

/// Accept and close every connection waiting on `port`, draining each; return the count.
///
/// What matters when the connection table runs out is not how many slots exist but how many
/// peers the application can still serve — and whether refusing the rest costs anything.
pub fn c_node_accept_count(port: u8) -> i32 {
    // SAFETY: bounds-checked on the C side; frees every packet it reads. Callers hold `LOCK`.
    unsafe { shim_node_accept_count(port) }
}

/// Set the C node's clock, in milliseconds.
///
/// `arch/posix/csp_time.c` is left out of this build and the shim supplies `csp_get_ms`, so
/// libcsp's own timers are reachable by assignment rather than by sleeping. Without it,
/// anything gated on an RDP timer or a connection timeout could not be asked at all.
pub fn c_clock_set(ms: u32) {
    // SAFETY: writes one `static uint32_t` the C reads. Callers hold `LOCK`.
    unsafe { shim_clock_set(ms) }
}

/// Move the C node's clock forward.
pub fn c_clock_advance(ms: u32) {
    // SAFETY: as `c_clock_set`.
    unsafe { shim_clock_advance(ms) }
}

/// Run libcsp's periodic connection maintenance: RDP timers and idle expiry.
pub fn c_node_check_timeouts() {
    // SAFETY: walks libcsp's connection array and pumps its router. Callers hold `LOCK`.
    unsafe { shim_node_check_timeouts() }
}

/// Turn the C node's promiscuous tap on.
pub fn c_node_promisc_enable() -> i32 {
    // SAFETY: allocates libcsp's tap queue once. Callers hold `LOCK`.
    unsafe { shim_node_promisc_enable() }
}

/// Drain the C node's promiscuous tap: `(destination, payload)` per tapped packet.
pub fn c_node_promisc_drain() -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::new();
    // SAFETY: the buffer is larger than any frame the C can emit; the shim frees each
    // packet it hands back. Callers hold `LOCK`.
    unsafe {
        loop {
            let mut buf = vec![0u8; 512];
            let mut dst: u16 = 0;
            let n = shim_node_promisc_read(buf.as_mut_ptr(), &mut dst);
            if n < 0 {
                break;
            }
            buf.truncate(n as usize);
            out.push((dst, buf));
        }
    }
    out
}

/// Set the C node's deduplication mode (`csp_conf.dedup`).
///
/// 0 off, 1 forwarded only, 2 incoming only, 3 both — the `csp_dedup_types` enum. Both
/// stacks default to off, so a differential test has to switch it on to compare anything.
pub fn c_node_set_dedup(mode: i32) {
    // SAFETY: writes one `uint8_t` in `csp_conf`, read per packet. Callers hold `LOCK`.
    unsafe { shim_node_set_dedup(mode) }
}

/// Close a connection the C node is holding, and hand back the frames that produced.
///
/// On an RDP connection `csp_conn_close` returns early while the close handshake is
/// outstanding (`csp_conn.c:230`), *before* flushing the receive queue and the
/// retransmission queue — so buffers stay held until the peer answers. Feed these to the
/// peer and pump its reply back to let the close finish.
pub fn c_node_release(port: u8) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    // SAFETY: bounds-checked on the C side; the buffer is larger than any frame the C can
    // emit. Callers hold `LOCK`.
    unsafe {
        shim_node_clear_tx();
        shim_node_release(port);
        for i in 0..shim_node_tx_count() {
            let mut buf = vec![0u8; 512];
            let n = shim_node_tx_get(i, buf.as_mut_ptr());
            if n > 0 {
                buf.truncate(n as usize);
                frames.push(buf);
            }
        }
    }
    frames
}

/// Feed `frame` to the C node, run its router to quiescence, and report only what an
/// application or a peer could see.
/// Pump the router and read `watch_ports`, without injecting anything first.
///
/// For paths that put a packet on the queue themselves — `csp_can_rx` reassembles and calls
/// `csp_qfifo_write` directly, so there is no frame to inject.
pub fn c_node_drain(watch_ports: &[u8]) -> NodeOutcome {
    let mut out = NodeOutcome::default();
    // SAFETY: same buffers and bounds as `c_node_exchange`. Callers hold `LOCK`.
    unsafe {
        shim_node_pump();
        for &port in watch_ports {
            loop {
                let (mut src, mut dst) = (0u16, 0u16);
                let (mut dport, mut sport) = (0u8, 0u8);
                let mut payload = vec![0u8; 512];
                let mut n: c_int = 0;
                let got = shim_node_recv(
                    port,
                    &mut src,
                    &mut dst,
                    &mut dport,
                    &mut sport,
                    payload.as_mut_ptr(),
                    &mut n,
                );
                if got == 0 {
                    break;
                }
                payload.truncate(n as usize);
                out.delivered.push(Delivered {
                    port,
                    src,
                    dst,
                    dport,
                    sport,
                    payload,
                });
            }
        }
    }
    out
}

pub fn c_node_exchange(frame: &[u8], watch_ports: &[u8]) -> NodeOutcome {
    let mut out = NodeOutcome::default();
    // SAFETY: every buffer below is sized for the largest frame the C can emit, and the
    // shim bounds-checks its own indices. Callers hold `LOCK`.
    unsafe {
        shim_node_clear_tx();
        shim_node_inject(frame.as_ptr(), frame.len() as u32);
        shim_node_pump();

        for &port in watch_ports {
            loop {
                let (mut src, mut dst) = (0u16, 0u16);
                let (mut dport, mut sport) = (0u8, 0u8);
                let mut payload = vec![0u8; 512];
                let mut n: c_int = 0;
                let got = shim_node_recv(
                    port,
                    &mut src,
                    &mut dst,
                    &mut dport,
                    &mut sport,
                    payload.as_mut_ptr(),
                    &mut n,
                );
                if got == 0 {
                    break;
                }
                payload.truncate(n as usize);
                out.delivered.push(Delivered {
                    port,
                    src,
                    dst,
                    dport,
                    sport,
                    payload,
                });
            }
        }

        let n = shim_node_tx_count();
        for i in 0..n {
            let mut buf = vec![0u8; 512];
            let len = shim_node_tx_get(i, buf.as_mut_ptr());
            if len >= 0 {
                buf.truncate(len as usize);
                out.tx.push(buf);
                let mut name = [0u8; 16];
                let mut via = 0u16;
                let nl = shim_node_tx_iface(i, name.as_mut_ptr(), &mut via);
                let nl = if nl > 0 { nl as usize } else { 0 };
                out.tx_via
                    .push((String::from_utf8_lossy(&name[..nl]).into_owned(), via));
            }
        }
    }
    out
}

/// Buffers free in the C pool — for asserting a node leaked nothing.
pub fn c_node_buf_free() -> i32 {
    // SAFETY: reads one counter.
    unsafe { shim_node_buf_free() }
}

/// `csp_socket_close` on the C node's socket for `port`.
pub fn c_node_unbind(port: u8) -> i32 {
    // SAFETY: bounded by SHIM_PORTS on the C side. Callers hold `LOCK`.
    unsafe { shim_node_unbind(port) }
}

/// Accept and read everything waiting on the C's `port`, then close: packets read.
pub fn c_node_read_count(port: u8) -> i32 {
    // SAFETY: bounded by SHIM_PORTS on the C side; frees what it reads. Callers hold `LOCK`.
    unsafe { shim_node_read_count(port) }
}

/// Read everything waiting on the connection the C holds for `port` (accepting one if
/// none is held) without closing it; release with [`c_node_release`].
pub fn c_node_read_held(port: u8) -> i32 {
    // SAFETY: bounded by SHIM_PORTS on the C side; frees what it reads. Callers hold `LOCK`.
    unsafe { shim_node_read_held(port) }
}

/// `csp_hmac_set_key` on the C node: one process-wide key, SHA-1-derived as the C does.
pub fn c_hmac_set_key(material: &[u8]) -> i32 {
    // SAFETY: the slice is valid for the call; the C copies the derived key. Callers hold `LOCK`.
    unsafe { shim_hmac_set_key(material.as_ptr(), material.len() as u32) }
}

/// `csp_conn_is_active` on the connection [`c_node_send_on`] holds for `port`: `Some(true)`
/// active, `Some(false)` not, `None` if nothing is held.
pub fn c_node_held_active(port: u8) -> Option<bool> {
    // SAFETY: bounded by SHIM_PORTS on the C side. Callers hold `LOCK`.
    match unsafe { shim_node_held_active(port) } {
        1 => Some(true),
        0 => Some(false),
        _ => None,
    }
}

/// Connections the C node holds open, counted through `csp_conn_get_array`.
pub fn c_node_open_conns() -> i32 {
    // SAFETY: reads libcsp's connection array. Callers hold `LOCK`.
    unsafe { shim_node_open_conns() }
}

/// Take `n` buffers out of the C's pool and keep them, so `csp_buffer_remaining()` drops
/// without any traffic. Returns how many are held in total. Give them back with
/// [`c_buffers_release`].
pub fn c_buffers_hold(n: i32) -> i32 {
    // SAFETY: bounded by SHIM_HOLD_MAX on the C side. Callers hold `LOCK`.
    unsafe { shim_buffers_hold(n) }
}

/// Return every buffer [`c_buffers_hold`] took.
pub fn c_buffers_release() {
    // SAFETY: frees only what the shim itself allocated. Callers hold `LOCK`.
    unsafe { shim_buffers_release() }
}

/// What the C's KISS decoder made of a byte stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KissResult {
    /// Complete frames produced.
    pub frames: i32,
    /// The last complete frame's **payload**, if any — the C's KISS layer strips the CSP
    /// header before handing the packet on.
    pub last: Option<Vec<u8>>,
    /// The last frame's header, re-encoded from the id the C parsed.
    pub id: Option<Vec<u8>>,
    /// `iface->rx_error` after the feed.
    pub rx_errors: u32,
    /// `iface->drop` — a frame started with no buffer available.
    pub drops: u32,
    /// `iface->frame` — a completed frame the CSP header parser rejected.
    pub frame_errors: u32,
}

/// Feed bytes to the C's KISS decoder, from a clean state.
///
/// Drives the real `csp_kiss_rx` state machine — the shim only replaces `csp_qfifo_write`
/// so a finished frame is captured instead of routed.
pub fn c_kiss_decode(bytes: &[u8]) -> KissResult {
    let mut out = vec![0u8; 4096];
    let mut out_len: c_int = -1;
    // SAFETY: `out` is far larger than any frame the decoder can emit (it is bounded by
    // the C buffer size), and `out_len` is a live slot. Callers hold `LOCK`, since the
    // decoder state and the buffer pool are C globals.
    let frames = unsafe {
        shim_kiss_reset();
        shim_kiss_feed(
            bytes.as_ptr(),
            bytes.len() as u32,
            out.as_mut_ptr(),
            &mut out_len,
        )
    };
    // SAFETY: reads one u32 global.
    let (rx_errors, drops, frame_errors) =
        // SAFETY: three u32 reads from the shim's static interface struct.
        unsafe { (shim_kiss_rx_errors(), shim_kiss_drops(), shim_kiss_frame_errors()) };
    let mut idbuf = [0u8; 8];
    // SAFETY: `idbuf` holds the largest header either version produces (6 bytes).
    let id_len = unsafe { shim_kiss_last_id(idbuf.as_mut_ptr()) };
    KissResult {
        frames,
        last: (out_len >= 0).then(|| out[..out_len as usize].to_vec()),
        id: (id_len > 0).then(|| idbuf[..id_len as usize].to_vec()),
        rx_errors,
        drops,
        frame_errors,
    }
}

/// Register an interface with the C, so route tables have something to name.
///
/// Idempotent: registering a name that is already there is a no-op, because
/// `csp_iflist_add` silently keeps the first (deviation 20).
pub fn c_add_iface(name: &str, addr: u16, netmask: u16) {
    let c = std::ffi::CString::new(name).expect("interface names have no NULs");
    // SAFETY: `c` outlives the call; the shim copies the name into its own static
    // storage, which is what `csp_iflist_add` requires since it keeps the pointer.
    unsafe {
        if shim_iface_registered(c.as_ptr() as *const u8) == 0 {
            shim_add_iface(c.as_ptr() as *const u8, addr, netmask);
        }
    }
}

/// The seven fields of a CSP v2 CAN identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct Cfp2Fields {
    pub pri: u16,
    pub dst: u16,
    pub sender: u16,
    pub sc: u16,
    pub fc: u16,
    pub begin: u16,
    pub end: u16,
}

/// Pack a CSP v2 CAN identifier with the C.
pub fn c_cfp2_make(f: Cfp2Fields) -> u32 {
    // SAFETY: pure arithmetic on the C side, no pointers.
    unsafe { shim_cfp2_make(f.pri, f.dst, f.sender, f.sc, f.fc, f.begin, f.end) }
}

/// Unpack a CSP v2 CAN identifier with the C.
pub fn c_cfp2_parse(id: u32) -> Cfp2Fields {
    let (mut pri, mut dst, mut sender) = (0u16, 0u16, 0u16);
    let (mut sc, mut fc, mut begin, mut end) = (0u16, 0u16, 0u16, 0u16);
    // SAFETY: seven live stack slots, all written by the shim.
    unsafe {
        shim_cfp2_parse(
            id,
            &mut pri,
            &mut dst,
            &mut sender,
            &mut sc,
            &mut fc,
            &mut begin,
            &mut end,
        )
    }
    Cfp2Fields {
        pri,
        dst,
        sender,
        sc,
        fc,
        begin,
        end,
    }
}

/// One route as the C reports it: interface name and via address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CRoute {
    /// Interface name.
    pub iface: String,
    /// Next hop, or `0xFFFF` for none.
    pub via: u16,
}

/// Parse a route table with the C, replacing whatever was loaded.
///
/// Returns the C's status: 0 on success, negative on failure, or `None` if the text has an
/// interior NUL and so cannot be handed to C at all -- rejected rather than truncated.
pub fn c_rtable_load(text: &str) -> Option<c_int> {
    let c = std::ffi::CString::new(text).ok()?;
    // SAFETY: `c` is NUL-terminated and outlives the call. Callers hold `LOCK`, since the
    // routing table is a C global.
    Some(unsafe { shim_rtable_load(c.as_ptr() as *const u8) })
}

/// What `csp_rtable_save` writes for the table `c_rtable_load` last installed.
///
/// The text a ground tool reads back off a node. `None` if libcsp reported an error.
pub fn c_rtable_save() -> Option<String> {
    let mut buf = vec![0u8; 512];
    // SAFETY: the shim writes at most `maxlen` bytes including the terminator, and reports
    // the length it wrote. Callers hold `LOCK`, since the routing table is a C global.
    let n = unsafe { shim_rtable_save(buf.as_mut_ptr(), buf.len() as c_int) };
    if n < 0 {
        return None;
    }
    buf.truncate(n as usize);
    String::from_utf8(buf).ok()
}

/// Validate a route table with the C without installing it.
pub fn c_rtable_check(text: &str) -> Option<c_int> {
    let c = std::ffi::CString::new(text).ok()?;
    // SAFETY: as above.
    Some(unsafe { shim_rtable_check(c.as_ptr() as *const u8) })
}

/// Look an address up in the table the C most recently loaded.
pub fn c_rtable_lookup(addr: u16) -> Option<CRoute> {
    let mut name = [0u8; 16];
    let mut via = 0u16;
    // SAFETY: `name` is the 16 bytes the shim documents, `via` is a live slot.
    let found = unsafe { shim_rtable_lookup(addr, name.as_mut_ptr(), &mut via) };
    if found == 0 {
        return None;
    }
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    Some(CRoute {
        iface: String::from_utf8_lossy(&name[..end]).into_owned(),
        via,
    })
}

/// Select the wire version the C side uses.
///
/// The C dispatches on a global. Not thread-safe, hence [`LOCK`].
pub fn c_set_version(v: csp_core::Version) {
    let n = match v {
        csp_core::Version::V1 => 1,
        csp_core::Version::V2 => 2,
    };
    // SAFETY: writes one `uint8_t` global in the C library. Callers hold `LOCK`.
    unsafe { shim_set_version(n) }
}

/// Serialises access to the C library's globals.
///
/// `csp_conf.version` is process-wide state, so differential tests that select a version
/// cannot run concurrently. This is exactly the property the port removes.
pub static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Take [`LOCK`], recovering if a previous test poisoned it.
///
/// `LOCK.lock().unwrap()` turns one genuine failure into a cascade: the panicking test
/// poisons the mutex and every test after it fails with `PoisonError` instead of its own
/// result. That happened here — a route-table test failed and `version_parameters_agree`
/// reported a poison error, which sent the investigation at the wrong thing first.
///
/// Recovering is the right trade for this harness. The C state a panicking test leaves
/// behind is re-established by the next test's `setup`/`c_node_init`, whereas a cascade
/// hides which test actually broke.
pub fn lock() -> std::sync::MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// The header `csp_id_prepend_fixup_cspv1` writes — the ZeroMQ hub's little-endian v1.
///
/// Identical to [`c_id_encode`] at v2 and byte-reversed at v1. Its only caller in libcsp is
/// `csp_if_zmqhub.c`, which is out of scope; this exists so that "not the same codec" is
/// measured rather than read off the `#if`.
pub fn c_id_encode_fixup(id: &csp_core::Id) -> Vec<u8> {
    let mut buf = [0u8; 16];
    // SAFETY: `buf` is larger than any header the C can write (max 6 bytes).
    let n = unsafe {
        shim_id_encode_fixup(
            id.pri,
            id.flags,
            id.src,
            id.dst,
            id.dport,
            id.sport,
            buf.as_mut_ptr(),
        )
    };
    buf[..n as usize].to_vec()
}

/// Encode a header with the C, returning the header bytes.
pub fn c_id_encode(id: &csp_core::Id) -> Vec<u8> {
    let mut buf = [0u8; 16];
    // SAFETY: `buf` is larger than any header the C can write (max 6 bytes).
    let n = unsafe {
        shim_id_encode(
            id.pri,
            id.flags,
            id.src,
            id.dst,
            id.dport,
            id.sport,
            buf.as_mut_ptr(),
        )
    };
    assert!(n > 0 && (n as usize) <= buf.len());
    buf[..n as usize].to_vec()
}

/// Decode a header with the C.
pub fn c_id_decode(data: &[u8]) -> csp_core::Id {
    assert!(data.len() >= c_header_size());
    let (mut pri, mut flags, mut dport, mut sport) = (0u8, 0u8, 0u8, 0u8);
    let (mut src, mut dst) = (0u16, 0u16);
    // SAFETY: `data` is at least the header size, checked above; the out pointers are
    // all to live locals.
    unsafe {
        shim_id_decode(
            data.as_ptr(),
            &mut pri,
            &mut flags,
            &mut src,
            &mut dst,
            &mut dport,
            &mut sport,
        )
    }
    csp_core::Id {
        pri,
        flags,
        src,
        dst,
        dport,
        sport,
    }
}

/// The C's header size for the selected version.
pub fn c_header_size() -> usize {
    // SAFETY: reads a global.
    unsafe { shim_header_size() as usize }
}

/// The C's address width for the selected version.
pub fn c_host_bits() -> u32 {
    // SAFETY: reads a global.
    unsafe { shim_host_bits() }
}

/// The C's maximum node id.
pub fn c_max_nodeid() -> u32 {
    // SAFETY: reads a global.
    unsafe { shim_max_nodeid() }
}

/// The C's maximum port.
pub fn c_max_port() -> u32 {
    // SAFETY: reads a global.
    unsafe { shim_max_port() }
}

/// The C's broadcast test.
pub fn c_is_broadcast(addr: u16, iface_addr: u16, iface_netmask: u16) -> bool {
    // SAFETY: builds a `csp_iface_t` on the C stack from scalars.
    unsafe { shim_is_broadcast(addr, iface_addr, iface_netmask) != 0 }
}

/// The C's CRC-32C.
pub fn c_crc32(data: &[u8]) -> u32 {
    // SAFETY: pointer and length describe `data`.
    unsafe { shim_crc32(data.as_ptr(), data.len() as u32) }
}

/// The C's SHA-1.
pub fn c_sha1(data: &[u8]) -> [u8; 20] {
    let mut out = [0u8; 20];
    // SAFETY: `out` is exactly the digest size the C writes.
    unsafe { shim_sha1(data.as_ptr(), data.len() as u32, out.as_mut_ptr()) }
    out
}

/// The C's HMAC-SHA1. `None` when the C refused the input.
///
/// The output buffer is 20 bytes, not `CSP_HMAC_LENGTH` — see the shim.
pub fn c_hmac(key: &[u8], data: &[u8]) -> Option<[u8; 20]> {
    let mut out = [0u8; 20];
    // SAFETY: `out` is 20 bytes, which is what csp_hmac_memory writes regardless of
    // CSP_HMAC_LENGTH. Passing a 4-byte buffer here would overflow by 16.
    let rc = unsafe {
        shim_hmac(
            key.as_ptr(),
            key.len() as u32,
            data.as_ptr(),
            data.len() as u32,
            out.as_mut_ptr(),
        )
    };
    if rc == 0 {
        Some(out)
    } else {
        None
    }
}

/// Build a CFP 1 CAN identifier with the C's macros.
pub fn c_cfp1_make(src: u16, dst: u16, kind: u32, remain: u32, ident: u16) -> u32 {
    // SAFETY: the shim only evaluates header macros on scalars.
    unsafe { shim_cfp1_make(src, dst, kind, remain, ident) }
}

/// Take a CFP 1 identifier apart with the C's macros.
pub fn c_cfp1_parse(id: u32) -> (u16, u16, u32, u32, u16) {
    let (mut src, mut dst, mut ident) = (0u16, 0u16, 0u16);
    let (mut kind, mut remain) = (0u32, 0u32);
    // SAFETY: all out pointers are to live locals.
    unsafe { shim_cfp1_parse(id, &mut src, &mut dst, &mut kind, &mut remain, &mut ident) }
    (src, dst, kind, remain, ident)
}

/// Deterministic xorshift, so a failing run can be reproduced from its seed.
pub struct Rng(pub u64);

impl Rng {
    /// Next 64 bits.
    #[allow(clippy::should_implement_trait)] // `next` is the conventional name for an RNG step
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    /// Next value below `n`.
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    /// Fill `buf` with random bytes.
    pub fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = self.next() as u8;
        }
    }
}
