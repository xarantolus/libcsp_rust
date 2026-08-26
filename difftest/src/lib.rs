//! Differential testing against the C libcsp.
//!
//! Links the real C library and exposes the same entry points as [`csp_core`], so a test
//! can run both on identical bytes and compare. **Dev-only** — this crate is never a
//! dependency of `csp-core` or `csp`, which is the whole point of the port.
//!
//! The 922 golden vectors check the inputs someone thought of. This checks the ones nobody
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

use core::ffi::c_int;

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
    fn shim_node_buf_free() -> c_int;
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

/// Close a connection the C node is holding, which resets the peer.
pub fn c_node_release(port: u8) {
    // SAFETY: bounds-checked on the C side; callers hold `LOCK`.
    unsafe { shim_node_release(port) }
}

/// Feed `frame` to the C node, run its router to quiescence, and report only what an
/// application or a peer could see.
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
