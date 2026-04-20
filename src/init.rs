/*
Cubesat Space Protocol - A small network-layer protocol designed for Cubesats
Copyright (C) 2012 GomSpace ApS (http://www.gomspace.com)
Copyright (C) 2012 AAUSAT3 Project (http://aausat3.space.aau.dk)

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.
*/

//! Safe initialisation builder for CSP.
//!
//! Call [`CspConfig::new()`], chain builder methods, then call
//! [`CspConfig::init()`] to initialise the CSP stack and receive a
//! [`CspNode`] token that keeps the CSP runtime alive.

extern crate alloc;

use alloc::ffi::CString;
use alloc::sync::Arc;
use core::ffi::c_char;
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};

use crate::error::csp_result;
use crate::sys;
use crate::{Connection, Packet, Priority, Result};

static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Cached node address. `csp_conf_t` does not store it in v2.x; each interface
/// owns its own address via `csp_iface_t::addr`. This mirror exists only so
/// [`CspNode::address`] remains cheap and does not require walking the iflist.
static NODE_ADDRESS: AtomicU16 = AtomicU16::new(0);

/// CSP deduplication mode (`csp_dedup_types`).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedupMode {
    /// Deduplication disabled.
    Off = sys::csp_dedup_types_CSP_DEDUP_OFF as u8,
    /// Deduplicate packets being forwarded.
    Forward = sys::csp_dedup_types_CSP_DEDUP_FWD as u8,
    /// Deduplicate incoming packets.
    Incoming = sys::csp_dedup_types_CSP_DEDUP_INCOMING as u8,
    /// Deduplicate both incoming and forwarded packets.
    All = sys::csp_dedup_types_CSP_DEDUP_ALL as u8,
}

/// Builder for the CSP runtime configuration.
///
/// Mirrors `csp_conf_t` from `csp.h`. Buffer pool size, connection count and
/// similar limits are compile-time constants set via build environment
/// variables (`LIBCSP_BUFFER_SIZE`, `LIBCSP_BUFFER_COUNT`, …). Use
/// [`crate::consts`] to read them back at runtime.
pub struct CspConfig {
    version: u8,
    address: u16,
    hostname: CString,
    model: CString,
    revision: CString,
    conn_dfl_so: u32,
    dedup: u8,
}

impl Default for CspConfig {
    fn default() -> Self {
        CspConfig {
            // v1 is the wire format expected by existing flight hardware.
            version: 1,
            address: 1,
            hostname: CString::new("hostname").unwrap(),
            model: CString::new("model").unwrap(),
            revision: CString::new("1.0").unwrap(),
            conn_dfl_so: 0,
            dedup: sys::csp_dedup_types_CSP_DEDUP_OFF as u8,
        }
    }
}

impl CspConfig {
    /// Create a new `CspConfig` with sane defaults (wire version 1, address 1).
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the CSP wire-format version (1 or 2).
    ///
    /// Version 1 uses a 4-byte header with 5-bit addresses (0–31). Version 2
    /// uses a 6-byte header with 14-bit addresses. Both ends of a link must
    /// agree. The default is 1 for compatibility with legacy devices.
    pub fn version(mut self, v: u8) -> Self {
        debug_assert!(v == 1 || v == 2, "version must be 1 or 2");
        self.version = v;
        self
    }

    /// Set this node's CSP address.
    ///
    /// Version 1 addresses are 0–31; version 2 addresses are 0–16383. The
    /// address is written into the loopback interface on [`init`](Self::init)
    /// so the node can receive traffic addressed to itself.
    pub fn address(mut self, addr: u16) -> Self {
        self.address = addr;
        self
    }

    /// Set the hostname string returned by the `CSP_CMP_IDENT` request.
    ///
    /// # Panics
    /// Panics if `name` contains a null byte.
    pub fn hostname(mut self, name: &str) -> Self {
        self.hostname = CString::new(name).expect("hostname must not contain null bytes");
        self
    }

    /// Set the model string returned by the `CSP_CMP_IDENT` request.
    ///
    /// # Panics
    /// Panics if `model` contains a null byte.
    pub fn model(mut self, model: &str) -> Self {
        self.model = CString::new(model).expect("model must not contain null bytes");
        self
    }

    /// Set the revision string returned by the `CSP_CMP_IDENT` request.
    ///
    /// # Panics
    /// Panics if `rev` contains a null byte.
    pub fn revision(mut self, rev: &str) -> Self {
        self.revision = CString::new(rev).expect("revision must not contain null bytes");
        self
    }

    /// Configure packet deduplication.
    pub fn dedup(mut self, mode: DedupMode) -> Self {
        self.dedup = mode as u8;
        self
    }

    /// Set the default connection options ORed onto every new connection.
    pub fn default_socket_opts(mut self, opts: u32) -> Self {
        self.conn_dfl_so = opts;
        self
    }

    /// Initialise the CSP stack.
    ///
    /// Writes the configured values into the `csp_conf` global and calls
    /// `csp_init()`. Returns a [`CspNode`] that keeps the `CString`s alive.
    ///
    /// # Errors
    /// Returns [`CspError::AlreadyInitialized`] if a `CspNode` already exists.
    ///
    /// [`CspError::AlreadyInitialized`]: crate::CspError::AlreadyInitialized
    pub fn init(self) -> Result<CspNode> {
        if INITIALIZED.swap(true, Ordering::SeqCst) {
            return Err(crate::CspError::AlreadyInitialized);
        }

        // Safety: `self.{hostname,model,revision}` outlive the runtime because
        // they are moved into `CspNodeInner` below and freed only when the last
        // `CspNode` clone is dropped.
        unsafe {
            sys::csp_conf.version = self.version;
            sys::csp_conf.hostname = self.hostname.as_ptr() as *const c_char;
            sys::csp_conf.model = self.model.as_ptr() as *const c_char;
            sys::csp_conf.revision = self.revision.as_ptr() as *const c_char;
            sys::csp_conf.conn_dfl_so = self.conn_dfl_so;
            sys::csp_conf.dedup = self.dedup;

            sys::csp_init();

            // Register a self-addressed pseudo-interface plus a
            // host-specific route for our own address. libcsp's built-in
            // `LOOP` interface keeps `addr=0`, so packets that csp_connect
            // emits with `src=0` never get their source filled in when the
            // destination is our own address — replies would flow to 0
            // instead of back to us. Routing through SELF_IFACE makes
            // `csp_send_direct` apply its addr as the outgoing source.
            //
            // `netmask=0` keeps SELF out of the subnet-match path; the
            // routing table is what directs self-traffic here.
            SELF_IFACE.addr = self.address;
            SELF_IFACE.netmask = 0;
            SELF_IFACE.name = SELF_IFACE_NAME.as_ptr() as *const c_char;
            SELF_IFACE.nexthop = Some(self_iface_tx);
            csp_iflist_add(&raw mut SELF_IFACE);

            // Zero the built-in loopback's netmask so subnet lookup never
            // picks it up — the rtable is the only delivery path now.
            let lo = sys::csp_iflist_get_by_name(b"LOOP\0".as_ptr() as *const c_char);
            if !lo.is_null() {
                (*lo).netmask = 0;
            }

            // Host-specific route for our own address. `-1` tells
            // `csp_rtable_set` to use the full host-bit width as the mask,
            // giving us an exact-match entry.
            sys::csp_rtable_set(
                self.address,
                -1,
                &raw mut SELF_IFACE,
                sys::CSP_NO_VIA_ADDRESS as u16,
            );
        }

        NODE_ADDRESS.store(self.address, Ordering::SeqCst);

        Ok(CspNode {
            _inner: Arc::new(CspNodeInner { _config: self }),
        })
    }
}

// ── Self-addressed loopback shim ─────────────────────────────────────────────

/// Static storage for the self-addressed interface added by [`CspConfig::init`].
///
/// Kept as a `static mut` because libcsp holds a pointer to it via the
/// interface list and expects the storage to live for the full runtime.
static mut SELF_IFACE: sys::csp_iface_t = sys::csp_iface_t {
    addr: 0,
    netmask: 0,
    name: core::ptr::null(),
    interface_data: core::ptr::null_mut(),
    driver_data: core::ptr::null_mut(),
    nexthop: None,
    is_default: 0,
    tx: 0,
    rx: 0,
    tx_error: 0,
    rx_error: 0,
    drop: 0,
    autherr: 0,
    frame: 0,
    txbytes: 0,
    rxbytes: 0,
    irq: 0,
    next: core::ptr::null_mut(),
};

static SELF_IFACE_NAME: &[u8] = b"SELF\0";

/// Nexthop for the self interface: forward the packet straight into the
/// router via `csp_qfifo_write`, mirroring libcsp's built-in loopback.
unsafe extern "C" fn self_iface_tx(
    _iface: *mut sys::csp_iface_t,
    _via: u16,
    packet: *mut sys::csp_packet_t,
    _from_me: core::ffi::c_int,
) -> core::ffi::c_int {
    sys::csp_qfifo_write(packet, &raw mut SELF_IFACE, core::ptr::null_mut());
    sys::CSP_ERR_NONE as core::ffi::c_int
}

// `csp_iflist_add` is declared in the public headers but its prototype is
// re-exported here for clarity.
use crate::sys::csp_iflist_add;

// ─────────────────────────────────────────────────────────────────────────────

/// Token representing an initialised CSP runtime.
///
/// Returned by [`CspConfig::init()`]. Cloneable; the CSP stack lives as long
/// as any clone is held.
///
/// ## Single Node Limitation
///
/// Due to global state in libcsp, only **one** `CspNode` can exist at a time
/// in a process. A second [`CspConfig::init()`] call returns
/// [`CspError::AlreadyInitialized`].
///
/// [`CspError::AlreadyInitialized`]: crate::CspError::AlreadyInitialized
#[derive(Clone)]
pub struct CspNode {
    _inner: Arc<CspNodeInner>,
}

struct CspNodeInner {
    _config: CspConfig,
}

impl Drop for CspNodeInner {
    fn drop(&mut self) {
        INITIALIZED.store(false, Ordering::SeqCst);
    }
}

impl CspNode {
    /// Return the CSP address of this node.
    pub fn address(&self) -> u16 {
        NODE_ADDRESS.load(Ordering::SeqCst)
    }

    // ── Routing ───────────────────────────────────────────────────────────

    /// Process one routing iteration.
    ///
    /// Call in a loop (or spawn a thread that does so) to dispatch incoming
    /// packets to their destinations. In v2.x libcsp no longer spawns a
    /// router thread of its own — applications drive the router themselves.
    pub fn route_work(&self) -> Result<()> {
        // Safety: libcsp is initialised.
        csp_result(unsafe { sys::csp_route_work() })
    }

    /// Spawn a POSIX thread that calls [`route_work`] in a loop.
    ///
    /// Convenience helper for hosted builds. On `external-arch` targets this
    /// returns `Err(CspError::NotSupported)` — pump [`route_work`] from your
    /// own scheduler instead.
    ///
    /// [`route_work`]: CspNode::route_work
    #[cfg(all(feature = "std", any(target_os = "linux", target_os = "macos")))]
    pub fn route_start_task(&self, _stack_size: u32, _priority: u32) -> Result<()> {
        let node = self.clone();
        std::thread::Builder::new()
            .name("csp-router".into())
            .spawn(move || loop {
                // Ignore per-iteration errors so transient queue timeouts
                // don't kill the router thread.
                let _ = node.route_work();
            })
            .map(|_| ())
            .map_err(|_| crate::CspError::DriverError)
    }

    #[cfg(not(all(feature = "std", any(target_os = "linux", target_os = "macos"))))]
    pub fn route_start_task(&self, _stack_size: u32, _priority: u32) -> Result<()> {
        Err(crate::CspError::NotSupported)
    }

    // ── Client connections ─────────────────────────────────────────────────

    /// Establish an outgoing connection to `dst:dst_port`.
    ///
    /// Returns `None` if no connection slots are free or the RDP handshake
    /// times out.
    pub fn connect(
        &self,
        prio: Priority,
        dst: u16,
        dst_port: u8,
        timeout: u32,
        opts: u32,
    ) -> Option<Connection> {
        let prio_u8 = prio as u8;
        debug_assert!(prio_u8 <= 3, "Priority must be 0-3, got {}", prio_u8);
        let ptr = unsafe { sys::csp_connect(prio_u8, dst, dst_port, timeout, opts) };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { Connection::from_raw(ptr) })
        }
    }

    // ── Connectionless send ────────────────────────────────────────────────

    /// Send a packet connectionlessly to `dst:dst_port`.
    ///
    /// Bypasses the connection table entirely. The packet is always consumed
    /// — libcsp frees the buffer regardless of delivery outcome.
    #[allow(clippy::too_many_arguments)]
    pub fn sendto(
        &self,
        prio: Priority,
        dst: u16,
        dst_port: u8,
        src_port: u8,
        opts: u32,
        packet: Packet,
    ) {
        let prio_u8 = prio as u8;
        debug_assert!(prio_u8 <= 3, "Priority must be 0-3, got {}", prio_u8);
        let raw = packet.into_raw();
        unsafe { sys::csp_sendto(prio_u8, dst, dst_port, src_port, opts, raw) };
    }

    // ── One-shot transactions ─────────────────────────────────────────────

    /// Perform a full request/reply transaction (new connection each call).
    ///
    /// `in_len` — expected reply length; `-1` for unknown, `0` for no reply.
    /// Returns `Ok(reply_len)` on success.
    #[allow(clippy::too_many_arguments)]
    pub fn transaction(
        &self,
        prio: Priority,
        dst: u16,
        dst_port: u8,
        timeout: u32,
        out_buf: &[u8],
        in_buf: &mut [u8],
        in_len: i32,
        opts: u32,
    ) -> Result<usize> {
        let prio_u8 = prio as u8;
        debug_assert!(prio_u8 <= 3, "Priority must be 0-3, got {}", prio_u8);
        let ret = unsafe {
            sys::csp_transaction_w_opts(
                prio_u8,
                dst,
                dst_port,
                timeout,
                out_buf.as_ptr() as *mut core::ffi::c_void,
                out_buf.len() as i32,
                in_buf.as_mut_ptr() as *mut core::ffi::c_void,
                in_len,
                opts,
            )
        };
        if ret > 0 || (ret == 1 && in_len == 0) {
            Ok(ret as usize)
        } else {
            Err(crate::CspError::TransmitFailed)
        }
    }

    // ── Routing helpers ───────────────────────────────────────────────────

    /// Load routing table entries from a compact string.
    pub fn route_load(&self, table: &str) -> Result<usize> {
        crate::route::load(table)
    }

    /// Add a route programmatically using a raw interface pointer.
    ///
    /// # Safety
    /// `iface` must be a valid, live `csp_iface_t *`.
    pub unsafe fn route_set_raw(
        &self,
        dest: u16,
        mask: u8,
        iface: *mut crate::sys::csp_iface_t,
        via: u16,
    ) -> Result<()> {
        crate::route::set_raw(dest, mask, iface, via)
    }

    // ── Service calls ──────────────────────────────────────────────────────

    /// Send a ping to `node` and return the echo time in ms.
    pub fn ping(&self, node: u16, timeout: u32, payload_size: u32, opts: u8) -> Result<u32> {
        let res = unsafe { sys::csp_ping(node, timeout, payload_size, opts) };
        if res >= 0 {
            Ok(res as u32)
        } else {
            Err(crate::CspError::TransmitFailed)
        }
    }

    /// Send a ping without waiting for a reply (keepalive).
    pub fn ping_noreply(&self, node: u16) {
        unsafe { sys::csp_ping_noreply(node) }
    }

    /// Request process/task list from `node`.
    pub fn ps(&self, node: u16, timeout: u32) {
        unsafe { sys::csp_ps(node, timeout) }
    }

    /// Request and return free memory on `node`.
    pub fn memfree(&self, node: u16, timeout: u32) -> Result<u32> {
        let mut size: u32 = 0;
        csp_result(unsafe { sys::csp_get_memfree(node, timeout, &mut size) })?;
        Ok(size)
    }

    /// Request and return uptime (seconds) of `node`.
    pub fn uptime(&self, node: u16, timeout: u32) -> Result<u32> {
        let mut secs: u32 = 0;
        csp_result(unsafe { sys::csp_get_uptime(node, timeout, &mut secs) })?;
        Ok(secs)
    }

    /// Request and return the number of free packet buffers on `node`.
    pub fn buf_free(&self, node: u16, timeout: u32) -> Result<u32> {
        let mut n: u32 = 0;
        csp_result(unsafe { sys::csp_get_buf_free(node, timeout, &mut n) })?;
        Ok(n)
    }

    /// Send a reboot request to `node`.
    pub fn reboot(&self, node: u16) {
        unsafe { sys::csp_reboot(node) }
    }

    /// Send a shutdown request to `node`.
    pub fn shutdown(&self, node: u16) {
        unsafe { sys::csp_shutdown(node) }
    }

    // ── Protocol Configuration ────────────────────────────────────────────────

    /// Configure RDP (Reliable Datagram Protocol) parameters.
    ///
    /// Requires the `rdp` feature (enabled by default).
    #[cfg(feature = "rdp")]
    pub fn rdp_set_opt(
        &self,
        window_size: u32,
        conn_timeout_ms: u32,
        packet_timeout_ms: u32,
        delayed_acks: u32,
        ack_timeout: u32,
        ack_delay_count: u32,
    ) {
        unsafe {
            sys::csp_rdp_set_opt(
                window_size,
                conn_timeout_ms,
                packet_timeout_ms,
                delayed_acks,
                ack_timeout,
                ack_delay_count,
            );
        }
    }

    /// Get current RDP configuration.
    ///
    /// Returns `(window_size, conn_timeout_ms, packet_timeout_ms, delayed_acks,
    /// ack_timeout, ack_delay_count)`.
    #[cfg(feature = "rdp")]
    pub fn rdp_get_opt(&self) -> (u32, u32, u32, u32, u32, u32) {
        let mut window_size = 0;
        let mut conn_timeout_ms = 0;
        let mut packet_timeout_ms = 0;
        let mut delayed_acks = 0;
        let mut ack_timeout = 0;
        let mut ack_delay_count = 0;

        unsafe {
            sys::csp_rdp_get_opt(
                &mut window_size,
                &mut conn_timeout_ms,
                &mut packet_timeout_ms,
                &mut delayed_acks,
                &mut ack_timeout,
                &mut ack_delay_count,
            );
        }

        (
            window_size,
            conn_timeout_ms,
            packet_timeout_ms,
            delayed_acks,
            ack_timeout,
            ack_delay_count,
        )
    }

    // ── Drivers ───────────────────────────────────────────────────────────────

    /// Open a Linux SocketCAN interface and add it to CSP.
    #[cfg(feature = "socketcan")]
    pub fn add_interface_socketcan(
        &self,
        device: &str,
        bitrate: i32,
        promisc: bool,
    ) -> Result<*mut sys::csp_iface_t> {
        let c_device = CString::new(device).map_err(|_| crate::CspError::InvalidArgument)?;
        let mut iface_ptr: *mut sys::csp_iface_t = core::ptr::null_mut();

        csp_result(unsafe {
            sys::csp_can_socketcan_open_and_add_interface(
                c_device.as_ptr(),
                sys::CSP_IF_CAN_DEFAULT_NAME.as_ptr() as *const c_char,
                self.address() as core::ffi::c_uint,
                bitrate,
                promisc,
                &mut iface_ptr,
            )
        })?;

        Ok(iface_ptr)
    }
}

impl core::fmt::Debug for CspNode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CspNode")
            .field("address", &self.address())
            .finish()
    }
}
