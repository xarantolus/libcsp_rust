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

use crate::error::csp_result;
use crate::sys;
use crate::{Connection, Packet, Result};

/// Builder for the CSP runtime configuration.
///
/// Mirrors the `csp_conf_t` struct in `csp.h`.  Heap allocation is only
/// required for the three C-string fields (`hostname`, `model`, `revision`);
/// all numeric fields are stack-allocated.
pub struct CspConfig {
    address:           u8,
    hostname:          CString,
    model:             CString,
    revision:          CString,
    conn_max:          u8,
    conn_queue_length: u8,
    fifo_length:       u8,
    port_max_bind:     u8,
    rdp_max_window:    u8,
    buffers:           u16,
    buffer_data_size:  u16,
    conn_dfl_so:       u32,
}

impl Default for CspConfig {
    /// Defaults mirror `csp_conf_get_defaults()` from `csp.h`.
    fn default() -> Self {
        CspConfig {
            address:           1,
            hostname:          CString::new("hostname").unwrap(),
            model:             CString::new("model").unwrap(),
            revision:          CString::new("1.0").unwrap(),
            conn_max:          10,
            conn_queue_length: 10,
            fifo_length:       25,
            port_max_bind:     24,
            rdp_max_window:    20,
            buffers:           10,
            buffer_data_size:  256,
            conn_dfl_so:       0,
        }
    }
}

impl CspConfig {
    /// Create a new `CspConfig` with sane defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set this node's CSP address (0–31).
    pub fn address(mut self, addr: u8) -> Self {
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

    /// Set the maximum number of simultaneous connections.
    pub fn conn_max(mut self, n: u8) -> Self {
        self.conn_max = n;
        self
    }

    /// Set the per-connection receive queue length.
    pub fn conn_queue_length(mut self, n: u8) -> Self {
        self.conn_queue_length = n;
        self
    }

    /// Set the router FIFO length (incoming message queue depth).
    pub fn fifo_length(mut self, n: u8) -> Self {
        self.fifo_length = n;
        self
    }

    /// Set the highest port number available for `csp_bind()`.
    pub fn port_max_bind(mut self, n: u8) -> Self {
        self.port_max_bind = n;
        self
    }

    /// Set the maximum RDP window size.
    pub fn rdp_max_window(mut self, n: u8) -> Self {
        self.rdp_max_window = n;
        self
    }

    /// Set the number of pre-allocated packet buffers and their data size.
    pub fn buffers(mut self, count: u16, data_size: u16) -> Self {
        self.buffers = count;
        self.buffer_data_size = data_size;
        self
    }

    /// Set the default connection options ORed onto every new connection.
    ///
    /// See `CSP_O_*` constants in the `sys` module.
    pub fn default_socket_opts(mut self, opts: u32) -> Self {
        self.conn_dfl_so = opts;
        self
    }

    /// Initialise the CSP stack.
    ///
    /// Calls `csp_init()` with the configured values.  On success returns a
    /// [`CspNode`] which keeps the string pointers alive for the duration of
    /// the CSP runtime.  Drop the `CspNode` to call `csp_free_resources()`.
    ///
    /// # Errors
    /// Returns [`CspError`](crate::CspError) if `csp_init()` fails.
    pub fn init(self) -> Result<CspNode> {
        // Build the C struct. The pointer fields point into self's CStrings.
        // Those must remain valid until csp_free_resources() is called.
        let conf = sys::csp_conf_t {
            address:           self.address,
            hostname:          self.hostname.as_ptr() as *const c_char,
            model:             self.model.as_ptr() as *const c_char,
            revision:          self.revision.as_ptr() as *const c_char,
            conn_max:          self.conn_max,
            conn_queue_length: self.conn_queue_length,
            fifo_length:       self.fifo_length,
            port_max_bind:     self.port_max_bind,
            rdp_max_window:    self.rdp_max_window,
            buffers:           self.buffers,
            buffer_data_size:  self.buffer_data_size,
            conn_dfl_so:       self.conn_dfl_so,
        };

        csp_result(unsafe { sys::csp_init(&conf) })?;

        // Move self into the node so the CStrings live as long as the node.
        Ok(CspNode { _inner: Arc::new(CspNodeInner { _config: self }) })
    }
}

// ─────────────────────────────────────────────────────────────────────────────

/// Token representing an initialised CSP runtime.
///
/// Returned by [`CspConfig::init()`].  When the last reference to this value
/// is dropped, `csp_free_resources()` is called to tear down the CSP stack.
///
/// All connections, sockets and packets obtained from this node must be
/// dropped **before** the `CspNode` itself is dropped.
#[derive(Clone)]
pub struct CspNode {
    /// Keeps the CSP runtime alive (calls `csp_free_resources` on last drop).
    _inner: Arc<CspNodeInner>,
}

struct CspNodeInner {
    _config: CspConfig,
}

impl Drop for CspNodeInner {
    fn drop(&mut self) {
        unsafe { sys::csp_free_resources() }
    }
}

impl CspNode {
    /// Return the CSP address of this node.
    pub fn address(&self) -> u8 {
        unsafe { sys::csp_get_address() }
    }

    // ── Routing ───────────────────────────────────────────────────────────

    /// Start the CSP router task.
    ///
    /// The router task calls `csp_route_work()` internally to dispatch
    /// incoming packets to their destinations.
    ///
    /// `stack_size` — task stack size in bytes (platform-dependent units on
    /// FreeRTOS; ignored on POSIX where `pthread` defaults apply).
    ///
    /// `priority` — task priority (platform-dependent).
    pub fn route_start_task(&self, stack_size: u32, priority: u32) -> Result<()> {
        csp_result(unsafe { sys::csp_route_start_task(stack_size, priority) })
    }

    /// Manually process one routing iteration (alternative to the task).
    ///
    /// Call this in your own scheduling loop instead of
    /// [`route_start_task`](CspNode::route_start_task) when you do not want
    /// a background thread.
    pub fn route_work(&self, timeout: u32) -> Result<()> {
        csp_result(unsafe { sys::csp_route_work(timeout) })
    }

    // ── Client connections ─────────────────────────────────────────────────

    /// Establish an outgoing connection to `dst:dst_port`.
    ///
    /// `prio` — message priority (0 = critical … 3 = low).
    /// `timeout` — connection timeout in ms (used for RDP; ignored for UDP).
    /// `opts` — connection options (`CSP_O_*` bitmask).
    ///
    /// Returns `None` if no connection slots are free or the RDP handshake
    /// times out.
    pub fn connect(
        &self,
        prio: u8,
        dst: u8,
        dst_port: u8,
        timeout: u32,
        opts: u32,
    ) -> Option<Connection> {
        let ptr = unsafe { sys::csp_connect(prio, dst, dst_port, timeout, opts) };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { Connection::from_raw(ptr) })
        }
    }

    // ── Connectionless send ────────────────────────────────────────────────

    /// Send a packet connectionlessly to `dst:dst_port`.
    ///
    /// Unlike [`connect`](CspNode::connect) + [`Connection::send`], this
    /// bypasses the connection table entirely — no connection slot is used.
    /// Useful for high-rate fire-and-forget traffic.
    ///
    /// `src_port` — source port number (use 0 to let CSP assign one).
    ///
    /// ## Ownership semantics
    ///
    /// - **On success** (`csp_sendto` returns 1): CSP takes ownership of the
    ///   buffer.  `Ok(())` is returned and `packet` is consumed.
    /// - **On failure**: The packet is returned as `Err((CspError, Packet))`
    ///   so the caller can inspect or drop it.
    pub fn sendto(
        &self,
        prio: u8,
        dst: u8,
        dst_port: u8,
        src_port: u8,
        opts: u32,
        packet: Packet,
        timeout: u32,
    ) -> core::result::Result<(), (crate::CspError, Packet)> {
        let raw = packet.into_raw();
        let ret = unsafe { sys::csp_sendto(prio, dst, dst_port, src_port, opts, raw, timeout) };
        if ret == 1 {
            // CSP owns `raw` now — do NOT reconstruct a Packet from it.
            Ok(())
        } else {
            // Reconstruct the Packet so Drop frees the buffer.
            let returned = unsafe { Packet::from_raw(raw) };
            Err((crate::CspError::TransmitFailed, returned))
        }
    }

    // ── One-shot transactions ─────────────────────────────────────────────

    /// Perform a full request/reply transaction (new connection each call).
    ///
    /// Creates a connection, sends `out_buf`, waits for a reply into `in_buf`,
    /// then closes the connection.
    ///
    /// `in_len` — expected reply length; `-1` for unknown, `0` for no reply.
    ///
    /// Returns `Ok(reply_len)` on success.
    #[allow(clippy::too_many_arguments)]
    pub fn transaction(
        &self,
        prio: u8,
        dst: u8,
        dst_port: u8,
        timeout: u32,
        out_buf: &[u8],
        in_buf: &mut [u8],
        in_len: i32,
        opts: u32,
    ) -> Result<i32> {
        let ret = unsafe {
            sys::csp_transaction_w_opts(
                prio,
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
            Ok(ret)
        } else {
            Err(crate::CspError::TransmitFailed)
        }
    }

    // ── Routing helpers ───────────────────────────────────────────────────────

    /// Load routing table entries from a compact string (convenience wrapper
    /// around [`route::load`](crate::route::load)).
    ///
    /// Format: `"<addr>[/<mask>] <iface> [<via>][, ...]"`
    ///
    /// Example: `"0/0 LOOP"` routes all traffic through the loopback interface.
    pub fn route_load(&self, table: &str) -> Result<i32> {
        crate::route::load(table)
    }

    /// Add a route programmatically using a raw interface pointer.
    ///
    /// # Safety
    /// `iface` must be a valid, live `csp_iface_t *`.
    pub unsafe fn route_set_raw(
        &self,
        dest: u8,
        mask: u8,
        iface: *mut crate::sys::csp_iface_t,
        via: u8,
    ) -> Result<()> {
        crate::route::set_raw(dest, mask, iface, via)
    }

    // ── Service calls ──────────────────────────────────────────────────────

    /// Send a ping to `node` and return the echo time in ms, or -1 on error.
    pub fn ping(&self, node: u8, timeout: u32, payload_size: u32, opts: u8) -> i32 {
        unsafe { sys::csp_ping(node, timeout, payload_size, opts) }
    }

    /// Request and return free memory on `node`.
    pub fn memfree(&self, node: u8, timeout: u32) -> Result<u32> {
        let mut size: u32 = 0;
        csp_result(unsafe { sys::csp_get_memfree(node, timeout, &mut size) })?;
        Ok(size)
    }

    /// Request and return uptime (seconds) of `node`.
    pub fn uptime(&self, node: u8, timeout: u32) -> Result<u32> {
        let mut secs: u32 = 0;
        csp_result(unsafe { sys::csp_get_uptime(node, timeout, &mut secs) })?;
        Ok(secs)
    }

    /// Request and return the number of free packet buffers on `node`.
    pub fn buf_free(&self, node: u8, timeout: u32) -> Result<u32> {
        let mut n: u32 = 0;
        csp_result(unsafe { sys::csp_get_buf_free(node, timeout, &mut n) })?;
        Ok(n)
    }

    /// Send a reboot request to `node`.
    pub fn reboot(&self, node: u8) {
        unsafe { sys::csp_reboot(node) }
    }

    /// Send a shutdown request to `node`.
    pub fn shutdown(&self, node: u8) {
        unsafe { sys::csp_shutdown(node) }
    }

    // ── Security ──────────────────────────────────────────────────────────────

    /// Load the 128-bit XTEA pre-shared key (four 32-bit words).
    ///
    /// Both ends of any XTEA-encrypted connection must share the same key.
    /// Call this **before** starting the router task and opening any
    /// encrypted connections.
    ///
    /// The key is stored in a global variable inside the C library.  This
    /// call is not thread-safe if made concurrently with active XTEA
    /// connections.
    ///
    /// Requires the `xtea` feature (enabled by default).
    #[cfg(feature = "xtea")]
    pub fn set_xtea_key(&self, key: &[u32; 4]) {
        unsafe { sys::csp_xtea_set_key(key.as_ptr() as *const core::ffi::c_void, 4); }
    }

    // ── Drivers ───────────────────────────────────────────────────────────────

    /// Open a Linux SocketCAN interface and add it to CSP.
    ///
    /// `device` — Linux device name (e.g., "can0", "vcan0").
    /// `bitrate` — bitrate in bps (0 to keep current OS setting).
    /// `promisc` — if true, receive all CAN frames; if false, filter for local address.
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
