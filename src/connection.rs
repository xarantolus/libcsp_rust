/*
Cubesat Space Protocol - A small network-layer protocol designed for Cubesats
Copyright (C) 2012 GomSpace ApS (http://www.gomspace.com)
Copyright (C) 2012 AAUSAT3 Project (http://aausat3.space.aau.dk)

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.
*/

//! RAII wrapper for `csp_conn_t`.

use core::fmt;

use crate::sys;
use crate::{CspError, Packet, Result};

/// An open CSP connection.
///
/// Wraps a `csp_conn_t *` and closes it automatically when dropped via
/// `csp_close()`.
///
/// Connections are obtained either from
/// [`CspNode::connect`](crate::CspNode::connect) (outgoing) or
/// [`Socket::accept`](crate::Socket::accept) (incoming).
pub struct Connection {
    inner: *mut sys::csp_conn_t,
}

impl Connection {
    /// Construct a `Connection` from a raw pointer, taking ownership.
    ///
    /// # Safety
    /// `ptr` must be a valid, open `csp_conn_t *` obtained from libcsp and
    /// must not be closed or freed elsewhere.
    #[inline]
    pub unsafe fn from_raw(ptr: *mut sys::csp_conn_t) -> Self {
        Connection { inner: ptr }
    }

    /// Return the raw C pointer.
    #[inline]
    pub fn as_raw(&self) -> *mut sys::csp_conn_t {
        self.inner
    }

    // ── Sending ──────────────────────────────────────────────────────────

    /// Send a packet over this connection.
    ///
    /// ## Ownership semantics
    ///
    /// - **On success** (`csp_send` returns 1): CSP takes ownership of the
    ///   buffer. `Ok(())` is returned and `packet` is consumed.
    /// - **On failure** (`csp_send` returns 0): CSP did **not** take
    ///   ownership. The packet is returned as `Err((CspError, Packet))` so
    ///   the caller can inspect or drop it.
    ///
    /// `timeout` is unused in libcsp 1.6 but is forwarded for future
    /// compatibility.
    pub fn send(
        &self,
        packet: Packet,
        timeout: u32,
    ) -> core::result::Result<(), (CspError, Packet)> {
        let raw = packet.into_raw(); // Rust forgets ownership
        let ret = unsafe { sys::csp_send(self.inner, raw, timeout) };
        if ret == 1 {
            // CSP owns `raw` now — do NOT reconstruct a Packet from it.
            Ok(())
        } else {
            // Reconstruct the Packet so Drop frees the buffer.
            let returned = unsafe { Packet::from_raw(raw) };
            Err((CspError::TransmitFailed, returned))
        }
    }

    /// Convenience wrapper around [`send`](Connection::send) that discards the
    /// packet on failure (frees the buffer automatically).
    pub fn send_discard(&self, packet: Packet, timeout: u32) -> Result<()> {
        self.send(packet, timeout).map_err(|(e, _pkt)| e)
    }

    // ── Receiving ─────────────────────────────────────────────────────────

    /// Read the next incoming packet from this connection's RX queue.
    ///
    /// Blocks for up to `timeout` milliseconds.  Use `0xFFFF_FFFF`
    /// (`CSP_MAX_TIMEOUT`) to block indefinitely.
    ///
    /// Returns `None` on timeout or error.  The returned [`Packet`] is owned
    /// by the caller and will be freed when dropped.
    pub fn read(&self, timeout: u32) -> Option<Packet> {
        let ptr =
            unsafe { sys::csp_read(self.inner, timeout) };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { Packet::from_raw(ptr) })
        }
    }

    // ── Connection metadata ───────────────────────────────────────────────

    /// Destination port.
    #[inline]
    pub fn dst_port(&self) -> i32 {
        unsafe { sys::csp_conn_dport(self.inner) }
    }

    /// Source port.
    #[inline]
    pub fn src_port(&self) -> i32 {
        unsafe { sys::csp_conn_sport(self.inner) }
    }

    /// Destination address.
    #[inline]
    pub fn dst_addr(&self) -> i32 {
        unsafe { sys::csp_conn_dst(self.inner) }
    }

    /// Source address.
    #[inline]
    pub fn src_addr(&self) -> i32 {
        unsafe { sys::csp_conn_src(self.inner) }
    }

    /// Header flags (see `CSP_F*` constants in the `sys` module).
    #[inline]
    pub fn flags(&self) -> i32 {
        unsafe { sys::csp_conn_flags(self.inner) }
    }

    // ── Transactions ──────────────────────────────────────────────────────

    /// Perform a complete request/reply exchange on this *existing* connection.
    ///
    /// Sends `out_buf`, waits up to `timeout` ms, and copies the reply into
    /// `in_buf`.  `in_len` is the expected reply size; pass `-1` for an
    /// unknown size (make sure `in_buf` is large enough) or `0` for no reply.
    ///
    /// Returns `Ok(reply_len)` on success.
    pub fn transaction(
        &self,
        timeout: u32,
        out_buf: &[u8],
        in_buf: &mut [u8],
        in_len: i32,
    ) -> Result<i32> {
        let ret = unsafe {
            sys::csp_transaction_persistent(
                self.inner,
                timeout,
                out_buf.as_ptr() as *mut core::ffi::c_void,
                out_buf.len() as i32,
                in_buf.as_mut_ptr() as *mut core::ffi::c_void,
                in_len,
            )
        };
        if ret > 0 || (ret == 1 && in_len == 0) {
            Ok(ret)
        } else {
            Err(CspError::TransmitFailed)
        }
    }

    // ── SFP (Simple Fragmentation Protocol) ──────────────────────────────

    /// Send a large blob of data over this connection using SFP.
    ///
    /// Data is chopped into chunks of at most `mtu` bytes.
    pub fn sfp_send(&self, data: &[u8], mtu: u32, timeout: u32) -> Result<()> {
        extern "C" {
            fn memcpy(dest: *mut core::ffi::c_void, src: *const core::ffi::c_void, n: usize) -> *mut core::ffi::c_void;
        }
        let ret = unsafe {
            sys::csp_sfp_send_own_memcpy(
                self.inner,
                data.as_ptr() as *const core::ffi::c_void,
                data.len() as u32,
                mtu,
                timeout,
                Some(memcpy),
            )
        };
        if ret == (sys::CSP_ERR_NONE as i32) {
            Ok(())
        } else {
            Err(CspError::from(ret))
        }
    }

    /// Receive a large blob of data over this connection using SFP.
    ///
    /// Returns the received data as a `Vec<u8>` if the `std` feature is enabled,
    /// otherwise it returns the raw pointer and size (caller must free via `csp_free`).
    #[cfg(feature = "std")]
    pub fn sfp_recv(&self, timeout: u32) -> Result<Vec<u8>> {
        let mut data_ptr: *mut core::ffi::c_void = core::ptr::null_mut();
        let mut data_size: core::ffi::c_int = 0;
        let ret = unsafe {
            sys::csp_sfp_recv_fp(
                self.inner,
                &mut data_ptr,
                &mut data_size,
                timeout,
                core::ptr::null_mut(),
            )
        };

        if ret == (sys::CSP_ERR_NONE as i32) && !data_ptr.is_null() {
            let slice = unsafe { core::slice::from_raw_parts(data_ptr as *const u8, data_size as usize) };
            let vec = slice.to_vec();
            unsafe { sys::csp_free(data_ptr) };
            Ok(vec)
        } else {
            Err(CspError::from(ret))
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // csp_close handles a NULL pointer gracefully, but our pointer is
        // always non-null (we only build Connection from non-null pointers).
        unsafe { sys::csp_close(self.inner) };
    }
}

// CSP connections are protected by internal OS synchronisation primitives,
// making it safe to move a Connection to another thread.
unsafe impl Send for Connection {}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("src_addr", &self.src_addr())
            .field("dst_addr", &self.dst_addr())
            .field("src_port", &self.src_port())
            .field("dst_port", &self.dst_port())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CspConfig, Packet};
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn ensure_init() {
        INIT.call_once(|| {
            let node = CspConfig::new()
                .address(1)
                .buffers(10, 256)
                .init()
                .expect("failed to init CSP for tests");
            core::mem::forget(node);
        });
    }

    #[test]
    fn test_connection_send_to_nowhere() {
        ensure_init();
        // Trying to connect to a node that isn't there (and we don't have a route for except LOOP)
        // If we connect to address 1 port 10 (loopback), we can test send.
        let node_addr = 1;
        let ptr = unsafe { sys::csp_connect(2, node_addr, 10, 100, 0) };
        assert!(!ptr.is_null());
        let conn = unsafe { Connection::from_raw(ptr) };

        let mut pkt = Packet::get(16).unwrap();
        pkt.write(b"hello").unwrap();

        // On loopback, send usually succeeds immediately because it just goes into a queue.
        let res = conn.send(pkt, 0);
        assert!(res.is_ok());
    }
}
