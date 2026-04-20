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
/// Wraps a `csp_conn_t *` and closes it automatically on drop via
/// `csp_close()`. Obtained from
/// [`CspNode::connect`](crate::CspNode::connect) (outgoing) or
/// [`Socket::accept`](crate::Socket::accept) (incoming).
pub struct Connection {
    inner: *mut sys::csp_conn_t,
}

impl Connection {
    /// Construct a `Connection` from a raw pointer, taking ownership.
    ///
    /// # Safety
    /// `ptr` must be a valid, open `csp_conn_t *` from libcsp.
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
    /// The packet is **always consumed** — libcsp frees the buffer regardless
    /// of delivery outcome. Failures are signalled out-of-band via debug
    /// counters (`csp_dbg_*`).
    pub fn send(&self, packet: Packet) {
        let raw = packet.into_raw();
        unsafe { sys::csp_send(self.inner, raw) };
    }

    /// Send a packet at the given priority without changing the connection's
    /// default priority permanently.
    pub fn send_prio(&self, prio: crate::Priority, packet: Packet) {
        let raw = packet.into_raw();
        unsafe { sys::csp_send_prio(prio as u8, self.inner, raw) };
    }

    // ── Receiving ─────────────────────────────────────────────────────────

    /// Read the next incoming packet from this connection's RX queue.
    ///
    /// Blocks for up to `timeout` milliseconds. Use `CSP_MAX_TIMEOUT` to block
    /// indefinitely. Returns `None` on timeout.
    pub fn read(&self, timeout: u32) -> Option<Packet> {
        let ptr = unsafe { sys::csp_read(self.inner, timeout) };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { Packet::from_raw(ptr) })
        }
    }

    // ── Connection metadata ───────────────────────────────────────────────

    /// Destination port.
    #[inline]
    pub fn dst_port(&self) -> u8 {
        unsafe { sys::csp_conn_dport(self.inner) as u8 }
    }

    /// Source port.
    #[inline]
    pub fn src_port(&self) -> u8 {
        unsafe { sys::csp_conn_sport(self.inner) as u8 }
    }

    /// Destination address.
    #[inline]
    pub fn dst_addr(&self) -> u16 {
        unsafe { sys::csp_conn_dst(self.inner) as u16 }
    }

    /// Source address.
    #[inline]
    pub fn src_addr(&self) -> u16 {
        unsafe { sys::csp_conn_src(self.inner) as u16 }
    }

    /// Header flags (`CSP_F*` bitmask).
    #[inline]
    pub fn flags(&self) -> i32 {
        unsafe { sys::csp_conn_flags(self.inner) }
    }

    /// Return `true` if this connection was opened with the RDP flag.
    #[inline]
    pub fn is_rdp(&self) -> bool {
        (self.flags() & sys::CSP_FRDP as i32) != 0
    }

    /// Return `true` if the connection is still active (no protocol timeout).
    #[inline]
    pub fn is_active(&self) -> bool {
        unsafe { sys::csp_conn_is_active(self.inner) }
    }

    // ── Transactions ──────────────────────────────────────────────────────

    /// Perform a complete request/reply exchange on this *existing* connection.
    ///
    /// Returns `Ok(reply_len)` on success.
    pub fn transaction(
        &self,
        timeout: u32,
        out_buf: &[u8],
        in_buf: &mut [u8],
        in_len: i32,
    ) -> Result<usize> {
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
            Ok(ret as usize)
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
            fn memcpy(
                dest: *mut core::ffi::c_void,
                src: *const core::ffi::c_void,
                n: usize,
            ) -> *mut core::ffi::c_void;
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
    /// Returns the received data as a `Vec<u8>`. The buffer is allocated by
    /// libcsp and copied into Rust-owned memory before release.
    pub fn sfp_recv(&self, timeout: u32) -> Result<alloc::vec::Vec<u8>> {
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
            // Safety: `data_ptr` was allocated by libcsp and `data_size` is valid.
            let slice =
                unsafe { core::slice::from_raw_parts(data_ptr as *const u8, data_size as usize) };
            let vec = slice.to_vec();
            // Free the sfp-internal allocation through libc since libcsp uses
            // the system allocator (posix) / csp_malloc shim (external-arch).
            extern "C" {
                fn free(ptr: *mut core::ffi::c_void);
            }
            unsafe { free(data_ptr) };
            Ok(vec)
        } else {
            Err(CspError::from(ret))
        }
    }

    /// Handle a CSP service request (PING, PS, MEMFREE, …) using the default
    /// libcsp service handler.
    ///
    /// Consumes the packet and either sends a reply or frees it.
    pub fn handle_service(&self, packet: Packet) {
        // v2.x service handler reads addressing from the packet itself.
        unsafe { sys::csp_service_handler(packet.into_raw()) };
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        unsafe { sys::csp_close(self.inner) };
    }
}

// libcsp guards connection access with internal OS primitives.
unsafe impl Send for Connection {}
unsafe impl Sync for Connection {}

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
    use crate::{test_helpers::with_csp_node, Packet, Priority};

    #[test]
    fn test_connection_send_to_nowhere() {
        with_csp_node(|node| {
            let node_addr = 1;
            let conn = node
                .connect(Priority::Norm, node_addr, 10, 100, 0)
                .expect("Connect failed");

            let mut pkt = Packet::get(16).unwrap();
            pkt.write(b"hello").unwrap();

            conn.send(pkt);
        });
    }

    #[test]
    fn test_connection_loopback() {
        with_csp_node(|node| {
            let my_addr = 1;
            let port = 10;

            let conn = node
                .connect(Priority::Norm, my_addr, port, 100, 0)
                .expect("Failed to connect to loopback");

            let mut pkt = Packet::get(32).unwrap();
            let test_data = b"loopback test data";
            pkt.write(test_data).unwrap();

            conn.send(pkt);

            if let Some(received) = conn.read(100) {
                assert_eq!(received.data(), test_data);
                assert_eq!(received.length() as usize, test_data.len());
            }
        });
    }

    #[test]
    fn test_connection_metadata() {
        with_csp_node(|node| {
            let my_addr = 1;
            let dst_port = 15;

            let conn = node
                .connect(Priority::High, my_addr, dst_port, 100, 0)
                .expect("Failed to connect");

            let _dst_addr = conn.dst_addr();
            let _dst_port = conn.dst_port();
            let _src_addr = conn.src_addr();
            let _src_port = conn.src_port();

            // With wire-format version 1 the host field is 5 bits wide.
            assert!(conn.dst_addr() <= 31);
            assert!(conn.src_addr() <= 31);
            assert!(conn.dst_port() <= 63);
            assert!(conn.src_port() <= 63);
        });
    }
}
