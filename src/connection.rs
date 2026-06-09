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
    /// `in_len` — expected reply length; pass `0` if no reply is expected.
    /// Returns `Ok(reply_bytes)` on success (always `0` when `in_len == 0`).
    ///
    /// libcsp returns `1` for "no reply expected, send succeeded" and `> 0`
    /// for "received this many reply bytes"; both are mapped to `Ok` here.
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
        match (ret, in_len) {
            // No reply expected: libcsp returns 1 for "send ok", 0 (CSP_ERR_NONE)
            // is also accepted defensively.
            (1, 0) | (0, 0) => Ok(0),
            // Reply received: ret carries the number of bytes.
            (n, _) if n > 0 => Ok(n as usize),
            _ => Err(CspError::TransmitFailed),
        }
    }

    // ── SFP (Simple Fragmentation Protocol) ──────────────────────────────

    /// Send a large blob of data over this connection using SFP.
    ///
    /// Data is chopped into chunks of at most `mtu` bytes. The post-malloc
    /// upstream API takes a user-provided read callback; we adapt by handing
    /// the slice in via `data` and copying out at the requested offset.
    pub fn sfp_send(&self, data: &[u8], mtu: u32, timeout: u32) -> Result<()> {
        self.sfp_send_with_progress(data, mtu, timeout, |_, _| {})
    }

    /// Send a large blob of data over this connection using SFP, reporting
    /// progress as each fragment is handed to the transmit path.
    ///
    /// `on_progress(sent, total)` is invoked once per fragment, where `sent`
    /// is the cumulative number of bytes read out so far (a multiple of `mtu`
    /// except for the final fragment) and `total` is the full transfer size
    /// (`data.len()`, known up front). It fires synchronously on the calling
    /// thread between fragments, so it must not block; over an RDP connection
    /// `csp_sfp_send` can stall on a full window, pausing then resuming the
    /// reported `sent` (it never decreases).
    pub fn sfp_send_with_progress<F>(
        &self,
        data: &[u8],
        mtu: u32,
        timeout: u32,
        on_progress: F,
    ) -> Result<()>
    where
        F: FnMut(u32, u32),
    {
        struct SendCtx<F> {
            ptr: *const u8,
            len: u32,
            progress: F,
        }
        unsafe extern "C" fn read_cb<F: FnMut(u32, u32)>(
            buffer: *mut u8,
            size: u32,
            offset: u32,
            data: *mut core::ffi::c_void,
        ) -> core::ffi::c_int {
            let ctx = unsafe { &mut *(data as *mut SendCtx<F>) };
            let end = offset.saturating_add(size);
            if end > ctx.len {
                return sys::CSP_ERR_INVAL;
            }
            unsafe {
                core::ptr::copy_nonoverlapping(ctx.ptr.add(offset as usize), buffer, size as usize);
            }
            (ctx.progress)(end, ctx.len);
            sys::CSP_ERR_NONE as i32
        }
        let mut ctx = SendCtx {
            ptr: data.as_ptr(),
            len: data.len() as u32,
            progress: on_progress,
        };
        let user = sys::csp_sfp_read_t {
            data: &mut ctx as *mut _ as *mut core::ffi::c_void,
            read: Some(read_cb::<F>),
        };
        let ret = unsafe { sys::csp_sfp_send(self.inner, &user, data.len() as u32, mtu, timeout) };
        if ret == (sys::CSP_ERR_NONE as i32) {
            Ok(())
        } else {
            Err(CspError::from(ret))
        }
    }

    /// Receive a large blob of data over this connection using SFP.
    ///
    /// Returns the received data as a `Vec<u8>`. The post-malloc upstream
    /// API delivers data via a write callback; we accumulate into a Vec
    /// sized on the first call from `totalsz`.
    pub fn sfp_recv(&self, timeout: u32) -> Result<alloc::vec::Vec<u8>> {
        self.sfp_recv_with_progress(timeout, |_, _, _| {})
    }

    /// Receive a large blob of data over this connection using SFP, reporting
    /// progress as each fragment arrives.
    ///
    /// `on_progress(received, total, prefix)` is invoked once per in-order
    /// fragment: `received` is the cumulative byte count, `total` is the full
    /// transfer size (from the SFP header, valid from the first fragment), and
    /// `prefix` is the contiguous bytes received so far (`&buf[..received]`).
    /// It fires synchronously on the calling thread, so it must not block.
    /// Over RDP, fragments are still delivered in order, so `received` is
    /// monotonic and reflects in-order delivered bytes.
    pub fn sfp_recv_with_progress<F>(
        &self,
        timeout: u32,
        on_progress: F,
    ) -> Result<alloc::vec::Vec<u8>>
    where
        F: FnMut(u32, u32, &[u8]),
    {
        use alloc::vec::Vec;
        struct VecCtx<F> {
            buf: Vec<u8>,
            progress: F,
        }
        unsafe extern "C" fn write_cb<F: FnMut(u32, u32, &[u8])>(
            buffer: *const u8,
            size: u32,
            offset: u32,
            totalsz: u32,
            data: *mut core::ffi::c_void,
        ) -> core::ffi::c_int {
            let ctx = unsafe { &mut *(data as *mut VecCtx<F>) };
            if ctx.buf.is_empty() && totalsz > 0 {
                ctx.buf.resize(totalsz as usize, 0);
            }
            let end = match (offset as usize).checked_add(size as usize) {
                Some(e) => e,
                None => return sys::CSP_ERR_INVAL,
            };
            if end > ctx.buf.len() {
                return sys::CSP_ERR_INVAL;
            }
            unsafe {
                core::ptr::copy_nonoverlapping(
                    buffer,
                    ctx.buf.as_mut_ptr().add(offset as usize),
                    size as usize,
                );
            }
            (ctx.progress)(end as u32, totalsz, &ctx.buf[..end]);
            sys::CSP_ERR_NONE as i32
        }
        let mut ctx = VecCtx {
            buf: Vec::new(),
            progress: on_progress,
        };
        let user = sys::csp_sfp_recv_t {
            data: &mut ctx as *mut _ as *mut core::ffi::c_void,
            write: Some(write_cb::<F>),
        };
        let ret =
            unsafe { sys::csp_sfp_recv_fp(self.inner, &user, timeout, core::ptr::null_mut()) };
        if ret == (sys::CSP_ERR_NONE as i32) {
            Ok(ctx.buf)
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

// libcsp guards connection access with internal OS primitives, but the
// *user-visible* operations on a connection are racy at the API level
// (e.g. concurrent `read()` calls would each pop a different packet from
// the rx queue with no defined ordering). Make the connection movable
// across threads but pin its use to one thread at a time.
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
