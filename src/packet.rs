/*
Cubesat Space Protocol - A small network-layer protocol designed for Cubesats
Copyright (C) 2012 GomSpace ApS (http://www.gomspace.com)
Copyright (C) 2012 AAUSAT3 Project (http://aausat3.space.aau.dk)

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.
*/

//! RAII wrapper for `csp_packet_t`.

use crate::sys;
use crate::Priority;
use core::ffi::c_void;
use core::fmt;
use core::slice;

/// Maximum payload size in bytes (compile-time constant from `CSP_BUFFER_SIZE`).
pub const BUFFER_SIZE: usize = sys::CSP_BUFFER_SIZE as usize;

/// Owned CSP packet.
///
/// Wraps a `csp_packet_t *` obtained from the CSP buffer pool. On drop the
/// buffer is returned to the pool via `csp_buffer_free()` unless
/// [`Packet::into_raw`] was called.
///
/// # Sending packets
///
/// Passing a `Packet` to [`crate::Connection::send`] or
/// [`crate::CspNode::sendto`] consumes it — libcsp always frees the buffer,
/// whether or not delivery succeeds.
pub struct Packet {
    inner: *mut sys::csp_packet_t,
}

impl Packet {
    /// Allocate a packet from the CSP buffer pool.
    ///
    /// `data_size` is ignored by libcsp (packets have a fixed size); it is
    /// retained as a parameter for callers used to the classic API.
    /// Returns `None` if the pool is exhausted.
    pub fn get(_data_size: usize) -> Option<Self> {
        let ptr = unsafe { sys::csp_buffer_get(0) };
        if ptr.is_null() {
            None
        } else {
            // Buffers returned by the pool may be reused and retain stale
            // header / scratch bytes (frame_begin, frame_length, rx_count, …).
            // Zero the whole struct so a freshly-allocated packet never leaks
            // state from the previous user, then leave the data union alone
            // (callers fill it via `write` / `data_buf_mut`).
            unsafe { core::ptr::write_bytes(ptr, 0, 1) };
            Some(Packet { inner: ptr })
        }
    }

    /// Number of payload bytes currently valid (the `length` field).
    #[inline]
    pub fn length(&self) -> u16 {
        unsafe { (*self.inner).length }
    }

    /// Set the payload length.
    ///
    /// Must be called before sending to tell CSP how many bytes to transmit.
    /// Clamped to [`BUFFER_SIZE`]; otherwise [`Self::data`] / [`Self::data_mut`]
    /// would form an out-of-bounds slice from safe code.
    #[inline]
    pub fn set_length(&mut self, len: u16) {
        let clamped = core::cmp::min(len as usize, BUFFER_SIZE) as u16;
        unsafe {
            (*self.inner).length = clamped;
        }
    }

    /// Read a copy of the CSP id header (priority, addresses, ports, flags).
    pub fn id(&self) -> sys::csp_id_t {
        // `csp_id_t` is `#[repr(C, packed)]`; copy through a raw pointer to
        // avoid forming unaligned references to its u16 fields.
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*self.inner).id)) }
    }

    /// Overwrite the CSP id header.
    pub fn set_id(&mut self, id: sys::csp_id_t) {
        unsafe { core::ptr::write_unaligned(core::ptr::addr_of_mut!((*self.inner).id), id) };
    }

    /// Message priority from the id header.
    ///
    /// `pri` is a 2-bit field on the wire (0..=3) so values 4..=255 should be
    /// impossible if libcsp filled in the id correctly. Any out-of-range
    /// value indicates a corrupted packet or a bug somewhere upstream:
    /// in debug builds we panic to surface it, in release builds we return
    /// [`Priority::Norm`] to avoid taking down a flight node over a logging
    /// glitch. Callers that care about the distinction should inspect
    /// [`Self::id`] directly.
    pub fn priority(&self) -> Priority {
        let id = self.id();
        match id.pri {
            0 => Priority::Critical,
            1 => Priority::High,
            2 => Priority::Norm,
            3 => Priority::Low,
            _ => {
                #[cfg(debug_assertions)]
                panic!("Invalid priority value: {}", id.pri);
                #[cfg(not(debug_assertions))]
                Priority::Norm
            }
        }
    }

    /// Source address.
    pub fn src_addr(&self) -> u16 {
        self.id().src
    }

    /// Destination address.
    pub fn dst_addr(&self) -> u16 {
        self.id().dst
    }

    /// Destination port.
    pub fn dst_port(&self) -> u8 {
        self.id().dport
    }

    /// Source port.
    pub fn src_port(&self) -> u8 {
        self.id().sport
    }

    /// Header flags.
    pub fn flags(&self) -> u8 {
        self.id().flags
    }

    /// Check if the RDP flag is set.
    pub fn is_rdp(&self) -> bool {
        (self.flags() & sys::CSP_FRDP as u8) != 0
    }

    /// Check if the HMAC flag is set.
    pub fn is_hmac(&self) -> bool {
        (self.flags() & sys::CSP_FHMAC as u8) != 0
    }

    /// Check if the CRC32 flag is set.
    pub fn is_crc32(&self) -> bool {
        (self.flags() & sys::CSP_FCRC32 as u8) != 0
    }

    /// Check if the fragmentation flag is set.
    pub fn is_frag(&self) -> bool {
        (self.flags() & sys::CSP_FFRAG as u8) != 0
    }

    /// Pointer to the start of the data buffer.
    fn data_ptr(&self) -> *mut u8 {
        // The data union (`__bindgen_anon_1`) is the final field of
        // `csp_packet_t`; `addr_of_mut!` gives a correctly-aligned pointer
        // independent of how bindgen named the anonymous union.
        unsafe { core::ptr::addr_of_mut!((*self.inner).__bindgen_anon_1) as *mut u8 }
    }

    /// Immutable view of the **used** payload (`[0..length()]`).
    pub fn data(&self) -> &[u8] {
        // `set_length` already clamps, but the field is also writable from
        // C code; re-clamp here defensively so this slice is always in-bounds.
        let len = core::cmp::min(self.length() as usize, BUFFER_SIZE);
        unsafe { slice::from_raw_parts(self.data_ptr(), len) }
    }

    /// Mutable view of the **used** payload (`[0..length()]`).
    pub fn data_mut(&mut self) -> &mut [u8] {
        let len = core::cmp::min(self.length() as usize, BUFFER_SIZE);
        unsafe { slice::from_raw_parts_mut(self.data_ptr(), len) }
    }

    /// Mutable view of the **entire** data buffer (capacity = [`BUFFER_SIZE`]).
    ///
    /// Use this to fill the payload before calling [`set_length`](Self::set_length).
    pub fn data_buf_mut(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.data_ptr(), BUFFER_SIZE) }
    }

    /// Write `bytes` into the payload buffer and set the length field.
    ///
    /// Returns `Err(bytes.len())` if the data does not fit in the buffer.
    pub fn write(&mut self, bytes: &[u8]) -> Result<(), usize> {
        if bytes.len() > BUFFER_SIZE {
            return Err(bytes.len());
        }
        // BUFFER_SIZE is a compile-time constant. Today it defaults to 256, but
        // it is overridable via `LIBCSP_BUFFER_SIZE`; assert the cast can't
        // truncate so a future bump past u16::MAX trips here in debug builds
        // instead of silently losing the high bits.
        debug_assert!(bytes.len() <= u16::MAX as usize);
        self.data_buf_mut()[..bytes.len()].copy_from_slice(bytes);
        self.set_length(bytes.len() as u16);
        Ok(())
    }

    /// Consume this `Packet` and return the raw pointer **without freeing it**.
    #[inline]
    pub fn into_raw(self) -> *mut sys::csp_packet_t {
        let ptr = self.inner;
        core::mem::forget(self);
        ptr
    }

    /// Reconstruct a `Packet` from a raw pointer, taking ownership.
    ///
    /// # Safety
    /// `ptr` must have been obtained from `csp_buffer_get` (or equivalent) and
    /// must not be freed elsewhere after this call.
    #[inline]
    pub unsafe fn from_raw(ptr: *mut sys::csp_packet_t) -> Self {
        Packet { inner: ptr }
    }
}

impl Drop for Packet {
    fn drop(&mut self) {
        unsafe { sys::csp_buffer_free(self.inner as *mut c_void) }
    }
}

// The CSP buffer pool is guarded by internal OS primitives.
unsafe impl Send for Packet {}

impl core::fmt::Debug for Packet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> fmt::Result {
        // `csp_id_t` is `#[repr(C, packed)]`; copy the u16 fields into locals
        // before taking references so we never form unaligned references.
        let id = self.id();
        let src = id.src;
        let dst = id.dst;
        f.debug_struct("Packet")
            .field("length", &self.length())
            .field("src", &src)
            .field("dst", &dst)
            .field("sport", &id.sport)
            .field("dport", &id.dport)
            .field("flags", &format_args!("0x{:02x}", id.flags))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::with_csp_node;

    #[test]
    fn test_packet_get_write_read() {
        with_csp_node(|_node| {
            let mut pkt = Packet::get(32).expect("should get packet");
            assert_eq!(pkt.length(), 0);

            let data = b"test data";
            pkt.write(data).expect("should write data");
            assert_eq!(pkt.length(), data.len() as u16);
            assert_eq!(pkt.data(), data);

            pkt.data_mut()[0] = b'X';
            assert_eq!(&pkt.data()[..1], b"X");
        });
    }

    #[test]
    fn test_packet_overflow() {
        with_csp_node(|_node| {
            let mut pkt = Packet::get(10).expect("should get packet");
            let big_data = vec![0u8; BUFFER_SIZE * 4];
            assert!(pkt.write(&big_data).is_err());
        });
    }

    #[test]
    fn test_packet_initialization() {
        with_csp_node(|_node| {
            let pkt = Packet::get(64).expect("should get packet");

            assert_eq!(pkt.length(), 0);
            assert_eq!(pkt.src_addr(), 0);
            assert_eq!(pkt.dst_addr(), 0);
            assert_eq!(pkt.src_port(), 0);
            assert_eq!(pkt.dst_port(), 0);
            assert_eq!(pkt.flags(), 0);
            assert_eq!(pkt.priority(), crate::Priority::Critical);
        });
    }

    #[test]
    fn test_packet_write_overwrites() {
        with_csp_node(|_node| {
            let mut pkt = Packet::get(64).expect("should get packet");

            pkt.write(b"hello").expect("should write");
            assert_eq!(pkt.length(), 5);
            assert_eq!(pkt.data(), b"hello");

            pkt.write(b"world").expect("should write");
            assert_eq!(pkt.length(), 5);
            assert_eq!(pkt.data(), b"world");

            pkt.write(b"hello world").expect("should write");
            assert_eq!(pkt.length(), 11);
            assert_eq!(pkt.data(), b"hello world");
        });
    }

    #[test]
    fn test_packet_set_length() {
        with_csp_node(|_node| {
            let mut pkt = Packet::get(32).expect("should get packet");

            pkt.set_length(10);
            assert_eq!(pkt.length(), 10);

            pkt.set_length(0);
            assert_eq!(pkt.length(), 0);
        });
    }

    #[test]
    fn test_packet_flags() {
        with_csp_node(|_node| {
            let pkt = Packet::get(16).expect("should get packet");

            assert!(!pkt.is_rdp());
            assert!(!pkt.is_hmac());
            assert!(!pkt.is_crc32());
            assert!(!pkt.is_frag());
        });
    }

    #[test]
    fn test_packet_reuse_buffer() {
        with_csp_node(|_node| {
            {
                let mut pkt = Packet::get(32).expect("should get packet");
                pkt.write(b"old data").unwrap();
            }

            let pkt = Packet::get(32).expect("should get packet");
            assert_eq!(pkt.length(), 0);
            assert_eq!(pkt.src_addr(), 0);
        });
    }
}
