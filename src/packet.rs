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
use core::slice;
use core::fmt;

/// The byte offset at which the data payload begins inside `csp_packet_t`.
///
/// ```text
/// offset  0: uint8_t  padding[10]   (10 bytes)
/// offset 10: uint16_t length         ( 2 bytes)
/// offset 12: csp_id_t id  (uint32_t) ( 4 bytes)
/// offset 16: uint8_t  data[]         (flexible)
/// ```
///
/// There is no compiler-added padding between these fields because the natural
/// alignment of each field is satisfied by the preceding cumulative sizes.
const DATA_OFFSET: usize = 10 + 2 + 4; // = 16

/// Owned CSP packet.
///
/// Wraps a `csp_packet_t *` obtained from the CSP buffer pool.  When this
/// value is dropped (without calling [`Packet::into_raw`]), the underlying
/// buffer is returned to the pool via `csp_buffer_free()`.
///
/// # Sending packets
///
/// Once you pass a `Packet` to [`crate::Connection::send`] and it succeeds,
/// CSP takes ownership of the buffer.  If the send **fails**, the `Packet` is
/// returned to you (inside the `Err`) so you can inspect or drop it.
pub struct Packet {
    inner: *mut sys::csp_packet_t,
}

impl Packet {
    /// Allocate a packet from the CSP buffer pool.
    ///
    /// `data_size` is the minimum number of payload bytes needed.
    /// Returns `None` if the pool is exhausted or `data_size` is too large.
    pub fn get(data_size: usize) -> Option<Self> {
        // Safety: `sys::csp_buffer_get` is thread-safe and returns a valid
        // pointer or NULL.
        let ptr = unsafe {
            sys::csp_buffer_get(data_size) as *mut sys::csp_packet_t
        };
        if ptr.is_null() {
            None
        } else {
            // Initialize packet fields to safe defaults.
            // libcsp's csp_buffer_get doesn't clear the buffer, so reused buffers
            // may contain stale data from previous uses.
            unsafe {
                (*ptr).length = 0;
                (*ptr).id.ext = 0;  // Clear the CSP header (src/dst addr, ports, flags)
            }
            Some(Packet { inner: ptr })
        }
    }

    /// Return the number of payload bytes currently marked as valid
    /// (the `length` field of the CSP packet header).
    #[inline]
    pub fn length(&self) -> u16 {
        // Safety: `inner` is a valid packet pointer.
        unsafe { (*self.inner).length }
    }

    /// Set the payload length field.
    ///
    /// You **must** call this before sending a packet to tell CSP how many
    /// bytes to transmit.
    #[inline]
    pub fn set_length(&mut self, len: u16) {
        // Safety: `inner` is a valid packet pointer.
        unsafe { (*self.inner).length = len; }
    }

    /// Return the raw 32-bit CSP header (priority, addresses, ports, flags).
    #[inline]
    pub fn id_raw(&self) -> u32 {
        // Safety: `inner` is a valid packet pointer.
        unsafe { (*self.inner).id.ext }
    }

    /// Set the raw 32-bit CSP header.
    #[inline]
    pub fn set_id_raw(&mut self, id: u32) {
        // Safety: `inner` is a valid packet pointer.
        unsafe { (*self.inner).id.ext = id; }
    }

    /// Return the message priority as a Priority enum.
    pub fn priority(&self) -> Priority {
        // Safety: Priority is a 2-bit field (0-3) in the CSP header.
        let prio = ((self.id_raw() & 0xC0000000) >> 30) as u8;
        // Always validate, even in release builds, to prevent UB from transmute
        match prio {
            0 => Priority::Critical,
            1 => Priority::High,
            2 => Priority::Norm,
            3 => Priority::Low,
            // Defensive: if corrupted data somehow has invalid priority,
            // return a safe default rather than causing UB
            _ => {
                #[cfg(debug_assertions)]
                panic!("Invalid priority value: {}", prio);
                #[cfg(not(debug_assertions))]
                Priority::Norm  // Safe fallback in release builds
            }
        }
    }

    /// Return the source address (0-31).
    pub fn src_addr(&self) -> u8 {
        // Safety: Addresses are 5-bit fields (0-31) in the CSP header.
        ((self.id_raw() & 0x3E000000) >> 25) as u8
    }

    /// Return the destination address (0-31).
    pub fn dst_addr(&self) -> u8 {
        // Safety: Addresses are 5-bit fields (0-31) in the CSP header.
        ((self.id_raw() & 0x01F00000) >> 20) as u8
    }

    /// Return the destination port (0-63).
    pub fn dst_port(&self) -> u8 {
        // Safety: Ports are 6-bit fields (0-63) in the CSP header.
        ((self.id_raw() & 0x000FC000) >> 14) as u8
    }

    /// Return the source port (0-63).
    pub fn src_port(&self) -> u8 {
        // Safety: Ports are 6-bit fields (0-63) in the CSP header.
        ((self.id_raw() & 0x00003F00) >> 8) as u8
    }

    /// Return the CSP header flags (8 bits).
    pub fn flags(&self) -> u8 {
        // Safety: Flags is an 8-bit field in the CSP header.
        (self.id_raw() & 0x000000FF) as u8
    }

    /// Check if the RDP flag is set.
    pub fn is_rdp(&self) -> bool {
        (self.flags() & 0x02) != 0
    }

    /// Check if the XTEA flag is set.
    pub fn is_xtea(&self) -> bool {
        (self.flags() & 0x04) != 0
    }

    /// Check if the HMAC flag is set.
    pub fn is_hmac(&self) -> bool {
        (self.flags() & 0x08) != 0
    }

    /// Check if the CRC32 flag is set.
    pub fn is_crc32(&self) -> bool {
        (self.flags() & 0x01) != 0
    }

    /// Check if the Fragmentation flag is set.
    pub fn is_frag(&self) -> bool {
        (self.flags() & 0x10) != 0
    }

    /// Immutable view of the **used** payload (`[0..length()]`).
    ///
    /// # Panics
    /// Does not panic, but will produce a zero-length slice if `length()` is 0.
    pub fn data(&self) -> &[u8] {
        let len = self.length() as usize;
        // Safety: `inner` was obtained from csp_buffer_get which guarantees
        // at least `data_size` bytes follow the fixed header fields.
        // DATA_OFFSET is the deterministic offset of the data union.
        unsafe {
            slice::from_raw_parts(
                (self.inner as *const u8).add(DATA_OFFSET),
                len,
            )
        }
    }

    /// Mutable view of the **used** payload (`[0..length()]`).
    pub fn data_mut(&mut self) -> &mut [u8] {
        let len = self.length() as usize;
        // Safety: `inner` is valid, and the data buffer is large enough for `len` bytes.
        unsafe {
            slice::from_raw_parts_mut(
                (self.inner as *mut u8).add(DATA_OFFSET),
                len,
            )
        }
    }

    /// Mutable view of the **entire** data buffer (capacity = `csp_buffer_data_size()`).
    ///
    /// Use this to fill the payload before calling [`set_length`](Packet::set_length).
    pub fn data_buf_mut(&mut self) -> &mut [u8] {
        // Safety: libcsp is initialised.
        let cap = unsafe { sys::csp_buffer_data_size() };
        // Safety: `inner` is valid, and the data buffer is exactly `cap` bytes.
        unsafe {
            slice::from_raw_parts_mut(
                (self.inner as *mut u8).add(DATA_OFFSET),
                cap as usize,
            )
        }
    }

    /// Write `bytes` into the payload buffer and set the length field.
    ///
    /// Returns `Err(bytes.len())` if the data does not fit in the buffer.
    pub fn write(&mut self, bytes: &[u8]) -> Result<(), usize> {
        let cap = unsafe { sys::csp_buffer_data_size() };
        if bytes.len() > cap {
            return Err(bytes.len());
        }
        self.data_buf_mut()[..bytes.len()].copy_from_slice(bytes);
        self.set_length(bytes.len() as u16);
        Ok(())
    }

    /// Consume this `Packet` and return the raw pointer **without freeing it**.
    ///
    /// The caller is responsible for eventually freeing the buffer, typically
    /// by reconstructing a `Packet` via [`Packet::from_raw`] or passing the
    /// pointer to a function that takes ownership (e.g. `csp_send`).
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
    /// must not be freed or used elsewhere after this call.
    #[inline]
    pub unsafe fn from_raw(ptr: *mut sys::csp_packet_t) -> Self {
        Packet { inner: ptr }
    }
}

impl Drop for Packet {
    fn drop(&mut self) {
        // Safety: `inner` is a valid pointer obtained from `csp_buffer_get`.
        // libcsp's buffer pool is thread-safe.
        unsafe { sys::csp_buffer_free(self.inner as *mut c_void) }
    }
}

// CSP packets live in a pool that is protected by internal OS primitives, so
// passing a packet between threads is safe.
unsafe impl Send for Packet {}

impl core::fmt::Debug for Packet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Packet")
            .field("length", &self.length())
            .field("id_raw", &format_args!("0x{:08x}", self.id_raw()))
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

            // Check data_mut
            pkt.data_mut()[0] = b'X';
            assert_eq!(&pkt.data()[..1], b"X");
        });
    }

    #[test]
    fn test_packet_overflow() {
        with_csp_node(|_node| {
            let mut pkt = Packet::get(10).expect("should get packet");
            let big_data = vec![0u8; 1024];
            assert!(pkt.write(&big_data).is_err());
        });
    }

    #[test]
    fn test_data_offset() {
        with_csp_node(|_node| {
            let mut pkt = Packet::get(1).expect("should get packet");
            let base = pkt.inner as usize;
            let data_ptr = pkt.data_buf_mut().as_ptr() as usize;
            assert_eq!(data_ptr - base, DATA_OFFSET, "DATA_OFFSET mismatch!");
        });
    }

    #[test]
    fn test_packet_initialization() {
        with_csp_node(|_node| {
            // Verify that newly allocated packets are properly initialized
            let pkt = Packet::get(64).expect("should get packet");

            // These should all be zero after initialization
            assert_eq!(pkt.length(), 0);
            assert_eq!(pkt.id_raw(), 0);
            assert_eq!(pkt.priority(), crate::Priority::Critical);  // 0 maps to Critical
            assert_eq!(pkt.src_addr(), 0);
            assert_eq!(pkt.dst_addr(), 0);
            assert_eq!(pkt.src_port(), 0);
            assert_eq!(pkt.dst_port(), 0);
            assert_eq!(pkt.flags(), 0);
        });
    }

    #[test]
    fn test_packet_write_overwrites() {
        with_csp_node(|_node| {
            let mut pkt = Packet::get(64).expect("should get packet");

            // Write some data
            pkt.write(b"hello").expect("should write");
            assert_eq!(pkt.length(), 5);
            assert_eq!(pkt.data(), b"hello");

            // Write again - this overwrites, doesn't append
            pkt.write(b"world").expect("should write");
            assert_eq!(pkt.length(), 5);
            assert_eq!(pkt.data(), b"world");

            // Write longer data
            pkt.write(b"hello world").expect("should write");
            assert_eq!(pkt.length(), 11);
            assert_eq!(pkt.data(), b"hello world");
        });
    }

    #[test]
    fn test_packet_set_length() {
        with_csp_node(|_node| {
            let mut pkt = Packet::get(32).expect("should get packet");

            // Manually set length
            pkt.set_length(10);
            assert_eq!(pkt.length(), 10);

            // Length should be settable to 0
            pkt.set_length(0);
            assert_eq!(pkt.length(), 0);
        });
    }

    #[test]
    fn test_packet_id_manipulation() {
        with_csp_node(|_node| {
            let mut pkt = Packet::get(16).expect("should get packet");

            // Test setting and reading the raw ID
            let test_id: u32 = 0x12345678;
            pkt.set_id_raw(test_id);
            assert_eq!(pkt.id_raw(), test_id);

            // Verify we can extract fields from the ID
            // (actual values depend on the bit layout)
            let _prio = pkt.priority();
            let _src = pkt.src_addr();
            let _dst = pkt.dst_addr();
            let _sport = pkt.src_port();
            let _dport = pkt.dst_port();
            let _flags = pkt.flags();
        });
    }

    #[test]
    fn test_packet_flags() {
        with_csp_node(|_node| {
            let pkt = Packet::get(16).expect("should get packet");

            // Initially all flags should be false
            assert!(!pkt.is_rdp());
            assert!(!pkt.is_xtea());
            assert!(!pkt.is_hmac());
            assert!(!pkt.is_crc32());
            assert!(!pkt.is_frag());
        });
    }

    #[test]
    fn test_packet_data_mut() {
        with_csp_node(|_node| {
            let mut pkt = Packet::get(32).expect("should get packet");

            // Write initial data
            pkt.write(b"test").unwrap();

            // Modify through data_mut
            let data = pkt.data_mut();
            data[0] = b'T';
            data[1] = b'E';

            assert_eq!(pkt.data(), b"TEst");
        });
    }

    #[test]
    fn test_packet_reuse_buffer() {
        with_csp_node(|_node| {
            // Allocate and free a packet
            {
                let mut pkt = Packet::get(32).expect("should get packet");
                pkt.write(b"old data").unwrap();
                // pkt is dropped here, returned to pool
            }

            // Allocate again - might get the same buffer
            let pkt = Packet::get(32).expect("should get packet");

            // Should be initialized to clean state despite buffer reuse
            assert_eq!(pkt.length(), 0);
            assert_eq!(pkt.id_raw(), 0);
        });
    }
}
