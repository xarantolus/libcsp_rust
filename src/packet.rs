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
use core::ffi::c_void;
use core::slice;

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
        let ptr = unsafe {
            sys::csp_buffer_get(data_size) as *mut sys::csp_packet_t
        };
        if ptr.is_null() {
            None
        } else {
            Some(Packet { inner: ptr })
        }
    }

    /// Return the number of payload bytes currently marked as valid
    /// (the `length` field of the CSP packet header).
    #[inline]
    pub fn length(&self) -> u16 {
        unsafe { (*self.inner).length }
    }

    /// Set the payload length field.
    ///
    /// You **must** call this before sending a packet to tell CSP how many
    /// bytes to transmit.
    #[inline]
    pub fn set_length(&mut self, len: u16) {
        unsafe { (*self.inner).length = len; }
    }

    /// Return the raw 32-bit CSP header (priority, addresses, ports, flags).
    #[inline]
    pub fn id_raw(&self) -> u32 {
        unsafe { (*self.inner).id.ext }
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
        let cap = unsafe { sys::csp_buffer_data_size() };
        unsafe {
            slice::from_raw_parts_mut(
                (self.inner as *mut u8).add(DATA_OFFSET),
                cap,
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
    pub(crate) fn into_raw(self) -> *mut sys::csp_packet_t {
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
    pub(crate) unsafe fn from_raw(ptr: *mut sys::csp_packet_t) -> Self {
        Packet { inner: ptr }
    }
}

impl Drop for Packet {
    fn drop(&mut self) {
        // Safety: `inner` is a valid pointer obtained from csp_buffer_get.
        unsafe { sys::csp_buffer_free(self.inner as *mut c_void) }
    }
}

// CSP packets live in a pool that is protected by internal OS primitives, so
// passing a packet between threads is safe.
unsafe impl Send for Packet {}

impl core::fmt::Debug for Packet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Packet")
            .field("length", &self.length())
            .field("id_raw", &format_args!("0x{:08x}", self.id_raw()))
            .finish()
    }
}
