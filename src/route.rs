/*
Cubesat Space Protocol - A small network-layer protocol designed for Cubesats
Copyright (C) 2012 GomSpace ApS (http://www.gomspace.com)
Copyright (C) 2012 AAUSAT3 Project (http://aausat3.space.aau.dk)

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.
*/

//! Safe wrappers for the CSP routing table (`csp_rtable.h`).
//!
//! The routing table maps destination CSP addresses (with optional CIDR-style
//! masks) to a network interface and an optional "via" address.
//!
//! ## Typical usage
//!
//! ```no_run
//! use libcsp::{CspConfig, route};
//!
//! let node = CspConfig::new().address(1).init().unwrap();
//!
//! // Load a full table from a compact string (most ergonomic)
//! route::load("0/0 LOOP").unwrap();          // default route → loopback
//!
//! // Or add individual entries programmatically:
//! // route::set_raw(2, 5, unsafe { get_my_iface() }, route::NO_VIA).unwrap();
//! ```

extern crate alloc;

use alloc::ffi::CString;
#[allow(unused_imports)]
use alloc::vec;
use alloc::vec::Vec; // bring vec! macro into scope for no_std

use crate::error::csp_result;
use crate::sys;
use crate::Result;

/// Sentinel for "send directly to destination address" (no via relay).
///
/// Maps to `CSP_NO_VIA_ADDRESS = 0xFF`.
pub const NO_VIA: u8 = 0xFF;

// ── Individual route entry ────────────────────────────────────────────────────

/// Add or update a single route in the routing table.
///
/// - `dest_address` — CSP destination node address (0–31; use 31 for broadcast
///   or `0xFF + 1` = 32 as `CSP_DEFAULT_ROUTE` for the catch-all).
/// - `mask` — number of significant bits in the address (like CIDR prefix
///   length).  Pass `CSP_ID_HOST_SIZE` (5) for a host-specific route.
/// - `iface` — raw pointer to the interface to use.  Obtain this from an
///   interface init function (e.g. `sys::csp_if_lo`).
/// - `via` — relay address; use [`NO_VIA`] (0xFF) to send directly to
///   `dest_address`.
///
/// # Safety
/// `iface` must be a valid, initialised `csp_iface_t *` for the lifetime of
/// the route.
pub unsafe fn set_raw(
    dest_address: u8,
    mask: u8,
    iface: *mut sys::csp_iface_t,
    via: u8,
) -> Result<()> {
    // Safety: `iface` is assumed to be a valid pointer provided by the caller.
    // `sys::csp_rtable_set` is thread-safe.
    csp_result(sys::csp_rtable_set(dest_address, mask, iface, via))
}

// ── Bulk load / save ──────────────────────────────────────────────────────────

/// Load routing table entries from a compact string.
///
/// Entries are separated by `,`.  Each entry has the form:
/// ```text
/// <address>[/<mask>] <interface-name> [<via-address>]
/// ```
///
/// **Examples:**
/// ```text
/// "0/0 LOOP"                   // all traffic → loopback
/// "0/0 CAN, 8 KISS, 10 I2C 10" // mixed routes; node 10 reachable via address 10
/// ```
///
/// Returns `Ok(n)` where `n` is the number of entries loaded, or a
/// [`CspError`](crate::CspError) on failure.
///
/// # Errors
/// Returns an error if any entry is malformed or references an unknown
/// interface name.
pub fn load(table: &str) -> Result<usize> {
    let cstr = CString::new(table).map_err(|_| crate::CspError::InvalidArgument)?;
    // Safety: `cstr` is a valid C-string. `sys::csp_rtable_load` is thread-safe.
    let ret = unsafe { sys::csp_rtable_load(cstr.as_ptr()) };
    if ret >= 0 {
        // Safety: Underlying C function returns the number of routes loaded (>= 0).
        Ok(ret as usize)
    } else {
        Err(crate::CspError::from_code(ret))
    }
}

/// Check a routing-table string for validity **without** applying it.
///
/// Returns `Ok(n)` (number of valid entries found) or a
/// [`CspError`](crate::CspError) on failure.
pub fn check(table: &str) -> Result<usize> {
    let cstr = CString::new(table).map_err(|_| crate::CspError::InvalidArgument)?;
    // Safety: `cstr` is a valid C-string. `sys::csp_rtable_check` is thread-safe.
    let ret = unsafe { sys::csp_rtable_check(cstr.as_ptr()) };
    if ret >= 0 {
        // Safety: Underlying C function returns the number of routes found (>= 0).
        Ok(ret as usize)
    } else {
        Err(crate::CspError::from_code(ret))
    }
}

/// Save the current routing table to a string in the same format accepted by
/// [`load`].
///
/// Returns the table string on success, or a [`CspError`](crate::CspError) if
/// the internal buffer was too small (increase `buf_size` or use the default
/// of 256).
pub fn save(buf_size: usize) -> Result<alloc::string::String> {
    let mut buf: Vec<u8> = vec![0u8; buf_size];

    // Safety: `buf` is a valid vector. `sys::csp_rtable_save` is thread-safe.
    let ret = unsafe { sys::csp_rtable_save(buf.as_mut_ptr() as *mut core::ffi::c_char, buf_size) };
    csp_result(ret)?;

    // Find the NUL terminator and truncate.
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf_size);
    buf.truncate(end);
    alloc::string::String::from_utf8(buf).map_err(|_| crate::CspError::InvalidArgument)
}

// ── Table management ──────────────────────────────────────────────────────────

/// Clear the routing table and re-add only the loopback route.
pub fn clear() {
    // Safety: `sys::csp_rtable_clear` is thread-safe.
    unsafe { sys::csp_rtable_clear() }
}

/// Clear **all** routing table entries, including the loopback route.
pub fn free_all() {
    // Safety: `sys::csp_rtable_free` is thread-safe.
    unsafe { sys::csp_rtable_free() }
}

/// Print the routing table to stdout (requires `debug` feature / `CSP_DEBUG`).
#[cfg(feature = "debug")]
pub fn print() {
    // Safety: `sys::csp_rtable_print` is thread-safe.
    unsafe { sys::csp_rtable_print() }
}

// ── Route lookup ──────────────────────────────────────────────────────────────

/// Look up the route for a destination address.
///
/// Returns a [`RouteEntry`] on success, or `None` if no route is found.
pub fn find(dest_address: u8) -> Option<RouteEntry> {
    // Safety: `sys::csp_rtable_find_route` is thread-safe and returns a valid
    // pointer or NULL.
    let ptr = unsafe { sys::csp_rtable_find_route(dest_address) };
    if ptr.is_null() {
        None
    } else {
        Some(RouteEntry { inner: ptr })
    }
}

/// A read-only view of a routing table entry.
///
/// Returned by [`find`].  The underlying memory is owned by the CSP routing
/// table; this struct is only valid as long as the table entry is not removed.
pub struct RouteEntry {
    inner: *const sys::csp_route_t,
}

impl RouteEntry {
    /// The "via" relay address (`NO_VIA` = 0xFF means direct delivery).
    pub fn via(&self) -> u8 {
        // Safety: `inner` is a valid pointer to a route entry.
        unsafe { (*self.inner).via }
    }

    /// Raw pointer to the interface.  Use the `sys` module for advanced
    /// interface inspection.
    pub fn iface_ptr(&self) -> *const sys::csp_iface_t {
        // Safety: `inner` is a valid pointer to a route entry.
        unsafe { (*self.inner).iface }
    }
}

/// Iterate over all entries in the routing table.
///
/// The closure `f` is called for each entry with:
/// 1. Destination address (u8)
/// 2. Mask (u8)
/// 3. The route entry details
///
/// Return `true` to continue iterating, or `false` to stop.
pub fn iterate<F>(f: F)
where
    F: FnMut(u8, u8, RouteEntry) -> bool,
{
    unsafe extern "C" fn shim<F>(
        ctx: *mut core::ffi::c_void,
        address: u8,
        mask: u8,
        route: *const sys::csp_route_t,
    ) -> bool
    where
        F: FnMut(u8, u8, RouteEntry) -> bool,
    {
        // Safety: `ctx` is a valid pointer to the closure `F`.
        // `route` is a valid pointer provided by libcsp.
        let f = &mut *(ctx as *mut F);
        f(address, mask, RouteEntry { inner: route })
    }

    let mut f_ref = f;
    // Safety: `sys::csp_rtable_iterate` is thread-safe.
    unsafe {
        sys::csp_rtable_iterate(
            Some(shim::<F>),
            &mut f_ref as *mut F as *mut core::ffi::c_void,
        );
    }
}

impl core::fmt::Debug for RouteEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let via = self.via();
        f.debug_struct("RouteEntry")
            .field(
                "via",
                &if via == NO_VIA {
                    "DIRECT".into()
                } else {
                    alloc::format!("{via}")
                },
            )
            .finish()
    }
}
