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
//! Maps destination CSP addresses (with optional CIDR-style masks) to a
//! network interface and an optional "via" address.
//!
//! ## Typical usage
//!
//! ```no_run
//! use libcsp::{CspConfig, route};
//!
//! let node = CspConfig::new().address(1).init().unwrap();
//!
//! // Load a full table from a compact string (most ergonomic)
//! route::load("0/0 LOOP").unwrap();
//!
//! // Or add individual entries programmatically:
//! // unsafe { route::set_raw(2, 5, get_my_iface(), route::NO_VIA) }.unwrap();
//! ```

extern crate alloc;

use alloc::ffi::CString;
#[allow(unused_imports)]
use alloc::vec;
use alloc::vec::Vec;

use crate::error::csp_result;
use crate::sys;
use crate::Result;

/// Sentinel for "send directly to destination address" (no via relay).
pub const NO_VIA: u16 = sys::CSP_NO_VIA_ADDRESS as u16;

/// Set the default route (catch-all) to a given interface.
///
/// # Safety
/// `iface` must be a valid, initialised `csp_iface_t *` for the lifetime of the route.
pub unsafe fn set_default(iface: *mut sys::csp_iface_t) -> Result<()> {
    unsafe { set_raw(0, 0, iface, NO_VIA) }
}

/// Set the default route via a CAN interface handle.
pub fn set_default_can(handle: &crate::CanInterfaceHandle) -> Result<()> {
    unsafe { set_default(handle.c_iface_ptr()) }
}

// ── Individual route entry ────────────────────────────────────────────────────

/// Add or update a single route in the routing table.
///
/// - `dest_address` — CSP destination node address.
/// - `mask` — number of significant bits in the address (CIDR prefix length).
///   Pass `0` for a default route (all-match).
/// - `iface` — raw pointer to the interface to use.
/// - `via` — relay address; use [`NO_VIA`] to send directly to `dest_address`.
///
/// # Safety
/// `iface` must be a valid, initialised `csp_iface_t *` for the lifetime of
/// the route.
pub unsafe fn set_raw(
    dest_address: u16,
    mask: u8,
    iface: *mut sys::csp_iface_t,
    via: u16,
) -> Result<()> {
    csp_result(sys::csp_rtable_set(
        dest_address,
        mask as core::ffi::c_int,
        iface,
        via,
    ))
}

// ── Bulk load / save ──────────────────────────────────────────────────────────

/// Load routing table entries from a compact string.
///
/// Entries are separated by `,`. Each entry has the form:
/// ```text
/// <address>[/<mask>] <interface-name> [<via-address>]
/// ```
///
/// Only available when libcsp is built with stdio support (i.e. not on
/// `external-arch` targets).
#[cfg(not(feature = "external-arch"))]
pub fn load(table: &str) -> Result<usize> {
    let cstr = CString::new(table).map_err(|_| crate::CspError::InvalidArgument)?;
    let ret = unsafe { sys::csp_rtable_load(cstr.as_ptr()) };
    if ret >= 0 {
        Ok(ret as usize)
    } else {
        Err(crate::CspError::from_code(ret))
    }
}

/// Load is unavailable on `external-arch` builds; always returns
/// [`CspError::NotImplemented`].
///
/// [`CspError::NotImplemented`]: crate::CspError::NotImplemented
#[cfg(feature = "external-arch")]
pub fn load(_table: &str) -> Result<usize> {
    Err(crate::CspError::NotImplemented)
}

/// Check a routing-table string for validity **without** applying it.
#[cfg(not(feature = "external-arch"))]
pub fn check(table: &str) -> Result<usize> {
    let cstr = CString::new(table).map_err(|_| crate::CspError::InvalidArgument)?;
    let ret = unsafe { sys::csp_rtable_check(cstr.as_ptr()) };
    if ret >= 0 {
        Ok(ret as usize)
    } else {
        Err(crate::CspError::from_code(ret))
    }
}

#[cfg(feature = "external-arch")]
pub fn check(_table: &str) -> Result<usize> {
    Err(crate::CspError::NotImplemented)
}

/// Save the current routing table to a string in the same format accepted by
/// [`load`].
#[cfg(not(feature = "external-arch"))]
pub fn save(buf_size: usize) -> Result<alloc::string::String> {
    let mut buf: Vec<u8> = vec![0u8; buf_size];

    let ret = unsafe { sys::csp_rtable_save(buf.as_mut_ptr() as *mut core::ffi::c_char, buf_size) };
    csp_result(ret)?;

    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf_size);
    buf.truncate(end);
    alloc::string::String::from_utf8(buf).map_err(|_| crate::CspError::InvalidArgument)
}

#[cfg(feature = "external-arch")]
pub fn save(_buf_size: usize) -> Result<alloc::string::String> {
    Err(crate::CspError::NotImplemented)
}

// ── Table management ──────────────────────────────────────────────────────────

/// Clear the routing table and re-add only the loopback route.
pub fn clear() {
    unsafe { sys::csp_rtable_clear() }
}

/// Clear **all** routing table entries, including the loopback route.
pub fn free_all() {
    unsafe { sys::csp_rtable_free() }
}

/// Print the routing table to stdout (requires `debug` feature / `CSP_DEBUG`).
#[cfg(feature = "debug")]
pub fn print() {
    unsafe { sys::csp_rtable_print() }
}

// ── Route lookup ──────────────────────────────────────────────────────────────

/// Look up the route for a destination address.
pub fn find(dest_address: u16) -> Option<RouteEntry> {
    let ptr = unsafe { sys::csp_rtable_find_route(dest_address) };
    if ptr.is_null() {
        None
    } else {
        Some(RouteEntry { inner: ptr })
    }
}

/// A read-only view of a routing table entry.
///
/// Returned by [`find`]. The underlying memory is owned by the CSP routing
/// table; this struct is only valid as long as the table entry is not removed.
pub struct RouteEntry {
    inner: *const sys::csp_route_t,
}

impl RouteEntry {
    /// Destination address matched by this entry.
    pub fn address(&self) -> u16 {
        unsafe { (*self.inner).address }
    }

    /// Prefix length (CIDR netmask).
    pub fn netmask(&self) -> u16 {
        unsafe { (*self.inner).netmask }
    }

    /// The "via" relay address ([`NO_VIA`] means direct delivery).
    pub fn via(&self) -> u16 {
        unsafe { (*self.inner).via }
    }

    /// Raw pointer to the interface.
    pub fn iface_ptr(&self) -> *const sys::csp_iface_t {
        unsafe { (*self.inner).iface }
    }
}

/// Iterate over all entries in the routing table.
///
/// Return `true` from the closure to continue iterating, or `false` to stop.
pub fn iterate<F>(f: F)
where
    F: FnMut(RouteEntry) -> bool,
{
    unsafe extern "C" fn shim<F>(
        ctx: *mut core::ffi::c_void,
        route: *mut sys::csp_route_t,
    ) -> bool
    where
        F: FnMut(RouteEntry) -> bool,
    {
        let f = &mut *(ctx as *mut F);
        f(RouteEntry { inner: route })
    }

    let mut f_ref = f;
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
            .field("address", &self.address())
            .field("netmask", &self.netmask())
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
