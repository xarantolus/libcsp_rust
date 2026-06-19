/*
Cubesat Space Protocol - A small network-layer protocol designed for Cubesats
Copyright (C) 2012 GomSpace ApS (http://www.gomspace.com)
Copyright (C) 2012 AAUSAT3 Project (http://aausat3.space.aau.dk)

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.
*/

//! Safe wrappers for the libcsp interface list and per-interface direct send.
//!
//! libcsp keeps a global linked list of registered `csp_iface_t` structures
//! (one per interface registered via [`crate::interface::register`] or the
//! built-in CAN/loopback drivers). The functions here let callers enumerate
//! that list and target a specific interface for transmission, bypassing the
//! routing table.

extern crate alloc;

use core::ffi::{c_char, c_int};
use core::ptr::NonNull;

use alloc::ffi::CString;
use alloc::string::String;
use alloc::vec::Vec;

use crate::sys;
use crate::Packet;

// `csp_send_direct_iface` is declared in the private header
// `port/libcsp/src/csp_io.h` (not in `include/csp/`), so bindgen does not
// pick it up. The symbol is exported by the library; declare the extern by
// hand and keep the unsafety contained inside [`send_via`].
extern "C" {
    fn csp_send_direct_iface(
        idout: *const sys::csp_id_t,
        packet: *mut sys::csp_packet_t,
        iface: *mut sys::csp_iface_t,
        via: u16,
        from_me: c_int,
    );
}

/// Opaque handle to a registered libcsp interface.
///
/// Obtain one via [`lookup`]. The pointer is owned by libcsp's global
/// interface list and remains valid for the lifetime of the process (libcsp
/// never frees registered interfaces).
#[derive(Clone, Copy)]
pub struct IfaceRef {
    ptr: NonNull<sys::csp_iface_t>,
}

// libcsp guards the iface list internally; the pointer is `'static` once
// registered.
unsafe impl Send for IfaceRef {}
unsafe impl Sync for IfaceRef {}

impl IfaceRef {
    /// The interface's registered name.
    pub fn name(&self) -> &str {
        unsafe {
            let p = self.ptr.as_ref().name;
            if p.is_null() {
                return "";
            }
            core::ffi::CStr::from_ptr(p).to_str().unwrap_or("")
        }
    }

    /// Raw pointer for callers that need to hand it to other libcsp APIs.
    pub fn as_ptr(&self) -> *mut sys::csp_iface_t {
        self.ptr.as_ptr()
    }
}

impl core::fmt::Debug for IfaceRef {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IfaceRef")
            .field("name", &self.name())
            .finish()
    }
}

/// Look up a registered interface by name. Returns `None` if no interface
/// with that name is currently registered.
pub fn lookup(name: &str) -> Option<IfaceRef> {
    let c_name = CString::new(name).ok()?;
    let ptr = unsafe { sys::csp_iflist_get_by_name(c_name.as_ptr() as *const c_char) };
    NonNull::new(ptr).map(|p| IfaceRef { ptr: p })
}

/// Snapshot the names of every currently-registered interface, in
/// registration order.
pub fn list_names() -> Vec<String> {
    let mut names = Vec::new();
    let mut cur: *mut sys::csp_iface_t = core::ptr::null_mut();
    unsafe {
        loop {
            cur = sys::csp_iflist_iterate(cur);
            if cur.is_null() {
                break;
            }
            let n_ptr = (*cur).name;
            if n_ptr.is_null() {
                continue;
            }
            if let Ok(s) = core::ffi::CStr::from_ptr(n_ptr).to_str() {
                names.push(String::from(s));
            }
        }
    }
    names
}

/// Per-interface counters snapshotted from the C struct fields.
#[derive(Debug, Clone, Copy, Default)]
pub struct IfaceStats {
    pub tx: u32,
    pub rx: u32,
    pub tx_error: u32,
    pub rx_error: u32,
    pub drop: u32,
    pub txbytes: u32,
    pub rxbytes: u32,
}

/// Read the counter block for one interface. The counters are u32 in libcsp
/// and may wrap on long-lived nodes.
pub fn stats(iface: IfaceRef) -> IfaceStats {
    unsafe {
        let r = iface.ptr.as_ref();
        IfaceStats {
            tx: r.tx,
            rx: r.rx,
            tx_error: r.tx_error,
            rx_error: r.rx_error,
            drop: r.drop,
            txbytes: r.txbytes,
            rxbytes: r.rxbytes,
        }
    }
}

/// Send a packet out a specific interface, bypassing the route table.
///
/// libcsp takes ownership of the packet buffer: it will be freed after
/// transmission regardless of success.
///
/// - `via`: next-hop CSP address. Pass [`crate::route::NO_VIA`] for direct
///   delivery to `packet.id.dst`.
/// - `from_me`: `true` for packets generated locally (libcsp will apply HMAC
///   / CRC32 / RDP framing as needed), `false` when forwarding a packet
///   received from another interface.
///
/// Returns immediately — `csp_send_direct_iface` is fire-and-forget at the
/// C layer (no synchronous failure path exposed; failures surface via the
/// iface's `tx_error` counter).
pub fn send_via(packet: Packet, iface: IfaceRef, via: u16, from_me: bool) {
    let id = packet.id();
    let raw = packet.into_raw();
    unsafe {
        csp_send_direct_iface(
            &id as *const sys::csp_id_t,
            raw,
            iface.as_ptr(),
            via,
            from_me as c_int,
        );
    }
}
