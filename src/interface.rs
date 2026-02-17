//! Safe custom interface (transport) support.
//!
//! This module allows implementing custom CSP interfaces (e.g. for CAN, UART,
//! or custom hardware) by implementing the [`CspInterface`] trait.

extern crate alloc;
use alloc::ffi::CString;
use alloc::boxed::Box;
use core::ffi::c_void;

use crate::sys;
use crate::Packet;

/// Trait for implementing a custom CSP interface.
pub trait CspInterface: Send {
    /// Called by the CSP router when a packet needs to be sent out.
    ///
    /// - `via`: Next-hop destination address.
    /// - `packet`: The packet to transmit.
    ///
    /// The implementation **must** ensure the packet is eventually freed (by
    /// letting the `Packet` drop or passing it back to CSP).
    fn nexthop(&mut self, via: u8, packet: Packet);

    /// Return the name of this interface.
    fn name(&self) -> &str;
}

/// Registration handle for a custom interface.
///
/// Keeps the interface state and the C-compatible callback pointers alive.
pub struct InterfaceHandle {
    _inner: Box<InterfaceState>,
}

struct InterfaceState {
    user_iface: Box<dyn CspInterface>,
    c_iface: sys::csp_iface_t,
    c_name: CString,
}

/// Register a custom interface with the CSP stack.
///
/// Returns an [`InterfaceHandle`] that must be kept alive for as long as
/// the interface is in use.
pub fn register<I: CspInterface + 'static>(interface: I) -> InterfaceHandle {
    let name = interface.name().to_string();
    let c_name = CString::new(name).unwrap();
    
    let mut state = Box::new(InterfaceState {
        user_iface: Box::new(interface),
        c_iface: unsafe { core::mem::zeroed() },
        c_name,
    });

    state.c_iface.name = state.c_name.as_ptr();
    state.c_iface.nexthop = Some(nexthop_shim);
    state.c_iface.interface_data = &mut *state as *mut InterfaceState as *mut c_void;
    state.c_iface.mtu = unsafe { sys::csp_buffer_data_size() } as u16;

    unsafe {
        sys::csp_iflist_add(&mut state.c_iface);
    }

    InterfaceHandle { _inner: state }
}

impl InterfaceHandle {
    /// Hand a received packet to the CSP router.
    ///
    /// Call this from your hardware RX interrupt or task when a new packet
    /// arrives.
    pub fn rx(&self, packet: Packet) {
        unsafe {
            let raw = packet.into_raw();
            sys::csp_qfifo_write(raw, &self._inner.c_iface as *const _ as *mut _, core::ptr::null_mut());
        }
    }
    
    /// Get the raw C interface pointer (for use with `sys::csp_rtable_set` etc).
    pub fn c_iface_ptr(&self) -> *mut sys::csp_iface_t {
        &self._inner.c_iface as *const _ as *mut _
    }
}

/// C-compatible shim that forwards the nexthop call to the Rust trait.
unsafe extern "C" fn nexthop_shim(route: *const sys::csp_route_t, packet: *mut sys::csp_packet_t) -> i32 {
    let iface = (*route).iface;
    let state_ptr = (*iface).interface_data as *mut InterfaceState;
    let state = &mut *state_ptr;
    
    let pkt = Packet::from_raw(packet);
    state.user_iface.nexthop((*route).via, pkt);
    
    0 // CSP_ERR_NONE
}
