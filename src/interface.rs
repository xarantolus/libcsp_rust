//! Safe custom interface (transport) support.
//!
//! This module allows implementing custom CSP interfaces (e.g. for CAN, UART,
//! or custom hardware) by implementing the [`CspInterface`] trait.

extern crate alloc;
use alloc::ffi::CString;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::string::ToString;
use core::ffi::c_void;
use core::cell::UnsafeCell;

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
/// This handle is internally reference-counted and can be cloned safely.
#[derive(Clone)]
pub struct InterfaceHandle {
    _inner: Arc<InterfaceState>,
}

// Safety: InterfaceHandle is an opaque handle to CSP data structures.
// InterfaceState uses UnsafeCell for the C struct (handled by C/libcsp locking)
// and Spin Mutex for the user trait object.
unsafe impl Send for InterfaceHandle {}
unsafe impl Sync for InterfaceHandle {}

struct InterfaceState {
    user_iface: spin::Mutex<Box<dyn CspInterface>>,
    // Wrapped in UnsafeCell because C library mutates it (counters, next pointers)
    // while we hold a shared reference (Arc).
    c_iface: UnsafeCell<sys::csp_iface_t>,
    // Kept alive so that `c_iface.name` (a raw pointer into this CString)
    // remains valid for the lifetime of the interface registration.
    _c_name: CString,
}

// Safety: InterfaceState is Sync because the mutable `c_iface` part is managed
// by libcsp's internal synchronization (or we assume single-threaded setup/usage patterns
// compatible with libcsp constraints), and `user_iface` is protected by a Mutex.
unsafe impl Sync for InterfaceState {}

/// Register a custom interface with the CSP stack.
///
/// Returns an [`InterfaceHandle`] that must be kept alive for as long as
/// the interface is in use.
pub fn register<I: CspInterface + 'static>(interface: I) -> InterfaceHandle {
    let name = interface.name().to_string();
    let c_name = CString::new(name).unwrap();
    
    // Safety: Creating a zeroed struct is safe as it's passed to C.
    let mut c_iface: sys::csp_iface_t = unsafe { core::mem::zeroed() };
    c_iface.name = c_name.as_ptr();
    c_iface.nexthop = Some(nexthop_shim);
    // Safety: libcsp is assumed to be initialised.
    c_iface.mtu = unsafe { sys::csp_buffer_data_size() } as u16;

    let state = Arc::new(InterfaceState {
        user_iface: spin::Mutex::new(Box::new(interface)),
        c_iface: UnsafeCell::new(c_iface),
        _c_name: c_name,
    });

    let state_ptr = Arc::as_ptr(&state) as *mut InterfaceState;
    // Safety: `state_ptr` is valid as it comes from an active `Arc`.
    // `sys::csp_iflist_add` is thread-safe.
    unsafe {
        // We need to write the self-pointer into the struct inside the Arc.
        // UnsafeCell::get() gives us a raw pointer to the inner data.
        let iface_ptr = (*state_ptr).c_iface.get();
        (*iface_ptr).interface_data = state_ptr as *mut c_void;
        sys::csp_iflist_add(iface_ptr);
    }

    InterfaceHandle { _inner: state }
}

impl InterfaceHandle {
    /// Hand a received packet to the CSP router.
    ///
    /// Call this from your hardware RX interrupt or task when a new packet
    /// arrives.
    pub fn rx(&self, packet: Packet) {
        // Safety: `self._inner` is valid. `packet.into_raw()` relinquishes ownership.
        unsafe {
            let raw = packet.into_raw();
            sys::csp_qfifo_write(raw, self._inner.c_iface.get(), core::ptr::null_mut());
        }
    }
    
    /// Get the raw C interface pointer (for use with `sys::csp_rtable_set` etc).
    pub fn c_iface_ptr(&self) -> *mut sys::csp_iface_t {
        self._inner.c_iface.get()
    }
}

/// C-compatible shim that forwards the nexthop call to the Rust trait.
unsafe extern "C" fn nexthop_shim(route: *const sys::csp_route_t, packet: *mut sys::csp_packet_t) -> i32 {
    // Safety: `route` and `packet` are valid pointers provided by libcsp.
    // `interface_data` is a valid pointer to `InterfaceState`.
    let iface = (*route).iface;
    // Note: (*iface).interface_data was set to `*mut InterfaceState` in register().
    let state_ptr = (*iface).interface_data as *mut InterfaceState;
    let state = &*state_ptr;
    
    let pkt = Packet::from_raw(packet);
    state.user_iface.lock().nexthop((*route).via, pkt);
    
    0 // CSP_ERR_NONE
}
