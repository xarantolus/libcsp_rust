//! Safe custom interface (transport) support.
//!
//! This module allows implementing custom CSP interfaces (e.g. for CAN, UART,
//! or custom hardware) by implementing the [`CspInterface`] trait.

extern crate alloc;
use alloc::boxed::Box;
use alloc::ffi::CString;
use alloc::string::ToString;
use core::cell::UnsafeCell;
use core::ffi::c_void;

use crate::sys;
use crate::Packet;

/// Trait for implementing a custom CSP interface.
pub trait CspInterface: Send {
    /// Called by the CSP router when a packet needs to be sent out.
    ///
    /// - `via`: Next-hop destination address.
    /// - `packet`: The packet to transmit.
    /// - `from_me`: `true` if the packet was generated locally rather than
    ///   forwarded through this node.
    ///
    /// The implementation **must** ensure the packet is eventually freed (by
    /// letting the `Packet` drop or passing it back to CSP).
    fn nexthop(&mut self, via: u16, packet: Packet, from_me: bool);

    /// Return the name of this interface.
    fn name(&self) -> &str;
}

/// Registration handle for a custom interface.
///
/// Holds a pointer to leaked `'static` storage shared with the CSP router.
/// The handle itself is `Copy` and dropping it does **not** unregister the
/// interface — the `init-once / run forever` model intentionally keeps the
/// interface registered for the lifetime of the process.
#[derive(Clone, Copy)]
pub struct InterfaceHandle {
    state: &'static InterfaceState,
}

// Safety: see InterfaceState; the handle just holds a shared reference.
unsafe impl Send for InterfaceHandle {}
unsafe impl Sync for InterfaceHandle {}

struct InterfaceState {
    user_iface: spin::Mutex<Box<dyn CspInterface>>,
    // Wrapped in UnsafeCell because C library mutates it (counters, next pointers)
    // while we hold a shared reference.
    c_iface: UnsafeCell<sys::csp_iface_t>,
    // Kept alive so that `c_iface.name` (a raw pointer into this CString)
    // remains valid for the lifetime of the interface registration.
    _c_name: CString,
}

// Safety: `c_iface` is mutated only from libcsp under its internal locking;
// `user_iface` is protected by a Mutex.
unsafe impl Sync for InterfaceState {}

/// Register a custom interface with the CSP stack.
///
/// The interface state is leaked into static memory and never freed, matching
/// libcsp's "register once, run forever" lifecycle. Returns an
/// [`InterfaceHandle`] that can be cloned freely; dropping it does **not**
/// unregister the interface.
pub fn register<I: CspInterface + 'static>(interface: I) -> InterfaceHandle {
    let name = interface.name().to_string();
    let c_name = CString::new(name).unwrap();

    // Build the state on the heap so we can grab a stable address, then leak
    // it so the address is `'static` — libcsp keeps a pointer to `c_iface`
    // (and `c_iface.name` keeps a pointer into `_c_name`) for as long as the
    // process lives.
    let state: &'static InterfaceState = Box::leak(Box::new(InterfaceState {
        user_iface: spin::Mutex::new(Box::new(interface)),
        c_iface: UnsafeCell::new(unsafe { core::mem::zeroed() }),
        _c_name: c_name,
    }));

    // Initialise the C-side struct through `UnsafeCell::get` so we never form
    // a `&mut` to data that libcsp will subsequently mutate behind our back.
    unsafe {
        let iface_ptr = state.c_iface.get();
        (*iface_ptr).name = state._c_name.as_ptr();
        (*iface_ptr).nexthop = Some(nexthop_shim);
        (*iface_ptr).interface_data = state as *const InterfaceState as *mut c_void;
        sys::csp_iflist_add(iface_ptr);
    }

    InterfaceHandle { state }
}

impl InterfaceHandle {
    /// Hand a received packet to the CSP router.
    ///
    /// Call this from your hardware RX interrupt or task when a new packet
    /// arrives.
    ///
    /// ## Ownership semantics
    /// libcsp always takes ownership of the packet. If the internal router
    /// queue is full, libcsp will free the packet automatically.
    pub fn rx(&self, packet: Packet) {
        // Safety: `state` is `'static`. `packet.into_raw()` relinquishes
        // ownership; libcsp always takes ownership of the raw packet and
        // will free it if needed.
        unsafe {
            let raw = packet.into_raw();
            sys::csp_qfifo_write(raw, self.state.c_iface.get(), core::ptr::null_mut());
        }
    }

    /// Get the raw C interface pointer (for use with `sys::csp_rtable_set` etc).
    pub fn c_iface_ptr(&self) -> *mut sys::csp_iface_t {
        self.state.c_iface.get()
    }
}

/// C-compatible shim that forwards the nexthop call to the Rust trait.
///
/// Catches Rust panics so unwinding never crosses the C frame.
unsafe extern "C" fn nexthop_shim(
    iface: *mut sys::csp_iface_t,
    via: u16,
    packet: *mut sys::csp_packet_t,
    from_me: core::ffi::c_int,
) -> i32 {
    // Safety: `iface` is a valid pointer from libcsp; `interface_data` was
    // populated in `register()` with a `'static` pointer to `InterfaceState`.
    let state_ptr = (*iface).interface_data as *const InterfaceState;
    if state_ptr.is_null() || packet.is_null() {
        return sys::CSP_ERR_INVAL;
    }
    let state = &*state_ptr;

    crate::ffi_util::guard("nexthop_shim", || {
        let pkt = Packet::from_raw(packet);
        state.user_iface.lock().nexthop(via, pkt, from_me != 0);
    });

    0 // CSP_ERR_NONE
}
