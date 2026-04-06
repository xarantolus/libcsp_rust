//! Safe CAN interface for embedded CSP.
//!
//! Wraps libcsp's CAN fragmentation protocol (CFP) layer, providing a safe API
//! to register a CAN interface and feed received CAN frames to CSP.

extern crate alloc;

use alloc::boxed::Box;
use alloc::ffi::CString;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ptr;

use crate::sys;

/// Trait for a CAN driver that can transmit raw CAN frames.
///
/// Implement this for your hardware-specific CAN peripheral.
#[allow(clippy::result_unit_err)]
pub trait CanDriver: Send {
    /// Transmit a single CAN frame.
    ///
    /// - `id`: 29-bit extended CAN identifier (CFP-encoded).
    /// - `data`: frame payload (up to 8 bytes).
    /// - `dlc`: data length code.
    ///
    /// Returns `Ok(())` on success, `Err(())` on failure.
    fn transmit(&mut self, id: u32, data: &[u8], dlc: u8) -> core::result::Result<(), ()>;
}

/// Handle for a registered CAN interface.
///
/// Must be kept alive for the lifetime of the interface. Use [`feed_rx`] to
/// pass received CAN frames to the CSP stack.
///
/// [`feed_rx`]: CanInterfaceHandle::feed_rx
pub struct CanInterfaceHandle {
    inner: Box<CanInterfaceInner>,
}

// Safety: the CanInterfaceHandle is only accessed from contexts where CSP
// operations are safe (single CSP work context or IRQ-protected).
unsafe impl Send for CanInterfaceHandle {}
unsafe impl Sync for CanInterfaceHandle {}

struct CanInterfaceInner {
    driver: spin::Mutex<Box<dyn CanDriver>>,
    c_iface: UnsafeCell<sys::csp_iface_t>,
    can_data: UnsafeCell<sys::csp_can_interface_data_t>,
    _c_name: CString,
}

// Safety: same reasoning as CanInterfaceHandle.
unsafe impl Send for CanInterfaceInner {}
unsafe impl Sync for CanInterfaceInner {}

/// Register a CAN interface with the CSP stack.
///
/// - `name`: interface name (e.g. `"CAN"`)
/// - `driver`: your [`CanDriver`] implementation
///
/// Returns a [`CanInterfaceHandle`] that must be kept alive. Use it to feed
/// received CAN frames via [`CanInterfaceHandle::feed_rx`].
pub fn add_interface(
    name: &str,
    driver: impl CanDriver + 'static,
) -> crate::Result<CanInterfaceHandle> {
    let c_name = CString::new(name).map_err(|_| crate::CspError::InvalidArgument)?;

    let inner = Box::new(CanInterfaceInner {
        driver: spin::Mutex::new(Box::new(driver)),
        c_iface: UnsafeCell::new(unsafe { core::mem::zeroed() }),
        can_data: UnsafeCell::new(unsafe { core::mem::zeroed() }),
        _c_name: c_name,
    });

    unsafe {
        let can_data = inner.can_data.get();
        (*can_data).tx_func = Some(can_tx_trampoline);

        let c_iface = inner.c_iface.get();
        (*c_iface).name = inner._c_name.as_ptr();
        // Store a pointer to inner as driver_data so the TX callback can find us.
        (*c_iface).driver_data = &*inner as *const CanInterfaceInner as *mut c_void;
        (*c_iface).interface_data = can_data as *mut c_void;

        let rc = sys::csp_can_add_interface(c_iface);
        if rc != 0 {
            return Err(crate::CspError::DriverError);
        }
    }

    Ok(CanInterfaceHandle { inner })
}

impl CanInterfaceHandle {
    /// Feed a received CAN frame to the CSP stack.
    ///
    /// Call this from your CAN RX polling loop or interrupt handler.
    ///
    /// - `id`: the 29-bit extended CAN identifier
    /// - `data`: frame payload
    /// - `dlc`: data length code
    pub fn feed_rx(&self, id: u32, data: &[u8], dlc: u8) {
        unsafe {
            sys::csp_can_rx(
                self.inner.c_iface.get(),
                id,
                data.as_ptr(),
                dlc,
                ptr::null_mut(),
            );
        }
    }

    /// Get the raw C interface pointer (for use with `csp_rtable_set`, etc).
    pub fn c_iface_ptr(&self) -> *mut sys::csp_iface_t {
        self.inner.c_iface.get()
    }
}

/// C callback invoked by libcsp's CAN TX path. Forwards to the Rust CanDriver.
unsafe extern "C" fn can_tx_trampoline(
    driver_data: *mut c_void,
    id: u32,
    data: *const u8,
    dlc: u8,
) -> i32 {
    if driver_data.is_null() || data.is_null() {
        return -1;
    }
    let inner = unsafe { &*(driver_data as *const CanInterfaceInner) };
    let slice = unsafe { core::slice::from_raw_parts(data, dlc as usize) };
    match inner.driver.lock().transmit(id, slice, dlc) {
        Ok(()) => 0,
        Err(()) => -1,
    }
}
