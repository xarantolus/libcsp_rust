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

use crate::ffi_util;
use crate::sys;

/// CFP (CAN Fragmentation Protocol) layout constants and helpers.
///
/// libcsp packs source / destination addresses, a fragment flag, a
/// remaining-fragments counter and a connection identifier into the 29-bit
/// extended CAN ID. Mirrors the `CFP_*_SIZE` / `CFP_MAKE_*` macros in
/// `libcsp/include/csp/interfaces/csp_if_can.h`.
///
/// ```text
///  bit  28 .. 24 | 23 .. 19 | 18 | 17 .. 10 |  9 .. 0
///       src (5)  | dst (5)  | T  | remain(8)| id (10)
/// ```
pub mod cfp {
    /// Width of the src / dst host-address fields (bits).
    pub const HOST_BITS: u32 = 5;
    /// Width of the CFP fragment-type flag.
    pub const TYPE_BITS: u32 = 1;
    /// Width of the remaining-fragments counter.
    pub const REMAIN_BITS: u32 = 8;
    /// Width of the CFP connection-identifier field.
    pub const ID_BITS: u32 = 10;

    /// `(1 << HOST_BITS) - 1` — mask for one host-address field.
    pub const HOST_MASK: u32 = (1 << HOST_BITS) - 1;
    /// LSB position of the dst field inside the 29-bit CAN ID.
    pub const DST_SHIFT: u32 = TYPE_BITS + REMAIN_BITS + ID_BITS;
    /// LSB position of the src field inside the 29-bit CAN ID.
    pub const SRC_SHIFT: u32 = HOST_BITS + TYPE_BITS + REMAIN_BITS + ID_BITS;

    /// All-ones in the dst field — libcsp's on-CAN broadcast target.
    /// Regardless of CSP wire version, CFP only carries 5 bits of dst.
    pub const BROADCAST_ADDR: u8 = HOST_MASK as u8;

    /// Encode `dst` (low 5 bits kept) into its CFP position in the CAN ID.
    /// Equivalent to libcsp's C `CFP_MAKE_DST` macro.
    pub const fn make_dst(dst: u8) -> u32 {
        ((dst as u32) & HOST_MASK) << DST_SHIFT
    }

    /// Encode `src` (low 5 bits kept) into its CFP position in the CAN ID.
    /// Equivalent to libcsp's C `CFP_MAKE_SRC` macro.
    pub const fn make_src(src: u8) -> u32 {
        ((src as u32) & HOST_MASK) << SRC_SHIFT
    }

    /// Extract the dst host address from a 29-bit CFP CAN ID.
    /// Equivalent to libcsp's C `CFP_DST` macro.
    pub const fn dst(id: u32) -> u8 {
        ((id >> DST_SHIFT) & HOST_MASK) as u8
    }

    /// Extract the src host address from a 29-bit CFP CAN ID.
    /// Equivalent to libcsp's C `CFP_SRC` macro.
    pub const fn src(id: u32) -> u8 {
        ((id >> SRC_SHIFT) & HOST_MASK) as u8
    }
}

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
/// The interface state is leaked into static memory at registration time
/// (matching libcsp's "register once, run forever" lifecycle). The handle
/// itself is `Copy`; dropping it does **not** unregister the interface.
///
/// Use [`feed_rx`] to pass received CAN frames to the CSP stack.
///
/// [`feed_rx`]: CanInterfaceHandle::feed_rx
#[derive(Clone, Copy)]
pub struct CanInterfaceHandle {
    inner: &'static CanInterfaceInner,
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
/// - `name`: interface name (e.g. `"CAN"`).
/// - `addr`: this interface's CSP address. Outgoing packets the upper
///   layer leaves with `id.src = 0` get backfilled from this field by
///   `csp_send_direct_iface`. Forgetting to set it is the kind of bug
///   that silently leaves you sending frames with `src=0` and never
///   seeing replies — so it's a required argument, not a setter you
///   might forget.
/// - `driver`: your [`CanDriver`] implementation.
///
/// Returns a [`CanInterfaceHandle`] that must be kept alive. Use it to
/// feed received CAN frames via [`CanInterfaceHandle::feed_rx`].
pub fn add_interface(
    name: &str,
    addr: u16,
    driver: impl CanDriver + 'static,
) -> crate::Result<CanInterfaceHandle> {
    let c_name = CString::new(name).map_err(|_| crate::CspError::InvalidArgument)?;

    // Leak the inner state: libcsp will keep raw pointers into `c_iface`,
    // `can_data` and the CString name for the rest of the process lifetime.
    let inner: &'static CanInterfaceInner = Box::leak(Box::new(CanInterfaceInner {
        driver: spin::Mutex::new(Box::new(driver)),
        c_iface: UnsafeCell::new(unsafe { core::mem::zeroed() }),
        can_data: UnsafeCell::new(unsafe { core::mem::zeroed() }),
        _c_name: c_name,
    }));

    unsafe {
        let can_data = inner.can_data.get();
        (*can_data).tx_func = Some(can_tx_trampoline);

        let c_iface = inner.c_iface.get();
        (*c_iface).name = inner._c_name.as_ptr();
        (*c_iface).addr = addr;
        // Store a pointer to inner as driver_data so the TX callback can find us.
        (*c_iface).driver_data = inner as *const CanInterfaceInner as *mut c_void;
        (*c_iface).interface_data = can_data as *mut c_void;

        let rc = sys::csp_can_add_interface(c_iface);
        if rc != 0 {
            // The inner state is already leaked; that's fine for this
            // run-forever model — registration just didn't happen.
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

    /// This interface's CSP address (the value passed to
    /// [`add_interface`]).
    pub fn addr(&self) -> u16 {
        // Safety: `addr` is a plain `u16` field initialised in
        // `add_interface` and never mutated from C after that.
        unsafe { (*self.inner.c_iface.get()).addr }
    }

    /// Raw `csp_iface_t *` for the rare case you need to call into C
    /// directly (e.g. extra `csp_rtable_set` entries beyond what the
    /// safe `route::*` helpers expose). Marked low-level — prefer the
    /// route helpers.
    #[doc(hidden)]
    pub fn c_iface_ptr(&self) -> *mut sys::csp_iface_t {
        self.inner.c_iface.get()
    }
}

/// C callback invoked by libcsp's CAN TX path. Forwards to the Rust CanDriver.
///
/// Catches Rust panics so unwinding never crosses the C frame.
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

    let mut rc = -1;
    let rc_ref = &mut rc;
    ffi_util::guard("can_tx_trampoline", move || {
        *rc_ref = match inner.driver.lock().transmit(id, slice, dlc) {
            Ok(()) => 0,
            Err(()) => -1,
        };
    });
    rc
}
