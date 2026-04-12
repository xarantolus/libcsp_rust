//! Handlers for CMP PEEK and POKE requests.
//!
//! libcsp's CMP service implements remote memory read (PEEK) and remote
//! memory write (POKE) on ports 0. Both are disabled by default — a remote
//! PEEK or POKE returns `CSP_ERR_NOTSUP` unless you install a handler.
//!
//! Each handler is a plain `fn` pointer (no captures) invoked from the
//! router thread. Handlers receive the in-packet buffer as a slice and the
//! wire-supplied address as a `u32`, and return `Ok(())` on success or an
//! `Err(i32)` carrying a CSP error code that is propagated to the remote.
//!
//! - **PEEK**: write `len` bytes of the requested memory into `data`.
//! - **POKE**: apply `len` bytes from `data` to the requested memory.

use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::sys;

/// Read `data.len()` bytes from memory at `addr` into `data`.
pub type PeekHandler = fn(data: &mut [u8], addr: u32) -> Result<(), i32>;

/// Write `data.len()` bytes from `data` to memory at `addr`.
pub type PokeHandler = fn(data: &[u8], addr: u32) -> Result<(), i32>;

static PEEK: AtomicUsize = AtomicUsize::new(0);
static POKE: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn peek_trampoline(data: *mut c_void, addr: u32, len: u8) -> i32 {
    let raw = PEEK.load(Ordering::Acquire);
    if raw == 0 {
        return sys::CSP_ERR_NOTSUP as i32;
    }
    let h: PeekHandler = unsafe { core::mem::transmute(raw) };
    let slice = unsafe { core::slice::from_raw_parts_mut(data as *mut u8, len as usize) };
    match h(slice, addr) {
        Ok(()) => sys::CSP_ERR_NONE as i32,
        Err(e) => e,
    }
}

unsafe extern "C" fn poke_trampoline(data: *const c_void, addr: u32, len: u8) -> i32 {
    let raw = POKE.load(Ordering::Acquire);
    if raw == 0 {
        return sys::CSP_ERR_NOTSUP as i32;
    }
    let h: PokeHandler = unsafe { core::mem::transmute(raw) };
    let slice = unsafe { core::slice::from_raw_parts(data as *const u8, len as usize) };
    match h(slice, addr) {
        Ok(()) => sys::CSP_ERR_NONE as i32,
        Err(e) => e,
    }
}

/// Install (or clear) the PEEK handler. With no handler, PEEK fails with
/// `CSP_ERR_NOTSUP`.
pub fn set_peek(h: Option<PeekHandler>) {
    match h {
        Some(h) => {
            PEEK.store(h as usize, Ordering::Release);
            unsafe { sys::csp_cmp_set_peek(Some(peek_trampoline)) };
        }
        None => {
            PEEK.store(0, Ordering::Release);
            unsafe { sys::csp_cmp_set_peek(None) };
        }
    }
}

/// Install (or clear) the POKE handler. With no handler, POKE fails with
/// `CSP_ERR_NOTSUP`.
pub fn set_poke(h: Option<PokeHandler>) {
    match h {
        Some(h) => {
            POKE.store(h as usize, Ordering::Release);
            unsafe { sys::csp_cmp_set_poke(Some(poke_trampoline)) };
        }
        None => {
            POKE.store(0, Ordering::Release);
            unsafe { sys::csp_cmp_set_poke(None) };
        }
    }
}
