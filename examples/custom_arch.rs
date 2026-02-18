//! Example: Providing a custom architecture implementation.
//!
//! When building for a bare-metal or custom-RTOS target with the
//! `external-arch` feature enabled, libcsp cannot use its built-in
//! POSIX/FreeRTOS primitives.  You must supply replacements by implementing
//! the [`CspArch`] trait and exporting it with the [`export_arch!`] macro.
//!
//! The stubs below return the safest possible no-op values.  On a real target
//! you would back them with your RTOS's semaphore/mutex/queue/heap APIs.
//!
//! Run with: cargo run --example custom_arch

extern crate alloc;
use libcsp::arch::CspArch;
use libcsp::export_arch;
use core::ffi::c_void;

/// Minimal architecture shim backed by no-ops.
///
/// Replace each method body with the appropriate RTOS call for your platform.
struct MyCustomArch;

impl CspArch for MyCustomArch {
    // ── Time ─────────────────────────────────────────────────────────────
    // CSP uses these for RDP timeouts and debug timestamps.
    fn get_ms(&self) -> u32 { 0 /* replace with e.g. embassy_time::Instant::now().as_millis() as u32 */ }
    fn get_s(&self)  -> u32 { 0 }

    // ── Binary semaphores ─────────────────────────────────────────────────
    // Used to synchronise the router and protocol state machines.
    fn bin_sem_create(&self) -> *mut c_void { core::ptr::null_mut() }
    fn bin_sem_remove(&self, _sem: *mut c_void) { }
    fn bin_sem_wait(&self, _sem: *mut c_void, _timeout_ms: u32) -> bool { true }
    fn bin_sem_post(&self, _sem: *mut c_void) -> bool { true }

    // ── Mutexes ───────────────────────────────────────────────────────────
    fn mutex_create(&self) -> *mut c_void { core::ptr::null_mut() }
    fn mutex_remove(&self, _mutex: *mut c_void) { }
    fn mutex_lock(&self, _mutex: *mut c_void, _timeout_ms: u32) -> bool { true }
    fn mutex_unlock(&self, _mutex: *mut c_void) -> bool { true }

    // ── Queues ────────────────────────────────────────────────────────────
    // CSP's router FIFO and per-connection RX queues are backed by these.
    fn queue_create(&self, _length: usize, _item_size: usize) -> *mut c_void { core::ptr::null_mut() }
    fn queue_remove(&self, _queue: *mut c_void) { }
    fn queue_enqueue(&self, _queue: *mut c_void, _item: *const c_void, _timeout_ms: u32) -> bool { true }
    fn queue_dequeue(&self, _queue: *mut c_void, _item: *mut c_void, _timeout_ms: u32) -> bool { true }
    fn queue_size(&self, _queue: *mut c_void) -> usize { 0 }

    // ── Heap ──────────────────────────────────────────────────────────────
    // libcsp uses these for connection and packet-pool bookkeeping.
    fn malloc(&self, _size: usize) -> *mut c_void { core::ptr::null_mut() }
    fn free(&self, _ptr: *mut c_void) { }
}

// A single static instance is sufficient — the trait takes &self.
static ARCH: MyCustomArch = MyCustomArch;

// export_arch!(Type, STATIC_INSTANCE) generates the #[no_mangle] C shims
// that libcsp's C code calls (csp_get_ms, csp_bin_sem_create, …).
export_arch!(MyCustomArch, ARCH);

fn main() {
    // Nothing to run — this example exists to show the trait implementation.
    // In a real application you would call CspConfig::new()…init() after
    // export_arch! has been called (it is called at link time, not runtime).
    println!("CspArch trait exported. Link this object into your embedded binary.");
}
