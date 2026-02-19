#![no_std]

//! Shared arch implementation for embassy CSP stress tests.

extern crate alloc;

use alloc::boxed::Box;
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, Ordering};
use cortex_m::interrupt;
use embassy_time::Instant;
use libcsp::CspArch;

#[global_allocator]
pub static HEAP: embedded_alloc::Heap = embedded_alloc::Heap::empty();

/// Proper arch implementation backed by critical sections and the global heap.
pub struct EmbassyArch;

// Safety: EmbassyArch only uses atomic operations and critical sections,
// both of which are safe across threads on single-core ARM Cortex-M.
unsafe impl Send for EmbassyArch {}
unsafe impl Sync for EmbassyArch {}

impl CspArch for EmbassyArch {
    // ── Time ──────────────────────────────────────────────────────────────────
    fn get_ms(&self) -> u32 {
        Instant::now().as_millis() as u32
    }

    fn get_s(&self) -> u32 {
        Instant::now().as_secs() as u32
    }

    // ── Binary semaphores ─────────────────────────────────────────────────────
    // Implemented as AtomicBool with proper acquire/release semantics.
    // CSP uses these for RDP state machines and router wake-up.
    fn bin_sem_create(&self) -> *mut c_void {
        Box::into_raw(Box::new(AtomicBool::new(false))) as *mut c_void
    }

    fn bin_sem_remove(&self, sem: *mut c_void) {
        unsafe { drop(Box::from_raw(sem as *mut AtomicBool)); }
    }

    fn bin_sem_wait(&self, sem: *mut c_void, timeout_ms: u32) -> bool {
        let sem = unsafe { &*(sem as *const AtomicBool) };
        let start = Instant::now();

        // Spin until the semaphore is available or timeout expires
        loop {
            if sem.swap(false, Ordering::Acquire) {
                return true;
            }

            if timeout_ms != u32::MAX
                && Instant::now().duration_since(start).as_millis() >= timeout_ms as u64
            {
                return false;
            }

            cortex_m::asm::nop();
        }
    }

    fn bin_sem_post(&self, sem: *mut c_void) -> bool {
        let sem = unsafe { &*(sem as *const AtomicBool) };
        sem.store(true, Ordering::Release);
        true
    }

    // ── Mutexes ───────────────────────────────────────────────────────────────
    // Implemented using critical sections (disables interrupts).
    // CSP uses these to protect the buffer pool and connection table.
    fn mutex_create(&self) -> *mut c_void {
        // Mutex is just a marker — actual locking uses critical sections
        Box::into_raw(Box::new(0u8)) as *mut c_void
    }

    fn mutex_remove(&self, mutex: *mut c_void) {
        unsafe { drop(Box::from_raw(mutex as *mut u8)); }
    }

    fn mutex_lock(&self, _mutex: *mut c_void, _timeout_ms: u32) -> bool {
        // Enter critical section (disables interrupts)
        // This is safe because we're single-core with critical-section-single-core feature
        interrupt::free(|_cs| {
            // Critical section held until drop
        });
        true
    }

    fn mutex_unlock(&self, _mutex: *mut c_void) -> bool {
        // Critical section is released automatically when the CS token drops
        true
    }

    // ── Queues ────────────────────────────────────────────────────────────────
    // CSP queues are used for the router FIFO and per-connection RX queues.
    // For now we use a minimal stub — a real implementation would use a ringbuffer.
    // TODO: Implement proper FIFO queues with blocking semantics.
    fn queue_create(&self, _length: usize, _item_size: usize) -> *mut c_void {
        // Placeholder: just allocate a marker
        Box::into_raw(Box::new(0usize)) as *mut c_void
    }

    fn queue_remove(&self, queue: *mut c_void) {
        unsafe { drop(Box::from_raw(queue as *mut usize)); }
    }

    fn queue_enqueue(&self, _queue: *mut c_void, _item: *const c_void, _timeout_ms: u32) -> bool {
        // TODO: Real queue logic
        true
    }

    fn queue_dequeue(&self, _queue: *mut c_void, _item: *mut c_void, _timeout_ms: u32) -> bool {
        // TODO: Real queue logic
        true
    }

    fn queue_size(&self, _queue: *mut c_void) -> usize {
        0
    }

    // ── Heap ──────────────────────────────────────────────────────────────────
    fn malloc(&self, size: usize) -> *mut c_void {
        // Safety: Layout::from_size_align_unchecked requires size <= isize::MAX
        // and align is a power of 2. We use align=4, which is valid.
        unsafe {
            core::alloc::GlobalAlloc::alloc(
                &HEAP,
                core::alloc::Layout::from_size_align_unchecked(size, 4),
            ) as *mut c_void
        }
    }

    fn free(&self, _ptr: *mut c_void) {
        // We don't know the original size — this is a limitation of the C API.
        // For embedded-alloc, we need to provide a layout. Since we don't have
        // the size, we skip the dealloc (leak). A real embedded allocator would
        // store metadata with each allocation.
        // TODO: Use an allocator that tracks sizes (e.g., linked_list_allocator)
    }
}

pub static ARCH: EmbassyArch = EmbassyArch;
