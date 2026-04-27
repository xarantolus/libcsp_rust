#![no_std]

//! Shared arch implementation for embassy CSP stress tests.

extern crate alloc;

mod queue;

use alloc::boxed::Box;
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, Ordering};
use embassy_time::Instant;
use libcsp::CspArch;
use queue::Queue;

#[global_allocator]
pub static HEAP: embedded_alloc::Heap = embedded_alloc::Heap::empty();

/// Proper arch implementation backed by critical sections and the global heap.
pub struct EmbassyArch;

// Safety: EmbassyArch only uses atomic operations and critical sections,
// both of which are safe across threads on single-core ARM Cortex-M.
unsafe impl Send for EmbassyArch {}
unsafe impl Sync for EmbassyArch {}

// Safety: This implementation correctly handles all raw pointers and implements
// the architecture primitives using Embassy's async runtime and critical sections.
unsafe impl CspArch for EmbassyArch {
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
        // Disable interrupts - the mutex IS the critical section
        cortex_m::interrupt::disable();
        true
    }

    fn mutex_unlock(&self, _mutex: *mut c_void) -> bool {
        // Re-enable interrupts
        unsafe { cortex_m::interrupt::enable(); }
        true
    }

    // ── Queues ────────────────────────────────────────────────────────────────
    // CSP queues are used for the router FIFO and per-connection RX queues.
    // We use a circular buffer implementation with critical section protection.
    fn queue_create(&self, length: usize, item_size: usize) -> *mut c_void {
        // Allocate buffer for the queue data
        let buffer_size = length * item_size;
        let buffer = self.malloc(buffer_size);
        if buffer.is_null() {
            return core::ptr::null_mut();
        }

        // Create the Queue struct
        // Safety: We just allocated the buffer above
        let queue = unsafe { Queue::new(buffer as *mut u8, length, item_size) };
        Box::into_raw(Box::new(queue)) as *mut c_void
    }

    fn queue_remove(&self, queue: *mut c_void) {
        if queue.is_null() {
            return;
        }
        // Safety: queue was created by queue_create
        unsafe {
            let q = Box::from_raw(queue as *mut Queue);
            // Free the buffer that was allocated in queue_create
            let buffer = *q.buffer.get();
            self.free(buffer as *mut c_void);
            // Queue struct is dropped here
        }
    }

    fn queue_enqueue(&self, queue: *mut c_void, item: *const c_void, timeout_ms: u32) -> bool {
        if queue.is_null() || item.is_null() {
            return false;
        }
        // Safety: queue was created by queue_create, item points to valid data
        unsafe {
            let q = &*(queue as *const Queue);
            q.enqueue(item as *const u8, timeout_ms)
        }
    }

    fn queue_dequeue(&self, queue: *mut c_void, item: *mut c_void, timeout_ms: u32) -> bool {
        if queue.is_null() || item.is_null() {
            return false;
        }
        // Safety: queue was created by queue_create, item points to valid data
        unsafe {
            let q = &*(queue as *const Queue);
            q.dequeue(item as *mut u8, timeout_ms)
        }
    }

    fn queue_size(&self, queue: *mut c_void) -> usize {
        if queue.is_null() {
            return 0;
        }
        // Safety: queue was created by queue_create
        unsafe {
            let q = &*(queue as *const Queue);
            q.size()
        }
    }

}

// libcsp v2.1 dropped `malloc`/`free` from `CspArch` — its packet pool /
// connection table are statically sized at compile time. SFP and a couple of
// drivers still call libc `malloc`/`free` directly, so on bare-metal we have
// to expose those symbols ourselves; we route them through `HEAP` below.
//
// Methods kept on `EmbassyArch` so the in-crate `queue_create` can still
// allocate its backing buffer the same way.
impl EmbassyArch {
    fn malloc(&self, size: usize) -> *mut c_void {
        // Store size in a header before the returned pointer so we can free it later
        const HEADER: usize = core::mem::size_of::<usize>();
        let total = HEADER + size;
        unsafe {
            let layout = core::alloc::Layout::from_size_align_unchecked(total, 8);
            let ptr = core::alloc::GlobalAlloc::alloc(&HEAP, layout);
            if ptr.is_null() {
                return core::ptr::null_mut();
            }
            // Store the size in the header
            *(ptr as *mut usize) = size;
            // Return pointer after the header
            ptr.add(HEADER) as *mut c_void
        }
    }

    fn free(&self, ptr: *mut c_void) {
        if ptr.is_null() {
            return;
        }
        const HEADER: usize = core::mem::size_of::<usize>();
        unsafe {
            // Get the original pointer (before the header)
            let original = (ptr as *mut u8).sub(HEADER);
            // Read the size from the header
            let size = *(original as *const usize);
            // Deallocate with the correct layout
            let layout = core::alloc::Layout::from_size_align_unchecked(HEADER + size, 8);
            core::alloc::GlobalAlloc::dealloc(&HEAP, original, layout);
        }
    }
}

pub static ARCH: EmbassyArch = EmbassyArch;

// `csp_sfp.c` and a couple of optional drivers still call libc `malloc`/
// `free` directly. On bare-metal the host C lib isn't linked in, so we
// publish C-compatible shims that route through the embedded heap.
#[no_mangle]
pub unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
    ARCH.malloc(size)
}

#[no_mangle]
pub unsafe extern "C" fn free(ptr: *mut c_void) {
    ARCH.free(ptr);
}

// NOTE: C string functions (strcpy, strncpy, strnlen, strncasecmp, strtok_r)
// and other stubs (rand, srand, _embassy_time_schedule_wake) are provided
// automatically by libcsp::export_arch! macro. No need to define them here!

// sscanf is provided by mini-scanf (compiled from C with varargs support)

// ── PRNG ──────────────────────────────────────────────────────────────────────
// Simple xorshift32 PRNG for stress test data generation

pub struct Prng {
    state: u32,
}

impl Prng {
    pub fn new(seed: u32) -> Self {
        Self {
            state: if seed == 0 { 1 } else { seed },
        }
    }

    pub fn next(&mut self) -> u32 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.state = x;
        x
    }

    pub fn next_with_seed(seed: u32) -> u32 {
        let mut x = if seed == 0 { 1 } else { seed };
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x
    }

    pub fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_exact_mut(4) {
            let val = self.next();
            chunk.copy_from_slice(&val.to_le_bytes());
        }
        let remaining = buf.len() % 4;
        if remaining > 0 {
            let val = self.next().to_le_bytes();
            let start = buf.len() - remaining;
            buf[start..].copy_from_slice(&val[..remaining]);
        }
    }
}
