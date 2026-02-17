//! Example: Providing a custom architecture implementation.
//! 
//! This demonstrates how to implement the `CspArch` trait to provide
//! OS primitives (mutex, semaphore, queue) for libcsp when running on
//! an unsupported RTOS or bare-metal.

extern crate alloc;
use libcsp::arch::CspArch;
use libcsp::export_arch;
use core::ffi::c_void;
use alloc::boxed::Box;

/// A dummy architecture implementation for demonstration.
struct MyCustomArch;

impl CspArch for MyCustomArch {
    fn get_ms(&self) -> u32 { 0 }
    fn get_s(&self) -> u32 { 0 }

    fn bin_sem_create(&self) -> *mut c_void { core::ptr::null_mut() }
    fn bin_sem_remove(&self, _sem: *mut c_void) { }
    fn bin_sem_wait(&self, _sem: *mut c_void, _timeout: u32) -> bool { true }
    fn bin_sem_post(&self, _sem: *mut c_void) -> bool { true }

    fn mutex_create(&self) -> *mut c_void { core::ptr::null_mut() }
    fn mutex_remove(&self, _mutex: *mut c_void) { }
    fn mutex_lock(&self, _mutex: *mut c_void, _timeout: u32) -> bool { true }
    fn mutex_unlock(&self, _mutex: *mut c_void) -> bool { true }

    fn queue_create(&self, _length: usize, _item_size: usize) -> *mut c_void { core::ptr::null_mut() }
    fn queue_remove(&self, _queue: *mut c_void) { }
    fn queue_enqueue(&self, _queue: *mut c_void, _item: *const c_void, _timeout: u32) -> bool { true }
    fn queue_dequeue(&self, _queue: *mut c_void, _item: *mut c_void, _timeout: u32) -> bool { true }
    fn queue_size(&self, _queue: *mut c_void) -> usize { 0 }

    fn malloc(&self, _size: usize) -> *mut c_void { core::ptr::null_mut() }
    fn free(&self, _ptr: *mut c_void) { }
}

// Global instance of our arch
static ARCH: MyCustomArch = MyCustomArch;

// Export the symbols to C
export_arch!(MyCustomArch, ARCH);

fn main() {
    println!("This example demonstrates the CspArch trait implementation.");
}
