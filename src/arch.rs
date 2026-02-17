//! Traits and helpers for providing custom architecture implementations.

use core::ffi::{c_void, c_char};

/// Trait for implementing OS-specific primitives for libcsp.
pub trait CspArch: Send + Sync {
    /// Return system time in milliseconds.
    fn get_ms(&self) -> u32;
    /// Return system time in seconds.
    fn get_s(&self) -> u32;
    /// Return uptime in seconds.
    fn get_uptime_s(&self) -> u32 { self.get_s() }

    // ── Semaphores ──────────────────────────────────────────────────────────
    fn bin_sem_create(&self) -> *mut c_void;
    fn bin_sem_remove(&self, sem: *mut c_void);
    fn bin_sem_wait(&self, sem: *mut c_void, timeout: u32) -> bool;
    fn bin_sem_post(&self, sem: *mut c_void) -> bool;

    // ── Mutexes ─────────────────────────────────────────────────────────────
    fn mutex_create(&self) -> *mut c_void;
    fn mutex_remove(&self, mutex: *mut c_void);
    fn mutex_lock(&self, mutex: *mut c_void, timeout: u32) -> bool;
    fn mutex_unlock(&self, mutex: *mut c_void) -> bool;

    // ── Queues ──────────────────────────────────────────────────────────────
    fn queue_create(&self, length: usize, item_size: usize) -> *mut c_void;
    fn queue_remove(&self, queue: *mut c_void);
    fn queue_enqueue(&self, queue: *mut c_void, item: *const c_void, timeout: u32) -> bool;
    fn queue_dequeue(&self, queue: *mut c_void, item: *mut c_void, timeout: u32) -> bool;
    fn queue_size(&self, queue: *mut c_void) -> usize;

    // ── Memory ──────────────────────────────────────────────────────────────
    fn malloc(&self, size: usize) -> *mut c_void;
    fn free(&self, ptr: *mut c_void);
    fn calloc(&self, nmemb: usize, size: usize) -> *mut c_void {
        let total = nmemb * size;
        let ptr = self.malloc(total);
        if !ptr.is_null() {
            unsafe { core::ptr::write_bytes(ptr, 0, total) };
        }
        ptr
    }
    
    // ── System ──────────────────────────────────────────────────────────────
    fn memfree(&self) -> u32 { 0 }
    fn reboot(&self) {}
    fn shutdown(&self) {}
    
    // ── Clock ───────────────────────────────────────────────────────────────
    fn clock_get_time(&self, _time: *mut c_void) {}
    fn clock_set_time(&self, _time: *mut c_void) {}

    // ── Task List ───────────────────────────────────────────────────────────
    fn sys_tasklist_size(&self) -> i32 { 0 }
    fn sys_tasklist(&self, _out: *mut c_char) {}
}

/// Helper macro to export a `CspArch` implementation to the C linker.
#[macro_export]
macro_rules! export_arch {
    ($impl_type:ty, $instance:expr) => {
        #[no_mangle] pub extern "C" fn csp_get_ms() -> u32 { <$impl_type as $crate::CspArch>::get_ms(&$instance) }
        #[no_mangle] pub extern "C" fn csp_get_s() -> u32 { <$impl_type as $crate::CspArch>::get_s(&$instance) }
        #[no_mangle] pub extern "C" fn csp_get_uptime_s() -> u32 { <$impl_type as $crate::CspArch>::get_uptime_s(&$instance) }
        #[no_mangle] pub extern "C" fn csp_get_ms_isr() -> u32 { <$impl_type as $crate::CspArch>::get_ms(&$instance) }

        #[no_mangle] pub extern "C" fn csp_bin_sem_create(sem: *mut *mut ::core::ffi::c_void) -> i32 {
            let s = <$impl_type as $crate::CspArch>::bin_sem_create(&$instance);
            if s.is_null() { 0 } else { unsafe { *sem = s }; 1 }
        }
        #[no_mangle] pub extern "C" fn csp_bin_sem_remove(sem: *mut *mut ::core::ffi::c_void) -> i32 {
            unsafe { <$impl_type as $crate::CspArch>::bin_sem_remove(&$instance, *sem) }; 1
        }
        #[no_mangle] pub extern "C" fn csp_bin_sem_wait(sem: *mut *mut ::core::ffi::c_void, timeout: u32) -> i32 {
            if unsafe { <$impl_type as $crate::CspArch>::bin_sem_wait(&$instance, *sem, timeout) } { 1 } else { 0 }
        }
        #[no_mangle] pub extern "C" fn csp_bin_sem_post(sem: *mut *mut ::core::ffi::c_void) -> i32 {
            if unsafe { <$impl_type as $crate::CspArch>::bin_sem_post(&$instance, *sem) } { 1 } else { 0 }
        }
        #[no_mangle] pub extern "C" fn csp_bin_sem_post_isr(sem: *mut *mut ::core::ffi::c_void, _px: *mut i32) -> i32 {
            if unsafe { <$impl_type as $crate::CspArch>::bin_sem_post(&$instance, *sem) } { 1 } else { 0 }
        }

        #[no_mangle] pub extern "C" fn csp_mutex_create(mutex: *mut *mut ::core::ffi::c_void) -> i32 {
            let m = <$impl_type as $crate::CspArch>::mutex_create(&$instance);
            if m.is_null() { 0 } else { unsafe { *mutex = m }; 1 }
        }
        #[no_mangle] pub extern "C" fn csp_mutex_remove(mutex: *mut *mut ::core::ffi::c_void) -> i32 {
            unsafe { <$impl_type as $crate::CspArch>::mutex_remove(&$instance, *mutex) }; 1
        }
        #[no_mangle] pub extern "C" fn csp_mutex_lock(mutex: *mut *mut ::core::ffi::c_void, timeout: u32) -> i32 {
            if unsafe { <$impl_type as $crate::CspArch>::mutex_lock(&$instance, *mutex, timeout) } { 1 } else { 0 }
        }
        #[no_mangle] pub extern "C" fn csp_mutex_unlock(mutex: *mut *mut ::core::ffi::c_void) -> i32 {
            if unsafe { <$impl_type as $crate::CspArch>::mutex_unlock(&$instance, *mutex) } { 1 } else { 0 }
        }

        #[no_mangle] pub extern "C" fn csp_queue_create(length: i32, item_size: usize) -> *mut ::core::ffi::c_void {
            <$impl_type as $crate::CspArch>::queue_create(&$instance, length as usize, item_size)
        }
        #[no_mangle] pub extern "C" fn csp_queue_remove(queue: *mut ::core::ffi::c_void) {
            <$impl_type as $crate::CspArch>::queue_remove(&$instance, queue)
        }
        #[no_mangle] pub extern "C" fn csp_queue_enqueue(queue: *mut ::core::ffi::c_void, item: *const ::core::ffi::c_void, timeout: u32) -> i32 {
            if <$impl_type as $crate::CspArch>::queue_enqueue(&$instance, queue, item, timeout) { 1 } else { 0 }
        }
        #[no_mangle] pub extern "C" fn csp_queue_enqueue_isr(queue: *mut ::core::ffi::c_void, item: *const ::core::ffi::c_void, _px: *mut i32) -> i32 {
            if <$impl_type as $crate::CspArch>::queue_enqueue(&$instance, queue, item, 0) { 1 } else { 0 }
        }
        #[no_mangle] pub extern "C" fn csp_queue_dequeue(queue: *mut ::core::ffi::c_void, item: *mut ::core::ffi::c_void, timeout: u32) -> i32 {
            if <$impl_type as $crate::CspArch>::queue_dequeue(&$instance, queue, item, timeout) { 1 } else { 0 }
        }
        #[no_mangle] pub extern "C" fn csp_queue_dequeue_isr(queue: *mut ::core::ffi::c_void, item: *mut ::core::ffi::c_void, _px: *mut i32) -> i32 {
            if <$impl_type as $crate::CspArch>::queue_dequeue(&$instance, queue, item, 0) { 1 } else { 0 }
        }
        #[no_mangle] pub extern "C" fn csp_queue_size(queue: *mut ::core::ffi::c_void) -> i32 {
            <$impl_type as $crate::CspArch>::queue_size(&$instance, queue) as i32
        }
        #[no_mangle] pub extern "C" fn csp_queue_size_isr(queue: *mut ::core::ffi::c_void) -> i32 {
            <$impl_type as $crate::CspArch>::queue_size(&$instance, queue) as i32
        }

        #[no_mangle] pub extern "C" fn csp_malloc(size: usize) -> *mut ::core::ffi::c_void {
            <$impl_type as $crate::CspArch>::malloc(&$instance, size)
        }
        #[no_mangle] pub extern "C" fn csp_calloc(nmemb: usize, size: usize) -> *mut ::core::ffi::c_void {
            <$impl_type as $crate::CspArch>::calloc(&$instance, nmemb, size)
        }
        #[no_mangle] pub extern "C" fn csp_free(ptr: *mut ::core::ffi::c_void) {
            <$impl_type as $crate::CspArch>::free(&$instance, ptr)
        }

        #[no_mangle] pub extern "C" fn csp_sys_memfree() -> u32 { <$impl_type as $crate::CspArch>::memfree(&$instance) }
        #[no_mangle] pub extern "C" fn csp_sys_reboot() { <$impl_type as $crate::CspArch>::reboot(&$instance) }
        #[no_mangle] pub extern "C" fn csp_sys_shutdown() { <$impl_type as $crate::CspArch>::shutdown(&$instance) }
        
        #[no_mangle] pub extern "C" fn csp_clock_get_time(time: *mut ::core::ffi::c_void) { <$impl_type as $crate::CspArch>::clock_get_time(&$instance, time) }
        #[no_mangle] pub extern "C" fn csp_clock_set_time(time: *mut ::core::ffi::c_void) { <$impl_type as $crate::CspArch>::clock_set_time(&$instance, time) }
        
        #[no_mangle] pub extern "C" fn csp_sys_tasklist_size() -> i32 { <$impl_type as $crate::CspArch>::sys_tasklist_size(&$instance) }
        #[no_mangle] pub extern "C" fn csp_sys_tasklist(out: *mut ::core::ffi::c_char) { <$impl_type as $crate::CspArch>::sys_tasklist(&$instance, out) }
    };
}
