//! Traits and helpers for providing custom architecture implementations.

use core::ffi::{c_void, c_char};

/// Trait for implementing OS-specific primitives for libcsp.
///
/// ## Minimal Required Implementation
///
/// To use CSP with `external-arch`, you **must** implement:
/// - Time: [`get_ms`], [`get_s`]
/// - Mutexes: [`mutex_create`], [`mutex_remove`], [`mutex_lock`], [`mutex_unlock`]
/// - Binary Semaphores: [`bin_sem_create`], [`bin_sem_remove`], [`bin_sem_wait`], [`bin_sem_post`]
/// - Queues: [`queue_create`], [`queue_remove`], [`queue_enqueue`], [`queue_dequeue`], [`queue_size`]
/// - Memory: [`malloc`], [`free`], ([`calloc`] has a default implementation)
///
/// ## Optional Functions
///
/// These have default implementations or are only needed for specific features:
/// - ISR variants (`get_ms_isr`, `bin_sem_post_isr`, `queue_*_isr`) - default to non-ISR versions
/// - [`thread_create`] - only needed if using [`CspNode::route_start_task`]. Use [`CspNode::route_work`] to avoid needing threads.
/// - [`sleep_ms`] - convenience function, no-op by default
/// - System functions (`sys_tasklist`, `memfree`, `reboot`, etc.) - used by CSP services, have no-op defaults
/// - Clock functions - for timestamps, have no-op defaults
///
/// [`get_ms`]: CspArch::get_ms
/// [`get_s`]: CspArch::get_s
/// [`mutex_create`]: CspArch::mutex_create
/// [`mutex_remove`]: CspArch::mutex_remove
/// [`mutex_lock`]: CspArch::mutex_lock
/// [`mutex_unlock`]: CspArch::mutex_unlock
/// [`bin_sem_create`]: CspArch::bin_sem_create
/// [`bin_sem_remove`]: CspArch::bin_sem_remove
/// [`bin_sem_wait`]: CspArch::bin_sem_wait
/// [`bin_sem_post`]: CspArch::bin_sem_post
/// [`queue_create`]: CspArch::queue_create
/// [`queue_remove`]: CspArch::queue_remove
/// [`queue_enqueue`]: CspArch::queue_enqueue
/// [`queue_dequeue`]: CspArch::queue_dequeue
/// [`queue_size`]: CspArch::queue_size
/// [`malloc`]: CspArch::malloc
/// [`free`]: CspArch::free
/// [`calloc`]: CspArch::calloc
/// [`thread_create`]: CspArch::thread_create
/// [`sleep_ms`]: CspArch::sleep_ms
/// [`CspNode::route_start_task`]: crate::CspNode::route_start_task
/// [`CspNode::route_work`]: crate::CspNode::route_work
pub trait CspArch: Send + Sync {
    // ── Time (REQUIRED) ─────────────────────────────────────────────────────

    /// Return system time in milliseconds.
    ///
    /// **Required.** Must be monotonic and wrap at u32::MAX.
    fn get_ms(&self) -> u32;

    /// Return system time in seconds.
    ///
    /// **Required.** Should be `get_ms() / 1000` or similar.
    fn get_s(&self) -> u32;

    // ── ISR variants (OPTIONAL) ─────────────────────────────────────────────
    // These default to the non-ISR versions. Override only if you need to call
    // CSP functions from interrupt handlers.

    /// Return system time in milliseconds (from ISR context).
    ///
    /// **Optional.** Defaults to [`get_ms`].
    ///
    /// [`get_ms`]: CspArch::get_ms
    fn get_ms_isr(&self) -> u32 { self.get_ms() }

    /// Return uptime in seconds.
    ///
    /// **Optional.** Defaults to [`get_s`].
    ///
    /// [`get_s`]: CspArch::get_s
    fn get_uptime_s(&self) -> u32 { self.get_s() }

    // ── Binary Semaphores (REQUIRED) ────────────────────────────────────────

    /// Create a binary semaphore.
    ///
    /// **Required.** Returns a handle, or null on failure.
    fn bin_sem_create(&self) -> *mut c_void;

    /// Remove/destroy a binary semaphore.
    ///
    /// **Required.**
    fn bin_sem_remove(&self, sem: *mut c_void);

    /// Wait on a binary semaphore with timeout (ms).
    ///
    /// **Required.** Returns true on success, false on timeout.
    /// `timeout` of 0xFFFFFFFF means wait forever.
    fn bin_sem_wait(&self, sem: *mut c_void, timeout: u32) -> bool;

    /// Post/signal a binary semaphore.
    ///
    /// **Required.** Returns true on success.
    fn bin_sem_post(&self, sem: *mut c_void) -> bool;

    /// Post/signal a binary semaphore from ISR.
    ///
    /// **Optional.** Defaults to [`bin_sem_post`].
    ///
    /// [`bin_sem_post`]: CspArch::bin_sem_post
    fn bin_sem_post_isr(&self, sem: *mut c_void, _task_woken: *mut i32) -> bool {
        self.bin_sem_post(sem)
    }

    // ── Mutexes (REQUIRED) ──────────────────────────────────────────────────

    /// Create a mutex.
    ///
    /// **Required.** Returns a handle, or null on failure.
    fn mutex_create(&self) -> *mut c_void;

    /// Remove/destroy a mutex.
    ///
    /// **Required.**
    fn mutex_remove(&self, mutex: *mut c_void);

    /// Lock a mutex with timeout (ms).
    ///
    /// **Required.** Returns true on success, false on timeout.
    /// Note: `timeout` parameter may be ignored if your mutex implementation doesn't support it.
    fn mutex_lock(&self, mutex: *mut c_void, timeout: u32) -> bool;

    /// Unlock a mutex.
    ///
    /// **Required.** Returns true on success.
    fn mutex_unlock(&self, mutex: *mut c_void) -> bool;

    // ── Queues (REQUIRED) ───────────────────────────────────────────────────

    /// Create a queue.
    ///
    /// **Required.** Returns a handle, or null on failure.
    /// - `length` - max number of items in the queue
    /// - `item_size` - size of each item in bytes
    fn queue_create(&self, length: usize, item_size: usize) -> *mut c_void;

    /// Remove/destroy a queue.
    ///
    /// **Required.**
    fn queue_remove(&self, queue: *mut c_void);

    /// Enqueue an item with timeout (ms).
    ///
    /// **Required.** Copies `item_size` bytes from `item` into the queue.
    /// Returns true on success, false on timeout or full queue.
    /// `timeout` of 0xFFFFFFFF means wait forever.
    fn queue_enqueue(&self, queue: *mut c_void, item: *const c_void, timeout: u32) -> bool;

    /// Dequeue an item with timeout (ms).
    ///
    /// **Required.** Copies `item_size` bytes from the queue into `item`.
    /// Returns true on success, false on timeout or empty queue.
    /// `timeout` of 0xFFFFFFFF means wait forever.
    fn queue_dequeue(&self, queue: *mut c_void, item: *mut c_void, timeout: u32) -> bool;

    /// Get the current number of items in the queue.
    ///
    /// **Required.**
    fn queue_size(&self, queue: *mut c_void) -> usize;

    /// Enqueue an item from ISR context.
    ///
    /// **Optional.** Defaults to [`queue_enqueue`] with timeout=0.
    ///
    /// [`queue_enqueue`]: CspArch::queue_enqueue
    fn queue_enqueue_isr(&self, queue: *mut c_void, item: *const c_void, _task_woken: *mut i32) -> bool {
        self.queue_enqueue(queue, item, 0)
    }

    /// Dequeue an item from ISR context.
    ///
    /// **Optional.** Defaults to [`queue_dequeue`] with timeout=0.
    ///
    /// [`queue_dequeue`]: CspArch::queue_dequeue
    fn queue_dequeue_isr(&self, queue: *mut c_void, item: *mut c_void, _task_woken: *mut i32) -> bool {
        self.queue_dequeue(queue, item, 0)
    }

    /// Get queue size from ISR context.
    ///
    /// **Optional.** Defaults to [`queue_size`].
    ///
    /// [`queue_size`]: CspArch::queue_size
    fn queue_size_isr(&self, queue: *mut c_void) -> usize {
        self.queue_size(queue)
    }

    // ── Memory (REQUIRED) ───────────────────────────────────────────────────

    /// Allocate memory.
    ///
    /// **Required.** Returns a pointer, or null on failure.
    fn malloc(&self, size: usize) -> *mut c_void;

    /// Free memory.
    ///
    /// **Required.** `ptr` must have been returned by [`malloc`] or [`calloc`].
    ///
    /// [`malloc`]: CspArch::malloc
    /// [`calloc`]: CspArch::calloc
    fn free(&self, ptr: *mut c_void);

    /// Allocate and zero-initialize memory.
    ///
    /// **Optional.** Default implementation uses [`malloc`] + `memset`.
    ///
    /// [`malloc`]: CspArch::malloc
    fn calloc(&self, nmemb: usize, size: usize) -> *mut c_void {
        let total = nmemb * size;
        let ptr = self.malloc(total);
        if !ptr.is_null() {
            // Safety: `ptr` is a valid pointer newly allocated by `malloc`.
            unsafe { core::ptr::write_bytes(ptr, 0, total) };
        }
        ptr
    }
    
    // ── System Services (OPTIONAL) ──────────────────────────────────────────
    // These are used by CSP service handlers. If you don't use those services,
    // the default no-op implementations are fine.

    /// Return free heap memory in bytes.
    ///
    /// **Optional.** Used by the MEMFREE service. Defaults to 0.
    fn memfree(&self) -> u32 { 0 }

    /// Reboot the system.
    ///
    /// **Optional.** Used by the REBOOT service. Defaults to no-op that returns CSP_ERR_NONE (0).
    /// @return CSP_ERR_NONE (0) on success, or error code.
    fn reboot(&self) -> i32 { 0 /* CSP_ERR_NONE */ }

    /// Shutdown the system.
    ///
    /// **Optional.** Used by the SHUTDOWN service. Defaults to no-op that returns CSP_ERR_NONE (0).
    /// @return CSP_ERR_NONE (0) on success, or error code.
    fn shutdown(&self) -> i32 { 0 /* CSP_ERR_NONE */ }

    /// Get task list size.
    ///
    /// **Optional.** Used by the PS service. Defaults to 0.
    fn sys_tasklist_size(&self) -> i32 { 0 }

    /// Write task list to buffer.
    ///
    /// **Optional.** Used by the PS service. Defaults to no-op.
    fn sys_tasklist(&self, _out: *mut c_char) {}

    /// Set terminal color.
    ///
    /// **Optional.** Used for colored debug output. Defaults to no-op.
    fn sys_set_color(&self, _color: crate::sys::csp_color_t) {}

    // ── Clock/Timestamp (OPTIONAL) ──────────────────────────────────────────
    // These are for packet timestamps. Not needed for basic CSP operation.

    /// Get current timestamp.
    ///
    /// **Optional.** Defaults to no-op.
    fn clock_get_time(&self, _time: *mut c_void) {}

    /// Set current timestamp.
    ///
    /// **Optional.** Defaults to no-op.
    fn clock_set_time(&self, _time: *mut c_void) {}

    // ── Threading (OPTIONAL) ────────────────────────────────────────────────
    // Only needed if you want to use `CspNode::route_start_task()`.
    // If you call `CspNode::route_work()` manually, you don't need this.

    /// Create a thread.
    ///
    /// **Optional.** Only needed for [`CspNode::route_start_task`].
    /// Defaults to returning error (0).
    ///
    /// If you manually call [`CspNode::route_work`] in your own scheduler,
    /// you don't need to implement this.
    ///
    /// [`CspNode::route_start_task`]: crate::CspNode::route_start_task
    /// [`CspNode::route_work`]: crate::CspNode::route_work
    fn thread_create(&self, _f: unsafe extern "C" fn(*mut c_void), _name: *const c_char, _stack: u32, _arg: *mut c_void, _prio: u32, _handle: *mut *mut c_void) -> i32 { 0 }

    /// Sleep for milliseconds.
    ///
    /// **Optional, but recommended.** Used by some drivers (e.g., SocketCAN) for retry loops.
    /// Defaults to no-op, but this may cause busy-waiting in some cases.
    ///
    /// On embedded systems with an RTOS, this should call the OS delay function.
    /// On POSIX systems, use `nanosleep()`.
    fn sleep_ms(&self, _ms: u32) {}
}

// test_arch is a POSIX-based implementation for host platforms.
// It requires libc and is only available on Linux, macOS, and Windows.
#[cfg(all(
    any(test, feature = "external-arch"),
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
pub mod test_arch;

/// Helper macro to export a `CspArch` implementation to the C linker.
#[macro_export]
macro_rules! export_arch {
    ($impl_type:ty, $instance:expr) => {
        #[no_mangle] pub unsafe extern "C" fn csp_get_ms() -> u32 { <$impl_type as $crate::CspArch>::get_ms(&$instance) }
        #[no_mangle] pub unsafe extern "C" fn csp_get_s() -> u32 { <$impl_type as $crate::CspArch>::get_s(&$instance) }
        #[no_mangle] pub unsafe extern "C" fn csp_get_uptime_s() -> u32 { <$impl_type as $crate::CspArch>::get_uptime_s(&$instance) }
        #[no_mangle] pub unsafe extern "C" fn csp_get_ms_isr() -> u32 { <$impl_type as $crate::CspArch>::get_ms_isr(&$instance) }
        #[no_mangle] pub unsafe extern "C" fn csp_sleep_ms(ms: u32) { <$impl_type as $crate::CspArch>::sleep_ms(&$instance, ms) }

        #[no_mangle] pub unsafe extern "C" fn csp_bin_sem_create(sem: *mut *mut ::core::ffi::c_void) -> i32 {
            let s = <$impl_type as $crate::CspArch>::bin_sem_create(&$instance);
            // Safety: `sem` is a valid pointer provided by libcsp.
            if s.is_null() { 0 } else { unsafe { *sem = s }; 1 }
        }
        #[no_mangle] pub unsafe extern "C" fn csp_bin_sem_remove(sem: *mut *mut ::core::ffi::c_void) -> i32 {
            // Safety: `sem` is a valid pointer to a handle created by this macro.
            unsafe { <$impl_type as $crate::CspArch>::bin_sem_remove(&$instance, *sem) }; 1
        }
        #[no_mangle] pub unsafe extern "C" fn csp_bin_sem_wait(sem: *mut *mut ::core::ffi::c_void, timeout: u32) -> i32 {
            // Safety: `sem` is a valid pointer.
            if unsafe { <$impl_type as $crate::CspArch>::bin_sem_wait(&$instance, *sem, timeout) } { 1 } else { 0 }
        }
        #[no_mangle] pub unsafe extern "C" fn csp_bin_sem_post(sem: *mut *mut ::core::ffi::c_void) -> i32 {
            // Safety: `sem` is a valid pointer.
            if unsafe { <$impl_type as $crate::CspArch>::bin_sem_post(&$instance, *sem) } { 1 } else { 0 }
        }
        #[no_mangle] pub unsafe extern "C" fn csp_bin_sem_post_isr(sem: *mut *mut ::core::ffi::c_void, _px: *mut i32) -> i32 {
            // Safety: `sem` is a valid pointer.
            if unsafe { <$impl_type as $crate::CspArch>::bin_sem_post(&$instance, *sem) } { 1 } else { 0 }
        }

        #[no_mangle] pub unsafe extern "C" fn csp_mutex_create(mutex: *mut *mut ::core::ffi::c_void) -> i32 {
            let m = <$impl_type as $crate::CspArch>::mutex_create(&$instance);
            // Safety: `mutex` is a valid pointer provided by libcsp.
            if m.is_null() { 0 } else { unsafe { *mutex = m }; 1 }
        }
        #[no_mangle] pub unsafe extern "C" fn csp_mutex_remove(mutex: *mut *mut ::core::ffi::c_void) -> i32 {
            // Safety: `mutex` is a valid pointer to a handle created by this macro.
            unsafe { <$impl_type as $crate::CspArch>::mutex_remove(&$instance, *mutex) }; 1
        }
        #[no_mangle] pub unsafe extern "C" fn csp_mutex_lock(mutex: *mut *mut ::core::ffi::c_void, timeout: u32) -> i32 {
            // Safety: `mutex` is a valid pointer.
            if unsafe { <$impl_type as $crate::CspArch>::mutex_lock(&$instance, *mutex, timeout) } { 1 } else { 0 }
        }
        #[no_mangle] pub unsafe extern "C" fn csp_mutex_unlock(mutex: *mut *mut ::core::ffi::c_void, _timeout: u32) -> i32 {
            // Safety: `mutex` is a valid pointer.
            if unsafe { <$impl_type as $crate::CspArch>::mutex_unlock(&$instance, *mutex) } { 1 } else { 0 }
        }

        #[no_mangle] pub unsafe extern "C" fn csp_queue_create(length: i32, item_size: usize) -> *mut ::core::ffi::c_void {
            <$impl_type as $crate::CspArch>::queue_create(&$instance, length as usize, item_size)
        }
        #[no_mangle] pub unsafe extern "C" fn csp_queue_remove(queue: *mut ::core::ffi::c_void) {
            <$impl_type as $crate::CspArch>::queue_remove(&$instance, queue)
        }
        #[no_mangle] pub unsafe extern "C" fn csp_queue_enqueue(queue: *mut ::core::ffi::c_void, item: *const ::core::ffi::c_void, timeout: u32) -> i32 {
            if <$impl_type as $crate::CspArch>::queue_enqueue(&$instance, queue, item, timeout) { 1 } else { 0 }
        }
        #[no_mangle] pub unsafe extern "C" fn csp_queue_enqueue_isr(queue: *mut ::core::ffi::c_void, item: *const ::core::ffi::c_void, _px: *mut i32) -> i32 {
            if <$impl_type as $crate::CspArch>::queue_enqueue(&$instance, queue, item, 0) { 1 } else { 0 }
        }
        #[no_mangle] pub unsafe extern "C" fn csp_queue_dequeue(queue: *mut ::core::ffi::c_void, item: *mut ::core::ffi::c_void, timeout: u32) -> i32 {
            if <$impl_type as $crate::CspArch>::queue_dequeue(&$instance, queue, item, timeout) { 1 } else { 0 }
        }
        #[no_mangle] pub unsafe extern "C" fn csp_queue_dequeue_isr(queue: *mut ::core::ffi::c_void, item: *mut ::core::ffi::c_void, _px: *mut i32) -> i32 {
            if <$impl_type as $crate::CspArch>::queue_dequeue(&$instance, queue, item, 0) { 1 } else { 0 }
        }
        #[no_mangle] pub unsafe extern "C" fn csp_queue_size(queue: *mut ::core::ffi::c_void) -> i32 {
            <$impl_type as $crate::CspArch>::queue_size(&$instance, queue) as i32
        }
        #[no_mangle] pub unsafe extern "C" fn csp_queue_size_isr(queue: *mut ::core::ffi::c_void) -> i32 {
            <$impl_type as $crate::CspArch>::queue_size(&$instance, queue) as i32
        }

        #[no_mangle] pub unsafe extern "C" fn csp_malloc(size: usize) -> *mut ::core::ffi::c_void {
            <$impl_type as $crate::CspArch>::malloc(&$instance, size)
        }
        #[no_mangle] pub unsafe extern "C" fn csp_calloc(nmemb: usize, size: usize) -> *mut ::core::ffi::c_void {
            <$impl_type as $crate::CspArch>::calloc(&$instance, nmemb, size)
        }
        #[no_mangle] pub unsafe extern "C" fn csp_free(ptr: *mut ::core::ffi::c_void) {
            <$impl_type as $crate::CspArch>::free(&$instance, ptr)
        }

        #[no_mangle] pub unsafe extern "C" fn csp_sys_memfree() -> u32 { <$impl_type as $crate::CspArch>::memfree(&$instance) }
        #[no_mangle] pub unsafe extern "C" fn csp_sys_reboot() -> i32 { <$impl_type as $crate::CspArch>::reboot(&$instance) }
        #[no_mangle] pub unsafe extern "C" fn csp_sys_shutdown() -> i32 { <$impl_type as $crate::CspArch>::shutdown(&$instance) }
        
        #[no_mangle] pub unsafe extern "C" fn csp_clock_get_time(time: *mut ::core::ffi::c_void) { <$impl_type as $crate::CspArch>::clock_get_time(&$instance, time) }
        #[no_mangle] pub unsafe extern "C" fn csp_clock_set_time(time: *mut ::core::ffi::c_void) { <$impl_type as $crate::CspArch>::clock_set_time(&$instance, time) }
        
        #[no_mangle] pub unsafe extern "C" fn csp_sys_tasklist_size() -> i32 { <$impl_type as $crate::CspArch>::sys_tasklist_size(&$instance) }
        #[no_mangle] pub unsafe extern "C" fn csp_sys_tasklist(out: *mut ::core::ffi::c_char) { <$impl_type as $crate::CspArch>::sys_tasklist(&$instance, out) }
        #[no_mangle] pub unsafe extern "C" fn csp_sys_set_color(color: $crate::sys::csp_color_t) { <$impl_type as $crate::CspArch>::sys_set_color(&$instance, color) }
        #[no_mangle] pub unsafe extern "C" fn csp_thread_create(f: unsafe extern "C" fn(*mut ::core::ffi::c_void), name: *const ::core::ffi::c_char, stack: u32, arg: *mut ::core::ffi::c_void, prio: u32, handle: *mut *mut ::core::ffi::c_void) -> i32 {
            // Wrap the unsafe function pointer in a safe wrapper
            extern "C" fn wrapper(arg: *mut ::core::ffi::c_void) {
                // Safety: This is the actual thread entry point from libcsp.
                // The function pointer was originally unsafe extern "C", so we call it with unsafe.
                unsafe {
                    // Retrieve the original function pointer from thread-local or static storage
                    // For now, we need to use transmute as there's no other way to convert
                    // between function pointer types with different safety.
                    let f_ptr = THREAD_ENTRY_POINT.load(core::sync::atomic::Ordering::Acquire);
                    if f_ptr != 0 {
                        let f: unsafe extern "C" fn(*mut ::core::ffi::c_void) = core::mem::transmute(f_ptr);
                        f(arg);
                    }
                }
            }

            // Store the function pointer in a static for the wrapper to access
            static THREAD_ENTRY_POINT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
            THREAD_ENTRY_POINT.store(f as usize, core::sync::atomic::Ordering::Release);

            <$impl_type as $crate::CspArch>::thread_create(&$instance, wrapper, name, stack, arg, prio, handle)
        }
    };
}
