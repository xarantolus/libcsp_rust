//! Traits and helpers for providing custom architecture implementations.

use core::ffi::{c_char, c_void};

/// Trait for implementing OS-specific primitives for libcsp.
///
/// ## Minimal Required Implementation
///
/// To use CSP with `external-arch`, you **must** implement:
/// - Time: [`get_ms`], [`get_s`]
/// - Mutexes: [`mutex_create`], [`mutex_remove`], [`mutex_lock`], [`mutex_unlock`]
/// - Binary Semaphores: [`bin_sem_create`], [`bin_sem_remove`], [`bin_sem_wait`], [`bin_sem_post`]
/// - Queues: [`queue_create`], [`queue_remove`], [`queue_enqueue`], [`queue_dequeue`], [`queue_size`]
///
/// ## Optional Functions
///
/// These have default implementations or are only needed for specific features:
/// - ISR variants (`get_ms_isr`, `bin_sem_post_isr`, `queue_*_isr`) - default to non-ISR versions
/// - [`thread_create`] - only needed if you want to spawn the router as a thread
/// - [`sleep_ms`] - convenience function, no-op by default
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
/// [`thread_create`]: CspArch::thread_create
/// [`sleep_ms`]: CspArch::sleep_ms
///
/// # Safety
///
/// Implementing this trait requires correctly implementing all the architecture-specific
/// primitives with valid pointer handling. Many methods take raw pointers that must be
/// valid for the operation being performed. Incorrect implementations can lead to
/// undefined behavior, memory corruption, or crashes.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub unsafe trait CspArch: Send + Sync {
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
    fn get_ms_isr(&self) -> u32 {
        self.get_ms()
    }

    /// Return uptime in seconds.
    ///
    /// **Optional.** Defaults to [`get_s`].
    ///
    /// [`get_s`]: CspArch::get_s
    fn get_uptime_s(&self) -> u32 {
        self.get_s()
    }

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

    /// Number of free slots in the queue (capacity − items).
    ///
    /// Backs `csp_queue_free`. Upstream's POSIX/FreeRTOS/Zephyr backends all
    /// return free-slot count here, and `csp_rdp_rx_queue_flush` relies on
    /// that — it bails out early when fewer than two slots are free.
    ///
    /// **Optional.** The default returns `usize::MAX` (i.e. "always has
    /// space"), which keeps callers like `csp_rdp_rx_queue_flush` working
    /// without forcing every existing arch impl to grow a method overnight.
    /// Implement it for accurate flow control.
    fn queue_free_slots(&self, _queue: *mut c_void) -> usize {
        usize::MAX
    }

    /// Enqueue an item from ISR context.
    ///
    /// **Optional.** Defaults to [`queue_enqueue`] with timeout=0.
    ///
    /// [`queue_enqueue`]: CspArch::queue_enqueue
    fn queue_enqueue_isr(
        &self,
        queue: *mut c_void,
        item: *const c_void,
        _task_woken: *mut i32,
    ) -> bool {
        self.queue_enqueue(queue, item, 0)
    }

    /// Dequeue an item from ISR context.
    ///
    /// **Optional.** Defaults to [`queue_dequeue`] with timeout=0.
    ///
    /// [`queue_dequeue`]: CspArch::queue_dequeue
    fn queue_dequeue_isr(
        &self,
        queue: *mut c_void,
        item: *mut c_void,
        _task_woken: *mut i32,
    ) -> bool {
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

    // ── CSP hooks (OPTIONAL) ────────────────────────────────────────────────
    // Backing functions for libcsp's CMP services (MEMFREE, REBOOT, PS, …).
    // Defaults are no-ops that return harmless values.

    /// Return free heap memory in bytes. Backs `csp_memfree_hook`.
    fn memfree_hook(&self) -> u32 {
        0
    }

    /// Reboot the system. Backs `csp_reboot_hook`. Default: no-op.
    fn reboot_hook(&self) {}

    /// Shut down the system. Backs `csp_shutdown_hook`. Default: no-op.
    fn shutdown_hook(&self) {}

    /// Fill `packet` with process/task information. Backs `csp_ps_hook`.
    /// Returns the number of entries written. Default: 0.
    ///
    /// # Safety
    /// The provided pointer is a valid `csp_packet_t *` when libcsp invokes it.
    fn ps_hook(&self, _packet: *mut crate::sys::csp_packet_t) -> u32 {
        0
    }

    /// Last-resort handler invoked by libcsp when an invariant fails.
    /// Should not return. Default: busy-loop.
    ///
    /// # Safety
    /// `msg` points to a NUL-terminated C string.
    fn panic(&self, _msg: *const c_char) -> ! {
        loop {
            core::hint::spin_loop();
        }
    }

    // ── Clock/Timestamp (OPTIONAL) ──────────────────────────────────────────
    // Back `csp_clock_get_time` / `csp_clock_set_time` hooks in csp_hooks.h.
    // Default implementations do nothing, which is fine if you never use the
    // CMP CLOCK service or packet timestamps.

    /// Populate `*time` (a `csp_timestamp_t`) with the current wall-clock time.
    fn clock_get_time(&self, _time: *mut c_void) {}

    /// Accept a wall-clock time (a `csp_timestamp_t`). Return 0 on success,
    /// negative on failure (e.g. `CSP_ERR_INVAL`).
    fn clock_set_time(&self, _time: *const c_void) -> i32 {
        0
    }

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
    fn thread_create(
        &self,
        _f: unsafe extern "C" fn(*mut c_void),
        _name: *const c_char,
        _stack: u32,
        _arg: *mut c_void,
        _prio: u32,
        _handle: *mut *mut c_void,
    ) -> i32 {
        0
    }

    /// Sleep for milliseconds.
    ///
    /// **Optional, but recommended.** Used by some drivers (e.g., SocketCAN) for retry loops.
    /// Defaults to no-op, but this may cause busy-waiting in some cases.
    ///
    /// On embedded systems with an RTOS, this should call the OS delay function.
    /// On POSIX systems, use `nanosleep()`.
    fn sleep_ms(&self, _ms: u32) {}

    // ── C String Functions (OPTIONAL) ───────────────────────────────────────
    // These are required by libcsp's C code but may not be available in no_std environments.
    // Default implementations are provided via tinyrlibc (when external-arch is enabled)
    // or simple Rust implementations. Override these if you need locale-aware or more
    // sophisticated string handling.

    /// Copy up to `n` bytes from `src` to `dest`, padding with zeros if `src` is shorter.
    ///
    /// **Optional.** Used by CSP services (CMP ident). Default implementation provided.
    /// This is `strncpy` from the C standard library.
    ///
    /// # Safety
    /// Caller must ensure `dest` and `src` are valid pointers and `dest` has enough space.
    fn strncpy(&self, dest: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
        unsafe {
            let mut i = 0;
            // Copy until null or n bytes
            while i < n && *src.add(i) != 0 {
                *dest.add(i) = *src.add(i);
                i += 1;
            }
            // Pad remaining with zeros
            while i < n {
                *dest.add(i) = 0;
                i += 1;
            }
            dest
        }
    }

    /// Copy string from `src` to `dest` including null terminator.
    ///
    /// **Optional.** Used by CSP services (PS error messages). Default implementation provided.
    /// This is `strcpy` from the C standard library.
    ///
    /// # Safety
    /// Caller must ensure `dest` and `src` are valid pointers and `dest` has enough space.
    fn strcpy(&self, dest: *mut c_char, src: *const c_char) -> *mut c_char {
        unsafe {
            let mut i = 0;
            loop {
                *dest.add(i) = *src.add(i);
                if *src.add(i) == 0 {
                    break;
                }
                i += 1;
            }
            dest
        }
    }

    /// Get the length of a string, up to `maxlen` bytes.
    ///
    /// **Optional.** Used by CSP routing and services. Default implementation provided.
    /// This is `strnlen` from the C standard library.
    ///
    /// # Safety
    /// Caller must ensure `s` is a valid pointer.
    fn strnlen(&self, s: *const c_char, maxlen: usize) -> usize {
        unsafe {
            let mut len = 0;
            while len < maxlen && *s.add(len) != 0 {
                len += 1;
            }
            len
        }
    }

    /// Compare two strings case-insensitively, up to `n` bytes.
    ///
    /// **Optional.** Used by CSP interface lookup. Default implementation provided.
    /// This is `strncasecmp` from the C standard library.
    /// Returns 0 if equal, <0 if s1 < s2, >0 if s1 > s2.
    ///
    /// # Safety
    /// Caller must ensure `s1` and `s2` are valid pointers.
    fn strncasecmp(&self, s1: *const c_char, s2: *const c_char, n: usize) -> i32 {
        unsafe {
            for i in 0..n {
                let c1 = (*s1.add(i) as u8).to_ascii_lowercase();
                let c2 = (*s2.add(i) as u8).to_ascii_lowercase();
                if c1 != c2 || c1 == 0 {
                    return (c1 as i32) - (c2 as i32);
                }
            }
            0
        }
    }

    /// Tokenize a string with a delimiter.
    ///
    /// **Optional, CRITICAL for route_load().** Used by CSP routing table parser. Default implementation provided.
    /// This is `strtok_r` from the C standard library.
    ///
    /// On first call, pass the string to tokenize as `s`. On subsequent calls, pass `null` to continue tokenizing.
    /// `delim` is the set of delimiter characters. `saveptr` stores state between calls.
    ///
    /// # Safety
    /// Caller must ensure `s`, `delim`, and `saveptr` are valid pointers (or `s` is null for continuation).
    fn strtok_r(
        &self,
        s: *mut c_char,
        delim: *const c_char,
        saveptr: *mut *mut c_char,
    ) -> *mut c_char {
        unsafe {
            let mut str = if s.is_null() { *saveptr } else { s };
            if str.is_null() {
                return core::ptr::null_mut();
            }

            // Skip leading delimiters
            while *str != 0 {
                let mut is_delim = false;
                let mut d = delim;
                while *d != 0 {
                    if *str == *d {
                        is_delim = true;
                        break;
                    }
                    d = d.add(1);
                }
                if !is_delim {
                    break;
                }
                str = str.add(1);
            }

            if *str == 0 {
                *saveptr = core::ptr::null_mut();
                return core::ptr::null_mut();
            }

            let token = str;

            // Find end of token
            while *str != 0 {
                let mut is_delim = false;
                let mut d = delim;
                while *d != 0 {
                    if *str == *d {
                        is_delim = true;
                        break;
                    }
                    d = d.add(1);
                }
                if is_delim {
                    *str = 0;
                    str = str.add(1);
                    break;
                }
                str = str.add(1);
            }

            *saveptr = str;
            token
        }
    }
}

// test_arch is a POSIX-based implementation for host platforms.
// It requires libc and std, and is only available on Linux, macOS, and Windows.
#[cfg(all(
    feature = "std",
    any(test, feature = "external-arch"),
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
pub mod test_arch;

/// Helper macro to export a `CspArch` implementation to the C linker.
#[macro_export]
macro_rules! export_arch {
    ($impl_type:ty, $instance:expr) => {
        #[allow(unexpected_cfgs)]
        #[cfg(not(feature = "ropi-rwpi"))]
        #[no_mangle]
        pub unsafe extern "C" fn csp_get_ms() -> u32 {
            <$impl_type as $crate::CspArch>::get_ms(&$instance)
        }
        #[allow(unexpected_cfgs)]
        #[cfg(feature = "ropi-rwpi")]
        #[no_mangle]
        pub unsafe extern "C" fn csp_get_ms_impl() -> u32 {
            <$impl_type as $crate::CspArch>::get_ms(&$instance)
        }
        #[no_mangle]
        pub unsafe extern "C" fn csp_get_s() -> u32 {
            <$impl_type as $crate::CspArch>::get_s(&$instance)
        }
        #[no_mangle]
        pub unsafe extern "C" fn csp_get_uptime_s() -> u32 {
            <$impl_type as $crate::CspArch>::get_uptime_s(&$instance)
        }
        #[allow(unexpected_cfgs)]
        #[cfg(not(feature = "ropi-rwpi"))]
        #[no_mangle]
        pub unsafe extern "C" fn csp_get_ms_isr() -> u32 {
            <$impl_type as $crate::CspArch>::get_ms_isr(&$instance)
        }
        #[allow(unexpected_cfgs)]
        #[cfg(feature = "ropi-rwpi")]
        #[no_mangle]
        pub unsafe extern "C" fn csp_get_ms_isr_impl() -> u32 {
            <$impl_type as $crate::CspArch>::get_ms_isr(&$instance)
        }
        #[no_mangle]
        pub unsafe extern "C" fn csp_sleep_ms(ms: u32) {
            <$impl_type as $crate::CspArch>::sleep_ms(&$instance, ms)
        }

        // libcsp v2.1 convention: CSP_SEMAPHORE_OK = 0, _ERROR = -1.
        // (Earlier versions used 1/0, which is what this macro used to emit.)
        #[no_mangle]
        pub unsafe extern "C" fn csp_bin_sem_create(sem: *mut *mut ::core::ffi::c_void) -> i32 {
            if sem.is_null() {
                return -1;
            }
            let s = <$impl_type as $crate::CspArch>::bin_sem_create(&$instance);
            if s.is_null() {
                -1
            } else {
                unsafe { *sem = s };
                0
            }
        }
        #[no_mangle]
        pub unsafe extern "C" fn csp_bin_sem_remove(sem: *mut *mut ::core::ffi::c_void) -> i32 {
            if sem.is_null() {
                return -1;
            }
            unsafe { <$impl_type as $crate::CspArch>::bin_sem_remove(&$instance, *sem) };
            0
        }
        /// Upstream (v2.1, csp_semaphore.h): the sem is initialised in the
        /// unlocked (posted, value 1) state. Callers embed `csp_bin_sem_t`
        /// directly in their structs; we store a pointer in the slot.
        #[no_mangle]
        pub unsafe extern "C" fn csp_bin_sem_init(sem: *mut *mut ::core::ffi::c_void) {
            if sem.is_null() {
                return;
            }
            let s = <$impl_type as $crate::CspArch>::bin_sem_create(&$instance);
            if !s.is_null() {
                /* create returns a locked sem; post once so it starts unlocked. */
                unsafe {
                    <$impl_type as $crate::CspArch>::bin_sem_post(&$instance, s);
                    *sem = s;
                }
            }
        }
        #[no_mangle]
        pub unsafe extern "C" fn csp_bin_sem_wait(
            sem: *mut *mut ::core::ffi::c_void,
            timeout: u32,
        ) -> i32 {
            if sem.is_null() {
                return -1;
            }
            if unsafe { <$impl_type as $crate::CspArch>::bin_sem_wait(&$instance, *sem, timeout) } {
                0
            } else {
                -1
            }
        }
        #[no_mangle]
        pub unsafe extern "C" fn csp_bin_sem_post(sem: *mut *mut ::core::ffi::c_void) -> i32 {
            if sem.is_null() {
                return -1;
            }
            if unsafe { <$impl_type as $crate::CspArch>::bin_sem_post(&$instance, *sem) } {
                0
            } else {
                -1
            }
        }
        #[no_mangle]
        pub unsafe extern "C" fn csp_bin_sem_post_isr(
            sem: *mut *mut ::core::ffi::c_void,
            _px: *mut i32,
        ) -> i32 {
            if sem.is_null() {
                return -1;
            }
            if unsafe { <$impl_type as $crate::CspArch>::bin_sem_post(&$instance, *sem) } {
                0
            } else {
                -1
            }
        }

        #[no_mangle]
        pub unsafe extern "C" fn csp_mutex_create(mutex: *mut *mut ::core::ffi::c_void) -> i32 {
            if mutex.is_null() {
                return -1;
            }
            let m = <$impl_type as $crate::CspArch>::mutex_create(&$instance);
            if m.is_null() {
                -1
            } else {
                unsafe { *mutex = m };
                0
            }
        }
        #[no_mangle]
        pub unsafe extern "C" fn csp_mutex_remove(mutex: *mut *mut ::core::ffi::c_void) -> i32 {
            if mutex.is_null() {
                return -1;
            }
            unsafe { <$impl_type as $crate::CspArch>::mutex_remove(&$instance, *mutex) };
            0
        }
        #[no_mangle]
        pub unsafe extern "C" fn csp_mutex_lock(
            mutex: *mut *mut ::core::ffi::c_void,
            timeout: u32,
        ) -> i32 {
            if mutex.is_null() {
                return -1;
            }
            if unsafe { <$impl_type as $crate::CspArch>::mutex_lock(&$instance, *mutex, timeout) } {
                0
            } else {
                -1
            }
        }
        #[no_mangle]
        pub unsafe extern "C" fn csp_mutex_unlock(
            mutex: *mut *mut ::core::ffi::c_void,
            _timeout: u32,
        ) -> i32 {
            if mutex.is_null() {
                return -1;
            }
            if unsafe { <$impl_type as $crate::CspArch>::mutex_unlock(&$instance, *mutex) } {
                0
            } else {
                -1
            }
        }

        // libcsp v2.1 convention: CSP_QUEUE_OK = 0, CSP_QUEUE_ERROR = -1.
        // Upstream calls `csp_queue_create_static` (not `csp_queue_create`);
        // our external-arch ignores the preallocated buffer / queue slot and
        // heap-allocates, same as libcsp's POSIX backend.
        #[allow(unexpected_cfgs)]
        #[cfg(not(feature = "ropi-rwpi"))]
        #[no_mangle]
        pub unsafe extern "C" fn csp_queue_create_static(
            length: i32,
            item_size: usize,
            _buffer: *mut ::core::ffi::c_char,
            _queue: *mut ::core::ffi::c_void,
        ) -> *mut ::core::ffi::c_void {
            if length <= 0 {
                return core::ptr::null_mut();
            }
            <$impl_type as $crate::CspArch>::queue_create(&$instance, length as usize, item_size)
        }
        #[allow(unexpected_cfgs)]
        #[cfg(feature = "ropi-rwpi")]
        #[no_mangle]
        pub unsafe extern "C" fn csp_queue_create_static_impl(
            length: i32,
            item_size: usize,
            _buffer: *mut ::core::ffi::c_char,
            _queue: *mut ::core::ffi::c_void,
        ) -> *mut ::core::ffi::c_void {
            if length <= 0 {
                return core::ptr::null_mut();
            }
            <$impl_type as $crate::CspArch>::queue_create(&$instance, length as usize, item_size)
        }
        /// Upstream contract: `csp_queue_free` returns the number of free
        /// slots in the queue (capacity − used), NOT a destructor. All three
        /// in-tree backends (POSIX/FreeRTOS/Zephyr) match this. Misreading
        /// it as a destructor used to tear down `conn->rx_queue` the first
        /// time `csp_rdp_rx_queue_flush` checked for headroom — UAF on the
        /// next enqueue. Cap to `i32::MAX` since the C return type is `int`.
        #[no_mangle]
        pub unsafe extern "C" fn csp_queue_free(queue: *mut ::core::ffi::c_void) -> i32 {
            let free = <$impl_type as $crate::CspArch>::queue_free_slots(&$instance, queue);
            if free > i32::MAX as usize {
                i32::MAX
            } else {
                free as i32
            }
        }
        /// Drain without freeing. The default impl loops `queue_dequeue` into
        /// a small scratch buffer until empty; backends may override for a
        /// constant-time reset.
        #[no_mangle]
        pub unsafe extern "C" fn csp_queue_empty(queue: *mut ::core::ffi::c_void) {
            /* 8 bytes is large enough for libcsp's internal queue items
               (`csp_packet_t *` or `csp_qfifo_t` = one or two pointers). */
            let mut scratch = [0u8; 16];
            while <$impl_type as $crate::CspArch>::queue_dequeue(
                &$instance,
                queue,
                scratch.as_mut_ptr() as *mut ::core::ffi::c_void,
                0,
            ) {}
        }
        #[no_mangle]
        pub unsafe extern "C" fn csp_queue_enqueue(
            queue: *mut ::core::ffi::c_void,
            item: *const ::core::ffi::c_void,
            timeout: u32,
        ) -> i32 {
            if <$impl_type as $crate::CspArch>::queue_enqueue(&$instance, queue, item, timeout) {
                0
            } else {
                -1
            }
        }
        #[no_mangle]
        pub unsafe extern "C" fn csp_queue_enqueue_isr(
            queue: *mut ::core::ffi::c_void,
            item: *const ::core::ffi::c_void,
            _px: *mut i32,
        ) -> i32 {
            if <$impl_type as $crate::CspArch>::queue_enqueue(&$instance, queue, item, 0) {
                0
            } else {
                -1
            }
        }
        #[no_mangle]
        pub unsafe extern "C" fn csp_queue_dequeue(
            queue: *mut ::core::ffi::c_void,
            item: *mut ::core::ffi::c_void,
            timeout: u32,
        ) -> i32 {
            if <$impl_type as $crate::CspArch>::queue_dequeue(&$instance, queue, item, timeout) {
                0
            } else {
                -1
            }
        }
        #[no_mangle]
        pub unsafe extern "C" fn csp_queue_dequeue_isr(
            queue: *mut ::core::ffi::c_void,
            item: *mut ::core::ffi::c_void,
            _px: *mut i32,
        ) -> i32 {
            if <$impl_type as $crate::CspArch>::queue_dequeue(&$instance, queue, item, 0) {
                0
            } else {
                -1
            }
        }
        #[no_mangle]
        pub unsafe extern "C" fn csp_queue_size(queue: *mut ::core::ffi::c_void) -> i32 {
            <$impl_type as $crate::CspArch>::queue_size(&$instance, queue) as i32
        }
        #[no_mangle]
        pub unsafe extern "C" fn csp_queue_size_isr(queue: *mut ::core::ffi::c_void) -> i32 {
            <$impl_type as $crate::CspArch>::queue_size(&$instance, queue) as i32
        }

        #[no_mangle]
        pub unsafe extern "C" fn csp_memfree_hook() -> u32 {
            <$impl_type as $crate::CspArch>::memfree_hook(&$instance)
        }
        #[no_mangle]
        pub unsafe extern "C" fn csp_reboot_hook() {
            <$impl_type as $crate::CspArch>::reboot_hook(&$instance)
        }
        #[no_mangle]
        pub unsafe extern "C" fn csp_shutdown_hook() {
            <$impl_type as $crate::CspArch>::shutdown_hook(&$instance)
        }
        #[no_mangle]
        pub unsafe extern "C" fn csp_ps_hook(packet: *mut $crate::sys::csp_packet_t) -> u32 {
            <$impl_type as $crate::CspArch>::ps_hook(&$instance, packet)
        }
        #[no_mangle]
        pub unsafe extern "C" fn csp_panic(msg: *const ::core::ffi::c_char) -> ! {
            <$impl_type as $crate::CspArch>::panic(&$instance, msg)
        }

        #[no_mangle]
        pub unsafe extern "C" fn csp_clock_get_time(time: *mut ::core::ffi::c_void) {
            <$impl_type as $crate::CspArch>::clock_get_time(&$instance, time)
        }
        #[no_mangle]
        pub unsafe extern "C" fn csp_clock_set_time(time: *const ::core::ffi::c_void) -> i32 {
            <$impl_type as $crate::CspArch>::clock_set_time(&$instance, time)
        }
        #[no_mangle]
        pub unsafe extern "C" fn csp_thread_create(
            f: unsafe extern "C" fn(*mut ::core::ffi::c_void),
            name: *const ::core::ffi::c_char,
            stack: u32,
            arg: *mut ::core::ffi::c_void,
            prio: u32,
            handle: *mut *mut ::core::ffi::c_void,
        ) -> i32 {
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
                        let f: unsafe extern "C" fn(*mut ::core::ffi::c_void) =
                            core::mem::transmute(f_ptr);
                        f(arg);
                    }
                }
            }

            // Store the function pointer in a static for the wrapper to access
            static THREAD_ENTRY_POINT: core::sync::atomic::AtomicUsize =
                core::sync::atomic::AtomicUsize::new(0);
            THREAD_ENTRY_POINT.store(f as usize, core::sync::atomic::Ordering::Release);

            <$impl_type as $crate::CspArch>::thread_create(
                &$instance, wrapper, name, stack, arg, prio, handle,
            )
        }

        // C string / PRNG fallbacks for bare-metal targets that don't link
        // libc. On hosted targets (Linux/macOS/Windows) the system libc
        // already provides these and `#[no_mangle]` would either collide at
        // link time or shadow libc — see issue #18 in the safety review.
        // Gate on `target_os = "none"` (the convention for thumb*-none-eabi
        // / arm-none-eabi etc.) so the macro stays usable on hosts for
        // tests, while still providing the symbols where they're actually
        // needed.
        #[cfg(target_os = "none")]
        #[no_mangle]
        pub unsafe extern "C" fn strncpy(
            dest: *mut ::core::ffi::c_char,
            src: *const ::core::ffi::c_char,
            n: usize,
        ) -> *mut ::core::ffi::c_char {
            <$impl_type as $crate::CspArch>::strncpy(&$instance, dest, src, n)
        }
        #[cfg(target_os = "none")]
        #[no_mangle]
        pub unsafe extern "C" fn strcpy(
            dest: *mut ::core::ffi::c_char,
            src: *const ::core::ffi::c_char,
        ) -> *mut ::core::ffi::c_char {
            <$impl_type as $crate::CspArch>::strcpy(&$instance, dest, src)
        }
        #[cfg(target_os = "none")]
        #[no_mangle]
        pub unsafe extern "C" fn strnlen(s: *const ::core::ffi::c_char, maxlen: usize) -> usize {
            <$impl_type as $crate::CspArch>::strnlen(&$instance, s, maxlen)
        }
        #[cfg(target_os = "none")]
        #[no_mangle]
        pub unsafe extern "C" fn strncasecmp(
            s1: *const ::core::ffi::c_char,
            s2: *const ::core::ffi::c_char,
            n: usize,
        ) -> i32 {
            <$impl_type as $crate::CspArch>::strncasecmp(&$instance, s1, s2, n)
        }
        #[cfg(target_os = "none")]
        #[no_mangle]
        pub unsafe extern "C" fn strtok_r(
            s: *mut ::core::ffi::c_char,
            delim: *const ::core::ffi::c_char,
            saveptr: *mut *mut ::core::ffi::c_char,
        ) -> *mut ::core::ffi::c_char {
            <$impl_type as $crate::CspArch>::strtok_r(&$instance, s, delim, saveptr)
        }
        // NOTE: sscanf is provided by mini-scanf (compiled from C with varargs support)
        // when external-arch feature is enabled. It's linked automatically.
        // On POSIX platforms, the system libc sscanf is used.

        #[cfg(target_os = "none")]
        #[no_mangle]
        pub unsafe extern "C" fn strncmp(
            s1: *const ::core::ffi::c_char,
            s2: *const ::core::ffi::c_char,
            n: usize,
        ) -> i32 {
            let mut i = 0;
            while i < n {
                let a = unsafe { *s1.add(i) } as u8;
                let b = unsafe { *s2.add(i) } as u8;
                if a != b {
                    return a as i32 - b as i32;
                }
                if a == 0 {
                    return 0;
                }
                i += 1;
            }
            0
        }

        // Additional C library stubs that may be needed by some platforms.
        // xorshift32 PRNG — libcsp uses this for RDP retransmit jitter, so any
        // deterministic pseudo-random sequence works.
        #[cfg(target_os = "none")]
        #[no_mangle]
        pub extern "C" fn rand() -> i32 {
            static STATE: ::core::sync::atomic::AtomicU32 =
                ::core::sync::atomic::AtomicU32::new(0xDEAD_BEEF);
            let mut s = STATE.load(::core::sync::atomic::Ordering::Relaxed);
            if s == 0 {
                s = 1;
            }
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            STATE.store(s, ::core::sync::atomic::Ordering::Relaxed);
            (s & 0x7FFF_FFFF) as i32
        }
        #[cfg(target_os = "none")]
        #[no_mangle]
        pub extern "C" fn srand(_seed: u32) {}
        #[cfg(target_os = "none")]
        #[no_mangle]
        pub unsafe extern "C" fn rand_r(seed: *mut u32) -> i32 {
            if seed.is_null() {
                return 0;
            }
            let mut s = unsafe { *seed };
            if s == 0 {
                s = 1;
            }
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            unsafe { *seed = s };
            (s & 0x7FFF_FFFF) as i32
        }
        #[cfg(target_os = "none")]
        #[no_mangle]
        pub extern "C" fn _embassy_time_schedule_wake(_at: u64) {}
    };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "arch_tests.rs"]
mod arch_tests;
