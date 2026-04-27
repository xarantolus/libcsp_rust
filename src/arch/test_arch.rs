use crate::arch::CspArch;
use core::ffi::{c_char, c_void};

use std::collections::VecDeque;
use std::sync::{Condvar, Mutex};

/// Single canonical layout for the test backend's queue handle.
///
/// The previous implementation redeclared `TestQueue` inside each
/// `queue_create` / `queue_enqueue` / `queue_dequeue` / `queue_size` method.
/// Locally-defined nominal types in different functions are *distinct* even
/// when structurally identical, and `repr(Rust)` makes no layout guarantees
/// across distinct types — so the cross-method casts were technically UB.
/// Hoisting it once here, with `#[repr(C)]`, makes the layout an FFI-stable
/// contract.
#[repr(C)]
struct TestQueue {
    data: Mutex<VecDeque<Vec<u8>>>,
    not_empty: Condvar,
    not_full: Condvar,
    max_len: usize,
    item_size: usize,
}

pub struct TestArch;

// Allow clippy::not_unsafe_ptr_arg_deref because:
// - The CspArch trait is already marked `unsafe trait`
// - All methods are only called from unsafe contexts (export_arch! macro)
// - Marking individual methods unsafe would complicate the API
#[allow(clippy::not_unsafe_ptr_arg_deref)]
// Safety: This implementation uses POSIX/libc primitives correctly.
// All pointer operations are validated and follow the platform's ABI.
unsafe impl CspArch for TestArch {
    fn get_ms(&self) -> u32 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // Safety: `ts` is a valid pointer.
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        (ts.tv_sec as u32)
            .wrapping_mul(1000)
            .wrapping_add((ts.tv_nsec / 1_000_000) as u32)
    }
    fn get_s(&self) -> u32 {
        self.get_ms() / 1000
    }
    fn bin_sem_create(&self) -> *mut c_void {
        unsafe {
            let sem = libc::malloc(core::mem::size_of::<libc::sem_t>()) as *mut libc::sem_t;
            if sem.is_null() {
                return core::ptr::null_mut();
            }
            if libc::sem_init(sem, 0, 1) == 0 {
                sem as *mut c_void
            } else {
                libc::free(sem as *mut c_void);
                core::ptr::null_mut()
            }
        }
    }
    fn bin_sem_remove(&self, sem: *mut c_void) {
        unsafe {
            libc::sem_destroy(sem as *mut libc::sem_t);
            libc::free(sem);
        }
    }
    fn bin_sem_wait(&self, sem: *mut c_void, timeout: u32) -> bool {
        unsafe {
            if timeout == 0xFFFF_FFFF {
                libc::sem_wait(sem as *mut libc::sem_t) == 0
            } else {
                let mut ts = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                };
                libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
                ts.tv_sec += (timeout / 1000) as libc::time_t;
                ts.tv_nsec += ((timeout % 1000) * 1_000_000) as libc::c_long;
                if ts.tv_nsec >= 1_000_000_000 {
                    ts.tv_sec += 1;
                    ts.tv_nsec -= 1_000_000_000;
                }
                libc::sem_timedwait(sem as *mut libc::sem_t, &ts) == 0
            }
        }
    }
    fn bin_sem_post(&self, sem: *mut c_void) -> bool {
        unsafe { libc::sem_post(sem as *mut libc::sem_t) == 0 }
    }

    fn mutex_create(&self) -> *mut c_void {
        unsafe {
            let mutex = libc::malloc(core::mem::size_of::<libc::pthread_mutex_t>())
                as *mut libc::pthread_mutex_t;
            if mutex.is_null() {
                return core::ptr::null_mut();
            }
            if libc::pthread_mutex_init(mutex, core::ptr::null()) == 0 {
                mutex as *mut c_void
            } else {
                libc::free(mutex as *mut c_void);
                core::ptr::null_mut()
            }
        }
    }
    fn mutex_remove(&self, mutex: *mut c_void) {
        unsafe {
            libc::pthread_mutex_destroy(mutex as *mut libc::pthread_mutex_t);
            libc::free(mutex);
        }
    }
    fn mutex_lock(&self, mutex: *mut c_void, _timeout: u32) -> bool {
        unsafe { libc::pthread_mutex_lock(mutex as *mut libc::pthread_mutex_t) == 0 }
    }
    fn mutex_unlock(&self, mutex: *mut c_void) -> bool {
        unsafe { libc::pthread_mutex_unlock(mutex as *mut libc::pthread_mutex_t) == 0 }
    }

    // ── Queues ────────────────────────────────────────────────────────────
    fn queue_create(&self, length: usize, item_size: usize) -> *mut c_void {
        // A simple queue implementation for testing using std primitives.
        // In a real system, this would be backed by an RTOS queue.
        let q = Box::new(TestQueue {
            data: Mutex::new(VecDeque::with_capacity(length)),
            not_empty: Condvar::new(),
            not_full: Condvar::new(),
            max_len: length,
            item_size,
        });
        Box::into_raw(q) as *mut c_void
    }

    fn queue_remove(&self, queue: *mut c_void) {
        if !queue.is_null() {
            // Safety: We created this pointer in queue_create.
            unsafe {
                let _ = Box::from_raw(queue as *mut TestQueue);
            }
        }
    }

    fn queue_enqueue(&self, queue: *mut c_void, item: *const c_void, timeout: u32) -> bool {
        use std::time::{Duration, Instant};

        if queue.is_null() || item.is_null() {
            return false;
        }

        // Safety: We created this pointer in queue_create
        unsafe {
            let q = &*(queue as *const TestQueue);
            let item_slice = core::slice::from_raw_parts(item as *const u8, q.item_size);

            let mut data = q.data.lock().unwrap();

            // Wait for space if queue is full
            if timeout == 0xFFFF_FFFF {
                // Infinite wait
                while data.len() >= q.max_len {
                    data = q.not_full.wait(data).unwrap();
                }
            } else if timeout > 0 {
                let deadline = Instant::now() + Duration::from_millis(timeout as u64);
                while data.len() >= q.max_len {
                    let now = Instant::now();
                    if now >= deadline {
                        return false;
                    }
                    let timeout_remaining = deadline - now;
                    let (new_data, timeout_result) =
                        q.not_full.wait_timeout(data, timeout_remaining).unwrap();
                    data = new_data;
                    if timeout_result.timed_out() {
                        return false;
                    }
                }
            } else {
                // No wait
                if data.len() >= q.max_len {
                    return false;
                }
            }

            data.push_back(item_slice.to_vec());
            drop(data);
            q.not_empty.notify_one();
            true
        }
    }

    fn queue_dequeue(&self, queue: *mut c_void, item: *mut c_void, timeout: u32) -> bool {
        use std::time::{Duration, Instant};

        if queue.is_null() || item.is_null() {
            return false;
        }

        // Safety: We created this pointer in queue_create
        unsafe {
            let q = &*(queue as *const TestQueue);
            let mut data = q.data.lock().unwrap();

            // Wait for data if queue is empty
            if timeout == 0xFFFF_FFFF {
                // Infinite wait
                while data.is_empty() {
                    data = q.not_empty.wait(data).unwrap();
                }
            } else if timeout > 0 {
                let deadline = Instant::now() + Duration::from_millis(timeout as u64);
                while data.is_empty() {
                    let now = Instant::now();
                    if now >= deadline {
                        return false;
                    }
                    let timeout_remaining = deadline - now;
                    let (new_data, timeout_result) =
                        q.not_empty.wait_timeout(data, timeout_remaining).unwrap();
                    data = new_data;
                    if timeout_result.timed_out() {
                        return false;
                    }
                }
            } else {
                // No wait
                if data.is_empty() {
                    return false;
                }
            }

            if let Some(queued_item) = data.pop_front() {
                let item_slice = core::slice::from_raw_parts_mut(item as *mut u8, q.item_size);
                let copy_len = queued_item.len().min(q.item_size);
                item_slice[..copy_len].copy_from_slice(&queued_item[..copy_len]);
                drop(data);
                q.not_full.notify_one();
                true
            } else {
                false
            }
        }
    }

    fn queue_size(&self, queue: *mut c_void) -> usize {
        if queue.is_null() {
            return 0;
        }

        // Safety: We created this pointer in queue_create
        unsafe {
            let q = &*(queue as *const TestQueue);
            q.data.lock().unwrap().len()
        }
    }

    // Hooks and clock primitives use the trait defaults, which are fine for
    // tests: no memfree reporting, no reboot/shutdown side-effects, and a
    // timestamp implementation is not exercised by the CSP test suite.
    fn thread_create(
        &self,
        f: unsafe extern "C" fn(*mut c_void),
        _name: *const c_char,
        _stack: u32,
        _arg: *mut c_void,
        _prio: u32,
        handle: *mut *mut c_void,
    ) -> i32 {
        // pthread_create expects extern "C" fn (safe), but CSP gives us unsafe extern "C" fn
        // We need to create a wrapper since we can't cast directly
        use std::collections::HashMap;
        use std::sync::Mutex;

        static THREAD_FN_MAP: Mutex<Option<HashMap<usize, unsafe extern "C" fn(*mut c_void)>>> =
            Mutex::new(None);

        extern "C" fn thread_wrapper(arg: *mut c_void) -> *mut c_void {
            let fn_ptr = arg as usize;
            let map = THREAD_FN_MAP.lock().unwrap();
            if let Some(ref m) = *map {
                if let Some(&f) = m.get(&fn_ptr) {
                    unsafe { f(core::ptr::null_mut()) };
                }
            }
            core::ptr::null_mut()
        }

        unsafe {
            // Store the function pointer in the map
            let mut map_lock = THREAD_FN_MAP.lock().unwrap();
            if map_lock.is_none() {
                *map_lock = Some(HashMap::new());
            }
            let fn_id = f as usize;
            map_lock.as_mut().unwrap().insert(fn_id, f);
            drop(map_lock);

            let mut thread: libc::pthread_t = core::mem::zeroed();
            let ret = libc::pthread_create(
                &mut thread,
                core::ptr::null(),
                thread_wrapper,
                fn_id as *mut c_void,
            );
            if ret == 0 {
                if !handle.is_null() {
                    *handle = thread as *mut c_void;
                }
                0
            } else {
                ret
            }
        }
    }
    fn sleep_ms(&self, ms: u32) {
        // Safety: nanosleep is safe to call with valid timespec
        unsafe {
            let ts = libc::timespec {
                tv_sec: (ms / 1000) as libc::time_t,
                tv_nsec: ((ms % 1000) * 1_000_000) as libc::c_long,
            };
            libc::nanosleep(&ts, core::ptr::null_mut());
        }
    }
    fn get_ms_isr(&self) -> u32 {
        self.get_ms()
    }
}

pub static ARCH: TestArch = TestArch;
