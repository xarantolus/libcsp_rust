extern "C" {
    fn clock_gettime(__clock_id: clockid_t, __tp: *mut timespec) -> ::core::ffi::c_int;
    fn pthread_mutex_init(
        __mutex: *mut pthread_mutex_t,
        __mutexattr: *const pthread_mutexattr_t,
    ) -> ::core::ffi::c_int;
    fn pthread_mutex_destroy(__mutex: *mut pthread_mutex_t) -> ::core::ffi::c_int;
    fn pthread_mutex_lock(__mutex: *mut pthread_mutex_t) -> ::core::ffi::c_int;
    fn pthread_mutex_unlock(__mutex: *mut pthread_mutex_t) -> ::core::ffi::c_int;
    fn pthread_cond_init(
        __cond: *mut pthread_cond_t,
        __cond_attr: *const pthread_condattr_t,
    ) -> ::core::ffi::c_int;
    fn pthread_cond_destroy(__cond: *mut pthread_cond_t) -> ::core::ffi::c_int;
    fn pthread_cond_broadcast(__cond: *mut pthread_cond_t) -> ::core::ffi::c_int;
    fn pthread_cond_wait(
        __cond: *mut pthread_cond_t,
        __mutex: *mut pthread_mutex_t,
    ) -> ::core::ffi::c_int;
    fn pthread_cond_timedwait(
        __cond: *mut pthread_cond_t,
        __mutex: *mut pthread_mutex_t,
        __abstime: *const timespec,
    ) -> ::core::ffi::c_int;
    fn pthread_condattr_init(__attr: *mut pthread_condattr_t) -> ::core::ffi::c_int;
    fn pthread_condattr_destroy(__attr: *mut pthread_condattr_t) -> ::core::ffi::c_int;
    fn pthread_condattr_setclock(
        __attr: *mut pthread_condattr_t,
        __clock_id: __clockid_t,
    ) -> ::core::ffi::c_int;
    fn memcpy(
        __dest: *mut ::core::ffi::c_void,
        __src: *const ::core::ffi::c_void,
        __n: size_t,
    ) -> *mut ::core::ffi::c_void;
    fn malloc(__size: size_t) -> *mut ::core::ffi::c_void;
    fn free(__ptr: *mut ::core::ffi::c_void);
    fn csp_print_func(fmt: *const ::core::ffi::c_char, ...);
}
pub type __uint32_t = u32;
pub type __time_t = ::core::ffi::c_long;
pub type __clockid_t = ::core::ffi::c_int;
pub type __syscall_slong_t = ::core::ffi::c_long;
pub type uint32_t = __uint32_t;
pub type size_t = usize;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timespec {
    pub tv_sec: __time_t,
    pub tv_nsec: __syscall_slong_t,
}
pub type clockid_t = __clockid_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub union __atomic_wide_counter {
    pub __value64: ::core::ffi::c_ulonglong,
    pub __value32: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed {
    pub __low: ::core::ffi::c_uint,
    pub __high: ::core::ffi::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __pthread_internal_list {
    pub __prev: *mut __pthread_internal_list,
    pub __next: *mut __pthread_internal_list,
}
pub type __pthread_list_t = __pthread_internal_list;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __pthread_mutex_s {
    pub __lock: ::core::ffi::c_int,
    pub __count: ::core::ffi::c_uint,
    pub __owner: ::core::ffi::c_int,
    pub __nusers: ::core::ffi::c_uint,
    pub __kind: ::core::ffi::c_int,
    pub __spins: ::core::ffi::c_short,
    pub __elision: ::core::ffi::c_short,
    pub __list: __pthread_list_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __pthread_cond_s {
    pub __wseq: __atomic_wide_counter,
    pub __g1_start: __atomic_wide_counter,
    pub __g_refs: [::core::ffi::c_uint; 2],
    pub __g_size: [::core::ffi::c_uint; 2],
    pub __g1_orig_size: ::core::ffi::c_uint,
    pub __wrefs: ::core::ffi::c_uint,
    pub __g_signals: [::core::ffi::c_uint; 2],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_mutexattr_t {
    pub __size: [::core::ffi::c_char; 4],
    pub __align: ::core::ffi::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_condattr_t {
    pub __size: [::core::ffi::c_char; 4],
    pub __align: ::core::ffi::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_mutex_t {
    pub __data: __pthread_mutex_s,
    pub __size: [::core::ffi::c_char; 40],
    pub __align: ::core::ffi::c_long,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_cond_t {
    pub __data: __pthread_cond_s,
    pub __size: [::core::ffi::c_char; 48],
    pub __align: ::core::ffi::c_longlong,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pthread_queue_s {
    pub buffer: *mut ::core::ffi::c_void,
    pub size: ::core::ffi::c_int,
    pub item_size: ::core::ffi::c_int,
    pub items: ::core::ffi::c_int,
    pub in_0: ::core::ffi::c_int,
    pub out: ::core::ffi::c_int,
    pub mutex: pthread_mutex_t,
    pub cond_full: pthread_cond_t,
    pub cond_empty: pthread_cond_t,
}
pub type pthread_queue_t = pthread_queue_s;
pub const UINT32_MAX: ::core::ffi::c_uint = 4294967295 as ::core::ffi::c_uint;
pub const CLOCK_MONOTONIC: ::core::ffi::c_int = 1 as ::core::ffi::c_int;
pub const PTHREAD_QUEUE_ERROR: ::core::ffi::c_int = CSP_QUEUE_ERROR;
pub const PTHREAD_QUEUE_EMPTY: ::core::ffi::c_int = CSP_QUEUE_ERROR;
pub const PTHREAD_QUEUE_FULL: ::core::ffi::c_int = CSP_QUEUE_ERROR;
pub const PTHREAD_QUEUE_OK: ::core::ffi::c_int = CSP_QUEUE_OK;
pub const EINTR: ::core::ffi::c_int = 4 as ::core::ffi::c_int;
pub const NULL: *mut ::core::ffi::c_void = ::core::ptr::null_mut::<
    ::core::ffi::c_void,
>();
pub const CSP_QUEUE_OK: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_QUEUE_ERROR: ::core::ffi::c_int = -(1 as ::core::ffi::c_int);
pub const CSP_MAX_TIMEOUT: ::core::ffi::c_uint = 4294967295 as ::core::ffi::c_uint;
pub const PTHREAD_QUEUE_CLOCK: ::core::ffi::c_int = CLOCK_MONOTONIC;
#[inline]
unsafe extern "C" fn get_deadline(
    mut ts: *mut timespec,
    mut timeout_ms: uint32_t,
) -> ::core::ffi::c_int {
    let mut ret: ::core::ffi::c_int = clock_gettime(PTHREAD_QUEUE_CLOCK, ts);
    if ret < 0 as ::core::ffi::c_int {
        return ret;
    }
    let mut sec: uint32_t = timeout_ms.wrapping_div(1000 as uint32_t);
    let mut nsec: uint32_t = timeout_ms
        .wrapping_sub((1000 as uint32_t).wrapping_mul(sec))
        .wrapping_mul(1000000 as uint32_t);
    (*ts).tv_sec += sec as __time_t;
    if (*ts).tv_nsec + nsec as __syscall_slong_t >= 1000000000 as __syscall_slong_t {
        (*ts).tv_sec += 1;
    }
    (*ts).tv_nsec = ((*ts).tv_nsec + nsec as __syscall_slong_t)
        % 1000000000 as __syscall_slong_t;
    return ret;
}
#[inline]
unsafe extern "C" fn init_cond_clock_monotonic(
    mut cond: *mut pthread_cond_t,
) -> ::core::ffi::c_int {
    let mut ret: ::core::ffi::c_int = 0;
    let mut attr: pthread_condattr_t = pthread_condattr_t {
        __size: [0; 4],
    };
    pthread_condattr_init(&raw mut attr);
    ret = pthread_condattr_setclock(&raw mut attr, CLOCK_MONOTONIC);
    if ret == 0 as ::core::ffi::c_int {
        ret = pthread_cond_init(cond, &raw mut attr);
    }
    pthread_condattr_destroy(&raw mut attr);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn pthread_queue_create(
    mut length: ::core::ffi::c_int,
    mut item_size: size_t,
) -> *mut pthread_queue_t {
    let mut ret: ::core::ffi::c_int = 0;
    let mut q: *mut pthread_queue_t = ::core::ptr::null_mut::<pthread_queue_t>();
    q = malloc(::core::mem::size_of::<pthread_queue_t>() as size_t)
        as *mut pthread_queue_t;
    if !q.is_null() {
        (*q).buffer = malloc((length as size_t).wrapping_mul(item_size));
        if !(*q).buffer.is_null() {
            (*q).size = length;
            (*q).item_size = item_size as ::core::ffi::c_int;
            (*q).items = 0 as ::core::ffi::c_int;
            (*q).in_0 = 0 as ::core::ffi::c_int;
            (*q).out = 0 as ::core::ffi::c_int;
            ret = pthread_mutex_init(
                &raw mut (*q).mutex,
                ::core::ptr::null::<pthread_mutexattr_t>(),
            );
            if !(ret != 0 as ::core::ffi::c_int) {
                ret = init_cond_clock_monotonic(&raw mut (*q).cond_full);
                if !(ret != 0 as ::core::ffi::c_int) {
                    ret = init_cond_clock_monotonic(&raw mut (*q).cond_empty);
                    if ret != 0 as ::core::ffi::c_int {
                        pthread_cond_destroy(&raw mut (*q).cond_full);
                    } else {
                        return q as *mut pthread_queue_t
                    }
                }
                pthread_mutex_destroy(&raw mut (*q).mutex);
            }
            free((*q).buffer);
            (*q).buffer = NULL;
        }
        free(q as *mut ::core::ffi::c_void);
        q = ::core::ptr::null_mut::<pthread_queue_t>();
    }
    return q as *mut pthread_queue_t;
}
#[no_mangle]
pub unsafe extern "C" fn pthread_queue_delete(mut q: *mut pthread_queue_t) {
    if q.is_null() {
        return;
    }
    free((*q).buffer);
    free(q as *mut ::core::ffi::c_void);
}
#[inline]
unsafe extern "C" fn wait_slot_available(
    mut queue: *mut pthread_queue_t,
    mut ts: *mut timespec,
) -> ::core::ffi::c_int {
    let mut ret: ::core::ffi::c_int = 0;
    while (*queue).items == (*queue).size {
        if !ts.is_null() {
            ret = pthread_cond_timedwait(
                &raw mut (*queue).cond_full,
                &raw mut (*queue).mutex,
                ts,
            );
        } else {
            ret = pthread_cond_wait(
                &raw mut (*queue).cond_full,
                &raw mut (*queue).mutex,
            );
        }
        if ret != 0 as ::core::ffi::c_int && ret != EINTR {
            return PTHREAD_QUEUE_FULL;
        }
    }
    return PTHREAD_QUEUE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn pthread_queue_enqueue(
    mut queue: *mut pthread_queue_t,
    mut value: *const ::core::ffi::c_void,
    mut timeout: uint32_t,
) -> ::core::ffi::c_int {
    let mut ret: ::core::ffi::c_int = 0;
    let mut ts: timespec = timespec { tv_sec: 0, tv_nsec: 0 };
    let mut pts: *mut timespec = ::core::ptr::null_mut::<timespec>();
    if timeout != CSP_MAX_TIMEOUT as uint32_t {
        if get_deadline(&raw mut ts, timeout) != 0 as ::core::ffi::c_int {
            return PTHREAD_QUEUE_ERROR;
        }
        pts = &raw mut ts;
    } else {
        pts = ::core::ptr::null_mut::<timespec>();
    }
    pthread_mutex_lock(&raw mut (*queue).mutex);
    ret = wait_slot_available(queue, pts);
    if ret == PTHREAD_QUEUE_OK {
        memcpy(
            ((*queue).buffer as *mut ::core::ffi::c_char)
                .offset(((*queue).in_0 * (*queue).item_size) as isize)
                as *mut ::core::ffi::c_void,
            value,
            (*queue).item_size as size_t,
        );
        (*queue).items += 1;
        (*queue).in_0 = ((*queue).in_0 + 1 as ::core::ffi::c_int) % (*queue).size;
    }
    pthread_mutex_unlock(&raw mut (*queue).mutex);
    if ret == PTHREAD_QUEUE_OK {
        pthread_cond_broadcast(&raw mut (*queue).cond_empty);
    }
    return ret;
}
#[inline]
unsafe extern "C" fn wait_item_available(
    mut queue: *mut pthread_queue_t,
    mut ts: *mut timespec,
) -> ::core::ffi::c_int {
    let mut ret: ::core::ffi::c_int = 0;
    while (*queue).items == 0 as ::core::ffi::c_int {
        if !ts.is_null() {
            ret = pthread_cond_timedwait(
                &raw mut (*queue).cond_empty,
                &raw mut (*queue).mutex,
                ts,
            );
        } else {
            ret = pthread_cond_wait(
                &raw mut (*queue).cond_empty,
                &raw mut (*queue).mutex,
            );
        }
        if ret != 0 as ::core::ffi::c_int && ret != EINTR {
            return PTHREAD_QUEUE_EMPTY;
        }
    }
    return PTHREAD_QUEUE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn pthread_queue_dequeue(
    mut queue: *mut pthread_queue_t,
    mut buf: *mut ::core::ffi::c_void,
    mut timeout: uint32_t,
) -> ::core::ffi::c_int {
    let mut ret: ::core::ffi::c_int = 0;
    let mut ts: timespec = timespec { tv_sec: 0, tv_nsec: 0 };
    let mut pts: *mut timespec = ::core::ptr::null_mut::<timespec>();
    if queue.is_null() {
        csp_print_func(
            b"csp not initialized\n\0" as *const u8 as *const ::core::ffi::c_char,
        );
        return PTHREAD_QUEUE_ERROR;
    }
    if timeout != CSP_MAX_TIMEOUT as uint32_t {
        if get_deadline(&raw mut ts, timeout) != 0 as ::core::ffi::c_int {
            return PTHREAD_QUEUE_ERROR;
        }
        pts = &raw mut ts;
    } else {
        pts = ::core::ptr::null_mut::<timespec>();
    }
    pthread_mutex_lock(&raw mut (*queue).mutex);
    ret = wait_item_available(queue, pts);
    if ret == PTHREAD_QUEUE_OK {
        memcpy(
            buf,
            ((*queue).buffer as *mut ::core::ffi::c_char)
                .offset(((*queue).out * (*queue).item_size) as isize)
                as *const ::core::ffi::c_void,
            (*queue).item_size as size_t,
        );
        (*queue).items -= 1;
        (*queue).out = ((*queue).out + 1 as ::core::ffi::c_int) % (*queue).size;
    }
    pthread_mutex_unlock(&raw mut (*queue).mutex);
    if ret == PTHREAD_QUEUE_OK {
        pthread_cond_broadcast(&raw mut (*queue).cond_full);
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn pthread_queue_items(
    mut queue: *mut pthread_queue_t,
) -> ::core::ffi::c_int {
    pthread_mutex_lock(&raw mut (*queue).mutex);
    let mut items: ::core::ffi::c_int = (*queue).items;
    pthread_mutex_unlock(&raw mut (*queue).mutex);
    return items;
}
#[no_mangle]
pub unsafe extern "C" fn pthread_queue_free(
    mut queue: *mut pthread_queue_t,
) -> ::core::ffi::c_int {
    pthread_mutex_lock(&raw mut (*queue).mutex);
    let mut free_0: ::core::ffi::c_int = (*queue).size - (*queue).items;
    pthread_mutex_unlock(&raw mut (*queue).mutex);
    return free_0;
}
#[no_mangle]
pub unsafe extern "C" fn pthread_queue_empty(mut queue: *mut pthread_queue_t) {
    pthread_mutex_lock(&raw mut (*queue).mutex);
    (*queue).items = 0 as ::core::ffi::c_int;
    (*queue).in_0 = 0 as ::core::ffi::c_int;
    (*queue).out = 0 as ::core::ffi::c_int;
    pthread_mutex_unlock(&raw mut (*queue).mutex);
}
