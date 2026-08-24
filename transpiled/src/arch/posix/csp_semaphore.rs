extern "C" {
    fn sem_init(
        __sem: *mut sem_t,
        __pshared: ::core::ffi::c_int,
        __value: ::core::ffi::c_uint,
    ) -> ::core::ffi::c_int;
    fn sem_wait(__sem: *mut sem_t) -> ::core::ffi::c_int;
    fn sem_timedwait(
        __sem: *mut sem_t,
        __abstime: *const timespec,
    ) -> ::core::ffi::c_int;
    fn sem_post(__sem: *mut sem_t) -> ::core::ffi::c_int;
    fn sem_getvalue(
        __sem: *mut sem_t,
        __sval: *mut ::core::ffi::c_int,
    ) -> ::core::ffi::c_int;
    fn clock_gettime(__clock_id: clockid_t, __tp: *mut timespec) -> ::core::ffi::c_int;
}
pub type __uint32_t = u32;
pub type __time_t = ::core::ffi::c_long;
pub type __clockid_t = ::core::ffi::c_int;
pub type __syscall_slong_t = ::core::ffi::c_long;
pub type clockid_t = __clockid_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timespec {
    pub tv_sec: __time_t,
    pub tv_nsec: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union sem_t {
    pub __size: [::core::ffi::c_char; 32],
    pub __align: ::core::ffi::c_long,
}
pub type csp_bin_sem_t = sem_t;
pub type uint32_t = __uint32_t;
pub const CSP_SEMAPHORE_OK: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_SEMAPHORE_ERROR: ::core::ffi::c_int = -(1 as ::core::ffi::c_int);
pub const UINT32_MAX: ::core::ffi::c_uint = 4294967295 as ::core::ffi::c_uint;
pub const CSP_MAX_TIMEOUT: ::core::ffi::c_uint = 4294967295 as ::core::ffi::c_uint;
pub const CLOCK_REALTIME: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
#[no_mangle]
pub unsafe extern "C" fn csp_bin_sem_init(mut sem: *mut csp_bin_sem_t) {
    sem_init(sem as *mut sem_t, 0 as ::core::ffi::c_int, 1 as ::core::ffi::c_uint);
}
#[no_mangle]
pub unsafe extern "C" fn csp_bin_sem_wait(
    mut sem: *mut csp_bin_sem_t,
    mut timeout: ::core::ffi::c_uint,
) -> ::core::ffi::c_int {
    let mut ret: ::core::ffi::c_int = 0;
    if timeout == CSP_MAX_TIMEOUT {
        ret = sem_wait(sem as *mut sem_t);
    } else {
        let mut ts: timespec = timespec { tv_sec: 0, tv_nsec: 0 };
        if clock_gettime(CLOCK_REALTIME, &raw mut ts) != 0 {
            return CSP_SEMAPHORE_ERROR;
        }
        let mut sec: uint32_t = (timeout as uint32_t).wrapping_div(1000 as uint32_t);
        let mut nsec: uint32_t = (timeout as uint32_t)
            .wrapping_sub((1000 as uint32_t).wrapping_mul(sec))
            .wrapping_mul(1000000 as uint32_t);
        ts.tv_sec += sec as __time_t;
        if ts.tv_nsec + nsec as __syscall_slong_t >= 1000000000 as __syscall_slong_t {
            ts.tv_sec += 1;
        }
        ts.tv_nsec = (ts.tv_nsec + nsec as __syscall_slong_t)
            % 1000000000 as __syscall_slong_t;
        ret = sem_timedwait(sem as *mut sem_t, &raw mut ts);
    }
    if ret != 0 as ::core::ffi::c_int {
        return CSP_SEMAPHORE_ERROR;
    }
    return CSP_SEMAPHORE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn csp_bin_sem_post(
    mut sem: *mut csp_bin_sem_t,
) -> ::core::ffi::c_int {
    let mut value: ::core::ffi::c_int = 0;
    sem_getvalue(sem as *mut sem_t, &raw mut value);
    if value > 0 as ::core::ffi::c_int {
        return CSP_SEMAPHORE_OK;
    }
    if sem_post(sem as *mut sem_t) == 0 as ::core::ffi::c_int {
        return CSP_SEMAPHORE_OK;
    }
    return CSP_SEMAPHORE_ERROR;
}
