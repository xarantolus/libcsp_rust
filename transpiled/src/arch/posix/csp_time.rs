extern "C" {
    fn clock_gettime(__clock_id: clockid_t, __tp: *mut timespec) -> ::core::ffi::c_int;
}
pub type __uint32_t = u32;
pub type __time_t = ::core::ffi::c_long;
pub type __clockid_t = ::core::ffi::c_int;
pub type __syscall_slong_t = ::core::ffi::c_long;
pub type uint32_t = __uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timespec {
    pub tv_sec: __time_t,
    pub tv_nsec: __syscall_slong_t,
}
pub type clockid_t = __clockid_t;
pub const CLOCK_MONOTONIC: ::core::ffi::c_int = 1 as ::core::ffi::c_int;
#[no_mangle]
pub unsafe extern "C" fn csp_get_ms() -> uint32_t {
    let mut ts: timespec = timespec { tv_sec: 0, tv_nsec: 0 };
    if clock_gettime(CLOCK_MONOTONIC, &raw mut ts) == 0 as ::core::ffi::c_int {
        return (ts.tv_sec as __syscall_slong_t * 1000 as __syscall_slong_t
            + ts.tv_nsec / 1000000 as __syscall_slong_t) as uint32_t;
    }
    return 0 as uint32_t;
}
#[no_mangle]
pub unsafe extern "C" fn csp_get_ms_isr() -> uint32_t {
    return csp_get_ms();
}
#[no_mangle]
pub unsafe extern "C" fn csp_get_s() -> uint32_t {
    let mut ts: timespec = timespec { tv_sec: 0, tv_nsec: 0 };
    if clock_gettime(CLOCK_MONOTONIC, &raw mut ts) == 0 as ::core::ffi::c_int {
        return ts.tv_sec as uint32_t;
    }
    return 0 as uint32_t;
}
#[no_mangle]
pub unsafe extern "C" fn csp_get_s_isr() -> uint32_t {
    return csp_get_s();
}
