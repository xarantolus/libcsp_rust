extern "C" {
    fn clock_gettime(__clock_id: clockid_t, __tp: *mut timespec) -> ::core::ffi::c_int;
    fn clock_settime(__clock_id: clockid_t, __tp: *const timespec) -> ::core::ffi::c_int;
}
pub type __uint32_t = u32;
pub type __time_t = ::core::ffi::c_long;
pub type __clockid_t = ::core::ffi::c_int;
pub type __syscall_slong_t = ::core::ffi::c_long;
pub type uint32_t = __uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct csp_timestamp_t {
    pub tv_sec: uint32_t,
    pub tv_nsec: uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timespec {
    pub tv_sec: __time_t,
    pub tv_nsec: __syscall_slong_t,
}
pub type clockid_t = __clockid_t;
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ERR_INVAL: ::core::ffi::c_int = -(2 as ::core::ffi::c_int);
pub const CLOCK_REALTIME: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
#[no_mangle]
pub unsafe extern "C" fn csp_clock_get_time(mut time: *mut csp_timestamp_t) {
    let mut ts: timespec = timespec { tv_sec: 0, tv_nsec: 0 };
    if clock_gettime(CLOCK_REALTIME, &raw mut ts) == 0 as ::core::ffi::c_int {
        (*time).tv_sec = ts.tv_sec as uint32_t;
        (*time).tv_nsec = ts.tv_nsec as uint32_t;
    } else {
        (*time).tv_sec = 0 as uint32_t;
        (*time).tv_nsec = 0 as uint32_t;
    };
}
#[no_mangle]
pub unsafe extern "C" fn csp_clock_set_time(
    mut time: *const csp_timestamp_t,
) -> ::core::ffi::c_int {
    let mut ts: timespec = timespec {
        tv_sec: (*time).tv_sec as __time_t,
        tv_nsec: (*time).tv_nsec as __syscall_slong_t,
    };
    if clock_settime(CLOCK_REALTIME, &raw mut ts) == 0 as ::core::ffi::c_int {
        return CSP_ERR_NONE;
    }
    return CSP_ERR_INVAL;
}
