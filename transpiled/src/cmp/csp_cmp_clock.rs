extern "C" {
    pub type csp_conn_s;
    static mut csp_dbg_errno: uint8_t;
    fn csp_clock_get_time(time: *mut csp_timestamp_t);
    fn csp_clock_set_time(time: *const csp_timestamp_t) -> ::core::ffi::c_int;
}
pub type __uint8_t = u8;
pub type __uint16_t = u16;
pub type __uint32_t = u32;
pub type __uint64_t = u64;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type size_t = usize;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct csp_timestamp_t {
    pub tv_sec: uint32_t,
    pub tv_nsec: uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct csp_id_t {
    pub pri: uint8_t,
    pub flags: uint8_t,
    pub src: uint16_t,
    pub dst: uint16_t,
    pub dport: uint8_t,
    pub sport: uint8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct csp_packet_s {
    pub timestamp_tx: uint32_t,
    pub timestamp_rx: uint64_t,
    pub conn: *mut csp_conn_s,
    pub rx_count: uint16_t,
    pub remain: uint16_t,
    pub cfpid: uint32_t,
    pub last_used: uint32_t,
    pub frame_begin: *mut uint8_t,
    pub frame_length: uint16_t,
    pub length: uint16_t,
    pub id: csp_id_t,
    pub next: *mut csp_packet_s,
    pub header: [uint8_t; 8],
    pub c2rust_unnamed: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub data: [uint8_t; 256],
    pub data16: [uint16_t; 128],
    pub data32: [uint32_t; 64],
}
pub type csp_packet_t = csp_packet_s;
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct csp_cmp_clock_msg {
    pub type_0: uint8_t,
    pub code: uint8_t,
    pub clock: csp_timestamp_t,
}
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ERR_INVAL: ::core::ffi::c_int = -(2 as ::core::ffi::c_int);
pub const CSP_DBG_ERR_CLOCK_SET_FAIL: ::core::ffi::c_int = 12 as ::core::ffi::c_int;
#[inline]
unsafe extern "C" fn csp_cmp_check_len(
    mut packet: *const csp_packet_t,
    mut min_len: size_t,
) -> ::core::ffi::c_int {
    if ((*packet).length as size_t) < min_len {
        return CSP_ERR_INVAL;
    }
    return CSP_ERR_NONE;
}
#[inline]
unsafe extern "C" fn __bswap_32(mut __bsx: __uint32_t) -> __uint32_t {
    return (__bsx & 0xff000000 as __uint32_t) >> 24 as ::core::ffi::c_int
        | (__bsx & 0xff0000 as __uint32_t) >> 8 as ::core::ffi::c_int
        | (__bsx & 0xff00 as __uint32_t) << 8 as ::core::ffi::c_int
        | (__bsx & 0xff as __uint32_t) << 24 as ::core::ffi::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn csp_cmp_clock_handler(
    mut packet: *mut csp_packet_t,
) -> ::core::ffi::c_int {
    let mut cmp: *mut csp_cmp_clock_msg = &raw mut (*packet).c2rust_unnamed.data
        as *mut uint8_t as *mut csp_cmp_clock_msg;
    if csp_cmp_check_len(packet, ::core::mem::size_of::<csp_cmp_clock_msg>() as size_t)
        != CSP_ERR_NONE
    {
        return CSP_ERR_INVAL;
    }
    let mut clock: csp_timestamp_t = csp_timestamp_t {
        tv_sec: 0,
        tv_nsec: 0,
    };
    clock.tv_sec = __bswap_32((*cmp).clock.tv_sec as __uint32_t) as uint32_t;
    clock.tv_nsec = __bswap_32((*cmp).clock.tv_nsec as __uint32_t) as uint32_t;
    let mut res: ::core::ffi::c_int = CSP_ERR_NONE;
    if clock.tv_sec != 0 as uint32_t {
        res = csp_clock_set_time(&raw mut clock);
        if res != CSP_ERR_NONE {
            csp_dbg_errno = CSP_DBG_ERR_CLOCK_SET_FAIL as uint8_t;
        }
    }
    csp_clock_get_time(&raw mut clock);
    (*cmp).clock.tv_sec = __bswap_32(clock.tv_sec as __uint32_t) as uint32_t;
    (*cmp).clock.tv_nsec = __bswap_32(clock.tv_nsec as __uint32_t) as uint32_t;
    (*packet).length = ::core::mem::size_of::<csp_cmp_clock_msg>() as uint16_t;
    return res;
}
