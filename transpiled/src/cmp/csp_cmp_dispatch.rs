extern "C" {
    pub type csp_conn_s;
    fn csp_cmp_ident_handler(packet: *mut csp_packet_t) -> ::core::ffi::c_int;
    fn csp_cmp_route_set_v1_handler(packet: *mut csp_packet_t) -> ::core::ffi::c_int;
    fn csp_cmp_route_set_v2_handler(packet: *mut csp_packet_t) -> ::core::ffi::c_int;
    fn csp_cmp_if_stats_handler(packet: *mut csp_packet_t) -> ::core::ffi::c_int;
    fn csp_cmp_peek_handler(packet: *mut csp_packet_t) -> ::core::ffi::c_int;
    fn csp_cmp_poke_handler(packet: *mut csp_packet_t) -> ::core::ffi::c_int;
    fn csp_cmp_peek_v2_handler(packet: *mut csp_packet_t) -> ::core::ffi::c_int;
    fn csp_cmp_poke_v2_handler(packet: *mut csp_packet_t) -> ::core::ffi::c_int;
    fn csp_cmp_clock_handler(packet: *mut csp_packet_t) -> ::core::ffi::c_int;
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
pub type C2RustUnnamed_0 = ::core::ffi::c_uint;
pub const CSP_CMP_REPLY: C2RustUnnamed_0 = 255;
pub const CSP_CMP_REQUEST: C2RustUnnamed_0 = 0;
pub type C2RustUnnamed_1 = ::core::ffi::c_uint;
pub const CSP_CMP_POKE_V2: C2RustUnnamed_1 = 9;
pub const CSP_CMP_PEEK_V2: C2RustUnnamed_1 = 8;
pub const CSP_CMP_ROUTE_SET_V2: C2RustUnnamed_1 = 7;
pub const CSP_CMP_CLOCK: C2RustUnnamed_1 = 6;
pub const CSP_CMP_POKE: C2RustUnnamed_1 = 5;
pub const CSP_CMP_PEEK: C2RustUnnamed_1 = 4;
pub const CSP_CMP_IF_STATS: C2RustUnnamed_1 = 3;
pub const CSP_CMP_ROUTE_SET_V1: C2RustUnnamed_1 = 2;
pub const CSP_CMP_IDENT: C2RustUnnamed_1 = 1;
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct csp_cmp_header {
    pub type_0: uint8_t,
    pub code: uint8_t,
}
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ERR_INVAL: ::core::ffi::c_int = -(2 as ::core::ffi::c_int);
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
#[no_mangle]
pub unsafe extern "C" fn csp_cmp_handler(
    mut packet: *mut csp_packet_t,
) -> ::core::ffi::c_int {
    if csp_cmp_check_len(packet, ::core::mem::size_of::<csp_cmp_header>() as size_t)
        != CSP_ERR_NONE
    {
        return CSP_ERR_INVAL;
    }
    let mut cmp: *mut csp_cmp_header = &raw mut (*packet).c2rust_unnamed.data
        as *mut uint8_t as *mut csp_cmp_header;
    if (*cmp).type_0 as ::core::ffi::c_int != CSP_CMP_REQUEST as ::core::ffi::c_int {
        return CSP_ERR_INVAL;
    }
    let mut ret: ::core::ffi::c_int = 0;
    match (*cmp).code as ::core::ffi::c_int {
        1 => {
            ret = csp_cmp_ident_handler(packet);
        }
        2 => {
            ret = csp_cmp_route_set_v1_handler(packet);
        }
        7 => {
            ret = csp_cmp_route_set_v2_handler(packet);
        }
        3 => {
            ret = csp_cmp_if_stats_handler(packet);
        }
        4 => {
            ret = csp_cmp_peek_handler(packet);
        }
        5 => {
            ret = csp_cmp_poke_handler(packet);
        }
        8 => {
            ret = csp_cmp_peek_v2_handler(packet);
        }
        9 => {
            ret = csp_cmp_poke_v2_handler(packet);
        }
        6 => {
            ret = csp_cmp_clock_handler(packet);
        }
        _ => return CSP_ERR_INVAL,
    }
    if ret == CSP_ERR_NONE {
        (*cmp).type_0 = CSP_CMP_REPLY as ::core::ffi::c_int as uint8_t;
    }
    return ret;
}
