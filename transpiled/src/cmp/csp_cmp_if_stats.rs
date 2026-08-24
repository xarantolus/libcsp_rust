extern "C" {
    pub type csp_conn_s;
    fn csp_iflist_get_by_name(name: *const ::core::ffi::c_char) -> *mut csp_iface_t;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct csp_iface_s {
    pub addr: uint16_t,
    pub netmask: uint16_t,
    pub name: *const ::core::ffi::c_char,
    pub interface_data: *mut ::core::ffi::c_void,
    pub driver_data: *mut ::core::ffi::c_void,
    pub nexthop: nexthop_t,
    pub add_alias: csp_alias_add_t,
    pub is_default: uint8_t,
    pub tx: uint32_t,
    pub rx: uint32_t,
    pub tx_error: uint32_t,
    pub rx_error: uint32_t,
    pub drop: uint32_t,
    pub autherr: uint32_t,
    pub frame: uint32_t,
    pub txbytes: uint32_t,
    pub rxbytes: uint32_t,
    pub irq: uint32_t,
    pub next: *mut csp_iface_s,
}
pub type csp_alias_add_t = Option<
    unsafe extern "C" fn(*mut ::core::ffi::c_void, uint16_t) -> ::core::ffi::c_int,
>;
pub type nexthop_t = Option<
    unsafe extern "C" fn(
        *mut csp_iface_t,
        uint16_t,
        *mut csp_packet_t,
        ::core::ffi::c_int,
    ) -> ::core::ffi::c_int,
>;
pub type csp_iface_t = csp_iface_s;
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct csp_cmp_if_stats_msg {
    pub type_0: uint8_t,
    pub code: uint8_t,
    pub interface: [::core::ffi::c_char; 11],
    pub tx: uint32_t,
    pub rx: uint32_t,
    pub tx_error: uint32_t,
    pub rx_error: uint32_t,
    pub drop: uint32_t,
    pub autherr: uint32_t,
    pub frame: uint32_t,
    pub txbytes: uint32_t,
    pub rxbytes: uint32_t,
    pub irq: uint32_t,
}
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ERR_INVAL: ::core::ffi::c_int = -(2 as ::core::ffi::c_int);
pub const NULL: *mut ::core::ffi::c_void = ::core::ptr::null_mut::<
    ::core::ffi::c_void,
>();
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
pub unsafe extern "C" fn csp_cmp_if_stats_handler(
    mut packet: *mut csp_packet_t,
) -> ::core::ffi::c_int {
    let mut cmp: *mut csp_cmp_if_stats_msg = &raw mut (*packet).c2rust_unnamed.data
        as *mut uint8_t as *mut csp_cmp_if_stats_msg;
    if csp_cmp_check_len(packet, 13 as size_t) != CSP_ERR_NONE {
        return CSP_ERR_INVAL;
    }
    let mut ifc: *mut csp_iface_t = csp_iflist_get_by_name(
        &raw mut (*cmp).interface as *mut ::core::ffi::c_char,
    );
    if ifc.is_null() {
        return CSP_ERR_INVAL;
    }
    (*cmp).tx = __bswap_32((*ifc).tx as __uint32_t) as uint32_t;
    (*cmp).rx = __bswap_32((*ifc).rx as __uint32_t) as uint32_t;
    (*cmp).tx_error = __bswap_32((*ifc).tx_error as __uint32_t) as uint32_t;
    (*cmp).rx_error = __bswap_32((*ifc).rx_error as __uint32_t) as uint32_t;
    (*cmp).drop = __bswap_32((*ifc).drop as __uint32_t) as uint32_t;
    (*cmp).autherr = __bswap_32((*ifc).autherr as __uint32_t) as uint32_t;
    (*cmp).frame = __bswap_32((*ifc).frame as __uint32_t) as uint32_t;
    (*cmp).txbytes = __bswap_32((*ifc).txbytes as __uint32_t) as uint32_t;
    (*cmp).rxbytes = __bswap_32((*ifc).rxbytes as __uint32_t) as uint32_t;
    (*cmp).irq = __bswap_32((*ifc).irq as __uint32_t) as uint32_t;
    (*packet).length = ::core::mem::size_of::<csp_cmp_if_stats_msg>() as uint16_t;
    return CSP_ERR_NONE;
}
