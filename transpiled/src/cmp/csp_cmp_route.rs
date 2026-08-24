extern "C" {
    pub type csp_conn_s;
    fn csp_iflist_get_by_name(name: *const ::core::ffi::c_char) -> *mut csp_iface_t;
    fn csp_rtable_set(
        dest_address: uint16_t,
        netmask: ::core::ffi::c_int,
        ifc: *mut csp_iface_t,
        via: uint16_t,
    ) -> ::core::ffi::c_int;
    fn csp_id_get_host_bits() -> ::core::ffi::c_uint;
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
pub struct csp_cmp_route_set_v1_msg {
    pub type_0: uint8_t,
    pub code: uint8_t,
    pub dest_node: uint8_t,
    pub next_hop_via: uint8_t,
    pub interface: [::core::ffi::c_char; 11],
}
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct csp_cmp_route_set_v2_msg {
    pub type_0: uint8_t,
    pub code: uint8_t,
    pub dest_node: uint16_t,
    pub next_hop_via: uint16_t,
    pub netmask: uint16_t,
    pub interface: [::core::ffi::c_char; 11],
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
unsafe extern "C" fn __bswap_16(mut __bsx: __uint16_t) -> __uint16_t {
    return (__bsx as ::core::ffi::c_int >> 8 as ::core::ffi::c_int
        & 0xff as ::core::ffi::c_int
        | (__bsx as ::core::ffi::c_int & 0xff as ::core::ffi::c_int)
            << 8 as ::core::ffi::c_int) as __uint16_t;
}
#[no_mangle]
pub unsafe extern "C" fn csp_cmp_route_set_v1_handler(
    mut packet: *mut csp_packet_t,
) -> ::core::ffi::c_int {
    let mut cmp: *mut csp_cmp_route_set_v1_msg = &raw mut (*packet).c2rust_unnamed.data
        as *mut uint8_t as *mut csp_cmp_route_set_v1_msg;
    if csp_cmp_check_len(
        packet,
        ::core::mem::size_of::<csp_cmp_route_set_v1_msg>() as size_t,
    ) != CSP_ERR_NONE
    {
        return CSP_ERR_INVAL;
    }
    let mut ifc: *mut csp_iface_t = csp_iflist_get_by_name(
        &raw mut (*cmp).interface as *mut ::core::ffi::c_char,
    );
    if ifc.is_null() {
        return CSP_ERR_INVAL;
    }
    if csp_rtable_set(
        (*cmp).dest_node as uint16_t,
        csp_id_get_host_bits() as ::core::ffi::c_int,
        ifc,
        (*cmp).next_hop_via as uint16_t,
    ) != CSP_ERR_NONE
    {
        return CSP_ERR_INVAL;
    }
    (*packet).length = ::core::mem::size_of::<csp_cmp_route_set_v1_msg>() as uint16_t;
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_cmp_route_set_v2_handler(
    mut packet: *mut csp_packet_t,
) -> ::core::ffi::c_int {
    let mut cmp: *mut csp_cmp_route_set_v2_msg = &raw mut (*packet).c2rust_unnamed.data
        as *mut uint8_t as *mut csp_cmp_route_set_v2_msg;
    if csp_cmp_check_len(
        packet,
        ::core::mem::size_of::<csp_cmp_route_set_v2_msg>() as size_t,
    ) != CSP_ERR_NONE
    {
        return CSP_ERR_INVAL;
    }
    let mut ifc: *mut csp_iface_t = csp_iflist_get_by_name(
        &raw mut (*cmp).interface as *mut ::core::ffi::c_char,
    );
    if ifc.is_null() {
        return CSP_ERR_INVAL;
    }
    if csp_rtable_set(
        __bswap_16((*cmp).dest_node as __uint16_t) as uint16_t,
        __bswap_16((*cmp).netmask as __uint16_t) as ::core::ffi::c_int,
        ifc,
        __bswap_16((*cmp).next_hop_via as __uint16_t) as uint16_t,
    ) != CSP_ERR_NONE
    {
        return CSP_ERR_INVAL;
    }
    (*packet).length = ::core::mem::size_of::<csp_cmp_route_set_v2_msg>() as uint16_t;
    return CSP_ERR_NONE;
}
