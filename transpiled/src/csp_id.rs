extern "C" {
    pub type csp_conn_s;
    fn memcpy(
        __dest: *mut ::core::ffi::c_void,
        __src: *const ::core::ffi::c_void,
        __n: size_t,
    ) -> *mut ::core::ffi::c_void;
    static mut csp_conf: csp_conf_t;
}
pub type __uint8_t = u8;
pub type __uint16_t = u16;
pub type __uint32_t = u32;
pub type __uint64_t = u64;
pub type size_t = usize;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
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
#[repr(C)]
pub struct csp_conf_s {
    pub version: uint8_t,
    pub hostname: *const ::core::ffi::c_char,
    pub model: *const ::core::ffi::c_char,
    pub revision: *const ::core::ffi::c_char,
    pub conn_dfl_so: uint32_t,
    pub dedup: uint8_t,
}
pub type csp_conf_t = csp_conf_s;
#[inline]
unsafe extern "C" fn __bswap_32(mut __bsx: __uint32_t) -> __uint32_t {
    return (__bsx & 0xff000000 as __uint32_t) >> 24 as ::core::ffi::c_int
        | (__bsx & 0xff0000 as __uint32_t) >> 8 as ::core::ffi::c_int
        | (__bsx & 0xff00 as __uint32_t) << 8 as ::core::ffi::c_int
        | (__bsx & 0xff as __uint32_t) << 24 as ::core::ffi::c_int;
}
#[inline]
unsafe extern "C" fn __bswap_64(mut __bsx: __uint64_t) -> __uint64_t {
    return ((__bsx as ::core::ffi::c_ulonglong
        & 0xff00000000000000 as ::core::ffi::c_ulonglong) >> 56 as ::core::ffi::c_int
        | (__bsx as ::core::ffi::c_ulonglong
            & 0xff000000000000 as ::core::ffi::c_ulonglong) >> 40 as ::core::ffi::c_int
        | (__bsx as ::core::ffi::c_ulonglong
            & 0xff0000000000 as ::core::ffi::c_ulonglong) >> 24 as ::core::ffi::c_int
        | (__bsx as ::core::ffi::c_ulonglong & 0xff00000000 as ::core::ffi::c_ulonglong)
            >> 8 as ::core::ffi::c_int
        | (__bsx as ::core::ffi::c_ulonglong & 0xff000000 as ::core::ffi::c_ulonglong)
            << 8 as ::core::ffi::c_int
        | (__bsx as ::core::ffi::c_ulonglong & 0xff0000 as ::core::ffi::c_ulonglong)
            << 24 as ::core::ffi::c_int
        | (__bsx as ::core::ffi::c_ulonglong & 0xff00 as ::core::ffi::c_ulonglong)
            << 40 as ::core::ffi::c_int
        | (__bsx as ::core::ffi::c_ulonglong & 0xff as ::core::ffi::c_ulonglong)
            << 56 as ::core::ffi::c_int) as __uint64_t;
}
#[inline]
unsafe extern "C" fn __uint32_identity(mut __x: __uint32_t) -> __uint32_t {
    return __x;
}
pub const true_0: ::core::ffi::c_int = 1 as ::core::ffi::c_int;
pub const false_0: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ID1_HOST_SIZE: ::core::ffi::c_int = 5 as ::core::ffi::c_int;
pub const CSP_ID1_PORT_SIZE: ::core::ffi::c_int = 6 as ::core::ffi::c_int;
pub const CSP_ID1_PRIO_MASK: ::core::ffi::c_int = 0x3 as ::core::ffi::c_int;
pub const CSP_ID1_PRIO_OFFSET: ::core::ffi::c_int = 30 as ::core::ffi::c_int;
pub const CSP_ID1_SRC_MASK: ::core::ffi::c_int = 0x1f as ::core::ffi::c_int;
pub const CSP_ID1_SRC_OFFSET: ::core::ffi::c_int = 25 as ::core::ffi::c_int;
pub const CSP_ID1_DST_MASK: ::core::ffi::c_int = 0x1f as ::core::ffi::c_int;
pub const CSP_ID1_DST_OFFSET: ::core::ffi::c_int = 20 as ::core::ffi::c_int;
pub const CSP_ID1_DPORT_MASK: ::core::ffi::c_int = 0x3f as ::core::ffi::c_int;
pub const CSP_ID1_DPORT_OFFSET: ::core::ffi::c_int = 14 as ::core::ffi::c_int;
pub const CSP_ID1_SPORT_MASK: ::core::ffi::c_int = 0x3f as ::core::ffi::c_int;
pub const CSP_ID1_SPORT_OFFSET: ::core::ffi::c_int = 8 as ::core::ffi::c_int;
pub const CSP_ID1_FLAGS_MASK: ::core::ffi::c_int = 0xff as ::core::ffi::c_int;
pub const CSP_ID1_FLAGS_OFFSET: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ID1_HEADER_SIZE: ::core::ffi::c_int = 4 as ::core::ffi::c_int;
unsafe extern "C" fn csp_id1_prepend(
    mut packet: *mut csp_packet_t,
    mut cspv1_fixup: bool,
) {
    let mut id1_raw: uint32_t = ((*packet).id.pri as uint32_t) << CSP_ID1_PRIO_OFFSET
        | ((*packet).id.dst as uint32_t) << CSP_ID1_DST_OFFSET
        | ((*packet).id.src as uint32_t) << CSP_ID1_SRC_OFFSET
        | ((*packet).id.dport as uint32_t) << CSP_ID1_DPORT_OFFSET
        | ((*packet).id.sport as uint32_t) << CSP_ID1_SPORT_OFFSET
        | ((*packet).id.flags as uint32_t) << CSP_ID1_FLAGS_OFFSET;
    let mut id1: uint32_t = __bswap_32(id1_raw as __uint32_t) as uint32_t;
    if cspv1_fixup {
        id1 = __uint32_identity(id1_raw as __uint32_t) as uint32_t;
    }
    (*packet).frame_begin = (&raw mut (*packet).c2rust_unnamed.data as *mut uint8_t)
        .offset(-(CSP_ID1_HEADER_SIZE as isize));
    (*packet).frame_length = ((*packet).length as ::core::ffi::c_int
        + CSP_ID1_HEADER_SIZE) as uint16_t;
    memcpy(
        (*packet).frame_begin as *mut ::core::ffi::c_void,
        &raw mut id1 as *const ::core::ffi::c_void,
        CSP_ID1_HEADER_SIZE as size_t,
    );
}
unsafe extern "C" fn csp_id1_extract(
    mut data: *const uint8_t,
    mut cspv1_fixup: bool,
) -> csp_id_t {
    let mut id1_raw: uint32_t = 0 as uint32_t;
    memcpy(
        &raw mut id1_raw as *mut ::core::ffi::c_void,
        data as *const ::core::ffi::c_void,
        CSP_ID1_HEADER_SIZE as size_t,
    );
    let mut id1: uint32_t = __bswap_32(id1_raw as __uint32_t) as uint32_t;
    if cspv1_fixup {
        id1 = __uint32_identity(id1_raw as __uint32_t) as uint32_t;
    }
    let mut id: csp_id_t = csp_id_t {
        pri: 0,
        flags: 0,
        src: 0,
        dst: 0,
        dport: 0,
        sport: 0,
    };
    id.pri = (id1 >> CSP_ID1_PRIO_OFFSET & CSP_ID1_PRIO_MASK as uint32_t) as uint8_t;
    id.dst = (id1 >> CSP_ID1_DST_OFFSET & CSP_ID1_DST_MASK as uint32_t) as uint16_t;
    id.src = (id1 >> CSP_ID1_SRC_OFFSET & CSP_ID1_SRC_MASK as uint32_t) as uint16_t;
    id.dport = (id1 >> CSP_ID1_DPORT_OFFSET & CSP_ID1_DPORT_MASK as uint32_t) as uint8_t;
    id.sport = (id1 >> CSP_ID1_SPORT_OFFSET & CSP_ID1_SPORT_MASK as uint32_t) as uint8_t;
    id.flags = (id1 >> CSP_ID1_FLAGS_OFFSET & CSP_ID1_FLAGS_MASK as uint32_t) as uint8_t;
    return id;
}
unsafe extern "C" fn csp_id1_setup_rx(mut packet: *mut csp_packet_t) {
    (*packet).frame_begin = (&raw mut (*packet).c2rust_unnamed.data as *mut uint8_t)
        .offset(-(CSP_ID1_HEADER_SIZE as isize));
    (*packet).frame_length = 0 as uint16_t;
}
pub const CSP_ID2_HOST_SIZE: ::core::ffi::c_int = 14 as ::core::ffi::c_int;
pub const CSP_ID2_PORT_SIZE: ::core::ffi::c_int = 6 as ::core::ffi::c_int;
pub const CSP_ID2_PRIO_MASK: ::core::ffi::c_int = 0x3 as ::core::ffi::c_int;
pub const CSP_ID2_PRIO_OFFSET: ::core::ffi::c_int = 46 as ::core::ffi::c_int;
pub const CSP_ID2_DST_MASK: ::core::ffi::c_int = 0x3fff as ::core::ffi::c_int;
pub const CSP_ID2_DST_OFFSET: ::core::ffi::c_int = 32 as ::core::ffi::c_int;
pub const CSP_ID2_SRC_MASK: ::core::ffi::c_int = 0x3fff as ::core::ffi::c_int;
pub const CSP_ID2_SRC_OFFSET: ::core::ffi::c_int = 18 as ::core::ffi::c_int;
pub const CSP_ID2_DPORT_MASK: ::core::ffi::c_int = 0x3f as ::core::ffi::c_int;
pub const CSP_ID2_DPORT_OFFSET: ::core::ffi::c_int = 12 as ::core::ffi::c_int;
pub const CSP_ID2_SPORT_MASK: ::core::ffi::c_int = 0x3f as ::core::ffi::c_int;
pub const CSP_ID2_SPORT_OFFSET: ::core::ffi::c_int = 6 as ::core::ffi::c_int;
pub const CSP_ID2_FLAGS_MASK: ::core::ffi::c_int = 0x3f as ::core::ffi::c_int;
pub const CSP_ID2_FLAGS_OFFSET: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ID2_HEADER_SIZE: ::core::ffi::c_int = 6 as ::core::ffi::c_int;
unsafe extern "C" fn csp_id2_prepend(mut packet: *mut csp_packet_t) {
    let mut id2: uint64_t = ((*packet).id.pri as uint64_t) << CSP_ID2_PRIO_OFFSET
        | ((*packet).id.dst as uint64_t) << CSP_ID2_DST_OFFSET
        | ((*packet).id.src as uint64_t) << CSP_ID2_SRC_OFFSET
        | (((*packet).id.dport as ::core::ffi::c_int) << CSP_ID2_DPORT_OFFSET)
            as uint64_t
        | (((*packet).id.sport as ::core::ffi::c_int) << CSP_ID2_SPORT_OFFSET)
            as uint64_t
        | (((*packet).id.flags as ::core::ffi::c_int) << CSP_ID2_FLAGS_OFFSET)
            as uint64_t;
    id2 = __bswap_64((id2 as __uint64_t) << 16 as ::core::ffi::c_int) as uint64_t;
    (*packet).frame_begin = (&raw mut (*packet).c2rust_unnamed.data as *mut uint8_t)
        .offset(-(CSP_ID2_HEADER_SIZE as isize));
    (*packet).frame_length = ((*packet).length as ::core::ffi::c_int
        + CSP_ID2_HEADER_SIZE) as uint16_t;
    memcpy(
        (*packet).frame_begin as *mut ::core::ffi::c_void,
        &raw mut id2 as *const ::core::ffi::c_void,
        CSP_ID2_HEADER_SIZE as size_t,
    );
}
unsafe extern "C" fn csp_id2_extract(mut data: *const uint8_t) -> csp_id_t {
    let mut id2: uint64_t = 0 as uint64_t;
    memcpy(
        &raw mut id2 as *mut ::core::ffi::c_void,
        data as *const ::core::ffi::c_void,
        CSP_ID2_HEADER_SIZE as size_t,
    );
    id2 = (__bswap_64(id2 as __uint64_t) >> 16 as ::core::ffi::c_int) as uint64_t;
    let mut id: csp_id_t = csp_id_t {
        pri: 0,
        flags: 0,
        src: 0,
        dst: 0,
        dport: 0,
        sport: 0,
    };
    id.pri = (id2 >> CSP_ID2_PRIO_OFFSET & CSP_ID2_PRIO_MASK as uint64_t) as uint8_t;
    id.dst = (id2 >> CSP_ID2_DST_OFFSET & CSP_ID2_DST_MASK as uint64_t) as uint16_t;
    id.src = (id2 >> CSP_ID2_SRC_OFFSET & CSP_ID2_SRC_MASK as uint64_t) as uint16_t;
    id.dport = (id2 >> CSP_ID2_DPORT_OFFSET & CSP_ID2_DPORT_MASK as uint64_t) as uint8_t;
    id.sport = (id2 >> CSP_ID2_SPORT_OFFSET & CSP_ID2_SPORT_MASK as uint64_t) as uint8_t;
    id.flags = (id2 >> CSP_ID2_FLAGS_OFFSET & CSP_ID2_FLAGS_MASK as uint64_t) as uint8_t;
    return id;
}
unsafe extern "C" fn csp_id2_setup_rx(mut packet: *mut csp_packet_t) {
    (*packet).frame_begin = (&raw mut (*packet).c2rust_unnamed.data as *mut uint8_t)
        .offset(-(CSP_ID2_HEADER_SIZE as isize));
    (*packet).frame_length = 0 as uint16_t;
}
#[no_mangle]
pub unsafe extern "C" fn csp_id_prepend(mut packet: *mut csp_packet_t) {
    if csp_conf.version as ::core::ffi::c_int == 2 as ::core::ffi::c_int {
        csp_id2_prepend(packet);
    } else {
        csp_id1_prepend(packet, false_0 != 0);
    };
}
#[no_mangle]
pub unsafe extern "C" fn csp_id_extract(mut data: *const uint8_t) -> csp_id_t {
    if csp_conf.version as ::core::ffi::c_int == 2 as ::core::ffi::c_int {
        return csp_id2_extract(data)
    } else {
        return csp_id1_extract(data, false_0 != 0)
    };
}
#[no_mangle]
pub unsafe extern "C" fn csp_id_strip(
    mut packet: *mut csp_packet_t,
) -> ::core::ffi::c_int {
    if ((*packet).frame_length as ::core::ffi::c_int) < csp_id_get_header_size() {
        return -(1 as ::core::ffi::c_int);
    }
    (*packet).id = csp_id_extract((*packet).frame_begin);
    (*packet).length = ((*packet).frame_length as ::core::ffi::c_int
        - csp_id_get_header_size()) as uint16_t;
    return 0 as ::core::ffi::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn csp_id_prepend_fixup_cspv1(mut packet: *mut csp_packet_t) {
    if csp_conf.version as ::core::ffi::c_int == 2 as ::core::ffi::c_int {
        csp_id2_prepend(packet);
    } else {
        csp_id1_prepend(packet, true_0 != 0);
    };
}
#[no_mangle]
pub unsafe extern "C" fn csp_id_extract_fixup_cspv1(
    mut data: *const uint8_t,
) -> csp_id_t {
    if csp_conf.version as ::core::ffi::c_int == 2 as ::core::ffi::c_int {
        return csp_id2_extract(data)
    } else {
        return csp_id1_extract(data, true_0 != 0)
    };
}
#[no_mangle]
pub unsafe extern "C" fn csp_id_strip_fixup_cspv1(
    mut packet: *mut csp_packet_t,
) -> ::core::ffi::c_int {
    if ((*packet).frame_length as ::core::ffi::c_int) < csp_id_get_header_size() {
        return -(1 as ::core::ffi::c_int);
    }
    (*packet).id = csp_id_extract_fixup_cspv1((*packet).frame_begin);
    (*packet).length = ((*packet).frame_length as ::core::ffi::c_int
        - csp_id_get_header_size()) as uint16_t;
    return 0 as ::core::ffi::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn csp_id_setup_rx(
    mut packet: *mut csp_packet_t,
) -> ::core::ffi::c_int {
    if csp_conf.version as ::core::ffi::c_int == 2 as ::core::ffi::c_int {
        csp_id2_setup_rx(packet);
        return CSP_ID2_HEADER_SIZE;
    } else {
        csp_id1_setup_rx(packet);
        return CSP_ID1_HEADER_SIZE;
    };
}
#[no_mangle]
pub unsafe extern "C" fn csp_id_get_host_bits() -> ::core::ffi::c_uint {
    if csp_conf.version as ::core::ffi::c_int == 2 as ::core::ffi::c_int {
        return CSP_ID2_HOST_SIZE as ::core::ffi::c_uint
    } else {
        return CSP_ID1_HOST_SIZE as ::core::ffi::c_uint
    };
}
#[no_mangle]
pub unsafe extern "C" fn csp_id_get_max_nodeid() -> ::core::ffi::c_uint {
    if csp_conf.version as ::core::ffi::c_int == 2 as ::core::ffi::c_int {
        return (((1 as ::core::ffi::c_int) << CSP_ID2_HOST_SIZE)
            - 1 as ::core::ffi::c_int) as ::core::ffi::c_uint
    } else {
        return (((1 as ::core::ffi::c_int) << CSP_ID1_HOST_SIZE)
            - 1 as ::core::ffi::c_int) as ::core::ffi::c_uint
    };
}
#[no_mangle]
pub unsafe extern "C" fn csp_id_get_max_port() -> ::core::ffi::c_uint {
    if csp_conf.version as ::core::ffi::c_int == 2 as ::core::ffi::c_int {
        return (((1 as ::core::ffi::c_int) << CSP_ID2_PORT_SIZE)
            - 1 as ::core::ffi::c_int) as ::core::ffi::c_uint
    } else {
        return (((1 as ::core::ffi::c_int) << CSP_ID1_PORT_SIZE)
            - 1 as ::core::ffi::c_int) as ::core::ffi::c_uint
    };
}
#[no_mangle]
pub unsafe extern "C" fn csp_id_is_broadcast(
    mut addr: uint16_t,
    mut iface: *mut csp_iface_t,
) -> ::core::ffi::c_int {
    let mut hostmask: uint16_t = (((1 as ::core::ffi::c_int)
        << csp_id_get_host_bits().wrapping_sub((*iface).netmask as ::core::ffi::c_uint))
        - 1 as ::core::ffi::c_int) as uint16_t;
    let mut netmask: uint16_t = (((1 as ::core::ffi::c_int) << csp_id_get_host_bits())
        - 1 as ::core::ffi::c_int - hostmask as ::core::ffi::c_int) as uint16_t;
    if addr as ::core::ffi::c_int & hostmask as ::core::ffi::c_int
        == hostmask as ::core::ffi::c_int
        && addr as ::core::ffi::c_int & netmask as ::core::ffi::c_int
            == (*iface).addr as ::core::ffi::c_int & netmask as ::core::ffi::c_int
    {
        return 1 as ::core::ffi::c_int;
    }
    if addr as ::core::ffi::c_uint == csp_id_get_max_nodeid() {
        return 1 as ::core::ffi::c_int;
    }
    return 0 as ::core::ffi::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn csp_id_get_header_size() -> ::core::ffi::c_int {
    if csp_conf.version as ::core::ffi::c_int == 2 as ::core::ffi::c_int {
        return CSP_ID2_HEADER_SIZE
    } else {
        return CSP_ID1_HEADER_SIZE
    };
}
