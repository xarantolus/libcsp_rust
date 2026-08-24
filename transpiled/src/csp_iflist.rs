extern "C" {
    pub type csp_conn_s;
    fn csp_print_func(fmt: *const ::core::ffi::c_char, ...);
    fn csp_id_get_host_bits() -> ::core::ffi::c_uint;
    fn csp_id_is_broadcast(
        addr: uint16_t,
        iface: *mut csp_iface_t,
    ) -> ::core::ffi::c_int;
    fn strncmp(
        __s1: *const ::core::ffi::c_char,
        __s2: *const ::core::ffi::c_char,
        __n: size_t,
    ) -> ::core::ffi::c_int;
    static mut csp_if_lo: csp_iface_t;
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
#[repr(C)]
pub struct csp_alias_s {
    pub addr: uint16_t,
    pub iface: *mut csp_iface_t,
    pub next: *mut csp_alias_s,
}
pub type csp_alias_t = csp_alias_s;
pub const NULL: *mut ::core::ffi::c_void = ::core::ptr::null_mut::<
    ::core::ffi::c_void,
>();
pub const CSP_IFLIST_NAME_MAX: ::core::ffi::c_int = 10 as ::core::ffi::c_int;
static mut interfaces: *mut csp_iface_t = ::core::ptr::null::<csp_iface_t>()
    as *mut csp_iface_t;
static mut aliass: *mut csp_alias_t = ::core::ptr::null::<csp_alias_t>()
    as *mut csp_alias_t;
#[no_mangle]
pub unsafe extern "C" fn csp_iflist_is_within_subnet(
    mut addr: uint16_t,
    mut ifc: *mut csp_iface_t,
) -> ::core::ffi::c_int {
    if ifc.is_null() {
        return 0 as ::core::ffi::c_int;
    }
    let mut netmask: uint16_t = ((((1 as ::core::ffi::c_int)
        << (*ifc).netmask as ::core::ffi::c_int) - 1 as ::core::ffi::c_int)
        << csp_id_get_host_bits().wrapping_sub((*ifc).netmask as ::core::ffi::c_uint))
        as uint16_t;
    let mut network_a: uint16_t = ((*ifc).addr as ::core::ffi::c_int
        & netmask as ::core::ffi::c_int) as uint16_t;
    let mut network_b: uint16_t = (addr as ::core::ffi::c_int
        & netmask as ::core::ffi::c_int) as uint16_t;
    if network_a as ::core::ffi::c_int == network_b as ::core::ffi::c_int {
        return 1 as ::core::ffi::c_int
    } else {
        return 0 as ::core::ffi::c_int
    };
}
#[no_mangle]
pub unsafe extern "C" fn csp_iflist_get_by_subnet(
    mut addr: uint16_t,
    mut ifc: *mut csp_iface_t,
) -> *mut csp_iface_t {
    if ifc.is_null() {
        ifc = interfaces;
    } else {
        ifc = (*ifc).next as *mut csp_iface_t;
    }
    while !ifc.is_null() {
        if (*ifc).netmask as ::core::ffi::c_int == 0 as ::core::ffi::c_int {
            ifc = (*ifc).next as *mut csp_iface_t;
        } else {
            if csp_iflist_is_within_subnet(addr, ifc) != 0 {
                return ifc;
            }
            ifc = (*ifc).next as *mut csp_iface_t;
        }
    }
    return ::core::ptr::null_mut::<csp_iface_t>();
}
#[no_mangle]
pub unsafe extern "C" fn csp_iflist_get_by_isdfl(
    mut ifc: *mut csp_iface_t,
) -> *mut csp_iface_t {
    if ifc.is_null() {
        ifc = interfaces;
    } else {
        ifc = (*ifc).next as *mut csp_iface_t;
    }
    while !ifc.is_null() {
        if (*ifc).is_default as ::core::ffi::c_int == 1 as ::core::ffi::c_int {
            return ifc;
        }
        ifc = (*ifc).next as *mut csp_iface_t;
    }
    return ::core::ptr::null_mut::<csp_iface_t>();
}
#[no_mangle]
pub unsafe extern "C" fn csp_iflist_iterate(
    mut ifc: *mut csp_iface_t,
) -> *mut csp_iface_t {
    if ifc.is_null() {
        ifc = interfaces;
    } else {
        ifc = (*ifc).next as *mut csp_iface_t;
    }
    return ifc;
}
#[no_mangle]
pub unsafe extern "C" fn csp_alias_add(
    mut addr: *mut csp_alias_t,
) -> ::core::ffi::c_int {
    if addr.is_null() || (*addr).iface.is_null() {
        return -(1 as ::core::ffi::c_int);
    }
    if (*(*addr).iface).add_alias.is_some() {
        let mut result: ::core::ffi::c_int = (*(*addr).iface)
            .add_alias
            .expect(
                "non-null function pointer",
            )((*(*addr).iface).driver_data, (*addr).addr);
        if result < 0 as ::core::ffi::c_int {
            return result;
        }
    }
    (*addr).next = aliass as *mut csp_alias_s;
    aliass = addr;
    return 0 as ::core::ffi::c_int;
}
unsafe extern "C" fn csp_alias_iterate(mut addr: *mut csp_alias_t) -> *mut csp_alias_t {
    if addr.is_null() {
        addr = aliass;
    } else {
        addr = (*addr).next as *mut csp_alias_t;
    }
    return addr;
}
#[no_mangle]
pub unsafe extern "C" fn csp_addr_is_alias(mut addr: uint16_t) -> ::core::ffi::c_int {
    let mut alias: *mut csp_alias_t = ::core::ptr::null_mut::<csp_alias_t>();
    loop {
        alias = csp_alias_iterate(alias);
        if alias.is_null() {
            break;
        }
        if addr as ::core::ffi::c_int == (*alias).addr as ::core::ffi::c_int {
            return 1 as ::core::ffi::c_int;
        }
    }
    return 0 as ::core::ffi::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn csp_iflist_check_dfl() {
    let mut iface: *mut csp_iface_t = csp_iflist_get_by_isdfl(
        ::core::ptr::null_mut::<csp_iface_t>(),
    );
    if !iface.is_null() {
        return;
    }
    loop {
        iface = csp_iflist_iterate(iface);
        if iface.is_null() {
            break;
        }
        if iface == &raw mut csp_if_lo {
            continue;
        }
        (*iface).is_default = 1 as uint8_t;
    };
}
#[no_mangle]
pub unsafe extern "C" fn csp_iflist_get_by_addr(mut addr: uint16_t) -> *mut csp_iface_t {
    let mut ifc: *mut csp_iface_t = interfaces;
    while !ifc.is_null() {
        if (*ifc).addr as ::core::ffi::c_int == addr as ::core::ffi::c_int {
            return ifc;
        }
        ifc = (*ifc).next as *mut csp_iface_t;
    }
    return ::core::ptr::null_mut::<csp_iface_t>();
}
#[no_mangle]
pub unsafe extern "C" fn csp_iflist_get_by_broadcast(
    mut addr: uint16_t,
) -> *mut csp_iface_t {
    let mut ifc: *mut csp_iface_t = interfaces;
    while !ifc.is_null() {
        if csp_id_is_broadcast(addr, ifc) != 0 {
            return ifc;
        }
        ifc = (*ifc).next as *mut csp_iface_t;
    }
    return ::core::ptr::null_mut::<csp_iface_t>();
}
#[no_mangle]
pub unsafe extern "C" fn csp_iflist_get_by_name(
    mut name: *const ::core::ffi::c_char,
) -> *mut csp_iface_t {
    let mut ifc: *mut csp_iface_t = interfaces;
    while !ifc.is_null() {
        if strncmp((*ifc).name, name, CSP_IFLIST_NAME_MAX as size_t)
            == 0 as ::core::ffi::c_int
        {
            return ifc;
        }
        ifc = (*ifc).next as *mut csp_iface_t;
    }
    return ::core::ptr::null_mut::<csp_iface_t>();
}
#[no_mangle]
pub unsafe extern "C" fn csp_iflist_get_by_index(
    mut idx: ::core::ffi::c_int,
) -> *mut csp_iface_t {
    let mut ifc: *mut csp_iface_t = interfaces;
    while !ifc.is_null()
        && {
            let fresh0 = idx;
            idx = idx - 1;
            fresh0 != 0
        }
    {
        ifc = (*ifc).next as *mut csp_iface_t;
    }
    return ifc;
}
#[no_mangle]
pub unsafe extern "C" fn csp_iflist_add(mut ifc: *mut csp_iface_t) {
    if ifc.is_null() || (*ifc).name.is_null() {
        return;
    }
    (*ifc).next = ::core::ptr::null_mut::<csp_iface_s>();
    if interfaces.is_null() {
        interfaces = ifc;
    } else {
        let mut last: *mut csp_iface_t = ::core::ptr::null_mut::<csp_iface_t>();
        let mut i: *mut csp_iface_t = interfaces;
        while !i.is_null() {
            if i == ifc
                || strncmp((*ifc).name, (*i).name, CSP_IFLIST_NAME_MAX as size_t)
                    == 0 as ::core::ffi::c_int
            {
                return;
            }
            last = i;
            i = (*i).next as *mut csp_iface_t;
        }
        (*last).next = ifc as *mut csp_iface_s;
    };
}
#[no_mangle]
pub unsafe extern "C" fn csp_iflist_remove(mut ifc: *mut csp_iface_t) {
    if ifc.is_null() {
        return;
    }
    if ifc == interfaces {
        interfaces = (*ifc).next as *mut csp_iface_t;
        (*ifc).next = ::core::ptr::null_mut::<csp_iface_s>();
    } else {
        let mut cur: *mut csp_iface_t = interfaces;
        while !cur.is_null() {
            if (*cur).next == ifc {
                (*cur).next = (*ifc).next;
                (*ifc).next = ::core::ptr::null_mut::<csp_iface_s>();
                break;
            } else {
                cur = (*cur).next as *mut csp_iface_t;
            }
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn csp_iflist_get() -> *mut csp_iface_t {
    return interfaces;
}
#[no_mangle]
pub unsafe extern "C" fn csp_bytesize(
    mut bytes: ::core::ffi::c_ulong,
    mut postfix: *mut ::core::ffi::c_char,
) -> ::core::ffi::c_ulong {
    let mut size: ::core::ffi::c_ulong = 0;
    if bytes
        >= (1024 as ::core::ffi::c_int * 1024 as ::core::ffi::c_int)
            as ::core::ffi::c_ulong
    {
        size = bytes
            .wrapping_div(
                (1024 as ::core::ffi::c_int * 1024 as ::core::ffi::c_int)
                    as ::core::ffi::c_ulong,
            );
        *postfix = 'M' as i32 as ::core::ffi::c_char;
    } else if bytes >= 1024 as ::core::ffi::c_ulong {
        size = bytes.wrapping_div(1024 as ::core::ffi::c_ulong);
        *postfix = 'K' as i32 as ::core::ffi::c_char;
    } else {
        size = bytes;
        *postfix = 'B' as i32 as ::core::ffi::c_char;
    }
    return size;
}
#[no_mangle]
pub unsafe extern "C" fn csp_iflist_print() {
    let mut i: *mut csp_iface_t = interfaces;
    let mut tx: ::core::ffi::c_ulong = 0;
    let mut rx: ::core::ffi::c_ulong = 0;
    let mut tx_postfix: ::core::ffi::c_char = 0;
    let mut rx_postfix: ::core::ffi::c_char = 0;
    while !i.is_null() {
        tx = csp_bytesize((*i).txbytes as ::core::ffi::c_ulong, &raw mut tx_postfix);
        rx = csp_bytesize((*i).rxbytes as ::core::ffi::c_ulong, &raw mut rx_postfix);
        csp_print_func(
            b"%-10s addr: %u netmask: %u dfl: %u\r\n           tx: %05u rx: %05u txe: %05u rxe: %05u\r\n           drop: %05u autherr: %05u frame: %05u\r\n           txb: %u (%u%c) rxb: %u (%u%c) \r\n\r\n\0"
                as *const u8 as *const ::core::ffi::c_char,
            (*i).name,
            (*i).addr as ::core::ffi::c_int,
            (*i).netmask as ::core::ffi::c_int,
            (*i).is_default as ::core::ffi::c_int,
            (*i).tx,
            (*i).rx,
            (*i).tx_error,
            (*i).rx_error,
            (*i).drop,
            (*i).autherr,
            (*i).frame,
            (*i).txbytes,
            tx,
            tx_postfix as ::core::ffi::c_int,
            (*i).rxbytes,
            rx,
            rx_postfix as ::core::ffi::c_int,
        );
        i = (*i).next as *mut csp_iface_t;
    }
}
