extern "C" {
    pub type csp_conn_s;
    fn memset(
        __s: *mut ::core::ffi::c_void,
        __c: ::core::ffi::c_int,
        __n: size_t,
    ) -> *mut ::core::ffi::c_void;
    static mut csp_dbg_errno: uint8_t;
    fn csp_print_func(fmt: *const ::core::ffi::c_char, ...);
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
#[repr(C)]
pub struct csp_route_s {
    pub address: uint16_t,
    pub netmask: uint16_t,
    pub via: uint16_t,
    pub iface: *mut csp_iface_t,
}
pub type csp_route_t = csp_route_s;
pub type csp_rtable_iterator_t = Option<
    unsafe extern "C" fn(*mut ::core::ffi::c_void, *mut csp_route_t) -> bool,
>;
pub const NULL: *mut ::core::ffi::c_void = ::core::ptr::null_mut::<
    ::core::ffi::c_void,
>();
pub const true_0: ::core::ffi::c_int = 1 as ::core::ffi::c_int;
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ERR_INVAL: ::core::ffi::c_int = -(2 as ::core::ffi::c_int);
pub const CSP_RTABLE_SIZE: ::core::ffi::c_int = 10 as ::core::ffi::c_int;
pub const CSP_NO_VIA_ADDRESS: ::core::ffi::c_int = 0xffff as ::core::ffi::c_int;
pub const CSP_DBG_ERR_INVALID_RTABLE_ENTRY: ::core::ffi::c_int = 6 as ::core::ffi::c_int;
static mut rtable: [csp_route_t; 10] = [
    csp_route_s {
        address: 0 as uint16_t,
        netmask: 0,
        via: 0,
        iface: ::core::ptr::null::<csp_iface_t>() as *mut csp_iface_t,
    },
    csp_route_s {
        address: 0,
        netmask: 0,
        via: 0,
        iface: ::core::ptr::null::<csp_iface_t>() as *mut csp_iface_t,
    },
    csp_route_s {
        address: 0,
        netmask: 0,
        via: 0,
        iface: ::core::ptr::null::<csp_iface_t>() as *mut csp_iface_t,
    },
    csp_route_s {
        address: 0,
        netmask: 0,
        via: 0,
        iface: ::core::ptr::null::<csp_iface_t>() as *mut csp_iface_t,
    },
    csp_route_s {
        address: 0,
        netmask: 0,
        via: 0,
        iface: ::core::ptr::null::<csp_iface_t>() as *mut csp_iface_t,
    },
    csp_route_s {
        address: 0,
        netmask: 0,
        via: 0,
        iface: ::core::ptr::null::<csp_iface_t>() as *mut csp_iface_t,
    },
    csp_route_s {
        address: 0,
        netmask: 0,
        via: 0,
        iface: ::core::ptr::null::<csp_iface_t>() as *mut csp_iface_t,
    },
    csp_route_s {
        address: 0,
        netmask: 0,
        via: 0,
        iface: ::core::ptr::null::<csp_iface_t>() as *mut csp_iface_t,
    },
    csp_route_s {
        address: 0,
        netmask: 0,
        via: 0,
        iface: ::core::ptr::null::<csp_iface_t>() as *mut csp_iface_t,
    },
    csp_route_s {
        address: 0,
        netmask: 0,
        via: 0,
        iface: ::core::ptr::null::<csp_iface_t>() as *mut csp_iface_t,
    },
];
static mut rtable_inptr: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
unsafe extern "C" fn csp_rtable_find_exact(
    mut addr: uint16_t,
    mut netmask: uint16_t,
    mut ifc: *mut csp_iface_t,
) -> *mut csp_route_t {
    let mut i: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
    while i < rtable_inptr {
        if rtable[i as usize].address as ::core::ffi::c_int == addr as ::core::ffi::c_int
            && rtable[i as usize].netmask as ::core::ffi::c_int
                == netmask as ::core::ffi::c_int && rtable[i as usize].iface == ifc
        {
            return (&raw mut rtable as *mut csp_route_t).offset(i as isize)
                as *mut csp_route_t;
        }
        i += 1;
    }
    return ::core::ptr::null_mut::<csp_route_t>();
}
#[no_mangle]
pub unsafe extern "C" fn csp_rtable_search_backward(
    mut start_route: *mut csp_route_t,
) -> *mut csp_route_t {
    if start_route.is_null() || start_route <= &raw mut rtable as *mut csp_route_t {
        return ::core::ptr::null_mut::<csp_route_t>();
    }
    let mut route: *mut csp_route_t = start_route
        .offset(-(1 as ::core::ffi::c_int as isize));
    while route >= &raw mut rtable as *mut csp_route_t {
        if (*route).netmask as ::core::ffi::c_int
            == (*start_route).netmask as ::core::ffi::c_int
            && (*route).address as ::core::ffi::c_int
                == (*start_route).address as ::core::ffi::c_int
        {
            return route;
        }
        route = route.offset(-1);
    }
    return ::core::ptr::null_mut::<csp_route_t>();
}
#[no_mangle]
pub unsafe extern "C" fn csp_rtable_find_route(mut addr: uint16_t) -> *mut csp_route_t {
    let mut best_result: ::core::ffi::c_int = -(1 as ::core::ffi::c_int);
    let mut best_result_mask: uint16_t = 0 as uint16_t;
    let mut i: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
    while i < rtable_inptr {
        let mut hostbits: uint16_t = (((1 as ::core::ffi::c_int)
            << csp_id_get_host_bits()
                .wrapping_sub(rtable[i as usize].netmask as ::core::ffi::c_uint))
            - 1 as ::core::ffi::c_int) as uint16_t;
        let mut netbits: uint16_t = !(hostbits as ::core::ffi::c_int) as uint16_t;
        let mut net_a: uint16_t = (rtable[i as usize].address as ::core::ffi::c_int
            & netbits as ::core::ffi::c_int) as uint16_t;
        let mut net_b: uint16_t = (addr as ::core::ffi::c_int
            & netbits as ::core::ffi::c_int) as uint16_t;
        if net_a as ::core::ffi::c_int == net_b as ::core::ffi::c_int {
            if rtable[i as usize].netmask as ::core::ffi::c_int
                >= best_result_mask as ::core::ffi::c_int
            {
                best_result = i;
                best_result_mask = rtable[i as usize].netmask;
            }
        }
        i += 1;
    }
    if best_result > -(1 as ::core::ffi::c_int) {
        return (&raw mut rtable as *mut csp_route_t).offset(best_result as isize)
            as *mut csp_route_t;
    }
    return ::core::ptr::null_mut::<csp_route_t>();
}
unsafe extern "C" fn csp_rtable_set_internal(
    mut address: uint16_t,
    mut netmask: uint16_t,
    mut ifc: *mut csp_iface_t,
    mut via: uint16_t,
) -> ::core::ffi::c_int {
    let mut entry: *mut csp_route_t = csp_rtable_find_exact(address, netmask, ifc);
    if entry.is_null() {
        let fresh0 = rtable_inptr;
        rtable_inptr = rtable_inptr + 1;
        entry = (&raw mut rtable as *mut csp_route_t).offset(fresh0 as isize)
            as *mut csp_route_t;
        if rtable_inptr >= CSP_RTABLE_SIZE {
            rtable_inptr = CSP_RTABLE_SIZE - 1 as ::core::ffi::c_int;
        }
    }
    (*entry).address = address;
    (*entry).netmask = netmask;
    (*entry).iface = ifc;
    (*entry).via = via;
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_rtable_free() {
    memset(
        &raw mut rtable as *mut csp_route_t as *mut ::core::ffi::c_void,
        0 as ::core::ffi::c_int,
        ::core::mem::size_of::<[csp_route_t; 10]>() as size_t,
    );
    rtable_inptr = 0 as ::core::ffi::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn csp_rtable_clear() {
    csp_rtable_free();
}
#[no_mangle]
pub unsafe extern "C" fn csp_rtable_set(
    mut address: uint16_t,
    mut netmask: ::core::ffi::c_int,
    mut ifc: *mut csp_iface_t,
    mut via: uint16_t,
) -> ::core::ffi::c_int {
    if netmask < 0 as ::core::ffi::c_int
        || netmask > csp_id_get_host_bits() as ::core::ffi::c_int
    {
        netmask = csp_id_get_host_bits() as ::core::ffi::c_int;
    }
    if ifc.is_null() {
        csp_dbg_errno = CSP_DBG_ERR_INVALID_RTABLE_ENTRY as uint8_t;
        return CSP_ERR_INVAL;
    }
    return csp_rtable_set_internal(address, netmask as uint16_t, ifc, via);
}
#[no_mangle]
pub unsafe extern "C" fn csp_rtable_iterate(
    mut iter: csp_rtable_iterator_t,
    mut ctx: *mut ::core::ffi::c_void,
) {
    let mut i: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
    while i < rtable_inptr {
        iter
            .expect(
                "non-null function pointer",
            )(
            ctx,
            (&raw mut rtable as *mut csp_route_t).offset(i as isize) as *mut csp_route_t,
        );
        i += 1;
    }
}
unsafe extern "C" fn csp_rtable_print_route(
    mut ctx: *mut ::core::ffi::c_void,
    mut route: *mut csp_route_t,
) -> bool {
    if (*route).via as ::core::ffi::c_int == CSP_NO_VIA_ADDRESS {
        csp_print_func(
            b"%u/%u %s\r\n\0" as *const u8 as *const ::core::ffi::c_char,
            (*route).address as ::core::ffi::c_int,
            (*route).netmask as ::core::ffi::c_int,
            (*(*route).iface).name,
        );
    } else {
        csp_print_func(
            b"%u/%u %s %u\r\n\0" as *const u8 as *const ::core::ffi::c_char,
            (*route).address as ::core::ffi::c_int,
            (*route).netmask as ::core::ffi::c_int,
            (*(*route).iface).name,
            (*route).via as ::core::ffi::c_int,
        );
    }
    return true_0 != 0;
}
#[no_mangle]
pub unsafe extern "C" fn csp_rtable_print() {
    csp_rtable_iterate(
        Some(
            csp_rtable_print_route
                as unsafe extern "C" fn(
                    *mut ::core::ffi::c_void,
                    *mut csp_route_t,
                ) -> bool,
        ),
        NULL,
    );
}
