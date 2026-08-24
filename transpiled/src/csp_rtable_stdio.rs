extern "C" {
    pub type csp_conn_s;
    fn snprintf(
        __s: *mut ::core::ffi::c_char,
        __maxlen: size_t,
        __format: *const ::core::ffi::c_char,
        ...
    ) -> ::core::ffi::c_int;
    fn sscanf(
        __s: *const ::core::ffi::c_char,
        __format: *const ::core::ffi::c_char,
        ...
    ) -> ::core::ffi::c_int;
    fn strncpy(
        __dest: *mut ::core::ffi::c_char,
        __src: *const ::core::ffi::c_char,
        __n: size_t,
    ) -> *mut ::core::ffi::c_char;
    fn strcmp(
        __s1: *const ::core::ffi::c_char,
        __s2: *const ::core::ffi::c_char,
    ) -> ::core::ffi::c_int;
    fn strtok_r(
        __s: *mut ::core::ffi::c_char,
        __delim: *const ::core::ffi::c_char,
        __save_ptr: *mut *mut ::core::ffi::c_char,
    ) -> *mut ::core::ffi::c_char;
    fn strlen(__s: *const ::core::ffi::c_char) -> size_t;
    fn strnlen(__string: *const ::core::ffi::c_char, __maxlen: size_t) -> size_t;
    static mut csp_dbg_errno: uint8_t;
    fn csp_iflist_get_by_name(name: *const ::core::ffi::c_char) -> *mut csp_iface_t;
    fn csp_rtable_set(
        dest_address: uint16_t,
        netmask: ::core::ffi::c_int,
        ifc: *mut csp_iface_t,
        via: uint16_t,
    ) -> ::core::ffi::c_int;
    fn csp_rtable_iterate(iter: csp_rtable_iterator_t, ctx: *mut ::core::ffi::c_void);
    fn csp_id_get_host_bits() -> ::core::ffi::c_uint;
    fn csp_id_get_max_nodeid() -> ::core::ffi::c_uint;
}
pub type size_t = usize;
pub type __uint8_t = u8;
pub type __uint16_t = u16;
pub type __uint32_t = u32;
pub type __uint64_t = u64;
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
pub struct csp_route_s {
    pub address: uint16_t,
    pub netmask: uint16_t,
    pub via: uint16_t,
    pub iface: *mut csp_iface_t,
}
pub type csp_route_t = csp_route_s;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct csp_rtable_save_ctx_t {
    pub buffer: *mut ::core::ffi::c_char,
    pub len: size_t,
    pub maxlen: size_t,
    pub error: ::core::ffi::c_int,
}
pub type csp_rtable_iterator_t = Option<
    unsafe extern "C" fn(*mut ::core::ffi::c_void, *mut csp_route_t) -> bool,
>;
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ERR_NOMEM: ::core::ffi::c_int = -(1 as ::core::ffi::c_int);
pub const CSP_ERR_INVAL: ::core::ffi::c_int = -(2 as ::core::ffi::c_int);
pub const CSP_DBG_ERR_INVALID_RTABLE_ENTRY: ::core::ffi::c_int = 6 as ::core::ffi::c_int;
pub const NULL: *mut ::core::ffi::c_void = ::core::ptr::null_mut::<
    ::core::ffi::c_void,
>();
pub const true_0: ::core::ffi::c_int = 1 as ::core::ffi::c_int;
pub const false_0: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_NO_VIA_ADDRESS: ::core::ffi::c_int = 0xffff as ::core::ffi::c_int;
pub const CSP_IF_LOOPBACK_NAME: [::core::ffi::c_char; 5] = unsafe {
    ::core::mem::transmute::<[u8; 5], [::core::ffi::c_char; 5]>(*b"LOOP\0")
};
unsafe extern "C" fn csp_rtable_parse(
    mut rtable: *const ::core::ffi::c_char,
    mut dry_run: ::core::ffi::c_int,
) -> ::core::ffi::c_int {
    let mut valid_entries: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
    let str_len: size_t = strnlen(rtable, 100 as size_t) as size_t;
    let vla = str_len.wrapping_add(1 as size_t) as usize;
    let mut rtable_copy: Vec<::core::ffi::c_char> = ::std::vec::from_elem(0, vla);
    strncpy(rtable_copy.as_mut_ptr(), rtable, str_len);
    *rtable_copy.as_mut_ptr().offset(str_len as isize) = 0 as ::core::ffi::c_char;
    let mut saveptr: *mut ::core::ffi::c_char = ::core::ptr::null_mut::<
        ::core::ffi::c_char,
    >();
    let mut str: *mut ::core::ffi::c_char = strtok_r(
        rtable_copy.as_mut_ptr(),
        b",\0" as *const u8 as *const ::core::ffi::c_char,
        &raw mut saveptr,
    );
    while !str.is_null() && strlen(str) > 1 as size_t {
        let mut address: ::core::ffi::c_uint = 0;
        let mut via: ::core::ffi::c_uint = 0;
        let mut netmask: ::core::ffi::c_int = 0;
        let mut name: [::core::ffi::c_char; 10] = [
            0 as ::core::ffi::c_int as ::core::ffi::c_char,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        if !(sscanf(
            str,
            b"%u/%d %9s %u\0" as *const u8 as *const ::core::ffi::c_char,
            &raw mut address,
            &raw mut netmask,
            &raw mut name as *mut ::core::ffi::c_char,
            &raw mut via,
        ) == 4 as ::core::ffi::c_int)
        {
            if sscanf(
                str,
                b"%u/%d %9s\0" as *const u8 as *const ::core::ffi::c_char,
                &raw mut address,
                &raw mut netmask,
                &raw mut name as *mut ::core::ffi::c_char,
            ) == 3 as ::core::ffi::c_int
            {
                via = CSP_NO_VIA_ADDRESS as ::core::ffi::c_uint;
            } else if sscanf(
                str,
                b"%u %9s %u\0" as *const u8 as *const ::core::ffi::c_char,
                &raw mut address,
                &raw mut name as *mut ::core::ffi::c_char,
                &raw mut via,
            ) == 3 as ::core::ffi::c_int
            {
                netmask = csp_id_get_host_bits() as ::core::ffi::c_int;
            } else if sscanf(
                str,
                b"%u %9s\0" as *const u8 as *const ::core::ffi::c_char,
                &raw mut address,
                &raw mut name as *mut ::core::ffi::c_char,
            ) == 2 as ::core::ffi::c_int
            {
                netmask = csp_id_get_host_bits() as ::core::ffi::c_int;
                via = CSP_NO_VIA_ADDRESS as ::core::ffi::c_uint;
            } else {
                name[0 as ::core::ffi::c_int as usize] = 0 as ::core::ffi::c_char;
            }
        }
        name[(::core::mem::size_of::<[::core::ffi::c_char; 10]>() as usize)
            .wrapping_sub(1 as usize) as usize] = 0 as ::core::ffi::c_char;
        let mut ifc: *mut csp_iface_t = csp_iflist_get_by_name(
            &raw mut name as *mut ::core::ffi::c_char,
        );
        if address > csp_id_get_max_nodeid()
            || netmask > csp_id_get_host_bits() as ::core::ffi::c_int || ifc.is_null()
        {
            csp_dbg_errno = CSP_DBG_ERR_INVALID_RTABLE_ENTRY as uint8_t;
            return CSP_ERR_INVAL;
        }
        if dry_run == 0 as ::core::ffi::c_int {
            let mut res: ::core::ffi::c_int = csp_rtable_set(
                address as uint16_t,
                netmask,
                ifc,
                via as uint16_t,
            );
            if res != CSP_ERR_NONE {
                csp_dbg_errno = CSP_DBG_ERR_INVALID_RTABLE_ENTRY as uint8_t;
                return res;
            }
        }
        valid_entries += 1;
        str = strtok_r(
            ::core::ptr::null_mut::<::core::ffi::c_char>(),
            b",\0" as *const u8 as *const ::core::ffi::c_char,
            &raw mut saveptr,
        );
    }
    return valid_entries;
}
#[no_mangle]
pub unsafe extern "C" fn csp_rtable_load(
    mut rtable: *const ::core::ffi::c_char,
) -> ::core::ffi::c_int {
    return csp_rtable_parse(rtable, 0 as ::core::ffi::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn csp_rtable_check(
    mut rtable: *const ::core::ffi::c_char,
) -> ::core::ffi::c_int {
    return csp_rtable_parse(rtable, 1 as ::core::ffi::c_int);
}
unsafe extern "C" fn csp_rtable_save_route(
    mut vctx: *mut ::core::ffi::c_void,
    mut route: *mut csp_route_t,
) -> bool {
    let mut ctx: *mut csp_rtable_save_ctx_t = vctx as *mut csp_rtable_save_ctx_t;
    if strcmp((*(*route).iface).name, CSP_IF_LOOPBACK_NAME.as_ptr())
        == 0 as ::core::ffi::c_int
    {
        return true_0 != 0;
    }
    let mut sep: *const ::core::ffi::c_char = if (*ctx).len == 0 as size_t {
        b"\0" as *const u8 as *const ::core::ffi::c_char
    } else {
        b",\0" as *const u8 as *const ::core::ffi::c_char
    };
    let mut mask_str: [::core::ffi::c_char; 10] = [0; 10];
    if (*route).netmask as ::core::ffi::c_uint != csp_id_get_host_bits() {
        snprintf(
            &raw mut mask_str as *mut ::core::ffi::c_char,
            ::core::mem::size_of::<[::core::ffi::c_char; 10]>() as size_t,
            b"/%u\0" as *const u8 as *const ::core::ffi::c_char,
            (*route).netmask as ::core::ffi::c_int,
        );
    } else {
        mask_str[0 as ::core::ffi::c_int as usize] = 0 as ::core::ffi::c_char;
    }
    let mut via_str: [::core::ffi::c_char; 10] = [0; 10];
    if (*route).via as ::core::ffi::c_int != CSP_NO_VIA_ADDRESS {
        snprintf(
            &raw mut via_str as *mut ::core::ffi::c_char,
            ::core::mem::size_of::<[::core::ffi::c_char; 10]>() as size_t,
            b" %u\0" as *const u8 as *const ::core::ffi::c_char,
            (*route).via as ::core::ffi::c_int,
        );
    } else {
        via_str[0 as ::core::ffi::c_int as usize] = 0 as ::core::ffi::c_char;
    }
    let mut remain_buf_size: size_t = (*ctx).maxlen.wrapping_sub((*ctx).len);
    let mut res: ::core::ffi::c_int = snprintf(
        (*ctx).buffer.offset((*ctx).len as isize),
        remain_buf_size,
        b"%s%u%s %s%s\0" as *const u8 as *const ::core::ffi::c_char,
        sep,
        (*route).address as ::core::ffi::c_int,
        &raw mut mask_str as *mut ::core::ffi::c_char,
        (*(*route).iface).name,
        &raw mut via_str as *mut ::core::ffi::c_char,
    );
    if res < 0 as ::core::ffi::c_int || res >= remain_buf_size as ::core::ffi::c_int {
        (*ctx).error = CSP_ERR_NOMEM;
        return false_0 != 0;
    }
    (*ctx).len = (*ctx).len.wrapping_add(res as size_t);
    return true_0 != 0;
}
#[no_mangle]
pub unsafe extern "C" fn csp_rtable_save(
    mut buffer: *mut ::core::ffi::c_char,
    mut maxlen: size_t,
) -> ::core::ffi::c_int {
    let mut ctx: csp_rtable_save_ctx_t = csp_rtable_save_ctx_t {
        buffer: buffer,
        len: 0 as size_t,
        maxlen: maxlen,
        error: CSP_ERR_NONE,
    };
    *buffer.offset(0 as ::core::ffi::c_int as isize) = 0 as ::core::ffi::c_char;
    csp_rtable_iterate(
        Some(
            csp_rtable_save_route
                as unsafe extern "C" fn(
                    *mut ::core::ffi::c_void,
                    *mut csp_route_t,
                ) -> bool,
        ),
        &raw mut ctx as *mut ::core::ffi::c_void,
    );
    return ctx.error;
}
