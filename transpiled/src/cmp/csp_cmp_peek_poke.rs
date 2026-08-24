extern "C" {
    pub type csp_conn_s;
    fn csp_cmp_memcpy(
        to: csp_memptr_t,
        from: csp_const_memptr_t,
        size: size_t,
    ) -> ::core::ffi::c_int;
    fn csp_cmp_memread64(
        to: csp_const_memptr_t,
        from: csp_memptr64_t,
        size: size_t,
    ) -> ::core::ffi::c_int;
    fn csp_cmp_memwrite64(
        to: csp_memptr64_t,
        from: csp_memptr_t,
        size: size_t,
    ) -> ::core::ffi::c_int;
}
pub type __uint8_t = u8;
pub type __uint16_t = u16;
pub type __uint32_t = u32;
pub type __uint64_t = u64;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type uintptr_t = usize;
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
pub type csp_memptr_t = *mut ::core::ffi::c_void;
pub type csp_const_memptr_t = *const ::core::ffi::c_void;
pub type csp_memptr64_t = uint64_t;
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct csp_cmp_header {
    pub type_0: uint8_t,
    pub code: uint8_t,
}
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct csp_cmp_peek_msg {
    pub type_0: uint8_t,
    pub code: uint8_t,
    pub addr: uint32_t,
    pub len: uint8_t,
    pub data: [uint8_t; 0],
}
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct csp_cmp_poke_msg {
    pub type_0: uint8_t,
    pub code: uint8_t,
    pub addr: uint32_t,
    pub len: uint8_t,
    pub data: [uint8_t; 0],
}
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct csp_cmp_peek_v2_msg {
    pub type_0: uint8_t,
    pub code: uint8_t,
    pub vaddr: uint64_t,
    pub len: uint8_t,
    pub data: [uint8_t; 0],
}
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct csp_cmp_poke_v2_msg {
    pub type_0: uint8_t,
    pub code: uint8_t,
    pub vaddr: uint64_t,
    pub len: uint8_t,
    pub data: [uint8_t; 0],
}
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ERR_INVAL: ::core::ffi::c_int = -(2 as ::core::ffi::c_int);
pub const CSP_CMP_PEEK_MAX_LEN: ::core::ffi::c_int = 200 as ::core::ffi::c_int;
pub const CSP_CMP_POKE_MAX_LEN: ::core::ffi::c_int = 200 as ::core::ffi::c_int;
pub const CSP_CMP_PEEK_V2_MAX_LEN: ::core::ffi::c_int = 196 as ::core::ffi::c_int;
pub const CSP_CMP_POKE_V2_MAX_LEN: ::core::ffi::c_int = 196 as ::core::ffi::c_int;
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
#[no_mangle]
pub unsafe extern "C" fn csp_cmp_peek_handler(
    mut packet: *mut csp_packet_t,
) -> ::core::ffi::c_int {
    let mut cmp: *mut csp_cmp_peek_msg = &raw mut (*packet).c2rust_unnamed.data
        as *mut uint8_t as *mut csp_cmp_peek_msg;
    if csp_cmp_check_len(packet, ::core::mem::size_of::<csp_cmp_peek_msg>() as size_t)
        != CSP_ERR_NONE
    {
        return CSP_ERR_INVAL;
    }
    (*cmp).addr = __bswap_32((*cmp).addr as __uint32_t) as uint32_t;
    if (*cmp).len as ::core::ffi::c_int > CSP_CMP_PEEK_MAX_LEN {
        return CSP_ERR_INVAL;
    }
    let mut res: ::core::ffi::c_int = csp_cmp_memcpy(
        &raw mut (*cmp).data as *mut uint8_t as uintptr_t as csp_memptr_t,
        (*cmp).addr as uintptr_t as csp_memptr_t as csp_const_memptr_t,
        (*cmp).len as size_t,
    );
    if res != CSP_ERR_NONE {
        return res;
    }
    (*packet).length = (::core::mem::size_of::<csp_cmp_peek_msg>() as usize)
        .wrapping_add(
            ((::core::mem::size_of::<csp_cmp_peek_msg>() as usize)
                .wrapping_sub(::core::mem::size_of::<csp_cmp_header>() as usize)
                .wrapping_add(3 as usize) & !(3 as ::core::ffi::c_uint) as usize)
                .wrapping_sub(
                    (::core::mem::size_of::<csp_cmp_peek_msg>() as usize)
                        .wrapping_sub(::core::mem::size_of::<csp_cmp_header>() as usize),
                ),
        )
        .wrapping_add((*cmp).len as usize) as uint16_t;
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_cmp_poke_handler(
    mut packet: *mut csp_packet_t,
) -> ::core::ffi::c_int {
    let mut cmp: *mut csp_cmp_poke_msg = &raw mut (*packet).c2rust_unnamed.data
        as *mut uint8_t as *mut csp_cmp_poke_msg;
    if csp_cmp_check_len(packet, ::core::mem::size_of::<csp_cmp_poke_msg>() as size_t)
        != CSP_ERR_NONE
    {
        return CSP_ERR_INVAL;
    }
    (*cmp).addr = __bswap_32((*cmp).addr as __uint32_t) as uint32_t;
    if (*cmp).len as ::core::ffi::c_int > CSP_CMP_POKE_MAX_LEN {
        return CSP_ERR_INVAL;
    }
    if csp_cmp_check_len(
        packet,
        (::core::mem::size_of::<csp_cmp_poke_msg>() as size_t)
            .wrapping_add((*cmp).len as size_t),
    ) != CSP_ERR_NONE
    {
        return CSP_ERR_INVAL;
    }
    let mut res: ::core::ffi::c_int = csp_cmp_memcpy(
        (*cmp).addr as uintptr_t as csp_memptr_t,
        &raw mut (*cmp).data as *mut uint8_t as uintptr_t as csp_memptr_t
            as csp_const_memptr_t,
        (*cmp).len as size_t,
    );
    if res != CSP_ERR_NONE {
        return res;
    }
    (*packet).length = (::core::mem::size_of::<csp_cmp_poke_msg>() as usize)
        .wrapping_add(
            ((::core::mem::size_of::<csp_cmp_poke_msg>() as usize)
                .wrapping_sub(::core::mem::size_of::<csp_cmp_header>() as usize)
                .wrapping_add(3 as usize) & !(3 as ::core::ffi::c_uint) as usize)
                .wrapping_sub(
                    (::core::mem::size_of::<csp_cmp_poke_msg>() as usize)
                        .wrapping_sub(::core::mem::size_of::<csp_cmp_header>() as usize),
                ),
        )
        .wrapping_add((*cmp).len as usize) as uint16_t;
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_cmp_peek_v2_handler(
    mut packet: *mut csp_packet_t,
) -> ::core::ffi::c_int {
    let mut cmp: *mut csp_cmp_peek_v2_msg = &raw mut (*packet).c2rust_unnamed.data
        as *mut uint8_t as *mut csp_cmp_peek_v2_msg;
    if csp_cmp_check_len(packet, ::core::mem::size_of::<csp_cmp_peek_v2_msg>() as size_t)
        != CSP_ERR_NONE
    {
        return CSP_ERR_INVAL;
    }
    (*cmp).vaddr = __bswap_64((*cmp).vaddr as __uint64_t) as uint64_t;
    if (*cmp).len as ::core::ffi::c_int > CSP_CMP_PEEK_V2_MAX_LEN {
        return CSP_ERR_INVAL;
    }
    let mut res: ::core::ffi::c_int = csp_cmp_memread64(
        &raw mut (*cmp).data as *mut uint8_t as csp_const_memptr_t,
        (*cmp).vaddr as csp_memptr64_t,
        (*cmp).len as size_t,
    );
    if res != CSP_ERR_NONE {
        return res;
    }
    (*packet).length = (::core::mem::size_of::<csp_cmp_peek_v2_msg>() as usize)
        .wrapping_add(
            ((::core::mem::size_of::<csp_cmp_peek_v2_msg>() as usize)
                .wrapping_sub(::core::mem::size_of::<csp_cmp_header>() as usize)
                .wrapping_add(3 as usize) & !(3 as ::core::ffi::c_uint) as usize)
                .wrapping_sub(
                    (::core::mem::size_of::<csp_cmp_peek_v2_msg>() as usize)
                        .wrapping_sub(::core::mem::size_of::<csp_cmp_header>() as usize),
                ),
        )
        .wrapping_add((*cmp).len as usize) as uint16_t;
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_cmp_poke_v2_handler(
    mut packet: *mut csp_packet_t,
) -> ::core::ffi::c_int {
    let mut cmp: *mut csp_cmp_poke_v2_msg = &raw mut (*packet).c2rust_unnamed.data
        as *mut uint8_t as *mut csp_cmp_poke_v2_msg;
    if csp_cmp_check_len(packet, ::core::mem::size_of::<csp_cmp_poke_v2_msg>() as size_t)
        != CSP_ERR_NONE
    {
        return CSP_ERR_INVAL;
    }
    (*cmp).vaddr = __bswap_64((*cmp).vaddr as __uint64_t) as uint64_t;
    if (*cmp).len as ::core::ffi::c_int > CSP_CMP_POKE_V2_MAX_LEN {
        return CSP_ERR_INVAL;
    }
    if csp_cmp_check_len(
        packet,
        (::core::mem::size_of::<csp_cmp_poke_v2_msg>() as size_t)
            .wrapping_add((*cmp).len as size_t),
    ) != CSP_ERR_NONE
    {
        return CSP_ERR_INVAL;
    }
    let mut res: ::core::ffi::c_int = csp_cmp_memwrite64(
        (*cmp).vaddr as csp_memptr64_t,
        &raw mut (*cmp).data as *mut uint8_t as csp_memptr_t,
        (*cmp).len as size_t,
    );
    if res != CSP_ERR_NONE {
        return res;
    }
    (*packet).length = (::core::mem::size_of::<csp_cmp_poke_v2_msg>() as usize)
        .wrapping_add(
            ((::core::mem::size_of::<csp_cmp_poke_v2_msg>() as usize)
                .wrapping_sub(::core::mem::size_of::<csp_cmp_header>() as usize)
                .wrapping_add(3 as usize) & !(3 as ::core::ffi::c_uint) as usize)
                .wrapping_sub(
                    (::core::mem::size_of::<csp_cmp_poke_v2_msg>() as usize)
                        .wrapping_sub(::core::mem::size_of::<csp_cmp_header>() as usize),
                ),
        )
        .wrapping_add((*cmp).len as usize) as uint16_t;
    return CSP_ERR_NONE;
}
