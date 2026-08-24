extern "C" {
    pub type csp_conn_s;
    fn csp_sha1_init(state: *mut csp_sha1_state_t);
    fn csp_sha1_process(
        state: *mut csp_sha1_state_t,
        data: *const ::core::ffi::c_void,
        length: uint32_t,
    );
    fn csp_sha1_done(state: *mut csp_sha1_state_t, sha1: *mut uint8_t);
    fn csp_sha1_memory(
        data: *const ::core::ffi::c_void,
        length: uint32_t,
        sha1: *mut uint8_t,
    );
    fn memcpy(
        __dest: *mut ::core::ffi::c_void,
        __src: *const ::core::ffi::c_void,
        __n: size_t,
    ) -> *mut ::core::ffi::c_void;
    fn memset(
        __s: *mut ::core::ffi::c_void,
        __c: ::core::ffi::c_int,
        __n: size_t,
    ) -> *mut ::core::ffi::c_void;
    fn memcmp(
        __s1: *const ::core::ffi::c_void,
        __s2: *const ::core::ffi::c_void,
        __n: size_t,
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
pub struct csp_sha1_state_t {
    pub length: uint64_t,
    pub state: [uint32_t; 5],
    pub curlen: uint32_t,
    pub buf: [uint8_t; 64],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct hmac_state {
    pub md: csp_sha1_state_t,
    pub key: [uint8_t; 64],
}
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ERR_NOMEM: ::core::ffi::c_int = -(1 as ::core::ffi::c_int);
pub const CSP_ERR_INVAL: ::core::ffi::c_int = -(2 as ::core::ffi::c_int);
pub const CSP_ERR_HMAC: ::core::ffi::c_int = -(100 as ::core::ffi::c_int);
pub const CSP_SHA1_BLOCKSIZE: ::core::ffi::c_int = 64 as ::core::ffi::c_int;
pub const CSP_SHA1_DIGESTSIZE: ::core::ffi::c_int = 20 as ::core::ffi::c_int;
pub const CSP_HMAC_LENGTH: ::core::ffi::c_int = 4 as ::core::ffi::c_int;
static mut csp_hmac_key: [uint8_t; 16] = [0; 16];
unsafe extern "C" fn csp_hmac_init(
    mut hmac: *mut hmac_state,
    mut key: *const uint8_t,
    mut keylen: uint32_t,
) -> ::core::ffi::c_int {
    let mut i: uint32_t = 0;
    let mut buf: [uint8_t; 64] = [0; 64];
    if hmac.is_null() || key.is_null() || keylen < 1 as uint32_t {
        return CSP_ERR_INVAL;
    }
    if keylen > CSP_SHA1_BLOCKSIZE as uint32_t {
        csp_sha1_memory(
            key as *const ::core::ffi::c_void,
            keylen,
            &raw mut (*hmac).key as *mut uint8_t,
        );
        if CSP_SHA1_DIGESTSIZE < CSP_SHA1_BLOCKSIZE {
            memset(
                (&raw mut (*hmac).key as *mut uint8_t)
                    .offset(CSP_SHA1_DIGESTSIZE as isize) as *mut ::core::ffi::c_void,
                0 as ::core::ffi::c_int,
                (CSP_SHA1_BLOCKSIZE - CSP_SHA1_DIGESTSIZE) as size_t,
            );
        }
    } else {
        memcpy(
            &raw mut (*hmac).key as *mut uint8_t as *mut ::core::ffi::c_void,
            key as *const ::core::ffi::c_void,
            keylen as size_t,
        );
        if keylen < CSP_SHA1_BLOCKSIZE as uint32_t {
            memset(
                (&raw mut (*hmac).key as *mut uint8_t).offset(keylen as isize)
                    as *mut ::core::ffi::c_void,
                0 as ::core::ffi::c_int,
                (CSP_SHA1_BLOCKSIZE as uint32_t).wrapping_sub(keylen) as size_t,
            );
        }
    }
    i = 0 as uint32_t;
    while i < CSP_SHA1_BLOCKSIZE as uint32_t {
        buf[i as usize] = ((*hmac).key[i as usize] as ::core::ffi::c_int
            ^ 0x36 as ::core::ffi::c_int) as uint8_t;
        i = i.wrapping_add(1);
    }
    csp_sha1_init(&raw mut (*hmac).md);
    csp_sha1_process(
        &raw mut (*hmac).md,
        &raw mut buf as *mut uint8_t as *const ::core::ffi::c_void,
        CSP_SHA1_BLOCKSIZE as uint32_t,
    );
    return CSP_ERR_NONE;
}
unsafe extern "C" fn csp_hmac_process(
    mut hmac: *mut hmac_state,
    mut in_0: *const uint8_t,
    mut inlen: uint32_t,
) -> ::core::ffi::c_int {
    if hmac.is_null() || in_0.is_null() {
        return CSP_ERR_INVAL;
    }
    csp_sha1_process(&raw mut (*hmac).md, in_0 as *const ::core::ffi::c_void, inlen);
    return CSP_ERR_NONE;
}
unsafe extern "C" fn csp_hmac_done(
    mut hmac: *mut hmac_state,
    mut out: *mut uint8_t,
) -> ::core::ffi::c_int {
    if hmac.is_null() || out.is_null() {
        return CSP_ERR_INVAL;
    }
    let mut isha: [uint8_t; 20] = [0; 20];
    csp_sha1_done(&raw mut (*hmac).md, &raw mut isha as *mut uint8_t);
    let mut buf: [uint8_t; 64] = [0; 64];
    let mut i: ::core::ffi::c_uint = 0 as ::core::ffi::c_uint;
    while (i as usize) < ::core::mem::size_of::<[uint8_t; 64]>() as usize {
        buf[i as usize] = ((*hmac).key[i as usize] as ::core::ffi::c_int
            ^ 0x5c as ::core::ffi::c_int) as uint8_t;
        i = i.wrapping_add(1);
    }
    csp_sha1_init(&raw mut (*hmac).md);
    csp_sha1_process(
        &raw mut (*hmac).md,
        &raw mut buf as *mut uint8_t as *const ::core::ffi::c_void,
        ::core::mem::size_of::<[uint8_t; 64]>() as uint32_t,
    );
    csp_sha1_process(
        &raw mut (*hmac).md,
        &raw mut isha as *mut uint8_t as *const ::core::ffi::c_void,
        ::core::mem::size_of::<[uint8_t; 20]>() as uint32_t,
    );
    csp_sha1_done(&raw mut (*hmac).md, &raw mut buf as *mut uint8_t);
    memcpy(
        out as *mut ::core::ffi::c_void,
        &raw mut buf as *mut uint8_t as *const ::core::ffi::c_void,
        CSP_SHA1_DIGESTSIZE as size_t,
    );
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_hmac_memory(
    mut key: *const ::core::ffi::c_void,
    mut keylen: uint32_t,
    mut data: *const ::core::ffi::c_void,
    mut datalen: uint32_t,
    mut hmac: *mut uint8_t,
) -> ::core::ffi::c_int {
    let mut state: hmac_state = hmac_state {
        md: csp_sha1_state_t {
            length: 0,
            state: [0; 5],
            curlen: 0,
            buf: [0; 64],
        },
        key: [0; 64],
    };
    if key.is_null() || data.is_null() || hmac.is_null() {
        return CSP_ERR_INVAL;
    }
    if csp_hmac_init(&raw mut state, key as *const uint8_t, keylen)
        != 0 as ::core::ffi::c_int
    {
        return CSP_ERR_INVAL;
    }
    if csp_hmac_process(&raw mut state, data as *const uint8_t, datalen)
        != 0 as ::core::ffi::c_int
    {
        return CSP_ERR_INVAL;
    }
    if csp_hmac_done(&raw mut state, hmac) != 0 as ::core::ffi::c_int {
        return CSP_ERR_INVAL;
    }
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_hmac_set_key(
    mut key: *const ::core::ffi::c_void,
    mut keylen: uint32_t,
) -> ::core::ffi::c_int {
    let mut hash: [uint8_t; 20] = [0; 20];
    csp_sha1_memory(key, keylen, &raw mut hash as *mut uint8_t);
    memcpy(
        &raw mut csp_hmac_key as *mut uint8_t as *mut ::core::ffi::c_void,
        &raw mut hash as *mut uint8_t as *const ::core::ffi::c_void,
        ::core::mem::size_of::<[uint8_t; 16]>() as size_t,
    );
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_hmac_append(
    mut packet: *mut csp_packet_t,
    mut include_header: bool,
) -> ::core::ffi::c_int {
    if ((*packet).length as ::core::ffi::c_uint)
        .wrapping_add(CSP_HMAC_LENGTH as ::core::ffi::c_uint) as usize
        > ::core::mem::size_of::<[uint8_t; 256]>() as usize
    {
        return CSP_ERR_NOMEM;
    }
    let mut hmac: [uint8_t; 20] = [0; 20];
    if include_header {
        csp_hmac_memory(
            &raw mut csp_hmac_key as *mut uint8_t as *const ::core::ffi::c_void,
            ::core::mem::size_of::<[uint8_t; 16]>() as uint32_t,
            (*packet).frame_begin as *const ::core::ffi::c_void,
            (*packet).frame_length as uint32_t,
            &raw mut hmac as *mut uint8_t,
        );
        memcpy(
            (*packet).frame_begin.offset((*packet).frame_length as isize) as *mut uint8_t
                as *mut ::core::ffi::c_void,
            &raw mut hmac as *mut uint8_t as *const ::core::ffi::c_void,
            CSP_HMAC_LENGTH as size_t,
        );
        (*packet).frame_length = ((*packet).frame_length as ::core::ffi::c_int
            + CSP_HMAC_LENGTH) as uint16_t;
        (*packet).length = ((*packet).length as ::core::ffi::c_int + CSP_HMAC_LENGTH)
            as uint16_t;
    } else {
        csp_hmac_memory(
            &raw mut csp_hmac_key as *mut uint8_t as *const ::core::ffi::c_void,
            ::core::mem::size_of::<[uint8_t; 16]>() as uint32_t,
            &raw mut (*packet).c2rust_unnamed.data as *mut uint8_t
                as *const ::core::ffi::c_void,
            (*packet).length as uint32_t,
            &raw mut hmac as *mut uint8_t,
        );
        memcpy(
            (&raw mut (*packet).c2rust_unnamed.data as *mut uint8_t)
                .offset((*packet).length as isize) as *mut uint8_t
                as *mut ::core::ffi::c_void,
            &raw mut hmac as *mut uint8_t as *const ::core::ffi::c_void,
            CSP_HMAC_LENGTH as size_t,
        );
        (*packet).length = ((*packet).length as ::core::ffi::c_int + CSP_HMAC_LENGTH)
            as uint16_t;
    }
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_hmac_verify(
    mut packet: *mut csp_packet_t,
    mut include_header: bool,
) -> ::core::ffi::c_int {
    if ((*packet).length as ::core::ffi::c_uint) < CSP_HMAC_LENGTH as ::core::ffi::c_uint
    {
        return CSP_ERR_HMAC;
    }
    let mut hmac: [uint8_t; 20] = [0; 20];
    if include_header {
        csp_hmac_memory(
            &raw mut csp_hmac_key as *mut uint8_t as *const ::core::ffi::c_void,
            ::core::mem::size_of::<[uint8_t; 16]>() as uint32_t,
            (*packet).frame_begin as *const ::core::ffi::c_void,
            ((*packet).frame_length as ::core::ffi::c_int - CSP_HMAC_LENGTH) as uint32_t,
            &raw mut hmac as *mut uint8_t,
        );
        if memcmp(
            ((*packet).frame_begin.offset((*packet).frame_length as isize)
                as *mut uint8_t)
                .offset(-(CSP_HMAC_LENGTH as isize)) as *const ::core::ffi::c_void,
            &raw mut hmac as *mut uint8_t as *const ::core::ffi::c_void,
            CSP_HMAC_LENGTH as size_t,
        ) != 0 as ::core::ffi::c_int
        {
            return CSP_ERR_HMAC;
        }
        (*packet).frame_length = ((*packet).frame_length as ::core::ffi::c_int
            - CSP_HMAC_LENGTH) as uint16_t;
    } else {
        csp_hmac_memory(
            &raw mut csp_hmac_key as *mut uint8_t as *const ::core::ffi::c_void,
            ::core::mem::size_of::<[uint8_t; 16]>() as uint32_t,
            &raw mut (*packet).c2rust_unnamed.data as *mut uint8_t
                as *const ::core::ffi::c_void,
            ((*packet).length as ::core::ffi::c_int - CSP_HMAC_LENGTH) as uint32_t,
            &raw mut hmac as *mut uint8_t,
        );
        if memcmp(
            ((&raw mut (*packet).c2rust_unnamed.data as *mut uint8_t)
                .offset((*packet).length as isize) as *mut uint8_t)
                .offset(-(CSP_HMAC_LENGTH as isize)) as *const ::core::ffi::c_void,
            &raw mut hmac as *mut uint8_t as *const ::core::ffi::c_void,
            CSP_HMAC_LENGTH as size_t,
        ) != 0 as ::core::ffi::c_int
        {
            return CSP_ERR_HMAC;
        }
        (*packet).length = ((*packet).length as ::core::ffi::c_int - CSP_HMAC_LENGTH)
            as uint16_t;
    }
    return CSP_ERR_NONE;
}
