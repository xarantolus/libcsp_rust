extern "C" {
    pub type csp_conn_s;
    static mut csp_conf: csp_conf_t;
    fn strncpy(
        __dest: *mut ::core::ffi::c_char,
        __src: *const ::core::ffi::c_char,
        __n: size_t,
    ) -> *mut ::core::ffi::c_char;
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
pub struct csp_conf_s {
    pub version: uint8_t,
    pub hostname: *const ::core::ffi::c_char,
    pub model: *const ::core::ffi::c_char,
    pub revision: *const ::core::ffi::c_char,
    pub conn_dfl_so: uint32_t,
    pub dedup: uint8_t,
}
pub type csp_conf_t = csp_conf_s;
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct csp_cmp_ident_msg {
    pub type_0: uint8_t,
    pub code: uint8_t,
    pub hostname: [::core::ffi::c_char; 20],
    pub model: [::core::ffi::c_char; 30],
    pub revision: [::core::ffi::c_char; 20],
    pub date: [::core::ffi::c_char; 12],
    pub time: [::core::ffi::c_char; 9],
}
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ERR_INVAL: ::core::ffi::c_int = -(2 as ::core::ffi::c_int);
pub const CSP_HOSTNAME_LEN: ::core::ffi::c_int = 20 as ::core::ffi::c_int;
pub const CSP_MODEL_LEN: ::core::ffi::c_int = 30 as ::core::ffi::c_int;
pub const CSP_CMP_IDENT_REV_LEN: ::core::ffi::c_int = 20 as ::core::ffi::c_int;
pub const CSP_CMP_IDENT_DATE_LEN: ::core::ffi::c_int = 12 as ::core::ffi::c_int;
pub const CSP_CMP_IDENT_TIME_LEN: ::core::ffi::c_int = 9 as ::core::ffi::c_int;
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
pub unsafe extern "C" fn csp_cmp_ident_handler(
    mut packet: *mut csp_packet_t,
) -> ::core::ffi::c_int {
    let mut cmp: *mut csp_cmp_ident_msg = &raw mut (*packet).c2rust_unnamed.data
        as *mut uint8_t as *mut csp_cmp_ident_msg;
    if csp_cmp_check_len(packet, ::core::mem::size_of::<csp_cmp_ident_msg>() as size_t)
        != CSP_ERR_NONE
    {
        return CSP_ERR_INVAL;
    }
    strncpy(
        &raw mut (*cmp).revision as *mut ::core::ffi::c_char,
        csp_conf.revision,
        CSP_CMP_IDENT_REV_LEN as size_t,
    );
    (*cmp).revision[(CSP_CMP_IDENT_REV_LEN - 1 as ::core::ffi::c_int) as usize] = '\0'
        as i32 as ::core::ffi::c_char;
    strncpy(
        &raw mut (*cmp).date as *mut ::core::ffi::c_char,
        b"Aug 24 2026\0" as *const u8 as *const ::core::ffi::c_char,
        CSP_CMP_IDENT_DATE_LEN as size_t,
    );
    (*cmp).date[(CSP_CMP_IDENT_DATE_LEN - 1 as ::core::ffi::c_int) as usize] = '\0'
        as i32 as ::core::ffi::c_char;
    strncpy(
        &raw mut (*cmp).time as *mut ::core::ffi::c_char,
        b"23:52:47\0" as *const u8 as *const ::core::ffi::c_char,
        CSP_CMP_IDENT_TIME_LEN as size_t,
    );
    (*cmp).time[(CSP_CMP_IDENT_TIME_LEN - 1 as ::core::ffi::c_int) as usize] = '\0'
        as i32 as ::core::ffi::c_char;
    strncpy(
        &raw mut (*cmp).hostname as *mut ::core::ffi::c_char,
        csp_conf.hostname,
        CSP_HOSTNAME_LEN as size_t,
    );
    (*cmp).hostname[(CSP_HOSTNAME_LEN - 1 as ::core::ffi::c_int) as usize] = '\0' as i32
        as ::core::ffi::c_char;
    strncpy(
        &raw mut (*cmp).model as *mut ::core::ffi::c_char,
        csp_conf.model,
        CSP_MODEL_LEN as size_t,
    );
    (*cmp).model[(CSP_MODEL_LEN - 1 as ::core::ffi::c_int) as usize] = '\0' as i32
        as ::core::ffi::c_char;
    (*packet).length = ::core::mem::size_of::<csp_cmp_ident_msg>() as uint16_t;
    return CSP_ERR_NONE;
}
