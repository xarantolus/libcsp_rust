extern "C" {
    pub type csp_conn_s;
    fn csp_buffer_free(buffer: *mut ::core::ffi::c_void);
    fn csp_buffer_remaining() -> ::core::ffi::c_int;
    fn csp_sendto_reply(
        request: *const csp_packet_t,
        reply: *mut csp_packet_t,
        opts: uint32_t,
    );
    fn memcpy(
        __dest: *mut ::core::ffi::c_void,
        __src: *const ::core::ffi::c_void,
        __n: size_t,
    ) -> *mut ::core::ffi::c_void;
    fn csp_reboot_hook();
    fn csp_shutdown_hook();
    fn csp_memfree_hook() -> uint32_t;
    fn csp_ps_hook(packet: *mut csp_packet_t) -> ::core::ffi::c_uint;
    fn csp_get_s() -> uint32_t;
    fn csp_cmp_handler(packet: *mut csp_packet_t) -> ::core::ffi::c_int;
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
pub type C2RustUnnamed = ::core::ffi::c_uint;
pub const CSP_UPTIME: C2RustUnnamed = 6;
pub const CSP_BUF_FREE: C2RustUnnamed = 5;
pub const CSP_REBOOT: C2RustUnnamed = 4;
pub const CSP_MEMFREE: C2RustUnnamed = 3;
pub const CSP_PS: C2RustUnnamed = 2;
pub const CSP_PING: C2RustUnnamed = 1;
pub const CSP_CMP: C2RustUnnamed = 0;
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
    pub c2rust_unnamed: C2RustUnnamed_0,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
    pub data: [uint8_t; 256],
    pub data16: [uint16_t; 128],
    pub data32: [uint32_t; 64],
}
pub type csp_packet_t = csp_packet_s;
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_SO_SAME: ::core::ffi::c_int = 0x8000 as ::core::ffi::c_int;
pub const CSP_O_SAME: ::core::ffi::c_int = CSP_SO_SAME;
pub const CSP_REBOOT_MAGIC: ::core::ffi::c_uint = 0x80078007 as ::core::ffi::c_uint;
pub const CSP_REBOOT_SHUTDOWN_MAGIC: ::core::ffi::c_uint = 0xd1e5529a
    as ::core::ffi::c_uint;
#[inline]
unsafe extern "C" fn __bswap_32(mut __bsx: __uint32_t) -> __uint32_t {
    return (__bsx & 0xff000000 as __uint32_t) >> 24 as ::core::ffi::c_int
        | (__bsx & 0xff0000 as __uint32_t) >> 8 as ::core::ffi::c_int
        | (__bsx & 0xff00 as __uint32_t) << 8 as ::core::ffi::c_int
        | (__bsx & 0xff as __uint32_t) << 24 as ::core::ffi::c_int;
}
unsafe extern "C" fn set_u32_reply(mut packet: *mut csp_packet_t, mut value: uint32_t) {
    let value_be: uint32_t = __bswap_32(value as __uint32_t) as uint32_t;
    memcpy(
        &raw mut (*packet).c2rust_unnamed.data as *mut uint8_t
            as *mut ::core::ffi::c_void,
        &raw const value_be as *const ::core::ffi::c_void,
        ::core::mem::size_of::<uint32_t>() as size_t,
    );
    (*packet).length = ::core::mem::size_of::<uint32_t>() as uint16_t;
}
#[no_mangle]
pub unsafe extern "C" fn csp_service_handler(mut packet: *mut csp_packet_t) {
    let mut current_block: u64;
    match (*packet).id.dport as ::core::ffi::c_int {
        0 => {
            if csp_cmp_handler(packet) != CSP_ERR_NONE {
                current_block = 14432673321361956680;
            } else {
                current_block = 12124785117276362961;
            }
        }
        1 => {
            current_block = 12124785117276362961;
        }
        2 => {
            (*packet).length = csp_ps_hook(packet) as uint16_t;
            if (*packet).length as ::core::ffi::c_int == 0 as ::core::ffi::c_int {
                current_block = 14432673321361956680;
            } else {
                current_block = 12124785117276362961;
            }
        }
        3 => {
            set_u32_reply(packet, csp_memfree_hook());
            current_block = 12124785117276362961;
        }
        4 => {
            let mut magic_word: uint32_t = 0;
            memcpy(
                &raw mut magic_word as *mut ::core::ffi::c_void,
                &raw mut (*packet).c2rust_unnamed.data as *mut uint8_t
                    as *const ::core::ffi::c_void,
                ::core::mem::size_of::<uint32_t>() as size_t,
            );
            magic_word = __bswap_32(magic_word as __uint32_t) as uint32_t;
            if magic_word == CSP_REBOOT_MAGIC as uint32_t {
                csp_reboot_hook();
            } else if magic_word == CSP_REBOOT_SHUTDOWN_MAGIC as uint32_t {
                csp_shutdown_hook();
            }
            current_block = 14432673321361956680;
        }
        5 => {
            set_u32_reply(packet, csp_buffer_remaining() as uint32_t);
            current_block = 12124785117276362961;
        }
        6 => {
            set_u32_reply(packet, csp_get_s());
            current_block = 12124785117276362961;
        }
        _ => {
            current_block = 14432673321361956680;
        }
    }
    match current_block {
        12124785117276362961 => {
            csp_sendto_reply(packet, packet, CSP_O_SAME as uint32_t);
            return;
        }
        _ => {
            csp_buffer_free(packet as *mut ::core::ffi::c_void);
            return;
        }
    };
}
