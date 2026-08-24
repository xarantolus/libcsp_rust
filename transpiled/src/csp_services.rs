extern "C" {
    pub type csp_conn_s;
    fn csp_print_func(fmt: *const ::core::ffi::c_char, ...);
    fn csp_buffer_get(unused: size_t) -> *mut csp_packet_t;
    fn csp_buffer_free(buffer: *mut ::core::ffi::c_void);
    fn csp_read(conn: *mut csp_conn_t, timeout: uint32_t) -> *mut csp_packet_t;
    fn csp_send(conn: *mut csp_conn_t, packet: *mut csp_packet_t);
    fn csp_transaction_w_opts(
        prio: uint8_t,
        dst: uint16_t,
        dst_port: uint8_t,
        timeout: uint32_t,
        outbuf: *const ::core::ffi::c_void,
        outlen: ::core::ffi::c_int,
        inbuf: *mut ::core::ffi::c_void,
        inlen: ::core::ffi::c_int,
        opts: uint32_t,
    ) -> ::core::ffi::c_int;
    fn csp_connect(
        prio: uint8_t,
        dst: uint16_t,
        dst_port: uint8_t,
        timeout: uint32_t,
        opts: uint32_t,
    ) -> *mut csp_conn_t;
    fn csp_close(conn: *mut csp_conn_t) -> ::core::ffi::c_int;
    fn csp_get_ms() -> uint32_t;
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
pub type C2RustUnnamed_0 = ::core::ffi::c_uint;
pub const CSP_PRIO_LOW: C2RustUnnamed_0 = 3;
pub const CSP_PRIO_NORM: C2RustUnnamed_0 = 2;
pub const CSP_PRIO_HIGH: C2RustUnnamed_0 = 1;
pub const CSP_PRIO_CRITICAL: C2RustUnnamed_0 = 0;
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
    pub c2rust_unnamed: C2RustUnnamed_1,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_1 {
    pub data: [uint8_t; 256],
    pub data16: [uint16_t; 128],
    pub data32: [uint32_t; 64],
}
pub type csp_packet_t = csp_packet_s;
pub type csp_conn_t = csp_conn_s;
pub type C2RustUnnamed_2 = ::core::ffi::c_uint;
pub const CSP_CMP_REPLY: C2RustUnnamed_2 = 255;
pub const CSP_CMP_REQUEST: C2RustUnnamed_2 = 0;
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct csp_cmp_header {
    pub type_0: uint8_t,
    pub code: uint8_t,
}
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ERR_TIMEDOUT: ::core::ffi::c_int = -(3 as ::core::ffi::c_int);
pub const NULL: *mut ::core::ffi::c_void = ::core::ptr::null_mut::<
    ::core::ffi::c_void,
>();
pub const CSP_BUFFER_SIZE: ::core::ffi::c_int = 256 as ::core::ffi::c_int;
pub const CSP_SO_CRC32REQ: ::core::ffi::c_int = 0x40 as ::core::ffi::c_int;
pub const CSP_O_CRC32: ::core::ffi::c_int = CSP_SO_CRC32REQ;
#[inline]
unsafe extern "C" fn __bswap_32(mut __bsx: __uint32_t) -> __uint32_t {
    return (__bsx & 0xff000000 as __uint32_t) >> 24 as ::core::ffi::c_int
        | (__bsx & 0xff0000 as __uint32_t) >> 8 as ::core::ffi::c_int
        | (__bsx & 0xff00 as __uint32_t) << 8 as ::core::ffi::c_int
        | (__bsx & 0xff as __uint32_t) << 24 as ::core::ffi::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn csp_ping(
    mut node: uint16_t,
    mut timeout: uint32_t,
    mut size: ::core::ffi::c_uint,
    mut conn_options: uint8_t,
) -> ::core::ffi::c_int {
    let mut current_block: u64;
    let mut i: ::core::ffi::c_uint = 0;
    let mut start: uint32_t = 0;
    let mut time: uint32_t = 0;
    let mut status: uint32_t = 0 as uint32_t;
    if size > CSP_BUFFER_SIZE as ::core::ffi::c_uint {
        return -(1 as ::core::ffi::c_int);
    }
    start = csp_get_ms();
    let mut conn: *mut csp_conn_t = csp_connect(
        CSP_PRIO_NORM as ::core::ffi::c_int as uint8_t,
        node,
        CSP_PING as ::core::ffi::c_int as uint8_t,
        timeout,
        conn_options as uint32_t,
    );
    if conn.is_null() {
        return -(1 as ::core::ffi::c_int);
    }
    let mut packet: *mut csp_packet_t = csp_buffer_get(0 as size_t);
    if !packet.is_null() {
        (*packet).length = size as uint16_t;
        i = 0 as ::core::ffi::c_uint;
        while i < size {
            (*packet).c2rust_unnamed.data[i as usize] = i as uint8_t;
            i = i.wrapping_add(1);
        }
        csp_send(conn, packet);
        packet = csp_read(conn, timeout);
        if !packet.is_null() {
            i = 0 as ::core::ffi::c_uint;
            loop {
                if !(i < size) {
                    current_block = 1054647088692577877;
                    break;
                }
                if (*packet).c2rust_unnamed.data[i as usize] as ::core::ffi::c_uint
                    != i
                        .wrapping_rem(
                            (0xff as ::core::ffi::c_int + 1 as ::core::ffi::c_int)
                                as ::core::ffi::c_uint,
                        )
                {
                    current_block = 13565261516738605841;
                    break;
                }
                i = i.wrapping_add(1);
            }
            match current_block {
                13565261516738605841 => {}
                _ => {
                    status = 1 as uint32_t;
                }
            }
        }
    }
    csp_buffer_free(packet as *mut ::core::ffi::c_void);
    csp_close(conn);
    time = csp_get_ms().wrapping_sub(start);
    if status != 0 {
        return time as ::core::ffi::c_int;
    }
    return -(1 as ::core::ffi::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn csp_ping_noreply(mut node: uint16_t) {
    let mut packet: *mut csp_packet_t = csp_buffer_get(0 as size_t);
    if packet.is_null() {
        return;
    }
    let mut conn: *mut csp_conn_t = csp_connect(
        CSP_PRIO_NORM as ::core::ffi::c_int as uint8_t,
        node,
        CSP_PING as ::core::ffi::c_int as uint8_t,
        0 as uint32_t,
        CSP_O_CRC32 as uint32_t,
    );
    if conn.is_null() {
        csp_buffer_free(packet as *mut ::core::ffi::c_void);
        return;
    }
    (*packet).c2rust_unnamed.data[0 as ::core::ffi::c_int as usize] = 0x55 as uint8_t;
    (*packet).length = 1 as uint16_t;
    csp_send(conn, packet);
    csp_close(conn);
}
#[no_mangle]
pub unsafe extern "C" fn csp_reboot(mut node: uint16_t) {
    let mut magic_word: uint32_t = __bswap_32(0x80078007 as __uint32_t) as uint32_t;
    csp_transaction_w_opts(
        CSP_PRIO_NORM as ::core::ffi::c_int as uint8_t,
        node,
        CSP_REBOOT as ::core::ffi::c_int as uint8_t,
        0 as uint32_t,
        &raw mut magic_word as *const ::core::ffi::c_void,
        ::core::mem::size_of::<uint32_t>() as ::core::ffi::c_int,
        NULL,
        0 as ::core::ffi::c_int,
        CSP_O_CRC32 as uint32_t,
    );
}
#[no_mangle]
pub unsafe extern "C" fn csp_shutdown(mut node: uint16_t) {
    let mut magic_word: uint32_t = __bswap_32(0xd1e5529a as __uint32_t) as uint32_t;
    csp_transaction_w_opts(
        CSP_PRIO_NORM as ::core::ffi::c_int as uint8_t,
        node,
        CSP_REBOOT as ::core::ffi::c_int as uint8_t,
        0 as uint32_t,
        &raw mut magic_word as *const ::core::ffi::c_void,
        ::core::mem::size_of::<uint32_t>() as ::core::ffi::c_int,
        NULL,
        0 as ::core::ffi::c_int,
        CSP_O_CRC32 as uint32_t,
    );
}
#[no_mangle]
pub unsafe extern "C" fn csp_ps(mut node: uint16_t, mut timeout: uint32_t) {
    let mut conn: *mut csp_conn_t = csp_connect(
        CSP_PRIO_NORM as ::core::ffi::c_int as uint8_t,
        node,
        CSP_PS as ::core::ffi::c_int as uint8_t,
        0 as uint32_t,
        CSP_O_CRC32 as uint32_t,
    );
    if conn.is_null() {
        return;
    }
    let mut packet: *mut csp_packet_t = csp_buffer_get(0 as size_t);
    if !packet.is_null() {
        (*packet).c2rust_unnamed.data[0 as ::core::ffi::c_int as usize] = 0x55
            as uint8_t;
        (*packet).length = 1 as uint16_t;
        csp_send(conn, packet);
        loop {
            packet = csp_read(conn, timeout);
            if packet.is_null() {
                break;
            }
            let length: ::core::ffi::c_uint = (if ((*packet).length as usize)
                < ::core::mem::size_of::<[uint8_t; 256]>() as usize
            {
                (*packet).length as usize
            } else {
                (::core::mem::size_of::<[uint8_t; 256]>() as usize)
                    .wrapping_sub(1 as usize)
            }) as ::core::ffi::c_uint;
            (*packet).c2rust_unnamed.data[length as usize] = 0 as uint8_t;
            csp_print_func(
                b"%s\0" as *const u8 as *const ::core::ffi::c_char,
                &raw mut (*packet).c2rust_unnamed.data as *mut uint8_t,
            );
            csp_buffer_free(packet as *mut ::core::ffi::c_void);
        }
        csp_print_func(b"\r\n\0" as *const u8 as *const ::core::ffi::c_char);
    }
    csp_buffer_free(packet as *mut ::core::ffi::c_void);
    csp_close(conn);
}
#[no_mangle]
pub unsafe extern "C" fn csp_get_memfree(
    mut node: uint16_t,
    mut timeout: uint32_t,
    mut size: *mut uint32_t,
) -> ::core::ffi::c_int {
    let mut status: ::core::ffi::c_int = csp_transaction_w_opts(
        CSP_PRIO_NORM as ::core::ffi::c_int as uint8_t,
        node,
        CSP_MEMFREE as ::core::ffi::c_int as uint8_t,
        timeout,
        ::core::ptr::null::<::core::ffi::c_void>(),
        0 as ::core::ffi::c_int,
        size as *mut ::core::ffi::c_void,
        ::core::mem::size_of::<uint32_t>() as ::core::ffi::c_int,
        CSP_O_CRC32 as uint32_t,
    );
    if status as usize == ::core::mem::size_of::<uint32_t>() as usize {
        *size = __bswap_32(*size) as uint32_t;
        return CSP_ERR_NONE;
    }
    *size = 0 as uint32_t;
    return CSP_ERR_TIMEDOUT;
}
#[no_mangle]
pub unsafe extern "C" fn csp_memfree(mut node: uint16_t, mut timeout: uint32_t) {
    let mut memfree: uint32_t = 0;
    let mut err: ::core::ffi::c_int = csp_get_memfree(node, timeout, &raw mut memfree);
    if err == CSP_ERR_NONE {
        csp_print_func(
            b"Free Memory at node %u is %u bytes\r\n\0" as *const u8
                as *const ::core::ffi::c_char,
            node as ::core::ffi::c_int,
            memfree,
        );
    } else {
        csp_print_func(
            b"Network error\r\n\0" as *const u8 as *const ::core::ffi::c_char,
        );
    };
}
#[no_mangle]
pub unsafe extern "C" fn csp_get_buf_free(
    mut node: uint16_t,
    mut timeout: uint32_t,
    mut size: *mut uint32_t,
) -> ::core::ffi::c_int {
    let mut status: ::core::ffi::c_int = csp_transaction_w_opts(
        CSP_PRIO_NORM as ::core::ffi::c_int as uint8_t,
        node,
        CSP_BUF_FREE as ::core::ffi::c_int as uint8_t,
        timeout,
        ::core::ptr::null::<::core::ffi::c_void>(),
        0 as ::core::ffi::c_int,
        size as *mut ::core::ffi::c_void,
        ::core::mem::size_of::<uint32_t>() as ::core::ffi::c_int,
        CSP_O_CRC32 as uint32_t,
    );
    if status as usize == ::core::mem::size_of::<uint32_t>() as usize {
        *size = __bswap_32(*size) as uint32_t;
        return CSP_ERR_NONE;
    }
    *size = 0 as uint32_t;
    return CSP_ERR_TIMEDOUT;
}
#[no_mangle]
pub unsafe extern "C" fn csp_buf_free(mut node: uint16_t, mut timeout: uint32_t) {
    let mut size: uint32_t = 0;
    let mut err: ::core::ffi::c_int = csp_get_buf_free(node, timeout, &raw mut size);
    if err == CSP_ERR_NONE {
        csp_print_func(
            b"Free buffers at node %u is %u\r\n\0" as *const u8
                as *const ::core::ffi::c_char,
            node as ::core::ffi::c_int,
            size,
        );
    } else {
        csp_print_func(
            b"Network error\r\n\0" as *const u8 as *const ::core::ffi::c_char,
        );
    };
}
#[no_mangle]
pub unsafe extern "C" fn csp_get_uptime(
    mut node: uint16_t,
    mut timeout: uint32_t,
    mut uptime: *mut uint32_t,
) -> ::core::ffi::c_int {
    let mut status: ::core::ffi::c_int = csp_transaction_w_opts(
        CSP_PRIO_NORM as ::core::ffi::c_int as uint8_t,
        node,
        CSP_UPTIME as ::core::ffi::c_int as uint8_t,
        timeout,
        ::core::ptr::null::<::core::ffi::c_void>(),
        0 as ::core::ffi::c_int,
        uptime as *mut ::core::ffi::c_void,
        ::core::mem::size_of::<uint32_t>() as ::core::ffi::c_int,
        CSP_O_CRC32 as uint32_t,
    );
    if status as usize == ::core::mem::size_of::<uint32_t>() as usize {
        *uptime = __bswap_32(*uptime) as uint32_t;
        return CSP_ERR_NONE;
    }
    *uptime = 0 as uint32_t;
    return CSP_ERR_TIMEDOUT;
}
#[no_mangle]
pub unsafe extern "C" fn csp_uptime(mut node: uint16_t, mut timeout: uint32_t) {
    let mut uptime: uint32_t = 0;
    let mut err: ::core::ffi::c_int = csp_get_uptime(node, timeout, &raw mut uptime);
    if err == CSP_ERR_NONE {
        csp_print_func(
            b"Uptime of node %u is %u s\r\n\0" as *const u8
                as *const ::core::ffi::c_char,
            node as ::core::ffi::c_int,
            uptime,
        );
    } else {
        csp_print_func(
            b"Network error\r\n\0" as *const u8 as *const ::core::ffi::c_char,
        );
    };
}
#[no_mangle]
pub unsafe extern "C" fn csp_cmp(
    mut node: uint16_t,
    mut timeout: uint32_t,
    mut code: uint8_t,
    mut msg_size: ::core::ffi::c_int,
    mut msg: *mut ::core::ffi::c_void,
) -> ::core::ffi::c_int {
    let mut header: *mut csp_cmp_header = msg as *mut csp_cmp_header;
    (*header).type_0 = CSP_CMP_REQUEST as ::core::ffi::c_int as uint8_t;
    (*header).code = code;
    let mut status: ::core::ffi::c_int = csp_transaction_w_opts(
        CSP_PRIO_NORM as ::core::ffi::c_int as uint8_t,
        node,
        CSP_CMP as ::core::ffi::c_int as uint8_t,
        timeout,
        msg,
        msg_size,
        msg,
        msg_size,
        CSP_O_CRC32 as uint32_t,
    );
    if status == 0 as ::core::ffi::c_int {
        return CSP_ERR_TIMEDOUT;
    }
    return CSP_ERR_NONE;
}
