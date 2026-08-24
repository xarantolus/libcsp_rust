extern "C" {
    pub type pthread_queue_s;
    pub type csp_conn_s;
    fn csp_queue_create_static(
        length: ::core::ffi::c_int,
        item_size: size_t,
        buffer: *mut ::core::ffi::c_char,
        queue: *mut csp_static_queue_t,
    ) -> csp_queue_handle_t;
    fn csp_queue_enqueue(
        handle: csp_queue_handle_t,
        value: *const ::core::ffi::c_void,
        timeout: uint32_t,
    ) -> ::core::ffi::c_int;
    fn csp_queue_enqueue_isr(
        handle: csp_queue_handle_t,
        value: *const ::core::ffi::c_void,
        pxTaskWoken: *mut ::core::ffi::c_int,
    ) -> ::core::ffi::c_int;
    fn csp_queue_dequeue(
        handle: csp_queue_handle_t,
        buf: *mut ::core::ffi::c_void,
        timeout: uint32_t,
    ) -> ::core::ffi::c_int;
    fn csp_queue_dequeue_isr(
        handle: csp_queue_handle_t,
        buf: *mut ::core::ffi::c_void,
        pxTaskWoken: *mut ::core::ffi::c_int,
    ) -> ::core::ffi::c_int;
    fn csp_queue_size(handle: csp_queue_handle_t) -> ::core::ffi::c_int;
    fn csp_queue_size_isr(handle: csp_queue_handle_t) -> ::core::ffi::c_int;
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
    static mut csp_dbg_buffer_out: uint8_t;
    static mut csp_dbg_errno: uint8_t;
    fn csp_panic(msg: *const ::core::ffi::c_char);
    fn csp_id_clear(target: *mut csp_id_t);
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
pub type pthread_queue_t = pthread_queue_s;
pub type csp_queue_handle_t = *mut pthread_queue_t;
pub type csp_static_queue_t = *mut ::core::ffi::c_void;
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
pub type csp_skbf_t = csp_skbf_s;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct csp_skbf_s {
    pub refcount: ::core::ffi::c_uint,
    pub skbf_addr: *mut ::core::ffi::c_void,
    pub skbf_data: csp_packet_t,
}
pub const CSP_BUFFER_SIZE: ::core::ffi::c_int = 256 as ::core::ffi::c_int;
pub const CSP_BUFFER_COUNT: ::core::ffi::c_int = 15 as ::core::ffi::c_int;
pub const CSP_PACKET_PADDING_BYTES: ::core::ffi::c_int = 8 as ::core::ffi::c_int;
pub const CSP_BUFFER_RESERVED_COUNT: ::core::ffi::c_int = 2 as ::core::ffi::c_int;
pub const NULL: *mut ::core::ffi::c_void = ::core::ptr::null_mut::<
    ::core::ffi::c_void,
>();
pub const CSP_DBG_ERR_CORRUPT_BUFFER: ::core::ffi::c_int = 1 as ::core::ffi::c_int;
pub const CSP_DBG_ERR_ALREADY_FREE: ::core::ffi::c_int = 3 as ::core::ffi::c_int;
pub const CSP_DBG_ERR_REFCOUNT: ::core::ffi::c_int = 4 as ::core::ffi::c_int;
pub const CSP_DBG_ERR_INVALID_POINTER: ::core::ffi::c_int = 11 as ::core::ffi::c_int;
static mut csp_buffers: csp_queue_handle_t = ::core::ptr::null::<pthread_queue_t>()
    as *mut pthread_queue_t;
#[link_section = ".noinit"]
static mut csp_buffer_pool: [csp_skbf_t; 15] = [csp_skbf_s {
    refcount: 0,
    skbf_addr: ::core::ptr::null::<::core::ffi::c_void>() as *mut ::core::ffi::c_void,
    skbf_data: csp_packet_s {
        timestamp_tx: 0,
        timestamp_rx: 0,
        conn: ::core::ptr::null::<csp_conn_s>() as *mut csp_conn_s,
        rx_count: 0,
        remain: 0,
        cfpid: 0,
        last_used: 0,
        frame_begin: ::core::ptr::null::<uint8_t>() as *mut uint8_t,
        frame_length: 0,
        length: 0,
        id: csp_id_t {
            pri: 0,
            flags: 0,
            src: 0,
            dst: 0,
            dport: 0,
            sport: 0,
        },
        next: ::core::ptr::null::<csp_packet_s>() as *mut csp_packet_s,
        header: [0; 8],
        c2rust_unnamed: C2RustUnnamed { data: [0; 256] },
    },
}; 15];
#[link_section = ".noinit"]
static mut csp_buffers_queue: csp_static_queue_t = ::core::ptr::null::<
    ::core::ffi::c_void,
>() as *mut ::core::ffi::c_void;
#[link_section = ".noinit"]
static mut csp_buffer_queue_data: [::core::ffi::c_char; 120] = [0; 120];
#[no_mangle]
pub unsafe extern "C" fn csp_buffer_init() {
    csp_buffers = csp_queue_create_static(
        CSP_BUFFER_COUNT,
        ::core::mem::size_of::<*mut csp_skbf_t>() as size_t,
        &raw mut csp_buffer_queue_data as *mut ::core::ffi::c_char,
        &raw mut csp_buffers_queue,
    );
    let mut i: ::core::ffi::c_uint = 0 as ::core::ffi::c_uint;
    while i < CSP_BUFFER_COUNT as ::core::ffi::c_uint {
        csp_buffer_pool[i as usize].skbf_addr = (&raw mut csp_buffer_pool
            as *mut csp_skbf_t)
            .offset(i as isize) as *mut csp_skbf_t as *mut ::core::ffi::c_void;
        let mut bufptr: *mut csp_skbf_t = (&raw mut csp_buffer_pool as *mut csp_skbf_t)
            .offset(i as isize) as *mut csp_skbf_t;
        csp_queue_enqueue(
            csp_buffers,
            &raw mut bufptr as *const ::core::ffi::c_void,
            0 as uint32_t,
        );
        i = i.wrapping_add(1);
    }
}
unsafe extern "C" fn csp_packet_init(
    mut packet: *mut csp_packet_t,
) -> *mut csp_packet_t {
    memset(
        packet as *mut ::core::ffi::c_void,
        0 as ::core::ffi::c_int,
        ::core::mem::size_of::<csp_packet_t>() as size_t,
    );
    (*packet).length = 0 as uint16_t;
    (*packet).frame_begin = &raw mut (*packet).c2rust_unnamed.data as *mut uint8_t;
    (*packet).frame_length = 0 as uint16_t;
    csp_id_clear(&raw mut (*packet).id);
    return packet;
}
unsafe extern "C" fn csp_buffer_get_actual(
    mut reserve: ::core::ffi::c_int,
    mut isr: ::core::ffi::c_int,
) -> *mut csp_packet_t {
    let mut remain: ::core::ffi::c_int = 0;
    if isr != 0 {
        remain = csp_queue_size_isr(csp_buffers);
    } else {
        remain = csp_queue_size(csp_buffers);
    }
    if remain <= reserve {
        return ::core::ptr::null_mut::<csp_packet_t>();
    }
    let mut buf: *mut csp_skbf_t = ::core::ptr::null_mut::<csp_skbf_t>();
    if isr != 0 {
        let mut task_woken: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
        csp_queue_dequeue_isr(
            csp_buffers,
            &raw mut buf as *mut ::core::ffi::c_void,
            &raw mut task_woken,
        );
    } else {
        csp_queue_dequeue(
            csp_buffers,
            &raw mut buf as *mut ::core::ffi::c_void,
            0 as uint32_t,
        );
    }
    if buf.is_null() {
        csp_dbg_buffer_out = csp_dbg_buffer_out.wrapping_add(1);
        return ::core::ptr::null_mut::<csp_packet_t>();
    }
    if buf != (*buf).skbf_addr as *mut csp_skbf_t {
        csp_dbg_errno = CSP_DBG_ERR_CORRUPT_BUFFER as uint8_t;
        return ::core::ptr::null_mut::<csp_packet_t>();
    }
    (*buf).refcount = 1 as ::core::ffi::c_uint;
    return csp_packet_init(&raw mut (*buf).skbf_data);
}
#[no_mangle]
pub unsafe extern "C" fn csp_buffer_free_isr(mut packet: *mut ::core::ffi::c_void) {
    if packet.is_null() {
        return;
    }
    let mut buf: *mut csp_skbf_t = (packet as *mut ::core::ffi::c_char)
        .offset(-(16 as ::core::ffi::c_ulong as isize)) as *mut ::core::ffi::c_void
        as *mut csp_skbf_t;
    if (*buf).skbf_addr != buf as *mut ::core::ffi::c_void {
        csp_dbg_errno = CSP_DBG_ERR_CORRUPT_BUFFER as uint8_t;
        return;
    }
    if (*buf).refcount == 0 as ::core::ffi::c_uint {
        csp_dbg_errno = CSP_DBG_ERR_ALREADY_FREE as uint8_t;
        return;
    }
    (*buf).refcount = (*buf).refcount.wrapping_sub(1);
    if (*buf).refcount > 0 as ::core::ffi::c_uint {
        csp_dbg_errno = CSP_DBG_ERR_REFCOUNT as uint8_t;
        return;
    }
    let mut task_woken: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
    csp_queue_enqueue_isr(
        csp_buffers,
        &raw mut buf as *const ::core::ffi::c_void,
        &raw mut task_woken,
    );
}
#[no_mangle]
pub unsafe extern "C" fn csp_buffer_free(mut packet: *mut ::core::ffi::c_void) {
    if packet.is_null() {
        return;
    }
    let mut buf: *mut csp_skbf_t = (packet as *mut ::core::ffi::c_char)
        .offset(-(16 as ::core::ffi::c_ulong as isize)) as *mut ::core::ffi::c_void
        as *mut csp_skbf_t;
    if (*buf).skbf_addr != buf as *mut ::core::ffi::c_void {
        csp_dbg_errno = CSP_DBG_ERR_CORRUPT_BUFFER as uint8_t;
        return;
    }
    if (*buf).refcount == 0 as ::core::ffi::c_uint {
        csp_dbg_errno = CSP_DBG_ERR_ALREADY_FREE as uint8_t;
        return;
    }
    (*buf).refcount = (*buf).refcount.wrapping_sub(1);
    if (*buf).refcount > 0 as ::core::ffi::c_uint {
        csp_dbg_errno = CSP_DBG_ERR_REFCOUNT as uint8_t;
        return;
    }
    csp_queue_enqueue(
        csp_buffers,
        &raw mut buf as *const ::core::ffi::c_void,
        0 as uint32_t,
    );
}
#[no_mangle]
pub unsafe extern "C" fn csp_buffer_clone(
    mut packet: *const csp_packet_t,
) -> *mut csp_packet_t {
    let mut clone: *mut csp_packet_t = ::core::ptr::null_mut::<csp_packet_t>();
    if !packet.is_null() {
        clone = csp_buffer_get(0 as size_t);
        csp_buffer_copy(packet, clone);
    }
    return clone;
}
#[no_mangle]
pub unsafe extern "C" fn csp_buffer_copy(
    mut src: *const csp_packet_t,
    mut dst: *mut csp_packet_t,
) {
    if !src.is_null() && !dst.is_null() {
        let mut size: size_t = (::core::mem::size_of::<csp_packet_t>() as size_t)
            .wrapping_sub(CSP_BUFFER_SIZE as size_t)
            .wrapping_add((*src).length as size_t);
        memcpy(
            dst as *mut ::core::ffi::c_void,
            src as *const ::core::ffi::c_void,
            if size > ::core::mem::size_of::<csp_packet_t>() as usize {
                ::core::mem::size_of::<csp_packet_t>() as size_t
            } else {
                size
            },
        );
        (*dst).frame_begin = (&raw mut (*dst).header as *mut uint8_t)
            .offset(CSP_PACKET_PADDING_BYTES as isize)
            .offset(
                -((&raw const (*src).c2rust_unnamed.data as *const uint8_t)
                    .offset_from((*src).frame_begin) as ::core::ffi::c_long as isize),
            );
    }
}
#[no_mangle]
pub unsafe extern "C" fn csp_buffer_refc_inc(mut buffer: *mut ::core::ffi::c_void) {
    if buffer.is_null() {
        csp_dbg_errno = CSP_DBG_ERR_INVALID_POINTER as uint8_t;
        return;
    }
    let mut buf: *mut csp_skbf_t = (buffer as *mut ::core::ffi::c_char)
        .offset(-(16 as ::core::ffi::c_ulong as isize)) as *mut ::core::ffi::c_void
        as *mut csp_skbf_t;
    if (*buf).skbf_addr != buf as *mut ::core::ffi::c_void {
        csp_dbg_errno = CSP_DBG_ERR_CORRUPT_BUFFER as uint8_t;
        return;
    }
    (*buf).refcount = (*buf).refcount.wrapping_add(1);
}
#[no_mangle]
pub unsafe extern "C" fn csp_buffer_remaining() -> ::core::ffi::c_int {
    return csp_queue_size(csp_buffers);
}
#[no_mangle]
pub unsafe extern "C" fn csp_buffer_get_always() -> *mut csp_packet_t {
    let mut packet: *mut csp_packet_t = csp_buffer_get_actual(
        0 as ::core::ffi::c_int,
        0 as ::core::ffi::c_int,
    );
    if packet.is_null() {
        csp_panic(b"Out of buffers\0" as *const u8 as *const ::core::ffi::c_char);
        loop {}
    }
    return packet;
}
#[no_mangle]
pub unsafe extern "C" fn csp_buffer_get_always_isr() -> *mut csp_packet_t {
    let mut packet: *mut csp_packet_t = csp_buffer_get_actual(
        0 as ::core::ffi::c_int,
        1 as ::core::ffi::c_int,
    );
    if packet.is_null() {
        csp_panic(b"Out of buffers\0" as *const u8 as *const ::core::ffi::c_char);
        loop {}
    }
    return packet;
}
#[no_mangle]
pub unsafe extern "C" fn csp_buffer_get(mut unused: size_t) -> *mut csp_packet_t {
    return csp_buffer_get_actual(CSP_BUFFER_RESERVED_COUNT, 0 as ::core::ffi::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn csp_buffer_get_isr(mut unused: size_t) -> *mut csp_packet_t {
    return csp_buffer_get_actual(CSP_BUFFER_RESERVED_COUNT, 1 as ::core::ffi::c_int);
}
