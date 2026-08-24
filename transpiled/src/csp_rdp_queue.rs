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
    fn csp_queue_dequeue(
        handle: csp_queue_handle_t,
        buf: *mut ::core::ffi::c_void,
        timeout: uint32_t,
    ) -> ::core::ffi::c_int;
    fn csp_queue_size(handle: csp_queue_handle_t) -> ::core::ffi::c_int;
    fn csp_buffer_free(buffer: *mut ::core::ffi::c_void);
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
pub type csp_conn_t = csp_conn_s;
pub const NULL: *mut ::core::ffi::c_void = ::core::ptr::null_mut::<
    ::core::ffi::c_void,
>();
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_RDP_MAX_WINDOW: ::core::ffi::c_int = 5 as ::core::ffi::c_int;
pub const CSP_QUEUE_OK: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
unsafe extern "C" fn __csp_rdp_queue_flush(
    mut queue: csp_queue_handle_t,
    mut conn: *mut csp_conn_t,
) -> ::core::ffi::c_int {
    let mut ret: ::core::ffi::c_int = CSP_ERR_NONE;
    let mut size: ::core::ffi::c_int = 0;
    size = csp_queue_size(queue);
    loop {
        let fresh0 = size;
        size = size - 1;
        if !(fresh0 != 0) {
            break;
        }
        let mut packet: *mut csp_packet_t = ::core::ptr::null_mut::<csp_packet_t>();
        ret = csp_queue_dequeue(
            queue,
            &raw mut packet as *mut ::core::ffi::c_void,
            0 as uint32_t,
        );
        if ret != CSP_QUEUE_OK {
            break;
        }
        if conn == (*packet).conn {
            csp_buffer_free(packet as *mut ::core::ffi::c_void);
        } else {
            ret = csp_queue_enqueue(
                queue,
                &raw mut packet as *const ::core::ffi::c_void,
                0 as uint32_t,
            );
            if ret != CSP_QUEUE_OK {
                break;
            }
        }
    }
    return ret;
}
unsafe extern "C" fn __csp_rdp_queue_flush_all(
    mut queue: csp_queue_handle_t,
) -> ::core::ffi::c_int {
    let mut ret: ::core::ffi::c_int = CSP_ERR_NONE;
    let mut size: ::core::ffi::c_int = 0;
    size = csp_queue_size(queue);
    loop {
        let fresh1 = size;
        size = size - 1;
        if !(fresh1 != 0) {
            break;
        }
        let mut packet: *mut csp_packet_t = ::core::ptr::null_mut::<csp_packet_t>();
        ret = csp_queue_dequeue(
            queue,
            &raw mut packet as *mut ::core::ffi::c_void,
            0 as uint32_t,
        );
        if ret != CSP_QUEUE_OK {
            break;
        }
        csp_buffer_free(packet as *mut ::core::ffi::c_void);
    }
    return ret;
}
unsafe extern "C" fn csp_rdp_queue_add(
    mut queue: csp_queue_handle_t,
    mut conn: *mut csp_conn_t,
    mut packet: *mut csp_packet_t,
) {
    (*packet).conn = conn as *mut csp_conn_s;
    if csp_queue_enqueue(
        queue,
        &raw mut packet as *const ::core::ffi::c_void,
        0 as uint32_t,
    ) != CSP_QUEUE_OK
    {
        csp_buffer_free(packet as *mut ::core::ffi::c_void);
    }
}
unsafe extern "C" fn csp_rdp_queue_get(
    mut queue: csp_queue_handle_t,
    mut conn: *mut csp_conn_t,
) -> *mut csp_packet_t {
    let mut packet: *mut csp_packet_t = ::core::ptr::null_mut::<csp_packet_t>();
    let mut size: ::core::ffi::c_int = csp_queue_size(queue);
    loop {
        let fresh2 = size;
        size = size - 1;
        if !(fresh2 != 0) {
            break;
        }
        if csp_queue_dequeue(
            queue,
            &raw mut packet as *mut ::core::ffi::c_void,
            0 as uint32_t,
        ) != CSP_QUEUE_OK
        {
            return ::core::ptr::null_mut::<csp_packet_t>();
        }
        if (*packet).conn == conn {
            return packet;
        }
        csp_rdp_queue_add(queue, conn, packet);
    }
    return ::core::ptr::null_mut::<csp_packet_t>();
}
static mut tx_queue: csp_queue_handle_t = ::core::ptr::null::<pthread_queue_t>()
    as *mut pthread_queue_t;
static mut tx_queue_static: csp_static_queue_t = ::core::ptr::null::<
    ::core::ffi::c_void,
>() as *mut ::core::ffi::c_void;
static mut tx_queue_static_data: [::core::ffi::c_char; 80] = [0; 80];
static mut rx_queue: csp_queue_handle_t = ::core::ptr::null::<pthread_queue_t>()
    as *mut pthread_queue_t;
static mut rx_queue_static: csp_static_queue_t = ::core::ptr::null::<
    ::core::ffi::c_void,
>() as *mut ::core::ffi::c_void;
static mut rx_queue_static_data: [::core::ffi::c_char; 80] = [0; 80];
#[no_mangle]
pub unsafe extern "C" fn csp_rdp_queue_init() {
    tx_queue = csp_queue_create_static(
        CSP_RDP_MAX_WINDOW * 2 as ::core::ffi::c_int,
        ::core::mem::size_of::<*mut csp_packet_t>() as size_t,
        &raw mut tx_queue_static_data as *mut ::core::ffi::c_char,
        &raw mut tx_queue_static,
    );
    rx_queue = csp_queue_create_static(
        CSP_RDP_MAX_WINDOW * 2 as ::core::ffi::c_int,
        ::core::mem::size_of::<*mut csp_packet_t>() as size_t,
        &raw mut rx_queue_static_data as *mut ::core::ffi::c_char,
        &raw mut rx_queue_static,
    );
}
#[no_mangle]
pub unsafe extern "C" fn csp_rdp_queue_flush(mut conn: *mut csp_conn_t) {
    if conn.is_null() {
        __csp_rdp_queue_flush_all(tx_queue);
        __csp_rdp_queue_flush_all(rx_queue);
    } else {
        __csp_rdp_queue_flush(tx_queue, conn);
        __csp_rdp_queue_flush(rx_queue, conn);
    };
}
#[no_mangle]
pub unsafe extern "C" fn csp_rdp_queue_tx_size() -> ::core::ffi::c_int {
    return csp_queue_size(tx_queue);
}
#[no_mangle]
pub unsafe extern "C" fn csp_rdp_queue_tx_add(
    mut conn: *mut csp_conn_t,
    mut packet: *mut csp_packet_t,
) {
    csp_rdp_queue_add(tx_queue, conn, packet);
}
#[no_mangle]
pub unsafe extern "C" fn csp_rdp_queue_tx_get(
    mut conn: *mut csp_conn_t,
) -> *mut csp_packet_t {
    return csp_rdp_queue_get(tx_queue, conn);
}
#[no_mangle]
pub unsafe extern "C" fn csp_rdp_queue_rx_size() -> ::core::ffi::c_int {
    return csp_queue_size(rx_queue);
}
#[no_mangle]
pub unsafe extern "C" fn csp_rdp_queue_rx_add(
    mut conn: *mut csp_conn_t,
    mut packet: *mut csp_packet_t,
) {
    csp_rdp_queue_add(rx_queue, conn, packet);
}
#[no_mangle]
pub unsafe extern "C" fn csp_rdp_queue_rx_get(
    mut conn: *mut csp_conn_t,
) -> *mut csp_packet_t {
    return csp_rdp_queue_get(rx_queue, conn);
}
