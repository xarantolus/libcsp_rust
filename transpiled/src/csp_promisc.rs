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
    static mut csp_dbg_conn_ovf: uint8_t;
    fn csp_buffer_free(buffer: *mut ::core::ffi::c_void);
    fn csp_buffer_clone(packet: *const csp_packet_t) -> *mut csp_packet_t;
    fn csp_buffer_remaining() -> ::core::ffi::c_int;
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
pub const NULL: *mut ::core::ffi::c_void = ::core::ptr::null_mut::<
    ::core::ffi::c_void,
>();
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ERR_INVAL: ::core::ffi::c_int = -(2 as ::core::ffi::c_int);
pub const CSP_ERR_USED: ::core::ffi::c_int = -(4 as ::core::ffi::c_int);
pub const CSP_CONN_RXQUEUE_LEN: ::core::ffi::c_int = 16 as ::core::ffi::c_int;
pub const CSP_BUFFER_COUNT: ::core::ffi::c_int = 15 as ::core::ffi::c_int;
pub const CSP_QUEUE_OK: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
static mut csp_promisc_queue: csp_queue_handle_t = ::core::ptr::null::<pthread_queue_t>()
    as *mut pthread_queue_t;
#[link_section = ".noinit"]
static mut csp_promisc_queue_static: csp_static_queue_t = ::core::ptr::null::<
    ::core::ffi::c_void,
>() as *mut ::core::ffi::c_void;
#[link_section = ".noinit"]
static mut csp_promisc_queue_buffer: [::core::ffi::c_char; 128] = [0; 128];
static mut csp_promisc_enabled: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_PROMISC_BUFFER_RESERVE: ::core::ffi::c_int = CSP_BUFFER_COUNT
    / 4 as ::core::ffi::c_int;
#[no_mangle]
pub unsafe extern "C" fn csp_promisc_enable(
    mut queue_size: ::core::ffi::c_uint,
) -> ::core::ffi::c_int {
    if !csp_promisc_queue.is_null() {
        csp_promisc_enabled = 1 as ::core::ffi::c_int;
        return CSP_ERR_USED;
    }
    csp_promisc_queue = csp_queue_create_static(
        CSP_CONN_RXQUEUE_LEN,
        ::core::mem::size_of::<*mut csp_packet_t>() as size_t,
        &raw mut csp_promisc_queue_buffer as *mut ::core::ffi::c_char,
        &raw mut csp_promisc_queue_static,
    );
    if csp_promisc_queue.is_null() {
        return CSP_ERR_INVAL;
    }
    csp_promisc_enabled = 1 as ::core::ffi::c_int;
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_promisc_disable() {
    csp_promisc_enabled = 0 as ::core::ffi::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn csp_promisc_read(mut timeout: uint32_t) -> *mut csp_packet_t {
    if csp_promisc_queue.is_null() {
        return ::core::ptr::null_mut::<csp_packet_t>();
    }
    let mut packet: *mut csp_packet_t = ::core::ptr::null_mut::<csp_packet_t>();
    csp_queue_dequeue(
        csp_promisc_queue,
        &raw mut packet as *mut ::core::ffi::c_void,
        timeout,
    );
    return packet;
}
#[no_mangle]
pub unsafe extern "C" fn csp_promisc_add(mut packet: *mut csp_packet_t) {
    if csp_promisc_enabled == 0 as ::core::ffi::c_int {
        return;
    }
    if !csp_promisc_queue.is_null() {
        if csp_buffer_remaining() <= CSP_PROMISC_BUFFER_RESERVE {
            csp_dbg_conn_ovf = csp_dbg_conn_ovf.wrapping_add(1);
            return;
        }
        let mut packet_copy: *mut csp_packet_t = csp_buffer_clone(packet);
        if !packet_copy.is_null() {
            if csp_queue_enqueue(
                csp_promisc_queue,
                &raw mut packet_copy as *const ::core::ffi::c_void,
                0 as uint32_t,
            ) != CSP_QUEUE_OK
            {
                csp_dbg_conn_ovf = csp_dbg_conn_ovf.wrapping_add(1);
                csp_buffer_free(packet_copy as *mut ::core::ffi::c_void);
            }
        }
    }
}
