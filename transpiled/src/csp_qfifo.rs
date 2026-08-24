extern "C" {
    pub type pthread_queue_s;
    pub type csp_conn_s;
    static mut csp_dbg_conn_ovf: uint8_t;
    static mut csp_dbg_errno: uint8_t;
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
    fn csp_buffer_free(buffer: *mut ::core::ffi::c_void);
    fn csp_buffer_free_isr(buffer: *mut ::core::ffi::c_void);
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
pub struct csp_qfifo_t {
    pub iface: *mut csp_iface_t,
    pub packet: *mut csp_packet_t,
}
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ERR_TIMEDOUT: ::core::ffi::c_int = -(3 as ::core::ffi::c_int);
pub const CSP_DBG_ERR_INVALID_POINTER: ::core::ffi::c_int = 11 as ::core::ffi::c_int;
pub const NULL: *mut ::core::ffi::c_void = ::core::ptr::null_mut::<
    ::core::ffi::c_void,
>();
pub const CSP_QFIFO_LEN: ::core::ffi::c_int = 15 as ::core::ffi::c_int;
pub const CSP_QUEUE_OK: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const FIFO_TIMEOUT: ::core::ffi::c_int = 100 as ::core::ffi::c_int;
#[link_section = ".noinit"]
static mut qfifo_queue: csp_static_queue_t = ::core::ptr::null::<::core::ffi::c_void>()
    as *mut ::core::ffi::c_void;
#[link_section = ".noinit"]
static mut qfifo_queue_handle: csp_queue_handle_t = ::core::ptr::null::<
    pthread_queue_t,
>() as *mut pthread_queue_t;
#[link_section = ".noinit"]
static mut qfifo_queue_buffer: [::core::ffi::c_char; 240] = [0; 240];
#[no_mangle]
pub unsafe extern "C" fn csp_qfifo_init() {
    qfifo_queue_handle = csp_queue_create_static(
        CSP_QFIFO_LEN,
        ::core::mem::size_of::<csp_qfifo_t>() as size_t,
        &raw mut qfifo_queue_buffer as *mut ::core::ffi::c_char,
        &raw mut qfifo_queue,
    );
}
#[no_mangle]
pub unsafe extern "C" fn csp_qfifo_read(
    mut input: *mut csp_qfifo_t,
) -> ::core::ffi::c_int {
    if csp_queue_dequeue(
        qfifo_queue_handle,
        input as *mut ::core::ffi::c_void,
        FIFO_TIMEOUT as uint32_t,
    ) != CSP_QUEUE_OK
    {
        return CSP_ERR_TIMEDOUT;
    }
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_qfifo_write(
    mut packet: *mut csp_packet_t,
    mut iface: *mut csp_iface_t,
    mut pxTaskWoken: *mut ::core::ffi::c_void,
) {
    let mut result: ::core::ffi::c_int = 0;
    if packet.is_null() {
        csp_dbg_errno = CSP_DBG_ERR_INVALID_POINTER as uint8_t;
        return;
    }
    if iface.is_null() {
        csp_dbg_errno = CSP_DBG_ERR_INVALID_POINTER as uint8_t;
        if pxTaskWoken.is_null() {
            csp_buffer_free(packet as *mut ::core::ffi::c_void);
        } else {
            csp_buffer_free_isr(packet as *mut ::core::ffi::c_void);
        }
        return;
    }
    let mut queue_element: csp_qfifo_t = csp_qfifo_t {
        iface: ::core::ptr::null_mut::<csp_iface_t>(),
        packet: ::core::ptr::null_mut::<csp_packet_t>(),
    };
    queue_element.iface = iface;
    queue_element.packet = packet;
    if pxTaskWoken.is_null() {
        result = csp_queue_enqueue(
            qfifo_queue_handle,
            &raw mut queue_element as *const ::core::ffi::c_void,
            1 as uint32_t,
        );
    } else {
        result = csp_queue_enqueue_isr(
            qfifo_queue_handle,
            &raw mut queue_element as *const ::core::ffi::c_void,
            pxTaskWoken as *mut ::core::ffi::c_int,
        );
    }
    if result != CSP_QUEUE_OK {
        csp_dbg_conn_ovf = csp_dbg_conn_ovf.wrapping_add(1);
        (*iface).tx_error = (*iface).tx_error.wrapping_add(1);
        if pxTaskWoken.is_null() {
            csp_buffer_free(packet as *mut ::core::ffi::c_void);
        } else {
            csp_buffer_free_isr(packet as *mut ::core::ffi::c_void);
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn csp_qfifo_wake_up() {
    let queue_element: csp_qfifo_t = csp_qfifo_t {
        iface: ::core::ptr::null_mut::<csp_iface_t>(),
        packet: ::core::ptr::null_mut::<csp_packet_t>(),
    };
    csp_queue_enqueue(
        qfifo_queue_handle,
        &raw const queue_element as *const ::core::ffi::c_void,
        0 as uint32_t,
    );
}
