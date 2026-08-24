extern "C" {
    pub type csp_conn_s;
    fn csp_kiss_add_interface(iface: *mut csp_iface_t) -> ::core::ffi::c_int;
    fn csp_kiss_rx(
        iface: *mut csp_iface_t,
        buf: *const uint8_t,
        len: size_t,
        pxTaskWoken: *mut ::core::ffi::c_void,
    );
    fn calloc(__nmemb: size_t, __size: size_t) -> *mut ::core::ffi::c_void;
    fn strncpy(
        __dest: *mut ::core::ffi::c_char,
        __src: *const ::core::ffi::c_char,
        __n: size_t,
    ) -> *mut ::core::ffi::c_char;
    fn csp_usart_open(
        conf: *const csp_usart_conf_t,
        rx_callback: csp_usart_callback_t,
        user_data: *mut ::core::ffi::c_void,
        fd: *mut csp_usart_fd_t,
    ) -> ::core::ffi::c_int;
    fn csp_usart_write(
        fd: csp_usart_fd_t,
        data: *const ::core::ffi::c_void,
        data_length: size_t,
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
pub type csp_kiss_driver_tx_t = Option<
    unsafe extern "C" fn(
        *mut ::core::ffi::c_void,
        *const uint8_t,
        size_t,
    ) -> ::core::ffi::c_int,
>;
pub type csp_kiss_mode_t = ::core::ffi::c_uint;
pub const KISS_MODE_SKIP_FRAME: csp_kiss_mode_t = 3;
pub const KISS_MODE_ESCAPED: csp_kiss_mode_t = 2;
pub const KISS_MODE_STARTED: csp_kiss_mode_t = 1;
pub const KISS_MODE_NOT_STARTED: csp_kiss_mode_t = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct csp_kiss_interface_data_t {
    pub tx_func: csp_kiss_driver_tx_t,
    pub rx_mode: csp_kiss_mode_t,
    pub rx_length: ::core::ffi::c_uint,
    pub rx_first: bool,
    pub rx_packet: *mut csp_packet_t,
}
pub type csp_usart_fd_t = ::core::ffi::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct csp_usart_conf {
    pub device: *const ::core::ffi::c_char,
    pub baudrate: uint32_t,
    pub databits: uint8_t,
    pub stopbits: uint8_t,
    pub paritysetting: uint8_t,
}
pub type csp_usart_conf_t = csp_usart_conf;
pub type csp_usart_callback_t = Option<
    unsafe extern "C" fn(
        *mut ::core::ffi::c_void,
        *mut uint8_t,
        size_t,
        *mut ::core::ffi::c_void,
    ) -> (),
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct kiss_context_t {
    pub name: [::core::ffi::c_char; 11],
    pub iface: csp_iface_t,
    pub ifdata: csp_kiss_interface_data_t,
    pub fd: csp_usart_fd_t,
}
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ERR_NOMEM: ::core::ffi::c_int = -(1 as ::core::ffi::c_int);
pub const CSP_ERR_TX: ::core::ffi::c_int = -(10 as ::core::ffi::c_int);
pub const CSP_IF_KISS_DEFAULT_NAME: [::core::ffi::c_char; 5] = unsafe {
    ::core::mem::transmute::<[u8; 5], [::core::ffi::c_char; 5]>(*b"KISS\0")
};
pub const NULL: *mut ::core::ffi::c_void = ::core::ptr::null_mut::<
    ::core::ffi::c_void,
>();
unsafe extern "C" fn kiss_driver_tx(
    mut driver_data: *mut ::core::ffi::c_void,
    mut data: *const ::core::ffi::c_uchar,
    mut data_length: size_t,
) -> ::core::ffi::c_int {
    let mut ctx: *mut kiss_context_t = driver_data as *mut kiss_context_t;
    if csp_usart_write((*ctx).fd, data as *const ::core::ffi::c_void, data_length)
        == data_length as ::core::ffi::c_int
    {
        return CSP_ERR_NONE;
    }
    return CSP_ERR_TX;
}
unsafe extern "C" fn kiss_driver_rx(
    mut user_data: *mut ::core::ffi::c_void,
    mut data: *mut uint8_t,
    mut data_size: size_t,
    mut pxTaskWoken: *mut ::core::ffi::c_void,
) {
    let mut ctx: *mut kiss_context_t = user_data as *mut kiss_context_t;
    csp_kiss_rx(&raw mut (*ctx).iface, data, data_size, pxTaskWoken);
}
#[no_mangle]
pub unsafe extern "C" fn csp_usart_open_and_add_kiss_interface(
    mut conf: *const csp_usart_conf_t,
    mut ifname: *const ::core::ffi::c_char,
    mut addr: uint16_t,
    mut return_iface: *mut *mut csp_iface_t,
) -> ::core::ffi::c_int {
    if ifname.is_null() {
        ifname = CSP_IF_KISS_DEFAULT_NAME.as_ptr();
    }
    let mut ctx: *mut kiss_context_t = calloc(
        1 as size_t,
        ::core::mem::size_of::<kiss_context_t>() as size_t,
    ) as *mut kiss_context_t;
    if ctx.is_null() {
        return CSP_ERR_NOMEM;
    }
    strncpy(
        &raw mut (*ctx).name as *mut ::core::ffi::c_char,
        ifname,
        (::core::mem::size_of::<[::core::ffi::c_char; 11]>() as size_t)
            .wrapping_sub(1 as size_t),
    );
    (*ctx).iface.name = &raw mut (*ctx).name as *mut ::core::ffi::c_char;
    (*ctx).iface.addr = addr;
    (*ctx).iface.driver_data = ctx as *mut ::core::ffi::c_void;
    (*ctx).iface.interface_data = &raw mut (*ctx).ifdata as *mut ::core::ffi::c_void;
    (*ctx).ifdata.tx_func = Some(
        kiss_driver_tx
            as unsafe extern "C" fn(
                *mut ::core::ffi::c_void,
                *const ::core::ffi::c_uchar,
                size_t,
            ) -> ::core::ffi::c_int,
    ) as csp_kiss_driver_tx_t;
    (*ctx).fd = -(1 as ::core::ffi::c_int) as csp_usart_fd_t;
    let mut res: ::core::ffi::c_int = csp_kiss_add_interface(&raw mut (*ctx).iface);
    if res == CSP_ERR_NONE {
        res = csp_usart_open(
            conf,
            Some(
                kiss_driver_rx
                    as unsafe extern "C" fn(
                        *mut ::core::ffi::c_void,
                        *mut uint8_t,
                        size_t,
                        *mut ::core::ffi::c_void,
                    ) -> (),
            ),
            ctx as *mut ::core::ffi::c_void,
            &raw mut (*ctx).fd,
        );
    }
    if !return_iface.is_null() {
        *return_iface = &raw mut (*ctx).iface;
    }
    return res;
}
