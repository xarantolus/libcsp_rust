extern "C" {
    pub type csp_conn_s;
    fn csp_qfifo_write(
        packet: *mut csp_packet_t,
        iface: *mut csp_iface_t,
        pxTaskWoken: *mut ::core::ffi::c_void,
    );
    fn csp_usart_lock(driver_data: *mut ::core::ffi::c_void);
    fn csp_usart_unlock(driver_data: *mut ::core::ffi::c_void);
    fn csp_buffer_free(buffer: *mut ::core::ffi::c_void);
    fn csp_iflist_add(iface: *mut csp_iface_t);
    fn csp_crc32_append(packet: *mut csp_packet_t) -> ::core::ffi::c_int;
    fn csp_crc32_verify(packet: *mut csp_packet_t) -> ::core::ffi::c_int;
    fn csp_id_prepend(packet: *mut csp_packet_t);
    fn csp_id_strip(packet: *mut csp_packet_t) -> ::core::ffi::c_int;
    fn csp_id_setup_rx(packet: *mut csp_packet_t) -> ::core::ffi::c_int;
    fn csp_buffer_get_always() -> *mut csp_packet_t;
    fn csp_buffer_get_always_isr() -> *mut csp_packet_t;
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
pub const true_0: ::core::ffi::c_int = 1 as ::core::ffi::c_int;
pub const false_0: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ERR_INVAL: ::core::ffi::c_int = -(2 as ::core::ffi::c_int);
pub const NULL: *mut ::core::ffi::c_void = ::core::ptr::null_mut::<
    ::core::ffi::c_void,
>();
pub const FEND: ::core::ffi::c_int = 0xc0 as ::core::ffi::c_int;
pub const FESC: ::core::ffi::c_int = 0xdb as ::core::ffi::c_int;
pub const TFEND: ::core::ffi::c_int = 0xdc as ::core::ffi::c_int;
pub const TFESC: ::core::ffi::c_int = 0xdd as ::core::ffi::c_int;
pub const TNC_DATA: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
#[no_mangle]
pub unsafe extern "C" fn csp_kiss_tx(
    mut iface: *mut csp_iface_t,
    mut via: uint16_t,
    mut packet: *mut csp_packet_t,
    mut from_me: ::core::ffi::c_int,
) -> ::core::ffi::c_int {
    let mut ifdata: *mut csp_kiss_interface_data_t = (*iface).interface_data
        as *mut csp_kiss_interface_data_t;
    let mut driver: *mut ::core::ffi::c_void = (*iface).driver_data;
    csp_usart_lock(driver);
    csp_crc32_append(packet);
    csp_id_prepend(packet);
    let start: [::core::ffi::c_uchar; 2] = [
        FEND as ::core::ffi::c_uchar,
        TNC_DATA as ::core::ffi::c_uchar,
    ];
    let esc_end: [::core::ffi::c_uchar; 2] = [
        FESC as ::core::ffi::c_uchar,
        TFEND as ::core::ffi::c_uchar,
    ];
    let esc_esc: [::core::ffi::c_uchar; 2] = [
        FESC as ::core::ffi::c_uchar,
        TFESC as ::core::ffi::c_uchar,
    ];
    let mut data: *const ::core::ffi::c_uchar = (*packet).frame_begin;
    (*ifdata)
        .tx_func
        .expect(
            "non-null function pointer",
        )(
        driver,
        &raw const start as *const uint8_t,
        ::core::mem::size_of::<[::core::ffi::c_uchar; 2]>() as size_t,
    );
    let mut i: ::core::ffi::c_uint = 0 as ::core::ffi::c_uint;
    while i < (*packet).frame_length as ::core::ffi::c_uint {
        if *data as ::core::ffi::c_int == FEND {
            (*ifdata)
                .tx_func
                .expect(
                    "non-null function pointer",
                )(
                driver,
                &raw const esc_end as *const uint8_t,
                ::core::mem::size_of::<[::core::ffi::c_uchar; 2]>() as size_t,
            );
        } else if *data as ::core::ffi::c_int == FESC {
            (*ifdata)
                .tx_func
                .expect(
                    "non-null function pointer",
                )(
                driver,
                &raw const esc_esc as *const uint8_t,
                ::core::mem::size_of::<[::core::ffi::c_uchar; 2]>() as size_t,
            );
        } else {
            (*ifdata)
                .tx_func
                .expect(
                    "non-null function pointer",
                )(driver, data as *const uint8_t, 1 as size_t);
        }
        i = i.wrapping_add(1);
        data = data.offset(1);
    }
    let stop: [::core::ffi::c_uchar; 1] = [FEND as ::core::ffi::c_uchar];
    (*ifdata)
        .tx_func
        .expect(
            "non-null function pointer",
        )(
        driver,
        &raw const stop as *const uint8_t,
        ::core::mem::size_of::<[::core::ffi::c_uchar; 1]>() as size_t,
    );
    csp_usart_unlock(driver);
    csp_buffer_free(packet as *mut ::core::ffi::c_void);
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_kiss_rx(
    mut iface: *mut csp_iface_t,
    mut buf: *const uint8_t,
    mut len: size_t,
    mut pxTaskWoken: *mut ::core::ffi::c_void,
) {
    let mut ifdata: *mut csp_kiss_interface_data_t = (*iface).interface_data
        as *mut csp_kiss_interface_data_t;
    loop {
        let fresh0 = len;
        len = len.wrapping_sub(1);
        if !(fresh0 != 0) {
            break;
        }
        let fresh1 = buf;
        buf = buf.offset(1);
        let mut inputbyte: uint8_t = *fresh1;
        if !(*ifdata).rx_packet.is_null()
            && (*(*ifdata).rx_packet).frame_begin.offset((*ifdata).rx_length as isize)
                as *mut uint8_t
                >= (&raw mut (*(*ifdata).rx_packet).c2rust_unnamed.data as *mut uint8_t)
                    .offset(::core::mem::size_of::<[uint8_t; 256]>() as isize)
                    as *mut uint8_t
        {
            (*iface).rx_error = (*iface).rx_error.wrapping_add(1);
            (*ifdata).rx_mode = KISS_MODE_NOT_STARTED;
            (*ifdata).rx_length = 0 as ::core::ffi::c_uint;
        }
        match (*ifdata).rx_mode as ::core::ffi::c_uint {
            0 => {
                if !(inputbyte as ::core::ffi::c_int != FEND) {
                    if (*ifdata).rx_packet.is_null() {
                        (*ifdata).rx_packet = if !pxTaskWoken.is_null() {
                            csp_buffer_get_always_isr()
                        } else {
                            csp_buffer_get_always()
                        };
                    }
                    if (*ifdata).rx_packet.is_null() {
                        (*ifdata).rx_mode = KISS_MODE_SKIP_FRAME;
                        (*iface).drop = (*iface).drop.wrapping_add(1);
                    } else {
                        csp_id_setup_rx((*ifdata).rx_packet);
                        (*ifdata).rx_length = 0 as ::core::ffi::c_uint;
                        (*ifdata).rx_mode = KISS_MODE_STARTED;
                        (*ifdata).rx_first = true_0 != 0;
                    }
                }
            }
            1 => {
                if inputbyte as ::core::ffi::c_int == FESC {
                    (*ifdata).rx_mode = KISS_MODE_ESCAPED;
                } else if (*ifdata).rx_packet.is_null() {
                    (*iface).rx_error = (*iface).rx_error.wrapping_add(1);
                    (*ifdata).rx_mode = KISS_MODE_NOT_STARTED;
                } else if inputbyte as ::core::ffi::c_int == FEND {
                    if (*ifdata).rx_length > 0 as ::core::ffi::c_uint {
                        (*(*ifdata).rx_packet).frame_length = (*ifdata).rx_length
                            as uint16_t;
                        if csp_id_strip((*ifdata).rx_packet) < 0 as ::core::ffi::c_int {
                            (*iface).frame = (*iface).frame.wrapping_add(1);
                            (*ifdata).rx_mode = KISS_MODE_NOT_STARTED;
                        } else if csp_crc32_verify((*ifdata).rx_packet) != CSP_ERR_NONE {
                            (*iface).frame = (*iface).frame.wrapping_add(1);
                            (*ifdata).rx_mode = KISS_MODE_NOT_STARTED;
                        } else {
                            csp_qfifo_write((*ifdata).rx_packet, iface, pxTaskWoken);
                            (*ifdata).rx_packet = ::core::ptr::null_mut::<
                                csp_packet_t,
                            >();
                            (*ifdata).rx_mode = KISS_MODE_NOT_STARTED;
                        }
                    }
                } else if (*ifdata).rx_first {
                    (*ifdata).rx_first = false_0 != 0;
                } else {
                    let fresh2 = (*ifdata).rx_length;
                    (*ifdata).rx_length = (*ifdata).rx_length.wrapping_add(1);
                    *(*(*ifdata).rx_packet).frame_begin.offset(fresh2 as isize) = inputbyte;
                }
            }
            2 => {
                if (*ifdata).rx_packet.is_null() {
                    (*iface).rx_error = (*iface).rx_error.wrapping_add(1);
                    (*ifdata).rx_mode = KISS_MODE_NOT_STARTED;
                } else {
                    if inputbyte as ::core::ffi::c_int == TFESC {
                        let fresh3 = (*ifdata).rx_length;
                        (*ifdata).rx_length = (*ifdata).rx_length.wrapping_add(1);
                        *(*(*ifdata).rx_packet).frame_begin.offset(fresh3 as isize) = FESC
                            as uint8_t;
                    }
                    if inputbyte as ::core::ffi::c_int == TFEND {
                        let fresh4 = (*ifdata).rx_length;
                        (*ifdata).rx_length = (*ifdata).rx_length.wrapping_add(1);
                        *(*(*ifdata).rx_packet).frame_begin.offset(fresh4 as isize) = FEND
                            as uint8_t;
                    }
                    (*ifdata).rx_mode = KISS_MODE_STARTED;
                }
            }
            3 => {
                if inputbyte as ::core::ffi::c_int == FEND {
                    (*ifdata).rx_mode = KISS_MODE_NOT_STARTED;
                }
            }
            _ => {}
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn csp_kiss_add_interface(
    mut iface: *mut csp_iface_t,
) -> ::core::ffi::c_int {
    if iface.is_null() || (*iface).name.is_null() || (*iface).interface_data.is_null() {
        return CSP_ERR_INVAL;
    }
    let mut ifdata: *mut csp_kiss_interface_data_t = (*iface).interface_data
        as *mut csp_kiss_interface_data_t;
    if (*ifdata).tx_func.is_none() {
        return CSP_ERR_INVAL;
    }
    (*ifdata).rx_length = 0 as ::core::ffi::c_uint;
    (*ifdata).rx_mode = KISS_MODE_NOT_STARTED;
    (*ifdata).rx_first = false_0 != 0;
    (*ifdata).rx_packet = ::core::ptr::null_mut::<csp_packet_t>();
    (*iface).nexthop = Some(
        csp_kiss_tx
            as unsafe extern "C" fn(
                *mut csp_iface_t,
                uint16_t,
                *mut csp_packet_t,
                ::core::ffi::c_int,
            ) -> ::core::ffi::c_int,
    ) as nexthop_t;
    csp_iflist_add(iface);
    return CSP_ERR_NONE;
}
