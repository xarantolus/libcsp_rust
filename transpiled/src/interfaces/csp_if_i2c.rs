extern "C" {
    pub type csp_conn_s;
    fn csp_qfifo_write(
        packet: *mut csp_packet_t,
        iface: *mut csp_iface_t,
        pxTaskWoken: *mut ::core::ffi::c_void,
    );
    fn csp_buffer_free(buffer: *mut ::core::ffi::c_void);
    fn csp_buffer_free_isr(buffer: *mut ::core::ffi::c_void);
    fn csp_iflist_add(iface: *mut csp_iface_t);
    fn csp_id_prepend(packet: *mut csp_packet_t);
    fn csp_id_strip(packet: *mut csp_packet_t) -> ::core::ffi::c_int;
}
pub type __uint8_t = u8;
pub type __uint16_t = u16;
pub type __uint32_t = u32;
pub type __uint64_t = u64;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
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
pub type csp_i2c_driver_tx_t = Option<
    unsafe extern "C" fn(
        *mut ::core::ffi::c_void,
        *mut csp_packet_t,
    ) -> ::core::ffi::c_int,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct csp_i2c_interface_data_t {
    pub tx_func: csp_i2c_driver_tx_t,
}
pub const NULL: *mut ::core::ffi::c_void = ::core::ptr::null_mut::<
    ::core::ffi::c_void,
>();
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ERR_INVAL: ::core::ffi::c_int = -(2 as ::core::ffi::c_int);
pub const CSP_NO_VIA_ADDRESS: ::core::ffi::c_int = 0xffff as ::core::ffi::c_int;
#[no_mangle]
pub unsafe extern "C" fn csp_i2c_tx(
    mut iface: *mut csp_iface_t,
    mut via: uint16_t,
    mut packet: *mut csp_packet_t,
    mut from_me: ::core::ffi::c_int,
) -> ::core::ffi::c_int {
    if (*packet).id.dst as ::core::ffi::c_int == (*iface).addr as ::core::ffi::c_int {
        csp_qfifo_write(packet, iface, NULL);
        return CSP_ERR_NONE;
    }
    csp_id_prepend(packet);
    (*packet).cfpid = (if via as ::core::ffi::c_int != CSP_NO_VIA_ADDRESS {
        via as ::core::ffi::c_int
    } else {
        (*packet).id.dst as ::core::ffi::c_int
    }) as uint32_t;
    (*packet).cfpid = (*packet).cfpid & 0x7f as uint32_t;
    let mut ifdata: *mut csp_i2c_interface_data_t = (*iface).interface_data
        as *mut csp_i2c_interface_data_t;
    return (*ifdata)
        .tx_func
        .expect("non-null function pointer")((*iface).driver_data, packet);
}
#[no_mangle]
pub unsafe extern "C" fn csp_i2c_rx(
    mut iface: *mut csp_iface_t,
    mut packet: *mut csp_packet_t,
    mut pxTaskWoken: *mut ::core::ffi::c_void,
) {
    if packet.is_null() {
        return;
    }
    if ((*packet).frame_length as usize) < ::core::mem::size_of::<uint32_t>() as usize {
        (*iface).frame = (*iface).frame.wrapping_add(1);
        if !pxTaskWoken.is_null() {
            csp_buffer_free_isr(packet as *mut ::core::ffi::c_void);
        } else {
            csp_buffer_free(packet as *mut ::core::ffi::c_void);
        };
        return;
    }
    csp_id_strip(packet);
    csp_qfifo_write(packet, iface, pxTaskWoken);
}
#[no_mangle]
pub unsafe extern "C" fn csp_i2c_add_interface(
    mut iface: *mut csp_iface_t,
) -> ::core::ffi::c_int {
    if iface.is_null() || (*iface).name.is_null() || (*iface).interface_data.is_null() {
        return CSP_ERR_INVAL;
    }
    let mut ifdata: *mut csp_i2c_interface_data_t = (*iface).interface_data
        as *mut csp_i2c_interface_data_t;
    if (*ifdata).tx_func.is_none() {
        return CSP_ERR_INVAL;
    }
    (*iface).nexthop = Some(
        csp_i2c_tx
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
