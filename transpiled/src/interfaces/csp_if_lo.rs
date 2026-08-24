extern "C" {
    pub type csp_conn_s;
    fn csp_qfifo_write(
        packet: *mut csp_packet_t,
        iface: *mut csp_iface_t,
        pxTaskWoken: *mut ::core::ffi::c_void,
    );
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
pub const NULL: *mut ::core::ffi::c_void = ::core::ptr::null_mut::<
    ::core::ffi::c_void,
>();
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_IF_LOOPBACK_NAME: [::core::ffi::c_char; 5] = unsafe {
    ::core::mem::transmute::<[u8; 5], [::core::ffi::c_char; 5]>(*b"LOOP\0")
};
unsafe extern "C" fn csp_lo_tx(
    mut iface: *mut csp_iface_t,
    mut via: uint16_t,
    mut packet: *mut csp_packet_t,
    mut from_me: ::core::ffi::c_int,
) -> ::core::ffi::c_int {
    csp_qfifo_write(packet, &raw mut csp_if_lo, NULL);
    return CSP_ERR_NONE;
}
#[no_mangle]
pub static mut csp_if_lo: csp_iface_t = unsafe {
    csp_iface_s {
        addr: 0 as uint16_t,
        netmask: 0,
        name: CSP_IF_LOOPBACK_NAME.as_ptr(),
        interface_data: ::core::ptr::null::<::core::ffi::c_void>()
            as *mut ::core::ffi::c_void,
        driver_data: ::core::ptr::null::<::core::ffi::c_void>()
            as *mut ::core::ffi::c_void,
        nexthop: Some(
            csp_lo_tx
                as unsafe extern "C" fn(
                    *mut csp_iface_t,
                    uint16_t,
                    *mut csp_packet_t,
                    ::core::ffi::c_int,
                ) -> ::core::ffi::c_int,
        ),
        add_alias: None,
        is_default: 0 as uint8_t,
        tx: 0,
        rx: 0,
        tx_error: 0,
        rx_error: 0,
        drop: 0,
        autherr: 0,
        frame: 0,
        txbytes: 0,
        rxbytes: 0,
        irq: 0,
        next: ::core::ptr::null::<csp_iface_s>() as *mut csp_iface_s,
    }
};
