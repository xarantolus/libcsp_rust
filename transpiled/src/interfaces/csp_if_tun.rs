extern "C" {
    pub type csp_conn_s;
    fn csp_buffer_get(unused: size_t) -> *mut csp_packet_t;
    fn csp_buffer_free(buffer: *mut ::core::ffi::c_void);
    fn csp_qfifo_write(
        packet: *mut csp_packet_t,
        iface: *mut csp_iface_t,
        pxTaskWoken: *mut ::core::ffi::c_void,
    );
    fn csp_iflist_add(iface: *mut csp_iface_t);
    fn csp_id_prepend(packet: *mut csp_packet_t);
    fn csp_id_strip(packet: *mut csp_packet_t) -> ::core::ffi::c_int;
    fn csp_id_setup_rx(packet: *mut csp_packet_t) -> ::core::ffi::c_int;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct csp_if_tun_conf_t {
    pub tun_src: ::core::ffi::c_int,
    pub tun_dst: ::core::ffi::c_int,
}
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const NULL: *mut ::core::ffi::c_void = ::core::ptr::null_mut::<
    ::core::ffi::c_void,
>();
#[no_mangle]
pub unsafe extern "C" fn csp_crypto_decrypt(
    mut ciphertext_in: *mut uint8_t,
    mut ciphertext_len: uint8_t,
    mut msg_out: *mut uint8_t,
) -> ::core::ffi::c_int {
    return -(1 as ::core::ffi::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn csp_crypto_encrypt(
    mut msg_begin: *mut uint8_t,
    mut msg_len: uint8_t,
    mut ciphertext_out: *mut uint8_t,
) -> ::core::ffi::c_int {
    return -(1 as ::core::ffi::c_int);
}
unsafe extern "C" fn csp_if_tun_tx(
    mut iface: *mut csp_iface_t,
    mut via: uint16_t,
    mut packet: *mut csp_packet_t,
    mut from_me: ::core::ffi::c_int,
) -> ::core::ffi::c_int {
    let mut ifconf: *mut csp_if_tun_conf_t = (*iface).driver_data
        as *mut csp_if_tun_conf_t;
    let mut new_packet: *mut csp_packet_t = csp_buffer_get(0 as size_t);
    if new_packet.is_null() {
        csp_buffer_free(packet as *mut ::core::ffi::c_void);
        return CSP_ERR_NONE;
    }
    if (*packet).id.dst as ::core::ffi::c_int == (*ifconf).tun_src {
        csp_id_setup_rx(new_packet);
        let mut length: ::core::ffi::c_int = csp_crypto_decrypt(
            &raw mut (*packet).c2rust_unnamed.data as *mut uint8_t,
            (*packet).length as uint8_t,
            (*new_packet).frame_begin,
        );
        if length < 0 as ::core::ffi::c_int {
            csp_buffer_free(new_packet as *mut ::core::ffi::c_void);
            csp_buffer_free(packet as *mut ::core::ffi::c_void);
            (*iface).rx_error = (*iface).rx_error.wrapping_add(1);
            return CSP_ERR_NONE;
        } else {
            (*new_packet).frame_length = length as uint16_t;
        }
        csp_buffer_free(packet as *mut ::core::ffi::c_void);
        csp_id_strip(new_packet);
        csp_qfifo_write(new_packet, iface, NULL);
    } else {
        csp_id_prepend(packet);
        (*new_packet).id.dst = (*ifconf).tun_dst as uint16_t;
        (*new_packet).id.src = (*ifconf).tun_src as uint16_t;
        (*new_packet).id.sport = 0 as uint8_t;
        (*new_packet).id.dport = 0 as uint8_t;
        (*new_packet).id.pri = (*packet).id.pri;
        (*new_packet).length = (*packet).frame_length;
        (*new_packet).length = csp_crypto_encrypt(
            (*packet).frame_begin,
            (*packet).frame_length as uint8_t,
            &raw mut (*new_packet).c2rust_unnamed.data as *mut uint8_t,
        ) as uint16_t;
        csp_buffer_free(packet as *mut ::core::ffi::c_void);
        csp_id_prepend(new_packet);
        csp_qfifo_write(new_packet, iface, NULL);
    }
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_if_tun_init(
    mut iface: *mut csp_iface_t,
    mut ifconf: *mut csp_if_tun_conf_t,
) {
    (*iface).driver_data = ifconf as *mut ::core::ffi::c_void;
    (*iface).name = b"TUN\0" as *const u8 as *const ::core::ffi::c_char;
    (*iface).nexthop = Some(
        csp_if_tun_tx
            as unsafe extern "C" fn(
                *mut csp_iface_t,
                uint16_t,
                *mut csp_packet_t,
                ::core::ffi::c_int,
            ) -> ::core::ffi::c_int,
    ) as nexthop_t;
    csp_iflist_add(iface);
}
