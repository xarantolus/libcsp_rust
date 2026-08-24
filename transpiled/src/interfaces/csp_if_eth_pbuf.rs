extern "C" {
    pub type csp_conn_s;
    fn csp_buffer_get(unused: size_t) -> *mut csp_packet_t;
    fn csp_buffer_get_isr(unused: size_t) -> *mut csp_packet_t;
    fn csp_buffer_free(buffer: *mut ::core::ffi::c_void);
    fn csp_buffer_free_isr(buffer: *mut ::core::ffi::c_void);
    fn csp_iflist_get_by_addr(addr: uint16_t) -> *mut csp_iface_t;
    fn csp_get_ms() -> uint32_t;
    fn csp_get_ms_isr() -> uint32_t;
    fn csp_buffer_get_always() -> *mut csp_packet_t;
    fn csp_buffer_get_always_isr() -> *mut csp_packet_t;
}
pub type size_t = usize;
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
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct csp_eth_header_s {
    pub ether_dhost: [uint8_t; 6],
    pub ether_shost: [uint8_t; 6],
    pub ether_type: uint16_t,
    pub packet_id: uint16_t,
    pub src_addr: uint16_t,
    pub seg_size: uint16_t,
    pub packet_length: uint16_t,
    pub frame_begin: [uint8_t; 0],
}
pub type csp_eth_header_t = csp_eth_header_s;
pub type csp_eth_driver_tx_t = Option<
    unsafe extern "C" fn(
        *mut ::core::ffi::c_void,
        *mut csp_eth_header_t,
    ) -> ::core::ffi::c_int,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct csp_eth_interface_data_t {
    pub iface: csp_iface_t,
    pub promisc: bool,
    pub tx_mtu: uint16_t,
    pub tx_func: csp_eth_driver_tx_t,
    pub tx_buf: *mut csp_eth_header_t,
    pub pbufs: *mut csp_packet_t,
    pub if_mac: [uint8_t; 6],
}
pub const NULL: *mut ::core::ffi::c_void = ::core::ptr::null_mut::<
    ::core::ffi::c_void,
>();
pub const PBUF_TIMEOUT_MS: ::core::ffi::c_int = 1000 as ::core::ffi::c_int;
#[no_mangle]
pub unsafe extern "C" fn csp_eth_pbuf_free(
    mut ifdata: *mut csp_eth_interface_data_t,
    mut buffer: *mut csp_packet_t,
    mut buf_free: ::core::ffi::c_int,
    mut task_woken: *mut ::core::ffi::c_int,
) {
    let mut packet: *mut csp_packet_t = (*ifdata).pbufs;
    let mut prev: *mut csp_packet_t = ::core::ptr::null_mut::<csp_packet_t>();
    while !packet.is_null() {
        if packet == buffer {
            if !prev.is_null() {
                (*prev).next = (*packet).next;
            } else {
                (*ifdata).pbufs = (*packet).next as *mut csp_packet_t;
            }
            if buf_free != 0 {
                if task_woken.is_null() {
                    csp_buffer_free(packet as *mut ::core::ffi::c_void);
                } else {
                    csp_buffer_free_isr(packet as *mut ::core::ffi::c_void);
                }
            }
            return;
        }
        prev = packet;
        packet = (*packet).next as *mut csp_packet_t;
    }
}
#[no_mangle]
pub unsafe extern "C" fn csp_eth_pbuf_new(
    mut ifdata: *mut csp_eth_interface_data_t,
    mut id: uint32_t,
    mut csp_id: csp_id_t,
    mut now: uint32_t,
    mut task_woken: *mut ::core::ffi::c_int,
) -> *mut csp_packet_t {
    csp_eth_pbuf_cleanup(ifdata, now, task_woken);
    let mut packet: *mut csp_packet_t = ::core::ptr::null_mut::<csp_packet_t>();
    if !csp_iflist_get_by_addr(csp_id.dst).is_null() {
        packet = if !task_woken.is_null() {
            csp_buffer_get_always_isr()
        } else {
            csp_buffer_get_always()
        };
    } else {
        packet = if !task_woken.is_null() {
            csp_buffer_get_isr(0 as size_t)
        } else {
            csp_buffer_get(0 as size_t)
        };
    }
    if packet.is_null() {
        return ::core::ptr::null_mut::<csp_packet_t>();
    }
    (*packet).last_used = now;
    (*packet).cfpid = id;
    (*packet).frame_length = 0 as uint16_t;
    (*packet).next = (*ifdata).pbufs as *mut csp_packet_s;
    (*ifdata).pbufs = packet;
    return packet;
}
#[no_mangle]
pub unsafe extern "C" fn csp_eth_pbuf_cleanup(
    mut ifdata: *mut csp_eth_interface_data_t,
    mut now: uint32_t,
    mut task_woken: *mut ::core::ffi::c_int,
) {
    let mut packet: *mut csp_packet_t = (*ifdata).pbufs;
    let mut prev: *mut csp_packet_t = ::core::ptr::null_mut::<csp_packet_t>();
    while !packet.is_null() {
        let mut next: *mut csp_packet_t = (*packet).next as *mut csp_packet_t;
        if now.wrapping_sub((*packet).last_used) > PBUF_TIMEOUT_MS as uint32_t {
            if !prev.is_null() {
                (*prev).next = next as *mut csp_packet_s;
            } else {
                (*ifdata).pbufs = next;
            }
            if task_woken.is_null() {
                csp_buffer_free(packet as *mut ::core::ffi::c_void);
            } else {
                csp_buffer_free_isr(packet as *mut ::core::ffi::c_void);
            }
            packet = next;
        } else {
            prev = packet;
            packet = next;
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn csp_eth_pbuf_find(
    mut ifdata: *mut csp_eth_interface_data_t,
    mut id: uint32_t,
    mut csp_id: csp_id_t,
    mut task_woken: *mut ::core::ffi::c_int,
) -> *mut csp_packet_t {
    let mut now: uint32_t = if !task_woken.is_null() {
        csp_get_ms_isr()
    } else {
        csp_get_ms()
    };
    let mut packet: *mut csp_packet_t = (*ifdata).pbufs;
    while !packet.is_null() {
        if (*packet).cfpid == id {
            (*packet).last_used = now;
            return packet;
        }
        packet = (*packet).next as *mut csp_packet_t;
    }
    return csp_eth_pbuf_new(ifdata, id, csp_id, now, task_woken);
}
