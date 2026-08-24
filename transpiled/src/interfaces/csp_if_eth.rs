extern "C" {
    pub type csp_conn_s;
    fn csp_qfifo_write(
        packet: *mut csp_packet_t,
        iface: *mut csp_iface_t,
        pxTaskWoken: *mut ::core::ffi::c_void,
    );
    fn csp_print_func(fmt: *const ::core::ffi::c_char, ...);
    fn csp_buffer_free(buffer: *mut ::core::ffi::c_void);
    fn csp_buffer_free_isr(buffer: *mut ::core::ffi::c_void);
    fn csp_hex_dump(
        desc: *const ::core::ffi::c_char,
        addr: *const ::core::ffi::c_void,
        len: ::core::ffi::c_int,
    );
    fn csp_eth_pbuf_free(
        ifdata: *mut csp_eth_interface_data_t,
        buffer: *mut csp_packet_t,
        buf_free: ::core::ffi::c_int,
        task_woken: *mut ::core::ffi::c_int,
    );
    fn csp_eth_pbuf_find(
        ifdata: *mut csp_eth_interface_data_t,
        id: uint32_t,
        csp_id: csp_id_t,
        task_woken: *mut ::core::ffi::c_int,
    ) -> *mut csp_packet_t;
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
    fn csp_id_prepend(packet: *mut csp_packet_t);
    fn csp_id_extract(data: *const uint8_t) -> csp_id_t;
    fn csp_id_setup_rx(packet: *mut csp_packet_t) -> ::core::ffi::c_int;
    fn csp_id_get_header_size() -> ::core::ffi::c_int;
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
pub type arp_list_entry_t = arp_list_entry_s;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct arp_list_entry_s {
    pub csp_addr: uint16_t,
    pub mac_addr: [uint8_t; 6],
    pub next: *mut arp_list_entry_s,
}
pub type atomic_int = ::core::ffi::c_int;
pub const NULL: *mut ::core::ffi::c_void = ::core::ptr::null_mut::<
    ::core::ffi::c_void,
>();
pub const true_0: ::core::ffi::c_int = 1 as ::core::ffi::c_int;
pub const false_0: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ERR_INVAL: ::core::ffi::c_int = -(2 as ::core::ffi::c_int);
pub const CSP_ERR_DRIVER: ::core::ffi::c_int = -(11 as ::core::ffi::c_int);
pub const CSP_BUFFER_SIZE: ::core::ffi::c_int = 256 as ::core::ffi::c_int;
pub const CSP_ETH_TYPE_CSP: ::core::ffi::c_int = 0x88b5 as ::core::ffi::c_int;
pub const CSP_ETH_FRAME_SIZE_MAX: ::core::ffi::c_int = 1500 as ::core::ffi::c_int;
pub const CSP_ETH_ALEN: ::core::ffi::c_int = 6 as ::core::ffi::c_int;
#[inline]
unsafe extern "C" fn __bswap_16(mut __bsx: __uint16_t) -> __uint16_t {
    return (__bsx as ::core::ffi::c_int >> 8 as ::core::ffi::c_int
        & 0xff as ::core::ffi::c_int
        | (__bsx as ::core::ffi::c_int & 0xff as ::core::ffi::c_int)
            << 8 as ::core::ffi::c_int) as __uint16_t;
}
#[no_mangle]
pub static mut eth_debug: bool = false_0 != 0;
#[no_mangle]
pub unsafe extern "C" fn csp_eth_pack_header(
    mut buf: *mut csp_eth_header_t,
    mut packet_id: uint16_t,
    mut src_addr: uint16_t,
    mut seg_size: uint16_t,
    mut packet_length: uint16_t,
) -> bool {
    if buf.is_null() {
        return false_0 != 0;
    }
    (*buf).packet_id = __bswap_16(packet_id as __uint16_t) as uint16_t;
    (*buf).src_addr = __bswap_16(src_addr as __uint16_t) as uint16_t;
    (*buf).seg_size = __bswap_16(seg_size as __uint16_t) as uint16_t;
    (*buf).packet_length = __bswap_16(packet_length as __uint16_t) as uint16_t;
    return true_0 != 0;
}
unsafe extern "C" fn csp_if_eth_unpack_header(
    mut buf: *mut csp_eth_header_t,
    mut packet_id: *mut uint32_t,
    mut seg_size: *mut uint16_t,
    mut packet_length: *mut uint16_t,
) -> bool {
    if packet_id.is_null() {
        return false_0 != 0;
    }
    if seg_size.is_null() {
        return false_0 != 0;
    }
    if packet_length.is_null() {
        return false_0 != 0;
    }
    *packet_id = (((*buf).packet_id as ::core::ffi::c_int) << 16 as ::core::ffi::c_int
        | (*buf).src_addr as ::core::ffi::c_int) as uint32_t;
    *seg_size = __bswap_16((*buf).seg_size as __uint16_t) as uint16_t;
    *packet_length = __bswap_16((*buf).packet_length as __uint16_t) as uint16_t;
    return true_0 != 0;
}
pub const ARP_MAX_ENTRIES: ::core::ffi::c_int = 10 as ::core::ffi::c_int;
static mut arp_array: [arp_list_entry_t; 10] = [arp_list_entry_s {
    csp_addr: 0,
    mac_addr: [0; 6],
    next: ::core::ptr::null::<arp_list_entry_s>() as *mut arp_list_entry_s,
}; 10];
static mut arp_used: size_t = 0 as size_t;
static mut arp_list: *mut arp_list_entry_t = ::core::ptr::null::<arp_list_entry_t>()
    as *mut arp_list_entry_t;
unsafe extern "C" fn arp_alloc() -> *mut arp_list_entry_t {
    if arp_used >= ARP_MAX_ENTRIES as size_t {
        return ::core::ptr::null_mut::<arp_list_entry_t>();
    }
    let fresh0 = arp_used;
    arp_used = arp_used.wrapping_add(1);
    return (&raw mut arp_array as *mut arp_list_entry_t).offset(fresh0 as isize)
        as *mut arp_list_entry_t;
}
#[no_mangle]
pub unsafe extern "C" fn csp_eth_arp_set_addr(
    mut mac_addr: *mut uint8_t,
    mut csp_addr: uint16_t,
) {
    let mut last_arp: *mut arp_list_entry_t = ::core::ptr::null_mut::<
        arp_list_entry_t,
    >();
    let mut arp: *mut arp_list_entry_t = arp_list;
    while !arp.is_null() {
        last_arp = arp;
        if (*arp).csp_addr as ::core::ffi::c_int == csp_addr as ::core::ffi::c_int {
            return;
        }
        arp = (*arp).next as *mut arp_list_entry_t;
    }
    let mut new_arp: *mut arp_list_entry_t = arp_alloc();
    if !new_arp.is_null() {
        (*new_arp).csp_addr = csp_addr;
        memcpy(
            &raw mut (*new_arp).mac_addr as *mut uint8_t as *mut ::core::ffi::c_void,
            mac_addr as *const ::core::ffi::c_void,
            CSP_ETH_ALEN as size_t,
        );
        (*new_arp).next = ::core::ptr::null_mut::<arp_list_entry_s>();
        if !last_arp.is_null() {
            (*last_arp).next = new_arp as *mut arp_list_entry_s;
        } else {
            arp_list = new_arp;
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn csp_eth_arp_get_addr(
    mut mac_addr: *mut uint8_t,
    mut csp_addr: uint16_t,
) {
    let mut arp: *mut arp_list_entry_t = arp_list;
    while !arp.is_null() {
        if (*arp).csp_addr as ::core::ffi::c_int == csp_addr as ::core::ffi::c_int {
            memcpy(
                mac_addr as *mut ::core::ffi::c_void,
                &raw mut (*arp).mac_addr as *mut uint8_t as *const ::core::ffi::c_void,
                CSP_ETH_ALEN as size_t,
            );
            return;
        }
        arp = (*arp).next as *mut arp_list_entry_t;
    }
    memset(
        mac_addr as *mut ::core::ffi::c_void,
        0xff as ::core::ffi::c_int,
        CSP_ETH_ALEN as size_t,
    );
}
#[no_mangle]
pub unsafe extern "C" fn csp_eth_rx(
    mut iface: *mut csp_iface_t,
    mut eth_frame: *mut csp_eth_header_t,
    mut received_len: uint32_t,
    mut task_woken: *mut ::core::ffi::c_int,
) -> ::core::ffi::c_int {
    let mut ifdata: *mut csp_eth_interface_data_t = (*iface).interface_data
        as *mut csp_eth_interface_data_t;
    if eth_debug {
        csp_hex_dump(
            b"rx\0" as *const u8 as *const ::core::ffi::c_char,
            eth_frame as *mut ::core::ffi::c_void,
            received_len as ::core::ffi::c_int,
        );
    }
    if __bswap_16((*eth_frame).ether_type as __uint16_t) as ::core::ffi::c_int
        != CSP_ETH_TYPE_CSP
    {
        (*iface).frame = (*iface).frame.wrapping_add(1);
        return CSP_ERR_INVAL;
    }
    if (received_len as usize) < ::core::mem::size_of::<csp_eth_header_t>() as usize {
        (*iface).frame = (*iface).frame.wrapping_add(1);
        return CSP_ERR_INVAL;
    }
    let mut packet_id: uint32_t = 0 as uint32_t;
    let mut seg_size: uint16_t = 0 as uint16_t;
    let mut frame_length: uint16_t = 0 as uint16_t;
    csp_if_eth_unpack_header(
        eth_frame,
        &raw mut packet_id,
        &raw mut seg_size,
        &raw mut frame_length,
    );
    if seg_size as ::core::ffi::c_int == 0 as ::core::ffi::c_int
        || seg_size as ::core::ffi::c_int > CSP_ETH_FRAME_SIZE_MAX
    {
        (*iface).frame = (*iface).frame.wrapping_add(1);
        csp_print_func(
            b"eth rx seg_size of %u bytes is invalid\n\0" as *const u8
                as *const ::core::ffi::c_char,
            seg_size as ::core::ffi::c_uint,
        );
        return CSP_ERR_INVAL;
    }
    if seg_size as ::core::ffi::c_int > frame_length as ::core::ffi::c_int {
        (*iface).frame = (*iface).frame.wrapping_add(1);
        csp_print_func(
            b"eth rx seg_size(%u) > frame_length(%u)\n\0" as *const u8
                as *const ::core::ffi::c_char,
            seg_size as ::core::ffi::c_uint,
            frame_length as ::core::ffi::c_uint,
        );
        return CSP_ERR_INVAL;
    }
    if (::core::mem::size_of::<csp_eth_header_t>() as usize)
        .wrapping_add(seg_size as usize) > received_len as usize
    {
        (*iface).frame = (*iface).frame.wrapping_add(1);
        csp_print_func(
            b"eth rx sizeof(csp_eth_frame_t) + seg_size(%u) > received(%u)\n\0"
                as *const u8 as *const ::core::ffi::c_char,
            seg_size as ::core::ffi::c_uint,
            received_len as ::core::ffi::c_uint,
        );
        return CSP_ERR_INVAL;
    }
    if (frame_length as ::core::ffi::c_int) < csp_id_get_header_size()
        || frame_length as ::core::ffi::c_int
            > CSP_BUFFER_SIZE + csp_id_get_header_size()
    {
        (*iface).frame = (*iface).frame.wrapping_add(1);
        csp_print_func(
            b"eth rx frame_length of %u is invalid\n\0" as *const u8
                as *const ::core::ffi::c_char,
            frame_length as ::core::ffi::c_int,
        );
        return CSP_ERR_INVAL;
    }
    let mut csp_id: csp_id_t = csp_id_extract(
        &raw mut (*eth_frame).frame_begin as *mut uint8_t,
    );
    let mut packet: *mut csp_packet_t = csp_eth_pbuf_find(
        ifdata,
        packet_id,
        csp_id,
        task_woken,
    );
    if packet.is_null() {
        (*iface).drop = (*iface).drop.wrapping_add(1);
        csp_print_func(
            b"eth rx cannot get csp packet\n\0" as *const u8
                as *const ::core::ffi::c_char,
        );
        return CSP_ERR_INVAL;
    }
    if (*packet).frame_length as ::core::ffi::c_int == 0 as ::core::ffi::c_int {
        csp_id_setup_rx(packet);
        (*packet).id = csp_id;
        (*packet).frame_length = frame_length;
        (*packet).rx_count = 0 as uint16_t;
    }
    if frame_length as ::core::ffi::c_int != (*packet).frame_length as ::core::ffi::c_int
    {
        csp_eth_pbuf_free(ifdata, packet, true_0, task_woken);
        (*iface).frame = (*iface).frame.wrapping_add(1);
        csp_print_func(
            b"eth rx inconsistent frame_length\n\0" as *const u8
                as *const ::core::ffi::c_char,
        );
        return CSP_ERR_INVAL;
    }
    if (*packet).rx_count as ::core::ffi::c_int + seg_size as ::core::ffi::c_int
        > (*packet).frame_length as ::core::ffi::c_int
    {
        csp_eth_pbuf_free(ifdata, packet, true_0, task_woken);
        (*iface).frame = (*iface).frame.wrapping_add(1);
        csp_print_func(
            b"eth rx data received exceeds frame_length\n\0" as *const u8
                as *const ::core::ffi::c_char,
        );
        return CSP_ERR_INVAL;
    }
    memcpy(
        (*packet).frame_begin.offset((*packet).rx_count as ::core::ffi::c_int as isize)
            as *mut ::core::ffi::c_void,
        &raw mut (*eth_frame).frame_begin as *mut uint8_t as *const ::core::ffi::c_void,
        seg_size as size_t,
    );
    (*packet).rx_count = ((*packet).rx_count as ::core::ffi::c_int
        + seg_size as ::core::ffi::c_int) as uint16_t;
    if ((*packet).rx_count as ::core::ffi::c_int)
        < (*packet).frame_length as ::core::ffi::c_int
    {
        return CSP_ERR_NONE;
    }
    (*packet).length = ((*packet).frame_length as ::core::ffi::c_int
        - csp_id_get_header_size()) as uint16_t;
    csp_eth_pbuf_free(ifdata, packet, false_0, task_woken);
    csp_eth_arp_set_addr(
        &raw mut (*eth_frame).ether_shost as *mut uint8_t,
        (*packet).id.src,
    );
    if (*packet).id.dst as ::core::ffi::c_int != (*iface).addr as ::core::ffi::c_int
        && !(*ifdata).promisc
    {
        if !task_woken.is_null() {
            csp_buffer_free_isr(packet as *mut ::core::ffi::c_void);
        } else {
            csp_buffer_free(packet as *mut ::core::ffi::c_void);
        };
        return CSP_ERR_NONE;
    }
    csp_qfifo_write(packet, iface, task_woken as *mut ::core::ffi::c_void);
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_eth_tx(
    mut iface: *mut csp_iface_t,
    mut via: uint16_t,
    mut packet: *mut csp_packet_t,
    mut from_me: ::core::ffi::c_int,
) -> ::core::ffi::c_int {
    let mut ifdata: *mut csp_eth_interface_data_t = (*iface).interface_data
        as *mut csp_eth_interface_data_t;
    if (*packet).id.dst as ::core::ffi::c_int == (*iface).addr as ::core::ffi::c_int {
        csp_qfifo_write(packet, iface, NULL);
        return CSP_ERR_NONE;
    }
    csp_id_prepend(packet);
    static mut packet_id: atomic_int = 0 as ::core::ffi::c_int;
    packet_id += 1;
    let mut offset: uint16_t = 0 as uint16_t;
    while (offset as ::core::ffi::c_int) < (*packet).frame_length as ::core::ffi::c_int {
        let mut eth_frame: *mut csp_eth_header_t = (*ifdata).tx_buf;
        let seg_size_max: uint16_t = ((*ifdata).tx_mtu as usize)
            .wrapping_sub(::core::mem::size_of::<csp_eth_header_t>() as usize)
            as uint16_t;
        let mut seg_size: uint16_t = ((*packet).frame_length as ::core::ffi::c_int
            - offset as ::core::ffi::c_int) as uint16_t;
        if seg_size as ::core::ffi::c_int > seg_size_max as ::core::ffi::c_int {
            seg_size = seg_size_max;
        }
        (*eth_frame).ether_type = __bswap_16(0x88b5 as __uint16_t) as uint16_t;
        csp_eth_arp_get_addr(
            &raw mut (*eth_frame).ether_dhost as *mut uint8_t,
            (*packet).id.dst,
        );
        memcpy(
            &raw mut (*eth_frame).ether_shost as *mut uint8_t
                as *mut ::core::ffi::c_void,
            &raw mut (*ifdata).if_mac as *mut uint8_t as *const ::core::ffi::c_void,
            CSP_ETH_ALEN as size_t,
        );
        csp_eth_pack_header(
            eth_frame,
            packet_id as uint16_t,
            (*packet).id.src,
            seg_size,
            (*packet).frame_length,
        );
        memcpy(
            &raw mut (*eth_frame).frame_begin as *mut uint8_t
                as *mut ::core::ffi::c_void,
            (*packet).frame_begin.offset(offset as ::core::ffi::c_int as isize)
                as *const ::core::ffi::c_void,
            seg_size as size_t,
        );
        if (*ifdata)
            .tx_func
            .expect("non-null function pointer")((*iface).driver_data, eth_frame)
            != CSP_ERR_NONE
        {
            (*iface).tx_error = (*iface).tx_error.wrapping_add(1);
            return CSP_ERR_DRIVER;
        }
        if eth_debug {
            csp_hex_dump(
                b"tx\0" as *const u8 as *const ::core::ffi::c_char,
                eth_frame as *const ::core::ffi::c_void,
                (::core::mem::size_of::<csp_eth_header_t>() as usize)
                    .wrapping_add(offset as usize)
                    .wrapping_add(seg_size as usize) as ::core::ffi::c_int,
            );
        }
        offset = (offset as ::core::ffi::c_int + seg_size as ::core::ffi::c_int)
            as uint16_t;
    }
    csp_buffer_free(packet as *mut ::core::ffi::c_void);
    return CSP_ERR_NONE;
}
