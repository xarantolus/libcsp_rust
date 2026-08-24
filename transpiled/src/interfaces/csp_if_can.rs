extern "C" {
    pub type csp_conn_s;
    fn csp_qfifo_write(
        packet: *mut csp_packet_t,
        iface: *mut csp_iface_t,
        pxTaskWoken: *mut ::core::ffi::c_void,
    );
    fn memcpy(
        __dest: *mut ::core::ffi::c_void,
        __src: *const ::core::ffi::c_void,
        __n: size_t,
    ) -> *mut ::core::ffi::c_void;
    static mut csp_dbg_can_errno: uint8_t;
    fn csp_buffer_free(buffer: *mut ::core::ffi::c_void);
    fn csp_iflist_add(iface: *mut csp_iface_t);
    fn csp_iflist_remove(ifc: *mut csp_iface_t);
    fn csp_addr_is_alias(addr: uint16_t) -> ::core::ffi::c_int;
    static mut csp_conf: csp_conf_t;
    fn csp_id_prepend(packet: *mut csp_packet_t);
    fn csp_id_extract(data: *const uint8_t) -> csp_id_t;
    fn csp_id_strip(packet: *mut csp_packet_t) -> ::core::ffi::c_int;
    fn csp_id_setup_rx(packet: *mut csp_packet_t) -> ::core::ffi::c_int;
    fn csp_id_get_header_size() -> ::core::ffi::c_int;
    fn csp_can_pbuf_free(
        ifdata: *mut csp_can_interface_data_t,
        buffer: *mut csp_packet_t,
        buf_free: ::core::ffi::c_int,
        task_woken: *mut ::core::ffi::c_int,
    );
    fn csp_can_pbuf_new(
        ifdata: *mut csp_can_interface_data_t,
        id: uint32_t,
        csp_id: csp_id_t,
        task_woken: *mut ::core::ffi::c_int,
    ) -> *mut csp_packet_t;
    fn csp_can_pbuf_find(
        ifdata: *mut csp_can_interface_data_t,
        id: uint32_t,
        mask: uint32_t,
        task_woken: *mut ::core::ffi::c_int,
    ) -> *mut csp_packet_t;
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
pub type atomic_int = ::core::ffi::c_int;
pub type csp_can_driver_tx_t = Option<
    unsafe extern "C" fn(
        *mut ::core::ffi::c_void,
        uint32_t,
        *const uint8_t,
        uint8_t,
        *const csp_packet_t,
    ) -> ::core::ffi::c_int,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct csp_can_interface_data_t {
    pub cfp_packet_counter: atomic_int,
    pub tx_func: csp_can_driver_tx_t,
    pub pbufs: *mut csp_packet_t,
}
pub const CFP_MORE: cfp_frame_t = 1;
pub const CFP_BEGIN: cfp_frame_t = 0;
pub type csp_conf_t = csp_conf_s;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct csp_conf_s {
    pub version: uint8_t,
    pub hostname: *const ::core::ffi::c_char,
    pub model: *const ::core::ffi::c_char,
    pub revision: *const ::core::ffi::c_char,
    pub conn_dfl_so: uint32_t,
    pub dedup: uint8_t,
}
pub type cfp_frame_t = ::core::ffi::c_uint;
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ERR_INVAL: ::core::ffi::c_int = -(2 as ::core::ffi::c_int);
pub const CSP_ERR_NOBUFS: ::core::ffi::c_int = -(9 as ::core::ffi::c_int);
pub const CSP_ERR_DRIVER: ::core::ffi::c_int = -(11 as ::core::ffi::c_int);
pub const NULL: *mut ::core::ffi::c_void = ::core::ptr::null_mut::<
    ::core::ffi::c_void,
>();
pub const CFP_ID_CONN_MASK: uint32_t = ((((1 as ::core::ffi::c_int)
    << 5 as ::core::ffi::c_int) as uint32_t)
    .wrapping_sub(1 as uint32_t)
    & (((1 as ::core::ffi::c_int) << 5 as ::core::ffi::c_int) as uint32_t)
        .wrapping_sub(1 as uint32_t))
    << 5 as ::core::ffi::c_int + 1 as ::core::ffi::c_int + 8 as ::core::ffi::c_int
        + 10 as ::core::ffi::c_int
    | ((((1 as ::core::ffi::c_int) << 5 as ::core::ffi::c_int) as uint32_t)
        .wrapping_sub(1 as uint32_t)
        & (((1 as ::core::ffi::c_int) << 5 as ::core::ffi::c_int) as uint32_t)
            .wrapping_sub(1 as uint32_t))
        << 1 as ::core::ffi::c_int + 8 as ::core::ffi::c_int + 10 as ::core::ffi::c_int
    | ((((1 as ::core::ffi::c_int) << 10 as ::core::ffi::c_int) as uint32_t)
        .wrapping_sub(1 as uint32_t)
        & (((1 as ::core::ffi::c_int) << 10 as ::core::ffi::c_int) as uint32_t)
            .wrapping_sub(1 as uint32_t)) << 0 as ::core::ffi::c_int;
pub const CFP2_PRIO_MASK: ::core::ffi::c_int = 0x3 as ::core::ffi::c_int;
pub const CFP2_PRIO_OFFSET: ::core::ffi::c_int = 27 as ::core::ffi::c_int;
pub const CFP2_DST_MASK: ::core::ffi::c_int = 0x3fff as ::core::ffi::c_int;
pub const CFP2_DST_OFFSET: ::core::ffi::c_int = 13 as ::core::ffi::c_int;
pub const CFP2_SENDER_MASK: ::core::ffi::c_int = 0x3f as ::core::ffi::c_int;
pub const CFP2_SENDER_OFFSET: ::core::ffi::c_int = 7 as ::core::ffi::c_int;
pub const CFP2_SC_MASK: ::core::ffi::c_int = 0x3 as ::core::ffi::c_int;
pub const CFP2_SC_OFFSET: ::core::ffi::c_int = 5 as ::core::ffi::c_int;
pub const CFP2_FC_MASK: ::core::ffi::c_int = 0x7 as ::core::ffi::c_int;
pub const CFP2_FC_OFFSET: ::core::ffi::c_int = 2 as ::core::ffi::c_int;
pub const CFP2_BEGIN_MASK: ::core::ffi::c_int = 0x1 as ::core::ffi::c_int;
pub const CFP2_BEGIN_OFFSET: ::core::ffi::c_int = 1 as ::core::ffi::c_int;
pub const CFP2_END_MASK: ::core::ffi::c_int = 0x1 as ::core::ffi::c_int;
pub const CFP2_END_OFFSET: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CFP2_SRC_MASK: ::core::ffi::c_int = 0x3fff as ::core::ffi::c_int;
pub const CFP2_SRC_OFFSET: ::core::ffi::c_int = 18 as ::core::ffi::c_int;
pub const CFP2_DPORT_MASK: ::core::ffi::c_int = 0x3f as ::core::ffi::c_int;
pub const CFP2_DPORT_OFFSET: ::core::ffi::c_int = 12 as ::core::ffi::c_int;
pub const CFP2_SPORT_MASK: ::core::ffi::c_int = 0x3f as ::core::ffi::c_int;
pub const CFP2_SPORT_OFFSET: ::core::ffi::c_int = 6 as ::core::ffi::c_int;
pub const CFP2_FLAGS_MASK: ::core::ffi::c_int = 0x3f as ::core::ffi::c_int;
pub const CFP2_FLAGS_OFFSET: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CFP2_ID_CONN_MASK: ::core::ffi::c_int = CFP2_DST_MASK << CFP2_DST_OFFSET
    | CFP2_SENDER_MASK << CFP2_SENDER_OFFSET | CFP2_PRIO_MASK << CFP2_PRIO_OFFSET
    | CFP2_SC_MASK << CFP2_SC_OFFSET;
#[inline]
unsafe extern "C" fn __bswap_16(mut __bsx: __uint16_t) -> __uint16_t {
    return (__bsx as ::core::ffi::c_int >> 8 as ::core::ffi::c_int
        & 0xff as ::core::ffi::c_int
        | (__bsx as ::core::ffi::c_int & 0xff as ::core::ffi::c_int)
            << 8 as ::core::ffi::c_int) as __uint16_t;
}
#[inline]
unsafe extern "C" fn __bswap_32(mut __bsx: __uint32_t) -> __uint32_t {
    return (__bsx & 0xff000000 as __uint32_t) >> 24 as ::core::ffi::c_int
        | (__bsx & 0xff0000 as __uint32_t) >> 8 as ::core::ffi::c_int
        | (__bsx & 0xff00 as __uint32_t) << 8 as ::core::ffi::c_int
        | (__bsx & 0xff as __uint32_t) << 24 as ::core::ffi::c_int;
}
pub const CSP_DBG_CAN_ERR_FRAME_LOST: ::core::ffi::c_int = 1 as ::core::ffi::c_int;
pub const CSP_DBG_CAN_ERR_RX_OVF: ::core::ffi::c_int = 2 as ::core::ffi::c_int;
pub const CSP_DBG_CAN_ERR_SHORT_BEGIN: ::core::ffi::c_int = 4 as ::core::ffi::c_int;
pub const CSP_DBG_CAN_ERR_UNKNOWN: ::core::ffi::c_int = 6 as ::core::ffi::c_int;
pub const CSP_NO_VIA_ADDRESS: ::core::ffi::c_int = 0xffff as ::core::ffi::c_int;
pub const CAN_FRAME_SIZE: ::core::ffi::c_int = 8 as ::core::ffi::c_int;
pub const CFP1_CSP_HEADER_OFFSET: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CFP1_CSP_HEADER_SIZE: ::core::ffi::c_int = 4 as ::core::ffi::c_int;
pub const CFP1_DATA_LEN_OFFSET: ::core::ffi::c_int = 4 as ::core::ffi::c_int;
pub const CFP1_DATA_LEN_SIZE: ::core::ffi::c_int = 2 as ::core::ffi::c_int;
pub const CFP1_DATA_OFFSET: ::core::ffi::c_int = 6 as ::core::ffi::c_int;
pub const CFP1_DATA_SIZE_BEGIN: ::core::ffi::c_int = 2 as ::core::ffi::c_int;
unsafe extern "C" fn csp_can1_rx(
    mut iface: *mut csp_iface_t,
    mut id: uint32_t,
    mut data: *const uint8_t,
    mut dlc: uint8_t,
    mut task_woken: *mut ::core::ffi::c_int,
) -> ::core::ffi::c_int {
    let mut ifdata: *mut csp_can_interface_data_t = (*iface).interface_data
        as *mut csp_can_interface_data_t;
    let mut packet: *mut csp_packet_t = csp_can_pbuf_find(
        ifdata,
        id,
        CFP_ID_CONN_MASK,
        task_woken,
    );
    if packet.is_null() {
        if id >> 8 as ::core::ffi::c_int + 10 as ::core::ffi::c_int
            & (((1 as ::core::ffi::c_int) << 1 as ::core::ffi::c_int)
                - 1 as ::core::ffi::c_int) as uint32_t
            == CFP_BEGIN as ::core::ffi::c_int as uint32_t
        {
            let mut header: [uint8_t; 4] = [0; 4];
            memcpy(
                &raw mut header as *mut uint8_t as *mut ::core::ffi::c_void,
                data as *const ::core::ffi::c_void,
                CFP1_CSP_HEADER_SIZE as size_t,
            );
            let mut csp_id: csp_id_t = csp_id_extract(&raw mut header as *mut uint8_t);
            packet = csp_can_pbuf_new(ifdata, id, csp_id, task_woken);
            if packet.is_null() {
                (*iface).drop = (*iface).drop.wrapping_add(1);
                return CSP_ERR_NOBUFS;
            }
            csp_id_setup_rx(packet);
            (*packet).id = csp_id;
            memcpy(
                (*packet).frame_begin as *mut ::core::ffi::c_void,
                data as *const ::core::ffi::c_void,
                CFP1_CSP_HEADER_SIZE as size_t,
            );
            (*packet).frame_length = ((*packet).frame_length as ::core::ffi::c_int
                + CFP1_CSP_HEADER_SIZE) as uint16_t;
        } else {
            (*iface).frame = (*iface).frame.wrapping_add(1);
            return CSP_ERR_INVAL;
        }
    }
    let mut offset: uint8_t = 0 as uint8_t;
    let mut length: uint16_t = 0;
    let mut current_block_44: u64;
    match id >> 8 as ::core::ffi::c_int + 10 as ::core::ffi::c_int
        & (((1 as ::core::ffi::c_int) << 1 as ::core::ffi::c_int)
            - 1 as ::core::ffi::c_int) as uint32_t
    {
        0 => {
            if (dlc as ::core::ffi::c_int) < CFP1_DATA_OFFSET {
                csp_dbg_can_errno = CSP_DBG_CAN_ERR_SHORT_BEGIN as uint8_t;
                (*iface).frame = (*iface).frame.wrapping_add(1);
                csp_can_pbuf_free(ifdata, packet, 1 as ::core::ffi::c_int, task_woken);
                current_block_44 = 3934796541983872331;
            } else {
                memcpy(
                    &raw mut (*packet).length as *mut ::core::ffi::c_void,
                    data.offset(CFP1_CSP_HEADER_SIZE as isize)
                        as *const ::core::ffi::c_void,
                    CFP1_DATA_LEN_SIZE as size_t,
                );
                (*packet).length = __bswap_16((*packet).length as __uint16_t)
                    as uint16_t;
                if (*packet).length as usize
                    > ::core::mem::size_of::<[uint8_t; 256]>() as usize
                {
                    (*iface).rx_error = (*iface).rx_error.wrapping_add(1);
                    csp_can_pbuf_free(
                        ifdata,
                        packet,
                        1 as ::core::ffi::c_int,
                        task_woken,
                    );
                    current_block_44 = 3934796541983872331;
                } else {
                    (*packet).rx_count = 0 as uint16_t;
                    offset = CFP1_DATA_OFFSET as uint8_t;
                    (*packet).remain = (id >> 10 as ::core::ffi::c_int
                        & (((1 as ::core::ffi::c_int) << 8 as ::core::ffi::c_int)
                            - 1 as ::core::ffi::c_int) as uint32_t)
                        .wrapping_add(1 as uint32_t) as uint16_t;
                    current_block_44 = 18162416701281615212;
                }
            }
        }
        1 => {
            current_block_44 = 18162416701281615212;
        }
        _ => {
            csp_dbg_can_errno = CSP_DBG_CAN_ERR_UNKNOWN as uint8_t;
            csp_can_pbuf_free(ifdata, packet, 1 as ::core::ffi::c_int, task_woken);
            current_block_44 = 3934796541983872331;
        }
    }
    match current_block_44 {
        18162416701281615212 => {
            if (id >> 10 as ::core::ffi::c_int
                & (((1 as ::core::ffi::c_int) << 8 as ::core::ffi::c_int)
                    - 1 as ::core::ffi::c_int) as uint32_t) as uint16_t
                as ::core::ffi::c_int
                != (*packet).remain as ::core::ffi::c_int - 1 as ::core::ffi::c_int
            {
                csp_dbg_can_errno = CSP_DBG_CAN_ERR_FRAME_LOST as uint8_t;
                csp_can_pbuf_free(ifdata, packet, 1 as ::core::ffi::c_int, task_woken);
                (*iface).frame = (*iface).frame.wrapping_add(1);
            } else {
                (*packet).remain = (*packet).remain.wrapping_sub(1);
                if (*packet).rx_count as ::core::ffi::c_int + dlc as ::core::ffi::c_int
                    - offset as ::core::ffi::c_int
                    > (*packet).length as ::core::ffi::c_int
                {
                    csp_dbg_can_errno = CSP_DBG_CAN_ERR_RX_OVF as uint8_t;
                    (*iface).frame = (*iface).frame.wrapping_add(1);
                    csp_can_pbuf_free(
                        ifdata,
                        packet,
                        1 as ::core::ffi::c_int,
                        task_woken,
                    );
                } else {
                    memcpy(
                        (&raw mut (*packet).c2rust_unnamed.data as *mut uint8_t)
                            .offset((*packet).rx_count as isize) as *mut uint8_t
                            as *mut ::core::ffi::c_void,
                        data.offset(offset as ::core::ffi::c_int as isize)
                            as *const ::core::ffi::c_void,
                        (dlc as ::core::ffi::c_int - offset as ::core::ffi::c_int)
                            as size_t,
                    );
                    (*packet).rx_count = ((*packet).rx_count as ::core::ffi::c_int
                        + (dlc as ::core::ffi::c_int - offset as ::core::ffi::c_int))
                        as uint16_t;
                    if !((*packet).rx_count as ::core::ffi::c_int
                        != (*packet).length as ::core::ffi::c_int)
                    {
                        length = (*packet).length;
                        csp_id_strip(packet);
                        (*packet).length = length;
                        if (*packet).id.dst as ::core::ffi::c_int
                            == 0x1f as ::core::ffi::c_int
                        {
                            (*packet).id.dst = (*iface).addr;
                        }
                        csp_can_pbuf_free(
                            ifdata,
                            packet,
                            0 as ::core::ffi::c_int,
                            task_woken,
                        );
                        csp_qfifo_write(
                            packet,
                            iface,
                            task_woken as *mut ::core::ffi::c_void,
                        );
                    }
                }
            }
        }
        _ => {}
    }
    return CSP_ERR_NONE;
}
unsafe extern "C" fn csp_can1_tx(
    mut iface: *mut csp_iface_t,
    mut via: uint16_t,
    mut packet: *mut csp_packet_t,
    mut from_me: ::core::ffi::c_int,
) -> ::core::ffi::c_int {
    if (*packet).id.dst as ::core::ffi::c_int == (*iface).addr as ::core::ffi::c_int {
        csp_qfifo_write(packet, iface, NULL);
        return CSP_ERR_NONE;
    }
    let mut ifdata: *mut csp_can_interface_data_t = (*iface).interface_data
        as *mut csp_can_interface_data_t;
    let fresh2 = (*ifdata).cfp_packet_counter;
    (*ifdata).cfp_packet_counter = (*ifdata).cfp_packet_counter + 1;
    let ident: uint32_t = fresh2 as uint32_t;
    let dest: uint8_t = (if via as ::core::ffi::c_int != CSP_NO_VIA_ADDRESS {
        via as ::core::ffi::c_int
    } else {
        (*packet).id.dst as ::core::ffi::c_int
    }) as uint8_t;
    let mut can_id: uint32_t = 0 as uint32_t;
    let mut data_bytes: uint8_t = 0 as uint8_t;
    let mut frame_buf: [uint8_t; 8] = [0; 8];
    can_id = ((*packet).id.src as uint32_t
        & (((1 as ::core::ffi::c_int) << 5 as ::core::ffi::c_int) as uint32_t)
            .wrapping_sub(1 as uint32_t))
        << 5 as ::core::ffi::c_int + 1 as ::core::ffi::c_int + 8 as ::core::ffi::c_int
            + 10 as ::core::ffi::c_int
        | (dest as uint32_t
            & (((1 as ::core::ffi::c_int) << 5 as ::core::ffi::c_int) as uint32_t)
                .wrapping_sub(1 as uint32_t))
            << 1 as ::core::ffi::c_int + 8 as ::core::ffi::c_int
                + 10 as ::core::ffi::c_int
        | (ident
            & (((1 as ::core::ffi::c_int) << 10 as ::core::ffi::c_int) as uint32_t)
                .wrapping_sub(1 as uint32_t)) << 0 as ::core::ffi::c_int
        | (CFP_BEGIN as ::core::ffi::c_int as uint32_t
            & (((1 as ::core::ffi::c_int) << 1 as ::core::ffi::c_int) as uint32_t)
                .wrapping_sub(1 as uint32_t))
            << 8 as ::core::ffi::c_int + 10 as ::core::ffi::c_int
        | ((((*packet).length as ::core::ffi::c_int + 6 as ::core::ffi::c_int
            - 1 as ::core::ffi::c_int) / 8 as ::core::ffi::c_int) as uint32_t
            & (((1 as ::core::ffi::c_int) << 8 as ::core::ffi::c_int) as uint32_t)
                .wrapping_sub(1 as uint32_t)) << 10 as ::core::ffi::c_int;
    csp_id_prepend(packet);
    memcpy(
        (&raw mut frame_buf as *mut uint8_t).offset(CFP1_CSP_HEADER_OFFSET as isize)
            as *mut ::core::ffi::c_void,
        (*packet).frame_begin as *const ::core::ffi::c_void,
        CFP1_CSP_HEADER_SIZE as size_t,
    );
    let mut csp_length_be: uint16_t = __bswap_16((*packet).length as __uint16_t)
        as uint16_t;
    memcpy(
        (&raw mut frame_buf as *mut uint8_t).offset(CFP1_DATA_LEN_OFFSET as isize)
            as *mut ::core::ffi::c_void,
        &raw mut csp_length_be as *const ::core::ffi::c_void,
        CFP1_DATA_LEN_SIZE as size_t,
    );
    data_bytes = (if (*packet).length as ::core::ffi::c_int <= CFP1_DATA_SIZE_BEGIN {
        (*packet).length as ::core::ffi::c_int
    } else {
        CFP1_DATA_SIZE_BEGIN
    }) as uint8_t;
    memcpy(
        (&raw mut frame_buf as *mut uint8_t).offset(CFP1_DATA_OFFSET as isize)
            as *mut ::core::ffi::c_void,
        &raw mut (*packet).c2rust_unnamed.data as *mut uint8_t
            as *const ::core::ffi::c_void,
        data_bytes as size_t,
    );
    let mut tx_count: uint16_t = data_bytes as uint16_t;
    let tx_func: csp_can_driver_tx_t = (*ifdata).tx_func;
    if tx_func
        .expect(
            "non-null function pointer",
        )(
        (*iface).driver_data,
        can_id,
        &raw mut frame_buf as *mut uint8_t,
        (CFP1_DATA_OFFSET + data_bytes as ::core::ffi::c_int) as uint8_t,
        ::core::ptr::null::<csp_packet_t>(),
    ) != CSP_ERR_NONE
    {
        (*iface).tx_error = (*iface).tx_error.wrapping_add(1);
        return CSP_ERR_DRIVER;
    }
    while (tx_count as ::core::ffi::c_int) < (*packet).length as ::core::ffi::c_int {
        data_bytes = (if (*packet).length as ::core::ffi::c_int
            - tx_count as ::core::ffi::c_int >= CAN_FRAME_SIZE
        {
            CAN_FRAME_SIZE
        } else {
            (*packet).length as ::core::ffi::c_int - tx_count as ::core::ffi::c_int
        }) as uint8_t;
        can_id = ((*packet).id.src as uint32_t
            & (((1 as ::core::ffi::c_int) << 5 as ::core::ffi::c_int) as uint32_t)
                .wrapping_sub(1 as uint32_t))
            << 5 as ::core::ffi::c_int + 1 as ::core::ffi::c_int
                + 8 as ::core::ffi::c_int + 10 as ::core::ffi::c_int
            | (dest as uint32_t
                & (((1 as ::core::ffi::c_int) << 5 as ::core::ffi::c_int) as uint32_t)
                    .wrapping_sub(1 as uint32_t))
                << 1 as ::core::ffi::c_int + 8 as ::core::ffi::c_int
                    + 10 as ::core::ffi::c_int
            | (ident
                & (((1 as ::core::ffi::c_int) << 10 as ::core::ffi::c_int) as uint32_t)
                    .wrapping_sub(1 as uint32_t)) << 0 as ::core::ffi::c_int
            | (CFP_MORE as ::core::ffi::c_int as uint32_t
                & (((1 as ::core::ffi::c_int) << 1 as ::core::ffi::c_int) as uint32_t)
                    .wrapping_sub(1 as uint32_t))
                << 8 as ::core::ffi::c_int + 10 as ::core::ffi::c_int
            | ((((*packet).length as ::core::ffi::c_int - tx_count as ::core::ffi::c_int
                - data_bytes as ::core::ffi::c_int + 8 as ::core::ffi::c_int
                - 1 as ::core::ffi::c_int) / 8 as ::core::ffi::c_int) as uint32_t
                & (((1 as ::core::ffi::c_int) << 8 as ::core::ffi::c_int) as uint32_t)
                    .wrapping_sub(1 as uint32_t)) << 10 as ::core::ffi::c_int;
        tx_count = (tx_count as ::core::ffi::c_int + data_bytes as ::core::ffi::c_int)
            as uint16_t;
        if tx_func
            .expect(
                "non-null function pointer",
            )(
            (*iface).driver_data,
            can_id,
            (&raw mut (*packet).c2rust_unnamed.data as *mut uint8_t)
                .offset(tx_count as ::core::ffi::c_int as isize)
                .offset(-(data_bytes as ::core::ffi::c_int as isize)),
            data_bytes,
            ::core::ptr::null::<csp_packet_t>(),
        ) != CSP_ERR_NONE
        {
            (*iface).tx_error = (*iface).tx_error.wrapping_add(1);
            return CSP_ERR_DRIVER;
        }
    }
    csp_buffer_free(packet as *mut ::core::ffi::c_void);
    return CSP_ERR_NONE;
}
unsafe extern "C" fn csp_can2_rx(
    mut iface: *mut csp_iface_t,
    mut id: uint32_t,
    mut data: *const uint8_t,
    mut dlc: uint8_t,
    mut timestamp_rx: uint32_t,
    mut task_woken: *mut ::core::ffi::c_int,
) -> ::core::ffi::c_int {
    let mut ifdata: *mut csp_can_interface_data_t = (*iface).interface_data
        as *mut csp_can_interface_data_t;
    let mut packet: *mut csp_packet_t = csp_can_pbuf_find(
        ifdata,
        id,
        CFP2_ID_CONN_MASK as uint32_t,
        task_woken,
    );
    if packet.is_null() {
        if id & (CFP2_BEGIN_MASK << CFP2_BEGIN_OFFSET) as uint32_t != 0 {
            if (dlc as ::core::ffi::c_int) < 4 as ::core::ffi::c_int {
                csp_dbg_can_errno = CSP_DBG_CAN_ERR_SHORT_BEGIN as uint8_t;
                (*iface).frame = (*iface).frame.wrapping_add(1);
                return CSP_ERR_INVAL;
            }
            let mut header: [uint8_t; 6] = [0; 6];
            let mut first_two: uint16_t = (id >> CFP2_DST_OFFSET) as uint16_t;
            first_two = __bswap_16(first_two as __uint16_t) as uint16_t;
            memcpy(
                &raw mut header as *mut uint8_t as *mut ::core::ffi::c_void,
                &raw mut first_two as *const ::core::ffi::c_void,
                2 as size_t,
            );
            memcpy(
                (&raw mut header as *mut uint8_t)
                    .offset(2 as ::core::ffi::c_int as isize) as *mut uint8_t
                    as *mut ::core::ffi::c_void,
                data as *const ::core::ffi::c_void,
                4 as size_t,
            );
            data = data.offset(4 as ::core::ffi::c_int as isize);
            dlc = (dlc as ::core::ffi::c_int - 4 as ::core::ffi::c_int) as uint8_t;
            let mut csp_id: csp_id_t = csp_id_extract(&raw mut header as *mut uint8_t);
            packet = csp_can_pbuf_new(ifdata, id, csp_id, task_woken);
            if packet.is_null() {
                (*iface).drop = (*iface).drop.wrapping_add(1);
                return CSP_ERR_NOBUFS;
            }
            csp_id_setup_rx(packet);
            (*packet).id = csp_id;
            memcpy(
                (*packet).frame_begin as *mut ::core::ffi::c_void,
                &raw mut header as *mut uint8_t as *const ::core::ffi::c_void,
                csp_id_get_header_size() as size_t,
            );
            (*packet).frame_length = csp_id_get_header_size() as uint16_t;
            (*packet).length = 0 as uint16_t;
            (*packet).rx_count = 1 as uint16_t;
        } else {
            (*iface).frame = (*iface).frame.wrapping_add(1);
            return CSP_ERR_INVAL;
        }
    }
    if id & (CFP2_BEGIN_MASK << CFP2_BEGIN_OFFSET) as uint32_t == 0 {
        let mut fragment_counter: ::core::ffi::c_int = (id >> CFP2_FC_OFFSET
            & CFP2_FC_MASK as uint32_t) as ::core::ffi::c_int;
        if (*packet).rx_count as ::core::ffi::c_int != fragment_counter {
            csp_dbg_can_errno = CSP_DBG_CAN_ERR_FRAME_LOST as uint8_t;
            csp_can_pbuf_free(ifdata, packet, 1 as ::core::ffi::c_int, task_woken);
            (*iface).frame = (*iface).frame.wrapping_add(1);
            return CSP_ERR_INVAL;
        }
        (*packet).rx_count = ((*packet).rx_count as ::core::ffi::c_int
            + 1 as ::core::ffi::c_int & CFP2_FC_MASK) as uint16_t;
    }
    if ((*packet).frame_begin.offset((*packet).frame_length as isize) as *mut uint8_t)
        .offset(dlc as ::core::ffi::c_int as isize)
        > (&raw mut (*packet).c2rust_unnamed.data as *mut uint8_t)
            .offset(::core::mem::size_of::<[uint8_t; 256]>() as isize) as *mut uint8_t
    {
        csp_dbg_can_errno = CSP_DBG_CAN_ERR_RX_OVF as uint8_t;
        (*iface).rx_error = (*iface).rx_error.wrapping_add(1);
        csp_can_pbuf_free(ifdata, packet, 1 as ::core::ffi::c_int, task_woken);
        return CSP_ERR_INVAL;
    }
    memcpy(
        (*packet).frame_begin.offset((*packet).frame_length as isize) as *mut uint8_t
            as *mut ::core::ffi::c_void,
        data as *const ::core::ffi::c_void,
        dlc as size_t,
    );
    (*packet).frame_length = ((*packet).frame_length as ::core::ffi::c_int
        + dlc as ::core::ffi::c_int) as uint16_t;
    if id & (CFP2_END_MASK << CFP2_END_OFFSET) as uint32_t != 0 {
        (*packet).timestamp_rx = timestamp_rx as uint64_t;
        (*packet).length = ((*packet).frame_length as ::core::ffi::c_int
            - csp_id_get_header_size()) as uint16_t;
        if (*packet).id.dst as ::core::ffi::c_int == 0x3fff as ::core::ffi::c_int {
            (*packet).id.dst = (*iface).addr;
        }
        csp_can_pbuf_free(ifdata, packet, 0 as ::core::ffi::c_int, task_woken);
        csp_qfifo_write(packet, iface, task_woken as *mut ::core::ffi::c_void);
    }
    return CSP_ERR_NONE;
}
unsafe extern "C" fn csp_can2_tx(
    mut iface: *mut csp_iface_t,
    mut via: uint16_t,
    mut packet: *mut csp_packet_t,
    mut from_me: ::core::ffi::c_int,
) -> ::core::ffi::c_int {
    if (*packet).id.dst as ::core::ffi::c_int == (*iface).addr as ::core::ffi::c_int
        || csp_addr_is_alias((*packet).id.dst) != 0
    {
        csp_qfifo_write(packet, iface, NULL);
        return CSP_ERR_NONE;
    }
    let mut ifdata: *mut csp_can_interface_data_t = (*iface).interface_data
        as *mut csp_can_interface_data_t;
    let fresh0 = (*ifdata).cfp_packet_counter;
    (*ifdata).cfp_packet_counter = (*ifdata).cfp_packet_counter + 1;
    let mut sender_count: ::core::ffi::c_int = fresh0;
    let mut tx_count: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
    let mut can_id: uint32_t = 0 as uint32_t;
    let mut frame_buf_inp: uint8_t = 0 as uint8_t;
    let mut ctx_packet: *const csp_packet_t = ::core::ptr::null::<csp_packet_t>();
    can_id = (((*packet).id.pri as ::core::ffi::c_int & CFP2_PRIO_MASK)
        << CFP2_PRIO_OFFSET
        | ((*packet).id.dst as ::core::ffi::c_int & CFP2_DST_MASK) << CFP2_DST_OFFSET
        | ((*iface).addr as ::core::ffi::c_int & CFP2_SENDER_MASK) << CFP2_SENDER_OFFSET
        | (sender_count & CFP2_SC_MASK) << CFP2_SC_OFFSET
        | (1 as ::core::ffi::c_int & CFP2_BEGIN_MASK) << CFP2_BEGIN_OFFSET) as uint32_t;
    let mut frame_buf_mem: [uint32_t; 2] = [0; 2];
    let mut frame_buf: *mut uint8_t = &raw mut frame_buf_mem as *mut uint32_t
        as *mut uint8_t;
    let mut header_extension: *mut uint32_t = &raw mut frame_buf_mem as *mut uint32_t;
    *header_extension = (((*packet).id.src as ::core::ffi::c_int & CFP2_SRC_MASK)
        << CFP2_SRC_OFFSET
        | ((*packet).id.dport as ::core::ffi::c_int & CFP2_DPORT_MASK)
            << CFP2_DPORT_OFFSET
        | ((*packet).id.sport as ::core::ffi::c_int & CFP2_SPORT_MASK)
            << CFP2_SPORT_OFFSET
        | ((*packet).id.flags as ::core::ffi::c_int & CFP2_FLAGS_MASK)
            << CFP2_FLAGS_OFFSET) as uint32_t;
    *header_extension = __bswap_32(*header_extension) as uint32_t;
    frame_buf_inp = (frame_buf_inp as ::core::ffi::c_int + 4 as ::core::ffi::c_int)
        as uint8_t;
    let mut data_bytes: ::core::ffi::c_int = if (*packet).length as ::core::ffi::c_int
        >= 4 as ::core::ffi::c_int
    {
        4 as ::core::ffi::c_int
    } else {
        (*packet).length as ::core::ffi::c_int
    };
    memcpy(
        frame_buf.offset(frame_buf_inp as ::core::ffi::c_int as isize)
            as *mut ::core::ffi::c_void,
        &raw mut (*packet).c2rust_unnamed.data as *mut uint8_t
            as *const ::core::ffi::c_void,
        data_bytes as size_t,
    );
    frame_buf_inp = (frame_buf_inp as ::core::ffi::c_int + data_bytes) as uint8_t;
    tx_count = data_bytes;
    if tx_count == (*packet).length as ::core::ffi::c_int {
        can_id
            |= ((1 as ::core::ffi::c_int & CFP2_END_MASK) << CFP2_END_OFFSET)
                as uint32_t;
        ctx_packet = packet;
    }
    if (*ifdata)
        .tx_func
        .expect(
            "non-null function pointer",
        )((*iface).driver_data, can_id, frame_buf, frame_buf_inp, ctx_packet)
        != CSP_ERR_NONE
    {
        (*iface).tx_error = (*iface).tx_error.wrapping_add(1);
        return CSP_ERR_DRIVER;
    }
    let mut fragment_count: ::core::ffi::c_int = 1 as ::core::ffi::c_int;
    while tx_count < (*packet).length as ::core::ffi::c_int {
        can_id = (((*packet).id.pri as ::core::ffi::c_int & CFP2_PRIO_MASK)
            << CFP2_PRIO_OFFSET
            | ((*packet).id.dst as ::core::ffi::c_int & CFP2_DST_MASK) << CFP2_DST_OFFSET
            | ((*iface).addr as ::core::ffi::c_int & CFP2_SENDER_MASK)
                << CFP2_SENDER_OFFSET | (sender_count & CFP2_SC_MASK) << CFP2_SC_OFFSET)
            as uint32_t;
        let fresh1 = fragment_count;
        fragment_count = fragment_count + 1;
        can_id |= ((fresh1 & CFP2_FC_MASK) << CFP2_FC_OFFSET) as uint32_t;
        data_bytes = if (*packet).length as ::core::ffi::c_int - tx_count
            >= CAN_FRAME_SIZE
        {
            CAN_FRAME_SIZE
        } else {
            (*packet).length as ::core::ffi::c_int - tx_count
        };
        if tx_count + data_bytes == (*packet).length as ::core::ffi::c_int {
            can_id
                |= ((1 as ::core::ffi::c_int & CFP2_END_MASK) << CFP2_END_OFFSET)
                    as uint32_t;
            ctx_packet = packet;
        }
        if (*ifdata)
            .tx_func
            .expect(
                "non-null function pointer",
            )(
            (*iface).driver_data,
            can_id,
            (&raw mut (*packet).c2rust_unnamed.data as *mut uint8_t)
                .offset(tx_count as isize),
            data_bytes as uint8_t,
            ctx_packet,
        ) != CSP_ERR_NONE
        {
            (*iface).tx_error = (*iface).tx_error.wrapping_add(1);
            return CSP_ERR_DRIVER;
        }
        tx_count += data_bytes;
    }
    csp_buffer_free(packet as *mut ::core::ffi::c_void);
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_can_add_interface(
    mut iface: *mut csp_iface_t,
) -> ::core::ffi::c_int {
    if iface.is_null() || (*iface).name.is_null() || (*iface).interface_data.is_null() {
        return CSP_ERR_INVAL;
    }
    let mut ifdata: *mut csp_can_interface_data_t = (*iface).interface_data
        as *mut csp_can_interface_data_t;
    if (*ifdata).tx_func.is_none() {
        return CSP_ERR_INVAL;
    }
    (*ifdata).cfp_packet_counter = 0 as ::core::ffi::c_int;
    if csp_conf.version as ::core::ffi::c_int == 1 as ::core::ffi::c_int {
        (*iface).nexthop = Some(
            csp_can1_tx
                as unsafe extern "C" fn(
                    *mut csp_iface_t,
                    uint16_t,
                    *mut csp_packet_t,
                    ::core::ffi::c_int,
                ) -> ::core::ffi::c_int,
        ) as nexthop_t;
    } else {
        (*iface).nexthop = Some(
            csp_can2_tx
                as unsafe extern "C" fn(
                    *mut csp_iface_t,
                    uint16_t,
                    *mut csp_packet_t,
                    ::core::ffi::c_int,
                ) -> ::core::ffi::c_int,
        ) as nexthop_t;
    }
    csp_iflist_add(iface);
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_can_remove_interface(
    mut iface: *mut csp_iface_t,
) -> ::core::ffi::c_int {
    if iface.is_null() {
        return CSP_ERR_INVAL;
    }
    csp_iflist_remove(iface);
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_can_rx(
    mut iface: *mut csp_iface_t,
    mut id: uint32_t,
    mut data: *const uint8_t,
    mut dlc: uint8_t,
    mut timestamp_rx: uint32_t,
    mut task_woken: *mut ::core::ffi::c_int,
) -> ::core::ffi::c_int {
    if csp_conf.version as ::core::ffi::c_int == 1 as ::core::ffi::c_int {
        return csp_can1_rx(iface, id, data, dlc, task_woken)
    } else {
        return csp_can2_rx(iface, id, data, dlc, timestamp_rx, task_woken)
    };
}
