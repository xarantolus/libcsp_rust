extern "C" {
    pub type pthread_queue_s;
    fn csp_buffer_get(unused: size_t) -> *mut csp_packet_t;
    fn csp_buffer_free(buffer: *mut ::core::ffi::c_void);
    fn csp_read(conn: *mut csp_conn_t, timeout: uint32_t) -> *mut csp_packet_t;
    fn csp_send(conn: *mut csp_conn_t, packet: *mut csp_packet_t);
    fn csp_conn_is_active(conn: *mut csp_conn_t) -> bool;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct csp_conn_s {
    pub type_0: atomic_int,
    pub state: atomic_int,
    pub idin: csp_id_t,
    pub idout: csp_id_t,
    pub sport_outgoing: uint8_t,
    pub rx_queue: csp_queue_handle_t,
    pub rx_queue_static: csp_static_queue_t,
    pub rx_queue_static_data: [::core::ffi::c_char; 128],
    pub callback: Option<unsafe extern "C" fn(*mut csp_packet_t) -> ()>,
    pub dest_socket: *mut csp_socket_t,
    pub timestamp: uint32_t,
    pub opts: uint32_t,
    pub rdp: csp_rdp_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct csp_rdp_t {
    pub state: csp_rdp_state_t,
    pub closed_by: uint8_t,
    pub snd_nxt: uint16_t,
    pub snd_una: uint16_t,
    pub snd_iss: uint16_t,
    pub rcv_cur: uint16_t,
    pub rcv_irs: uint16_t,
    pub rcv_lsa: uint16_t,
    pub window_size: uint32_t,
    pub conn_timeout: uint32_t,
    pub packet_timeout: uint32_t,
    pub delayed_acks: uint32_t,
    pub ack_timeout: uint32_t,
    pub ack_delay_count: uint32_t,
    pub ack_timestamp: uint32_t,
    pub retransmits: uint32_t,
    pub tx_wait: csp_bin_sem_t,
}
pub type sem_t = csp_bin_sem_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub union csp_bin_sem_t {
    pub __size: [::core::ffi::c_char; 32],
    pub __align: ::core::ffi::c_long,
}
pub type csp_rdp_state_t = ::core::ffi::c_uint;
pub const RDP_CLOSE_WAIT: csp_rdp_state_t = 4;
pub const RDP_OPEN: csp_rdp_state_t = 3;
pub const RDP_SYN_RCVD: csp_rdp_state_t = 2;
pub const RDP_SYN_SENT: csp_rdp_state_t = 1;
pub const RDP_CLOSED: csp_rdp_state_t = 0;
pub type csp_socket_t = csp_socket_s;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct csp_socket_s {
    pub rx_queue: csp_queue_handle_t,
    pub rx_queue_static: csp_static_queue_t,
    pub rx_queue_static_data: [::core::ffi::c_char; 128],
    pub opts: uint32_t,
}
pub type csp_packet_t = csp_packet_s;
pub type atomic_int = ::core::ffi::c_int;
pub type csp_conn_t = csp_conn_s;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct csp_sfp_read_t {
    pub data: *mut ::core::ffi::c_void,
    pub read: Option<
        unsafe extern "C" fn(
            *mut uint8_t,
            uint32_t,
            uint32_t,
            *mut ::core::ffi::c_void,
        ) -> ::core::ffi::c_int,
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct csp_sfp_recv_t {
    pub data: *mut ::core::ffi::c_void,
    pub write: Option<
        unsafe extern "C" fn(
            *const uint8_t,
            uint32_t,
            uint32_t,
            uint32_t,
            *mut ::core::ffi::c_void,
        ) -> ::core::ffi::c_int,
    >,
}
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct sfp_header_t {
    pub offset: uint32_t,
    pub totalsize: uint32_t,
}
pub type csp_crc32_t = uint32_t;
pub const NULL: *mut ::core::ffi::c_void = ::core::ptr::null_mut::<
    ::core::ffi::c_void,
>();
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ERR_NOMEM: ::core::ffi::c_int = -(1 as ::core::ffi::c_int);
pub const CSP_ERR_INVAL: ::core::ffi::c_int = -(2 as ::core::ffi::c_int);
pub const CSP_ERR_TIMEDOUT: ::core::ffi::c_int = -(3 as ::core::ffi::c_int);
pub const CSP_ERR_SFP: ::core::ffi::c_int = -(103 as ::core::ffi::c_int);
pub const CSP_ERR_MTU: ::core::ffi::c_int = -(104 as ::core::ffi::c_int);
pub const CSP_BUFFER_SIZE: ::core::ffi::c_int = 256 as ::core::ffi::c_int;
pub const CSP_FFRAG: ::core::ffi::c_int = 0x10 as ::core::ffi::c_int;
pub const CSP_SO_RDPREQ: ::core::ffi::c_int = 0x1 as ::core::ffi::c_int;
pub const CSP_SO_HMACREQ: ::core::ffi::c_int = 0x4 as ::core::ffi::c_int;
pub const CSP_SO_CRC32REQ: ::core::ffi::c_int = 0x40 as ::core::ffi::c_int;
pub const CSP_O_RDP: ::core::ffi::c_int = CSP_SO_RDPREQ;
pub const CSP_O_HMAC: ::core::ffi::c_int = CSP_SO_HMACREQ;
pub const CSP_O_CRC32: ::core::ffi::c_int = CSP_SO_CRC32REQ;
pub const CSP_RDP_HEADER_SIZE: ::core::ffi::c_int = 5 as ::core::ffi::c_int;
#[inline]
unsafe extern "C" fn __bswap_32(mut __bsx: __uint32_t) -> __uint32_t {
    return (__bsx & 0xff000000 as __uint32_t) >> 24 as ::core::ffi::c_int
        | (__bsx & 0xff0000 as __uint32_t) >> 8 as ::core::ffi::c_int
        | (__bsx & 0xff00 as __uint32_t) << 8 as ::core::ffi::c_int
        | (__bsx & 0xff as __uint32_t) << 24 as ::core::ffi::c_int;
}
pub const CSP_HMAC_LENGTH: ::core::ffi::c_int = 4 as ::core::ffi::c_int;
#[inline]
unsafe extern "C" fn csp_sfp_header_add(
    mut packet: *mut csp_packet_t,
) -> *mut sfp_header_t {
    let mut header: *mut sfp_header_t = (&raw mut (*packet).c2rust_unnamed.data
        as *mut uint8_t)
        .offset((*packet).length as isize) as *mut uint8_t as *mut sfp_header_t;
    (*packet).length = ((*packet).length as ::core::ffi::c_ulong)
        .wrapping_add(
            ::core::mem::size_of::<sfp_header_t>() as usize as ::core::ffi::c_ulong,
        ) as uint16_t as uint16_t;
    return header;
}
#[inline]
unsafe extern "C" fn csp_sfp_header_remove(
    mut packet: *mut csp_packet_t,
) -> *mut sfp_header_t {
    if (*packet).id.flags as ::core::ffi::c_int & CSP_FFRAG == 0 as ::core::ffi::c_int {
        return ::core::ptr::null_mut::<sfp_header_t>();
    }
    let mut header: *mut sfp_header_t = ::core::ptr::null_mut::<sfp_header_t>();
    if ((*packet).length as usize) < ::core::mem::size_of::<sfp_header_t>() as usize {
        return ::core::ptr::null_mut::<sfp_header_t>();
    }
    header = (&raw mut (*packet).c2rust_unnamed.data as *mut uint8_t)
        .offset(
            ((*packet).length as usize)
                .wrapping_sub(::core::mem::size_of::<sfp_header_t>() as usize) as isize,
        ) as *mut uint8_t as *mut sfp_header_t;
    (*packet).length = ((*packet).length as ::core::ffi::c_ulong)
        .wrapping_sub(
            ::core::mem::size_of::<sfp_header_t>() as usize as ::core::ffi::c_ulong,
        ) as uint16_t as uint16_t;
    (*header).offset = __bswap_32((*header).offset as __uint32_t) as uint32_t;
    (*header).totalsize = __bswap_32((*header).totalsize as __uint32_t) as uint32_t;
    if (*header).offset > (*header).totalsize {
        return ::core::ptr::null_mut::<sfp_header_t>();
    }
    return header;
}
#[no_mangle]
pub unsafe extern "C" fn csp_sfp_opts_max_mtu(mut opts: uint32_t) -> uint32_t {
    let mut overhead: uint32_t = 0 as uint32_t;
    if opts & CSP_O_RDP as uint32_t != 0 {
        overhead = overhead.wrapping_add(CSP_RDP_HEADER_SIZE as uint32_t);
    }
    if opts & CSP_O_CRC32 as uint32_t != 0 {
        overhead = (overhead as ::core::ffi::c_ulong)
            .wrapping_add(
                ::core::mem::size_of::<csp_crc32_t>() as usize as ::core::ffi::c_ulong,
            ) as uint32_t as uint32_t;
    }
    if opts & CSP_O_HMAC as uint32_t != 0 {
        overhead = overhead.wrapping_add(CSP_HMAC_LENGTH as uint32_t);
    }
    overhead = (overhead as ::core::ffi::c_ulong)
        .wrapping_add(
            ::core::mem::size_of::<sfp_header_t>() as usize as ::core::ffi::c_ulong,
        ) as uint32_t as uint32_t;
    return (CSP_BUFFER_SIZE as uint32_t).wrapping_sub(overhead);
}
#[no_mangle]
pub unsafe extern "C" fn csp_sfp_conn_max_mtu(mut conn: *const csp_conn_t) -> uint32_t {
    let mut max_mtu: uint32_t = 0 as uint32_t;
    if !conn.is_null() {
        max_mtu = csp_sfp_opts_max_mtu((*conn).opts);
    }
    return max_mtu;
}
#[no_mangle]
pub unsafe extern "C" fn csp_sfp_send(
    mut conn: *mut csp_conn_t,
    mut user: *const csp_sfp_read_t,
    mut totalsize: uint32_t,
    mut mtu: uint32_t,
    mut timeout: uint32_t,
) -> ::core::ffi::c_int {
    if conn.is_null() || user.is_null() || (*user).read.is_none() {
        return CSP_ERR_INVAL
    } else {
        let mut max_mtu: uint32_t = csp_sfp_conn_max_mtu(conn);
        if mtu > max_mtu || 0 as uint32_t == mtu {
            return CSP_ERR_MTU;
        }
    }
    let mut error: ::core::ffi::c_int = CSP_ERR_NONE;
    let mut count: uint32_t = 0 as uint32_t;
    while count < totalsize && csp_conn_is_active(conn) as ::core::ffi::c_int != 0 {
        let mut sfp_header: *mut sfp_header_t = ::core::ptr::null_mut::<sfp_header_t>();
        let mut packet: *mut csp_packet_t = csp_buffer_get(0 as size_t);
        if packet.is_null() {
            return CSP_ERR_NOMEM;
        }
        let mut size: uint32_t = totalsize.wrapping_sub(count);
        if size > mtu {
            size = mtu;
        }
        error = (*user)
            .read
            .expect(
                "non-null function pointer",
            )(
            &raw mut (*packet).c2rust_unnamed.data as *mut uint8_t,
            size,
            count,
            (*user).data,
        );
        if CSP_ERR_NONE != error {
            csp_buffer_free(packet as *mut ::core::ffi::c_void);
            return error;
        }
        (*packet).length = size as uint16_t;
        (*conn).idout.flags = ((*conn).idout.flags as ::core::ffi::c_int | CSP_FFRAG)
            as uint8_t;
        sfp_header = csp_sfp_header_add(packet);
        (*sfp_header).totalsize = __bswap_32(totalsize as __uint32_t) as uint32_t;
        (*sfp_header).offset = __bswap_32(count as __uint32_t) as uint32_t;
        csp_send(conn, packet);
        count = count.wrapping_add(size);
    }
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_sfp_recv_fp(
    mut conn: *mut csp_conn_t,
    mut user: *const csp_sfp_recv_t,
    mut timeout: uint32_t,
    mut first_packet: *mut csp_packet_t,
) -> ::core::ffi::c_int {
    if conn.is_null() || user.is_null() || (*user).write.is_none() {
        return CSP_ERR_INVAL;
    }
    let mut packet: *mut csp_packet_t = ::core::ptr::null_mut::<csp_packet_t>();
    if first_packet.is_null() {
        packet = csp_read(conn, timeout);
        if packet.is_null() {
            return CSP_ERR_TIMEDOUT;
        }
    } else {
        packet = first_packet;
    }
    let max_mtu: uint32_t = csp_sfp_conn_max_mtu(conn) as uint32_t;
    let mut datasize: uint32_t = 0 as uint32_t;
    let mut data_offset: uint32_t = 0 as uint32_t;
    let mut error: ::core::ffi::c_int = CSP_ERR_TIMEDOUT;
    loop {
        let mut sfp_header: *mut sfp_header_t = csp_sfp_header_remove(packet);
        if sfp_header.is_null() {
            csp_buffer_free(packet as *mut ::core::ffi::c_void);
            error = CSP_ERR_SFP;
            break;
        } else if (*sfp_header).offset != data_offset {
            csp_buffer_free(packet as *mut ::core::ffi::c_void);
            error = CSP_ERR_SFP;
            break;
        } else if max_mtu < (*packet).length as uint32_t
            || 0 as ::core::ffi::c_int >= (*packet).length as ::core::ffi::c_int
        {
            csp_buffer_free(packet as *mut ::core::ffi::c_void);
            error = CSP_ERR_SFP;
            break;
        } else if 0 as uint32_t == (*sfp_header).totalsize {
            csp_buffer_free(packet as *mut ::core::ffi::c_void);
            error = CSP_ERR_SFP;
            break;
        } else {
            if datasize == 0 as uint32_t {
                datasize = (*sfp_header).totalsize;
            }
            if datasize != (*sfp_header).totalsize {
                csp_buffer_free(packet as *mut ::core::ffi::c_void);
                error = CSP_ERR_SFP;
                break;
            } else if (*sfp_header).offset
                > datasize.wrapping_sub((*packet).length as uint32_t)
            {
                csp_buffer_free(packet as *mut ::core::ffi::c_void);
                error = CSP_ERR_SFP;
                break;
            } else if data_offset.wrapping_add((*packet).length as uint32_t) > datasize
                || datasize != (*sfp_header).totalsize
            {
                csp_buffer_free(packet as *mut ::core::ffi::c_void);
                error = CSP_ERR_SFP;
                break;
            } else {
                error = (*user)
                    .write
                    .expect(
                        "non-null function pointer",
                    )(
                    &raw mut (*packet).c2rust_unnamed.data as *mut uint8_t,
                    (*packet).length as uint32_t,
                    data_offset,
                    datasize,
                    (*user).data,
                );
                if CSP_ERR_NONE != error {
                    csp_buffer_free(packet as *mut ::core::ffi::c_void);
                    break;
                } else {
                    data_offset = data_offset.wrapping_add((*packet).length as uint32_t);
                    if data_offset >= datasize {
                        csp_buffer_free(packet as *mut ::core::ffi::c_void);
                        return CSP_ERR_NONE;
                    }
                    if (*packet).length as ::core::ffi::c_int == 0 as ::core::ffi::c_int
                    {
                        csp_buffer_free(packet as *mut ::core::ffi::c_void);
                        error = CSP_ERR_SFP;
                        break;
                    } else {
                        csp_buffer_free(packet as *mut ::core::ffi::c_void);
                        packet = csp_read(conn, timeout);
                        if packet.is_null() {
                            break;
                        }
                    }
                }
            }
        }
    }
    return error;
}
