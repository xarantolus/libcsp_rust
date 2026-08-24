extern "C" {
    pub type pthread_queue_s;
    fn csp_queue_enqueue(
        handle: csp_queue_handle_t,
        value: *const ::core::ffi::c_void,
        timeout: uint32_t,
    ) -> ::core::ffi::c_int;
    fn csp_queue_size(handle: csp_queue_handle_t) -> ::core::ffi::c_int;
    fn csp_queue_free(handle: csp_queue_handle_t) -> ::core::ffi::c_int;
    fn csp_rdp_queue_flush(conn: *mut csp_conn_t);
    fn csp_rdp_queue_tx_size() -> ::core::ffi::c_int;
    fn csp_rdp_queue_tx_add(conn: *mut csp_conn_t, packet: *mut csp_packet_t);
    fn csp_rdp_queue_tx_get(conn: *mut csp_conn_t) -> *mut csp_packet_t;
    fn csp_rdp_queue_rx_size() -> ::core::ffi::c_int;
    fn csp_rdp_queue_rx_add(conn: *mut csp_conn_t, packet: *mut csp_packet_t);
    fn csp_rdp_queue_rx_get(conn: *mut csp_conn_t) -> *mut csp_packet_t;
    fn rand_r(__seed: *mut ::core::ffi::c_uint) -> ::core::ffi::c_int;
    fn abs(__x: ::core::ffi::c_int) -> ::core::ffi::c_int;
    fn memset(
        __s: *mut ::core::ffi::c_void,
        __c: ::core::ffi::c_int,
        __n: size_t,
    ) -> *mut ::core::ffi::c_void;
    static mut csp_dbg_conn_ovf: uint8_t;
    static mut csp_dbg_rdp_print: uint8_t;
    fn csp_print_func(fmt: *const ::core::ffi::c_char, ...);
    fn csp_buffer_get(unused: size_t) -> *mut csp_packet_t;
    fn csp_buffer_free(buffer: *mut ::core::ffi::c_void);
    fn csp_buffer_clone(packet: *const csp_packet_t) -> *mut csp_packet_t;
    fn csp_buffer_copy(src: *const csp_packet_t, dst: *mut csp_packet_t);
    fn csp_get_ms() -> uint32_t;
    fn csp_bin_sem_init(sem: *mut csp_bin_sem_t);
    fn csp_bin_sem_wait(
        sem: *mut csp_bin_sem_t,
        timeout: ::core::ffi::c_uint,
    ) -> ::core::ffi::c_int;
    fn csp_bin_sem_post(sem: *mut csp_bin_sem_t) -> ::core::ffi::c_int;
    fn csp_conn_enqueue_packet(
        conn: *mut csp_conn_t,
        packet: *mut csp_packet_t,
    ) -> ::core::ffi::c_int;
    fn csp_conn_close(conn: *mut csp_conn_t, closed_by: uint8_t) -> ::core::ffi::c_int;
    fn csp_send_direct(
        idout: *mut csp_id_t,
        packet: *mut csp_packet_t,
        routed_from: *mut csp_iface_t,
    );
}
pub type __uint8_t = u8;
pub type __int16_t = i16;
pub type __uint16_t = u16;
pub type __int32_t = i32;
pub type __uint32_t = u32;
pub type __uint64_t = u64;
pub type int16_t = __int16_t;
pub type int32_t = __int32_t;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type size_t = usize;
pub type pthread_queue_t = pthread_queue_s;
pub type csp_queue_handle_t = *mut pthread_queue_t;
pub type csp_static_queue_t = *mut ::core::ffi::c_void;
pub type C2RustUnnamed = ::core::ffi::c_uint;
pub const CSP_PRIO_LOW: C2RustUnnamed = 3;
pub const CSP_PRIO_NORM: C2RustUnnamed = 2;
pub const CSP_PRIO_HIGH: C2RustUnnamed = 1;
pub const CSP_PRIO_CRITICAL: C2RustUnnamed = 0;
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
    pub c2rust_unnamed: C2RustUnnamed_0,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
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
pub type csp_conn_t = csp_conn_s;
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct rdp_header_t {
    pub flags: uint8_t,
    pub seq_nr: uint16_t,
    pub ack_nr: uint16_t,
}
pub const true_0: ::core::ffi::c_int = 1 as ::core::ffi::c_int;
pub const false_0: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ERR_NOMEM: ::core::ffi::c_int = -(1 as ::core::ffi::c_int);
pub const CSP_ERR_TIMEDOUT: ::core::ffi::c_int = -(3 as ::core::ffi::c_int);
pub const CSP_ERR_USED: ::core::ffi::c_int = -(4 as ::core::ffi::c_int);
pub const CSP_ERR_ALREADY: ::core::ffi::c_int = -(7 as ::core::ffi::c_int);
pub const CSP_ERR_RESET: ::core::ffi::c_int = -(8 as ::core::ffi::c_int);
pub const CSP_ERR_NOBUFS: ::core::ffi::c_int = -(9 as ::core::ffi::c_int);
pub const CSP_ERR_AGAIN: ::core::ffi::c_int = -(12 as ::core::ffi::c_int);
pub const CSP_CONN_RXQUEUE_LEN: ::core::ffi::c_int = 16 as ::core::ffi::c_int;
pub const CSP_RDP_MAX_WINDOW: ::core::ffi::c_int = 5 as ::core::ffi::c_int;
pub const CSP_QUEUE_ERROR: ::core::ffi::c_int = -(1 as ::core::ffi::c_int);
pub const CSP_RDP_MIN_CONN_TIMEOUT: ::core::ffi::c_int = 1000 as ::core::ffi::c_int;
pub const CSP_RDP_MAX_CONN_TIMEOUT: ::core::ffi::c_int = 60000 as ::core::ffi::c_int;
pub const CSP_RDP_MIN_PACKET_TIMEOUT: ::core::ffi::c_int = 100 as ::core::ffi::c_int;
pub const CSP_RDP_MAX_PACKET_TIMEOUT: ::core::ffi::c_int = 60000 as ::core::ffi::c_int;
pub const CSP_RDP_MIN_ACK_TIMEOUT: ::core::ffi::c_int = 10 as ::core::ffi::c_int;
pub const CSP_RDP_MAX_RETRANSMITS: ::core::ffi::c_int = 10 as ::core::ffi::c_int;
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
pub const NULL: *mut ::core::ffi::c_void = ::core::ptr::null_mut::<
    ::core::ffi::c_void,
>();
pub const CSP_SEMAPHORE_OK: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_RDP_CLOSED_BY_USERSPACE: ::core::ffi::c_int = 0x1 as ::core::ffi::c_int;
pub const CSP_RDP_CLOSED_BY_PROTOCOL: ::core::ffi::c_int = 0x2 as ::core::ffi::c_int;
pub const CSP_RDP_CLOSED_BY_TIMEOUT: ::core::ffi::c_int = 0x4 as ::core::ffi::c_int;
pub const CSP_RDP_CLOSED_BY_ALL: ::core::ffi::c_int = CSP_RDP_CLOSED_BY_USERSPACE
    | CSP_RDP_CLOSED_BY_PROTOCOL | CSP_RDP_CLOSED_BY_TIMEOUT;
pub const RDP_SYN: ::core::ffi::c_int = 0x8 as ::core::ffi::c_int;
pub const RDP_ACK: ::core::ffi::c_int = 0x4 as ::core::ffi::c_int;
pub const RDP_EAK: ::core::ffi::c_int = 0x2 as ::core::ffi::c_int;
pub const RDP_RST: ::core::ffi::c_int = 0x1 as ::core::ffi::c_int;
pub const CSP_USE_RDP_FAST_CLOSE: ::core::ffi::c_int = 1 as ::core::ffi::c_int;
static mut csp_rdp_window_size: uint32_t = 4 as uint32_t;
static mut csp_rdp_conn_timeout: uint32_t = 10000 as uint32_t;
static mut csp_rdp_packet_timeout: uint32_t = 1000 as uint32_t;
static mut csp_rdp_delayed_acks: uint32_t = 1 as uint32_t;
static mut csp_rdp_ack_timeout: uint32_t = (1000 as ::core::ffi::c_int
    / 4 as ::core::ffi::c_int) as uint32_t;
static mut csp_rdp_ack_delay_count: uint32_t = (4 as ::core::ffi::c_int
    / 2 as ::core::ffi::c_int) as uint32_t;
static mut csp_rdp_incr: uint8_t = 0 as uint8_t;
pub const RDP_SYN_OPTIONS_SIZE: usize = (6 as usize)
    .wrapping_mul(::core::mem::size_of::<uint32_t>() as usize);
unsafe extern "C" fn csp_rdp_clamp(
    mut value: uint32_t,
    mut min: uint32_t,
    mut max: uint32_t,
) -> uint32_t {
    if value < min {
        return min;
    }
    if value > max {
        return max;
    }
    return value;
}
unsafe extern "C" fn csp_rdp_header_add(
    mut packet: *mut csp_packet_t,
) -> *mut rdp_header_t {
    let mut header: *mut rdp_header_t = ::core::ptr::null_mut::<rdp_header_t>();
    if ((*packet).length as usize)
        .wrapping_add(::core::mem::size_of::<rdp_header_t>() as usize)
        > ::core::mem::size_of::<[uint8_t; 256]>() as usize
    {
        return ::core::ptr::null_mut::<rdp_header_t>();
    }
    header = (&raw mut (*packet).c2rust_unnamed.data as *mut uint8_t)
        .offset((*packet).length as isize) as *mut uint8_t as *mut rdp_header_t;
    (*packet).length = ((*packet).length as ::core::ffi::c_ulong)
        .wrapping_add(
            ::core::mem::size_of::<rdp_header_t>() as usize as ::core::ffi::c_ulong,
        ) as uint16_t as uint16_t;
    memset(
        header as *mut ::core::ffi::c_void,
        0 as ::core::ffi::c_int,
        ::core::mem::size_of::<rdp_header_t>() as size_t,
    );
    return header;
}
unsafe extern "C" fn csp_rdp_header_remove(
    mut packet: *mut csp_packet_t,
) -> *mut rdp_header_t {
    let mut header: *mut rdp_header_t = (&raw mut (*packet).c2rust_unnamed.data
        as *mut uint8_t)
        .offset(
            ((*packet).length as usize)
                .wrapping_sub(::core::mem::size_of::<rdp_header_t>() as usize) as isize,
        ) as *mut uint8_t as *mut rdp_header_t;
    (*packet).length = ((*packet).length as ::core::ffi::c_ulong)
        .wrapping_sub(
            ::core::mem::size_of::<rdp_header_t>() as usize as ::core::ffi::c_ulong,
        ) as uint16_t as uint16_t;
    return header;
}
unsafe extern "C" fn csp_rdp_header_ref(
    mut packet: *mut csp_packet_t,
) -> *mut rdp_header_t {
    let mut header: *mut rdp_header_t = (&raw mut (*packet).c2rust_unnamed.data
        as *mut uint8_t)
        .offset(
            ((*packet).length as usize)
                .wrapping_sub(::core::mem::size_of::<rdp_header_t>() as usize) as isize,
        ) as *mut uint8_t as *mut rdp_header_t;
    return header;
}
#[inline]
unsafe extern "C" fn csp_rdp_seq_between(
    mut seq: uint16_t,
    mut start: uint16_t,
    mut end: uint16_t,
) -> ::core::ffi::c_int {
    return ((end as ::core::ffi::c_int - start as ::core::ffi::c_int) as uint16_t
        as ::core::ffi::c_int
        >= (seq as ::core::ffi::c_int - start as ::core::ffi::c_int) as uint16_t
            as ::core::ffi::c_int) as ::core::ffi::c_int;
}
#[inline]
unsafe extern "C" fn csp_rdp_seq_before(
    mut seq: uint16_t,
    mut cmp: uint16_t,
) -> ::core::ffi::c_int {
    return (((seq as ::core::ffi::c_int - cmp as ::core::ffi::c_int) as int16_t
        as ::core::ffi::c_int) < 0 as ::core::ffi::c_int) as ::core::ffi::c_int;
}
#[inline]
unsafe extern "C" fn csp_rdp_seq_after(
    mut seq: uint16_t,
    mut cmp: uint16_t,
) -> ::core::ffi::c_int {
    return csp_rdp_seq_before(cmp, seq);
}
#[inline]
unsafe extern "C" fn csp_rdp_time_before(
    mut time: uint32_t,
    mut cmp: uint32_t,
) -> ::core::ffi::c_int {
    return ((time.wrapping_sub(cmp) as int32_t) < 0 as int32_t) as ::core::ffi::c_int;
}
#[inline]
unsafe extern "C" fn csp_rdp_time_after(
    mut time: uint32_t,
    mut cmp: uint32_t,
) -> ::core::ffi::c_int {
    return csp_rdp_time_before(cmp, time);
}
unsafe extern "C" fn csp_rdp_send_cmp(
    mut conn: *mut csp_conn_t,
    mut packet: *mut csp_packet_t,
    mut flags: ::core::ffi::c_int,
    mut seq_nr: ::core::ffi::c_int,
    mut ack_nr: ::core::ffi::c_int,
) -> ::core::ffi::c_int {
    if packet.is_null() {
        packet = csp_buffer_get(0 as size_t);
        if packet.is_null() {
            return CSP_ERR_NOMEM;
        }
        (*packet).length = 0 as uint16_t;
    }
    if flags & RDP_ACK != 0 {
        (*conn).rdp.rcv_lsa = ack_nr as uint16_t;
    }
    (*conn).rdp.ack_timestamp = csp_get_ms();
    let mut header: *mut rdp_header_t = csp_rdp_header_add(packet);
    if header.is_null() {
        if csp_dbg_rdp_print as ::core::ffi::c_int >= 1 as ::core::ffi::c_int {
            csp_print_func(
                b"\x1B[31mRDP %p: No space for RDP header (cmp)\x1B[0m\0" as *const u8
                    as *const ::core::ffi::c_char,
                conn as *mut ::core::ffi::c_void,
            );
        }
        csp_buffer_free(packet as *mut ::core::ffi::c_void);
        return CSP_ERR_NOMEM;
    }
    (*header).seq_nr = __bswap_16(seq_nr as __uint16_t) as uint16_t;
    (*header).ack_nr = __bswap_16(ack_nr as __uint16_t) as uint16_t;
    let fresh0 = csp_rdp_incr;
    csp_rdp_incr = csp_rdp_incr.wrapping_add(1);
    (*header).flags = ((*header).flags as ::core::ffi::c_int
        | ((fresh0 as ::core::ffi::c_int) << 4 as ::core::ffi::c_int | flags))
        as uint8_t;
    if flags & RDP_SYN != 0 {
        let mut rdp_packet: *mut csp_packet_t = csp_buffer_clone(packet);
        if rdp_packet.is_null() {
            return CSP_ERR_NOMEM;
        }
        (*rdp_packet).timestamp_tx = csp_get_ms();
        csp_rdp_queue_tx_add(conn, rdp_packet);
    }
    let mut idout: csp_id_t = (*conn).idout;
    idout.pri = (if ((*conn).idout.pri as ::core::ffi::c_int)
        < CSP_PRIO_HIGH as ::core::ffi::c_int
    {
        (*conn).idout.pri as ::core::ffi::c_int
    } else {
        CSP_PRIO_HIGH as ::core::ffi::c_int
    }) as uint8_t;
    if csp_dbg_rdp_print as ::core::ffi::c_int >= 2 as ::core::ffi::c_int {
        csp_print_func(
            b"\x1B[34mRDP %p: Send CMP S %u: syn %u, ack %u, eack %u, rst %u, seq_nr %5u, ack_nr %5u, packet_len %u (%u)\n\x1B[0m\0"
                as *const u8 as *const ::core::ffi::c_char,
            conn as *mut ::core::ffi::c_void,
            (*conn).rdp.state as ::core::ffi::c_uint,
            ((*header).flags as ::core::ffi::c_int & 0x8 as ::core::ffi::c_int
                != 0 as ::core::ffi::c_int) as ::core::ffi::c_int,
            ((*header).flags as ::core::ffi::c_int & 0x4 as ::core::ffi::c_int
                != 0 as ::core::ffi::c_int) as ::core::ffi::c_int,
            ((*header).flags as ::core::ffi::c_int & 0x2 as ::core::ffi::c_int
                != 0 as ::core::ffi::c_int) as ::core::ffi::c_int,
            ((*header).flags as ::core::ffi::c_int & 0x1 as ::core::ffi::c_int
                != 0 as ::core::ffi::c_int) as ::core::ffi::c_int,
            __bswap_16((*header).seq_nr as __uint16_t) as ::core::ffi::c_int,
            __bswap_16((*header).ack_nr as __uint16_t) as ::core::ffi::c_int,
            (*packet).length as ::core::ffi::c_int,
            ((*packet).length as usize)
                .wrapping_sub(::core::mem::size_of::<rdp_header_t>() as usize)
                as ::core::ffi::c_uint,
        );
    }
    csp_send_direct(&raw mut idout, packet, ::core::ptr::null_mut::<csp_iface_t>());
    return CSP_ERR_NONE;
}
unsafe extern "C" fn csp_rdp_send_syn(mut conn: *mut csp_conn_t) -> ::core::ffi::c_int {
    let mut packet: *mut csp_packet_t = csp_buffer_get(0 as size_t);
    if packet.is_null() {
        return CSP_ERR_NOMEM;
    }
    (*packet).c2rust_unnamed.data32[0 as ::core::ffi::c_int as usize] = __bswap_32(
        csp_rdp_window_size as __uint32_t,
    ) as uint32_t;
    (*packet).c2rust_unnamed.data32[1 as ::core::ffi::c_int as usize] = __bswap_32(
        csp_rdp_conn_timeout as __uint32_t,
    ) as uint32_t;
    (*packet).c2rust_unnamed.data32[2 as ::core::ffi::c_int as usize] = __bswap_32(
        csp_rdp_packet_timeout as __uint32_t,
    ) as uint32_t;
    (*packet).c2rust_unnamed.data32[3 as ::core::ffi::c_int as usize] = __bswap_32(
        csp_rdp_delayed_acks as __uint32_t,
    ) as uint32_t;
    (*packet).c2rust_unnamed.data32[4 as ::core::ffi::c_int as usize] = __bswap_32(
        csp_rdp_ack_timeout as __uint32_t,
    ) as uint32_t;
    (*packet).c2rust_unnamed.data32[5 as ::core::ffi::c_int as usize] = __bswap_32(
        csp_rdp_ack_delay_count as __uint32_t,
    ) as uint32_t;
    (*packet).length = (6 as usize)
        .wrapping_mul(::core::mem::size_of::<uint32_t>() as usize) as uint16_t;
    return csp_rdp_send_cmp(
        conn,
        packet,
        RDP_SYN,
        (*conn).rdp.snd_iss as ::core::ffi::c_int,
        0 as ::core::ffi::c_int,
    );
}
#[inline]
unsafe extern "C" fn csp_rdp_receive_data(
    mut conn: *mut csp_conn_t,
    mut packet: *mut csp_packet_t,
) -> ::core::ffi::c_int {
    csp_rdp_header_remove(packet);
    if csp_conn_enqueue_packet(conn, packet) != CSP_ERR_NONE {
        csp_dbg_conn_ovf = csp_dbg_conn_ovf.wrapping_add(1);
        if csp_dbg_rdp_print as ::core::ffi::c_int >= 1 as ::core::ffi::c_int {
            csp_print_func(
                b"\x1B[31mRDP %p: Conn RX buffer full\n\x1B[0m\0" as *const u8
                    as *const ::core::ffi::c_char,
                conn as *mut ::core::ffi::c_void,
            );
        }
        return CSP_ERR_NOBUFS;
    }
    return CSP_ERR_NONE;
}
#[inline]
unsafe extern "C" fn csp_rdp_rx_queue_flush(mut conn: *mut csp_conn_t) {
    let mut i: ::core::ffi::c_int = 0;
    let mut count: ::core::ffi::c_int = 0;
    let mut packet: *mut csp_packet_t = ::core::ptr::null_mut::<csp_packet_t>();
    '_front: loop {
        count = csp_rdp_queue_rx_size();
        i = 0 as ::core::ffi::c_int;
        loop {
            if !(i < count) {
                break '_front;
            }
            if csp_queue_free((*conn).rx_queue) <= 2 as ::core::ffi::c_int {
                return;
            }
            packet = csp_rdp_queue_rx_get(conn);
            if packet.is_null() {
                break '_front;
            }
            let mut header: *mut rdp_header_t = csp_rdp_header_ref(packet);
            if (*header).seq_nr as ::core::ffi::c_int
                == ((*conn).rdp.rcv_cur as ::core::ffi::c_int + 1 as ::core::ffi::c_int)
                    as uint16_t as ::core::ffi::c_int
            {
                if csp_dbg_rdp_print as ::core::ffi::c_int >= 2 as ::core::ffi::c_int {
                    csp_print_func(
                        b"\x1B[34mRDP %p: Deliver seq %u\n\x1B[0m\0" as *const u8
                            as *const ::core::ffi::c_char,
                        conn as *mut ::core::ffi::c_void,
                        (*header).seq_nr as ::core::ffi::c_int,
                    );
                }
                if csp_rdp_receive_data(conn, packet) != CSP_ERR_NONE {
                    if csp_dbg_rdp_print as ::core::ffi::c_int >= 1 as ::core::ffi::c_int
                    {
                        csp_print_func(
                            b"\x1B[31mRDP lost packet internally, stream corrupted!\n\x1B[0m\0"
                                as *const u8 as *const ::core::ffi::c_char,
                        );
                    }
                    csp_buffer_free(packet as *mut ::core::ffi::c_void);
                }
                (*conn).rdp.rcv_cur = (*conn).rdp.rcv_cur.wrapping_add(1);
                break;
            } else {
                csp_rdp_queue_rx_add(conn, packet);
                i += 1;
            }
        }
    };
}
#[inline]
unsafe extern "C" fn csp_rdp_seq_in_rx_queue(
    mut conn: *mut csp_conn_t,
    mut seq_nr: uint16_t,
) -> bool {
    let mut i: ::core::ffi::c_int = 0;
    let mut count: ::core::ffi::c_int = 0;
    let mut packet: *mut csp_packet_t = ::core::ptr::null_mut::<csp_packet_t>();
    count = csp_rdp_queue_rx_size();
    i = 0 as ::core::ffi::c_int;
    while i < count {
        packet = csp_rdp_queue_rx_get(conn);
        if packet.is_null() {
            break;
        }
        csp_rdp_queue_rx_add(conn, packet);
        let mut header: *mut rdp_header_t = csp_rdp_header_ref(packet);
        if (*header).seq_nr as ::core::ffi::c_int == seq_nr as ::core::ffi::c_int {
            return true_0 != 0;
        }
        i += 1;
    }
    return false_0 != 0;
}
#[inline]
unsafe extern "C" fn csp_rdp_rx_queue_add(
    mut conn: *mut csp_conn_t,
    mut packet: *mut csp_packet_t,
    mut seq_nr: uint16_t,
) -> ::core::ffi::c_int {
    if csp_rdp_seq_in_rx_queue(conn, seq_nr) {
        if csp_dbg_rdp_print as ::core::ffi::c_int >= 2 as ::core::ffi::c_int {
            csp_print_func(
                b"\x1B[34mRDP %p: Already exists in RX queue %u\n\x1B[0m\0" as *const u8
                    as *const ::core::ffi::c_char,
                conn as *mut ::core::ffi::c_void,
                seq_nr as ::core::ffi::c_int,
            );
        }
        return CSP_ERR_USED;
    }
    if csp_dbg_rdp_print as ::core::ffi::c_int >= 2 as ::core::ffi::c_int {
        csp_print_func(
            b"\x1B[34mRDP %p: Add to RX queue %u\n\x1B[0m\0" as *const u8
                as *const ::core::ffi::c_char,
            conn as *mut ::core::ffi::c_void,
            seq_nr as ::core::ffi::c_int,
        );
    }
    csp_rdp_queue_rx_add(conn, packet);
    return CSP_ERR_NONE;
}
#[inline]
unsafe extern "C" fn csp_rdp_should_ack(mut conn: *mut csp_conn_t) -> bool {
    if (*conn).rdp.delayed_acks == 0 {
        return true_0 != 0;
    }
    let mut time_now: uint32_t = csp_get_ms();
    if csp_rdp_time_after(
        time_now,
        (*conn).rdp.ack_timestamp.wrapping_add((*conn).rdp.ack_timeout),
    ) != 0
    {
        return true_0 != 0;
    }
    if csp_rdp_seq_after(
        (*conn).rdp.rcv_cur,
        ((*conn).rdp.rcv_lsa as uint32_t).wrapping_add((*conn).rdp.ack_delay_count)
            as uint16_t,
    ) != 0
    {
        return true_0 != 0;
    }
    return false_0 != 0;
}
#[no_mangle]
pub unsafe extern "C" fn csp_rdp_check_ack(
    mut conn: *mut csp_conn_t,
) -> ::core::ffi::c_int {
    if (abs(CSP_CONN_RXQUEUE_LEN - csp_queue_size((*conn).rx_queue)) as uint32_t)
        < (*conn).rdp.window_size
    {
        return CSP_ERR_NONE;
    }
    if csp_rdp_should_ack(conn) {
        csp_rdp_send_cmp(
            conn,
            ::core::ptr::null_mut::<csp_packet_t>(),
            RDP_ACK,
            (*conn).rdp.snd_nxt as ::core::ffi::c_int,
            (*conn).rdp.rcv_cur as ::core::ffi::c_int,
        );
    }
    return CSP_ERR_NONE;
}
#[inline]
unsafe extern "C" fn csp_rdp_is_conn_ready_for_tx(mut conn: *mut csp_conn_t) -> bool {
    if csp_rdp_seq_after(
        (*conn).rdp.snd_nxt,
        ((*conn).rdp.snd_una as uint32_t)
            .wrapping_add((*conn).rdp.window_size)
            .wrapping_sub(1 as uint32_t) as uint16_t,
    ) != 0
    {
        return false_0 != 0;
    }
    return true_0 != 0;
}
#[no_mangle]
pub unsafe extern "C" fn csp_rdp_check_timeouts(mut conn: *mut csp_conn_t) {
    let time_now: uint32_t = csp_get_ms() as uint32_t;
    if !(*conn).dest_socket.is_null() {
        if csp_rdp_time_after(
            time_now,
            (*conn).timestamp.wrapping_add((*conn).rdp.conn_timeout),
        ) != 0
        {
            if csp_dbg_rdp_print as ::core::ffi::c_int >= 1 as ::core::ffi::c_int {
                csp_print_func(
                    b"\x1B[31mRDP %p: Found a lost connection (now: %u, ts: %u, to: %u), closing\n\x1B[0m\0"
                        as *const u8 as *const ::core::ffi::c_char,
                    conn as *mut ::core::ffi::c_void,
                    time_now,
                    (*conn).timestamp,
                    (*conn).rdp.conn_timeout,
                );
            }
            csp_conn_close(
                conn,
                (CSP_RDP_CLOSED_BY_USERSPACE | CSP_RDP_CLOSED_BY_PROTOCOL
                    | CSP_RDP_CLOSED_BY_TIMEOUT) as uint8_t,
            );
            return;
        }
    }
    if (*conn).rdp.state as ::core::ffi::c_uint
        == RDP_CLOSE_WAIT as ::core::ffi::c_int as ::core::ffi::c_uint
    {
        if csp_rdp_time_after(
            time_now,
            (*conn).timestamp.wrapping_add((*conn).rdp.conn_timeout),
        ) != 0
        {
            csp_conn_close(
                conn,
                (CSP_RDP_CLOSED_BY_PROTOCOL | CSP_RDP_CLOSED_BY_TIMEOUT) as uint8_t,
            );
            return;
        }
    }
    let mut retransmitted: bool = false_0 != 0;
    let mut count: ::core::ffi::c_int = csp_rdp_queue_tx_size();
    let mut i: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
    while i < count {
        let mut packet: *mut csp_packet_t = ::core::ptr::null_mut::<csp_packet_t>();
        packet = csp_rdp_queue_tx_get(conn);
        if packet.is_null() {
            break;
        }
        let mut header: *mut rdp_header_t = csp_rdp_header_ref(packet);
        if csp_rdp_seq_before(
            __bswap_16((*header).seq_nr as __uint16_t) as uint16_t,
            (*conn).rdp.snd_una,
        ) != 0
        {
            if csp_dbg_rdp_print as ::core::ffi::c_int >= 2 as ::core::ffi::c_int {
                csp_print_func(
                    b"\x1B[34mRDP %p: TX Element Free, time %u, seq %u, una %u\n\x1B[0m\0"
                        as *const u8 as *const ::core::ffi::c_char,
                    conn as *mut ::core::ffi::c_void,
                    (*packet).timestamp_tx,
                    __bswap_16((*header).seq_nr as __uint16_t) as ::core::ffi::c_int,
                    (*conn).rdp.snd_una as ::core::ffi::c_int,
                );
            }
            csp_buffer_free(packet as *mut ::core::ffi::c_void);
        } else {
            if csp_rdp_time_after(
                time_now,
                (*packet).timestamp_tx.wrapping_add((*conn).rdp.packet_timeout),
            ) != 0
            {
                let mut new_packet: *mut csp_packet_t = csp_buffer_get(0 as size_t);
                if !new_packet.is_null() {
                    if csp_dbg_rdp_print as ::core::ffi::c_int >= 2 as ::core::ffi::c_int
                    {
                        csp_print_func(
                            b"\x1B[34mRDP %p: TX Element timed out, retransmitting seq %u\n\x1B[0m\0"
                                as *const u8 as *const ::core::ffi::c_char,
                            conn as *mut ::core::ffi::c_void,
                            __bswap_16((*header).seq_nr as __uint16_t)
                                as ::core::ffi::c_int,
                        );
                    }
                    (*header).ack_nr = __bswap_16((*conn).rdp.rcv_cur as __uint16_t)
                        as uint16_t;
                    (*conn).rdp.ack_timestamp = csp_get_ms();
                    (*packet).timestamp_tx = csp_get_ms();
                    csp_buffer_copy(packet, new_packet);
                    csp_send_direct(
                        &raw mut (*conn).idout,
                        new_packet,
                        ::core::ptr::null_mut::<csp_iface_t>(),
                    );
                    retransmitted = true_0 != 0;
                } else if csp_dbg_rdp_print as ::core::ffi::c_int
                    >= 1 as ::core::ffi::c_int
                {
                    csp_print_func(
                        b"\x1B[31mRDP %p: Failed to allocate packet buffer\n\x1B[0m\0"
                            as *const u8 as *const ::core::ffi::c_char,
                        conn as *mut ::core::ffi::c_void,
                    );
                }
            }
            csp_rdp_queue_tx_add(conn, packet);
        }
        i += 1;
    }
    if retransmitted as ::core::ffi::c_int != 0
        && {
            (*conn).rdp.retransmits = (*conn).rdp.retransmits.wrapping_add(1);
            (*conn).rdp.retransmits > CSP_RDP_MAX_RETRANSMITS as uint32_t
        }
    {
        if csp_dbg_rdp_print as ::core::ffi::c_int >= 1 as ::core::ffi::c_int {
            csp_print_func(
                b"\x1B[31mRDP %p: No progress after %u retransmissions, closing\n\x1B[0m\0"
                    as *const u8 as *const ::core::ffi::c_char,
                conn as *mut ::core::ffi::c_void,
                10 as ::core::ffi::c_int as ::core::ffi::c_uint,
            );
        }
        let mut closed_by: uint8_t = (CSP_RDP_CLOSED_BY_PROTOCOL
            | CSP_RDP_CLOSED_BY_TIMEOUT) as uint8_t;
        if !(*conn).dest_socket.is_null() {
            closed_by = (closed_by as ::core::ffi::c_int | CSP_RDP_CLOSED_BY_USERSPACE)
                as uint8_t;
        }
        csp_conn_close(conn, closed_by);
        csp_bin_sem_post(&raw mut (*conn).rdp.tx_wait);
        return;
    }
    if (*conn).rdp.state as ::core::ffi::c_uint
        == RDP_OPEN as ::core::ffi::c_int as ::core::ffi::c_uint
    {
        if csp_rdp_time_after(
            time_now,
            (*conn).timestamp.wrapping_add((*conn).rdp.conn_timeout),
        ) != 0
        {
            csp_conn_close(
                conn,
                (CSP_RDP_CLOSED_BY_PROTOCOL | CSP_RDP_CLOSED_BY_TIMEOUT) as uint8_t,
            );
            csp_bin_sem_post(&raw mut (*conn).rdp.tx_wait);
            return;
        }
        if (*conn).rdp.delayed_acks != 0 {
            csp_rdp_check_ack(conn);
        }
        if csp_rdp_is_conn_ready_for_tx(conn) {
            csp_bin_sem_post(&raw mut (*conn).rdp.tx_wait);
        }
    }
    csp_rdp_rx_queue_flush(conn);
}
#[no_mangle]
pub unsafe extern "C" fn csp_rdp_new_packet(
    mut conn: *mut csp_conn_t,
    mut packet: *mut csp_packet_t,
) -> bool {
    let mut current_block: u64;
    let mut close_connection: bool = false_0 != 0;
    let mut rx_header: *mut rdp_header_t = csp_rdp_header_ref(packet);
    (*rx_header).ack_nr = __bswap_16((*rx_header).ack_nr as __uint16_t) as uint16_t;
    (*rx_header).seq_nr = __bswap_16((*rx_header).seq_nr as __uint16_t) as uint16_t;
    let mut closed_by: uint8_t = CSP_RDP_CLOSED_BY_PROTOCOL as uint8_t;
    if csp_dbg_rdp_print as ::core::ffi::c_int >= 2 as ::core::ffi::c_int {
        csp_print_func(
            b"\x1B[34mRDP %p: Received in S %u: syn %u, ack %u, eack %u, rst %u, seq_nr %5u, ack_nr %5u, packet_len %u (%u)\n\x1B[0m\0"
                as *const u8 as *const ::core::ffi::c_char,
            conn as *mut ::core::ffi::c_void,
            (*conn).rdp.state as ::core::ffi::c_uint,
            ((*rx_header).flags as ::core::ffi::c_int & 0x8 as ::core::ffi::c_int
                != 0 as ::core::ffi::c_int) as ::core::ffi::c_int,
            ((*rx_header).flags as ::core::ffi::c_int & 0x4 as ::core::ffi::c_int
                != 0 as ::core::ffi::c_int) as ::core::ffi::c_int,
            ((*rx_header).flags as ::core::ffi::c_int & 0x2 as ::core::ffi::c_int
                != 0 as ::core::ffi::c_int) as ::core::ffi::c_int,
            ((*rx_header).flags as ::core::ffi::c_int & 0x1 as ::core::ffi::c_int
                != 0 as ::core::ffi::c_int) as ::core::ffi::c_int,
            (*rx_header).seq_nr as ::core::ffi::c_int,
            (*rx_header).ack_nr as ::core::ffi::c_int,
            (*packet).length as ::core::ffi::c_int,
            ((*packet).length as usize)
                .wrapping_sub(::core::mem::size_of::<rdp_header_t>() as usize)
                as ::core::ffi::c_uint,
        );
    }
    if (*rx_header).flags as ::core::ffi::c_int & RDP_RST != 0 {
        if (*rx_header).flags as ::core::ffi::c_int & RDP_ACK != 0 {
            (*conn).rdp.snd_una = ((*rx_header).ack_nr as ::core::ffi::c_int
                + 1 as ::core::ffi::c_int) as uint16_t;
        }
        if (*conn).rdp.state as ::core::ffi::c_uint
            == RDP_CLOSED as ::core::ffi::c_int as ::core::ffi::c_uint
        {
            if csp_dbg_rdp_print as ::core::ffi::c_int >= 2 as ::core::ffi::c_int {
                csp_print_func(
                    b"\x1B[34mRDP %p: RST received in CLOSED - ignored\n\x1B[0m\0"
                        as *const u8 as *const ::core::ffi::c_char,
                    conn as *mut ::core::ffi::c_void,
                );
            }
            close_connection = !(*conn).dest_socket.is_null();
            current_block = 5293619145580216047;
        } else if (*conn).rdp.state as ::core::ffi::c_uint
            == RDP_CLOSE_WAIT as ::core::ffi::c_int as ::core::ffi::c_uint
        {
            if csp_dbg_rdp_print as ::core::ffi::c_int >= 2 as ::core::ffi::c_int {
                csp_print_func(
                    b"\x1B[34mRDP %p: RST received in CLOSE_WAIT, ack: %d - closing\n\x1B[0m\0"
                        as *const u8 as *const ::core::ffi::c_char,
                    conn as *mut ::core::ffi::c_void,
                    (*rx_header).flags as ::core::ffi::c_int & 0x4 as ::core::ffi::c_int,
                );
            }
            if (*rx_header).flags as ::core::ffi::c_int & RDP_ACK != 0
                && CSP_USE_RDP_FAST_CLOSE != 0
            {
                closed_by = (closed_by as ::core::ffi::c_int | CSP_RDP_CLOSED_BY_TIMEOUT)
                    as uint8_t;
            }
            current_block = 14066215848136132313;
        } else if (*rx_header).seq_nr as ::core::ffi::c_int
            == ((*conn).rdp.rcv_cur as ::core::ffi::c_int + 1 as ::core::ffi::c_int)
                as uint16_t as ::core::ffi::c_int
        {
            if csp_dbg_rdp_print as ::core::ffi::c_int >= 2 as ::core::ffi::c_int {
                csp_print_func(
                    b"\x1B[34mRDP %p: Received RST in sequence, no more data incoming, reply with RST\n\x1B[0m\0"
                        as *const u8 as *const ::core::ffi::c_char,
                    conn as *mut ::core::ffi::c_void,
                );
            }
            (*conn).rdp.state = RDP_CLOSE_WAIT;
            (*conn).timestamp = csp_get_ms();
            csp_rdp_send_cmp(
                conn,
                ::core::ptr::null_mut::<csp_packet_t>(),
                RDP_ACK | RDP_RST,
                (*conn).rdp.snd_nxt as ::core::ffi::c_int,
                (*conn).rdp.rcv_cur as ::core::ffi::c_int,
            );
            closed_by = (closed_by as ::core::ffi::c_int | CSP_RDP_CLOSED_BY_TIMEOUT)
                as uint8_t;
            current_block = 14066215848136132313;
        } else {
            if csp_dbg_rdp_print as ::core::ffi::c_int >= 2 as ::core::ffi::c_int {
                csp_print_func(
                    b"\x1B[34mRDP %p: RST out of sequence, keep connection open\n\x1B[0m\0"
                        as *const u8 as *const ::core::ffi::c_char,
                    conn as *mut ::core::ffi::c_void,
                );
            }
            current_block = 5293619145580216047;
        }
    } else {
        match (*conn).rdp.state as ::core::ffi::c_uint {
            0 => {
                let mut rx_header_flags: uint8_t = ((*rx_header).flags
                    as ::core::ffi::c_int & 0xf as ::core::ffi::c_int) as uint8_t;
                if rx_header_flags as ::core::ffi::c_int != RDP_SYN {
                    if csp_dbg_rdp_print as ::core::ffi::c_int >= 2 as ::core::ffi::c_int
                    {
                        csp_print_func(
                            b"\x1B[34mRDP %p: Not SYN received in CLOSED state. Discarding packet\n\x1B[0m\0"
                                as *const u8 as *const ::core::ffi::c_char,
                            conn as *mut ::core::ffi::c_void,
                        );
                    }
                    csp_rdp_send_cmp(
                        conn,
                        ::core::ptr::null_mut::<csp_packet_t>(),
                        RDP_RST,
                        (*conn).rdp.snd_nxt as ::core::ffi::c_int,
                        (*conn).rdp.rcv_cur as ::core::ffi::c_int,
                    );
                    current_block = 14066215848136132313;
                } else {
                    if csp_dbg_rdp_print as ::core::ffi::c_int >= 2 as ::core::ffi::c_int
                    {
                        csp_print_func(
                            b"\x1B[34mRDP %p: SYN-Received\n\x1B[0m\0" as *const u8
                                as *const ::core::ffi::c_char,
                            conn as *mut ::core::ffi::c_void,
                        );
                    }
                    let mut seed: ::core::ffi::c_uint = csp_get_ms()
                        as ::core::ffi::c_uint;
                    (*conn).rdp.snd_iss = rand_r(&raw mut seed) as uint16_t;
                    (*conn).rdp.snd_nxt = ((*conn).rdp.snd_iss as ::core::ffi::c_int
                        + 1 as ::core::ffi::c_int) as uint16_t;
                    (*conn).rdp.snd_una = (*conn).rdp.snd_iss;
                    (*conn).rdp.rcv_cur = (*rx_header).seq_nr;
                    (*conn).rdp.rcv_irs = (*rx_header).seq_nr;
                    (*conn).rdp.rcv_lsa = (*rx_header).seq_nr;
                    if ((*packet).length as usize)
                        < RDP_SYN_OPTIONS_SIZE
                            .wrapping_add(
                                ::core::mem::size_of::<rdp_header_t>() as usize,
                            )
                    {
                        if csp_dbg_rdp_print as ::core::ffi::c_int
                            >= 1 as ::core::ffi::c_int
                        {
                            csp_print_func(
                                b"\x1B[31mRDP %p: SYN without a complete option block\n\x1B[0m\0"
                                    as *const u8 as *const ::core::ffi::c_char,
                                conn as *mut ::core::ffi::c_void,
                            );
                        }
                        csp_rdp_send_cmp(
                            conn,
                            ::core::ptr::null_mut::<csp_packet_t>(),
                            RDP_RST,
                            (*conn).rdp.snd_nxt as ::core::ffi::c_int,
                            (*conn).rdp.rcv_cur as ::core::ffi::c_int,
                        );
                        current_block = 14066215848136132313;
                    } else {
                        (*conn).rdp.window_size = csp_rdp_clamp(
                            __bswap_32(
                                (*packet)
                                    .c2rust_unnamed
                                    .data32[0 as ::core::ffi::c_int as usize],
                            ) as uint32_t,
                            1 as uint32_t,
                            CSP_RDP_MAX_WINDOW as uint32_t,
                        );
                        (*conn).rdp.conn_timeout = csp_rdp_clamp(
                            __bswap_32(
                                (*packet)
                                    .c2rust_unnamed
                                    .data32[1 as ::core::ffi::c_int as usize],
                            ) as uint32_t,
                            CSP_RDP_MIN_CONN_TIMEOUT as uint32_t,
                            CSP_RDP_MAX_CONN_TIMEOUT as uint32_t,
                        );
                        (*conn).rdp.packet_timeout = csp_rdp_clamp(
                            __bswap_32(
                                (*packet)
                                    .c2rust_unnamed
                                    .data32[2 as ::core::ffi::c_int as usize],
                            ) as uint32_t,
                            CSP_RDP_MIN_PACKET_TIMEOUT as uint32_t,
                            CSP_RDP_MAX_PACKET_TIMEOUT as uint32_t,
                        );
                        (*conn).rdp.delayed_acks = (__bswap_32(
                            (*packet)
                                .c2rust_unnamed
                                .data32[3 as ::core::ffi::c_int as usize],
                        ) != 0 as __uint32_t) as ::core::ffi::c_int as uint32_t;
                        (*conn).rdp.ack_timeout = csp_rdp_clamp(
                            __bswap_32(
                                (*packet)
                                    .c2rust_unnamed
                                    .data32[4 as ::core::ffi::c_int as usize],
                            ) as uint32_t,
                            CSP_RDP_MIN_ACK_TIMEOUT as uint32_t,
                            (*conn).rdp.conn_timeout,
                        );
                        (*conn).rdp.ack_delay_count = csp_rdp_clamp(
                            __bswap_32(
                                (*packet)
                                    .c2rust_unnamed
                                    .data32[5 as ::core::ffi::c_int as usize],
                            ) as uint32_t,
                            1 as uint32_t,
                            (*conn).rdp.window_size,
                        );
                        if csp_dbg_rdp_print as ::core::ffi::c_int
                            >= 2 as ::core::ffi::c_int
                        {
                            csp_print_func(
                                b"\x1B[34mRDP %p: window size %u, conn timeout %u, packet timeout %u, delayed acks: %u, ack timeout %u, ack each %u packet\n\x1B[0m\0"
                                    as *const u8 as *const ::core::ffi::c_char,
                                conn as *mut ::core::ffi::c_void,
                                (*conn).rdp.window_size,
                                (*conn).rdp.conn_timeout,
                                (*conn).rdp.packet_timeout,
                                (*conn).rdp.delayed_acks,
                                (*conn).rdp.ack_timeout,
                                (*conn).rdp.ack_delay_count,
                            );
                        }
                        (*conn).rdp.state = RDP_SYN_RCVD;
                        csp_rdp_send_cmp(
                            conn,
                            ::core::ptr::null_mut::<csp_packet_t>(),
                            RDP_ACK | RDP_SYN,
                            (*conn).rdp.snd_iss as ::core::ffi::c_int,
                            (*conn).rdp.rcv_irs as ::core::ffi::c_int,
                        );
                        current_block = 5293619145580216047;
                    }
                }
            }
            1 => {
                if (*rx_header).flags as ::core::ffi::c_int & RDP_SYN != 0
                    && (*rx_header).flags as ::core::ffi::c_int & RDP_ACK != 0
                {
                    (*conn).rdp.rcv_cur = (*rx_header).seq_nr;
                    (*conn).rdp.rcv_irs = (*rx_header).seq_nr;
                    (*conn).rdp.rcv_lsa = ((*rx_header).seq_nr as ::core::ffi::c_int
                        - 1 as ::core::ffi::c_int) as uint16_t;
                    (*conn).rdp.snd_una = ((*rx_header).ack_nr as ::core::ffi::c_int
                        + 1 as ::core::ffi::c_int) as uint16_t;
                    (*conn).rdp.retransmits = 0 as uint32_t;
                    (*conn).rdp.ack_timestamp = csp_get_ms();
                    (*conn).rdp.state = RDP_OPEN;
                    if csp_dbg_rdp_print as ::core::ffi::c_int >= 2 as ::core::ffi::c_int
                    {
                        csp_print_func(
                            b"\x1B[34mRDP %p: NP: Connection OPEN\n\x1B[0m\0"
                                as *const u8 as *const ::core::ffi::c_char,
                            conn as *mut ::core::ffi::c_void,
                        );
                    }
                    csp_rdp_send_cmp(
                        conn,
                        ::core::ptr::null_mut::<csp_packet_t>(),
                        RDP_ACK,
                        (*conn).rdp.snd_nxt as ::core::ffi::c_int,
                        (*conn).rdp.rcv_cur as ::core::ffi::c_int,
                    );
                    if csp_dbg_rdp_print as ::core::ffi::c_int >= 2 as ::core::ffi::c_int
                    {
                        csp_print_func(
                            b"\x1B[34mRDP %p: Wake Tx task (ack)\n\x1B[0m\0" as *const u8
                                as *const ::core::ffi::c_char,
                            conn as *mut ::core::ffi::c_void,
                        );
                    }
                    csp_bin_sem_post(&raw mut (*conn).rdp.tx_wait);
                    current_block = 5293619145580216047;
                } else if (*rx_header).flags as ::core::ffi::c_int & RDP_ACK != 0 {
                    if csp_dbg_rdp_print as ::core::ffi::c_int >= 1 as ::core::ffi::c_int
                    {
                        csp_print_func(
                            b"\x1B[31mRDP %p: Half-open connection found, send RST and wake Tx task\n\x1B[0m\0"
                                as *const u8 as *const ::core::ffi::c_char,
                            conn as *mut ::core::ffi::c_void,
                        );
                    }
                    csp_rdp_send_cmp(
                        conn,
                        ::core::ptr::null_mut::<csp_packet_t>(),
                        RDP_RST,
                        (*conn).rdp.snd_nxt as ::core::ffi::c_int,
                        (*conn).rdp.rcv_cur as ::core::ffi::c_int,
                    );
                    csp_bin_sem_post(&raw mut (*conn).rdp.tx_wait);
                    current_block = 5293619145580216047;
                } else {
                    if csp_dbg_rdp_print as ::core::ffi::c_int >= 1 as ::core::ffi::c_int
                    {
                        csp_print_func(
                            b"\x1B[31mRDP %p: Invalid reply to SYN request\n\x1B[0m\0"
                                as *const u8 as *const ::core::ffi::c_char,
                            conn as *mut ::core::ffi::c_void,
                        );
                    }
                    current_block = 14066215848136132313;
                }
            }
            2 | 3 => {
                if (*rx_header).flags as ::core::ffi::c_int & RDP_SYN != 0
                    || (*rx_header).flags as ::core::ffi::c_int & RDP_ACK == 0
                {
                    if (*rx_header).seq_nr as ::core::ffi::c_int
                        != (*conn).rdp.rcv_irs as ::core::ffi::c_int
                    {
                        if csp_dbg_rdp_print as ::core::ffi::c_int
                            >= 1 as ::core::ffi::c_int
                        {
                            csp_print_func(
                                b"\x1B[31mRDP %p: Invalid SYN or no ACK, resetting!\n\x1B[0m\0"
                                    as *const u8 as *const ::core::ffi::c_char,
                                conn as *mut ::core::ffi::c_void,
                            );
                        }
                        current_block = 14066215848136132313;
                    } else {
                        if csp_dbg_rdp_print as ::core::ffi::c_int
                            >= 2 as ::core::ffi::c_int
                        {
                            csp_print_func(
                                b"\x1B[34mRDP %p: Ignoring duplicate SYN packet!\n\x1B[0m\0"
                                    as *const u8 as *const ::core::ffi::c_char,
                                conn as *mut ::core::ffi::c_void,
                            );
                        }
                        current_block = 5293619145580216047;
                    }
                } else if csp_rdp_seq_between(
                    (*rx_header).seq_nr,
                    ((*conn).rdp.rcv_cur as ::core::ffi::c_int + 1 as ::core::ffi::c_int)
                        as uint16_t,
                    ((*conn).rdp.rcv_cur as uint32_t)
                        .wrapping_add(
                            (*conn).rdp.window_size.wrapping_mul(2 as uint32_t),
                        ) as uint16_t,
                ) == 0
                {
                    if csp_dbg_rdp_print as ::core::ffi::c_int >= 2 as ::core::ffi::c_int
                    {
                        csp_print_func(
                            b"\x1B[34mRDP %p: Invalid sequence number! %u not between %u and %u\n\x1B[0m\0"
                                as *const u8 as *const ::core::ffi::c_char,
                            conn as *mut ::core::ffi::c_void,
                            (*rx_header).seq_nr as ::core::ffi::c_int,
                            ((*conn).rdp.rcv_cur as ::core::ffi::c_uint)
                                .wrapping_add(1 as ::core::ffi::c_uint),
                            ((*conn).rdp.rcv_cur as uint32_t)
                                .wrapping_add(
                                    (*conn).rdp.window_size.wrapping_mul(2 as uint32_t),
                                ),
                        );
                    }
                    if (*conn).rdp.state as ::core::ffi::c_uint
                        == RDP_SYN_RCVD as ::core::ffi::c_int as ::core::ffi::c_uint
                    {
                        csp_rdp_send_cmp(
                            conn,
                            ::core::ptr::null_mut::<csp_packet_t>(),
                            RDP_ACK | RDP_SYN,
                            (*conn).rdp.snd_iss as ::core::ffi::c_int,
                            (*conn).rdp.rcv_irs as ::core::ffi::c_int,
                        );
                    }
                    current_block = 5293619145580216047;
                } else if csp_rdp_seq_between(
                    (*rx_header).ack_nr,
                    (((*conn).rdp.snd_una as ::core::ffi::c_int
                        - 1 as ::core::ffi::c_int) as uint32_t)
                        .wrapping_sub(
                            (*conn).rdp.window_size.wrapping_mul(2 as uint32_t),
                        ) as uint16_t,
                    ((*conn).rdp.snd_nxt as ::core::ffi::c_int - 1 as ::core::ffi::c_int)
                        as uint16_t,
                ) == 0
                {
                    if csp_dbg_rdp_print as ::core::ffi::c_int >= 1 as ::core::ffi::c_int
                    {
                        csp_print_func(
                            b"\x1B[31mRDP %p: Invalid ACK number! %u not between %u and %u\n\x1B[0m\0"
                                as *const u8 as *const ::core::ffi::c_char,
                            conn as *mut ::core::ffi::c_void,
                            (*rx_header).ack_nr as ::core::ffi::c_int,
                            (((*conn).rdp.snd_una as ::core::ffi::c_int
                                - 1 as ::core::ffi::c_int) as uint32_t)
                                .wrapping_sub(
                                    (*conn).rdp.window_size.wrapping_mul(2 as uint32_t),
                                ),
                            (*conn).rdp.snd_nxt as ::core::ffi::c_int
                                - 1 as ::core::ffi::c_int,
                        );
                    }
                    current_block = 5293619145580216047;
                } else {
                    if (*conn).rdp.state as ::core::ffi::c_uint
                        == RDP_SYN_RCVD as ::core::ffi::c_int as ::core::ffi::c_uint
                    {
                        if (*rx_header).ack_nr as ::core::ffi::c_int
                            != (*conn).rdp.snd_iss as ::core::ffi::c_int
                        {
                            if csp_dbg_rdp_print as ::core::ffi::c_int
                                >= 1 as ::core::ffi::c_int
                            {
                                csp_print_func(
                                    b"\x1B[31mRDP %p: SYN-RCVD: Wrong ACK number\n\x1B[0m\0"
                                        as *const u8 as *const ::core::ffi::c_char,
                                    conn as *mut ::core::ffi::c_void,
                                );
                            }
                            current_block = 14066215848136132313;
                        } else {
                            if csp_dbg_rdp_print as ::core::ffi::c_int
                                >= 2 as ::core::ffi::c_int
                            {
                                csp_print_func(
                                    b"\x1B[34mRDP %p: NC: Connection OPEN\n\x1B[0m\0"
                                        as *const u8 as *const ::core::ffi::c_char,
                                    conn as *mut ::core::ffi::c_void,
                                );
                            }
                            (*conn).rdp.state = RDP_OPEN;
                            if !(*conn).dest_socket.is_null() {
                                if csp_queue_enqueue(
                                    (*(*conn).dest_socket).rx_queue,
                                    &raw mut conn as *const ::core::ffi::c_void,
                                    0 as uint32_t,
                                ) == CSP_QUEUE_ERROR
                                {
                                    if csp_dbg_rdp_print as ::core::ffi::c_int
                                        >= 1 as ::core::ffi::c_int
                                    {
                                        csp_print_func(
                                            b"\x1B[31mRDP %p: ERROR socket cannot accept more connections\n\x1B[0m\0"
                                                as *const u8 as *const ::core::ffi::c_char,
                                            conn as *mut ::core::ffi::c_void,
                                        );
                                    }
                                    current_block = 14066215848136132313;
                                } else {
                                    (*conn).dest_socket = ::core::ptr::null_mut::<
                                        csp_socket_t,
                                    >();
                                    current_block = 12099607619007264150;
                                }
                            } else {
                                current_block = 12099607619007264150;
                            }
                        }
                    } else {
                        current_block = 12099607619007264150;
                    }
                    match current_block {
                        14066215848136132313 => {}
                        _ => {
                            if (*conn).dest_socket.is_null() {
                                (*conn).timestamp = csp_get_ms();
                            }
                            (*conn).rdp.snd_una = ((*rx_header).ack_nr
                                as ::core::ffi::c_int + 1 as ::core::ffi::c_int)
                                as uint16_t;
                            (*conn).rdp.retransmits = 0 as uint32_t;
                            if (*rx_header).flags as ::core::ffi::c_int & RDP_EAK != 0 {
                                if csp_dbg_rdp_print as ::core::ffi::c_int
                                    >= 2 as ::core::ffi::c_int
                                {
                                    csp_print_func(
                                        b"\x1B[34mRDP %p: Got EACK\n\x1B[0m\0" as *const u8
                                            as *const ::core::ffi::c_char,
                                        conn as *mut ::core::ffi::c_void,
                                    );
                                }
                                current_block = 5293619145580216047;
                            } else if (*packet).length as usize
                                <= ::core::mem::size_of::<rdp_header_t>() as usize
                            {
                                current_block = 5293619145580216047;
                            } else if (*rx_header).seq_nr as ::core::ffi::c_int
                                != ((*conn).rdp.rcv_cur as ::core::ffi::c_int
                                    + 1 as ::core::ffi::c_int) as uint16_t as ::core::ffi::c_int
                            {
                                if csp_rdp_rx_queue_add(conn, packet, (*rx_header).seq_nr)
                                    != CSP_ERR_NONE
                                {
                                    csp_rdp_check_ack(conn);
                                    current_block = 5293619145580216047;
                                } else {
                                    current_block = 6507493651122679119;
                                }
                            } else {
                                let mut seq_nr: uint16_t = (*rx_header).seq_nr;
                                if csp_rdp_receive_data(conn, packet) != CSP_ERR_NONE {
                                    current_block = 5293619145580216047;
                                } else {
                                    (*conn).rdp.rcv_cur = seq_nr;
                                    csp_rdp_check_ack(conn);
                                    csp_rdp_rx_queue_flush(conn);
                                    current_block = 6507493651122679119;
                                }
                            }
                        }
                    }
                }
            }
            4 => {
                if (*rx_header).flags as ::core::ffi::c_int & RDP_SYN != 0
                    || (*rx_header).flags as ::core::ffi::c_int & RDP_ACK == 0
                {
                    if csp_dbg_rdp_print as ::core::ffi::c_int >= 2 as ::core::ffi::c_int
                    {
                        csp_print_func(
                            b"\x1B[34mRDP %p: Invalid SYN or no ACK in CLOSE-WAIT\n\x1B[0m\0"
                                as *const u8 as *const ::core::ffi::c_char,
                            conn as *mut ::core::ffi::c_void,
                        );
                    }
                } else if csp_rdp_seq_between(
                    (*rx_header).ack_nr,
                    (((*conn).rdp.snd_una as ::core::ffi::c_int
                        - 1 as ::core::ffi::c_int) as uint32_t)
                        .wrapping_sub(
                            (*conn).rdp.window_size.wrapping_mul(2 as uint32_t),
                        ) as uint16_t,
                    ((*conn).rdp.snd_nxt as ::core::ffi::c_int - 1 as ::core::ffi::c_int)
                        as uint16_t,
                ) == 0
                {
                    if csp_dbg_rdp_print as ::core::ffi::c_int >= 1 as ::core::ffi::c_int
                    {
                        csp_print_func(
                            b"\x1B[31mRDP %p: Invalid ACK number! %u not between %u and %u\n\x1B[0m\0"
                                as *const u8 as *const ::core::ffi::c_char,
                            conn as *mut ::core::ffi::c_void,
                            (*rx_header).ack_nr as ::core::ffi::c_int,
                            (((*conn).rdp.snd_una as ::core::ffi::c_int
                                - 1 as ::core::ffi::c_int) as uint32_t)
                                .wrapping_sub(
                                    (*conn).rdp.window_size.wrapping_mul(2 as uint32_t),
                                ),
                            (*conn).rdp.snd_nxt as ::core::ffi::c_int
                                - 1 as ::core::ffi::c_int,
                        );
                    }
                } else {
                    (*conn).rdp.snd_una = ((*rx_header).ack_nr as ::core::ffi::c_int
                        + 1 as ::core::ffi::c_int) as uint16_t;
                    csp_rdp_send_cmp(
                        conn,
                        ::core::ptr::null_mut::<csp_packet_t>(),
                        RDP_ACK | RDP_RST,
                        (*conn).rdp.snd_nxt as ::core::ffi::c_int,
                        (*conn).rdp.rcv_cur as ::core::ffi::c_int,
                    );
                }
                current_block = 5293619145580216047;
            }
            _ => {
                if csp_dbg_rdp_print as ::core::ffi::c_int >= 1 as ::core::ffi::c_int {
                    csp_print_func(
                        b"\x1B[31mRDP %p: ERROR default state!\n\x1B[0m\0" as *const u8
                            as *const ::core::ffi::c_char,
                        conn as *mut ::core::ffi::c_void,
                    );
                }
                current_block = 14066215848136132313;
            }
        }
    }
    match current_block {
        14066215848136132313 => {
            if (*conn).dest_socket.is_null() {
                csp_conn_close(conn, closed_by);
                csp_conn_enqueue_packet(conn, ::core::ptr::null_mut::<csp_packet_t>());
            } else {
                csp_conn_close(
                    conn,
                    (closed_by as ::core::ffi::c_int | CSP_RDP_CLOSED_BY_USERSPACE)
                        as uint8_t,
                );
            }
            current_block = 5293619145580216047;
        }
        _ => {}
    }
    match current_block {
        5293619145580216047 => {
            csp_buffer_free(packet as *mut ::core::ffi::c_void);
        }
        _ => {}
    }
    return close_connection;
}
#[no_mangle]
pub unsafe extern "C" fn csp_rdp_connect(
    mut conn: *mut csp_conn_t,
) -> ::core::ffi::c_int {
    let mut seed: ::core::ffi::c_uint = 0;
    let mut result: ::core::ffi::c_int = 0;
    let mut retry: ::core::ffi::c_int = 1 as ::core::ffi::c_int;
    (*conn).rdp.window_size = csp_rdp_window_size;
    (*conn).rdp.conn_timeout = csp_rdp_conn_timeout;
    (*conn).rdp.packet_timeout = csp_rdp_packet_timeout;
    (*conn).rdp.delayed_acks = csp_rdp_delayed_acks;
    (*conn).rdp.ack_timeout = csp_rdp_ack_timeout;
    (*conn).rdp.ack_delay_count = csp_rdp_ack_delay_count;
    (*conn).rdp.ack_timestamp = csp_get_ms();
    (*conn).rdp.retransmits = 0 as uint32_t;
    loop {
        if csp_dbg_rdp_print as ::core::ffi::c_int >= 2 as ::core::ffi::c_int {
            csp_print_func(
                b"\x1B[34mRDP %p: Active connect, conn state %u\n\x1B[0m\0" as *const u8
                    as *const ::core::ffi::c_char,
                conn as *mut ::core::ffi::c_void,
                (*conn).rdp.state as ::core::ffi::c_uint,
            );
        }
        if (*conn).rdp.state as ::core::ffi::c_uint
            == RDP_OPEN as ::core::ffi::c_int as ::core::ffi::c_uint
        {
            if csp_dbg_rdp_print as ::core::ffi::c_int >= 1 as ::core::ffi::c_int {
                csp_print_func(
                    b"\x1B[31mRDP %p: Connection already open\n\x1B[0m\0" as *const u8
                        as *const ::core::ffi::c_char,
                    conn as *mut ::core::ffi::c_void,
                );
            }
            return CSP_ERR_ALREADY;
        }
        seed = csp_get_ms() as ::core::ffi::c_uint;
        (*conn).rdp.snd_iss = rand_r(&raw mut seed) as uint16_t;
        (*conn).rdp.snd_nxt = ((*conn).rdp.snd_iss as ::core::ffi::c_int
            + 1 as ::core::ffi::c_int) as uint16_t;
        (*conn).rdp.snd_una = (*conn).rdp.snd_iss;
        if csp_dbg_rdp_print as ::core::ffi::c_int >= 2 as ::core::ffi::c_int {
            csp_print_func(
                b"\x1B[34mRDP %p: AC: Sending SYN\n\x1B[0m\0" as *const u8
                    as *const ::core::ffi::c_char,
                conn as *mut ::core::ffi::c_void,
            );
        }
        csp_bin_sem_wait(&raw mut (*conn).rdp.tx_wait, 0 as ::core::ffi::c_uint);
        (*conn).rdp.state = RDP_SYN_SENT;
        if csp_rdp_send_syn(conn) != CSP_ERR_NONE {
            break;
        }
        if csp_dbg_rdp_print as ::core::ffi::c_int >= 2 as ::core::ffi::c_int {
            csp_print_func(
                b"\x1B[34mRDP %p: AC: Waiting for SYN/ACK reply...\n\x1B[0m\0"
                    as *const u8 as *const ::core::ffi::c_char,
                conn as *mut ::core::ffi::c_void,
            );
        }
        result = csp_bin_sem_wait(
            &raw mut (*conn).rdp.tx_wait,
            (*conn).rdp.conn_timeout as ::core::ffi::c_uint,
        );
        if !(result == CSP_SEMAPHORE_OK) {
            break;
        }
        if (*conn).rdp.state as ::core::ffi::c_uint
            == RDP_OPEN as ::core::ffi::c_int as ::core::ffi::c_uint
        {
            if csp_dbg_rdp_print as ::core::ffi::c_int >= 2 as ::core::ffi::c_int {
                csp_print_func(
                    b"\x1B[34mRDP %p: AC: Connection OPEN\n\x1B[0m\0" as *const u8
                        as *const ::core::ffi::c_char,
                    conn as *mut ::core::ffi::c_void,
                );
            }
            return CSP_ERR_NONE;
        }
        if !((*conn).rdp.state as ::core::ffi::c_uint
            == RDP_SYN_SENT as ::core::ffi::c_int as ::core::ffi::c_uint)
        {
            break;
        }
        if retry != 0 {
            if csp_dbg_rdp_print as ::core::ffi::c_int >= 1 as ::core::ffi::c_int {
                csp_print_func(
                    b"\x1B[31mRDP %p: Half-open connection detected, RST sent, now retrying\n\x1B[0m\0"
                        as *const u8 as *const ::core::ffi::c_char,
                    conn as *mut ::core::ffi::c_void,
                );
            }
            csp_rdp_queue_flush(conn);
            retry = 0 as ::core::ffi::c_int;
        } else {
            if csp_dbg_rdp_print as ::core::ffi::c_int >= 1 as ::core::ffi::c_int {
                csp_print_func(
                    b"\x1B[31mRDP %p: Connection stayed half-open, even after RST and retry!\n\x1B[0m\0"
                        as *const u8 as *const ::core::ffi::c_char,
                    conn as *mut ::core::ffi::c_void,
                );
            }
            break;
        }
    }
    if csp_dbg_rdp_print as ::core::ffi::c_int >= 2 as ::core::ffi::c_int {
        csp_print_func(
            b"\x1B[34mRDP %p: AC: Connection Failed\n\x1B[0m\0" as *const u8
                as *const ::core::ffi::c_char,
            conn as *mut ::core::ffi::c_void,
        );
    }
    csp_rdp_close_internal(conn, CSP_RDP_CLOSED_BY_PROTOCOL as uint8_t, false_0 != 0);
    return CSP_ERR_TIMEDOUT;
}
#[no_mangle]
pub unsafe extern "C" fn csp_rdp_send(
    mut conn: *mut csp_conn_t,
    mut packet: *mut csp_packet_t,
) -> ::core::ffi::c_int {
    if (*conn).rdp.state as ::core::ffi::c_uint
        != RDP_OPEN as ::core::ffi::c_int as ::core::ffi::c_uint
    {
        if csp_dbg_rdp_print as ::core::ffi::c_int >= 1 as ::core::ffi::c_int {
            csp_print_func(
                b"\x1B[31mRDP %p: ERROR cannot send, connection not open (%d)\n\x1B[0m\0"
                    as *const u8 as *const ::core::ffi::c_char,
                conn as *mut ::core::ffi::c_void,
                (*conn).rdp.state as ::core::ffi::c_uint,
            );
        }
        return CSP_ERR_RESET;
    }
    loop {
        if (*conn).rdp.state as ::core::ffi::c_uint
            == RDP_CLOSE_WAIT as ::core::ffi::c_int as ::core::ffi::c_uint
            || (*conn).rdp.state as ::core::ffi::c_uint
                == RDP_CLOSED as ::core::ffi::c_int as ::core::ffi::c_uint
        {
            if csp_dbg_rdp_print as ::core::ffi::c_int >= 1 as ::core::ffi::c_int {
                csp_print_func(
                    b"\x1B[31mRDP %p: ERROR cannot send, connection closed by peer or timeout\n\x1B[0m\0"
                        as *const u8 as *const ::core::ffi::c_char,
                    conn as *mut ::core::ffi::c_void,
                );
            }
            return CSP_ERR_RESET;
        }
        if csp_rdp_is_conn_ready_for_tx(conn) as ::core::ffi::c_int == true_0 {
            break;
        }
        if csp_dbg_rdp_print as ::core::ffi::c_int >= 2 as ::core::ffi::c_int {
            csp_print_func(
                b"\x1B[34mRDP %p: Waiting for window update before sending seq %u\n\x1B[0m\0"
                    as *const u8 as *const ::core::ffi::c_char,
                conn as *mut ::core::ffi::c_void,
                (*conn).rdp.snd_nxt as ::core::ffi::c_int,
            );
        }
        csp_bin_sem_wait(
            &raw mut (*conn).rdp.tx_wait,
            (*conn).rdp.conn_timeout as ::core::ffi::c_uint,
        );
    }
    let mut tx_header: *mut rdp_header_t = csp_rdp_header_add(packet);
    if tx_header.is_null() {
        if csp_dbg_rdp_print as ::core::ffi::c_int >= 1 as ::core::ffi::c_int {
            csp_print_func(
                b"\x1B[31mRDP %p: No space for RDP header (send)\n\x1B[0m\0" as *const u8
                    as *const ::core::ffi::c_char,
                conn as *mut ::core::ffi::c_void,
            );
        }
        return CSP_ERR_NOMEM;
    }
    (*tx_header).ack_nr = __bswap_16((*conn).rdp.rcv_cur as __uint16_t) as uint16_t;
    (*tx_header).seq_nr = __bswap_16((*conn).rdp.snd_nxt as __uint16_t) as uint16_t;
    (*tx_header).flags = ((*tx_header).flags as ::core::ffi::c_int | RDP_ACK) as uint8_t;
    let mut rdp_packet: *mut csp_packet_t = csp_buffer_clone(packet);
    if rdp_packet.is_null() {
        if csp_dbg_rdp_print as ::core::ffi::c_int >= 1 as ::core::ffi::c_int {
            csp_print_func(
                b"\x1B[31mRDP %p: Failed to allocate packet buffer\n\x1B[0m\0"
                    as *const u8 as *const ::core::ffi::c_char,
                conn as *mut ::core::ffi::c_void,
            );
        }
        return CSP_ERR_NOMEM;
    }
    (*rdp_packet).timestamp_tx = csp_get_ms();
    csp_rdp_queue_tx_add(conn, rdp_packet);
    if csp_dbg_rdp_print as ::core::ffi::c_int >= 2 as ::core::ffi::c_int {
        csp_print_func(
            b"\x1B[34mRDP %p: Sending  in S %u: syn %u, ack %u, eack %u, rst %u, seq_nr %5u, ack_nr %5u, packet_len %u (%u)\n\x1B[0m\0"
                as *const u8 as *const ::core::ffi::c_char,
            conn as *mut ::core::ffi::c_void,
            (*conn).rdp.state as ::core::ffi::c_uint,
            (*tx_header).flags as ::core::ffi::c_int & 0x8 as ::core::ffi::c_int,
            (*tx_header).flags as ::core::ffi::c_int & 0x4 as ::core::ffi::c_int,
            (*tx_header).flags as ::core::ffi::c_int & 0x2 as ::core::ffi::c_int,
            (*tx_header).flags as ::core::ffi::c_int & 0x1 as ::core::ffi::c_int,
            __bswap_16((*tx_header).seq_nr as __uint16_t) as ::core::ffi::c_int,
            __bswap_16((*tx_header).ack_nr as __uint16_t) as ::core::ffi::c_int,
            (*packet).length as ::core::ffi::c_int,
            ((*packet).length as usize)
                .wrapping_sub(::core::mem::size_of::<rdp_header_t>() as usize)
                as ::core::ffi::c_uint,
        );
    }
    (*conn).rdp.snd_nxt = (*conn).rdp.snd_nxt.wrapping_add(1);
    (*conn).rdp.ack_timestamp = csp_get_ms();
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_rdp_init(mut conn: *mut csp_conn_t) {
    (*conn).rdp.state = RDP_CLOSED;
    (*conn).rdp.closed_by = 0 as uint8_t;
    (*conn).rdp.retransmits = 0 as uint32_t;
    (*conn).rdp.conn_timeout = csp_rdp_conn_timeout;
    (*conn).rdp.packet_timeout = csp_rdp_packet_timeout;
    csp_bin_sem_init(&raw mut (*conn).rdp.tx_wait);
}
#[no_mangle]
pub unsafe extern "C" fn csp_rdp_close(
    mut conn: *mut csp_conn_t,
    mut closed_by: uint8_t,
) -> ::core::ffi::c_int {
    return csp_rdp_close_internal(conn, closed_by, true_0 != 0);
}
unsafe extern "C" fn csp_rdp_close_internal(
    mut conn: *mut csp_conn_t,
    mut closed_by: uint8_t,
    mut send_rst: bool,
) -> ::core::ffi::c_int {
    if (*conn).rdp.state as ::core::ffi::c_uint
        == RDP_CLOSED as ::core::ffi::c_int as ::core::ffi::c_uint
    {
        return CSP_ERR_NONE;
    }
    (*conn).rdp.closed_by = ((*conn).rdp.closed_by as ::core::ffi::c_int
        | closed_by as ::core::ffi::c_int) as uint8_t;
    if (*conn).rdp.state as ::core::ffi::c_uint
        != RDP_CLOSE_WAIT as ::core::ffi::c_int as ::core::ffi::c_uint
    {
        (*conn).rdp.state = RDP_CLOSE_WAIT;
        (*conn).timestamp = csp_get_ms();
        if send_rst {
            csp_rdp_send_cmp(
                conn,
                ::core::ptr::null_mut::<csp_packet_t>(),
                RDP_ACK | RDP_RST,
                (*conn).rdp.snd_nxt as ::core::ffi::c_int,
                (*conn).rdp.rcv_cur as ::core::ffi::c_int,
            );
        }
        if csp_dbg_rdp_print as ::core::ffi::c_int >= 2 as ::core::ffi::c_int {
            csp_print_func(
                b"\x1B[34mRDP %p: csp_rdp_close(0x%x)%s -> CLOSE_WAIT\n\x1B[0m\0"
                    as *const u8 as *const ::core::ffi::c_char,
                conn as *mut ::core::ffi::c_void,
                closed_by as ::core::ffi::c_int,
                if send_rst as ::core::ffi::c_int != 0 {
                    b", sent RST\0" as *const u8 as *const ::core::ffi::c_char
                } else {
                    b"\0" as *const u8 as *const ::core::ffi::c_char
                },
            );
        }
        csp_bin_sem_post(&raw mut (*conn).rdp.tx_wait);
    }
    if (*conn).rdp.closed_by as ::core::ffi::c_int != CSP_RDP_CLOSED_BY_ALL {
        if csp_dbg_rdp_print as ::core::ffi::c_int >= 2 as ::core::ffi::c_int {
            csp_print_func(
                b"\x1B[34mRDP %p: csp_rdp_close(0x%x) != %x, waiting for:%s%s%s\n\x1B[0m\0"
                    as *const u8 as *const ::core::ffi::c_char,
                conn as *mut ::core::ffi::c_void,
                closed_by as ::core::ffi::c_int,
                (*conn).rdp.closed_by as ::core::ffi::c_int,
                if (*conn).rdp.closed_by as ::core::ffi::c_int
                    & 0x1 as ::core::ffi::c_int != 0
                {
                    b"\0" as *const u8 as *const ::core::ffi::c_char
                } else {
                    b" userspace\0" as *const u8 as *const ::core::ffi::c_char
                },
                if (*conn).rdp.closed_by as ::core::ffi::c_int
                    & 0x2 as ::core::ffi::c_int != 0
                {
                    b"\0" as *const u8 as *const ::core::ffi::c_char
                } else {
                    b" protocol\0" as *const u8 as *const ::core::ffi::c_char
                },
                if (*conn).rdp.closed_by as ::core::ffi::c_int
                    & 0x4 as ::core::ffi::c_int != 0
                {
                    b"\0" as *const u8 as *const ::core::ffi::c_char
                } else {
                    b" timeout\0" as *const u8 as *const ::core::ffi::c_char
                },
            );
        }
        return CSP_ERR_AGAIN;
    }
    if csp_dbg_rdp_print as ::core::ffi::c_int >= 2 as ::core::ffi::c_int {
        csp_print_func(
            b"\x1B[34mRDP %p: csp_rdp_close(0x%x) -> CLOSED\n\x1B[0m\0" as *const u8
                as *const ::core::ffi::c_char,
            conn as *mut ::core::ffi::c_void,
            closed_by as ::core::ffi::c_int,
        );
    }
    (*conn).rdp.state = RDP_CLOSED;
    (*conn).rdp.closed_by = 0 as uint8_t;
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_rdp_set_opt(
    mut window_size: ::core::ffi::c_uint,
    mut conn_timeout_ms: ::core::ffi::c_uint,
    mut packet_timeout_ms: ::core::ffi::c_uint,
    mut delayed_acks: ::core::ffi::c_uint,
    mut ack_timeout: ::core::ffi::c_uint,
    mut ack_delay_count: ::core::ffi::c_uint,
) {
    csp_rdp_window_size = window_size as uint32_t;
    csp_rdp_conn_timeout = conn_timeout_ms as uint32_t;
    csp_rdp_packet_timeout = packet_timeout_ms as uint32_t;
    csp_rdp_delayed_acks = delayed_acks as uint32_t;
    csp_rdp_ack_timeout = ack_timeout as uint32_t;
    csp_rdp_ack_delay_count = ack_delay_count as uint32_t;
}
#[no_mangle]
pub unsafe extern "C" fn csp_rdp_get_opt(
    mut window_size: *mut ::core::ffi::c_uint,
    mut conn_timeout_ms: *mut ::core::ffi::c_uint,
    mut packet_timeout_ms: *mut ::core::ffi::c_uint,
    mut delayed_acks: *mut ::core::ffi::c_uint,
    mut ack_timeout: *mut ::core::ffi::c_uint,
    mut ack_delay_count: *mut ::core::ffi::c_uint,
) {
    if !window_size.is_null() {
        *window_size = csp_rdp_window_size as ::core::ffi::c_uint;
    }
    if !conn_timeout_ms.is_null() {
        *conn_timeout_ms = csp_rdp_conn_timeout as ::core::ffi::c_uint;
    }
    if !packet_timeout_ms.is_null() {
        *packet_timeout_ms = csp_rdp_packet_timeout as ::core::ffi::c_uint;
    }
    if !delayed_acks.is_null() {
        *delayed_acks = csp_rdp_delayed_acks as ::core::ffi::c_uint;
    }
    if !ack_timeout.is_null() {
        *ack_timeout = csp_rdp_ack_timeout as ::core::ffi::c_uint;
    }
    if !ack_delay_count.is_null() {
        *ack_delay_count = csp_rdp_ack_delay_count as ::core::ffi::c_uint;
    }
}
#[no_mangle]
pub unsafe extern "C" fn csp_rdp_conn_is_active(mut conn: *mut csp_conn_t) -> bool {
    let mut time_now: uint32_t = csp_get_ms();
    let mut active: bool = true_0 != 0;
    if csp_rdp_time_after(
        time_now,
        (*conn).timestamp.wrapping_add((*conn).rdp.conn_timeout),
    ) != 0
    {
        if csp_dbg_rdp_print as ::core::ffi::c_int >= 1 as ::core::ffi::c_int {
            csp_print_func(
                b"\x1B[31mRDP %p: Timeout no packets received last %u ms\n\x1B[0m\0"
                    as *const u8 as *const ::core::ffi::c_char,
                conn as *mut ::core::ffi::c_void,
                (*conn).rdp.conn_timeout,
            );
        }
        active = false_0 != 0;
    }
    if (*conn).rdp.state as ::core::ffi::c_uint
        == RDP_CLOSE_WAIT as ::core::ffi::c_int as ::core::ffi::c_uint
        || (*conn).rdp.state as ::core::ffi::c_uint
            == RDP_CLOSED as ::core::ffi::c_int as ::core::ffi::c_uint
    {
        active = false_0 != 0;
    }
    return active;
}
