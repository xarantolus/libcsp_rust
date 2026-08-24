extern "C" {
    pub type pthread_queue_s;
    static mut csp_dbg_conn_out: uint8_t;
    static mut csp_dbg_conn_ovf: uint8_t;
    static mut csp_dbg_packet_print: uint8_t;
    fn csp_print_func(fmt: *const ::core::ffi::c_char, ...);
    fn csp_queue_enqueue(
        handle: csp_queue_handle_t,
        value: *const ::core::ffi::c_void,
        timeout: uint32_t,
    ) -> ::core::ffi::c_int;
    fn csp_buffer_free(buffer: *mut ::core::ffi::c_void);
    fn csp_iflist_get_by_addr(addr: uint16_t) -> *mut csp_iface_t;
    fn csp_addr_is_alias(addr: uint16_t) -> ::core::ffi::c_int;
    static mut csp_conf: csp_conf_t;
    fn csp_close(conn: *mut csp_conn_t) -> ::core::ffi::c_int;
    fn csp_crc32_verify(packet: *mut csp_packet_t) -> ::core::ffi::c_int;
    fn csp_get_ms() -> uint32_t;
    fn csp_hmac_verify(
        packet: *mut csp_packet_t,
        include_header: bool,
    ) -> ::core::ffi::c_int;
    fn csp_id_is_broadcast(
        addr: uint16_t,
        iface: *mut csp_iface_t,
    ) -> ::core::ffi::c_int;
    fn csp_port_get_socket(dport: ::core::ffi::c_uint) -> *mut csp_socket_t;
    fn csp_port_get_callback(port: ::core::ffi::c_uint) -> csp_callback_t;
    fn csp_socket_is_conn_less(socket: *const csp_socket_t) -> bool;
    fn csp_conn_enqueue_packet(
        conn: *mut csp_conn_t,
        packet: *mut csp_packet_t,
    ) -> ::core::ffi::c_int;
    fn csp_conn_find_existing(id: *mut csp_id_t) -> *mut csp_conn_t;
    fn csp_conn_new(
        idin: csp_id_t,
        idout: csp_id_t,
        type_0: csp_conn_type_t,
    ) -> *mut csp_conn_t;
    fn csp_conn_check_timeouts();
    fn csp_send_direct(
        idout: *mut csp_id_t,
        packet: *mut csp_packet_t,
        routed_from: *mut csp_iface_t,
    );
    fn csp_promisc_add(packet: *mut csp_packet_t);
    fn csp_qfifo_read(input: *mut csp_qfifo_t) -> ::core::ffi::c_int;
    fn csp_dedup_is_duplicate(packet: *mut csp_packet_t) -> bool;
    fn csp_rdp_new_packet(conn: *mut csp_conn_t, packet: *mut csp_packet_t) -> bool;
}
pub type __uint8_t = u8;
pub type __uint16_t = u16;
pub type __uint32_t = u32;
pub type __uint64_t = u64;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
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
pub type csp_callback_t = Option<unsafe extern "C" fn(*mut csp_packet_t) -> ()>;
pub type csp_conn_t = csp_conn_s;
pub type csp_dedup_types = ::core::ffi::c_uint;
pub const CSP_DEDUP_ALL: csp_dedup_types = 3;
pub const CSP_DEDUP_INCOMING: csp_dedup_types = 2;
pub const CSP_DEDUP_FWD: csp_dedup_types = 1;
pub const CSP_DEDUP_OFF: csp_dedup_types = 0;
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
pub type csp_conf_t = csp_conf_s;
pub type csp_conn_type_t = ::core::ffi::c_uint;
pub const CONN_SERVER: csp_conn_type_t = 1;
pub const CONN_CLIENT: csp_conn_type_t = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct csp_qfifo_t {
    pub iface: *mut csp_iface_t,
    pub packet: *mut csp_packet_t,
}
pub const NULL: *mut ::core::ffi::c_void = ::core::ptr::null_mut::<
    ::core::ffi::c_void,
>();
pub const true_0: ::core::ffi::c_int = 1 as ::core::ffi::c_int;
pub const false_0: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_QUEUE_OK: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_FHMAC: ::core::ffi::c_int = 0x8 as ::core::ffi::c_int;
pub const CSP_FRDP: ::core::ffi::c_int = 0x2 as ::core::ffi::c_int;
pub const CSP_FCRC32: ::core::ffi::c_int = 0x1 as ::core::ffi::c_int;
pub const CSP_SO_RDPREQ: ::core::ffi::c_int = 0x1 as ::core::ffi::c_int;
pub const CSP_SO_HMACREQ: ::core::ffi::c_int = 0x4 as ::core::ffi::c_int;
pub const CSP_SO_CRC32REQ: ::core::ffi::c_int = 0x40 as ::core::ffi::c_int;
unsafe extern "C" fn csp_route_check_options(
    mut iface: *mut csp_iface_t,
    mut packet: *mut csp_packet_t,
) -> ::core::ffi::c_int {
    return CSP_ERR_NONE;
}
unsafe extern "C" fn csp_route_security_check(
    mut security_opts: uint32_t,
    mut iface: *mut csp_iface_t,
    mut packet: *mut csp_packet_t,
) -> ::core::ffi::c_int {
    if (*packet).id.flags as ::core::ffi::c_int & CSP_FCRC32 != 0 {
        if csp_crc32_verify(packet) != CSP_ERR_NONE {
            (*iface).rx_error = (*iface).rx_error.wrapping_add(1);
            return CSP_ERR_CRC32;
        }
    } else if security_opts & CSP_SO_CRC32REQ as uint32_t != 0 {
        (*iface).rx_error = (*iface).rx_error.wrapping_add(1);
        return CSP_ERR_CRC32;
    }
    if (*packet).id.flags as ::core::ffi::c_int & CSP_FHMAC != 0 {
        if csp_hmac_verify(packet, false_0 != 0) != CSP_ERR_NONE {
            (*iface).autherr = (*iface).autherr.wrapping_add(1);
            return CSP_ERR_HMAC;
        }
    } else if security_opts & CSP_SO_HMACREQ as uint32_t != 0 {
        (*iface).autherr = (*iface).autherr.wrapping_add(1);
        return CSP_ERR_HMAC;
    }
    if (*packet).id.flags as ::core::ffi::c_int & CSP_FRDP == 0 {
        if security_opts & CSP_SO_RDPREQ as uint32_t != 0 {
            (*iface).rx_error = (*iface).rx_error.wrapping_add(1);
            return CSP_ERR_INVAL;
        }
    }
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_input_hook(
    mut iface: *mut csp_iface_t,
    mut packet: *mut csp_packet_t,
) {
    if csp_dbg_packet_print as ::core::ffi::c_int >= 1 as ::core::ffi::c_int {
        csp_print_func(
            b"\x1B[32mINP: S %u, D %u, Dp %u, Sp %u, Pr %u, Fl 0x%02X, Sz %u VIA: %s, Tms %u\n\x1B[0m\0"
                as *const u8 as *const ::core::ffi::c_char,
            (*packet).id.src as ::core::ffi::c_int,
            (*packet).id.dst as ::core::ffi::c_int,
            (*packet).id.dport as ::core::ffi::c_int,
            (*packet).id.sport as ::core::ffi::c_int,
            (*packet).id.pri as ::core::ffi::c_int,
            (*packet).id.flags as ::core::ffi::c_int,
            (*packet).length as ::core::ffi::c_int,
            (*iface).name,
            csp_get_ms(),
        );
    }
}
unsafe extern "C" fn csp_route_deliver_callback(
    mut iface: *mut csp_iface_t,
    mut packet: *mut csp_packet_t,
) -> bool {
    let mut callback: csp_callback_t = csp_port_get_callback(
        (*packet).id.dport as ::core::ffi::c_uint,
    );
    if callback.is_none() {
        return false_0 != 0;
    }
    if csp_route_security_check(CSP_SO_CRC32REQ as uint32_t, iface, packet)
        != CSP_ERR_NONE
    {
        csp_buffer_free(packet as *mut ::core::ffi::c_void);
        return true_0 != 0;
    }
    callback.expect("non-null function pointer")(packet);
    return true_0 != 0;
}
unsafe extern "C" fn csp_route_deliver_conn_less(
    mut socket: *mut csp_socket_t,
    mut packet: *mut csp_packet_t,
) {
    if csp_queue_enqueue(
        (*socket).rx_queue,
        &raw mut packet as *const ::core::ffi::c_void,
        0 as uint32_t,
    ) != CSP_QUEUE_OK
    {
        csp_dbg_conn_ovf = csp_dbg_conn_ovf.wrapping_add(1);
        csp_buffer_free(packet as *mut ::core::ffi::c_void);
        return;
    }
}
unsafe extern "C" fn csp_route_deliver_connection(
    mut conn: *mut csp_conn_t,
    mut socket: *mut csp_socket_t,
    mut packet: *mut csp_packet_t,
) {
    if conn.is_null() {
        let mut idout: csp_id_t = csp_id_t {
            pri: 0,
            flags: 0,
            src: 0,
            dst: 0,
            dport: 0,
            sport: 0,
        };
        idout.pri = (*packet).id.pri;
        idout.src = (*packet).id.dst;
        idout.dst = (*packet).id.src;
        idout.dport = (*packet).id.sport;
        idout.sport = (*packet).id.dport;
        idout.flags = (*packet).id.flags;
        conn = csp_conn_new((*packet).id, idout, CONN_SERVER);
        if conn.is_null() {
            csp_dbg_conn_out = csp_dbg_conn_out.wrapping_add(1);
            csp_buffer_free(packet as *mut ::core::ffi::c_void);
            return;
        }
        (*conn).dest_socket = socket;
        (*conn).opts = (*socket).opts;
    }
    if (*packet).id.flags as ::core::ffi::c_int & CSP_FRDP != 0 {
        let mut close_connection: bool = csp_rdp_new_packet(conn, packet);
        if close_connection {
            csp_close(conn);
        }
        return;
    }
    if csp_conn_enqueue_packet(conn, packet) != CSP_ERR_NONE {
        csp_dbg_conn_ovf = csp_dbg_conn_ovf.wrapping_add(1);
        csp_buffer_free(packet as *mut ::core::ffi::c_void);
        return;
    }
    if !(*conn).dest_socket.is_null() {
        if csp_queue_enqueue(
            (*(*conn).dest_socket).rx_queue,
            &raw mut conn as *const ::core::ffi::c_void,
            0 as uint32_t,
        ) != CSP_QUEUE_OK
        {
            csp_dbg_conn_ovf = csp_dbg_conn_ovf.wrapping_add(1);
            csp_close(conn);
            return;
        }
        (*conn).dest_socket = ::core::ptr::null_mut::<csp_socket_t>();
    }
}
#[no_mangle]
pub unsafe extern "C" fn csp_route_work() -> ::core::ffi::c_int {
    let mut input: csp_qfifo_t = csp_qfifo_t {
        iface: ::core::ptr::null_mut::<csp_iface_t>(),
        packet: ::core::ptr::null_mut::<csp_packet_t>(),
    };
    let mut packet: *mut csp_packet_t = ::core::ptr::null_mut::<csp_packet_t>();
    let mut socket: *mut csp_socket_t = ::core::ptr::null_mut::<csp_socket_t>();
    csp_conn_check_timeouts();
    if csp_qfifo_read(&raw mut input) != CSP_ERR_NONE {
        return CSP_ERR_TIMEDOUT;
    }
    packet = input.packet;
    if packet.is_null() {
        return CSP_ERR_TIMEDOUT;
    }
    csp_input_hook(input.iface, packet);
    (*input.iface).rx = (*input.iface).rx.wrapping_add(1);
    (*input.iface).rxbytes = (*input.iface)
        .rxbytes
        .wrapping_add((*packet).length as uint32_t);
    let mut is_to_me: ::core::ffi::c_int = (!csp_iflist_get_by_addr((*packet).id.dst)
        .is_null() || csp_id_is_broadcast((*packet).id.dst, input.iface) != 0
        || csp_addr_is_alias((*packet).id.dst) != 0) as ::core::ffi::c_int;
    if csp_conf.dedup as ::core::ffi::c_int == CSP_DEDUP_ALL as ::core::ffi::c_int
        || is_to_me != 0
            && csp_conf.dedup as ::core::ffi::c_int
                == CSP_DEDUP_INCOMING as ::core::ffi::c_int
        || is_to_me == 0
            && csp_conf.dedup as ::core::ffi::c_int
                == CSP_DEDUP_FWD as ::core::ffi::c_int
    {
        if csp_dedup_is_duplicate(packet) {
            (*input.iface).drop = (*input.iface).drop.wrapping_add(1);
            csp_buffer_free(packet as *mut ::core::ffi::c_void);
            return CSP_ERR_NONE;
        }
    }
    csp_promisc_add(packet);
    if is_to_me == 0 {
        csp_send_direct(&raw mut (*packet).id, packet, input.iface);
        return CSP_ERR_NONE;
    }
    if csp_route_check_options(input.iface, packet) != CSP_ERR_NONE {
        csp_buffer_free(packet as *mut ::core::ffi::c_void);
        return CSP_ERR_NONE;
    }
    if csp_route_deliver_callback(input.iface, packet) {
        return CSP_ERR_NONE;
    }
    socket = csp_port_get_socket((*packet).id.dport as ::core::ffi::c_uint);
    let mut conn: *mut csp_conn_t = csp_conn_find_existing(&raw mut (*packet).id);
    if conn.is_null() && socket.is_null() {
        csp_buffer_free(packet as *mut ::core::ffi::c_void);
        return CSP_ERR_NONE;
    }
    let mut opts: uint32_t = if !conn.is_null() { (*conn).opts } else { (*socket).opts };
    if csp_route_security_check(opts, input.iface, packet) != CSP_ERR_NONE {
        csp_buffer_free(packet as *mut ::core::ffi::c_void);
        return CSP_ERR_NONE;
    }
    if !socket.is_null() && csp_socket_is_conn_less(socket) as ::core::ffi::c_int != 0 {
        csp_route_deliver_conn_less(socket, packet);
    } else {
        csp_route_deliver_connection(conn, socket, packet);
    }
    return CSP_ERR_NONE;
}
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ERR_INVAL: ::core::ffi::c_int = -(2 as ::core::ffi::c_int);
pub const CSP_ERR_TIMEDOUT: ::core::ffi::c_int = -(3 as ::core::ffi::c_int);
pub const CSP_ERR_HMAC: ::core::ffi::c_int = -(100 as ::core::ffi::c_int);
pub const CSP_ERR_CRC32: ::core::ffi::c_int = -(102 as ::core::ffi::c_int);
