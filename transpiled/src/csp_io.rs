extern "C" {
    pub type pthread_queue_s;
    static mut csp_dbg_inval_reply: uint8_t;
    static mut csp_dbg_errno: uint8_t;
    static mut csp_dbg_packet_print: uint8_t;
    fn csp_print_func(fmt: *const ::core::ffi::c_char, ...);
    fn csp_queue_dequeue(
        handle: csp_queue_handle_t,
        buf: *mut ::core::ffi::c_void,
        timeout: uint32_t,
    ) -> ::core::ffi::c_int;
    fn csp_buffer_get(unused: size_t) -> *mut csp_packet_t;
    fn csp_buffer_free(buffer: *mut ::core::ffi::c_void);
    fn csp_buffer_clone(packet: *const csp_packet_t) -> *mut csp_packet_t;
    fn csp_iflist_get_by_subnet(
        addr: uint16_t,
        from: *mut csp_iface_t,
    ) -> *mut csp_iface_t;
    fn csp_iflist_get_by_isdfl(ifc: *mut csp_iface_t) -> *mut csp_iface_t;
    fn csp_iflist_is_within_subnet(
        addr: uint16_t,
        ifc: *mut csp_iface_t,
    ) -> ::core::ffi::c_int;
    fn csp_rtable_search_backward(start_route: *mut csp_route_t) -> *mut csp_route_t;
    fn csp_rtable_find_route(dest_address: uint16_t) -> *mut csp_route_t;
    fn csp_connect(
        prio: uint8_t,
        dst: uint16_t,
        dst_port: uint8_t,
        timeout: uint32_t,
        opts: uint32_t,
    ) -> *mut csp_conn_t;
    fn csp_close(conn: *mut csp_conn_t) -> ::core::ffi::c_int;
    fn memcpy(
        __dest: *mut ::core::ffi::c_void,
        __src: *const ::core::ffi::c_void,
        __n: size_t,
    ) -> *mut ::core::ffi::c_void;
    fn csp_crc32_append(packet: *mut csp_packet_t) -> ::core::ffi::c_int;
    static mut csp_if_lo: csp_iface_t;
    fn csp_get_ms() -> uint32_t;
    fn csp_hmac_append(
        packet: *mut csp_packet_t,
        include_header: bool,
    ) -> ::core::ffi::c_int;
    fn csp_id_get_max_nodeid() -> ::core::ffi::c_uint;
    fn csp_id_is_broadcast(
        addr: uint16_t,
        iface: *mut csp_iface_t,
    ) -> ::core::ffi::c_int;
    fn csp_promisc_add(packet: *mut csp_packet_t);
    fn csp_rdp_send(
        conn: *mut csp_conn_t,
        packet: *mut csp_packet_t,
    ) -> ::core::ffi::c_int;
    fn csp_rdp_check_ack(conn: *mut csp_conn_t) -> ::core::ffi::c_int;
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
#[repr(C)]
pub struct csp_route_s {
    pub address: uint16_t,
    pub netmask: uint16_t,
    pub via: uint16_t,
    pub iface: *mut csp_iface_t,
}
pub type csp_route_t = csp_route_s;
pub const CONN_OPEN: C2RustUnnamed_0 = 1;
pub type C2RustUnnamed_0 = ::core::ffi::c_uint;
pub const CONN_CLOSED: C2RustUnnamed_0 = 0;
pub const NULL: *mut ::core::ffi::c_void = ::core::ptr::null_mut::<
    ::core::ffi::c_void,
>();
pub const CSP_DBG_ERR_UNSUPPORTED: ::core::ffi::c_int = 7 as ::core::ffi::c_int;
pub const CSP_DBG_ERR_INVALID_POINTER: ::core::ffi::c_int = 11 as ::core::ffi::c_int;
pub const false_0: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_BUFFER_SIZE: ::core::ffi::c_int = 256 as ::core::ffi::c_int;
pub const CSP_QUEUE_OK: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_FHMAC: ::core::ffi::c_int = 0x8 as ::core::ffi::c_int;
pub const CSP_FRDP: ::core::ffi::c_int = 0x2 as ::core::ffi::c_int;
pub const CSP_FCRC32: ::core::ffi::c_int = 0x1 as ::core::ffi::c_int;
pub const CSP_SO_RDPREQ: ::core::ffi::c_int = 0x1 as ::core::ffi::c_int;
pub const CSP_SO_HMACREQ: ::core::ffi::c_int = 0x4 as ::core::ffi::c_int;
pub const CSP_SO_CRC32REQ: ::core::ffi::c_int = 0x40 as ::core::ffi::c_int;
pub const CSP_SO_CONN_LESS: ::core::ffi::c_int = 0x100 as ::core::ffi::c_int;
pub const CSP_SO_SAME: ::core::ffi::c_int = 0x8000 as ::core::ffi::c_int;
pub const CSP_O_RDP: ::core::ffi::c_int = CSP_SO_RDPREQ;
pub const CSP_O_HMAC: ::core::ffi::c_int = CSP_SO_HMACREQ;
pub const CSP_O_CRC32: ::core::ffi::c_int = CSP_SO_CRC32REQ;
pub const CSP_O_SAME: ::core::ffi::c_int = CSP_SO_SAME;
pub const CSP_NO_VIA_ADDRESS: ::core::ffi::c_int = 0xffff as ::core::ffi::c_int;
#[no_mangle]
pub unsafe extern "C" fn csp_accept(
    mut sock: *mut csp_socket_t,
    mut timeout: uint32_t,
) -> *mut csp_conn_t {
    if sock.is_null() || (*sock).rx_queue.is_null() {
        csp_dbg_errno = CSP_DBG_ERR_INVALID_POINTER as uint8_t;
        return ::core::ptr::null_mut::<csp_conn_t>();
    }
    if (*sock).opts & CSP_SO_CONN_LESS as uint32_t != 0 {
        csp_dbg_errno = CSP_DBG_ERR_UNSUPPORTED as uint8_t;
        return ::core::ptr::null_mut::<csp_conn_t>();
    }
    let mut conn: *mut csp_conn_t = ::core::ptr::null_mut::<csp_conn_t>();
    if csp_queue_dequeue(
        (*sock).rx_queue,
        &raw mut conn as *mut ::core::ffi::c_void,
        timeout,
    ) == CSP_QUEUE_OK
    {
        return conn;
    }
    return ::core::ptr::null_mut::<csp_conn_t>();
}
#[no_mangle]
pub unsafe extern "C" fn csp_read(
    mut conn: *mut csp_conn_t,
    mut timeout: uint32_t,
) -> *mut csp_packet_t {
    let mut packet: *mut csp_packet_t = ::core::ptr::null_mut::<csp_packet_t>();
    if conn.is_null() || (*conn).state != CONN_OPEN as ::core::ffi::c_int {
        return ::core::ptr::null_mut::<csp_packet_t>();
    }
    if timeout != 0 && (*conn).idin.flags as ::core::ffi::c_int & CSP_FRDP != 0
        && timeout < (*conn).rdp.conn_timeout
    {
        timeout = (*conn).rdp.conn_timeout;
    }
    if csp_queue_dequeue(
        (*conn).rx_queue,
        &raw mut packet as *mut ::core::ffi::c_void,
        timeout,
    ) != CSP_QUEUE_OK
    {
        return ::core::ptr::null_mut::<csp_packet_t>();
    }
    if (*conn).idin.flags as ::core::ffi::c_int & CSP_FRDP != 0
        && (*conn).rdp.delayed_acks != 0
    {
        csp_rdp_check_ack(conn);
    }
    return packet;
}
#[no_mangle]
pub unsafe extern "C" fn csp_id_copy(
    mut target: *mut csp_id_t,
    mut source: *const csp_id_t,
) {
    (*target).pri = (*source).pri;
    (*target).dst = (*source).dst;
    (*target).src = (*source).src;
    (*target).dport = (*source).dport;
    (*target).sport = (*source).sport;
    (*target).flags = (*source).flags;
}
#[no_mangle]
pub unsafe extern "C" fn csp_id_clear(mut target: *mut csp_id_t) {
    (*target).pri = 0 as uint8_t;
    (*target).dst = 0 as uint16_t;
    (*target).src = 0 as uint16_t;
    (*target).dport = 0 as uint8_t;
    (*target).sport = 0 as uint8_t;
    (*target).flags = 0 as uint8_t;
}
#[inline]
unsafe extern "C" fn is_same_subnet(
    mut iface: *mut csp_iface_t,
    mut routed_from: *mut csp_iface_t,
) -> ::core::ffi::c_int {
    if iface == routed_from {
        return 1 as ::core::ffi::c_int;
    }
    if csp_iflist_is_within_subnet((*iface).addr, routed_from) != 0 {
        return 1 as ::core::ffi::c_int;
    }
    return 0 as ::core::ffi::c_int;
}
#[inline]
unsafe extern "C" fn convert_broadcast(
    mut idout: *mut csp_id_t,
    mut idout_copy: *mut csp_id_t,
    mut snd_iface: *mut csp_iface_t,
) {
    if csp_id_is_broadcast((*idout).dst, snd_iface) != 0 {
        (*idout_copy).dst = csp_id_get_max_nodeid() as uint16_t;
    }
}
#[inline]
unsafe extern "C" fn send_packet(
    mut idout_copy: *mut csp_id_t,
    mut snd_pkt: *mut csp_packet_t,
    mut snd_iface: *mut csp_iface_t,
    mut via: uint16_t,
    mut from_me: ::core::ffi::c_int,
) {
    if from_me != 0 && (*idout_copy).src as ::core::ffi::c_int == 0 as ::core::ffi::c_int
    {
        (*idout_copy).src = (*snd_iface).addr;
    }
    if !snd_pkt.is_null() {
        csp_send_direct_iface(idout_copy, snd_pkt, snd_iface, via, from_me);
    }
}
#[no_mangle]
pub unsafe extern "C" fn csp_send_direct(
    mut idout: *mut csp_id_t,
    mut packet: *mut csp_packet_t,
    mut routed_from: *mut csp_iface_t,
) {
    let mut from_me: ::core::ffi::c_int = if routed_from.is_null() {
        1 as ::core::ffi::c_int
    } else {
        0 as ::core::ffi::c_int
    };
    let mut via: ::core::ffi::c_int = CSP_NO_VIA_ADDRESS;
    if (*idout).dst as ::core::ffi::c_int == csp_if_lo.addr as ::core::ffi::c_int {
        csp_send_direct_iface(
            idout,
            packet,
            &raw mut csp_if_lo,
            via as uint16_t,
            from_me,
        );
        return;
    }
    let mut idout_copy: csp_id_t = *idout;
    let mut iface: *mut csp_iface_t = ::core::ptr::null_mut::<csp_iface_t>();
    let mut next_iface: *mut csp_iface_t = ::core::ptr::null_mut::<csp_iface_t>();
    let mut local_found: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
    loop {
        iface = csp_iflist_get_by_subnet((*idout).dst, iface);
        if iface.is_null() {
            break;
        }
        local_found = 1 as ::core::ffi::c_int;
        if is_same_subnet(iface, routed_from) != 0 {
            continue;
        }
        if !next_iface.is_null() {
            let mut copy: *mut csp_packet_t = csp_buffer_clone(packet);
            convert_broadcast(idout, &raw mut idout_copy, next_iface);
            send_packet(&raw mut idout_copy, copy, next_iface, via as uint16_t, from_me);
        }
        next_iface = iface;
    }
    if local_found != 0 {
        if !next_iface.is_null() {
            convert_broadcast(idout, &raw mut idout_copy, next_iface);
            send_packet(
                &raw mut idout_copy,
                packet,
                next_iface,
                via as uint16_t,
                from_me,
            );
        } else {
            csp_buffer_free(packet as *mut ::core::ffi::c_void);
        }
        return;
    }
    let mut route_found: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
    let mut route: *mut csp_route_t = csp_rtable_find_route((*idout).dst);
    if !route.is_null() {
        loop {
            route_found = 1 as ::core::ffi::c_int;
            if !(is_same_subnet((*route).iface, routed_from) != 0) {
                if !next_iface.is_null() {
                    let mut copy_0: *mut csp_packet_t = csp_buffer_clone(packet);
                    send_packet(
                        &raw mut idout_copy,
                        copy_0,
                        next_iface,
                        via as uint16_t,
                        from_me,
                    );
                }
                next_iface = (*route).iface;
                via = (*route).via as ::core::ffi::c_int;
            }
            route = csp_rtable_search_backward(route);
            if route.is_null() {
                break;
            }
        }
    }
    if route_found == 1 as ::core::ffi::c_int {
        if !next_iface.is_null() {
            send_packet(
                &raw mut idout_copy,
                packet,
                next_iface,
                via as uint16_t,
                from_me,
            );
        } else {
            csp_buffer_free(packet as *mut ::core::ffi::c_void);
        }
        return;
    }
    loop {
        iface = csp_iflist_get_by_isdfl(iface);
        if iface.is_null() {
            break;
        }
        if is_same_subnet(iface, routed_from) != 0 {
            continue;
        }
        if !next_iface.is_null() {
            let mut copy_1: *mut csp_packet_t = csp_buffer_clone(packet);
            send_packet(
                &raw mut idout_copy,
                copy_1,
                next_iface,
                via as uint16_t,
                from_me,
            );
        }
        next_iface = iface;
    }
    if !next_iface.is_null() {
        send_packet(&raw mut idout_copy, packet, next_iface, via as uint16_t, from_me);
        return;
    }
    csp_buffer_free(packet as *mut ::core::ffi::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn csp_output_hook(
    mut idout: *const csp_id_t,
    mut packet: *mut csp_packet_t,
    mut iface: *mut csp_iface_t,
    mut via: uint16_t,
    mut from_me: ::core::ffi::c_int,
) {
    if csp_dbg_packet_print as ::core::ffi::c_int >= 1 as ::core::ffi::c_int {
        csp_print_func(
            b"\x1B[32mOUT: S %u, D %u, Dp %u, Sp %u, Pr %u, Fl 0x%02X, Sz %u VIA: %s (%u), Tms %u\n\x1B[0m\0"
                as *const u8 as *const ::core::ffi::c_char,
            (*idout).src as ::core::ffi::c_int,
            (*idout).dst as ::core::ffi::c_int,
            (*idout).dport as ::core::ffi::c_int,
            (*idout).sport as ::core::ffi::c_int,
            (*idout).pri as ::core::ffi::c_int,
            (*idout).flags as ::core::ffi::c_int,
            (*packet).length as ::core::ffi::c_int,
            (*iface).name,
            if via as ::core::ffi::c_int != 0xffff as ::core::ffi::c_int {
                via as ::core::ffi::c_int
            } else {
                (*idout).dst as ::core::ffi::c_int
            },
            csp_get_ms(),
        );
    }
}
#[no_mangle]
pub unsafe extern "C" fn csp_send_direct_iface(
    mut idout: *const csp_id_t,
    mut packet: *mut csp_packet_t,
    mut iface: *mut csp_iface_t,
    mut via: uint16_t,
    mut from_me: ::core::ffi::c_int,
) {
    let mut bytes: uint16_t = 0;
    let mut current_block: u64;
    csp_output_hook(idout, packet, iface, via, from_me);
    if idout != &raw mut (*packet).id as *const csp_id_t {
        csp_id_copy(&raw mut (*packet).id, idout);
    }
    if from_me != 0 {
        if (*idout).flags as ::core::ffi::c_int & CSP_FHMAC != 0 {
            if csp_hmac_append(packet, false_0 != 0) != CSP_ERR_NONE {
                current_block = 14623059078890942241;
            } else {
                current_block = 15619007995458559411;
            }
        } else {
            current_block = 15619007995458559411;
        }
        match current_block {
            14623059078890942241 => {}
            _ => {
                if (*idout).flags as ::core::ffi::c_int & CSP_FCRC32 != 0 {
                    if csp_crc32_append(packet) != CSP_ERR_NONE {
                        current_block = 14623059078890942241;
                    } else {
                        current_block = 5720623009719927633;
                    }
                } else {
                    current_block = 5720623009719927633;
                }
                match current_block {
                    14623059078890942241 => {}
                    _ => {
                        if iface != &raw mut csp_if_lo {
                            csp_promisc_add(packet);
                        }
                        current_block = 5399440093318478209;
                    }
                }
            }
        }
    } else {
        current_block = 5399440093318478209;
    }
    match current_block {
        5399440093318478209 => {
            bytes = (*packet).length;
            if !(Some((*iface).nexthop.expect("non-null function pointer"))
                .expect("non-null function pointer")(iface, via, packet, from_me)
                != CSP_ERR_NONE)
            {
                (*iface).tx = (*iface).tx.wrapping_add(1);
                (*iface).txbytes = (*iface).txbytes.wrapping_add(bytes as uint32_t);
                return;
            }
        }
        _ => {}
    }
    csp_buffer_free(packet as *mut ::core::ffi::c_void);
    (*iface).tx_error = (*iface).tx_error.wrapping_add(1);
}
#[no_mangle]
pub unsafe extern "C" fn csp_send(
    mut conn: *mut csp_conn_t,
    mut packet: *mut csp_packet_t,
) {
    if packet.is_null() {
        return;
    }
    if conn.is_null() || (*conn).state != CONN_OPEN as ::core::ffi::c_int {
        csp_buffer_free(packet as *mut ::core::ffi::c_void);
        return;
    }
    if (*conn).idout.flags as ::core::ffi::c_int & CSP_FRDP != 0 {
        if csp_rdp_send(conn, packet) != CSP_ERR_NONE {
            csp_buffer_free(packet as *mut ::core::ffi::c_void);
            return;
        }
    }
    csp_send_direct(
        &raw mut (*conn).idout,
        packet,
        ::core::ptr::null_mut::<csp_iface_t>(),
    );
}
#[no_mangle]
pub unsafe extern "C" fn csp_send_prio(
    mut prio: uint8_t,
    mut conn: *mut csp_conn_t,
    mut packet: *mut csp_packet_t,
) {
    (*conn).idout.pri = prio;
    csp_send(conn, packet);
}
#[no_mangle]
pub unsafe extern "C" fn csp_transaction_persistent(
    mut conn: *mut csp_conn_t,
    mut timeout: uint32_t,
    mut outbuf: *const ::core::ffi::c_void,
    mut outlen: ::core::ffi::c_int,
    mut inbuf: *mut ::core::ffi::c_void,
    mut inlen: ::core::ffi::c_int,
) -> ::core::ffi::c_int {
    if outlen > CSP_BUFFER_SIZE {
        return 0 as ::core::ffi::c_int;
    }
    let mut packet: *mut csp_packet_t = csp_buffer_get(0 as size_t);
    if packet.is_null() {
        return 0 as ::core::ffi::c_int;
    }
    if outlen > 0 as ::core::ffi::c_int && !outbuf.is_null() {
        memcpy(
            &raw mut (*packet).c2rust_unnamed.data as *mut uint8_t
                as *mut ::core::ffi::c_void,
            outbuf,
            outlen as size_t,
        );
    }
    (*packet).length = outlen as uint16_t;
    csp_send(conn, packet);
    if inlen == 0 as ::core::ffi::c_int {
        return 1 as ::core::ffi::c_int;
    }
    packet = csp_read(conn, timeout);
    if packet.is_null() {
        return 0 as ::core::ffi::c_int;
    }
    if inlen != -(1 as ::core::ffi::c_int)
        && (*packet).length as ::core::ffi::c_int != inlen
    {
        csp_dbg_inval_reply = csp_dbg_inval_reply.wrapping_add(1);
        csp_buffer_free(packet as *mut ::core::ffi::c_void);
        return 0 as ::core::ffi::c_int;
    }
    memcpy(
        inbuf,
        &raw mut (*packet).c2rust_unnamed.data as *mut uint8_t
            as *const ::core::ffi::c_void,
        (*packet).length as size_t,
    );
    let mut length: ::core::ffi::c_int = (*packet).length as ::core::ffi::c_int;
    csp_buffer_free(packet as *mut ::core::ffi::c_void);
    return length;
}
#[no_mangle]
pub unsafe extern "C" fn csp_transaction_w_opts(
    mut prio: uint8_t,
    mut dest: uint16_t,
    mut port: uint8_t,
    mut timeout: uint32_t,
    mut outbuf: *const ::core::ffi::c_void,
    mut outlen: ::core::ffi::c_int,
    mut inbuf: *mut ::core::ffi::c_void,
    mut inlen: ::core::ffi::c_int,
    mut opts: uint32_t,
) -> ::core::ffi::c_int {
    let mut conn: *mut csp_conn_t = csp_connect(prio, dest, port, 0 as uint32_t, opts);
    if conn.is_null() {
        return 0 as ::core::ffi::c_int;
    }
    let mut status: ::core::ffi::c_int = csp_transaction_persistent(
        conn,
        timeout,
        outbuf,
        outlen,
        inbuf,
        inlen,
    );
    csp_close(conn);
    return status;
}
#[no_mangle]
pub unsafe extern "C" fn csp_recvfrom(
    mut socket: *mut csp_socket_t,
    mut timeout: uint32_t,
) -> *mut csp_packet_t {
    if socket.is_null() || (*socket).opts & CSP_SO_CONN_LESS as uint32_t == 0 {
        return ::core::ptr::null_mut::<csp_packet_t>();
    }
    let mut packet: *mut csp_packet_t = ::core::ptr::null_mut::<csp_packet_t>();
    csp_queue_dequeue(
        (*socket).rx_queue,
        &raw mut packet as *mut ::core::ffi::c_void,
        timeout,
    );
    return packet;
}
#[no_mangle]
pub unsafe extern "C" fn csp_sendto(
    mut prio: uint8_t,
    mut dest: uint16_t,
    mut dport: uint8_t,
    mut src_port: uint8_t,
    mut opts: uint32_t,
    mut packet: *mut csp_packet_t,
) {
    if opts & CSP_O_SAME as uint32_t == 0 {
        (*packet).id.flags = 0 as uint8_t;
    }
    if opts & CSP_O_RDP as uint32_t != 0 {
        csp_dbg_errno = CSP_DBG_ERR_UNSUPPORTED as uint8_t;
        csp_buffer_free(packet as *mut ::core::ffi::c_void);
        return;
    }
    if opts & CSP_O_HMAC as uint32_t != 0 {
        (*packet).id.flags = ((*packet).id.flags as ::core::ffi::c_int | CSP_FHMAC)
            as uint8_t;
    }
    if opts & CSP_O_CRC32 as uint32_t != 0 {
        (*packet).id.flags = ((*packet).id.flags as ::core::ffi::c_int | CSP_FCRC32)
            as uint8_t;
    }
    (*packet).id.dst = dest;
    (*packet).id.dport = dport;
    (*packet).id.sport = src_port;
    (*packet).id.pri = prio;
    csp_send_direct(
        &raw mut (*packet).id,
        packet,
        ::core::ptr::null_mut::<csp_iface_t>(),
    );
}
#[no_mangle]
pub unsafe extern "C" fn csp_sendto_reply(
    mut request_packet: *const csp_packet_t,
    mut reply_packet: *mut csp_packet_t,
    mut opts: uint32_t,
) {
    if request_packet.is_null() {
        return;
    }
    if opts & CSP_O_SAME as uint32_t != 0 {
        (*reply_packet).id.flags = (*request_packet).id.flags;
    }
    let mut dst: uint16_t = (*request_packet).id.src;
    if (*request_packet).id.dst as ::core::ffi::c_uint != csp_id_get_max_nodeid() {
        (*reply_packet).id.src = (*request_packet).id.dst;
    } else {
        (*reply_packet).id.src = 0 as uint16_t;
    }
    csp_sendto(
        (*request_packet).id.pri,
        dst,
        (*request_packet).id.sport,
        (*request_packet).id.dport,
        opts,
        reply_packet,
    );
}
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
