extern "C" {
    pub type pthread_queue_s;
    static mut csp_dbg_conn_out: uint8_t;
    static mut csp_dbg_conn_ovf: uint8_t;
    static mut csp_dbg_errno: uint8_t;
    fn csp_print_func(fmt: *const ::core::ffi::c_char, ...);
    fn csp_queue_create_static(
        length: ::core::ffi::c_int,
        item_size: size_t,
        buffer: *mut ::core::ffi::c_char,
        queue: *mut csp_static_queue_t,
    ) -> csp_queue_handle_t;
    fn csp_queue_enqueue(
        handle: csp_queue_handle_t,
        value: *const ::core::ffi::c_void,
        timeout: uint32_t,
    ) -> ::core::ffi::c_int;
    fn csp_queue_dequeue(
        handle: csp_queue_handle_t,
        buf: *mut ::core::ffi::c_void,
        timeout: uint32_t,
    ) -> ::core::ffi::c_int;
    fn csp_buffer_free(buffer: *mut ::core::ffi::c_void);
    static mut csp_conf: csp_conf_t;
    fn csp_id_copy(target: *mut csp_id_t, source: *const csp_id_t);
    fn strncat(
        __dest: *mut ::core::ffi::c_char,
        __src: *const ::core::ffi::c_char,
        __n: size_t,
    ) -> *mut ::core::ffi::c_char;
    fn strlen(__s: *const ::core::ffi::c_char) -> size_t;
    fn csp_get_ms() -> uint32_t;
    fn csp_rdp_queue_flush(conn: *mut csp_conn_t);
    fn csp_rdp_init(conn: *mut csp_conn_t);
    fn csp_rdp_check_timeouts(conn: *mut csp_conn_t);
    fn csp_rdp_connect(conn: *mut csp_conn_t) -> ::core::ffi::c_int;
    fn csp_rdp_close(conn: *mut csp_conn_t, closed_by: uint8_t) -> ::core::ffi::c_int;
    fn csp_rdp_conn_is_active(conn: *mut csp_conn_t) -> bool;
    fn snprintf(
        __s: *mut ::core::ffi::c_char,
        __maxlen: size_t,
        __format: *const ::core::ffi::c_char,
        ...
    ) -> ::core::ffi::c_int;
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
pub type atomic_int = ::core::ffi::c_int;
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
pub type csp_conn_t = csp_conn_s;
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
pub const CONN_OPEN: C2RustUnnamed_0 = 1;
pub const CONN_CLOSED: C2RustUnnamed_0 = 0;
pub type C2RustUnnamed_0 = ::core::ffi::c_uint;
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ERR_NOMEM: ::core::ffi::c_int = -(1 as ::core::ffi::c_int);
pub const CSP_ERR_INVAL: ::core::ffi::c_int = -(2 as ::core::ffi::c_int);
pub const CSP_ERR_AGAIN: ::core::ffi::c_int = -(12 as ::core::ffi::c_int);
pub const true_0: ::core::ffi::c_int = 1 as ::core::ffi::c_int;
pub const CSP_DBG_ERR_ALREADY_CLOSED: ::core::ffi::c_int = 10 as ::core::ffi::c_int;
pub const CSP_PORT_MAX_BIND: ::core::ffi::c_int = 16 as ::core::ffi::c_int;
pub const CSP_CONN_RXQUEUE_LEN: ::core::ffi::c_int = 16 as ::core::ffi::c_int;
pub const CSP_CONN_MAX: ::core::ffi::c_int = 8 as ::core::ffi::c_int;
pub const CSP_QUEUE_OK: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_FHMAC: ::core::ffi::c_int = 0x8 as ::core::ffi::c_int;
pub const CSP_FRDP: ::core::ffi::c_int = 0x2 as ::core::ffi::c_int;
pub const CSP_FCRC32: ::core::ffi::c_int = 0x1 as ::core::ffi::c_int;
pub const CSP_SO_RDPREQ: ::core::ffi::c_int = 0x1 as ::core::ffi::c_int;
pub const CSP_SO_HMACREQ: ::core::ffi::c_int = 0x4 as ::core::ffi::c_int;
pub const CSP_SO_CRC32REQ: ::core::ffi::c_int = 0x40 as ::core::ffi::c_int;
pub const CSP_SO_CRC32PROHIB: ::core::ffi::c_int = 0x80 as ::core::ffi::c_int;
pub const CSP_O_RDP: ::core::ffi::c_int = CSP_SO_RDPREQ;
pub const CSP_O_HMAC: ::core::ffi::c_int = CSP_SO_HMACREQ;
pub const CSP_O_CRC32: ::core::ffi::c_int = CSP_SO_CRC32REQ;
pub const CSP_O_NOCRC32: ::core::ffi::c_int = CSP_SO_CRC32PROHIB;
pub const CSP_RDP_CLOSED_BY_USERSPACE: ::core::ffi::c_int = 0x1 as ::core::ffi::c_int;
/* PATCHED BY HAND -- c2rust could not translate this static.
 *
 *   error: Failed to translate arr_conn: Unsupported default initializer:
 *          Atomic(CQualTypeId { ... })
 *
 * The C is `static csp_conn_t arr_conn[CSP_CONN_MAX] __noinit;`. c2rust cannot
 * synthesise a default initializer for a struct containing an _Atomic field, so it
 * emitted all 11 *uses* of the symbol and none of its definition -- and still exited 0.
 *
 * `core::mem::zeroed()` is not const on the nightly-2023-04-15 that c2rust pins, so the
 * initializer has to be written out field by field. The C section is .noinit, i.e.
 * genuinely uninitialised; zeroed is a superset of that and csp_conn_init() overwrites
 * every field anyway.
 */
const CONN_ZERO_ID: csp_id_t = csp_id_t { pri: 0, flags: 0, src: 0, dst: 0, dport: 0, sport: 0 };

const CONN_ZERO_RDP: csp_rdp_t = csp_rdp_t {
    state: 0,
    closed_by: 0,
    snd_nxt: 0,
    snd_una: 0,
    snd_iss: 0,
    rcv_cur: 0,
    rcv_irs: 0,
    rcv_lsa: 0,
    window_size: 0,
    conn_timeout: 0,
    packet_timeout: 0,
    delayed_acks: 0,
    ack_timeout: 0,
    ack_delay_count: 0,
    ack_timestamp: 0,
    retransmits: 0,
    tx_wait: csp_bin_sem_t { __size: [0; 32] },
};

const CONN_ZERO: csp_conn_t = csp_conn_t {
    type_0: 0,
    state: 0,
    idin: CONN_ZERO_ID,
    idout: CONN_ZERO_ID,
    sport_outgoing: 0,
    rx_queue: ::core::ptr::null_mut(),
    rx_queue_static: ::core::ptr::null_mut(),
    rx_queue_static_data: [0; 128],
    callback: None,
    dest_socket: ::core::ptr::null_mut(),
    timestamp: 0,
    opts: 0,
    rdp: CONN_ZERO_RDP,
};

static mut arr_conn: [csp_conn_t; 8] = [CONN_ZERO; 8];

static mut csp_conn_last_given: uint8_t = 0 as uint8_t;
#[no_mangle]
pub unsafe extern "C" fn csp_conn_check_timeouts() {
    let mut i: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
    while i < CSP_CONN_MAX {
        if arr_conn[i as usize].state == CONN_OPEN as ::core::ffi::c_int {
            if arr_conn[i as usize].idin.flags as ::core::ffi::c_int & CSP_FRDP != 0 {
                csp_rdp_check_timeouts(
                    (&raw mut arr_conn as *mut csp_conn_t).offset(i as isize)
                        as *mut csp_conn_t,
                );
            }
        }
        i += 1;
    }
}
#[no_mangle]
pub unsafe extern "C" fn csp_conn_enqueue_packet(
    mut conn: *mut csp_conn_t,
    mut packet: *mut csp_packet_t,
) -> ::core::ffi::c_int {
    if conn.is_null() {
        return CSP_ERR_INVAL;
    }
    if csp_queue_enqueue(
        (*conn).rx_queue,
        &raw mut packet as *const ::core::ffi::c_void,
        0 as uint32_t,
    ) != CSP_QUEUE_OK
    {
        csp_dbg_conn_ovf = csp_dbg_conn_ovf.wrapping_add(1);
        return CSP_ERR_NOMEM;
    }
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_conn_init() {
    let mut i: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
    while i < CSP_CONN_MAX {
        let mut conn: *mut csp_conn_t = (&raw mut arr_conn as *mut csp_conn_t)
            .offset(i as isize) as *mut csp_conn_t;
        (*conn).sport_outgoing = (CSP_PORT_MAX_BIND + 1 as ::core::ffi::c_int + i)
            as uint8_t;
        (*conn).state = CONN_CLOSED as ::core::ffi::c_int;
        (*conn).idin.flags = 0 as uint8_t;
        (*conn).rx_queue = csp_queue_create_static(
            CSP_CONN_RXQUEUE_LEN,
            ::core::mem::size_of::<*mut csp_packet_t>() as size_t,
            &raw mut (*conn).rx_queue_static_data as *mut ::core::ffi::c_char,
            &raw mut (*conn).rx_queue_static,
        );
        csp_rdp_init(conn);
        i += 1;
    }
}
#[no_mangle]
pub unsafe extern "C" fn csp_conn_find_dport(
    mut dport: ::core::ffi::c_uint,
) -> *mut csp_conn_t {
    let mut i: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
    while i < CSP_CONN_MAX {
        let mut conn: *mut csp_conn_t = (&raw mut arr_conn as *mut csp_conn_t)
            .offset(i as isize) as *mut csp_conn_t;
        if !((*conn).idin.dport as ::core::ffi::c_uint != dport) {
            if !((*conn).state != CONN_OPEN as ::core::ffi::c_int) {
                if !((*conn).type_0 != CONN_CLIENT as ::core::ffi::c_int) {
                    return conn;
                }
            }
        }
        i += 1;
    }
    return ::core::ptr::null_mut::<csp_conn_t>();
}
#[no_mangle]
pub unsafe extern "C" fn csp_conn_find_existing(
    mut id: *mut csp_id_t,
) -> *mut csp_conn_t {
    let mut current_block_0: u64;
    let mut i: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
    while i < CSP_CONN_MAX {
        let mut conn: *mut csp_conn_t = (&raw mut arr_conn as *mut csp_conn_t)
            .offset(i as isize) as *mut csp_conn_t;
        if !((*conn).state != CONN_OPEN as ::core::ffi::c_int) {
            if (*conn).type_0 == CONN_CLIENT as ::core::ffi::c_int {
                if (*conn).idin.dport as ::core::ffi::c_int
                    != (*id).dport as ::core::ffi::c_int
                {
                    current_block_0 = 792017965103506125;
                } else {
                    current_block_0 = 5720623009719927633;
                }
            } else if (*conn).idin.dport as ::core::ffi::c_int
                != (*id).dport as ::core::ffi::c_int
            {
                current_block_0 = 792017965103506125;
            } else if (*conn).idin.sport as ::core::ffi::c_int
                != (*id).sport as ::core::ffi::c_int
            {
                current_block_0 = 792017965103506125;
            } else if (*conn).idin.src as ::core::ffi::c_int
                != (*id).src as ::core::ffi::c_int
            {
                current_block_0 = 792017965103506125;
            } else {
                current_block_0 = 5720623009719927633;
            }
            match current_block_0 {
                792017965103506125 => {}
                _ => return conn,
            }
        }
        i += 1;
    }
    return ::core::ptr::null_mut::<csp_conn_t>();
}
unsafe extern "C" fn csp_conn_flush_rx_queue(
    mut conn: *mut csp_conn_t,
) -> ::core::ffi::c_int {
    let mut packet: *mut csp_packet_t = ::core::ptr::null_mut::<csp_packet_t>();
    while csp_queue_dequeue(
        (*conn).rx_queue,
        &raw mut packet as *mut ::core::ffi::c_void,
        0 as uint32_t,
    ) == CSP_QUEUE_OK
    {
        if !packet.is_null() {
            csp_buffer_free(packet as *mut ::core::ffi::c_void);
        }
    }
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_conn_allocate(
    mut type_0: csp_conn_type_t,
) -> *mut csp_conn_t {
    let mut conn: *mut csp_conn_t = ::core::ptr::null_mut::<csp_conn_t>();
    let mut i: ::core::ffi::c_int = csp_conn_last_given as ::core::ffi::c_int;
    let mut j: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
    while j < CSP_CONN_MAX {
        i = (i + 1 as ::core::ffi::c_int) % CSP_CONN_MAX;
        let mut expected: ::core::ffi::c_int = CONN_CLOSED as ::core::ffi::c_int;
        let fresh0 = ::core::intrinsics::atomic_cxchg_seqcst_seqcst(
            &raw mut (*(&raw mut arr_conn as *mut csp_conn_t).offset(i as isize)).state,
            *&raw mut expected,
            CONN_OPEN as ::core::ffi::c_int,
        );
        *&raw mut expected = fresh0.0;
        if fresh0.1 {
            conn = (&raw mut arr_conn as *mut csp_conn_t).offset(i as isize)
                as *mut csp_conn_t;
            csp_conn_last_given = i as uint8_t;
            break;
        } else {
            j += 1;
        }
    }
    if conn.is_null() {
        csp_dbg_conn_out = csp_dbg_conn_out.wrapping_add(1);
        return ::core::ptr::null_mut::<csp_conn_t>();
    }
    (*conn).timestamp = 0 as uint32_t;
    (*conn).type_0 = type_0 as ::core::ffi::c_int;
    (*conn).idin.flags = 0 as uint8_t;
    (*conn).idout.flags = 0 as uint8_t;
    return conn;
}
#[no_mangle]
pub unsafe extern "C" fn csp_conn_new(
    mut idin: csp_id_t,
    mut idout: csp_id_t,
    mut type_0: csp_conn_type_t,
) -> *mut csp_conn_t {
    let mut conn: *mut csp_conn_t = csp_conn_allocate(type_0);
    if !conn.is_null() {
        csp_id_copy(&raw mut (*conn).idin, &raw mut idin);
        csp_id_copy(&raw mut (*conn).idout, &raw mut idout);
        (*conn).timestamp = csp_get_ms();
        csp_conn_flush_rx_queue(conn);
    }
    return conn;
}
#[no_mangle]
pub unsafe extern "C" fn csp_close(mut conn: *mut csp_conn_t) -> ::core::ffi::c_int {
    return csp_conn_close(conn, CSP_RDP_CLOSED_BY_USERSPACE as uint8_t);
}
#[no_mangle]
pub unsafe extern "C" fn csp_conn_close(
    mut conn: *mut csp_conn_t,
    mut closed_by: uint8_t,
) -> ::core::ffi::c_int {
    if conn.is_null() {
        return CSP_ERR_NONE;
    }
    if (*conn).state == CONN_CLOSED as ::core::ffi::c_int {
        csp_dbg_errno = CSP_DBG_ERR_ALREADY_CLOSED as uint8_t;
        return CSP_ERR_NONE;
    }
    if (*conn).idin.flags as ::core::ffi::c_int & CSP_FRDP != 0
        || (*conn).idout.flags as ::core::ffi::c_int & CSP_FRDP != 0
    {
        if csp_rdp_close(conn, closed_by) == CSP_ERR_AGAIN {
            return CSP_ERR_NONE;
        }
    }
    csp_conn_flush_rx_queue(conn);
    if (*conn).idin.flags as ::core::ffi::c_int & CSP_FRDP != 0 {
        csp_rdp_queue_flush(conn);
    }
    (*conn).state = CONN_CLOSED as ::core::ffi::c_int;
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_connect(
    mut prio: uint8_t,
    mut dest: uint16_t,
    mut dport: uint8_t,
    mut timeout: uint32_t,
    mut opts: uint32_t,
) -> *mut csp_conn_t {
    opts |= csp_conf.conn_dfl_so;
    let mut incoming_id: csp_id_t = csp_id_t {
        pri: 0 as uint8_t,
        flags: 0,
        src: 0,
        dst: 0,
        dport: 0,
        sport: 0,
    };
    let mut outgoing_id: csp_id_t = csp_id_t {
        pri: 0 as uint8_t,
        flags: 0,
        src: 0,
        dst: 0,
        dport: 0,
        sport: 0,
    };
    incoming_id.dst = 0 as uint16_t;
    outgoing_id.src = 0 as uint16_t;
    incoming_id.pri = prio;
    outgoing_id.pri = prio;
    incoming_id.src = dest;
    outgoing_id.dst = dest;
    incoming_id.sport = dport;
    outgoing_id.dport = dport;
    incoming_id.flags = 0 as uint8_t;
    outgoing_id.flags = 0 as uint8_t;
    if opts & CSP_O_NOCRC32 as uint32_t != 0 {
        opts &= !CSP_O_CRC32 as uint32_t;
    }
    if opts & CSP_O_RDP as uint32_t != 0 {
        incoming_id.flags = (incoming_id.flags as ::core::ffi::c_int | CSP_FRDP)
            as uint8_t;
        outgoing_id.flags = (outgoing_id.flags as ::core::ffi::c_int | CSP_FRDP)
            as uint8_t;
    }
    if opts & CSP_O_HMAC as uint32_t != 0 {
        outgoing_id.flags = (outgoing_id.flags as ::core::ffi::c_int | CSP_FHMAC)
            as uint8_t;
        incoming_id.flags = (incoming_id.flags as ::core::ffi::c_int | CSP_FHMAC)
            as uint8_t;
    }
    if opts & CSP_O_CRC32 as uint32_t != 0 {
        outgoing_id.flags = (outgoing_id.flags as ::core::ffi::c_int | CSP_FCRC32)
            as uint8_t;
        incoming_id.flags = (incoming_id.flags as ::core::ffi::c_int | CSP_FCRC32)
            as uint8_t;
    }
    let mut conn: *mut csp_conn_t = csp_conn_new(incoming_id, outgoing_id, CONN_CLIENT);
    if conn.is_null() {
        return ::core::ptr::null_mut::<csp_conn_t>();
    }
    (*conn).idout.sport = (*conn).sport_outgoing;
    (*conn).idin.dport = (*conn).sport_outgoing;
    (*conn).dest_socket = ::core::ptr::null_mut::<csp_socket_t>();
    (*conn).opts = opts;
    if outgoing_id.flags as ::core::ffi::c_int & CSP_FRDP != 0 {
        if csp_rdp_connect(conn) != CSP_ERR_NONE {
            csp_close(conn);
            return ::core::ptr::null_mut::<csp_conn_t>();
        }
    }
    return conn;
}
#[no_mangle]
pub unsafe extern "C" fn csp_conn_dport(
    mut conn: *const csp_conn_t,
) -> ::core::ffi::c_int {
    return (*conn).idin.dport as ::core::ffi::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn csp_conn_sport(
    mut conn: *const csp_conn_t,
) -> ::core::ffi::c_int {
    return (*conn).idin.sport as ::core::ffi::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn csp_conn_dst(
    mut conn: *const csp_conn_t,
) -> ::core::ffi::c_int {
    return (*conn).idin.dst as ::core::ffi::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn csp_conn_src(
    mut conn: *const csp_conn_t,
) -> ::core::ffi::c_int {
    return (*conn).idin.src as ::core::ffi::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn csp_conn_flags(
    mut conn: *const csp_conn_t,
) -> ::core::ffi::c_int {
    return (*conn).idin.flags as ::core::ffi::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn csp_conn_print_table() {
    let mut i: ::core::ffi::c_uint = 0 as ::core::ffi::c_uint;
    while i < CSP_CONN_MAX as ::core::ffi::c_uint {
        let mut conn: *mut csp_conn_t = (&raw mut arr_conn as *mut csp_conn_t)
            .offset(i as isize) as *mut csp_conn_t;
        csp_print_func(
            b"[%02u %p] S:%u, %u -> %u, %u -> %u (%u) fl %x\r\n\0" as *const u8
                as *const ::core::ffi::c_char,
            i,
            conn as *mut ::core::ffi::c_void,
            (*conn).state,
            (*conn).idin.src as ::core::ffi::c_int,
            (*conn).idin.dst as ::core::ffi::c_int,
            (*conn).idin.dport as ::core::ffi::c_int,
            (*conn).idin.sport as ::core::ffi::c_int,
            (*conn).sport_outgoing as ::core::ffi::c_int,
            (*conn).idin.flags as ::core::ffi::c_int,
        );
        if (*conn).idin.flags as ::core::ffi::c_int & CSP_FRDP != 0 {
            csp_print_func(
                b"\tRDP: S:%d (closed by 0x%x), rcv %u, snd %u, win %u\n\0" as *const u8
                    as *const ::core::ffi::c_char,
                (*conn).rdp.state as ::core::ffi::c_uint,
                (*conn).rdp.closed_by as ::core::ffi::c_int,
                (*conn).rdp.rcv_cur as ::core::ffi::c_int,
                (*conn).rdp.snd_una as ::core::ffi::c_int,
                (*conn).rdp.window_size,
            );
        }
        i = i.wrapping_add(1);
    }
}
#[no_mangle]
pub unsafe extern "C" fn csp_conn_print_table_str(
    mut str_buf: *mut ::core::ffi::c_char,
    mut str_size: ::core::ffi::c_int,
) -> ::core::ffi::c_int {
    let mut start: ::core::ffi::c_uint = (if CSP_CONN_MAX > 10 as ::core::ffi::c_int {
        CSP_CONN_MAX - 10 as ::core::ffi::c_int
    } else {
        0 as ::core::ffi::c_int
    }) as ::core::ffi::c_uint;
    let mut i: ::core::ffi::c_uint = start;
    while i < CSP_CONN_MAX as ::core::ffi::c_uint {
        let mut conn: *mut csp_conn_t = (&raw mut arr_conn as *mut csp_conn_t)
            .offset(i as isize) as *mut csp_conn_t;
        let mut buf: [::core::ffi::c_char; 100] = [0; 100];
        snprintf(
            &raw mut buf as *mut ::core::ffi::c_char,
            ::core::mem::size_of::<[::core::ffi::c_char; 100]>() as size_t,
            b"[%02u %p] S:%u, %u -> %u, %u -> %u (%u)\n\0" as *const u8
                as *const ::core::ffi::c_char,
            i,
            conn as *mut ::core::ffi::c_void,
            (*conn).state,
            (*conn).idin.src as ::core::ffi::c_int,
            (*conn).idin.dst as ::core::ffi::c_int,
            (*conn).idin.dport as ::core::ffi::c_int,
            (*conn).idin.sport as ::core::ffi::c_int,
            (*conn).sport_outgoing as ::core::ffi::c_int,
        );
        strncat(str_buf, &raw mut buf as *mut ::core::ffi::c_char, str_size as size_t);
        str_size = (str_size as size_t)
            .wrapping_sub(strlen(&raw mut buf as *mut ::core::ffi::c_char))
            as ::core::ffi::c_int as ::core::ffi::c_int;
        if str_size <= 0 as ::core::ffi::c_int {
            break;
        }
        i = i.wrapping_add(1);
    }
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_conn_get_array(mut size: *mut size_t) -> *const csp_conn_t {
    *size = CSP_CONN_MAX as size_t;
    return &raw mut arr_conn as *mut csp_conn_t;
}
#[no_mangle]
pub unsafe extern "C" fn csp_conn_is_active(mut conn: *mut csp_conn_t) -> bool {
    if (*conn).idin.flags as ::core::ffi::c_int & CSP_FRDP != 0
        || (*conn).idout.flags as ::core::ffi::c_int & CSP_FRDP != 0
    {
        return csp_rdp_conn_is_active(conn);
    }
    return true_0 != 0;
}
pub const __ATOMIC_SEQ_CST: ::core::ffi::c_int = 5 as ::core::ffi::c_int;
pub const NULL: *mut ::core::ffi::c_void = ::core::ptr::null_mut::<
    ::core::ffi::c_void,
>();
