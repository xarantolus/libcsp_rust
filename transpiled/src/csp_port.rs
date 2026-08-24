extern "C" {
    pub type pthread_queue_s;
    fn csp_queue_create_static(
        length: ::core::ffi::c_int,
        item_size: size_t,
        buffer: *mut ::core::ffi::c_char,
        queue: *mut csp_static_queue_t,
    ) -> csp_queue_handle_t;
    fn csp_queue_dequeue(
        handle: csp_queue_handle_t,
        buf: *mut ::core::ffi::c_void,
        timeout: uint32_t,
    ) -> ::core::ffi::c_int;
    fn csp_queue_free(handle: csp_queue_handle_t) -> ::core::ffi::c_int;
    static mut csp_dbg_errno: uint8_t;
    fn csp_buffer_free(buffer: *mut ::core::ffi::c_void);
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
pub type csp_callback_t = Option<unsafe extern "C" fn(*mut csp_packet_t) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
    pub socket: *mut csp_socket_t,
    pub callback: csp_callback_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct csp_port_t {
    pub state: csp_port_state_t,
    pub c2rust_unnamed: C2RustUnnamed_0,
}
pub type csp_port_state_t = ::core::ffi::c_uint;
pub const PORT_OPEN_CB: csp_port_state_t = 2;
pub const PORT_OPEN: csp_port_state_t = 1;
pub const PORT_CLOSED: csp_port_state_t = 0;
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ERR_INVAL: ::core::ffi::c_int = -(2 as ::core::ffi::c_int);
pub const CSP_ERR_USED: ::core::ffi::c_int = -(4 as ::core::ffi::c_int);
pub const CSP_ERR_ALREADY: ::core::ffi::c_int = -(7 as ::core::ffi::c_int);
pub const CSP_PORT_MAX_BIND: ::core::ffi::c_int = 16 as ::core::ffi::c_int;
pub const CSP_CONN_RXQUEUE_LEN: ::core::ffi::c_int = 16 as ::core::ffi::c_int;
pub const CSP_QUEUE_OK: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ANY: ::core::ffi::c_int = 255 as ::core::ffi::c_int;
pub const CSP_SO_CONN_LESS: ::core::ffi::c_int = 0x100 as ::core::ffi::c_int;
pub const NULL: *mut ::core::ffi::c_void = ::core::ptr::null_mut::<
    ::core::ffi::c_void,
>();
pub const CSP_DBG_ERR_INVALID_BIND_PORT: ::core::ffi::c_int = 8 as ::core::ffi::c_int;
pub const CSP_DBG_ERR_PORT_ALREADY_IN_USE: ::core::ffi::c_int = 9 as ::core::ffi::c_int;
pub const CSP_DBG_ERR_INVALID_POINTER: ::core::ffi::c_int = 11 as ::core::ffi::c_int;
static mut ports: [csp_port_t; 18] = [
    csp_port_t {
        state: PORT_CLOSED,
        c2rust_unnamed: C2RustUnnamed_0 {
            socket: ::core::ptr::null::<csp_socket_t>() as *mut csp_socket_t,
        },
    },
    csp_port_t {
        state: PORT_CLOSED,
        c2rust_unnamed: C2RustUnnamed_0 {
            socket: ::core::ptr::null::<csp_socket_t>() as *mut csp_socket_t,
        },
    },
    csp_port_t {
        state: PORT_CLOSED,
        c2rust_unnamed: C2RustUnnamed_0 {
            socket: ::core::ptr::null::<csp_socket_t>() as *mut csp_socket_t,
        },
    },
    csp_port_t {
        state: PORT_CLOSED,
        c2rust_unnamed: C2RustUnnamed_0 {
            socket: ::core::ptr::null::<csp_socket_t>() as *mut csp_socket_t,
        },
    },
    csp_port_t {
        state: PORT_CLOSED,
        c2rust_unnamed: C2RustUnnamed_0 {
            socket: ::core::ptr::null::<csp_socket_t>() as *mut csp_socket_t,
        },
    },
    csp_port_t {
        state: PORT_CLOSED,
        c2rust_unnamed: C2RustUnnamed_0 {
            socket: ::core::ptr::null::<csp_socket_t>() as *mut csp_socket_t,
        },
    },
    csp_port_t {
        state: PORT_CLOSED,
        c2rust_unnamed: C2RustUnnamed_0 {
            socket: ::core::ptr::null::<csp_socket_t>() as *mut csp_socket_t,
        },
    },
    csp_port_t {
        state: PORT_CLOSED,
        c2rust_unnamed: C2RustUnnamed_0 {
            socket: ::core::ptr::null::<csp_socket_t>() as *mut csp_socket_t,
        },
    },
    csp_port_t {
        state: PORT_CLOSED,
        c2rust_unnamed: C2RustUnnamed_0 {
            socket: ::core::ptr::null::<csp_socket_t>() as *mut csp_socket_t,
        },
    },
    csp_port_t {
        state: PORT_CLOSED,
        c2rust_unnamed: C2RustUnnamed_0 {
            socket: ::core::ptr::null::<csp_socket_t>() as *mut csp_socket_t,
        },
    },
    csp_port_t {
        state: PORT_CLOSED,
        c2rust_unnamed: C2RustUnnamed_0 {
            socket: ::core::ptr::null::<csp_socket_t>() as *mut csp_socket_t,
        },
    },
    csp_port_t {
        state: PORT_CLOSED,
        c2rust_unnamed: C2RustUnnamed_0 {
            socket: ::core::ptr::null::<csp_socket_t>() as *mut csp_socket_t,
        },
    },
    csp_port_t {
        state: PORT_CLOSED,
        c2rust_unnamed: C2RustUnnamed_0 {
            socket: ::core::ptr::null::<csp_socket_t>() as *mut csp_socket_t,
        },
    },
    csp_port_t {
        state: PORT_CLOSED,
        c2rust_unnamed: C2RustUnnamed_0 {
            socket: ::core::ptr::null::<csp_socket_t>() as *mut csp_socket_t,
        },
    },
    csp_port_t {
        state: PORT_CLOSED,
        c2rust_unnamed: C2RustUnnamed_0 {
            socket: ::core::ptr::null::<csp_socket_t>() as *mut csp_socket_t,
        },
    },
    csp_port_t {
        state: PORT_CLOSED,
        c2rust_unnamed: C2RustUnnamed_0 {
            socket: ::core::ptr::null::<csp_socket_t>() as *mut csp_socket_t,
        },
    },
    csp_port_t {
        state: PORT_CLOSED,
        c2rust_unnamed: C2RustUnnamed_0 {
            socket: ::core::ptr::null::<csp_socket_t>() as *mut csp_socket_t,
        },
    },
    csp_port_t {
        state: PORT_CLOSED,
        c2rust_unnamed: C2RustUnnamed_0 {
            socket: ::core::ptr::null::<csp_socket_t>() as *mut csp_socket_t,
        },
    },
];
#[no_mangle]
pub unsafe extern "C" fn csp_port_get_callback(
    mut port: ::core::ffi::c_uint,
) -> csp_callback_t {
    if port > CSP_PORT_MAX_BIND as ::core::ffi::c_uint {
        return None;
    }
    if ports[port as usize].state as ::core::ffi::c_uint
        == PORT_OPEN_CB as ::core::ffi::c_int as ::core::ffi::c_uint
    {
        return ports[port as usize].c2rust_unnamed.callback;
    }
    if ports[port as usize].state as ::core::ffi::c_uint
        == PORT_OPEN as ::core::ffi::c_int as ::core::ffi::c_uint
    {
        return None;
    }
    if ports[(CSP_PORT_MAX_BIND + 1 as ::core::ffi::c_int) as usize].state
        as ::core::ffi::c_uint
        == PORT_OPEN_CB as ::core::ffi::c_int as ::core::ffi::c_uint
    {
        return ports[(CSP_PORT_MAX_BIND + 1 as ::core::ffi::c_int) as usize]
            .c2rust_unnamed
            .callback;
    }
    return None;
}
#[no_mangle]
pub unsafe extern "C" fn csp_port_get_socket(
    mut port: ::core::ffi::c_uint,
) -> *mut csp_socket_t {
    if port > CSP_PORT_MAX_BIND as ::core::ffi::c_uint {
        return ::core::ptr::null_mut::<csp_socket_t>();
    }
    if ports[port as usize].state as ::core::ffi::c_uint
        == PORT_OPEN as ::core::ffi::c_int as ::core::ffi::c_uint
    {
        return ports[port as usize].c2rust_unnamed.socket;
    }
    if ports[port as usize].state as ::core::ffi::c_uint
        == PORT_OPEN_CB as ::core::ffi::c_int as ::core::ffi::c_uint
    {
        return ::core::ptr::null_mut::<csp_socket_t>();
    }
    if ports[(CSP_PORT_MAX_BIND + 1 as ::core::ffi::c_int) as usize].state
        as ::core::ffi::c_uint == PORT_OPEN as ::core::ffi::c_int as ::core::ffi::c_uint
    {
        return ports[(CSP_PORT_MAX_BIND + 1 as ::core::ffi::c_int) as usize]
            .c2rust_unnamed
            .socket;
    }
    return ::core::ptr::null_mut::<csp_socket_t>();
}
#[no_mangle]
pub unsafe extern "C" fn csp_socket_is_conn_less(
    mut socket: *const csp_socket_t,
) -> bool {
    return (*socket).opts & CSP_SO_CONN_LESS as uint32_t != 0 as uint32_t;
}
#[no_mangle]
pub unsafe extern "C" fn csp_listen(
    mut socket: *mut csp_socket_t,
    mut backlog: size_t,
) -> ::core::ffi::c_int {
    (*socket).rx_queue = csp_queue_create_static(
        CSP_CONN_RXQUEUE_LEN,
        ::core::mem::size_of::<*mut csp_packet_t>() as size_t,
        &raw mut (*socket).rx_queue_static_data as *mut ::core::ffi::c_char,
        &raw mut (*socket).rx_queue_static,
    );
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_bind(
    mut socket: *mut csp_socket_t,
    mut port: uint8_t,
) -> ::core::ffi::c_int {
    if socket.is_null() {
        return CSP_ERR_INVAL;
    }
    if port as ::core::ffi::c_int == CSP_ANY {
        port = (CSP_PORT_MAX_BIND + 1 as ::core::ffi::c_int) as uint8_t;
    } else if port as ::core::ffi::c_int > CSP_PORT_MAX_BIND {
        csp_dbg_errno = CSP_DBG_ERR_INVALID_BIND_PORT as uint8_t;
        return CSP_ERR_INVAL;
    }
    if ports[port as usize].state as ::core::ffi::c_uint
        != PORT_CLOSED as ::core::ffi::c_int as ::core::ffi::c_uint
    {
        csp_dbg_errno = CSP_DBG_ERR_PORT_ALREADY_IN_USE as uint8_t;
        return CSP_ERR_USED;
    }
    ports[port as usize].c2rust_unnamed.socket = socket;
    ports[port as usize].state = PORT_OPEN;
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_bind_callback(
    mut callback: csp_callback_t,
    mut port: uint8_t,
) -> ::core::ffi::c_int {
    if callback.is_none() {
        csp_dbg_errno = CSP_DBG_ERR_INVALID_POINTER as uint8_t;
        return CSP_ERR_INVAL;
    }
    if port as ::core::ffi::c_int == CSP_ANY {
        port = (CSP_PORT_MAX_BIND + 1 as ::core::ffi::c_int) as uint8_t;
    } else if port as ::core::ffi::c_int > CSP_PORT_MAX_BIND {
        csp_dbg_errno = CSP_DBG_ERR_INVALID_BIND_PORT as uint8_t;
        return CSP_ERR_INVAL;
    }
    if ports[port as usize].state as ::core::ffi::c_uint
        != PORT_CLOSED as ::core::ffi::c_int as ::core::ffi::c_uint
    {
        csp_dbg_errno = CSP_DBG_ERR_PORT_ALREADY_IN_USE as uint8_t;
        return CSP_ERR_ALREADY;
    }
    ports[port as usize].c2rust_unnamed.callback = callback;
    ports[port as usize].state = PORT_OPEN_CB;
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_socket_close(
    mut sock: *mut csp_socket_t,
) -> ::core::ffi::c_int {
    if sock.is_null() {
        return CSP_ERR_NONE;
    }
    let mut i: size_t = 0 as size_t;
    while i < (CSP_PORT_MAX_BIND + 2 as ::core::ffi::c_int) as size_t {
        let mut port: *mut csp_port_t = (&raw mut ports as *mut csp_port_t)
            .offset(i as isize) as *mut csp_port_t;
        if (*port).state as ::core::ffi::c_uint
            == PORT_OPEN as ::core::ffi::c_int as ::core::ffi::c_uint
            && (*port).c2rust_unnamed.socket == sock
        {
            (*port).state = PORT_CLOSED;
            (*port).c2rust_unnamed.socket = ::core::ptr::null_mut::<csp_socket_t>();
            break;
        } else {
            i = i.wrapping_add(1);
        }
    }
    if !(*sock).rx_queue.is_null() {
        let mut packet: *mut csp_packet_t = ::core::ptr::null_mut::<csp_packet_t>();
        while csp_queue_dequeue(
            (*sock).rx_queue,
            &raw mut packet as *mut ::core::ffi::c_void,
            0 as uint32_t,
        ) == CSP_QUEUE_OK
        {
            if !packet.is_null() {
                csp_buffer_free(packet as *mut ::core::ffi::c_void);
            }
        }
        csp_queue_free((*sock).rx_queue);
    }
    return CSP_ERR_NONE;
}
