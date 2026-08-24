extern "C" {
    pub type pthread_queue_s;
    static mut csp_if_lo: csp_iface_t;
    fn csp_buffer_init();
    fn csp_iflist_add(iface: *mut csp_iface_t);
    fn csp_id_get_host_bits() -> ::core::ffi::c_uint;
    fn csp_conn_init();
    fn csp_qfifo_init();
    fn csp_rdp_queue_init();
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
pub const CSP_SO_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_O_NONE: ::core::ffi::c_int = CSP_SO_NONE;
#[no_mangle]
pub unsafe extern "C" fn csp_panic(mut msg: *const ::core::ffi::c_char) {}
#[no_mangle]
pub static mut csp_conf: csp_conf_t = csp_conf_s {
    version: 2 as uint8_t,
    hostname: b"\0" as *const u8 as *const ::core::ffi::c_char,
    model: b"\0" as *const u8 as *const ::core::ffi::c_char,
    revision: b"\0" as *const u8 as *const ::core::ffi::c_char,
    conn_dfl_so: CSP_O_NONE as uint32_t,
    dedup: CSP_DEDUP_OFF as ::core::ffi::c_int as uint8_t,
};
#[no_mangle]
pub unsafe extern "C" fn csp_init() {
    if csp_conf.version as ::core::ffi::c_int == 0 as ::core::ffi::c_int
        || csp_conf.version as ::core::ffi::c_int > 2 as ::core::ffi::c_int
    {
        csp_conf.version = 2 as uint8_t;
    }
    if csp_conf.dedup as ::core::ffi::c_int > CSP_DEDUP_ALL as ::core::ffi::c_int {
        csp_conf.dedup = CSP_DEDUP_OFF as ::core::ffi::c_int as uint8_t;
    }
    csp_buffer_init();
    csp_conn_init();
    csp_qfifo_init();
    csp_rdp_queue_init();
    csp_if_lo.netmask = csp_id_get_host_bits() as uint16_t;
    csp_iflist_add(&raw mut csp_if_lo);
}
#[no_mangle]
pub unsafe extern "C" fn csp_get_conf() -> *const csp_conf_t {
    return &raw mut csp_conf;
}
