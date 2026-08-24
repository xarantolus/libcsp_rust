extern "C" {
    pub type csp_conn_s;
    fn csp_print_func(fmt: *const ::core::ffi::c_char, ...);
    fn csp_buffer_get(unused: size_t) -> *mut csp_packet_t;
    fn csp_buffer_free(buffer: *mut ::core::ffi::c_void);
    fn csp_qfifo_write(
        packet: *mut csp_packet_t,
        iface: *mut csp_iface_t,
        pxTaskWoken: *mut ::core::ffi::c_void,
    );
    fn csp_iflist_add(iface: *mut csp_iface_t);
    fn pthread_create(
        __newthread: *mut pthread_t,
        __attr: *const pthread_attr_t,
        __start_routine: Option<
            unsafe extern "C" fn(*mut ::core::ffi::c_void) -> *mut ::core::ffi::c_void,
        >,
        __arg: *mut ::core::ffi::c_void,
    ) -> ::core::ffi::c_int;
    fn pthread_attr_init(__attr: *mut pthread_attr_t) -> ::core::ffi::c_int;
    fn pthread_attr_destroy(__attr: *mut pthread_attr_t) -> ::core::ffi::c_int;
    fn pthread_attr_setdetachstate(
        __attr: *mut pthread_attr_t,
        __detachstate: ::core::ffi::c_int,
    ) -> ::core::ffi::c_int;
    fn socket(
        __domain: ::core::ffi::c_int,
        __type: ::core::ffi::c_int,
        __protocol: ::core::ffi::c_int,
    ) -> ::core::ffi::c_int;
    fn bind(
        __fd: ::core::ffi::c_int,
        __addr: *const sockaddr,
        __len: socklen_t,
    ) -> ::core::ffi::c_int;
    fn sendto(
        __fd: ::core::ffi::c_int,
        __buf: *const ::core::ffi::c_void,
        __n: size_t,
        __flags: ::core::ffi::c_int,
        __addr: *const sockaddr,
        __addr_len: socklen_t,
    ) -> ssize_t;
    fn recvfrom(
        __fd: ::core::ffi::c_int,
        __buf: *mut ::core::ffi::c_void,
        __n: size_t,
        __flags: ::core::ffi::c_int,
        __addr: *mut sockaddr,
        __addr_len: *mut socklen_t,
    ) -> ssize_t;
    fn strerror(__errnum: ::core::ffi::c_int) -> *mut ::core::ffi::c_char;
    fn sleep(__seconds: ::core::ffi::c_uint) -> ::core::ffi::c_uint;
    fn usleep(__useconds: __useconds_t) -> ::core::ffi::c_int;
    fn inet_ntoa(__in: in_addr) -> *mut ::core::ffi::c_char;
    fn inet_aton(
        __cp: *const ::core::ffi::c_char,
        __inp: *mut in_addr,
    ) -> ::core::ffi::c_int;
    fn csp_id_prepend(packet: *mut csp_packet_t);
    fn csp_id_strip(packet: *mut csp_packet_t) -> ::core::ffi::c_int;
    fn csp_id_setup_rx(packet: *mut csp_packet_t) -> ::core::ffi::c_int;
}
pub type __uint8_t = u8;
pub type __uint16_t = u16;
pub type __uint32_t = u32;
pub type __uint64_t = u64;
pub type __useconds_t = ::core::ffi::c_uint;
pub type __socklen_t = ::core::ffi::c_uint;
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
pub type pthread_t = ::core::ffi::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_attr_t {
    pub __size: [::core::ffi::c_char; 56],
    pub __align: ::core::ffi::c_long,
}
pub type C2RustUnnamed_0 = ::core::ffi::c_uint;
pub const PTHREAD_CREATE_DETACHED: C2RustUnnamed_0 = 1;
pub const PTHREAD_CREATE_JOINABLE: C2RustUnnamed_0 = 0;
pub type ssize_t = isize;
pub type socklen_t = __socklen_t;
pub type __socket_type = ::core::ffi::c_uint;
pub const SOCK_NONBLOCK: __socket_type = 2048;
pub const SOCK_CLOEXEC: __socket_type = 524288;
pub const SOCK_PACKET: __socket_type = 10;
pub const SOCK_DCCP: __socket_type = 6;
pub const SOCK_SEQPACKET: __socket_type = 5;
pub const SOCK_RDM: __socket_type = 4;
pub const SOCK_RAW: __socket_type = 3;
pub const SOCK_DGRAM: __socket_type = 2;
pub const SOCK_STREAM: __socket_type = 1;
pub type sa_family_t = ::core::ffi::c_ushort;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [::core::ffi::c_char; 14],
}
pub type C2RustUnnamed_1 = ::core::ffi::c_uint;
pub const MSG_CMSG_CLOEXEC: C2RustUnnamed_1 = 1073741824;
pub const MSG_FASTOPEN: C2RustUnnamed_1 = 536870912;
pub const MSG_ZEROCOPY: C2RustUnnamed_1 = 67108864;
pub const MSG_BATCH: C2RustUnnamed_1 = 262144;
pub const MSG_WAITFORONE: C2RustUnnamed_1 = 65536;
pub const MSG_MORE: C2RustUnnamed_1 = 32768;
pub const MSG_NOSIGNAL: C2RustUnnamed_1 = 16384;
pub const MSG_ERRQUEUE: C2RustUnnamed_1 = 8192;
pub const MSG_RST: C2RustUnnamed_1 = 4096;
pub const MSG_CONFIRM: C2RustUnnamed_1 = 2048;
pub const MSG_SYN: C2RustUnnamed_1 = 1024;
pub const MSG_FIN: C2RustUnnamed_1 = 512;
pub const MSG_WAITALL: C2RustUnnamed_1 = 256;
pub const MSG_EOR: C2RustUnnamed_1 = 128;
pub const MSG_DONTWAIT: C2RustUnnamed_1 = 64;
pub const MSG_TRUNC: C2RustUnnamed_1 = 32;
pub const MSG_PROXY: C2RustUnnamed_1 = 16;
pub const MSG_CTRUNC: C2RustUnnamed_1 = 8;
pub const MSG_DONTROUTE: C2RustUnnamed_1 = 4;
pub const MSG_PEEK: C2RustUnnamed_1 = 2;
pub const MSG_OOB: C2RustUnnamed_1 = 1;
pub type in_addr_t = uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in_addr {
    pub s_addr: in_addr_t,
}
pub type C2RustUnnamed_2 = ::core::ffi::c_uint;
pub const IPPROTO_MAX: C2RustUnnamed_2 = 263;
pub const IPPROTO_MPTCP: C2RustUnnamed_2 = 262;
pub const IPPROTO_RAW: C2RustUnnamed_2 = 255;
pub const IPPROTO_ETHERNET: C2RustUnnamed_2 = 143;
pub const IPPROTO_MPLS: C2RustUnnamed_2 = 137;
pub const IPPROTO_UDPLITE: C2RustUnnamed_2 = 136;
pub const IPPROTO_SCTP: C2RustUnnamed_2 = 132;
pub const IPPROTO_L2TP: C2RustUnnamed_2 = 115;
pub const IPPROTO_COMP: C2RustUnnamed_2 = 108;
pub const IPPROTO_PIM: C2RustUnnamed_2 = 103;
pub const IPPROTO_ENCAP: C2RustUnnamed_2 = 98;
pub const IPPROTO_BEETPH: C2RustUnnamed_2 = 94;
pub const IPPROTO_MTP: C2RustUnnamed_2 = 92;
pub const IPPROTO_AH: C2RustUnnamed_2 = 51;
pub const IPPROTO_ESP: C2RustUnnamed_2 = 50;
pub const IPPROTO_GRE: C2RustUnnamed_2 = 47;
pub const IPPROTO_RSVP: C2RustUnnamed_2 = 46;
pub const IPPROTO_IPV6: C2RustUnnamed_2 = 41;
pub const IPPROTO_DCCP: C2RustUnnamed_2 = 33;
pub const IPPROTO_TP: C2RustUnnamed_2 = 29;
pub const IPPROTO_IDP: C2RustUnnamed_2 = 22;
pub const IPPROTO_UDP: C2RustUnnamed_2 = 17;
pub const IPPROTO_PUP: C2RustUnnamed_2 = 12;
pub const IPPROTO_EGP: C2RustUnnamed_2 = 8;
pub const IPPROTO_TCP: C2RustUnnamed_2 = 6;
pub const IPPROTO_IPIP: C2RustUnnamed_2 = 4;
pub const IPPROTO_IGMP: C2RustUnnamed_2 = 2;
pub const IPPROTO_ICMP: C2RustUnnamed_2 = 1;
pub const IPPROTO_IP: C2RustUnnamed_2 = 0;
pub type in_port_t = uint16_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_in {
    pub sin_family: sa_family_t,
    pub sin_port: in_port_t,
    pub sin_addr: in_addr,
    pub sin_zero: [::core::ffi::c_uchar; 8],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct csp_if_udp_conf_t {
    pub host: *mut ::core::ffi::c_char,
    pub lport: ::core::ffi::c_int,
    pub rport: ::core::ffi::c_int,
    pub server_handle: pthread_t,
    pub peer_addr: sockaddr_in,
    pub sockfd: ::core::ffi::c_int,
}
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ERR_NOMEM: ::core::ffi::c_int = -(1 as ::core::ffi::c_int);
pub const CSP_ERR_INVAL: ::core::ffi::c_int = -(2 as ::core::ffi::c_int);
pub const NULL: *mut ::core::ffi::c_void = ::core::ptr::null_mut::<
    ::core::ffi::c_void,
>();
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
pub const PF_INET: ::core::ffi::c_int = 2 as ::core::ffi::c_int;
pub const AF_INET: ::core::ffi::c_int = PF_INET;
unsafe extern "C" fn csp_if_udp_tx(
    mut iface: *mut csp_iface_t,
    mut via: uint16_t,
    mut packet: *mut csp_packet_t,
    mut from_me: ::core::ffi::c_int,
) -> ::core::ffi::c_int {
    let mut ifconf: *mut csp_if_udp_conf_t = (*iface).driver_data
        as *mut csp_if_udp_conf_t;
    if (*ifconf).sockfd == 0 as ::core::ffi::c_int {
        csp_print_func(b"Sockfd null\n\0" as *const u8 as *const ::core::ffi::c_char);
        csp_buffer_free(packet as *mut ::core::ffi::c_void);
        return CSP_ERR_NONE;
    }
    csp_id_prepend(packet);
    (*ifconf).peer_addr.sin_family = AF_INET as sa_family_t;
    (*ifconf).peer_addr.sin_port = __bswap_16((*ifconf).rport as __uint16_t)
        as in_port_t;
    sendto(
        (*ifconf).sockfd,
        (*packet).frame_begin as *const ::core::ffi::c_void,
        (*packet).frame_length as size_t,
        MSG_CONFIRM as ::core::ffi::c_int,
        &raw mut (*ifconf).peer_addr as *mut sockaddr,
        ::core::mem::size_of::<sockaddr_in>() as socklen_t,
    );
    csp_buffer_free(packet as *mut ::core::ffi::c_void);
    return CSP_ERR_NONE;
}
unsafe extern "C" fn csp_if_udp_rx_work(
    mut sockfd: ::core::ffi::c_int,
    mut unused: size_t,
    mut iface: *mut csp_iface_t,
) -> ::core::ffi::c_int {
    let mut packet: *mut csp_packet_t = csp_buffer_get(0 as size_t);
    if packet.is_null() {
        return CSP_ERR_NOMEM;
    }
    let mut header_size: ::core::ffi::c_int = csp_id_setup_rx(packet);
    let mut received_len: ::core::ffi::c_int = recvfrom(
        sockfd,
        (*packet).frame_begin as *mut ::core::ffi::c_char as *mut ::core::ffi::c_void,
        (::core::mem::size_of::<[uint8_t; 256]>() as size_t)
            .wrapping_add(header_size as size_t),
        MSG_WAITALL as ::core::ffi::c_int,
        ::core::ptr::null_mut::<sockaddr>(),
        ::core::ptr::null_mut::<socklen_t>(),
    ) as ::core::ffi::c_int;
    if received_len < header_size {
        csp_buffer_free(packet as *mut ::core::ffi::c_void);
        return CSP_ERR_NOMEM;
    }
    (*packet).frame_length = received_len as uint16_t;
    if csp_id_strip(packet) != 0 as ::core::ffi::c_int {
        csp_buffer_free(packet as *mut ::core::ffi::c_void);
        return CSP_ERR_INVAL;
    }
    csp_qfifo_write(packet, iface, NULL);
    return CSP_ERR_NONE;
}
unsafe extern "C" fn csp_if_udp_rx_loop(
    mut param: *mut ::core::ffi::c_void,
) -> *mut ::core::ffi::c_void {
    let mut iface: *mut csp_iface_t = param as *mut csp_iface_t;
    let mut ifconf: *mut csp_if_udp_conf_t = (*iface).driver_data
        as *mut csp_if_udp_conf_t;
    while (*ifconf).sockfd == 0 as ::core::ffi::c_int {
        (*ifconf).sockfd = socket(
            AF_INET,
            SOCK_DGRAM as ::core::ffi::c_int,
            IPPROTO_UDP as ::core::ffi::c_int,
        );
        let mut server_addr: sockaddr_in = sockaddr_in {
            sin_family: 0 as sa_family_t,
            sin_port: 0,
            sin_addr: in_addr { s_addr: 0 },
            sin_zero: [0; 8],
        };
        server_addr.sin_family = AF_INET as sa_family_t;
        server_addr.sin_addr.s_addr = __bswap_32(0 as ::core::ffi::c_int as __uint32_t)
            as in_addr_t;
        server_addr.sin_port = __bswap_16((*ifconf).lport as __uint16_t) as in_port_t;
        bind(
            (*ifconf).sockfd,
            &raw mut server_addr as *mut sockaddr,
            ::core::mem::size_of::<sockaddr_in>() as socklen_t,
        );
        if !((*ifconf).sockfd < 0 as ::core::ffi::c_int) {
            break;
        }
        csp_print_func(
            b"  UDP server waiting for port %d\n\0" as *const u8
                as *const ::core::ffi::c_char,
            (*ifconf).lport,
        );
        sleep(1 as ::core::ffi::c_uint);
    }
    loop {
        let mut ret: ::core::ffi::c_int = 0;
        ret = csp_if_udp_rx_work((*ifconf).sockfd, 0 as size_t, iface);
        if ret == CSP_ERR_INVAL {
            (*iface).rx_error = (*iface).rx_error.wrapping_add(1);
        } else if ret == CSP_ERR_NOMEM {
            usleep(10000 as __useconds_t);
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn csp_if_udp_init(
    mut iface: *mut csp_iface_t,
    mut ifconf: *mut csp_if_udp_conf_t,
) {
    let mut attributes: pthread_attr_t = pthread_attr_t { __size: [0; 56] };
    let mut ret: ::core::ffi::c_int = 0;
    (*iface).driver_data = ifconf as *mut ::core::ffi::c_void;
    if inet_aton((*ifconf).host, &raw mut (*ifconf).peer_addr.sin_addr)
        == 0 as ::core::ffi::c_int
    {
        csp_print_func(
            b"  Unknown peer address %s\n\0" as *const u8 as *const ::core::ffi::c_char,
            (*ifconf).host,
        );
    }
    csp_print_func(
        b"  UDP peer address: %s:%d (listening on port %d)\n\0" as *const u8
            as *const ::core::ffi::c_char,
        inet_ntoa((*ifconf).peer_addr.sin_addr),
        (*ifconf).rport,
        (*ifconf).lport,
    );
    ret = pthread_attr_init(&raw mut attributes);
    if ret != 0 as ::core::ffi::c_int {
        csp_print_func(
            b"csp_if_udp_init: pthread_attr_init failed: %s: %d\n\0" as *const u8
                as *const ::core::ffi::c_char,
            strerror(ret),
            ret,
        );
    }
    ret = pthread_attr_setdetachstate(
        &raw mut attributes,
        PTHREAD_CREATE_DETACHED as ::core::ffi::c_int,
    );
    if ret != 0 as ::core::ffi::c_int {
        csp_print_func(
            b"csp_if_udp_init: pthread_attr_setdetachstate failed: %s: %d\n\0"
                as *const u8 as *const ::core::ffi::c_char,
            strerror(ret),
            ret,
        );
    }
    ret = pthread_create(
        &raw mut (*ifconf).server_handle,
        &raw mut attributes,
        Some(
            csp_if_udp_rx_loop
                as unsafe extern "C" fn(
                    *mut ::core::ffi::c_void,
                ) -> *mut ::core::ffi::c_void,
        ),
        iface as *mut ::core::ffi::c_void,
    );
    if ret != 0 as ::core::ffi::c_int {
        csp_print_func(
            b"csp_if_udp_init: pthread_create failed: %s: %d\n\0" as *const u8
                as *const ::core::ffi::c_char,
            strerror(ret),
            ret,
        );
    }
    ret = pthread_attr_destroy(&raw mut attributes);
    if ret != 0 as ::core::ffi::c_int {
        csp_print_func(
            b"csp_if_udp_init: pthread_attr_destroy failed: %s: %d\n\0" as *const u8
                as *const ::core::ffi::c_char,
            strerror(ret),
            ret,
        );
    }
    (*iface).name = b"UDP\0" as *const u8 as *const ::core::ffi::c_char;
    (*iface).nexthop = Some(
        csp_if_udp_tx
            as unsafe extern "C" fn(
                *mut csp_iface_t,
                uint16_t,
                *mut csp_packet_t,
                ::core::ffi::c_int,
            ) -> ::core::ffi::c_int,
    ) as nexthop_t;
    csp_iflist_add(iface);
}
