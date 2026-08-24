extern "C" {
    pub type csp_conn_s;
    fn csp_eth_tx(
        iface: *mut csp_iface_t,
        via: uint16_t,
        packet: *mut csp_packet_t,
        from_me: ::core::ffi::c_int,
    ) -> ::core::ffi::c_int;
    fn csp_eth_rx(
        iface: *mut csp_iface_t,
        eth_frame: *mut csp_eth_header_t,
        received_len: uint32_t,
        task_woken: *mut ::core::ffi::c_int,
    ) -> ::core::ffi::c_int;
    fn perror(__s: *const ::core::ffi::c_char);
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
    fn strncpy(
        __dest: *mut ::core::ffi::c_char,
        __src: *const ::core::ffi::c_char,
        __n: size_t,
    ) -> *mut ::core::ffi::c_char;
    fn calloc(__nmemb: size_t, __size: size_t) -> *mut ::core::ffi::c_void;
    fn free(__ptr: *mut ::core::ffi::c_void);
    fn close(__fd: ::core::ffi::c_int) -> ::core::ffi::c_int;
    fn readlink(
        __path: *const ::core::ffi::c_char,
        __buf: *mut ::core::ffi::c_char,
        __len: size_t,
    ) -> ssize_t;
    fn csp_print_func(fmt: *const ::core::ffi::c_char, ...);
    fn csp_iflist_add(iface: *mut csp_iface_t);
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
    fn setsockopt(
        __fd: ::core::ffi::c_int,
        __level: ::core::ffi::c_int,
        __optname: ::core::ffi::c_int,
        __optval: *const ::core::ffi::c_void,
        __optlen: socklen_t,
    ) -> ::core::ffi::c_int;
    fn ioctl(
        __fd: ::core::ffi::c_int,
        __request: ::core::ffi::c_ulong,
        ...
    ) -> ::core::ffi::c_int;
    fn pthread_create(
        __newthread: *mut pthread_t,
        __attr: *const pthread_attr_t,
        __start_routine: Option<
            unsafe extern "C" fn(*mut ::core::ffi::c_void) -> *mut ::core::ffi::c_void,
        >,
        __arg: *mut ::core::ffi::c_void,
    ) -> ::core::ffi::c_int;
}
pub type __uint8_t = u8;
pub type __uint16_t = u16;
pub type __uint32_t = u32;
pub type __uint64_t = u64;
pub type __ssize_t = ::core::ffi::c_long;
pub type __caddr_t = *mut ::core::ffi::c_char;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct eth_context_t {
    pub name: [::core::ffi::c_char; 11],
    pub ifdata: csp_eth_interface_data_t,
    pub sockfd: ::core::ffi::c_int,
    pub if_idx: ifreq,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ifreq {
    pub ifr_ifrn: C2RustUnnamed_1,
    pub ifr_ifru: C2RustUnnamed_0,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
    pub ifru_addr: sockaddr,
    pub ifru_dstaddr: sockaddr,
    pub ifru_broadaddr: sockaddr,
    pub ifru_netmask: sockaddr,
    pub ifru_hwaddr: sockaddr,
    pub ifru_flags: ::core::ffi::c_short,
    pub ifru_ivalue: ::core::ffi::c_int,
    pub ifru_mtu: ::core::ffi::c_int,
    pub ifru_map: ifmap,
    pub ifru_slave: [::core::ffi::c_char; 16],
    pub ifru_newname: [::core::ffi::c_char; 16],
    pub ifru_data: __caddr_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ifmap {
    pub mem_start: ::core::ffi::c_ulong,
    pub mem_end: ::core::ffi::c_ulong,
    pub base_addr: ::core::ffi::c_ushort,
    pub irq: ::core::ffi::c_uchar,
    pub dma: ::core::ffi::c_uchar,
    pub port: ::core::ffi::c_uchar,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [::core::ffi::c_char; 14],
}
pub type sa_family_t = ::core::ffi::c_ushort;
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_1 {
    pub ifrn_name: [::core::ffi::c_char; 16],
}
pub type ssize_t = __ssize_t;
pub type socklen_t = __socklen_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_attr_t {
    pub __size: [::core::ffi::c_char; 56],
    pub __align: ::core::ffi::c_long,
}
pub type pthread_t = ::core::ffi::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_ll {
    pub sll_family: ::core::ffi::c_ushort,
    pub sll_protocol: __be16,
    pub sll_ifindex: ::core::ffi::c_int,
    pub sll_hatype: ::core::ffi::c_ushort,
    pub sll_pkttype: ::core::ffi::c_uchar,
    pub sll_halen: ::core::ffi::c_uchar,
    pub sll_addr: [::core::ffi::c_uchar; 8],
}
pub type __be16 = __u16;
pub type __u16 = ::core::ffi::c_ushort;
pub const SOCK_RAW: __socket_type = 3;
pub type __socket_type = ::core::ffi::c_uint;
pub const SOCK_NONBLOCK: __socket_type = 2048;
pub const SOCK_CLOEXEC: __socket_type = 524288;
pub const SOCK_PACKET: __socket_type = 10;
pub const SOCK_DCCP: __socket_type = 6;
pub const SOCK_SEQPACKET: __socket_type = 5;
pub const SOCK_RDM: __socket_type = 4;
pub const SOCK_DGRAM: __socket_type = 2;
pub const SOCK_STREAM: __socket_type = 1;
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ERR_NOMEM: ::core::ffi::c_int = -(1 as ::core::ffi::c_int);
pub const CSP_ERR_INVAL: ::core::ffi::c_int = -(2 as ::core::ffi::c_int);
pub const CSP_ERR_DRIVER: ::core::ffi::c_int = -(11 as ::core::ffi::c_int);
pub const CSP_ETH_BUF_SIZE: ::core::ffi::c_int = 3000 as ::core::ffi::c_int;
pub const CSP_ETH_ALEN: ::core::ffi::c_int = 6 as ::core::ffi::c_int;
#[inline]
unsafe extern "C" fn __bswap_16(mut __bsx: __uint16_t) -> __uint16_t {
    return (__bsx as ::core::ffi::c_int >> 8 as ::core::ffi::c_int
        & 0xff as ::core::ffi::c_int
        | (__bsx as ::core::ffi::c_int & 0xff as ::core::ffi::c_int)
            << 8 as ::core::ffi::c_int) as __uint16_t;
}
pub const NULL: *mut ::core::ffi::c_void = ::core::ptr::null_mut::<
    ::core::ffi::c_void,
>();
pub const PF_PACKET: ::core::ffi::c_int = 17 as ::core::ffi::c_int;
pub const AF_PACKET: ::core::ffi::c_int = PF_PACKET;
pub const SOL_SOCKET: ::core::ffi::c_int = 1 as ::core::ffi::c_int;
pub const SO_REUSEADDR: ::core::ffi::c_int = 2 as ::core::ffi::c_int;
pub const SO_BINDTODEVICE: ::core::ffi::c_int = 25 as ::core::ffi::c_int;
pub const SIOCGIFHWADDR: ::core::ffi::c_int = 0x8927 as ::core::ffi::c_int;
pub const SIOCGIFINDEX: ::core::ffi::c_int = 0x8933 as ::core::ffi::c_int;
pub const IF_NAMESIZE: ::core::ffi::c_int = 16 as ::core::ffi::c_int;
pub const IFNAMSIZ: ::core::ffi::c_int = IF_NAMESIZE;
#[no_mangle]
pub unsafe extern "C" fn csp_eth_tx_frame(
    mut driver_data: *mut ::core::ffi::c_void,
    mut eth_frame: *mut csp_eth_header_t,
) -> ::core::ffi::c_int {
    let mut ctx: *const eth_context_t = driver_data as *mut eth_context_t;
    let mut socket_address: sockaddr_ll = sockaddr_ll {
        sll_family: 0 as ::core::ffi::c_ushort,
        sll_protocol: 0,
        sll_ifindex: 0,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };
    socket_address.sll_ifindex = (*ctx).if_idx.ifr_ifru.ifru_ivalue;
    socket_address.sll_halen = CSP_ETH_ALEN as ::core::ffi::c_uchar;
    memcpy(
        &raw mut socket_address.sll_addr as *mut ::core::ffi::c_uchar
            as *mut ::core::ffi::c_void,
        &raw mut (*eth_frame).ether_dhost as *mut uint8_t as *const ::core::ffi::c_void,
        CSP_ETH_ALEN as size_t,
    );
    let mut txsize: uint32_t = (::core::mem::size_of::<csp_eth_header_t>() as usize)
        .wrapping_add(__bswap_16((*eth_frame).seg_size as __uint16_t) as usize)
        as uint32_t;
    if sendto(
        (*ctx).sockfd,
        eth_frame as *mut ::core::ffi::c_void,
        txsize as size_t,
        0 as ::core::ffi::c_int,
        &raw mut socket_address as *mut sockaddr,
        ::core::mem::size_of::<sockaddr_ll>() as socklen_t,
    ) < 0 as ssize_t
    {
        return CSP_ERR_DRIVER;
    }
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_eth_rx_loop(
    mut param: *mut ::core::ffi::c_void,
) -> *mut ::core::ffi::c_void {
    let mut ctx: *mut eth_context_t = param as *mut eth_context_t;
    static mut recvbuf: [uint8_t; 3000] = [0; 3000];
    let mut eth_frame: *mut csp_eth_header_t = &raw mut recvbuf as *mut uint8_t
        as *mut csp_eth_header_t;
    loop {
        let mut received_len: uint32_t = recvfrom(
            (*ctx).sockfd,
            &raw mut recvbuf as *mut uint8_t as *mut ::core::ffi::c_void,
            CSP_ETH_BUF_SIZE as size_t,
            0 as ::core::ffi::c_int,
            ::core::ptr::null_mut::<sockaddr>(),
            ::core::ptr::null_mut::<socklen_t>(),
        ) as uint32_t;
        csp_eth_rx(
            &raw mut (*ctx).ifdata.iface,
            eth_frame,
            received_len,
            ::core::ptr::null_mut::<::core::ffi::c_int>(),
        );
    };
}
static mut csp_eth_tx_buffer: [uint8_t; 3000] = [0; 3000];
#[no_mangle]
pub unsafe extern "C" fn csp_eth_init(
    mut device: *const ::core::ffi::c_char,
    mut ifname: *const ::core::ffi::c_char,
    mut mtu: ::core::ffi::c_int,
    mut node_id: ::core::ffi::c_uint,
    mut promisc: bool,
    mut return_iface: *mut *mut csp_iface_t,
) -> ::core::ffi::c_int {
    let mut ctx: *mut eth_context_t = calloc(
        1 as size_t,
        ::core::mem::size_of::<eth_context_t>() as size_t,
    ) as *mut eth_context_t;
    if ctx.is_null() {
        return CSP_ERR_NOMEM;
    }
    strncpy(
        &raw mut (*ctx).name as *mut ::core::ffi::c_char,
        ifname,
        (::core::mem::size_of::<[::core::ffi::c_char; 11]>() as size_t)
            .wrapping_sub(1 as size_t),
    );
    (*ctx).ifdata.iface.name = &raw mut (*ctx).name as *mut ::core::ffi::c_char;
    (*ctx).ifdata.tx_func = Some(
        csp_eth_tx_frame
            as unsafe extern "C" fn(
                *mut ::core::ffi::c_void,
                *mut csp_eth_header_t,
            ) -> ::core::ffi::c_int,
    ) as csp_eth_driver_tx_t;
    (*ctx).ifdata.tx_buf = &raw mut csp_eth_tx_buffer as *mut csp_eth_header_t;
    (*ctx).ifdata.iface.nexthop = Some(
        csp_eth_tx
            as unsafe extern "C" fn(
                *mut csp_iface_t,
                uint16_t,
                *mut csp_packet_t,
                ::core::ffi::c_int,
            ) -> ::core::ffi::c_int,
    ) as nexthop_t;
    (*ctx).ifdata.iface.addr = node_id as uint16_t;
    (*ctx).ifdata.iface.driver_data = ctx as *mut ::core::ffi::c_void;
    (*ctx).ifdata.iface.interface_data = &raw mut (*ctx).ifdata
        as *mut ::core::ffi::c_void;
    (*ctx).ifdata.promisc = promisc;
    if mtu < 24 as ::core::ffi::c_int {
        csp_print_func(
            b"csp_if_eth_init: mtu < 24\n\0" as *const u8 as *const ::core::ffi::c_char,
        );
        free(ctx as *mut ::core::ffi::c_void);
        return CSP_ERR_INVAL;
    }
    (*ctx).sockfd = socket(
        AF_PACKET,
        SOCK_RAW as ::core::ffi::c_int,
        __bswap_16(0x88b5 as __uint16_t) as ::core::ffi::c_int,
    );
    if (*ctx).sockfd == -(1 as ::core::ffi::c_int) {
        perror(b"socket\0" as *const u8 as *const ::core::ffi::c_char);
        let mut exe: [::core::ffi::c_char; 1024] = [0; 1024];
        let mut count: ::core::ffi::c_int = readlink(
            b"/proc/self/exe\0" as *const u8 as *const ::core::ffi::c_char,
            &raw mut exe as *mut ::core::ffi::c_char,
            ::core::mem::size_of::<[::core::ffi::c_char; 1024]>() as size_t,
        ) as ::core::ffi::c_int;
        if count > 0 as ::core::ffi::c_int {
            csp_print_func(
                b"Use command 'sudo setcap cap_net_raw+ep %s'\n\0" as *const u8
                    as *const ::core::ffi::c_char,
                &raw mut exe as *mut ::core::ffi::c_char,
            );
        }
        free(ctx as *mut ::core::ffi::c_void);
        return CSP_ERR_INVAL;
    }
    memset(
        &raw mut (*ctx).if_idx as *mut ::core::ffi::c_void,
        0 as ::core::ffi::c_int,
        ::core::mem::size_of::<ifreq>() as size_t,
    );
    strncpy(
        &raw mut (*ctx).if_idx.ifr_ifrn.ifrn_name as *mut ::core::ffi::c_char,
        device,
        (IFNAMSIZ - 1 as ::core::ffi::c_int) as size_t,
    );
    if ioctl((*ctx).sockfd, SIOCGIFINDEX as ::core::ffi::c_ulong, &raw mut (*ctx).if_idx)
        < 0 as ::core::ffi::c_int
    {
        perror(b"SIOCGIFINDEX\0" as *const u8 as *const ::core::ffi::c_char);
        free(ctx as *mut ::core::ffi::c_void);
        return CSP_ERR_INVAL;
    }
    let mut if_mac: ifreq = ifreq {
        ifr_ifrn: C2RustUnnamed_1 {
            ifrn_name: [0; 16],
        },
        ifr_ifru: C2RustUnnamed_0 {
            ifru_addr: sockaddr {
                sa_family: 0,
                sa_data: [0; 14],
            },
        },
    };
    memset(
        &raw mut if_mac as *mut ::core::ffi::c_void,
        0 as ::core::ffi::c_int,
        ::core::mem::size_of::<ifreq>() as size_t,
    );
    strncpy(
        &raw mut if_mac.ifr_ifrn.ifrn_name as *mut ::core::ffi::c_char,
        device,
        (IFNAMSIZ - 1 as ::core::ffi::c_int) as size_t,
    );
    if ioctl((*ctx).sockfd, SIOCGIFHWADDR as ::core::ffi::c_ulong, &raw mut if_mac)
        < 0 as ::core::ffi::c_int
    {
        perror(b"SIOCGIFHWADDR\0" as *const u8 as *const ::core::ffi::c_char);
        free(ctx as *mut ::core::ffi::c_void);
        return CSP_ERR_INVAL;
    }
    memcpy(
        &raw mut (*ctx).ifdata.if_mac as *mut ::core::ffi::c_void,
        &raw mut if_mac.ifr_ifru.ifru_hwaddr.sa_data as *mut ::core::ffi::c_char
            as *const ::core::ffi::c_void,
        ::core::mem::size_of::<[uint8_t; 6]>() as size_t,
    );
    csp_print_func(
        b"INIT %s %s idx %d node %d mac %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n\0"
            as *const u8 as *const ::core::ffi::c_char,
        ifname,
        device,
        (*ctx).if_idx.ifr_ifru.ifru_ivalue,
        node_id,
        *(&raw mut if_mac.ifr_ifru.ifru_hwaddr.sa_data as *mut ::core::ffi::c_char
            as *mut uint8_t)
            .offset(0 as ::core::ffi::c_int as isize) as ::core::ffi::c_int,
        *(&raw mut if_mac.ifr_ifru.ifru_hwaddr.sa_data as *mut ::core::ffi::c_char
            as *mut uint8_t)
            .offset(1 as ::core::ffi::c_int as isize) as ::core::ffi::c_int,
        *(&raw mut if_mac.ifr_ifru.ifru_hwaddr.sa_data as *mut ::core::ffi::c_char
            as *mut uint8_t)
            .offset(2 as ::core::ffi::c_int as isize) as ::core::ffi::c_int,
        *(&raw mut if_mac.ifr_ifru.ifru_hwaddr.sa_data as *mut ::core::ffi::c_char
            as *mut uint8_t)
            .offset(3 as ::core::ffi::c_int as isize) as ::core::ffi::c_int,
        *(&raw mut if_mac.ifr_ifru.ifru_hwaddr.sa_data as *mut ::core::ffi::c_char
            as *mut uint8_t)
            .offset(4 as ::core::ffi::c_int as isize) as ::core::ffi::c_int,
        *(&raw mut if_mac.ifr_ifru.ifru_hwaddr.sa_data as *mut ::core::ffi::c_char
            as *mut uint8_t)
            .offset(5 as ::core::ffi::c_int as isize) as ::core::ffi::c_int,
    );
    let sockopt: ::core::ffi::c_int = 1 as ::core::ffi::c_int;
    if setsockopt(
        (*ctx).sockfd,
        SOL_SOCKET,
        SO_REUSEADDR,
        &raw const sockopt as *const ::core::ffi::c_void,
        ::core::mem::size_of::<::core::ffi::c_int>() as socklen_t,
    ) == -(1 as ::core::ffi::c_int)
    {
        perror(b"setsockopt\0" as *const u8 as *const ::core::ffi::c_char);
        close((*ctx).sockfd);
        free(ctx as *mut ::core::ffi::c_void);
        return CSP_ERR_INVAL;
    }
    if setsockopt(
        (*ctx).sockfd,
        SOL_SOCKET,
        SO_BINDTODEVICE,
        device as *const ::core::ffi::c_void,
        (IFNAMSIZ - 1 as ::core::ffi::c_int) as socklen_t,
    ) == -(1 as ::core::ffi::c_int)
    {
        perror(b"SO_BINDTODEVICE\0" as *const u8 as *const ::core::ffi::c_char);
        close((*ctx).sockfd);
        free(ctx as *mut ::core::ffi::c_void);
        return CSP_ERR_INVAL;
    }
    let mut my_addr: sockaddr_ll = sockaddr_ll {
        sll_family: 0,
        sll_protocol: 0,
        sll_ifindex: 0,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };
    my_addr.sll_family = AF_PACKET as ::core::ffi::c_ushort;
    my_addr.sll_protocol = __bswap_16(0x88b5 as __uint16_t) as __be16;
    my_addr.sll_ifindex = (*ctx).if_idx.ifr_ifru.ifru_ivalue;
    bind(
        (*ctx).sockfd,
        &raw mut my_addr as *mut sockaddr,
        ::core::mem::size_of::<sockaddr_ll>() as socklen_t,
    );
    (*ctx).ifdata.tx_mtu = mtu as uint16_t;
    static mut server_handle: pthread_t = 0;
    pthread_create(
        &raw mut server_handle,
        ::core::ptr::null::<pthread_attr_t>(),
        Some(
            csp_eth_rx_loop
                as unsafe extern "C" fn(
                    *mut ::core::ffi::c_void,
                ) -> *mut ::core::ffi::c_void,
        ),
        ctx as *mut ::core::ffi::c_void,
    );
    csp_iflist_add(&raw mut (*ctx).ifdata.iface);
    if !return_iface.is_null() {
        *return_iface = &raw mut (*ctx).ifdata.iface;
    }
    return CSP_ERR_NONE;
}
