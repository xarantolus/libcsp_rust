extern "C" {
    pub type csp_conn_s;
    fn csp_can_add_interface(iface: *mut csp_iface_t) -> ::core::ffi::c_int;
    fn csp_can_remove_interface(iface: *mut csp_iface_t) -> ::core::ffi::c_int;
    fn csp_can_rx(
        iface: *mut csp_iface_t,
        id: uint32_t,
        data: *const uint8_t,
        dlc: uint8_t,
        timestamp_rx: uint32_t,
        pxTaskWoken: *mut ::core::ffi::c_int,
    ) -> ::core::ffi::c_int;
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
    fn strerror(__errnum: ::core::ffi::c_int) -> *mut ::core::ffi::c_char;
    fn pthread_create(
        __newthread: *mut pthread_t,
        __attr: *const pthread_attr_t,
        __start_routine: Option<
            unsafe extern "C" fn(*mut ::core::ffi::c_void) -> *mut ::core::ffi::c_void,
        >,
        __arg: *mut ::core::ffi::c_void,
    ) -> ::core::ffi::c_int;
    fn pthread_exit(__retval: *mut ::core::ffi::c_void) -> !;
    fn pthread_join(
        __th: pthread_t,
        __thread_return: *mut *mut ::core::ffi::c_void,
    ) -> ::core::ffi::c_int;
    fn pthread_cancel(__th: pthread_t) -> ::core::ffi::c_int;
    fn select(
        __nfds: ::core::ffi::c_int,
        __readfds: *mut fd_set,
        __writefds: *mut fd_set,
        __exceptfds: *mut fd_set,
        __timeout: *mut timeval,
    ) -> ::core::ffi::c_int;
    fn calloc(__nmemb: size_t, __size: size_t) -> *mut ::core::ffi::c_void;
    fn free(__ptr: *mut ::core::ffi::c_void);
    fn csp_print_func(fmt: *const ::core::ffi::c_char, ...);
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
    fn getsockopt(
        __fd: ::core::ffi::c_int,
        __level: ::core::ffi::c_int,
        __optname: ::core::ffi::c_int,
        __optval: *mut ::core::ffi::c_void,
        __optlen: *mut socklen_t,
    ) -> ::core::ffi::c_int;
    fn setsockopt(
        __fd: ::core::ffi::c_int,
        __level: ::core::ffi::c_int,
        __optname: ::core::ffi::c_int,
        __optval: *const ::core::ffi::c_void,
        __optlen: socklen_t,
    ) -> ::core::ffi::c_int;
    fn close(__fd: ::core::ffi::c_int) -> ::core::ffi::c_int;
    fn read(
        __fd: ::core::ffi::c_int,
        __buf: *mut ::core::ffi::c_void,
        __nbytes: size_t,
    ) -> ssize_t;
    fn write(
        __fd: ::core::ffi::c_int,
        __buf: *const ::core::ffi::c_void,
        __n: size_t,
    ) -> ssize_t;
    fn usleep(__useconds: __useconds_t) -> ::core::ffi::c_int;
    fn __errno_location() -> *mut ::core::ffi::c_int;
    fn ioctl(
        __fd: ::core::ffi::c_int,
        __request: ::core::ffi::c_ulong,
        ...
    ) -> ::core::ffi::c_int;
    fn fcntl(
        __fd: ::core::ffi::c_int,
        __cmd: ::core::ffi::c_int,
        ...
    ) -> ::core::ffi::c_int;
    fn can_do_stop(name: *const ::core::ffi::c_char) -> ::core::ffi::c_int;
    fn can_do_start(name: *const ::core::ffi::c_char) -> ::core::ffi::c_int;
    fn can_set_restart_ms(
        name: *const ::core::ffi::c_char,
        restart_ms: __u32,
    ) -> ::core::ffi::c_int;
    fn can_set_bitrate(
        name: *const ::core::ffi::c_char,
        bitrate: __u32,
    ) -> ::core::ffi::c_int;
    static mut csp_conf: csp_conf_t;
    fn csp_id_get_host_bits() -> ::core::ffi::c_uint;
}
pub type __uint8_t = u8;
pub type __uint16_t = u16;
pub type __uint32_t = u32;
pub type __uint64_t = u64;
pub type __time_t = ::core::ffi::c_long;
pub type __useconds_t = ::core::ffi::c_uint;
pub type __suseconds_t = ::core::ffi::c_long;
pub type __ssize_t = ::core::ffi::c_long;
pub type __caddr_t = *mut ::core::ffi::c_char;
pub type __socklen_t = ::core::ffi::c_uint;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type uintptr_t = usize;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct can_context_t {
    pub name: [::core::ffi::c_char; 11],
    pub iface: csp_iface_t,
    pub ifdata: csp_can_interface_data_t,
    pub rx_thread: pthread_t,
    pub socket: ::core::ffi::c_int,
}
pub type pthread_t = ::core::ffi::c_ulong;
pub type __u8 = ::core::ffi::c_uchar;
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub union C2RustUnnamed_0 {
    pub len: __u8,
    pub can_dlc: __u8,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct can_frame {
    pub can_id: canid_t,
    pub c2rust_unnamed: C2RustUnnamed_0,
    pub __pad: __u8,
    pub __res0: __u8,
    pub len8_dlc: __u8,
    pub data: [__u8; 8],
}
pub type canid_t = __u32;
pub type __u32 = ::core::ffi::c_uint;
pub type ssize_t = __ssize_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timeval {
    pub tv_sec: __time_t,
    pub tv_usec: __suseconds_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct fd_set {
    pub __fds_bits: [__fd_mask; 16],
}
pub type __fd_mask = ::core::ffi::c_long;
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_attr_t {
    pub __size: [::core::ffi::c_char; 56],
    pub __align: ::core::ffi::c_long,
}
pub type socklen_t = __socklen_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct can_filter {
    pub can_id: canid_t,
    pub can_mask: canid_t,
}
pub const CAN_RAW_FILTER: C2RustUnnamed_6 = 1;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_can {
    pub can_family: __kernel_sa_family_t,
    pub can_ifindex: ::core::ffi::c_int,
    pub can_addr: C2RustUnnamed_1,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_1 {
    pub tp: C2RustUnnamed_3,
    pub j1939: C2RustUnnamed_2,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_2 {
    pub name: __u64,
    pub pgn: __u32,
    pub addr: __u8,
}
pub type __u64 = ::core::ffi::c_ulonglong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_3 {
    pub rx_id: canid_t,
    pub tx_id: canid_t,
}
pub type __kernel_sa_family_t = ::core::ffi::c_ushort;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [::core::ffi::c_char; 14],
}
pub type sa_family_t = ::core::ffi::c_ushort;
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_4 {
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
pub struct ifreq {
    pub ifr_ifrn: C2RustUnnamed_5,
    pub ifr_ifru: C2RustUnnamed_4,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_5 {
    pub ifrn_name: [::core::ffi::c_char; 16],
}
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
pub type C2RustUnnamed_6 = ::core::ffi::c_uint;
pub const CAN_RAW_XL_FRAMES: C2RustUnnamed_6 = 7;
pub const CAN_RAW_JOIN_FILTERS: C2RustUnnamed_6 = 6;
pub const CAN_RAW_FD_FRAMES: C2RustUnnamed_6 = 5;
pub const CAN_RAW_RECV_OWN_MSGS: C2RustUnnamed_6 = 4;
pub const CAN_RAW_LOOPBACK: C2RustUnnamed_6 = 3;
pub const CAN_RAW_ERR_FILTER: C2RustUnnamed_6 = 2;
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ERR_NOMEM: ::core::ffi::c_int = -(1 as ::core::ffi::c_int);
pub const CSP_ERR_INVAL: ::core::ffi::c_int = -(2 as ::core::ffi::c_int);
pub const CSP_ERR_TX: ::core::ffi::c_int = -(10 as ::core::ffi::c_int);
pub const CSP_ERR_DRIVER: ::core::ffi::c_int = -(11 as ::core::ffi::c_int);
pub const CFP2_DST_MASK: ::core::ffi::c_int = 0x3fff as ::core::ffi::c_int;
pub const CFP2_DST_OFFSET: ::core::ffi::c_int = 13 as ::core::ffi::c_int;
pub const CSP_IF_CAN_DEFAULT_NAME: [::core::ffi::c_char; 4] = unsafe {
    ::core::mem::transmute::<[u8; 4], [::core::ffi::c_char; 4]>(*b"CAN\0")
};
pub const NULL: *mut ::core::ffi::c_void = ::core::ptr::null_mut::<
    ::core::ffi::c_void,
>();
pub const __NFDBITS: ::core::ffi::c_int = 8 as ::core::ffi::c_int
    * ::core::mem::size_of::<__fd_mask>() as ::core::ffi::c_int;
pub const PF_CAN: ::core::ffi::c_int = 29 as ::core::ffi::c_int;
pub const AF_CAN: ::core::ffi::c_int = PF_CAN;
pub const ENOBUFS: ::core::ffi::c_int = 105 as ::core::ffi::c_int;
pub const SIOCGIFINDEX: ::core::ffi::c_int = 0x8933 as ::core::ffi::c_int;
pub const EINTR: ::core::ffi::c_int = 4 as ::core::ffi::c_int;
pub const EAGAIN: ::core::ffi::c_int = 11 as ::core::ffi::c_int;
pub const O_NONBLOCK: ::core::ffi::c_int = 0o4000 as ::core::ffi::c_int;
pub const F_SETFL: ::core::ffi::c_int = 4 as ::core::ffi::c_int;
pub const IF_NAMESIZE: ::core::ffi::c_int = 16 as ::core::ffi::c_int;
pub const IFNAMSIZ: ::core::ffi::c_int = IF_NAMESIZE;
pub const CAN_EFF_FLAG: ::core::ffi::c_uint = 0x80000000 as ::core::ffi::c_uint;
pub const CAN_RTR_FLAG: ::core::ffi::c_uint = 0x40000000 as ::core::ffi::c_uint;
pub const CAN_ERR_FLAG: ::core::ffi::c_uint = 0x20000000 as ::core::ffi::c_uint;
pub const CAN_EFF_MASK: ::core::ffi::c_uint = 0x1fffffff as ::core::ffi::c_uint;
pub const CAN_MAX_DLEN: ::core::ffi::c_int = 8 as ::core::ffi::c_int;
pub const CAN_RAW: ::core::ffi::c_int = 1 as ::core::ffi::c_int;
pub const SOL_CAN_BASE: ::core::ffi::c_int = 100 as ::core::ffi::c_int;
pub const SOL_CAN_RAW: ::core::ffi::c_int = SOL_CAN_BASE + CAN_RAW;
unsafe extern "C" fn socketcan_free(mut ctx: *mut can_context_t) {
    if !ctx.is_null() {
        if (*ctx).socket >= 0 as ::core::ffi::c_int {
            close((*ctx).socket);
        }
        free(ctx as *mut ::core::ffi::c_void);
    }
}
unsafe extern "C" fn socketcan_rx_thread(
    mut arg: *mut ::core::ffi::c_void,
) -> *mut ::core::ffi::c_void {
    let mut ctx: *mut can_context_t = arg as *mut can_context_t;
    loop {
        let mut input: fd_set = fd_set { __fds_bits: [0; 16] };
        let mut __i: ::core::ffi::c_uint = 0;
        let mut __arr: *mut fd_set = &raw mut input;
        __i = 0 as ::core::ffi::c_uint;
        while (__i as usize)
            < (::core::mem::size_of::<fd_set>() as usize)
                .wrapping_div(::core::mem::size_of::<__fd_mask>() as usize)
        {
            (*__arr).__fds_bits[__i as usize] = 0 as __fd_mask;
            __i = __i.wrapping_add(1);
        }
        input.__fds_bits[((*ctx).socket / __NFDBITS) as usize]
            |= ((1 as ::core::ffi::c_ulong) << (*ctx).socket % __NFDBITS) as __fd_mask;
        let mut timeout: timeval = timeval {
            tv_sec: 10 as __time_t,
            tv_usec: 0,
        };
        let mut n: ::core::ffi::c_int = select(
            (*ctx).socket + 1 as ::core::ffi::c_int,
            &raw mut input,
            ::core::ptr::null_mut::<fd_set>(),
            ::core::ptr::null_mut::<fd_set>(),
            &raw mut timeout,
        );
        if n == -(1 as ::core::ffi::c_int) {
            csp_print_func(
                b"CAN read error\n\0" as *const u8 as *const ::core::ffi::c_char,
            );
        } else {
            if n == 0 as ::core::ffi::c_int {
                continue;
            }
            let mut frame: can_frame = can_frame {
                can_id: 0,
                c2rust_unnamed: C2RustUnnamed_0 { len: 0 },
                __pad: 0,
                __res0: 0,
                len8_dlc: 0,
                data: [0; 8],
            };
            let mut nbytes: ::core::ffi::c_int = read(
                (*ctx).socket,
                &raw mut frame as *mut ::core::ffi::c_void,
                ::core::mem::size_of::<can_frame>() as size_t,
            ) as ::core::ffi::c_int;
            if nbytes < 0 as ::core::ffi::c_int {
                if *__errno_location() == EAGAIN || *__errno_location() == EINTR {
                    continue;
                }
                csp_print_func(
                    b"%s[%s]: read() failed, errno %d: %s\n\0" as *const u8
                        as *const ::core::ffi::c_char,
                    b"socketcan_rx_thread\0" as *const u8 as *const ::core::ffi::c_char,
                    &raw mut (*ctx).name as *mut ::core::ffi::c_char,
                    *__errno_location(),
                    strerror(*__errno_location()),
                );
                usleep(
                    (1 as ::core::ffi::c_int as ::core::ffi::c_double * 1E6f64)
                        as __useconds_t,
                );
            } else if nbytes as usize != ::core::mem::size_of::<can_frame>() as usize {
                csp_print_func(
                    b"%s[%s]: Read incomplete CAN frame, size: %d, expected: %u bytes\n\0"
                        as *const u8 as *const ::core::ffi::c_char,
                    b"socketcan_rx_thread\0" as *const u8 as *const ::core::ffi::c_char,
                    &raw mut (*ctx).name as *mut ::core::ffi::c_char,
                    nbytes,
                    ::core::mem::size_of::<can_frame>() as ::core::ffi::c_uint,
                );
            } else {
                if frame.c2rust_unnamed.can_dlc as ::core::ffi::c_int > CAN_MAX_DLEN {
                    continue;
                }
                if frame.can_id as ::core::ffi::c_uint & CAN_EFF_FLAG == 0 {
                    continue;
                }
                if frame.can_id as ::core::ffi::c_uint & (CAN_ERR_FLAG | CAN_RTR_FLAG)
                    != 0
                {
                    csp_print_func(
                        b"%s[%s]: discarding ERR/RTR/SFF frame\n\0" as *const u8
                            as *const ::core::ffi::c_char,
                        b"socketcan_rx_thread\0" as *const u8
                            as *const ::core::ffi::c_char,
                        &raw mut (*ctx).name as *mut ::core::ffi::c_char,
                    );
                } else {
                    frame.can_id &= CAN_EFF_MASK;
                    csp_can_rx(
                        &raw mut (*ctx).iface,
                        frame.can_id as uint32_t,
                        &raw mut frame.data as *mut __u8,
                        frame.c2rust_unnamed.can_dlc as uint8_t,
                        0 as uint32_t,
                        ::core::ptr::null_mut::<::core::ffi::c_int>(),
                    );
                }
            }
        }
    };
}
unsafe extern "C" fn csp_can_tx_frame(
    mut driver_data: *mut ::core::ffi::c_void,
    mut id: uint32_t,
    mut data: *const uint8_t,
    mut dlc: uint8_t,
    mut packet: *const csp_packet_t,
) -> ::core::ffi::c_int {
    if dlc as ::core::ffi::c_int > CAN_MAX_DLEN {
        return CSP_ERR_INVAL;
    }
    let mut frame: can_frame = can_frame {
        can_id: id as canid_t | CAN_EFF_FLAG,
        c2rust_unnamed: C2RustUnnamed_0 { can_dlc: dlc },
        __pad: 0,
        __res0: 0,
        len8_dlc: 0,
        data: [0; 8],
    };
    memcpy(
        &raw mut frame.data as *mut __u8 as *mut ::core::ffi::c_void,
        data as *const ::core::ffi::c_void,
        dlc as size_t,
    );
    let mut waiting_ms: uint32_t = 0 as uint32_t;
    let mut ctx: *mut can_context_t = driver_data as *mut can_context_t;
    let mut pdata: uintptr_t = &raw mut frame as uintptr_t;
    let mut pend: uintptr_t = (&raw mut frame as uintptr_t)
        .wrapping_add(::core::mem::size_of::<can_frame>() as uintptr_t);
    let mut length: size_t = ::core::mem::size_of::<can_frame>() as size_t;
    while pdata < pend {
        let mut written: ::core::ffi::c_int = 0;
        written = write((*ctx).socket, pdata as *mut ::core::ffi::c_void, length)
            as ::core::ffi::c_int;
        if written < 0 as ::core::ffi::c_int {
            if *__errno_location() == ENOBUFS {
                usleep(5000 as __useconds_t);
                waiting_ms = waiting_ms.wrapping_add(5 as uint32_t);
            } else if *__errno_location() == EAGAIN || *__errno_location() == EINTR {
                waiting_ms = waiting_ms.wrapping_add(5 as uint32_t);
            } else {
                csp_print_func(
                    b"%s[%s]: write() failed, encountered an error during write(). %d - '%s'\n\0"
                        as *const u8 as *const ::core::ffi::c_char,
                    b"csp_can_tx_frame\0" as *const u8 as *const ::core::ffi::c_char,
                    &raw mut (*ctx).name as *mut ::core::ffi::c_char,
                    *__errno_location(),
                    strerror(*__errno_location()),
                );
                return CSP_ERR_TX;
            }
            if waiting_ms >= 1000 as uint32_t {
                csp_print_func(
                    b"%s[%s]: write() failed, we have been waiting for CAN buffers for too long (>1000 ms)\n\0"
                        as *const u8 as *const ::core::ffi::c_char,
                    b"csp_can_tx_frame\0" as *const u8 as *const ::core::ffi::c_char,
                    &raw mut (*ctx).name as *mut ::core::ffi::c_char,
                );
                return CSP_ERR_TX;
            }
        } else {
            waiting_ms = 0 as uint32_t;
            pdata = pdata.wrapping_add(written as uintptr_t);
            length = length.wrapping_sub(written as size_t);
        }
    }
    return CSP_ERR_NONE;
}
unsafe extern "C" fn csp_can_socketcan_set_promisc(
    promisc: bool,
    mut ctx: *mut can_context_t,
) -> ::core::ffi::c_int {
    let mut filter: [can_filter; 3] = [
        can_filter {
            can_id: (((*ctx).iface.addr as uint32_t
                & (((1 as ::core::ffi::c_int) << 5 as ::core::ffi::c_int) as uint32_t)
                    .wrapping_sub(1 as uint32_t))
                << 1 as ::core::ffi::c_int + 8 as ::core::ffi::c_int
                    + 10 as ::core::ffi::c_int) as canid_t,
            can_mask: 0 as canid_t,
        },
        can_filter {
            can_id: 0,
            can_mask: 0,
        },
        can_filter {
            can_id: 0,
            can_mask: 0,
        },
    ];
    if (*ctx).socket == 0 as ::core::ffi::c_int {
        return CSP_ERR_INVAL;
    }
    let mut num_filters: ::core::ffi::c_int = 1 as ::core::ffi::c_int;
    if !promisc {
        if csp_conf.version as ::core::ffi::c_int == 1 as ::core::ffi::c_int {
            num_filters = 1 as ::core::ffi::c_int;
            filter[0 as ::core::ffi::c_int as usize].can_id = (((*ctx).iface.addr
                as uint32_t
                & (((1 as ::core::ffi::c_int) << 5 as ::core::ffi::c_int) as uint32_t)
                    .wrapping_sub(1 as uint32_t))
                << 1 as ::core::ffi::c_int + 8 as ::core::ffi::c_int
                    + 10 as ::core::ffi::c_int) as canid_t;
            filter[0 as ::core::ffi::c_int as usize].can_mask = (((((1
                as ::core::ffi::c_int) << 5 as ::core::ffi::c_int)
                - 1 as ::core::ffi::c_int) as uint32_t
                & (((1 as ::core::ffi::c_int) << 5 as ::core::ffi::c_int) as uint32_t)
                    .wrapping_sub(1 as uint32_t))
                << 1 as ::core::ffi::c_int + 8 as ::core::ffi::c_int
                    + 10 as ::core::ffi::c_int) as canid_t;
        } else {
            num_filters = 3 as ::core::ffi::c_int;
            filter[0 as ::core::ffi::c_int as usize].can_id = (((*ctx).iface.addr
                as ::core::ffi::c_int) << CFP2_DST_OFFSET) as canid_t;
            filter[0 as ::core::ffi::c_int as usize].can_mask = (CFP2_DST_MASK
                << CFP2_DST_OFFSET) as canid_t;
            filter[1 as ::core::ffi::c_int as usize].can_id = ((((1
                as ::core::ffi::c_int)
                << csp_id_get_host_bits()
                    .wrapping_sub((*ctx).iface.netmask as ::core::ffi::c_uint))
                - 1 as ::core::ffi::c_int) << CFP2_DST_OFFSET) as canid_t;
            filter[1 as ::core::ffi::c_int as usize].can_mask = (CFP2_DST_MASK
                << CFP2_DST_OFFSET) as canid_t;
            filter[2 as ::core::ffi::c_int as usize].can_id = ((0x3fff
                as ::core::ffi::c_int) << CFP2_DST_OFFSET) as canid_t;
            filter[2 as ::core::ffi::c_int as usize].can_mask = (CFP2_DST_MASK
                << CFP2_DST_OFFSET) as canid_t;
        }
    }
    if setsockopt(
        (*ctx).socket,
        SOL_CAN_RAW,
        CAN_RAW_FILTER as ::core::ffi::c_int,
        &raw mut filter as *const ::core::ffi::c_void,
        (num_filters as usize)
            .wrapping_mul(::core::mem::size_of::<can_filter>() as usize) as socklen_t,
    ) < 0 as ::core::ffi::c_int
    {
        csp_print_func(
            b"%s: setsockopt() failed, error: %s\n\0" as *const u8
                as *const ::core::ffi::c_char,
            b"csp_can_socketcan_set_promisc\0" as *const u8
                as *const ::core::ffi::c_char,
            strerror(*__errno_location()),
        );
        return CSP_ERR_INVAL;
    }
    return CSP_ERR_NONE;
}
unsafe extern "C" fn csp_can_socketcan_add_alias(
    mut driver_data: *mut ::core::ffi::c_void,
    mut addr: uint16_t,
) -> ::core::ffi::c_int {
    if csp_conf.version as ::core::ffi::c_int == 1 as ::core::ffi::c_int {
        return -(1 as ::core::ffi::c_int);
    }
    let mut ctx: *mut can_context_t = driver_data as *mut can_context_t;
    let mut filter: [can_filter; 10] = [can_filter {
        can_id: 0,
        can_mask: 0,
    }; 10];
    let mut len: socklen_t = ::core::mem::size_of::<[can_filter; 10]>() as socklen_t;
    getsockopt(
        (*ctx).socket,
        SOL_CAN_RAW,
        CAN_RAW_FILTER as ::core::ffi::c_int,
        &raw mut filter as *mut ::core::ffi::c_void,
        &raw mut len,
    );
    if len as usize == ::core::mem::size_of::<[can_filter; 10]>() as usize {
        return -(2 as ::core::ffi::c_int);
    }
    if len as usize == ::core::mem::size_of::<can_filter>() as usize {
        return 0 as ::core::ffi::c_int;
    }
    filter[(len as usize).wrapping_div(::core::mem::size_of::<can_filter>() as usize)
            as usize]
        .can_id = ((addr as ::core::ffi::c_int) << CFP2_DST_OFFSET) as canid_t;
    filter[(len as usize).wrapping_div(::core::mem::size_of::<can_filter>() as usize)
            as usize]
        .can_mask = (CFP2_DST_MASK << CFP2_DST_OFFSET) as canid_t;
    if setsockopt(
        (*ctx).socket,
        SOL_CAN_RAW,
        CAN_RAW_FILTER as ::core::ffi::c_int,
        &raw mut filter as *const ::core::ffi::c_void,
        (len as usize).wrapping_add(::core::mem::size_of::<can_filter>() as usize)
            as socklen_t,
    ) < 0 as ::core::ffi::c_int
    {
        return -(2 as ::core::ffi::c_int);
    }
    return 0 as ::core::ffi::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn csp_can_socketcan_open_and_add_interface(
    mut device: *const ::core::ffi::c_char,
    mut ifname: *const ::core::ffi::c_char,
    mut node_id: ::core::ffi::c_uint,
    mut bitrate: ::core::ffi::c_int,
    mut promisc: bool,
    mut return_iface: *mut *mut csp_iface_t,
) -> ::core::ffi::c_int {
    if ifname.is_null() {
        ifname = CSP_IF_CAN_DEFAULT_NAME.as_ptr();
    }
    csp_print_func(
        b"INIT %s: device: [%s], bitrate: %d, promisc: %d\n\0" as *const u8
            as *const ::core::ffi::c_char,
        ifname,
        device,
        bitrate,
        promisc as ::core::ffi::c_int,
    );
    if bitrate > 0 as ::core::ffi::c_int {
        can_do_stop(device);
        can_set_bitrate(device, bitrate as __u32);
        can_set_restart_ms(device, 100 as __u32);
        can_do_start(device);
    }
    let mut ctx: *mut can_context_t = calloc(
        1 as size_t,
        ::core::mem::size_of::<can_context_t>() as size_t,
    ) as *mut can_context_t;
    if ctx.is_null() {
        return CSP_ERR_NOMEM;
    }
    (*ctx).socket = -(1 as ::core::ffi::c_int);
    strncpy(
        &raw mut (*ctx).name as *mut ::core::ffi::c_char,
        ifname,
        (::core::mem::size_of::<[::core::ffi::c_char; 11]>() as size_t)
            .wrapping_sub(1 as size_t),
    );
    (*ctx).iface.name = &raw mut (*ctx).name as *mut ::core::ffi::c_char;
    (*ctx).iface.addr = node_id as uint16_t;
    (*ctx).iface.interface_data = &raw mut (*ctx).ifdata as *mut ::core::ffi::c_void;
    (*ctx).iface.driver_data = ctx as *mut ::core::ffi::c_void;
    (*ctx).ifdata.tx_func = Some(
        csp_can_tx_frame
            as unsafe extern "C" fn(
                *mut ::core::ffi::c_void,
                uint32_t,
                *const uint8_t,
                uint8_t,
                *const csp_packet_t,
            ) -> ::core::ffi::c_int,
    ) as csp_can_driver_tx_t;
    (*ctx).iface.add_alias = Some(
        csp_can_socketcan_add_alias
            as unsafe extern "C" fn(
                *mut ::core::ffi::c_void,
                uint16_t,
            ) -> ::core::ffi::c_int,
    ) as csp_alias_add_t;
    (*ctx).ifdata.pbufs = ::core::ptr::null_mut::<csp_packet_t>();
    (*ctx).socket = socket(PF_CAN, SOCK_RAW as ::core::ffi::c_int, CAN_RAW);
    if (*ctx).socket < 0 as ::core::ffi::c_int {
        csp_print_func(
            b"%s[%s]: socket() failed, error: %s\n\0" as *const u8
                as *const ::core::ffi::c_char,
            b"csp_can_socketcan_open_and_add_interface\0" as *const u8
                as *const ::core::ffi::c_char,
            &raw mut (*ctx).name as *mut ::core::ffi::c_char,
            strerror(*__errno_location()),
        );
        socketcan_free(ctx);
        return CSP_ERR_INVAL;
    }
    let mut ifr: ifreq = ifreq {
        ifr_ifrn: C2RustUnnamed_5 {
            ifrn_name: [0; 16],
        },
        ifr_ifru: C2RustUnnamed_4 {
            ifru_addr: sockaddr {
                sa_family: 0,
                sa_data: [0; 14],
            },
        },
    };
    strncpy(
        &raw mut ifr.ifr_ifrn.ifrn_name as *mut ::core::ffi::c_char,
        device,
        (IFNAMSIZ - 1 as ::core::ffi::c_int) as size_t,
    );
    if ioctl((*ctx).socket, SIOCGIFINDEX as ::core::ffi::c_ulong, &raw mut ifr)
        < 0 as ::core::ffi::c_int
    {
        csp_print_func(
            b"%s[%s]: device: [%s], ioctl() failed, error: %s\n\0" as *const u8
                as *const ::core::ffi::c_char,
            b"csp_can_socketcan_open_and_add_interface\0" as *const u8
                as *const ::core::ffi::c_char,
            &raw mut (*ctx).name as *mut ::core::ffi::c_char,
            device,
            strerror(*__errno_location()),
        );
        socketcan_free(ctx);
        return CSP_ERR_INVAL;
    }
    fcntl((*ctx).socket, F_SETFL, O_NONBLOCK);
    let mut addr: sockaddr_can = sockaddr_can {
        can_family: 0,
        can_ifindex: 0,
        can_addr: C2RustUnnamed_1 {
            tp: C2RustUnnamed_3 {
                rx_id: 0,
                tx_id: 0,
            },
        },
    };
    memset(
        &raw mut addr as *mut ::core::ffi::c_void,
        0 as ::core::ffi::c_int,
        ::core::mem::size_of::<sockaddr_can>() as size_t,
    );
    addr.can_family = AF_CAN as __kernel_sa_family_t;
    addr.can_ifindex = ifr.ifr_ifru.ifru_ivalue;
    if bind(
        (*ctx).socket,
        &raw mut addr as *mut sockaddr,
        ::core::mem::size_of::<sockaddr_can>() as socklen_t,
    ) < 0 as ::core::ffi::c_int
    {
        csp_print_func(
            b"%s[%s]: bind() failed, error: %s\n\0" as *const u8
                as *const ::core::ffi::c_char,
            b"csp_can_socketcan_open_and_add_interface\0" as *const u8
                as *const ::core::ffi::c_char,
            &raw mut (*ctx).name as *mut ::core::ffi::c_char,
            strerror(*__errno_location()),
        );
        socketcan_free(ctx);
        return CSP_ERR_INVAL;
    }
    if csp_can_socketcan_set_promisc(promisc, ctx) != CSP_ERR_NONE {
        csp_print_func(
            b"%s[%s]: csp_can_socketcan_set_promisc() failed, error: %s\n\0" as *const u8
                as *const ::core::ffi::c_char,
            b"csp_can_socketcan_open_and_add_interface\0" as *const u8
                as *const ::core::ffi::c_char,
            &raw mut (*ctx).name as *mut ::core::ffi::c_char,
            strerror(*__errno_location()),
        );
        socketcan_free(ctx);
        return CSP_ERR_INVAL;
    }
    let mut res: ::core::ffi::c_int = csp_can_add_interface(&raw mut (*ctx).iface);
    if res != CSP_ERR_NONE {
        csp_print_func(
            b"%s[%s]: csp_can_add_interface() failed, error: %d\n\0" as *const u8
                as *const ::core::ffi::c_char,
            b"csp_can_socketcan_open_and_add_interface\0" as *const u8
                as *const ::core::ffi::c_char,
            &raw mut (*ctx).name as *mut ::core::ffi::c_char,
            res,
        );
        socketcan_free(ctx);
        return res;
    }
    if pthread_create(
        &raw mut (*ctx).rx_thread,
        ::core::ptr::null::<pthread_attr_t>(),
        Some(
            socketcan_rx_thread
                as unsafe extern "C" fn(
                    *mut ::core::ffi::c_void,
                ) -> *mut ::core::ffi::c_void,
        ),
        ctx as *mut ::core::ffi::c_void,
    ) != 0 as ::core::ffi::c_int
    {
        csp_print_func(
            b"%s[%s]: pthread_create() failed, error: %s\n\0" as *const u8
                as *const ::core::ffi::c_char,
            b"csp_can_socketcan_open_and_add_interface\0" as *const u8
                as *const ::core::ffi::c_char,
            &raw mut (*ctx).name as *mut ::core::ffi::c_char,
            strerror(*__errno_location()),
        );
        csp_can_remove_interface(&raw mut (*ctx).iface);
        socketcan_free(ctx);
        return CSP_ERR_NOMEM;
    }
    if !return_iface.is_null() {
        *return_iface = &raw mut (*ctx).iface;
    }
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_can_socketcan_init(
    mut device: *const ::core::ffi::c_char,
    mut node_id: ::core::ffi::c_uint,
    mut bitrate: ::core::ffi::c_int,
    mut promisc: bool,
) -> *mut csp_iface_t {
    let mut return_iface: *mut csp_iface_t = ::core::ptr::null_mut::<csp_iface_t>();
    let mut res: ::core::ffi::c_int = csp_can_socketcan_open_and_add_interface(
        device,
        CSP_IF_CAN_DEFAULT_NAME.as_ptr(),
        node_id,
        bitrate,
        promisc,
        &raw mut return_iface,
    );
    return if res == CSP_ERR_NONE {
        return_iface
    } else {
        ::core::ptr::null_mut::<csp_iface_t>()
    };
}
#[no_mangle]
pub unsafe extern "C" fn csp_can_socketcan_stop(
    mut iface: *mut csp_iface_t,
) -> ::core::ffi::c_int {
    let mut ctx: *mut can_context_t = (*iface).driver_data as *mut can_context_t;
    let mut error: ::core::ffi::c_int = pthread_cancel((*ctx).rx_thread);
    if error != 0 as ::core::ffi::c_int {
        csp_print_func(
            b"%s[%s]: pthread_cancel() failed, error: %s\n\0" as *const u8
                as *const ::core::ffi::c_char,
            b"csp_can_socketcan_stop\0" as *const u8 as *const ::core::ffi::c_char,
            &raw mut (*ctx).name as *mut ::core::ffi::c_char,
            strerror(*__errno_location()),
        );
        return CSP_ERR_DRIVER;
    }
    error = pthread_join(
        (*ctx).rx_thread,
        ::core::ptr::null_mut::<*mut ::core::ffi::c_void>(),
    );
    if error != 0 as ::core::ffi::c_int {
        csp_print_func(
            b"%s[%s]: pthread_join() failed, error: %s\n\0" as *const u8
                as *const ::core::ffi::c_char,
            b"csp_can_socketcan_stop\0" as *const u8 as *const ::core::ffi::c_char,
            &raw mut (*ctx).name as *mut ::core::ffi::c_char,
            strerror(*__errno_location()),
        );
        return CSP_ERR_DRIVER;
    }
    socketcan_free(ctx);
    return CSP_ERR_NONE;
}
