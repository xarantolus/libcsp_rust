extern "C" {
    fn csp_print_func(fmt: *const ::core::ffi::c_char, ...);
    fn malloc(__size: size_t) -> *mut ::core::ffi::c_void;
    fn calloc(__nmemb: size_t, __size: size_t) -> *mut ::core::ffi::c_void;
    fn free(__ptr: *mut ::core::ffi::c_void);
    fn exit(__status: ::core::ffi::c_int) -> !;
    fn strerror(__errnum: ::core::ffi::c_int) -> *mut ::core::ffi::c_char;
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
    fn __errno_location() -> *mut ::core::ffi::c_int;
    fn cfsetospeed(__termios_p: *mut termios, __speed: speed_t) -> ::core::ffi::c_int;
    fn cfsetispeed(__termios_p: *mut termios, __speed: speed_t) -> ::core::ffi::c_int;
    fn tcgetattr(
        __fd: ::core::ffi::c_int,
        __termios_p: *mut termios,
    ) -> ::core::ffi::c_int;
    fn tcsetattr(
        __fd: ::core::ffi::c_int,
        __optional_actions: ::core::ffi::c_int,
        __termios_p: *const termios,
    ) -> ::core::ffi::c_int;
    fn tcflush(
        __fd: ::core::ffi::c_int,
        __queue_selector: ::core::ffi::c_int,
    ) -> ::core::ffi::c_int;
    fn fcntl(
        __fd: ::core::ffi::c_int,
        __cmd: ::core::ffi::c_int,
        ...
    ) -> ::core::ffi::c_int;
    fn open(
        __file: *const ::core::ffi::c_char,
        __oflag: ::core::ffi::c_int,
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
    fn pthread_attr_init(__attr: *mut pthread_attr_t) -> ::core::ffi::c_int;
    fn pthread_attr_destroy(__attr: *mut pthread_attr_t) -> ::core::ffi::c_int;
    fn pthread_attr_setdetachstate(
        __attr: *mut pthread_attr_t,
        __detachstate: ::core::ffi::c_int,
    ) -> ::core::ffi::c_int;
    fn pthread_mutex_lock(__mutex: *mut pthread_mutex_t) -> ::core::ffi::c_int;
    fn pthread_mutex_unlock(__mutex: *mut pthread_mutex_t) -> ::core::ffi::c_int;
}
pub type __uint8_t = u8;
pub type __uint32_t = u32;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type size_t = usize;
pub type csp_usart_fd_t = ::core::ffi::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct csp_usart_conf {
    pub device: *const ::core::ffi::c_char,
    pub baudrate: uint32_t,
    pub databits: uint8_t,
    pub stopbits: uint8_t,
    pub paritysetting: uint8_t,
}
pub type csp_usart_conf_t = csp_usart_conf;
pub type csp_usart_callback_t = Option<
    unsafe extern "C" fn(
        *mut ::core::ffi::c_void,
        *mut uint8_t,
        size_t,
        *mut ::core::ffi::c_void,
    ) -> (),
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_attr_t {
    pub __size: [::core::ffi::c_char; 56],
    pub __align: ::core::ffi::c_long,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct usart_context_t {
    pub rx_callback: csp_usart_callback_t,
    pub user_data: *mut ::core::ffi::c_void,
    pub fd: csp_usart_fd_t,
    pub rx_thread: pthread_t,
}
pub type pthread_t = ::core::ffi::c_ulong;
pub type ssize_t = isize;
pub const PTHREAD_CREATE_DETACHED: C2RustUnnamed = 1;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct termios {
    pub c_iflag: tcflag_t,
    pub c_oflag: tcflag_t,
    pub c_cflag: tcflag_t,
    pub c_lflag: tcflag_t,
    pub c_line: cc_t,
    pub c_cc: [cc_t; 32],
    pub c_ispeed: speed_t,
    pub c_ospeed: speed_t,
}
pub type speed_t = ::core::ffi::c_uint;
pub type cc_t = ::core::ffi::c_uchar;
pub type tcflag_t = ::core::ffi::c_uint;
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_mutex_t {
    pub __data: __pthread_mutex_s,
    pub __size: [::core::ffi::c_char; 40],
    pub __align: ::core::ffi::c_long,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __pthread_mutex_s {
    pub __lock: ::core::ffi::c_int,
    pub __count: ::core::ffi::c_uint,
    pub __owner: ::core::ffi::c_int,
    pub __nusers: ::core::ffi::c_uint,
    pub __kind: ::core::ffi::c_int,
    pub __spins: ::core::ffi::c_short,
    pub __elision: ::core::ffi::c_short,
    pub __list: __pthread_list_t,
}
pub type __pthread_list_t = __pthread_internal_list;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __pthread_internal_list {
    pub __prev: *mut __pthread_internal_list,
    pub __next: *mut __pthread_internal_list,
}
pub const PTHREAD_MUTEX_TIMED_NP: C2RustUnnamed_0 = 0;
pub type C2RustUnnamed = ::core::ffi::c_uint;
pub const PTHREAD_CREATE_JOINABLE: C2RustUnnamed = 0;
pub type C2RustUnnamed_0 = ::core::ffi::c_uint;
pub const PTHREAD_MUTEX_DEFAULT: C2RustUnnamed_0 = 0;
pub const PTHREAD_MUTEX_ERRORCHECK: C2RustUnnamed_0 = 2;
pub const PTHREAD_MUTEX_RECURSIVE: C2RustUnnamed_0 = 1;
pub const PTHREAD_MUTEX_NORMAL: C2RustUnnamed_0 = 0;
pub const PTHREAD_MUTEX_ADAPTIVE_NP: C2RustUnnamed_0 = 3;
pub const PTHREAD_MUTEX_ERRORCHECK_NP: C2RustUnnamed_0 = 2;
pub const PTHREAD_MUTEX_RECURSIVE_NP: C2RustUnnamed_0 = 1;
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ERR_NOMEM: ::core::ffi::c_int = -(1 as ::core::ffi::c_int);
pub const CSP_ERR_INVAL: ::core::ffi::c_int = -(2 as ::core::ffi::c_int);
pub const CSP_ERR_TX: ::core::ffi::c_int = -(10 as ::core::ffi::c_int);
pub const CSP_ERR_DRIVER: ::core::ffi::c_int = -(11 as ::core::ffi::c_int);
pub const NULL: *mut ::core::ffi::c_void = ::core::ptr::null_mut::<
    ::core::ffi::c_void,
>();
pub const VTIME: ::core::ffi::c_int = 5 as ::core::ffi::c_int;
pub const VMIN: ::core::ffi::c_int = 6 as ::core::ffi::c_int;
pub const IGNBRK: ::core::ffi::c_int = 0o1 as ::core::ffi::c_int;
pub const BRKINT: ::core::ffi::c_int = 0o2 as ::core::ffi::c_int;
pub const PARMRK: ::core::ffi::c_int = 0o10 as ::core::ffi::c_int;
pub const INPCK: ::core::ffi::c_int = 0o20 as ::core::ffi::c_int;
pub const ISTRIP: ::core::ffi::c_int = 0o40 as ::core::ffi::c_int;
pub const INLCR: ::core::ffi::c_int = 0o100 as ::core::ffi::c_int;
pub const ICRNL: ::core::ffi::c_int = 0o400 as ::core::ffi::c_int;
pub const IXON: ::core::ffi::c_int = 0o2000 as ::core::ffi::c_int;
pub const OPOST: ::core::ffi::c_int = 0o1 as ::core::ffi::c_int;
pub const ONLCR: ::core::ffi::c_int = 0o4 as ::core::ffi::c_int;
pub const OCRNL: ::core::ffi::c_int = 0o10 as ::core::ffi::c_int;
pub const ONOCR: ::core::ffi::c_int = 0o20 as ::core::ffi::c_int;
pub const ONLRET: ::core::ffi::c_int = 0o40 as ::core::ffi::c_int;
pub const OFILL: ::core::ffi::c_int = 0o100 as ::core::ffi::c_int;
pub const B4800: ::core::ffi::c_int = 0o14 as ::core::ffi::c_int;
pub const B9600: ::core::ffi::c_int = 0o15 as ::core::ffi::c_int;
pub const B19200: ::core::ffi::c_int = 0o16 as ::core::ffi::c_int;
pub const B38400: ::core::ffi::c_int = 0o17 as ::core::ffi::c_int;
pub const B57600: ::core::ffi::c_int = 0o10001 as ::core::ffi::c_int;
pub const B115200: ::core::ffi::c_int = 0o10002 as ::core::ffi::c_int;
pub const B230400: ::core::ffi::c_int = 0o10003 as ::core::ffi::c_int;
pub const B460800: ::core::ffi::c_int = 0o10004 as ::core::ffi::c_int;
pub const B500000: ::core::ffi::c_int = 0o10005 as ::core::ffi::c_int;
pub const B576000: ::core::ffi::c_int = 0o10006 as ::core::ffi::c_int;
pub const B921600: ::core::ffi::c_int = 0o10007 as ::core::ffi::c_int;
pub const B1000000: ::core::ffi::c_int = 0o10010 as ::core::ffi::c_int;
pub const B1152000: ::core::ffi::c_int = 0o10011 as ::core::ffi::c_int;
pub const B1500000: ::core::ffi::c_int = 0o10012 as ::core::ffi::c_int;
pub const B2000000: ::core::ffi::c_int = 0o10013 as ::core::ffi::c_int;
pub const B2500000: ::core::ffi::c_int = 0o10014 as ::core::ffi::c_int;
pub const B3000000: ::core::ffi::c_int = 0o10015 as ::core::ffi::c_int;
pub const B3500000: ::core::ffi::c_int = 0o10016 as ::core::ffi::c_int;
pub const B4000000: ::core::ffi::c_int = 0o10017 as ::core::ffi::c_int;
pub const CSIZE: ::core::ffi::c_int = 0o60 as ::core::ffi::c_int;
pub const CS8: ::core::ffi::c_int = 0o60 as ::core::ffi::c_int;
pub const CSTOPB: ::core::ffi::c_int = 0o100 as ::core::ffi::c_int;
pub const CREAD: ::core::ffi::c_int = 0o200 as ::core::ffi::c_int;
pub const PARENB: ::core::ffi::c_int = 0o400 as ::core::ffi::c_int;
pub const CLOCAL: ::core::ffi::c_int = 0o4000 as ::core::ffi::c_int;
pub const ISIG: ::core::ffi::c_int = 0o1 as ::core::ffi::c_int;
pub const ICANON: ::core::ffi::c_int = 0o2 as ::core::ffi::c_int;
pub const ECHO: ::core::ffi::c_int = 0o10 as ::core::ffi::c_int;
pub const ECHONL: ::core::ffi::c_int = 0o100 as ::core::ffi::c_int;
pub const IEXTEN: ::core::ffi::c_int = 0o100000 as ::core::ffi::c_int;
pub const TCIOFLUSH: ::core::ffi::c_int = 2 as ::core::ffi::c_int;
pub const TCSANOW: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const O_RDWR: ::core::ffi::c_int = 0o2 as ::core::ffi::c_int;
pub const O_NOCTTY: ::core::ffi::c_int = 0o400 as ::core::ffi::c_int;
pub const O_NONBLOCK: ::core::ffi::c_int = 0o4000 as ::core::ffi::c_int;
pub const F_SETFL: ::core::ffi::c_int = 4 as ::core::ffi::c_int;
static mut lock: pthread_mutex_t = pthread_mutex_t {
    __data: __pthread_mutex_s {
        __lock: 0 as ::core::ffi::c_int,
        __count: 0 as ::core::ffi::c_uint,
        __owner: 0 as ::core::ffi::c_int,
        __nusers: 0 as ::core::ffi::c_uint,
        __kind: PTHREAD_MUTEX_TIMED_NP as ::core::ffi::c_int,
        __spins: 0 as ::core::ffi::c_short,
        __elision: 0 as ::core::ffi::c_short,
        __list: __pthread_internal_list {
            __prev: ::core::ptr::null::<__pthread_internal_list>()
                as *mut __pthread_internal_list,
            __next: ::core::ptr::null::<__pthread_internal_list>()
                as *mut __pthread_internal_list,
        },
    },
};
#[no_mangle]
pub unsafe extern "C" fn csp_usart_lock(mut driver_data: *mut ::core::ffi::c_void) {
    pthread_mutex_lock(&raw mut lock);
}
#[no_mangle]
pub unsafe extern "C" fn csp_usart_unlock(mut driver_data: *mut ::core::ffi::c_void) {
    pthread_mutex_unlock(&raw mut lock);
}
unsafe extern "C" fn usart_rx_thread(
    mut arg: *mut ::core::ffi::c_void,
) -> *mut ::core::ffi::c_void {
    let mut ctx: *mut usart_context_t = arg as *mut usart_context_t;
    let CBUF_SIZE: ::core::ffi::c_uint = 400 as ::core::ffi::c_uint;
    let mut cbuf: *mut uint8_t = malloc(CBUF_SIZE as size_t) as *mut uint8_t;
    if cbuf.is_null() {
        csp_print_func(
            b"%s: malloc() failed, returned NULL\n\0" as *const u8
                as *const ::core::ffi::c_char,
            b"usart_rx_thread\0" as *const u8 as *const ::core::ffi::c_char,
        );
        exit(1 as ::core::ffi::c_int);
    }
    loop {
        let mut length: ::core::ffi::c_int = read(
            (*ctx).fd as ::core::ffi::c_int,
            cbuf as *mut ::core::ffi::c_void,
            CBUF_SIZE as size_t,
        ) as ::core::ffi::c_int;
        if length <= 0 as ::core::ffi::c_int {
            csp_print_func(
                b"%s: read() failed, returned: %d\n\0" as *const u8
                    as *const ::core::ffi::c_char,
                b"usart_rx_thread\0" as *const u8 as *const ::core::ffi::c_char,
                length,
            );
            exit(1 as ::core::ffi::c_int);
        }
        (*ctx)
            .rx_callback
            .expect(
                "non-null function pointer",
            )((*ctx).user_data, cbuf, length as size_t, NULL);
    };
}
#[no_mangle]
pub unsafe extern "C" fn csp_usart_write(
    mut fd: csp_usart_fd_t,
    mut data: *const ::core::ffi::c_void,
    mut data_length: size_t,
) -> ::core::ffi::c_int {
    if fd >= 0 as ::core::ffi::c_int {
        let mut res: ::core::ffi::c_int = write(
            fd as ::core::ffi::c_int,
            data,
            data_length,
        ) as ::core::ffi::c_int;
        if res >= 0 as ::core::ffi::c_int {
            return res;
        }
    }
    return CSP_ERR_TX;
}
#[no_mangle]
pub unsafe extern "C" fn csp_usart_open(
    mut conf: *const csp_usart_conf_t,
    mut rx_callback: csp_usart_callback_t,
    mut user_data: *mut ::core::ffi::c_void,
    mut return_fd: *mut csp_usart_fd_t,
) -> ::core::ffi::c_int {
    if rx_callback.is_none() && return_fd.is_null() {
        csp_print_func(
            b"%s: No rx_callback function pointer or return_fd pointer provided\n\0"
                as *const u8 as *const ::core::ffi::c_char,
            b"csp_usart_open\0" as *const u8 as *const ::core::ffi::c_char,
        );
        return CSP_ERR_INVAL;
    }
    let mut brate: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
    match (*conf).baudrate {
        4800 => {
            brate = B4800;
        }
        9600 => {
            brate = B9600;
        }
        19200 => {
            brate = B19200;
        }
        38400 => {
            brate = B38400;
        }
        57600 => {
            brate = B57600;
        }
        115200 => {
            brate = B115200;
        }
        230400 => {
            brate = B230400;
        }
        460800 => {
            brate = B460800;
        }
        500000 => {
            brate = B500000;
        }
        576000 => {
            brate = B576000;
        }
        921600 => {
            brate = B921600;
        }
        1000000 => {
            brate = B1000000;
        }
        1152000 => {
            brate = B1152000;
        }
        1500000 => {
            brate = B1500000;
        }
        2000000 => {
            brate = B2000000;
        }
        2500000 => {
            brate = B2500000;
        }
        3000000 => {
            brate = B3000000;
        }
        3500000 => {
            brate = B3500000;
        }
        4000000 => {
            brate = B4000000;
        }
        _ => {
            csp_print_func(
                b"%s: Unsupported baudrate: %u\n\0" as *const u8
                    as *const ::core::ffi::c_char,
                b"csp_usart_open\0" as *const u8 as *const ::core::ffi::c_char,
                (*conf).baudrate,
            );
            return CSP_ERR_INVAL;
        }
    }
    let mut fd: ::core::ffi::c_int = open(
        (*conf).device,
        O_RDWR | O_NOCTTY | O_NONBLOCK,
    );
    if fd < 0 as ::core::ffi::c_int {
        csp_print_func(
            b"%s: failed to open device: [%s], errno: %s\n\0" as *const u8
                as *const ::core::ffi::c_char,
            b"csp_usart_open\0" as *const u8 as *const ::core::ffi::c_char,
            (*conf).device,
            strerror(*__errno_location()),
        );
        return CSP_ERR_INVAL;
    }
    let mut options: termios = termios {
        c_iflag: 0,
        c_oflag: 0,
        c_cflag: 0,
        c_lflag: 0,
        c_line: 0,
        c_cc: [0; 32],
        c_ispeed: 0,
        c_ospeed: 0,
    };
    tcgetattr(fd, &raw mut options);
    cfsetispeed(&raw mut options, brate as speed_t);
    cfsetospeed(&raw mut options, brate as speed_t);
    options.c_cflag |= (CLOCAL | CREAD) as tcflag_t;
    options.c_cflag &= !PARENB as tcflag_t;
    options.c_cflag &= !CSTOPB as tcflag_t;
    options.c_cflag &= !CSIZE as tcflag_t;
    options.c_cflag |= CS8 as tcflag_t;
    options.c_lflag &= !(ECHO | ECHONL | ICANON | IEXTEN | ISIG) as tcflag_t;
    options.c_iflag
        &= !(IGNBRK | BRKINT | ICRNL | INLCR | PARMRK | INPCK | ISTRIP | IXON)
            as tcflag_t;
    options.c_oflag &= !(OCRNL | ONLCR | ONLRET | ONOCR | OFILL | OPOST) as tcflag_t;
    options.c_cc[VTIME as usize] = 0 as cc_t;
    options.c_cc[VMIN as usize] = 1 as cc_t;
    if tcsetattr(fd, TCSANOW, &raw mut options) != 0 as ::core::ffi::c_int {
        csp_print_func(
            b"%s: Failed to set attributes on device: [%s], errno: %s\n\0" as *const u8
                as *const ::core::ffi::c_char,
            b"csp_usart_open\0" as *const u8 as *const ::core::ffi::c_char,
            (*conf).device,
            strerror(*__errno_location()),
        );
        close(fd);
        return CSP_ERR_DRIVER;
    }
    fcntl(fd, F_SETFL, 0 as ::core::ffi::c_int);
    if tcflush(fd, TCIOFLUSH) != 0 as ::core::ffi::c_int {
        csp_print_func(
            b"%s: Error flushing device: [%s], errno: %s\n\0" as *const u8
                as *const ::core::ffi::c_char,
            b"csp_usart_open\0" as *const u8 as *const ::core::ffi::c_char,
            (*conf).device,
            strerror(*__errno_location()),
        );
        close(fd);
        return CSP_ERR_DRIVER;
    }
    if rx_callback.is_some() {
        let mut ctx: *mut usart_context_t = calloc(
            1 as size_t,
            ::core::mem::size_of::<usart_context_t>() as size_t,
        ) as *mut usart_context_t;
        if ctx.is_null() {
            csp_print_func(
                b"%s: Error allocating context, device: [%s], errno: %s\n\0" as *const u8
                    as *const ::core::ffi::c_char,
                b"csp_usart_open\0" as *const u8 as *const ::core::ffi::c_char,
                (*conf).device,
                strerror(*__errno_location()),
            );
            close(fd);
            return CSP_ERR_NOMEM;
        }
        (*ctx).rx_callback = rx_callback;
        (*ctx).user_data = user_data;
        (*ctx).fd = fd as csp_usart_fd_t;
        let mut ret: ::core::ffi::c_int = 0;
        let mut attributes: pthread_attr_t = pthread_attr_t { __size: [0; 56] };
        ret = pthread_attr_init(&raw mut attributes);
        if ret != 0 as ::core::ffi::c_int {
            free(ctx as *mut ::core::ffi::c_void);
            close(fd);
            return CSP_ERR_NOMEM;
        }
        pthread_attr_setdetachstate(
            &raw mut attributes,
            PTHREAD_CREATE_DETACHED as ::core::ffi::c_int,
        );
        ret = pthread_create(
            &raw mut (*ctx).rx_thread,
            &raw mut attributes,
            Some(
                usart_rx_thread
                    as unsafe extern "C" fn(
                        *mut ::core::ffi::c_void,
                    ) -> *mut ::core::ffi::c_void,
            ),
            ctx as *mut ::core::ffi::c_void,
        );
        if ret != 0 as ::core::ffi::c_int {
            csp_print_func(
                b"%s: pthread_create() failed to create Rx thread for device: [%s], errno: %s\n\0"
                    as *const u8 as *const ::core::ffi::c_char,
                b"csp_usart_open\0" as *const u8 as *const ::core::ffi::c_char,
                (*conf).device,
                strerror(*__errno_location()),
            );
            free(ctx as *mut ::core::ffi::c_void);
            close(fd);
            return CSP_ERR_NOMEM;
        }
        ret = pthread_attr_destroy(&raw mut attributes);
        if ret != 0 as ::core::ffi::c_int {
            csp_print_func(
                b"%s: pthread_attr_destroy() failed: %s, errno: %d\n\0" as *const u8
                    as *const ::core::ffi::c_char,
                b"csp_usart_open\0" as *const u8 as *const ::core::ffi::c_char,
                strerror(ret),
                ret,
            );
        }
    }
    if !return_fd.is_null() {
        *return_fd = fd as csp_usart_fd_t;
    }
    return CSP_ERR_NONE;
}
