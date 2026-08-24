extern "C" {
    pub type csp_conn_s;
    fn sync();
    fn sysinfo(__info: *mut sysinfo) -> ::core::ffi::c_int;
    fn reboot(__howto: ::core::ffi::c_int) -> ::core::ffi::c_int;
}
pub type __uint8_t = u8;
pub type __uint16_t = u16;
pub type __uint32_t = u32;
pub type __uint64_t = u64;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
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
pub type __kernel_ulong_t = ::core::ffi::c_ulong;
pub type __u32 = ::core::ffi::c_uint;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sysinfo {
    pub uptime: __kernel_long_t,
    pub loads: [__kernel_ulong_t; 3],
    pub totalram: __kernel_ulong_t,
    pub freeram: __kernel_ulong_t,
    pub sharedram: __kernel_ulong_t,
    pub bufferram: __kernel_ulong_t,
    pub totalswap: __kernel_ulong_t,
    pub freeswap: __kernel_ulong_t,
    pub procs: __u16,
    pub pad: __u16,
    pub totalhigh: __kernel_ulong_t,
    pub freehigh: __kernel_ulong_t,
    pub mem_unit: __u32,
    pub _f: [::core::ffi::c_char; 0],
}
pub type __u16 = ::core::ffi::c_ushort;
pub type __kernel_long_t = ::core::ffi::c_long;
pub const LINUX_REBOOT_CMD_RESTART: ::core::ffi::c_int = 0x1234567 as ::core::ffi::c_int;
pub const LINUX_REBOOT_CMD_HALT: ::core::ffi::c_uint = 0xcdef0123 as ::core::ffi::c_uint;
#[no_mangle]
pub unsafe extern "C" fn csp_memfree_hook() -> uint32_t {
    let mut total: uint32_t = 0 as uint32_t;
    let mut info: sysinfo = sysinfo {
        uptime: 0,
        loads: [0; 3],
        totalram: 0,
        freeram: 0,
        sharedram: 0,
        bufferram: 0,
        totalswap: 0,
        freeswap: 0,
        procs: 0,
        pad: 0,
        totalhigh: 0,
        freehigh: 0,
        mem_unit: 0,
        _f: [0; 0],
    };
    sysinfo(&raw mut info);
    total = info.freeram.wrapping_mul(info.mem_unit as __kernel_ulong_t) as uint32_t;
    return total;
}
#[no_mangle]
pub unsafe extern "C" fn csp_ps_hook(
    mut packet: *mut csp_packet_t,
) -> ::core::ffi::c_uint {
    return 0 as ::core::ffi::c_uint;
}
#[no_mangle]
pub unsafe extern "C" fn csp_reboot_hook() {
    sync();
    reboot(LINUX_REBOOT_CMD_RESTART);
}
#[no_mangle]
pub unsafe extern "C" fn csp_shutdown_hook() {
    sync();
    reboot(LINUX_REBOOT_CMD_HALT as ::core::ffi::c_int);
}
