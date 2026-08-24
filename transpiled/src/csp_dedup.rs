extern "C" {
    pub type csp_conn_s;
    fn csp_get_ms() -> uint32_t;
    fn csp_crc32_memory(addr: *const ::core::ffi::c_void, length: uint32_t) -> uint32_t;
    fn csp_id_prepend(packet: *mut csp_packet_t);
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
pub const true_0: ::core::ffi::c_int = 1 as ::core::ffi::c_int;
pub const false_0: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_DEDUP_COUNT: ::core::ffi::c_int = 16 as ::core::ffi::c_int;
pub const CSP_DEDUP_WINDOW_MS: ::core::ffi::c_int = 100 as ::core::ffi::c_int;
static mut csp_dedup_array: [uint32_t; 16] = [
    0 as ::core::ffi::c_int as uint32_t,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
];
static mut csp_dedup_timestamp: [uint32_t; 16] = [
    0 as ::core::ffi::c_int as uint32_t,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
];
static mut csp_dedup_in: ::core::ffi::c_uint = 0 as ::core::ffi::c_uint;
#[no_mangle]
pub unsafe extern "C" fn csp_dedup_is_duplicate(mut packet: *mut csp_packet_t) -> bool {
    csp_id_prepend(packet);
    let mut crc: uint32_t = csp_crc32_memory(
        (*packet).frame_begin as *const ::core::ffi::c_void,
        (*packet).frame_length as uint32_t,
    );
    let mut time: uint32_t = csp_get_ms();
    let mut i: ::core::ffi::c_uint = csp_dedup_in
        .wrapping_sub(1 as ::core::ffi::c_uint)
        .wrapping_rem(CSP_DEDUP_COUNT as ::core::ffi::c_uint);
    while i != csp_dedup_in {
        if time
            > csp_dedup_timestamp[i as usize]
                .wrapping_add(CSP_DEDUP_WINDOW_MS as uint32_t)
        {
            break;
        }
        if crc == csp_dedup_array[i as usize] {
            return true_0 != 0;
        }
        i = i.wrapping_sub(1 as ::core::ffi::c_uint)
            & (CSP_DEDUP_COUNT - 1 as ::core::ffi::c_int) as ::core::ffi::c_uint;
    }
    csp_dedup_array[csp_dedup_in as usize] = crc;
    csp_dedup_timestamp[csp_dedup_in as usize] = time;
    csp_dedup_in = csp_dedup_in
        .wrapping_add(1 as ::core::ffi::c_uint)
        .wrapping_rem(CSP_DEDUP_COUNT as ::core::ffi::c_uint);
    return false_0 != 0;
}
