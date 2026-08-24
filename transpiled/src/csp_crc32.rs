extern "C" {
    pub type csp_conn_s;
    fn memcpy(
        __dest: *mut ::core::ffi::c_void,
        __src: *const ::core::ffi::c_void,
        __n: size_t,
    ) -> *mut ::core::ffi::c_void;
    fn memcmp(
        __s1: *const ::core::ffi::c_void,
        __s2: *const ::core::ffi::c_void,
        __n: size_t,
    ) -> ::core::ffi::c_int;
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
pub type csp_crc32_t = uint32_t;
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ERR_NOMEM: ::core::ffi::c_int = -(1 as ::core::ffi::c_int);
pub const CSP_ERR_CRC32: ::core::ffi::c_int = -(102 as ::core::ffi::c_int);
#[inline]
unsafe extern "C" fn __bswap_32(mut __bsx: __uint32_t) -> __uint32_t {
    return (__bsx & 0xff000000 as __uint32_t) >> 24 as ::core::ffi::c_int
        | (__bsx & 0xff0000 as __uint32_t) >> 8 as ::core::ffi::c_int
        | (__bsx & 0xff00 as __uint32_t) << 8 as ::core::ffi::c_int
        | (__bsx & 0xff as __uint32_t) << 24 as ::core::ffi::c_int;
}
static mut crc_tab: [uint32_t; 256] = [
    0 as ::core::ffi::c_int as uint32_t,
    0xf26b8303 as ::core::ffi::c_uint,
    0xe13b70f7 as ::core::ffi::c_uint,
    0x1350f3f4 as ::core::ffi::c_int as uint32_t,
    0xc79a971f as ::core::ffi::c_uint,
    0x35f1141c as ::core::ffi::c_int as uint32_t,
    0x26a1e7e8 as ::core::ffi::c_int as uint32_t,
    0xd4ca64eb as ::core::ffi::c_uint,
    0x8ad958cf as ::core::ffi::c_uint,
    0x78b2dbcc as ::core::ffi::c_int as uint32_t,
    0x6be22838 as ::core::ffi::c_int as uint32_t,
    0x9989ab3b as ::core::ffi::c_uint,
    0x4d43cfd0 as ::core::ffi::c_int as uint32_t,
    0xbf284cd3 as ::core::ffi::c_uint,
    0xac78bf27 as ::core::ffi::c_uint,
    0x5e133c24 as ::core::ffi::c_int as uint32_t,
    0x105ec76f as ::core::ffi::c_int as uint32_t,
    0xe235446c as ::core::ffi::c_uint,
    0xf165b798 as ::core::ffi::c_uint,
    0x30e349b as ::core::ffi::c_int as uint32_t,
    0xd7c45070 as ::core::ffi::c_uint,
    0x25afd373 as ::core::ffi::c_int as uint32_t,
    0x36ff2087 as ::core::ffi::c_int as uint32_t,
    0xc494a384 as ::core::ffi::c_uint,
    0x9a879fa0 as ::core::ffi::c_uint,
    0x68ec1ca3 as ::core::ffi::c_int as uint32_t,
    0x7bbcef57 as ::core::ffi::c_int as uint32_t,
    0x89d76c54 as ::core::ffi::c_uint,
    0x5d1d08bf as ::core::ffi::c_int as uint32_t,
    0xaf768bbc as ::core::ffi::c_uint,
    0xbc267848 as ::core::ffi::c_uint,
    0x4e4dfb4b as ::core::ffi::c_int as uint32_t,
    0x20bd8ede as ::core::ffi::c_int as uint32_t,
    0xd2d60ddd as ::core::ffi::c_uint,
    0xc186fe29 as ::core::ffi::c_uint,
    0x33ed7d2a as ::core::ffi::c_int as uint32_t,
    0xe72719c1 as ::core::ffi::c_uint,
    0x154c9ac2 as ::core::ffi::c_int as uint32_t,
    0x61c6936 as ::core::ffi::c_int as uint32_t,
    0xf477ea35 as ::core::ffi::c_uint,
    0xaa64d611 as ::core::ffi::c_uint,
    0x580f5512 as ::core::ffi::c_int as uint32_t,
    0x4b5fa6e6 as ::core::ffi::c_int as uint32_t,
    0xb93425e5 as ::core::ffi::c_uint,
    0x6dfe410e as ::core::ffi::c_int as uint32_t,
    0x9f95c20d as ::core::ffi::c_uint,
    0x8cc531f9 as ::core::ffi::c_uint,
    0x7eaeb2fa as ::core::ffi::c_int as uint32_t,
    0x30e349b1 as ::core::ffi::c_int as uint32_t,
    0xc288cab2 as ::core::ffi::c_uint,
    0xd1d83946 as ::core::ffi::c_uint,
    0x23b3ba45 as ::core::ffi::c_int as uint32_t,
    0xf779deae as ::core::ffi::c_uint,
    0x5125dad as ::core::ffi::c_int as uint32_t,
    0x1642ae59 as ::core::ffi::c_int as uint32_t,
    0xe4292d5a as ::core::ffi::c_uint,
    0xba3a117e as ::core::ffi::c_uint,
    0x4851927d as ::core::ffi::c_int as uint32_t,
    0x5b016189 as ::core::ffi::c_int as uint32_t,
    0xa96ae28a as ::core::ffi::c_uint,
    0x7da08661 as ::core::ffi::c_int as uint32_t,
    0x8fcb0562 as ::core::ffi::c_uint,
    0x9c9bf696 as ::core::ffi::c_uint,
    0x6ef07595 as ::core::ffi::c_int as uint32_t,
    0x417b1dbc as ::core::ffi::c_int as uint32_t,
    0xb3109ebf as ::core::ffi::c_uint,
    0xa0406d4b as ::core::ffi::c_uint,
    0x522bee48 as ::core::ffi::c_int as uint32_t,
    0x86e18aa3 as ::core::ffi::c_uint,
    0x748a09a0 as ::core::ffi::c_int as uint32_t,
    0x67dafa54 as ::core::ffi::c_int as uint32_t,
    0x95b17957 as ::core::ffi::c_uint,
    0xcba24573 as ::core::ffi::c_uint,
    0x39c9c670 as ::core::ffi::c_int as uint32_t,
    0x2a993584 as ::core::ffi::c_int as uint32_t,
    0xd8f2b687 as ::core::ffi::c_uint,
    0xc38d26c as ::core::ffi::c_int as uint32_t,
    0xfe53516f as ::core::ffi::c_uint,
    0xed03a29b as ::core::ffi::c_uint,
    0x1f682198 as ::core::ffi::c_int as uint32_t,
    0x5125dad3 as ::core::ffi::c_int as uint32_t,
    0xa34e59d0 as ::core::ffi::c_uint,
    0xb01eaa24 as ::core::ffi::c_uint,
    0x42752927 as ::core::ffi::c_int as uint32_t,
    0x96bf4dcc as ::core::ffi::c_uint,
    0x64d4cecf as ::core::ffi::c_int as uint32_t,
    0x77843d3b as ::core::ffi::c_int as uint32_t,
    0x85efbe38 as ::core::ffi::c_uint,
    0xdbfc821c as ::core::ffi::c_uint,
    0x2997011f as ::core::ffi::c_int as uint32_t,
    0x3ac7f2eb as ::core::ffi::c_int as uint32_t,
    0xc8ac71e8 as ::core::ffi::c_uint,
    0x1c661503 as ::core::ffi::c_int as uint32_t,
    0xee0d9600 as ::core::ffi::c_uint,
    0xfd5d65f4 as ::core::ffi::c_uint,
    0xf36e6f7 as ::core::ffi::c_int as uint32_t,
    0x61c69362 as ::core::ffi::c_int as uint32_t,
    0x93ad1061 as ::core::ffi::c_uint,
    0x80fde395 as ::core::ffi::c_uint,
    0x72966096 as ::core::ffi::c_int as uint32_t,
    0xa65c047d as ::core::ffi::c_uint,
    0x5437877e as ::core::ffi::c_int as uint32_t,
    0x4767748a as ::core::ffi::c_int as uint32_t,
    0xb50cf789 as ::core::ffi::c_uint,
    0xeb1fcbad as ::core::ffi::c_uint,
    0x197448ae as ::core::ffi::c_int as uint32_t,
    0xa24bb5a as ::core::ffi::c_int as uint32_t,
    0xf84f3859 as ::core::ffi::c_uint,
    0x2c855cb2 as ::core::ffi::c_int as uint32_t,
    0xdeeedfb1 as ::core::ffi::c_uint,
    0xcdbe2c45 as ::core::ffi::c_uint,
    0x3fd5af46 as ::core::ffi::c_int as uint32_t,
    0x7198540d as ::core::ffi::c_int as uint32_t,
    0x83f3d70e as ::core::ffi::c_uint,
    0x90a324fa as ::core::ffi::c_uint,
    0x62c8a7f9 as ::core::ffi::c_int as uint32_t,
    0xb602c312 as ::core::ffi::c_uint,
    0x44694011 as ::core::ffi::c_int as uint32_t,
    0x5739b3e5 as ::core::ffi::c_int as uint32_t,
    0xa55230e6 as ::core::ffi::c_uint,
    0xfb410cc2 as ::core::ffi::c_uint,
    0x92a8fc1 as ::core::ffi::c_int as uint32_t,
    0x1a7a7c35 as ::core::ffi::c_int as uint32_t,
    0xe811ff36 as ::core::ffi::c_uint,
    0x3cdb9bdd as ::core::ffi::c_int as uint32_t,
    0xceb018de as ::core::ffi::c_uint,
    0xdde0eb2a as ::core::ffi::c_uint,
    0x2f8b6829 as ::core::ffi::c_int as uint32_t,
    0x82f63b78 as ::core::ffi::c_uint,
    0x709db87b as ::core::ffi::c_int as uint32_t,
    0x63cd4b8f as ::core::ffi::c_int as uint32_t,
    0x91a6c88c as ::core::ffi::c_uint,
    0x456cac67 as ::core::ffi::c_int as uint32_t,
    0xb7072f64 as ::core::ffi::c_uint,
    0xa457dc90 as ::core::ffi::c_uint,
    0x563c5f93 as ::core::ffi::c_int as uint32_t,
    0x82f63b7 as ::core::ffi::c_int as uint32_t,
    0xfa44e0b4 as ::core::ffi::c_uint,
    0xe9141340 as ::core::ffi::c_uint,
    0x1b7f9043 as ::core::ffi::c_int as uint32_t,
    0xcfb5f4a8 as ::core::ffi::c_uint,
    0x3dde77ab as ::core::ffi::c_int as uint32_t,
    0x2e8e845f as ::core::ffi::c_int as uint32_t,
    0xdce5075c as ::core::ffi::c_uint,
    0x92a8fc17 as ::core::ffi::c_uint,
    0x60c37f14 as ::core::ffi::c_int as uint32_t,
    0x73938ce0 as ::core::ffi::c_int as uint32_t,
    0x81f80fe3 as ::core::ffi::c_uint,
    0x55326b08 as ::core::ffi::c_int as uint32_t,
    0xa759e80b as ::core::ffi::c_uint,
    0xb4091bff as ::core::ffi::c_uint,
    0x466298fc as ::core::ffi::c_int as uint32_t,
    0x1871a4d8 as ::core::ffi::c_int as uint32_t,
    0xea1a27db as ::core::ffi::c_uint,
    0xf94ad42f as ::core::ffi::c_uint,
    0xb21572c as ::core::ffi::c_int as uint32_t,
    0xdfeb33c7 as ::core::ffi::c_uint,
    0x2d80b0c4 as ::core::ffi::c_int as uint32_t,
    0x3ed04330 as ::core::ffi::c_int as uint32_t,
    0xccbbc033 as ::core::ffi::c_uint,
    0xa24bb5a6 as ::core::ffi::c_uint,
    0x502036a5 as ::core::ffi::c_int as uint32_t,
    0x4370c551 as ::core::ffi::c_int as uint32_t,
    0xb11b4652 as ::core::ffi::c_uint,
    0x65d122b9 as ::core::ffi::c_int as uint32_t,
    0x97baa1ba as ::core::ffi::c_uint,
    0x84ea524e as ::core::ffi::c_uint,
    0x7681d14d as ::core::ffi::c_int as uint32_t,
    0x2892ed69 as ::core::ffi::c_int as uint32_t,
    0xdaf96e6a as ::core::ffi::c_uint,
    0xc9a99d9e as ::core::ffi::c_uint,
    0x3bc21e9d as ::core::ffi::c_int as uint32_t,
    0xef087a76 as ::core::ffi::c_uint,
    0x1d63f975 as ::core::ffi::c_int as uint32_t,
    0xe330a81 as ::core::ffi::c_int as uint32_t,
    0xfc588982 as ::core::ffi::c_uint,
    0xb21572c9 as ::core::ffi::c_uint,
    0x407ef1ca as ::core::ffi::c_int as uint32_t,
    0x532e023e as ::core::ffi::c_int as uint32_t,
    0xa145813d as ::core::ffi::c_uint,
    0x758fe5d6 as ::core::ffi::c_int as uint32_t,
    0x87e466d5 as ::core::ffi::c_uint,
    0x94b49521 as ::core::ffi::c_uint,
    0x66df1622 as ::core::ffi::c_int as uint32_t,
    0x38cc2a06 as ::core::ffi::c_int as uint32_t,
    0xcaa7a905 as ::core::ffi::c_uint,
    0xd9f75af1 as ::core::ffi::c_uint,
    0x2b9cd9f2 as ::core::ffi::c_int as uint32_t,
    0xff56bd19 as ::core::ffi::c_uint,
    0xd3d3e1a as ::core::ffi::c_int as uint32_t,
    0x1e6dcdee as ::core::ffi::c_int as uint32_t,
    0xec064eed as ::core::ffi::c_uint,
    0xc38d26c4 as ::core::ffi::c_uint,
    0x31e6a5c7 as ::core::ffi::c_int as uint32_t,
    0x22b65633 as ::core::ffi::c_int as uint32_t,
    0xd0ddd530 as ::core::ffi::c_uint,
    0x417b1db as ::core::ffi::c_int as uint32_t,
    0xf67c32d8 as ::core::ffi::c_uint,
    0xe52cc12c as ::core::ffi::c_uint,
    0x1747422f as ::core::ffi::c_int as uint32_t,
    0x49547e0b as ::core::ffi::c_int as uint32_t,
    0xbb3ffd08 as ::core::ffi::c_uint,
    0xa86f0efc as ::core::ffi::c_uint,
    0x5a048dff as ::core::ffi::c_int as uint32_t,
    0x8ecee914 as ::core::ffi::c_uint,
    0x7ca56a17 as ::core::ffi::c_int as uint32_t,
    0x6ff599e3 as ::core::ffi::c_int as uint32_t,
    0x9d9e1ae0 as ::core::ffi::c_uint,
    0xd3d3e1ab as ::core::ffi::c_uint,
    0x21b862a8 as ::core::ffi::c_int as uint32_t,
    0x32e8915c as ::core::ffi::c_int as uint32_t,
    0xc083125f as ::core::ffi::c_uint,
    0x144976b4 as ::core::ffi::c_int as uint32_t,
    0xe622f5b7 as ::core::ffi::c_uint,
    0xf5720643 as ::core::ffi::c_uint,
    0x7198540 as ::core::ffi::c_int as uint32_t,
    0x590ab964 as ::core::ffi::c_int as uint32_t,
    0xab613a67 as ::core::ffi::c_uint,
    0xb831c993 as ::core::ffi::c_uint,
    0x4a5a4a90 as ::core::ffi::c_int as uint32_t,
    0x9e902e7b as ::core::ffi::c_uint,
    0x6cfbad78 as ::core::ffi::c_int as uint32_t,
    0x7fab5e8c as ::core::ffi::c_int as uint32_t,
    0x8dc0dd8f as ::core::ffi::c_uint,
    0xe330a81a as ::core::ffi::c_uint,
    0x115b2b19 as ::core::ffi::c_int as uint32_t,
    0x20bd8ed as ::core::ffi::c_int as uint32_t,
    0xf0605bee as ::core::ffi::c_uint,
    0x24aa3f05 as ::core::ffi::c_int as uint32_t,
    0xd6c1bc06 as ::core::ffi::c_uint,
    0xc5914ff2 as ::core::ffi::c_uint,
    0x37faccf1 as ::core::ffi::c_int as uint32_t,
    0x69e9f0d5 as ::core::ffi::c_int as uint32_t,
    0x9b8273d6 as ::core::ffi::c_uint,
    0x88d28022 as ::core::ffi::c_uint,
    0x7ab90321 as ::core::ffi::c_int as uint32_t,
    0xae7367ca as ::core::ffi::c_uint,
    0x5c18e4c9 as ::core::ffi::c_int as uint32_t,
    0x4f48173d as ::core::ffi::c_int as uint32_t,
    0xbd23943e as ::core::ffi::c_uint,
    0xf36e6f75 as ::core::ffi::c_uint,
    0x105ec76 as ::core::ffi::c_int as uint32_t,
    0x12551f82 as ::core::ffi::c_int as uint32_t,
    0xe03e9c81 as ::core::ffi::c_uint,
    0x34f4f86a as ::core::ffi::c_int as uint32_t,
    0xc69f7b69 as ::core::ffi::c_uint,
    0xd5cf889d as ::core::ffi::c_uint,
    0x27a40b9e as ::core::ffi::c_int as uint32_t,
    0x79b737ba as ::core::ffi::c_int as uint32_t,
    0x8bdcb4b9 as ::core::ffi::c_uint,
    0x988c474d as ::core::ffi::c_uint,
    0x6ae7c44e as ::core::ffi::c_int as uint32_t,
    0xbe2da0a5 as ::core::ffi::c_uint,
    0x4c4623a6 as ::core::ffi::c_int as uint32_t,
    0x5f16d052 as ::core::ffi::c_int as uint32_t,
    0xad7d5351 as ::core::ffi::c_uint,
];
#[no_mangle]
pub unsafe extern "C" fn csp_crc32_init(mut crc: *mut csp_crc32_t) {
    if !crc.is_null() {
        *crc = 0xffffffff as ::core::ffi::c_uint as csp_crc32_t;
    }
}
#[no_mangle]
pub unsafe extern "C" fn csp_crc32_update(
    mut crc: *mut csp_crc32_t,
    mut data: *const ::core::ffi::c_void,
    mut length: uint32_t,
) {
    let mut data8: *const uint8_t = data as *mut uint8_t;
    if !crc.is_null() {
        loop {
            let fresh0 = length;
            length = length.wrapping_sub(1);
            if !(fresh0 != 0) {
                break;
            }
            let fresh1 = data8;
            data8 = data8.offset(1);
            *crc = (crc_tab[((*crc ^ *fresh1 as csp_crc32_t) as ::core::ffi::c_long
                & 0xff as ::core::ffi::c_long) as usize]
                ^ *crc >> 8 as ::core::ffi::c_int) as csp_crc32_t;
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn csp_crc32_final(mut crc: *mut csp_crc32_t) -> uint32_t {
    if !crc.is_null() {
        return *crc ^ 0xffffffff as uint32_t;
    }
    return 0 as uint32_t;
}
#[no_mangle]
pub unsafe extern "C" fn csp_crc32_memory(
    mut data: *const ::core::ffi::c_void,
    mut length: uint32_t,
) -> uint32_t {
    let mut crc: csp_crc32_t = 0;
    csp_crc32_init(&raw mut crc);
    csp_crc32_update(&raw mut crc, data, length);
    return csp_crc32_final(&raw mut crc);
}
#[no_mangle]
pub unsafe extern "C" fn csp_crc32_append(
    mut packet: *mut csp_packet_t,
) -> ::core::ffi::c_int {
    let mut crc: uint32_t = 0;
    if ((*packet).length as usize)
        .wrapping_add(::core::mem::size_of::<uint32_t>() as usize)
        > ::core::mem::size_of::<[uint8_t; 256]>() as usize
    {
        return CSP_ERR_NOMEM;
    }
    crc = csp_crc32_memory(
        &raw mut (*packet).c2rust_unnamed.data as *mut uint8_t
            as *const ::core::ffi::c_void,
        (*packet).length as uint32_t,
    );
    crc = __bswap_32(crc as __uint32_t) as uint32_t;
    memcpy(
        (&raw mut (*packet).c2rust_unnamed.data as *mut uint8_t)
            .offset((*packet).length as isize) as *mut uint8_t
            as *mut ::core::ffi::c_void,
        &raw mut crc as *const ::core::ffi::c_void,
        ::core::mem::size_of::<uint32_t>() as size_t,
    );
    (*packet).length = ((*packet).length as ::core::ffi::c_ulong)
        .wrapping_add(
            ::core::mem::size_of::<uint32_t>() as usize as ::core::ffi::c_ulong,
        ) as uint16_t as uint16_t;
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_crc32_verify(
    mut packet: *mut csp_packet_t,
) -> ::core::ffi::c_int {
    let mut crc: uint32_t = 0;
    if ((*packet).length as usize) < ::core::mem::size_of::<uint32_t>() as usize {
        return CSP_ERR_CRC32;
    }
    csp_id_prepend(packet);
    crc = csp_crc32_memory(
        (*packet).frame_begin as *const ::core::ffi::c_void,
        ((*packet).frame_length as usize)
            .wrapping_sub(::core::mem::size_of::<uint32_t>() as usize) as uint32_t,
    );
    crc = __bswap_32(crc as __uint32_t) as uint32_t;
    if memcmp(
        ((&raw mut (*packet).c2rust_unnamed.data as *mut uint8_t)
            .offset((*packet).length as isize) as *mut uint8_t)
            .offset(-(::core::mem::size_of::<uint32_t>() as usize as isize))
            as *const ::core::ffi::c_void,
        &raw mut crc as *const ::core::ffi::c_void,
        ::core::mem::size_of::<uint32_t>() as size_t,
    ) != 0 as ::core::ffi::c_int
    {
        crc = csp_crc32_memory(
            &raw mut (*packet).c2rust_unnamed.data as *mut uint8_t
                as *const ::core::ffi::c_void,
            ((*packet).length as usize)
                .wrapping_sub(::core::mem::size_of::<uint32_t>() as usize) as uint32_t,
        );
        crc = __bswap_32(crc as __uint32_t) as uint32_t;
        if memcmp(
            ((&raw mut (*packet).c2rust_unnamed.data as *mut uint8_t)
                .offset((*packet).length as isize) as *mut uint8_t)
                .offset(-(::core::mem::size_of::<uint32_t>() as usize as isize))
                as *const ::core::ffi::c_void,
            &raw mut crc as *const ::core::ffi::c_void,
            ::core::mem::size_of::<uint32_t>() as size_t,
        ) != 0 as ::core::ffi::c_int
        {
            return CSP_ERR_CRC32;
        }
    }
    (*packet).length = ((*packet).length as ::core::ffi::c_ulong)
        .wrapping_sub(
            ::core::mem::size_of::<uint32_t>() as usize as ::core::ffi::c_ulong,
        ) as uint16_t as uint16_t;
    return CSP_ERR_NONE;
}
