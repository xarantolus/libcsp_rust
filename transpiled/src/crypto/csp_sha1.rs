extern "C" {
    fn memcpy(
        __dest: *mut ::core::ffi::c_void,
        __src: *const ::core::ffi::c_void,
        __n: size_t,
    ) -> *mut ::core::ffi::c_void;
}
pub type __uint8_t = u8;
pub type __uint32_t = u32;
pub type __uint64_t = u64;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type size_t = usize;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct csp_sha1_state_t {
    pub length: uint64_t,
    pub state: [uint32_t; 5],
    pub curlen: uint32_t,
    pub buf: [uint8_t; 64],
}
pub const CSP_SHA1_BLOCKSIZE: ::core::ffi::c_int = 64 as ::core::ffi::c_int;
unsafe extern "C" fn csp_sha1_compress(
    mut sha1: *mut csp_sha1_state_t,
    mut buf: *const uint8_t,
) {
    let mut a: uint32_t = 0;
    let mut b: uint32_t = 0;
    let mut c: uint32_t = 0;
    let mut d: uint32_t = 0;
    let mut e: uint32_t = 0;
    let mut W: [uint32_t; 80] = [0; 80];
    let mut i: uint32_t = 0;
    i = 0 as uint32_t;
    while i < 16 as uint32_t {
        W[i as usize] = ((*buf
            .offset((4 as uint32_t).wrapping_mul(i) as isize)
            .offset(0 as ::core::ffi::c_int as isize) as ::core::ffi::c_int
            & 0xff as ::core::ffi::c_int) as uint32_t) << 24 as ::core::ffi::c_int
            | ((*buf
                .offset((4 as uint32_t).wrapping_mul(i) as isize)
                .offset(1 as ::core::ffi::c_int as isize) as ::core::ffi::c_int
                & 0xff as ::core::ffi::c_int) as uint32_t) << 16 as ::core::ffi::c_int
            | ((*buf
                .offset((4 as uint32_t).wrapping_mul(i) as isize)
                .offset(2 as ::core::ffi::c_int as isize) as ::core::ffi::c_int
                & 0xff as ::core::ffi::c_int) as uint32_t) << 8 as ::core::ffi::c_int
            | ((*buf
                .offset((4 as uint32_t).wrapping_mul(i) as isize)
                .offset(3 as ::core::ffi::c_int as isize) as ::core::ffi::c_int
                & 0xff as ::core::ffi::c_int) as uint32_t) << 0 as ::core::ffi::c_int;
        i = i.wrapping_add(1);
    }
    a = (*sha1).state[0 as ::core::ffi::c_int as usize];
    b = (*sha1).state[1 as ::core::ffi::c_int as usize];
    c = (*sha1).state[2 as ::core::ffi::c_int as usize];
    d = (*sha1).state[3 as ::core::ffi::c_int as usize];
    e = (*sha1).state[4 as ::core::ffi::c_int as usize];
    i = 16 as uint32_t;
    while i < 80 as uint32_t {
        W[i as usize] = (W[i.wrapping_sub(3 as uint32_t) as usize]
            ^ W[i.wrapping_sub(8 as uint32_t) as usize]
            ^ W[i.wrapping_sub(14 as uint32_t) as usize]
            ^ W[i.wrapping_sub(16 as uint32_t) as usize]) << 1 as ::core::ffi::c_int
            | (W[i.wrapping_sub(3 as uint32_t) as usize]
                ^ W[i.wrapping_sub(8 as uint32_t) as usize]
                ^ W[i.wrapping_sub(14 as uint32_t) as usize]
                ^ W[i.wrapping_sub(16 as uint32_t) as usize])
                >> 32 as ::core::ffi::c_int - 1 as ::core::ffi::c_int;
        i = i.wrapping_add(1);
    }
    i = 0 as uint32_t;
    while i < 20 as uint32_t {
        let fresh0 = i;
        i = i.wrapping_add(1);
        e = ((a << 5 as ::core::ffi::c_int
            | a >> 32 as ::core::ffi::c_int - 5 as ::core::ffi::c_int)
            .wrapping_add(d ^ b & (c ^ d))
            .wrapping_add(e)
            .wrapping_add(W[fresh0 as usize]) as ::core::ffi::c_ulong)
            .wrapping_add(0x5a827999 as ::core::ffi::c_ulong) as uint32_t;
        b = b << 30 as ::core::ffi::c_int
            | b >> 32 as ::core::ffi::c_int - 30 as ::core::ffi::c_int;
        let fresh1 = i;
        i = i.wrapping_add(1);
        d = ((e << 5 as ::core::ffi::c_int
            | e >> 32 as ::core::ffi::c_int - 5 as ::core::ffi::c_int)
            .wrapping_add(c ^ a & (b ^ c))
            .wrapping_add(d)
            .wrapping_add(W[fresh1 as usize]) as ::core::ffi::c_ulong)
            .wrapping_add(0x5a827999 as ::core::ffi::c_ulong) as uint32_t;
        a = a << 30 as ::core::ffi::c_int
            | a >> 32 as ::core::ffi::c_int - 30 as ::core::ffi::c_int;
        let fresh2 = i;
        i = i.wrapping_add(1);
        c = ((d << 5 as ::core::ffi::c_int
            | d >> 32 as ::core::ffi::c_int - 5 as ::core::ffi::c_int)
            .wrapping_add(b ^ e & (a ^ b))
            .wrapping_add(c)
            .wrapping_add(W[fresh2 as usize]) as ::core::ffi::c_ulong)
            .wrapping_add(0x5a827999 as ::core::ffi::c_ulong) as uint32_t;
        e = e << 30 as ::core::ffi::c_int
            | e >> 32 as ::core::ffi::c_int - 30 as ::core::ffi::c_int;
        let fresh3 = i;
        i = i.wrapping_add(1);
        b = ((c << 5 as ::core::ffi::c_int
            | c >> 32 as ::core::ffi::c_int - 5 as ::core::ffi::c_int)
            .wrapping_add(a ^ d & (e ^ a))
            .wrapping_add(b)
            .wrapping_add(W[fresh3 as usize]) as ::core::ffi::c_ulong)
            .wrapping_add(0x5a827999 as ::core::ffi::c_ulong) as uint32_t;
        d = d << 30 as ::core::ffi::c_int
            | d >> 32 as ::core::ffi::c_int - 30 as ::core::ffi::c_int;
        let fresh4 = i;
        i = i.wrapping_add(1);
        a = ((b << 5 as ::core::ffi::c_int
            | b >> 32 as ::core::ffi::c_int - 5 as ::core::ffi::c_int)
            .wrapping_add(e ^ c & (d ^ e))
            .wrapping_add(a)
            .wrapping_add(W[fresh4 as usize]) as ::core::ffi::c_ulong)
            .wrapping_add(0x5a827999 as ::core::ffi::c_ulong) as uint32_t;
        c = c << 30 as ::core::ffi::c_int
            | c >> 32 as ::core::ffi::c_int - 30 as ::core::ffi::c_int;
    }
    while i < 40 as uint32_t {
        let fresh5 = i;
        i = i.wrapping_add(1);
        e = ((a << 5 as ::core::ffi::c_int
            | a >> 32 as ::core::ffi::c_int - 5 as ::core::ffi::c_int)
            .wrapping_add(b ^ c ^ d)
            .wrapping_add(e)
            .wrapping_add(W[fresh5 as usize]) as ::core::ffi::c_ulong)
            .wrapping_add(0x6ed9eba1 as ::core::ffi::c_ulong) as uint32_t;
        b = b << 30 as ::core::ffi::c_int
            | b >> 32 as ::core::ffi::c_int - 30 as ::core::ffi::c_int;
        let fresh6 = i;
        i = i.wrapping_add(1);
        d = ((e << 5 as ::core::ffi::c_int
            | e >> 32 as ::core::ffi::c_int - 5 as ::core::ffi::c_int)
            .wrapping_add(a ^ b ^ c)
            .wrapping_add(d)
            .wrapping_add(W[fresh6 as usize]) as ::core::ffi::c_ulong)
            .wrapping_add(0x6ed9eba1 as ::core::ffi::c_ulong) as uint32_t;
        a = a << 30 as ::core::ffi::c_int
            | a >> 32 as ::core::ffi::c_int - 30 as ::core::ffi::c_int;
        let fresh7 = i;
        i = i.wrapping_add(1);
        c = ((d << 5 as ::core::ffi::c_int
            | d >> 32 as ::core::ffi::c_int - 5 as ::core::ffi::c_int)
            .wrapping_add(e ^ a ^ b)
            .wrapping_add(c)
            .wrapping_add(W[fresh7 as usize]) as ::core::ffi::c_ulong)
            .wrapping_add(0x6ed9eba1 as ::core::ffi::c_ulong) as uint32_t;
        e = e << 30 as ::core::ffi::c_int
            | e >> 32 as ::core::ffi::c_int - 30 as ::core::ffi::c_int;
        let fresh8 = i;
        i = i.wrapping_add(1);
        b = ((c << 5 as ::core::ffi::c_int
            | c >> 32 as ::core::ffi::c_int - 5 as ::core::ffi::c_int)
            .wrapping_add(d ^ e ^ a)
            .wrapping_add(b)
            .wrapping_add(W[fresh8 as usize]) as ::core::ffi::c_ulong)
            .wrapping_add(0x6ed9eba1 as ::core::ffi::c_ulong) as uint32_t;
        d = d << 30 as ::core::ffi::c_int
            | d >> 32 as ::core::ffi::c_int - 30 as ::core::ffi::c_int;
        let fresh9 = i;
        i = i.wrapping_add(1);
        a = ((b << 5 as ::core::ffi::c_int
            | b >> 32 as ::core::ffi::c_int - 5 as ::core::ffi::c_int)
            .wrapping_add(c ^ d ^ e)
            .wrapping_add(a)
            .wrapping_add(W[fresh9 as usize]) as ::core::ffi::c_ulong)
            .wrapping_add(0x6ed9eba1 as ::core::ffi::c_ulong) as uint32_t;
        c = c << 30 as ::core::ffi::c_int
            | c >> 32 as ::core::ffi::c_int - 30 as ::core::ffi::c_int;
    }
    while i < 60 as uint32_t {
        let fresh10 = i;
        i = i.wrapping_add(1);
        e = ((a << 5 as ::core::ffi::c_int
            | a >> 32 as ::core::ffi::c_int - 5 as ::core::ffi::c_int)
            .wrapping_add(b & c | d & (b | c))
            .wrapping_add(e)
            .wrapping_add(W[fresh10 as usize]) as ::core::ffi::c_ulong)
            .wrapping_add(0x8f1bbcdc as ::core::ffi::c_ulong) as uint32_t;
        b = b << 30 as ::core::ffi::c_int
            | b >> 32 as ::core::ffi::c_int - 30 as ::core::ffi::c_int;
        let fresh11 = i;
        i = i.wrapping_add(1);
        d = ((e << 5 as ::core::ffi::c_int
            | e >> 32 as ::core::ffi::c_int - 5 as ::core::ffi::c_int)
            .wrapping_add(a & b | c & (a | b))
            .wrapping_add(d)
            .wrapping_add(W[fresh11 as usize]) as ::core::ffi::c_ulong)
            .wrapping_add(0x8f1bbcdc as ::core::ffi::c_ulong) as uint32_t;
        a = a << 30 as ::core::ffi::c_int
            | a >> 32 as ::core::ffi::c_int - 30 as ::core::ffi::c_int;
        let fresh12 = i;
        i = i.wrapping_add(1);
        c = ((d << 5 as ::core::ffi::c_int
            | d >> 32 as ::core::ffi::c_int - 5 as ::core::ffi::c_int)
            .wrapping_add(e & a | b & (e | a))
            .wrapping_add(c)
            .wrapping_add(W[fresh12 as usize]) as ::core::ffi::c_ulong)
            .wrapping_add(0x8f1bbcdc as ::core::ffi::c_ulong) as uint32_t;
        e = e << 30 as ::core::ffi::c_int
            | e >> 32 as ::core::ffi::c_int - 30 as ::core::ffi::c_int;
        let fresh13 = i;
        i = i.wrapping_add(1);
        b = ((c << 5 as ::core::ffi::c_int
            | c >> 32 as ::core::ffi::c_int - 5 as ::core::ffi::c_int)
            .wrapping_add(d & e | a & (d | e))
            .wrapping_add(b)
            .wrapping_add(W[fresh13 as usize]) as ::core::ffi::c_ulong)
            .wrapping_add(0x8f1bbcdc as ::core::ffi::c_ulong) as uint32_t;
        d = d << 30 as ::core::ffi::c_int
            | d >> 32 as ::core::ffi::c_int - 30 as ::core::ffi::c_int;
        let fresh14 = i;
        i = i.wrapping_add(1);
        a = ((b << 5 as ::core::ffi::c_int
            | b >> 32 as ::core::ffi::c_int - 5 as ::core::ffi::c_int)
            .wrapping_add(c & d | e & (c | d))
            .wrapping_add(a)
            .wrapping_add(W[fresh14 as usize]) as ::core::ffi::c_ulong)
            .wrapping_add(0x8f1bbcdc as ::core::ffi::c_ulong) as uint32_t;
        c = c << 30 as ::core::ffi::c_int
            | c >> 32 as ::core::ffi::c_int - 30 as ::core::ffi::c_int;
    }
    while i < 80 as uint32_t {
        let fresh15 = i;
        i = i.wrapping_add(1);
        e = ((a << 5 as ::core::ffi::c_int
            | a >> 32 as ::core::ffi::c_int - 5 as ::core::ffi::c_int)
            .wrapping_add(b ^ c ^ d)
            .wrapping_add(e)
            .wrapping_add(W[fresh15 as usize]) as ::core::ffi::c_ulong)
            .wrapping_add(0xca62c1d6 as ::core::ffi::c_ulong) as uint32_t;
        b = b << 30 as ::core::ffi::c_int
            | b >> 32 as ::core::ffi::c_int - 30 as ::core::ffi::c_int;
        let fresh16 = i;
        i = i.wrapping_add(1);
        d = ((e << 5 as ::core::ffi::c_int
            | e >> 32 as ::core::ffi::c_int - 5 as ::core::ffi::c_int)
            .wrapping_add(a ^ b ^ c)
            .wrapping_add(d)
            .wrapping_add(W[fresh16 as usize]) as ::core::ffi::c_ulong)
            .wrapping_add(0xca62c1d6 as ::core::ffi::c_ulong) as uint32_t;
        a = a << 30 as ::core::ffi::c_int
            | a >> 32 as ::core::ffi::c_int - 30 as ::core::ffi::c_int;
        let fresh17 = i;
        i = i.wrapping_add(1);
        c = ((d << 5 as ::core::ffi::c_int
            | d >> 32 as ::core::ffi::c_int - 5 as ::core::ffi::c_int)
            .wrapping_add(e ^ a ^ b)
            .wrapping_add(c)
            .wrapping_add(W[fresh17 as usize]) as ::core::ffi::c_ulong)
            .wrapping_add(0xca62c1d6 as ::core::ffi::c_ulong) as uint32_t;
        e = e << 30 as ::core::ffi::c_int
            | e >> 32 as ::core::ffi::c_int - 30 as ::core::ffi::c_int;
        let fresh18 = i;
        i = i.wrapping_add(1);
        b = ((c << 5 as ::core::ffi::c_int
            | c >> 32 as ::core::ffi::c_int - 5 as ::core::ffi::c_int)
            .wrapping_add(d ^ e ^ a)
            .wrapping_add(b)
            .wrapping_add(W[fresh18 as usize]) as ::core::ffi::c_ulong)
            .wrapping_add(0xca62c1d6 as ::core::ffi::c_ulong) as uint32_t;
        d = d << 30 as ::core::ffi::c_int
            | d >> 32 as ::core::ffi::c_int - 30 as ::core::ffi::c_int;
        let fresh19 = i;
        i = i.wrapping_add(1);
        a = ((b << 5 as ::core::ffi::c_int
            | b >> 32 as ::core::ffi::c_int - 5 as ::core::ffi::c_int)
            .wrapping_add(c ^ d ^ e)
            .wrapping_add(a)
            .wrapping_add(W[fresh19 as usize]) as ::core::ffi::c_ulong)
            .wrapping_add(0xca62c1d6 as ::core::ffi::c_ulong) as uint32_t;
        c = c << 30 as ::core::ffi::c_int
            | c >> 32 as ::core::ffi::c_int - 30 as ::core::ffi::c_int;
    }
    (*sha1).state[0 as ::core::ffi::c_int as usize] = (*sha1)
        .state[0 as ::core::ffi::c_int as usize]
        .wrapping_add(a);
    (*sha1).state[1 as ::core::ffi::c_int as usize] = (*sha1)
        .state[1 as ::core::ffi::c_int as usize]
        .wrapping_add(b);
    (*sha1).state[2 as ::core::ffi::c_int as usize] = (*sha1)
        .state[2 as ::core::ffi::c_int as usize]
        .wrapping_add(c);
    (*sha1).state[3 as ::core::ffi::c_int as usize] = (*sha1)
        .state[3 as ::core::ffi::c_int as usize]
        .wrapping_add(d);
    (*sha1).state[4 as ::core::ffi::c_int as usize] = (*sha1)
        .state[4 as ::core::ffi::c_int as usize]
        .wrapping_add(e);
}
#[no_mangle]
pub unsafe extern "C" fn csp_sha1_init(mut sha1: *mut csp_sha1_state_t) {
    (*sha1).state[0 as ::core::ffi::c_int as usize] = 0x67452301 as uint32_t;
    (*sha1).state[1 as ::core::ffi::c_int as usize] = 0xefcdab89 as uint32_t;
    (*sha1).state[2 as ::core::ffi::c_int as usize] = 0x98badcfe as uint32_t;
    (*sha1).state[3 as ::core::ffi::c_int as usize] = 0x10325476 as uint32_t;
    (*sha1).state[4 as ::core::ffi::c_int as usize] = 0xc3d2e1f0 as uint32_t;
    (*sha1).curlen = 0 as uint32_t;
    (*sha1).length = 0 as uint64_t;
}
#[no_mangle]
pub unsafe extern "C" fn csp_sha1_process(
    mut sha1: *mut csp_sha1_state_t,
    mut data: *const ::core::ffi::c_void,
    mut inlen: uint32_t,
) {
    let mut in_0: *const uint8_t = data as *const uint8_t;
    let mut n: uint32_t = 0;
    while inlen > 0 as uint32_t {
        if (*sha1).curlen == 0 as uint32_t && inlen >= CSP_SHA1_BLOCKSIZE as uint32_t {
            csp_sha1_compress(sha1, in_0);
            (*sha1).length = (*sha1)
                .length
                .wrapping_add(
                    (CSP_SHA1_BLOCKSIZE * 8 as ::core::ffi::c_int) as uint64_t,
                );
            in_0 = in_0.offset(CSP_SHA1_BLOCKSIZE as isize);
            inlen = inlen.wrapping_sub(CSP_SHA1_BLOCKSIZE as uint32_t);
        } else {
            n = if inlen < (64 as uint32_t).wrapping_sub((*sha1).curlen) {
                inlen
            } else {
                (64 as uint32_t).wrapping_sub((*sha1).curlen)
            };
            memcpy(
                (&raw mut (*sha1).buf as *mut uint8_t).offset((*sha1).curlen as isize)
                    as *mut ::core::ffi::c_void,
                in_0 as *const ::core::ffi::c_void,
                n as size_t,
            );
            (*sha1).curlen = (*sha1).curlen.wrapping_add(n);
            in_0 = in_0.offset(n as isize);
            inlen = inlen.wrapping_sub(n);
            if (*sha1).curlen == CSP_SHA1_BLOCKSIZE as uint32_t {
                csp_sha1_compress(sha1, &raw mut (*sha1).buf as *mut uint8_t);
                (*sha1).length = (*sha1)
                    .length
                    .wrapping_add(
                        (CSP_SHA1_BLOCKSIZE * 8 as ::core::ffi::c_int) as uint64_t,
                    );
                (*sha1).curlen = 0 as uint32_t;
            }
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn csp_sha1_done(
    mut sha1: *mut csp_sha1_state_t,
    mut out: *mut uint8_t,
) {
    let mut i: uint32_t = 0;
    (*sha1).length = (*sha1)
        .length
        .wrapping_add((*sha1).curlen.wrapping_mul(8 as uint32_t) as uint64_t);
    let fresh20 = (*sha1).curlen;
    (*sha1).curlen = (*sha1).curlen.wrapping_add(1);
    (*sha1).buf[fresh20 as usize] = 0x80 as uint8_t;
    if (*sha1).curlen > 56 as uint32_t {
        while (*sha1).curlen < 64 as uint32_t {
            let fresh21 = (*sha1).curlen;
            (*sha1).curlen = (*sha1).curlen.wrapping_add(1);
            (*sha1).buf[fresh21 as usize] = 0 as uint8_t;
        }
        csp_sha1_compress(sha1, &raw mut (*sha1).buf as *mut uint8_t);
        (*sha1).curlen = 0 as uint32_t;
    }
    while (*sha1).curlen < 56 as uint32_t {
        let fresh22 = (*sha1).curlen;
        (*sha1).curlen = (*sha1).curlen.wrapping_add(1);
        (*sha1).buf[fresh22 as usize] = 0 as uint8_t;
    }
    *(&raw mut (*sha1).buf as *mut uint8_t)
        .offset(56 as ::core::ffi::c_int as isize)
        .offset(0 as ::core::ffi::c_int as isize) = ((*sha1).length
        >> 56 as ::core::ffi::c_int & 0xff as uint64_t) as uint8_t;
    *(&raw mut (*sha1).buf as *mut uint8_t)
        .offset(56 as ::core::ffi::c_int as isize)
        .offset(1 as ::core::ffi::c_int as isize) = ((*sha1).length
        >> 48 as ::core::ffi::c_int & 0xff as uint64_t) as uint8_t;
    *(&raw mut (*sha1).buf as *mut uint8_t)
        .offset(56 as ::core::ffi::c_int as isize)
        .offset(2 as ::core::ffi::c_int as isize) = ((*sha1).length
        >> 40 as ::core::ffi::c_int & 0xff as uint64_t) as uint8_t;
    *(&raw mut (*sha1).buf as *mut uint8_t)
        .offset(56 as ::core::ffi::c_int as isize)
        .offset(3 as ::core::ffi::c_int as isize) = ((*sha1).length
        >> 32 as ::core::ffi::c_int & 0xff as uint64_t) as uint8_t;
    *(&raw mut (*sha1).buf as *mut uint8_t)
        .offset(56 as ::core::ffi::c_int as isize)
        .offset(4 as ::core::ffi::c_int as isize) = ((*sha1).length
        >> 24 as ::core::ffi::c_int & 0xff as uint64_t) as uint8_t;
    *(&raw mut (*sha1).buf as *mut uint8_t)
        .offset(56 as ::core::ffi::c_int as isize)
        .offset(5 as ::core::ffi::c_int as isize) = ((*sha1).length
        >> 16 as ::core::ffi::c_int & 0xff as uint64_t) as uint8_t;
    *(&raw mut (*sha1).buf as *mut uint8_t)
        .offset(56 as ::core::ffi::c_int as isize)
        .offset(6 as ::core::ffi::c_int as isize) = ((*sha1).length
        >> 8 as ::core::ffi::c_int & 0xff as uint64_t) as uint8_t;
    *(&raw mut (*sha1).buf as *mut uint8_t)
        .offset(56 as ::core::ffi::c_int as isize)
        .offset(7 as ::core::ffi::c_int as isize) = ((*sha1).length
        >> 0 as ::core::ffi::c_int & 0xff as uint64_t) as uint8_t;
    csp_sha1_compress(sha1, &raw mut (*sha1).buf as *mut uint8_t);
    i = 0 as uint32_t;
    while i < 5 as uint32_t {
        *out
            .offset((4 as uint32_t).wrapping_mul(i) as isize)
            .offset(0 as ::core::ffi::c_int as isize) = ((*sha1).state[i as usize]
            >> 24 as ::core::ffi::c_int & 0xff as uint32_t) as uint8_t;
        *out
            .offset((4 as uint32_t).wrapping_mul(i) as isize)
            .offset(1 as ::core::ffi::c_int as isize) = ((*sha1).state[i as usize]
            >> 16 as ::core::ffi::c_int & 0xff as uint32_t) as uint8_t;
        *out
            .offset((4 as uint32_t).wrapping_mul(i) as isize)
            .offset(2 as ::core::ffi::c_int as isize) = ((*sha1).state[i as usize]
            >> 8 as ::core::ffi::c_int & 0xff as uint32_t) as uint8_t;
        *out
            .offset((4 as uint32_t).wrapping_mul(i) as isize)
            .offset(3 as ::core::ffi::c_int as isize) = ((*sha1).state[i as usize]
            >> 0 as ::core::ffi::c_int & 0xff as uint32_t) as uint8_t;
        i = i.wrapping_add(1);
    }
}
#[no_mangle]
pub unsafe extern "C" fn csp_sha1_memory(
    mut msg: *const ::core::ffi::c_void,
    mut len: uint32_t,
    mut hash: *mut uint8_t,
) {
    let mut md: csp_sha1_state_t = csp_sha1_state_t {
        length: 0,
        state: [0; 5],
        curlen: 0,
        buf: [0; 64],
    };
    csp_sha1_init(&raw mut md);
    csp_sha1_process(&raw mut md, msg, len);
    csp_sha1_done(&raw mut md, hash);
}
