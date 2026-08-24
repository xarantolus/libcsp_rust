extern "C" {
    fn csp_print_func(fmt: *const ::core::ffi::c_char, ...);
}
pub type __uint8_t = u8;
pub type uint8_t = __uint8_t;
pub const NULL: *mut ::core::ffi::c_void = ::core::ptr::null_mut::<
    ::core::ffi::c_void,
>();
unsafe extern "C" fn csp_hex_dump_format(
    mut desc: *const ::core::ffi::c_char,
    mut addr: *const ::core::ffi::c_void,
    mut len: ::core::ffi::c_int,
    mut format: ::core::ffi::c_int,
) {
    let mut i: ::core::ffi::c_int = 0;
    let mut buff: [::core::ffi::c_uchar; 17] = [0; 17];
    let mut pc: *mut ::core::ffi::c_uchar = addr as *mut ::core::ffi::c_uchar;
    if !desc.is_null() {
        csp_print_func(b"%s\n\0" as *const u8 as *const ::core::ffi::c_char, desc);
    }
    if !(len > 0 as ::core::ffi::c_int) {
        return;
    }
    i = 0 as ::core::ffi::c_int;
    while i < len {
        if i % 16 as ::core::ffi::c_int == 0 as ::core::ffi::c_int {
            if i != 0 as ::core::ffi::c_int {
                csp_print_func(
                    b"  %s\n\0" as *const u8 as *const ::core::ffi::c_char,
                    &raw mut buff as *mut ::core::ffi::c_uchar,
                );
            }
            if format & 0x1 as ::core::ffi::c_int != 0 {
                csp_print_func(
                    b"  %p \0" as *const u8 as *const ::core::ffi::c_char,
                    (addr as *mut uint8_t).offset(i as isize) as *mut ::core::ffi::c_void,
                );
            } else {
                csp_print_func(b"        \0" as *const u8 as *const ::core::ffi::c_char);
            }
        }
        csp_print_func(
            b" %02x\0" as *const u8 as *const ::core::ffi::c_char,
            *pc.offset(i as isize) as ::core::ffi::c_int,
        );
        if (*pc.offset(i as isize) as ::core::ffi::c_int) < 0x20 as ::core::ffi::c_int
            || *pc.offset(i as isize) as ::core::ffi::c_int > 0x7e as ::core::ffi::c_int
        {
            buff[(i % 16 as ::core::ffi::c_int) as usize] = '.' as i32
                as ::core::ffi::c_uchar;
        } else {
            buff[(i % 16 as ::core::ffi::c_int) as usize] = *pc.offset(i as isize);
        }
        buff[(i % 16 as ::core::ffi::c_int + 1 as ::core::ffi::c_int) as usize] = '\0'
            as i32 as ::core::ffi::c_uchar;
        i += 1;
    }
    while i % 16 as ::core::ffi::c_int != 0 as ::core::ffi::c_int {
        csp_print_func(b"   \0" as *const u8 as *const ::core::ffi::c_char);
        i += 1;
    }
    csp_print_func(
        b"  %s\n\0" as *const u8 as *const ::core::ffi::c_char,
        &raw mut buff as *mut ::core::ffi::c_uchar,
    );
}
#[no_mangle]
pub unsafe extern "C" fn csp_hex_dump(
    mut desc: *const ::core::ffi::c_char,
    mut addr: *const ::core::ffi::c_void,
    mut len: ::core::ffi::c_int,
) {
    csp_hex_dump_format(desc, addr, len, 0 as ::core::ffi::c_int);
}
