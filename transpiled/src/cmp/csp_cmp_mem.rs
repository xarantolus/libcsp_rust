extern "C" {
    fn memcpy(
        __dest: *mut ::core::ffi::c_void,
        __src: *const ::core::ffi::c_void,
        __n: size_t,
    ) -> *mut ::core::ffi::c_void;
}
pub type __uint64_t = u64;
pub type uint64_t = __uint64_t;
pub type size_t = usize;
pub type csp_memptr_t = *mut ::core::ffi::c_void;
pub type csp_const_memptr_t = *const ::core::ffi::c_void;
pub type csp_memptr64_t = uint64_t;
pub type csp_memcpy_fnc_t = Option<
    unsafe extern "C" fn(csp_memptr_t, csp_const_memptr_t, size_t) -> csp_memptr_t,
>;
pub type csp_memread64_fnc_t = Option<
    unsafe extern "C" fn(csp_const_memptr_t, csp_memptr64_t, size_t) -> csp_memptr64_t,
>;
pub type csp_memwrite64_fnc_t = Option<
    unsafe extern "C" fn(csp_memptr64_t, csp_memptr_t, size_t) -> csp_memptr64_t,
>;
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_ERR_DRIVER: ::core::ffi::c_int = -(11 as ::core::ffi::c_int);
#[no_mangle]
pub unsafe extern "C" fn csp_cmp_memcpy(
    mut to: csp_memptr_t,
    mut from: csp_const_memptr_t,
    mut size: size_t,
) -> ::core::ffi::c_int {
    memcpy(to as *mut ::core::ffi::c_void, from as *const ::core::ffi::c_void, size);
    return CSP_ERR_NONE;
}
#[no_mangle]
pub unsafe extern "C" fn csp_cmp_memread64(
    mut to: csp_const_memptr_t,
    mut from: csp_memptr64_t,
    mut size: size_t,
) -> ::core::ffi::c_int {
    return CSP_ERR_DRIVER;
}
#[no_mangle]
pub unsafe extern "C" fn csp_cmp_memwrite64(
    mut to: csp_memptr64_t,
    mut from: csp_memptr_t,
    mut size: size_t,
) -> ::core::ffi::c_int {
    return CSP_ERR_DRIVER;
}
#[no_mangle]
pub unsafe extern "C" fn csp_cmp_set_memcpy(mut fnc: csp_memcpy_fnc_t) {}
#[no_mangle]
pub unsafe extern "C" fn csp_cmp_set_memread64(mut fnc: csp_memread64_fnc_t) {}
#[no_mangle]
pub unsafe extern "C" fn csp_cmp_set_memwrite64(mut fnc: csp_memwrite64_fnc_t) {}
