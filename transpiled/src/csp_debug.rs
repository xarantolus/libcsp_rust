extern "C" {
    fn vprintf(
        __format: *const ::core::ffi::c_char,
        __arg: ::core::ffi::VaList,
    ) -> ::core::ffi::c_int;
}
pub type __builtin_va_list = [__va_list_tag; 1];
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __va_list_tag {
    pub gp_offset: ::core::ffi::c_uint,
    pub fp_offset: ::core::ffi::c_uint,
    pub overflow_arg_area: *mut ::core::ffi::c_void,
    pub reg_save_area: *mut ::core::ffi::c_void,
}
pub type __uint8_t = u8;
pub type uint8_t = __uint8_t;
pub type va_list = __builtin_va_list;
#[no_mangle]
pub static mut csp_dbg_buffer_out: uint8_t = 0;
#[no_mangle]
pub static mut csp_dbg_errno: uint8_t = 0;
#[no_mangle]
pub static mut csp_dbg_conn_out: uint8_t = 0;
#[no_mangle]
pub static mut csp_dbg_conn_ovf: uint8_t = 0;
#[no_mangle]
pub static mut csp_dbg_conn_noroute: uint8_t = 0;
#[no_mangle]
pub static mut csp_dbg_can_errno: uint8_t = 0;
#[no_mangle]
pub static mut csp_dbg_eth_errno: uint8_t = 0;
#[no_mangle]
pub static mut csp_dbg_inval_reply: uint8_t = 0;
#[no_mangle]
pub static mut csp_dbg_rdp_print: uint8_t = 0;
#[no_mangle]
pub static mut csp_dbg_packet_print: uint8_t = 0;
#[no_mangle]
pub unsafe extern "C" fn csp_print_func(
    mut fmt: *const ::core::ffi::c_char,
    mut args: ...
) {
    let mut args_0: ::core::ffi::VaListImpl;
    args_0 = args.clone();
    vprintf(fmt, args_0.as_va_list());
}
