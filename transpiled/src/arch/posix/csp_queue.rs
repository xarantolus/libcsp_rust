extern "C" {
    fn pthread_queue_create(
        length: ::core::ffi::c_int,
        item_size: size_t,
    ) -> *mut pthread_queue_t;
    fn pthread_queue_enqueue(
        queue: *mut pthread_queue_t,
        value: *const ::core::ffi::c_void,
        timeout: uint32_t,
    ) -> ::core::ffi::c_int;
    fn pthread_queue_dequeue(
        queue: *mut pthread_queue_t,
        buf: *mut ::core::ffi::c_void,
        timeout: uint32_t,
    ) -> ::core::ffi::c_int;
    fn pthread_queue_items(queue: *mut pthread_queue_t) -> ::core::ffi::c_int;
    fn pthread_queue_free(queue: *mut pthread_queue_t) -> ::core::ffi::c_int;
    fn pthread_queue_empty(queue: *mut pthread_queue_t);
}
pub type __uint32_t = u32;
pub type uint32_t = __uint32_t;
pub type size_t = usize;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pthread_queue_s {
    pub buffer: *mut ::core::ffi::c_void,
    pub size: ::core::ffi::c_int,
    pub item_size: ::core::ffi::c_int,
    pub items: ::core::ffi::c_int,
    pub in_0: ::core::ffi::c_int,
    pub out: ::core::ffi::c_int,
    pub mutex: pthread_mutex_t,
    pub cond_full: pthread_cond_t,
    pub cond_empty: pthread_cond_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_cond_t {
    pub __data: __pthread_cond_s,
    pub __size: [::core::ffi::c_char; 48],
    pub __align: ::core::ffi::c_longlong,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __pthread_cond_s {
    pub __wseq: __atomic_wide_counter,
    pub __g1_start: __atomic_wide_counter,
    pub __g_refs: [::core::ffi::c_uint; 2],
    pub __g_size: [::core::ffi::c_uint; 2],
    pub __g1_orig_size: ::core::ffi::c_uint,
    pub __wrefs: ::core::ffi::c_uint,
    pub __g_signals: [::core::ffi::c_uint; 2],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union __atomic_wide_counter {
    pub __value64: ::core::ffi::c_ulonglong,
    pub __value32: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed {
    pub __low: ::core::ffi::c_uint,
    pub __high: ::core::ffi::c_uint,
}
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
pub type pthread_queue_t = pthread_queue_s;
pub type csp_queue_handle_t = *mut pthread_queue_t;
pub type csp_static_queue_t = *mut ::core::ffi::c_void;
pub const NULL: *mut ::core::ffi::c_void = ::core::ptr::null_mut::<
    ::core::ffi::c_void,
>();
#[no_mangle]
pub unsafe extern "C" fn csp_queue_create_static(
    mut length: ::core::ffi::c_int,
    mut item_size: size_t,
    mut buffer: *mut ::core::ffi::c_char,
    mut queue: *mut csp_static_queue_t,
) -> csp_queue_handle_t {
    return pthread_queue_create(length, item_size) as csp_queue_handle_t;
}
#[no_mangle]
pub unsafe extern "C" fn csp_queue_enqueue(
    mut handle: csp_queue_handle_t,
    mut value: *const ::core::ffi::c_void,
    mut timeout: uint32_t,
) -> ::core::ffi::c_int {
    return pthread_queue_enqueue(handle as *mut pthread_queue_t, value, timeout);
}
#[no_mangle]
pub unsafe extern "C" fn csp_queue_enqueue_isr(
    mut handle: csp_queue_handle_t,
    mut value: *const ::core::ffi::c_void,
    mut task_woken: *mut ::core::ffi::c_int,
) -> ::core::ffi::c_int {
    if !task_woken.is_null() {
        *task_woken = 0 as ::core::ffi::c_int;
    }
    return csp_queue_enqueue(handle, value, 0 as uint32_t);
}
#[no_mangle]
pub unsafe extern "C" fn csp_queue_dequeue(
    mut handle: csp_queue_handle_t,
    mut buf: *mut ::core::ffi::c_void,
    mut timeout: uint32_t,
) -> ::core::ffi::c_int {
    return pthread_queue_dequeue(handle as *mut pthread_queue_t, buf, timeout);
}
#[no_mangle]
pub unsafe extern "C" fn csp_queue_dequeue_isr(
    mut handle: csp_queue_handle_t,
    mut buf: *mut ::core::ffi::c_void,
    mut task_woken: *mut ::core::ffi::c_int,
) -> ::core::ffi::c_int {
    if !task_woken.is_null() {
        *task_woken = 0 as ::core::ffi::c_int;
    }
    return csp_queue_dequeue(handle, buf, 0 as uint32_t);
}
#[no_mangle]
pub unsafe extern "C" fn csp_queue_size(
    mut handle: csp_queue_handle_t,
) -> ::core::ffi::c_int {
    return pthread_queue_items(handle as *mut pthread_queue_t);
}
#[no_mangle]
pub unsafe extern "C" fn csp_queue_size_isr(
    mut handle: csp_queue_handle_t,
) -> ::core::ffi::c_int {
    return pthread_queue_items(handle as *mut pthread_queue_t);
}
#[no_mangle]
pub unsafe extern "C" fn csp_queue_free(
    mut handle: csp_queue_handle_t,
) -> ::core::ffi::c_int {
    return pthread_queue_free(handle as *mut pthread_queue_t);
}
#[no_mangle]
pub unsafe extern "C" fn csp_queue_empty(mut handle: csp_queue_handle_t) {
    pthread_queue_empty(handle as *mut pthread_queue_t);
}
