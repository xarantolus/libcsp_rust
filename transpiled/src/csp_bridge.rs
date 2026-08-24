extern "C" {
    pub type csp_conn_s;
    static mut csp_dbg_packet_print: uint8_t;
    fn csp_print_func(fmt: *const ::core::ffi::c_char, ...);
    fn csp_buffer_free(buffer: *mut ::core::ffi::c_void);
    fn csp_qfifo_read(input: *mut csp_qfifo_t) -> ::core::ffi::c_int;
    fn csp_send_direct_iface(
        idout: *const csp_id_t,
        packet: *mut csp_packet_t,
        iface: *mut csp_iface_t,
        via: uint16_t,
        from_me: ::core::ffi::c_int,
    );
    fn csp_promisc_add(packet: *mut csp_packet_t);
    fn csp_dedup_is_duplicate(packet: *mut csp_packet_t) -> bool;
    fn csp_get_ms() -> uint32_t;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct csp_qfifo_t {
    pub iface: *mut csp_iface_t,
    pub packet: *mut csp_packet_t,
}
pub const NULL: *mut ::core::ffi::c_void = ::core::ptr::null_mut::<
    ::core::ffi::c_void,
>();
pub const CSP_ERR_NONE: ::core::ffi::c_int = 0 as ::core::ffi::c_int;
pub const CSP_NO_VIA_ADDRESS: ::core::ffi::c_int = 0xffff as ::core::ffi::c_int;
static mut bif_a: *mut csp_iface_t = ::core::ptr::null::<csp_iface_t>()
    as *mut csp_iface_t;
static mut bif_b: *mut csp_iface_t = ::core::ptr::null::<csp_iface_t>()
    as *mut csp_iface_t;
#[no_mangle]
pub unsafe extern "C" fn csp_bridge_set_interfaces(
    mut if_a: *mut csp_iface_t,
    mut if_b: *mut csp_iface_t,
) {
    bif_a = if_a;
    bif_b = if_b;
}
/* PATCHED BY HAND -- duplicate weak symbol.
 *
 *   error: symbol `csp_input_hook` is already defined
 *
 * The C defines csp_input_hook __weak TWICE in one library, byte-identically:
 * csp_route.c:106 and csp_bridge.c:19. C linkers silently pick one, so which
 * implementation runs is link-order dependent and nobody notices. Rust has no weak
 * symbols, so c2rust emitted both as #[no_mangle] and the build fails outright.
 *
 * The latent C defect became a hard compile error. Definition removed here; the
 * csp_route.c one is kept. See SCOPE.md deviation 2.
 */
#[no_mangle]
pub unsafe extern "C" fn csp_bridge_work() {
    if bif_a.is_null() || bif_b.is_null() {
        csp_print_func(
            b"Bridge interfaces are not setup yet. Make sure to call csp_bridge_set_interfaces()\n\0"
                as *const u8 as *const ::core::ffi::c_char,
        );
        return;
    }
    let mut input: csp_qfifo_t = csp_qfifo_t {
        iface: ::core::ptr::null_mut::<csp_iface_t>(),
        packet: ::core::ptr::null_mut::<csp_packet_t>(),
    };
    if csp_qfifo_read(&raw mut input) != CSP_ERR_NONE {
        return;
    }
    let mut packet: *mut csp_packet_t = input.packet;
    if packet.is_null() {
        csp_print_func(
            b"Packet of router queue item is NULL\n\0" as *const u8
                as *const ::core::ffi::c_char,
        );
        return;
    }
    if csp_dedup_is_duplicate(packet) {
        csp_print_func(
            b"Retrieved packet is a duplicate\n\0" as *const u8
                as *const ::core::ffi::c_char,
        );
        csp_buffer_free(packet as *mut ::core::ffi::c_void);
        return;
    }
    /* c2rust re-declares every C type per module, so csp_bridge::csp_iface_s and
     * csp_route::csp_iface_s are distinct Rust types for the same C struct.
     * Cast through raw pointers. --reorganize-definitions would dedupe these but
     * needs c2rust-refactor on the pinned 2023 nightly. */
    crate::src::csp_route::csp_input_hook(
        input.iface as *mut _,
        packet as *mut _,
    );
    csp_promisc_add(packet);
    let mut destif: *mut csp_iface_t = ::core::ptr::null_mut::<csp_iface_t>();
    if input.iface == bif_a {
        destif = bif_b;
    } else {
        destif = bif_a;
    }
    csp_send_direct_iface(
        &raw mut (*packet).id,
        packet,
        destif,
        CSP_NO_VIA_ADDRESS as uint16_t,
        0 as ::core::ffi::c_int,
    );
}
