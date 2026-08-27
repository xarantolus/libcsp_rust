// Builds the C libcsp and a thin shim so the differential tests can call both
// implementations on the same bytes.
//
// This crate is dev-only. Nothing here reaches csp-core or csp: the whole point of the
// port is that the shipped crates contain no C.
use std::path::PathBuf;

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let libcsp = root.join("libcsp");
    let autoconf = root.join("build/canonical/include");

    if !autoconf.join("csp/autoconfig.h").exists() {
        panic!(
            "configure libcsp first:\n  cmake -S libcsp -B build/canonical -G Ninja \\\n\
             -DCSP_USE_RDP=ON -DCSP_USE_HMAC=ON -DCSP_USE_PROMISC=ON -DCSP_USE_RTABLE=ON\n\
             (looked for {})",
            autoconf.join("csp/autoconfig.h").display()
        );
    }

    let mut b = cc::Build::new();
    b.include(libcsp.join("include"))
        .include(&autoconf)
        .include(libcsp.join("src"))
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wno-sign-compare")
        .flag_if_supported("-Wno-gnu-zero-variadic-macro-arguments");

    for f in [
        "src/csp_id.c",
        "src/csp_crc32.c",
        "src/crypto/csp_sha1.c",
        "src/crypto/csp_hmac.c",
        "src/csp_init.c",
        "src/csp_debug.c",
        // The route table and the interface list it names. csp_rtable_stdio.c is the
        // parser under test; the CIDR table is what it loads into.
        "src/csp_rtable_cidr.c",
        "src/csp_rtable_stdio.c",
        "src/csp_iflist.c",
        "src/interfaces/csp_if_kiss.c",
        "src/csp_buffer.c",
        // The whole portable node, so the harness can run a real C node against a real
        // Rust one instead of comparing codecs and hoping the layers above agree.
        "src/csp_io.c",
        "src/csp_conn.c",
        "src/csp_port.c",
        "src/csp_qfifo.c",
        "src/csp_route.c",
        "src/csp_promisc.c",
        "src/csp_dedup.c",
        // `csp_bridge_work` is a second forwarding path entirely: no routing table, no
        // split horizon, no address rewrite, and dedup applied unconditionally. It had
        // never been compiled in this project, so everything the port's `bridge_work` did
        // was a reading of it.
        "src/csp_bridge.c",
        "src/csp_services.c",
        "src/csp_service_handler.c",
        // Pulled in by `csp_service_handler`, which `shim_node_serve` calls so a real C
        // node can *answer* a request the port sent. Before that the handler was compiled
        // but never referenced, so these stayed dead-stripped.
        "src/cmp/csp_cmp_dispatch.c",
        "src/cmp/csp_cmp_ident.c",
        "src/cmp/csp_cmp_if_stats.c",
        "src/cmp/csp_cmp_route.c",
        "src/cmp/csp_cmp_mem.c",
        "src/cmp/csp_cmp_peek_poke.c",
        "src/cmp/csp_cmp_clock.c",
        // `arch/posix/csp_system.c` is deliberately absent, like `csp_time.c` below.
        // Its `csp_reboot_hook` is `sync(); reboot(LINUX_REBOOT_CMD_RESTART)` on Linux, so
        // a test that sent port 4 with the right magic word would reboot the machine
        // running it. `shim.c` supplies recording hooks instead -- which is also what makes
        // MEMFREE comparable at all, the real one being however much RAM the host has free
        // at that instant. `ctest/hooks.c` already did this; difftest had not.
        "src/arch/posix/csp_clock.c",
        "src/csp_sfp.c",
        "src/csp_rdp.c",
        "src/csp_rdp_queue.c",
        "src/csp_hex_dump.c",
        "src/interfaces/csp_if_lo.c",
        // The CAN interface, and the reassembly pool behind it. Neither was in this build
        // nor in `ctest`'s, so every comparison of CFP so far has been of the *identifier*
        // bit layout, with `shim.c` expanding the header's macros itself -- not one line of
        // `csp_if_can.c` ran. CAN is the flight bus, and its reassembly is the part that
        // has to survive a lost or reordered frame.
        // `csp_if_i2c.c` was in neither build, and the api_map claimed its three functions
        // were ported to the *generic* `Interface` methods. Two of the things it does are
        // not generic: the seven-bit bus address and the four-byte receive guard.
        "src/interfaces/csp_if_i2c.c",
        "src/interfaces/csp_if_can.c",
        "src/interfaces/csp_if_can_pbuf.c",
        // csp_buffer.c uses the OS queue shim.
        "src/arch/posix/csp_queue.c",
        "src/arch/posix/pthread_queue.c",
        "src/arch/posix/csp_semaphore.c",
        // `arch/posix/csp_time.c` is deliberately absent: `shim.c` supplies `csp_get_ms`
        // itself, so the C node's own timers -- RDP retransmission, connection expiry --
        // can be driven from a test instead of waiting on the wall clock. `ctest/` has done
        // this from the start; without it here, "does libcsp eventually free that?" was a
        // question the differential harness could not ask.
    ] {
        b.file(libcsp.join(f));
    }
    b.file("src/shim.c");
    b.compile("cshim");

    println!("cargo:rerun-if-changed=src/shim.c");
}
