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
        // KISS framing. csp_kiss_rx pushes into the qfifo, which the shim overrides to
        // capture the frame, so only the buffer pool comes with it.
        "src/interfaces/csp_if_kiss.c",
        "src/csp_buffer.c",
        // csp_buffer.c uses the OS queue shim.
        "src/arch/posix/csp_queue.c",
        "src/arch/posix/pthread_queue.c",
        "src/arch/posix/csp_semaphore.c",
        "src/arch/posix/csp_time.c",
    ] {
        b.file(libcsp.join(f));
    }
    b.file("src/shim.c");
    b.compile("cshim");

    println!("cargo:rerun-if-changed=src/shim.c");
}
