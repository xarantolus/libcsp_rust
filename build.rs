/*
Cubesat Space Protocol - A small network-layer protocol designed for Cubesats
Copyright (C) 2012 GomSpace ApS (http://www.gomspace.com)
Copyright (C) 2012 AAUSAT3 Project (http://aausat3.space.aau.dk)

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.
*/

use std::env;
use std::fs;
use std::path::PathBuf;

/// Returns true when building for a bare-metal embedded target (no OS).
fn is_embedded_target() -> bool {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    matches!(target_os.as_str(), "none" | "unknown" | "")
        || env::var("TARGET").is_ok_and(|t| t.contains("thumb") || t.contains("arm-none"))
}

/// Returns true when the arch implementation is provided externally (in Rust)
/// rather than by libcsp's built-in POSIX C implementation.
fn uses_external_arch() -> bool {
    env::var("CARGO_FEATURE_EXTERNAL_ARCH").is_ok() || is_embedded_target()
}

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let libcsp_dir = PathBuf::from("libcsp");
    let src_dir = libcsp_dir.join("src");
    let include_dir = libcsp_dir.join("include");

    emit_rerun_triggers();

    // 1. Generate csp/autoconfig.h into OUT_DIR/include/csp/
    let gen_include_dir = out_dir.join("include");
    let gen_csp_dir = gen_include_dir.join("csp");
    fs::create_dir_all(&gen_csp_dir).expect("failed to create generated include dir");
    generate_autoconfig(&gen_csp_dir);

    if uses_external_arch() {
        generate_external_arch_headers(&gen_csp_dir);
    }

    // 2. Compile libcsp as a static library
    compile_libcsp(&src_dir, &include_dir, &gen_include_dir);

    // 2b. ROPI-RWPI trampolines: compile the assembly shim on ARM targets
    if env::var("CARGO_FEATURE_ROPI_RWPI").is_ok()
        && env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("arm")
    {
        cc::Build::new()
            .file("src/arch/ropi_rwpi.S")
            .compile("csp_ropi_rwpi_trampolines");
        println!("cargo:rerun-if-changed=src/arch/ropi_rwpi.S");
    }

    // 3. Generate Rust bindings via bindgen (all targets, including embedded)
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    generate_bindings(&include_dir, &gen_include_dir, &out_dir);

    // 4. Emit link flags
    match target_os.as_str() {
        "linux" => {
            println!("cargo:rustc-link-lib=pthread");
            println!("cargo:rustc-link-lib=rt");
        }
        "macos" => {
            println!("cargo:rustc-link-lib=pthread");
        }
        _ => {}
    }

    if env::var("CARGO_FEATURE_SOCKETCAN").is_ok() {
        println!("cargo:rustc-link-lib=socketcan");
    }
    if env::var("CARGO_FEATURE_ZMQ").is_ok() {
        println!("cargo:rustc-link-lib=zmq");
    }
}

/// Emit `rerun-if-changed` / `rerun-if-env-changed` directives.
fn emit_rerun_triggers() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=libcsp/include");
    println!("cargo:rerun-if-changed=libcsp/src");

    // Sizing overrides via environment variables
    for name in &[
        "LIBCSP_BUFFER_SIZE",
        "LIBCSP_BUFFER_COUNT",
        "LIBCSP_CONN_MAX",
        "LIBCSP_CONN_RXQUEUE_LEN",
        "LIBCSP_QFIFO_LEN",
        "LIBCSP_PORT_MAX_BIND",
        "LIBCSP_RTABLE_SIZE",
        "LIBCSP_MAX_INTERFACES",
        "LIBCSP_RDP_MAX_WINDOW",
        "LIBCSP_PACKET_PADDING_BYTES",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
}

/// Read a sizing constant from an env var, falling back to a default.
fn cfg_u32(env_name: &str, default: u32) -> u32 {
    env::var(env_name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Generate `csp/autoconfig.h` in `dest_dir` based on enabled Cargo features
/// and optional environment-variable overrides for buffer/connection sizing.
fn generate_autoconfig(dest_dir: &std::path::Path) {
    let target_endian = env::var("CARGO_CFG_TARGET_ENDIAN").unwrap_or_else(|_| "little".into());

    // Endianness
    let endian_define = if target_endian == "big" {
        "#define CSP_BIG_ENDIAN    1\n#define CSP_LITTLE_ENDIAN 0"
    } else {
        "#define CSP_LITTLE_ENDIAN 1\n#define CSP_BIG_ENDIAN    0"
    };

    // Feature flags — controlled by Cargo features
    let feat = |env: &str| -> &'static str {
        if env::var(env).is_ok() {
            "1"
        } else {
            "0"
        }
    };
    let use_rdp = feat("CARGO_FEATURE_RDP");
    let use_rdp_fc = feat("CARGO_FEATURE_RDP_FAST_CLOSE");
    let use_hmac = feat("CARGO_FEATURE_HMAC");
    let use_promisc = feat("CARGO_FEATURE_PROMISC");
    let use_dedup = feat("CARGO_FEATURE_DEDUP");
    let use_zmq_fixup = feat("CARGO_FEATURE_ZMQ_V1_FIXUP");
    let use_buf_zero = feat("CARGO_FEATURE_BUFFER_ZERO_CLEAR");
    let debug = feat("CARGO_FEATURE_DEBUG");

    // Whether csp_print() is compiled in. Off for bare-metal external-arch,
    // on otherwise (POSIX host). Rtable load/save/check also need this.
    let enable_csp_print = if uses_external_arch() { "0" } else { "1" };

    // stdio/strings require a hosted libc — disable for bare-metal external-arch.
    let have_stdio = if uses_external_arch() { "0" } else { "1" };
    let print_stdio = have_stdio;

    // Sizing — overridable via env vars
    let buf_size = cfg_u32("LIBCSP_BUFFER_SIZE", 256);
    let buf_count = cfg_u32("LIBCSP_BUFFER_COUNT", 10);
    let conn_max = cfg_u32("LIBCSP_CONN_MAX", 10);
    let conn_rxq = cfg_u32("LIBCSP_CONN_RXQUEUE_LEN", 10);
    let qfifo_len = cfg_u32("LIBCSP_QFIFO_LEN", 25);
    // CSP ports are 6-bit (0..=63). Ports above `CSP_PORT_MAX_BIND` are used
    // by the library as ephemeral source ports for outbound connections, so
    // keep MAX_BIND strictly below 63 to leave at least one ephemeral slot.
    let port_max = cfg_u32("LIBCSP_PORT_MAX_BIND", 48);
    let rtable_sz = cfg_u32("LIBCSP_RTABLE_SIZE", 10);
    let max_iface = cfg_u32("LIBCSP_MAX_INTERFACES", 8);
    let rdp_win = cfg_u32("LIBCSP_RDP_MAX_WINDOW", 20);
    let padding_bytes = cfg_u32("LIBCSP_PACKET_PADDING_BYTES", 8);

    // Export the sizing constants as cargo environment variables so Rust code
    // can reference them via `env!("CSP_*")` without going through `sys::`.
    for (name, val) in [
        ("CSP_BUFFER_SIZE", buf_size),
        ("CSP_BUFFER_COUNT", buf_count),
        ("CSP_CONN_MAX", conn_max),
        ("CSP_CONN_RXQUEUE_LEN", conn_rxq),
        ("CSP_QFIFO_LEN", qfifo_len),
        ("CSP_PORT_MAX_BIND", port_max),
        ("CSP_RTABLE_SIZE", rtable_sz),
        ("CSP_MAX_INTERFACES", max_iface),
        ("CSP_RDP_MAX_WINDOW", rdp_win),
        ("CSP_PACKET_PADDING_BYTES", padding_bytes),
    ] {
        println!("cargo:rustc-env={name}={val}");
    }

    let content = format!(
        r#"/*
 * Auto-generated by Rust build script — DO NOT EDIT.
 * Cubesat Space Protocol v2.1 compile-time configuration.
 *
 * Copyright (C) 2012 GomSpace ApS (http://www.gomspace.com)
 * Licensed under the GNU Lesser General Public License v2.1+
 */
#ifndef CSP_AUTOCONFIG_H
#define CSP_AUTOCONFIG_H

/* Endianness */
{endian_define}

/* Feature flags */
#define CSP_USE_RDP               {use_rdp}
#define CSP_USE_RDP_FAST_CLOSE    {use_rdp_fc}
#define CSP_USE_HMAC              {use_hmac}
#define CSP_USE_PROMISC           {use_promisc}
#define CSP_USE_RTABLE            1
#define CSP_ENABLE_CSP_PRINT      {enable_csp_print}
#define CSP_HAVE_STDIO            {have_stdio}
#define CSP_PRINT_STDIO           {print_stdio}
#define CSP_FIXUP_V1_ZMQ_LITTLE_ENDIAN {use_zmq_fixup}
#define CSP_BUFFER_ZERO_CLEAR     {use_buf_zero}

/* Dedup is a runtime toggle (csp_conf.dedup); this compile-time flag just
 * gates inclusion of dedup-related source files. */
#define CSP_USE_DEDUP             {use_dedup}

/* Debug / logging */
#define CSP_DEBUG                 {debug}

/* Buffer and connection sizing */
#define CSP_BUFFER_SIZE           {buf_size}
#define CSP_BUFFER_COUNT          {buf_count}
#define CSP_CONN_MAX              {conn_max}
#define CSP_CONN_RXQUEUE_LEN      {conn_rxq}
#define CSP_QFIFO_LEN             {qfifo_len}
#define CSP_PORT_MAX_BIND         {port_max}
#define CSP_RTABLE_SIZE           {rtable_sz}
#define CSP_MAX_INTERFACES        {max_iface}
#define CSP_RDP_MAX_WINDOW        {rdp_win}
#define CSP_PACKET_PADDING_BYTES  {padding_bytes}

/* Library version */
#define LIBCSP_VERSION            "2.1"
#define GIT_REV                   "unknown"

#endif /* CSP_AUTOCONFIG_H */
"#
    );

    let dest = dest_dir.join("autoconfig.h");
    fs::write(&dest, &content).expect("failed to write autoconfig.h");
}

/// External-arch stub header: extra declarations that libcsp leaves out when
/// none of its supported OS flavours (`CSP_POSIX`, `CSP_FREERTOS`,
/// `CSP_ZEPHYR`) are selected. The `export_arch!` macro supplies the bodies
/// from Rust.
fn generate_external_arch_headers(dest_dir: &std::path::Path) {
    let content = r#"#ifndef CSP_EXTERNAL_ARCH_H
#define CSP_EXTERNAL_ARCH_H

#include <stdint.h>
#include <stddef.h>

/* Binary semaphore handle for external-arch targets.
 * Declared as a pointer-sized opaque handle so it fits in the same slot
 * whether the Rust backing store is a raw pointer or a boxed primitive. */
typedef void * csp_bin_sem_t;

uint32_t csp_get_ms(void);
uint32_t csp_get_s(void);
uint32_t csp_get_ms_isr(void);
uint32_t csp_get_s_isr(void);
uint32_t csp_get_uptime_s(void);
void     csp_sleep_ms(uint32_t ms);

int csp_thread_create(void (*f)(void *), const char * name, unsigned int stack, void * arg, unsigned int prio, void ** handle);

#endif
"#;
    fs::write(dest_dir.join("csp_external_arch.h"), content)
        .expect("failed to write csp_external_arch.h");
}

/// Compile all libcsp C sources as a single static library `libcsp.a`.
fn compile_libcsp(
    src_dir: &std::path::Path,
    include_dir: &std::path::Path,
    gen_include_dir: &std::path::Path,
) {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let external_arch = uses_external_arch();

    // On bare-metal ARM (arm-none-eabi / thumb*-none-*), newlib ships
    // <sys/endian.h> but not a top-level <endian.h>, which libcsp's
    // csp_crc32.c / csp_sfp.c / … unconditionally include. Drop a shim into
    // OUT_DIR/include/ that forwards to <sys/endian.h>, so the fix travels
    // with the crate and downstream projects don't need to set CFLAGS.
    if is_embedded_target() {
        let shim = gen_include_dir.join("endian.h");
        if !shim.exists() {
            fs::write(
                &shim,
                "/* Generated by libcsp_rust build.rs for arm-none-eabi.\n\
                 * newlib exposes these macros via <sys/endian.h>; libcsp's\n\
                 * C sources want them at the glibc-style location. */\n\
                 #pragma once\n\
                 #include <sys/endian.h>\n",
            )
            .expect("failed to write endian.h shim");
        }
    }

    let mut build = cc::Build::new();

    // ── Include paths ──────────────────────────────────────────────────────
    build.include(include_dir); // libcsp/include
    build.include(src_dir); // private headers in src/
    build.include(src_dir.join("interfaces"));
    build.include(gen_include_dir); // OUT_DIR/include (csp/autoconfig.h, endian.h shim)

    // ── Compiler flags ─────────────────────────────────────────────────────
    build
        .flag("-std=gnu99")
        .flag("-Os")
        .flag("-Wall")
        .flag("-Wextra")
        .flag("-Wshadow")
        .flag("-Wcast-align")
        .flag("-Wwrite-strings")
        .flag("-Wno-unused-parameter")
        .flag("-Wno-address-of-packed-member");

    // ── Feature defines — must match csp/autoconfig.h ─────────────────────
    let feat_define = |b: &mut cc::Build, env: &str, name: &str| {
        let val = if env::var(env).is_ok() { "1" } else { "0" };
        b.define(name, val);
    };

    feat_define(&mut build, "CARGO_FEATURE_RDP", "CSP_USE_RDP");
    feat_define(
        &mut build,
        "CARGO_FEATURE_RDP_FAST_CLOSE",
        "CSP_USE_RDP_FAST_CLOSE",
    );
    feat_define(&mut build, "CARGO_FEATURE_HMAC", "CSP_USE_HMAC");
    feat_define(&mut build, "CARGO_FEATURE_PROMISC", "CSP_USE_PROMISC");
    feat_define(&mut build, "CARGO_FEATURE_DEDUP", "CSP_USE_DEDUP");
    feat_define(&mut build, "CARGO_FEATURE_DEBUG", "CSP_DEBUG");
    feat_define(
        &mut build,
        "CARGO_FEATURE_ZMQ_V1_FIXUP",
        "CSP_FIXUP_V1_ZMQ_LITTLE_ENDIAN",
    );
    feat_define(
        &mut build,
        "CARGO_FEATURE_BUFFER_ZERO_CLEAR",
        "CSP_BUFFER_ZERO_CLEAR",
    );

    build.define(
        "CSP_ENABLE_CSP_PRINT",
        if external_arch { "0" } else { "1" },
    );
    build.define("CSP_HAVE_STDIO", if external_arch { "0" } else { "1" });
    build.define("CSP_PRINT_STDIO", if external_arch { "0" } else { "1" });

    if external_arch {
        build.flag("-include").flag("csp/csp_external_arch.h");
    }

    // ROPI-RWPI: compile C code with R9-relative data access so globals are
    // accessed through the static-base register, matching user-space binaries.
    if env::var("CARGO_FEATURE_ROPI_RWPI").is_ok()
        && env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("arm")
    {
        build.flag("-msingle-pic-base");
        build.flag("-mpic-register=r9");
        build.flag("-mno-pic-data-is-text-relative");
    }

    build.define("CSP_USE_RTABLE", "1");

    // ── Core source files ──────────────────────────────────────────────────
    let core = [
        "csp_buffer.c",
        "csp_bridge.c",
        "csp_conn.c",
        "csp_crc32.c",
        "csp_debug.c",
        "csp_dedup.c",
        "csp_id.c",
        "csp_iflist.c",
        "csp_init.c",
        "csp_io.c",
        "csp_port.c",
        "csp_promisc.c",
        "csp_qfifo.c",
        "csp_route.c",
        "csp_rtable_cidr.c",
        "csp_service_handler.c",
        "csp_services.c",
        "csp_sfp.c",
    ];
    for f in &core {
        build.file(src_dir.join(f));
    }

    // Hex-dump and rtable stdio helpers depend on stdio being available;
    // skip them on external-arch builds where CSP_ENABLE_CSP_PRINT=0.
    if !external_arch {
        build.file(src_dir.join("csp_hex_dump.c"));
        build.file(src_dir.join("csp_rtable_stdio.c"));
    }

    // Transport
    if env::var("CARGO_FEATURE_RDP").is_ok() {
        build.file(src_dir.join("csp_rdp.c"));
        build.file(src_dir.join("csp_rdp_queue.c"));
    }

    // Crypto
    if env::var("CARGO_FEATURE_HMAC").is_ok() {
        build.file(src_dir.join("crypto/csp_hmac.c"));
        build.file(src_dir.join("crypto/csp_sha1.c"));
    }

    // Compile mini-scanf for external-arch (sscanf with varargs support)
    if external_arch {
        compile_mini_scanf();
    }

    // Interfaces
    let mut interfaces = vec![
        "interfaces/csp_if_can.c",
        "interfaces/csp_if_can_pbuf.c",
        "interfaces/csp_if_i2c.c",
        "interfaces/csp_if_kiss.c",
        "interfaces/csp_if_lo.c",
    ];
    // UDP and TUN interfaces only make sense when stdio / sockets exist.
    if !external_arch {
        interfaces.push("interfaces/csp_if_udp.c");
        interfaces.push("interfaces/csp_if_tun.c");
    }
    if env::var("CARGO_FEATURE_ZMQ").is_ok() {
        interfaces.push("interfaces/csp_if_zmqhub.c");
    }
    for f in &interfaces {
        build.file(src_dir.join(f));
    }

    // OS-specific arch files
    if !external_arch {
        match target_os.as_str() {
            "macos" | "linux" => {
                build.define("CSP_POSIX", "1");
                let posix_src = src_dir.join("arch/posix");
                for f in &[
                    "csp_clock.c",
                    "csp_queue.c",
                    "csp_semaphore.c",
                    "csp_system.c",
                    "csp_time.c",
                    "pthread_queue.c",
                ] {
                    build.file(posix_src.join(f));
                }
            }
            _ => {
                // Unknown hosted OS — treat as POSIX; will fail to link if unsupported.
                build.define("CSP_POSIX", "1");
                let posix_src = src_dir.join("arch/posix");
                for f in &[
                    "csp_clock.c",
                    "csp_queue.c",
                    "csp_semaphore.c",
                    "csp_system.c",
                    "csp_time.c",
                    "pthread_queue.c",
                ] {
                    build.file(posix_src.join(f));
                }
            }
        }
    }

    // Optional: SocketCAN driver
    if env::var("CARGO_FEATURE_SOCKETCAN").is_ok() {
        build.file(src_dir.join("drivers/can/can_socketcan.c"));
    }

    // Optional: USART drivers
    if env::var("CARGO_FEATURE_USART_LINUX").is_ok() && target_os == "linux" {
        build.file(src_dir.join("drivers/usart/usart_kiss.c"));
        build.file(src_dir.join("drivers/usart/usart_linux.c"));
    }

    build.compile("csp");
}

/// Compile mini-scanf for sscanf support in external-arch mode.
/// mini-scanf is a minimal sscanf implementation designed for embedded systems.
fn compile_mini_scanf() {
    let mini_scanf_dir = PathBuf::from("libcsp-sys/mini-scanf");

    // Verify submodule is initialized
    if !mini_scanf_dir.join("c_scan.c").exists() {
        panic!(
            "mini-scanf submodule not initialized. Run: git submodule update --init --recursive"
        );
    }

    let mut build = cc::Build::new();
    build
        .file(mini_scanf_dir.join("c_scan.c"))
        .file("libcsp-sys/sscanf_wrapper.c")
        .include(&mini_scanf_dir)
        .flag("-std=c99")
        .flag("-Os")
        .flag("-Wall")
        .define("C_SSCANF", None)
        .compile("mini_scanf");

    println!("cargo:rerun-if-changed=libcsp-sys/mini-scanf/c_scan.c");
    println!("cargo:rerun-if-changed=libcsp-sys/mini-scanf/c_scan.h");
    println!("cargo:rerun-if-changed=libcsp-sys/sscanf_wrapper.c");
}

/// Return include directories so bindgen can find `stddef.h`, `stdint.h`, etc.
fn gcc_builtin_include() -> Vec<String> {
    let mut paths = Vec::new();
    let target = env::var("TARGET").unwrap_or_default();
    let is_arm_embedded = target.contains("thumb") || target.contains("arm-none-eabi");

    if is_arm_embedded {
        if let Ok(output) = std::process::Command::new("arm-none-eabi-gcc")
            .arg("-print-file-name=include")
            .output()
        {
            let path = std::str::from_utf8(&output.stdout)
                .unwrap_or_default()
                .trim()
                .to_owned();
            if !path.is_empty() && path != "include" {
                paths.push(path);
            }
        }
        for candidate in &["/usr/arm-none-eabi/include", "/usr/include/newlib"] {
            if std::path::Path::new(candidate).exists() {
                paths.push((*candidate).to_owned());
                break;
            }
        }
        return paths;
    }

    let cc = env::var("CC").unwrap_or_else(|_| "cc".to_string());
    if let Ok(output) = std::process::Command::new(&cc)
        .arg("-print-file-name=include")
        .output()
    {
        let path = std::str::from_utf8(&output.stdout)
            .unwrap_or_default()
            .trim()
            .to_owned();
        if !path.is_empty() && path != "include" {
            paths.push(path);
        }
    }
    if paths.is_empty() && std::path::Path::new("/usr/include").exists() {
        paths.push("/usr/include".into());
    }
    paths
}

/// Use bindgen to generate Rust FFI bindings from the v2.1 public headers.
fn generate_bindings(
    include_dir: &std::path::Path,
    gen_include_dir: &std::path::Path,
    out_dir: &std::path::Path,
) {
    let license_header = r#"/*
Cubesat Space Protocol - A small network-layer protocol designed for Cubesats
Copyright (C) 2012 GomSpace ApS (http://www.gomspace.com)
Copyright (C) 2012 AAUSAT3 Project (http://aausat3.space.aau.dk)

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.
*/
// AUTO-GENERATED FILE — DO NOT EDIT
// Generated by bindgen from libcsp v2.1 headers"#;

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target = env::var("TARGET").unwrap_or_default();
    let is_arm_embedded = target.contains("thumb")
        || target.contains("arm-none-eabi")
        || matches!(target_os.as_str(), "none" | "unknown");
    let target_endian = env::var("CARGO_CFG_TARGET_ENDIAN").unwrap_or_else(|_| "little".into());

    let endian_define = if target_endian == "big" {
        "CSP_BIG_ENDIAN=1"
    } else {
        "CSP_LITTLE_ENDIAN=1"
    };

    let mut builder = bindgen::Builder::default()
        .header(
            include_dir
                .join("csp/csp.h")
                .to_str()
                .expect("include path is not valid UTF-8"),
        )
        .header(
            include_dir
                .join("csp/csp_cmp.h")
                .to_str()
                .expect("include path is not valid UTF-8"),
        )
        .header(
            include_dir
                .join("csp/csp_sfp.h")
                .to_str()
                .expect("include path is not valid UTF-8"),
        )
        .header(
            include_dir
                .join("csp/csp_id.h")
                .to_str()
                .expect("include path is not valid UTF-8"),
        )
        .header(
            include_dir
                .join("csp/csp_hooks.h")
                .to_str()
                .expect("include path is not valid UTF-8"),
        )
        .header(
            include_dir
                .join("csp/csp_interface.h")
                .to_str()
                .expect("include path is not valid UTF-8"),
        )
        .header(
            include_dir
                .join("csp/csp_iflist.h")
                .to_str()
                .expect("include path is not valid UTF-8"),
        )
        .header(
            include_dir
                .join("csp/csp_rtable.h")
                .to_str()
                .expect("include path is not valid UTF-8"),
        )
        .header(
            include_dir
                .join("csp/csp_debug.h")
                .to_str()
                .expect("include path is not valid UTF-8"),
        )
        .header(
            include_dir
                .join("csp/interfaces/csp_if_can.h")
                .to_str()
                .expect("include path is not valid UTF-8"),
        );

    if env::var("CARGO_FEATURE_HMAC").is_ok() {
        builder = builder.header(
            include_dir
                .join("csp/crypto/csp_hmac.h")
                .to_str()
                .expect("include path is not valid UTF-8"),
        );
    }

    builder = builder
        // Include paths
        .clang_arg(format!("-I{}", include_dir.display()))
        .clang_arg(format!("-I{}", gen_include_dir.display()))
        // Endian defines so bindgen sees the correct conditional branches
        .clang_arg(format!("-D{endian_define}"))
        .clang_arg("-DCSP_USE_RTABLE=1");

    // For ARM embedded targets, tell clang to generate 32-bit layouts and
    // point it at the ARM newlib/GCC headers instead of the host's.
    if is_arm_embedded {
        builder = builder.clang_arg(format!("--target={target}"));
    }

    if uses_external_arch() {
        let arch_header = gen_include_dir
            .join("csp/csp_external_arch.h")
            .to_str()
            .expect("arch header path is not valid UTF-8")
            .to_owned();
        builder = builder.clang_arg(format!("-include{arch_header}"));
    }

    // On some systems libclang cannot locate GCC's built-in headers
    // (stddef.h, stdint.h, …) on its own. Ask the C compiler where they live
    // and forward that as a -isystem path to clang.
    for gcc_include in gcc_builtin_include() {
        builder = builder.clang_arg(format!("-isystem{gcc_include}"));
    }

    // SocketCAN header is Linux-only — skip for embedded/non-Linux targets
    // to avoid pulling in Linux kernel headers that don't exist in newlib.
    if !is_arm_embedded && target_os == "linux" {
        builder = builder.header(
            include_dir
                .join("csp/drivers/can_socketcan.h")
                .to_str()
                .expect("include path is not valid UTF-8"),
        );
    }

    let bindings = builder
        // Inject the LGPL header into the generated file
        .raw_line(license_header)
        // Allow-list: only emit CSP symbols
        .allowlist_function("csp_.*")
        .allowlist_type("csp_.*")
        .allowlist_var("(CSP|csp)_.*")
        // Derive common traits where possible
        .derive_debug(true)
        .derive_copy(true)
        .derive_default(true)
        // Use core:: types instead of std:: so the generated bindings compile
        // in no_std environments (requires Rust 1.64+ for core::ffi::c_*).
        .use_core()
        .generate()
        .expect("bindgen failed to generate bindings");

    let out = out_dir.join("bindings.rs");
    bindings
        .write_to_file(&out)
        .expect("failed to write bindings.rs");
}
