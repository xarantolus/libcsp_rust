/*
Cubesat Space Protocol - A small network-layer protocol designed for Cubesats
Copyright (C) 2012 GomSpace ApS (http://www.gomspace.com)
Copyright (C) 2012 AAUSAT3 Project (http://aausat3.space.aau.dk)

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let libcsp_dir = PathBuf::from("libcsp");
    let src_dir = libcsp_dir.join("src");
    let include_dir = libcsp_dir.join("include");

    // Notify cargo of files/env vars that trigger rebuild
    emit_rerun_triggers();

    // 1. Generate csp_autoconfig.h into OUT_DIR/include/csp/
    let gen_include_dir = out_dir.join("include");
    let gen_csp_dir = gen_include_dir.join("csp");
    fs::create_dir_all(&gen_csp_dir).expect("failed to create generated include dir");
    generate_autoconfig(&gen_csp_dir);

    if env::var("CARGO_FEATURE_EXTERNAL_ARCH").is_ok() {
        generate_external_arch_headers(&gen_csp_dir);
    }

    // 2. Compile libcsp as a static library
    compile_libcsp(&src_dir, &include_dir, &gen_include_dir);

    // 3. Generate Rust bindings via bindgen
    generate_bindings(&include_dir, &gen_include_dir, &out_dir);

    // 4. Emit link flags
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    match target_os.as_str() {
        "linux" => {
            println!("cargo:rustc-link-lib=pthread");
            println!("cargo:rustc-link-lib=rt");
        }
        "macos" => {
            println!("cargo:rustc-link-lib=pthread");
        }
        "windows" => {
            println!("cargo:rustc-link-lib=ws2_32");
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

/// Generate `csp_autoconfig.h` in `dest_dir` based on enabled Cargo features
/// and optional environment-variable overrides for buffer/connection sizing.
fn generate_autoconfig(dest_dir: &std::path::Path) {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_endian = env::var("CARGO_CFG_TARGET_ENDIAN").unwrap_or_else(|_| "little".into());

    // OS defines
    let os_define = match target_os.as_str() {
        "windows" => "#define CSP_WINDOWS 1\n#define CSP_POSIX  0\n#define CSP_MACOSX 0",
        "macos"   => "#define CSP_MACOSX 1\n#define CSP_POSIX  0\n#define CSP_WINDOWS 0",
        _         => "#define CSP_POSIX  1\n#define CSP_WINDOWS 0\n#define CSP_MACOSX 0",
    };

    // Endianness
    let endian_define = if target_endian == "big" {
        "#define CSP_BIG_ENDIAN    1\n#define CSP_LITTLE_ENDIAN 0"
    } else {
        "#define CSP_LITTLE_ENDIAN 1\n#define CSP_BIG_ENDIAN    0"
    };

    // Feature flags — controlled by Cargo features
    let feat = |env: &str| -> &'static str {
        if env::var(env).is_ok() { "1" } else { "0" }
    };
    let use_rdp        = feat("CARGO_FEATURE_RDP");
    let use_rdp_fc     = feat("CARGO_FEATURE_RDP_FAST_CLOSE");
    let use_crc32      = feat("CARGO_FEATURE_CRC32");
    let use_hmac       = feat("CARGO_FEATURE_HMAC");
    let use_xtea       = feat("CARGO_FEATURE_XTEA");
    let use_qos        = feat("CARGO_FEATURE_QOS");
    let use_promisc    = feat("CARGO_FEATURE_PROMISC");
    let use_dedup      = feat("CARGO_FEATURE_DEDUP");
    let debug          = feat("CARGO_FEATURE_DEBUG");
    let debug_ts       = feat("CARGO_FEATURE_DEBUG_TIMESTAMP");

    // Log levels: in release (no debug feature) only ERROR is enabled
    let (log_debug, log_info, log_warn, log_error) = if debug == "1" {
        ("1", "1", "1", "1")
    } else {
        ("0", "0", "0", "1")
    };

    // Sizing — overridable via env vars
    let buf_size   = cfg_u32("LIBCSP_BUFFER_SIZE",      256);
    let buf_count  = cfg_u32("LIBCSP_BUFFER_COUNT",      10);
    let conn_max   = cfg_u32("LIBCSP_CONN_MAX",          10);
    let conn_rxq   = cfg_u32("LIBCSP_CONN_RXQUEUE_LEN",  10);
    let qfifo_len  = cfg_u32("LIBCSP_QFIFO_LEN",         25);
    let port_max   = cfg_u32("LIBCSP_PORT_MAX_BIND",      24);
    let rtable_sz  = cfg_u32("LIBCSP_RTABLE_SIZE",        10);
    let max_iface  = cfg_u32("LIBCSP_MAX_INTERFACES",      8);
    let rdp_win    = cfg_u32("LIBCSP_RDP_MAX_WINDOW",     20);

    let content = format!(
        r#"/*
 * Auto-generated by Rust build script — DO NOT EDIT.
 * Cubesat Space Protocol v1.6 compile-time configuration.
 *
 * Copyright (C) 2012 GomSpace ApS (http://www.gomspace.com)
 * Licensed under the GNU Lesser General Public License v2.1+
 */
#ifndef CSP_AUTOCONFIG_H
#define CSP_AUTOCONFIG_H

/* OS selection */
{os_define}

/* Endianness */
{endian_define}

/* Feature flags */
#define CSP_USE_RDP               {use_rdp}
#define CSP_USE_RDP_FAST_CLOSE    {use_rdp_fc}
#define CSP_USE_CRC32             {use_crc32}
#define CSP_USE_HMAC              {use_hmac}
#define CSP_USE_XTEA              {use_xtea}
#define CSP_USE_QOS               {use_qos}
#define CSP_USE_PROMISC           {use_promisc}
#define CSP_USE_DEDUP             {use_dedup}
#define CSP_USE_RTABLE            1

/* Debug / logging */
#define CSP_DEBUG                 {debug}
#define CSP_DEBUG_TIMESTAMP       {debug_ts}
#define CSP_LOG_LEVEL_DEBUG       {log_debug}
#define CSP_LOG_LEVEL_INFO        {log_info}
#define CSP_LOG_LEVEL_WARN        {log_warn}
#define CSP_LOG_LEVEL_ERROR       {log_error}

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

/* Library version */
#define LIBCSP_VERSION            "1.6"
#define GIT_REV                   "unknown"

#include <stdio.h>

#endif /* CSP_AUTOCONFIG_H */
"#
    );

    let dest = dest_dir.join("csp_autoconfig.h");
    fs::write(&dest, &content).expect("failed to write csp_autoconfig.h");
}

fn generate_external_arch_headers(dest_dir: &std::path::Path) {
    let content = r#"/*
 * Hack to support external architecture implementation in Rust.
 * We define the types as void* so they always fit a pointer.
 */
#ifndef CSP_EXTERNAL_ARCH_H
#define CSP_EXTERNAL_ARCH_H

/* Prevent libcsp's arch headers from declaring conflicting functions */
#define _CSP_THREAD_H_
#define _CSP_SEMAPHORE_H_
#define _CSP_QUEUE_H_
#define _CSP_TIME_H_
#define _CSP_MALLOC_H_
#define _CSP_SYSTEM_H_
#define _CSP_ARCH_CLOCK_H_

#include <stdint.h>
#include <stddef.h>

/* Thread types and macros normally provided by csp_thread.h */
typedef void * csp_thread_handle_t;
typedef void * csp_thread_return_t;
typedef csp_thread_return_t (* csp_thread_func_t)(void *);
#define CSP_DEFINE_TASK(task_name) csp_thread_return_t task_name(void * param)
#define CSP_TASK_RETURN NULL

typedef void * csp_bin_sem_handle_t;
typedef void * csp_mutex_t;
typedef void * csp_queue_handle_t;
typedef int    CSP_BASE_TYPE;

#define COLOR_MASK_COLOR 	0x0F
#define COLOR_MASK_MODIFIER	0xF0

typedef enum {
    COLOR_RESET		= 0xF0,
    COLOR_BLACK		= 0x01,
    COLOR_RED		= 0x02,
    COLOR_GREEN		= 0x03,
    COLOR_YELLOW		= 0x04,
    COLOR_BLUE		= 0x05,
    COLOR_MAGENTA		= 0x06,
    COLOR_CYAN		= 0x07,
    COLOR_WHITE		= 0x08,
    COLOR_NORMAL		= 0x0F,
    COLOR_BOLD		= 0x10,
    COLOR_UNDERLINE		= 0x20,
    COLOR_BLINK		= 0x30,
    COLOR_HIDE		= 0x40,
} csp_color_t;

#define CSP_SEMAPHORE_OK    1
#define CSP_SEMAPHORE_ERROR 0
#define CSP_MUTEX_OK        1
#define CSP_MUTEX_ERROR     0

#ifndef CSP_QUEUE_OK
#define CSP_QUEUE_OK        1
#endif
#ifndef CSP_QUEUE_ERROR
#define CSP_QUEUE_ERROR     0
#endif
#ifndef CSP_QUEUE_FULL
#define CSP_QUEUE_FULL      0
#endif

/* Prototypes */
uint32_t csp_get_ms(void);
uint32_t csp_get_s(void);
uint32_t csp_get_ms_isr(void);
uint32_t csp_get_s_isr(void);
uint32_t csp_get_uptime_s(void);

typedef struct {
    uint32_t tv_sec;
    uint32_t tv_nsec;
} csp_timestamp_t;

void csp_clock_get_time(csp_timestamp_t * time);
int  csp_clock_set_time(const csp_timestamp_t * time);

int csp_mutex_create(csp_mutex_t * mutex);
int csp_mutex_remove(csp_mutex_t * mutex);
int csp_mutex_lock(csp_mutex_t * mutex, uint32_t timeout);
int csp_mutex_unlock(csp_mutex_t * mutex);

int csp_bin_sem_create(csp_bin_sem_handle_t * sem);
int csp_bin_sem_remove(csp_bin_sem_handle_t * sem);
int csp_bin_sem_wait(csp_bin_sem_handle_t * sem, uint32_t timeout);
int csp_bin_sem_post(csp_bin_sem_handle_t * sem);
int csp_bin_sem_post_isr(csp_bin_sem_handle_t * sem, CSP_BASE_TYPE * pxTaskWoken);

csp_queue_handle_t csp_queue_create(int length, size_t item_size);
void csp_queue_remove(csp_queue_handle_t queue);
int csp_queue_enqueue(csp_queue_handle_t handle, const void *value, uint32_t timeout);
int csp_queue_enqueue_isr(csp_queue_handle_t handle, const void * value, CSP_BASE_TYPE * pxTaskWoken);
int csp_queue_dequeue(csp_queue_handle_t handle, void *buf, uint32_t timeout);
int csp_queue_dequeue_isr(csp_queue_handle_t handle, void * buf, CSP_BASE_TYPE * pxTaskWoken);
int csp_queue_size(csp_queue_handle_t handle);
int csp_queue_size_isr(csp_queue_handle_t handle);

void * csp_malloc(size_t size);
void * csp_calloc(size_t nmemb, size_t size);
void   csp_free(void * ptr);

uint32_t csp_sys_memfree(void);
int      csp_sys_tasklist(char * out);
int      csp_sys_tasklist_size(void);
void     csp_sys_set_color(csp_color_t color);
int      csp_sys_reboot(void);
int      csp_sys_shutdown(void);
void     csp_sleep_ms(uint32_t ms);
int      csp_thread_create(csp_thread_func_t func, const char * const name, unsigned int stack_size, void * parameter, unsigned int priority, csp_thread_handle_t * handle);

#endif"#;
    fs::write(dest_dir.join("csp_external_arch.h"), content).expect("failed to write csp_external_arch.h");
}

/// Compile all libcsp C sources as a single static library `libcsp.a`.
fn compile_libcsp(
    src_dir: &std::path::Path,
    include_dir: &std::path::Path,
    gen_include_dir: &std::path::Path,
) {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    let mut build = cc::Build::new();

    // ── Include paths ──────────────────────────────────────────────────────
    build.include(include_dir);                        // libcsp/include
    build.include(src_dir);                            // private headers in src/
    build.include(src_dir.join("transport"));
    build.include(src_dir.join("interfaces"));
    build.include(gen_include_dir);                    // OUT_DIR/include (csp_autoconfig.h)

    // ── Compiler flags ─────────────────────────────────────────────────────
    build
        .flag("-std=gnu99")
        .flag("-Os")
        .flag("-Wall")
        .flag("-Wextra")
        .flag("-Wshadow")
        .flag("-Wcast-align")
        .flag("-Wwrite-strings")
        .flag("-Wno-unused-parameter");

    // ── Feature defines — must match csp_autoconfig.h ─────────────────────
    let feat_define = |b: &mut cc::Build, env: &str, name: &str| {
        let val = if env::var(env).is_ok() { "1" } else { "0" };
        b.define(name, val);
    };

    feat_define(&mut build, "CARGO_FEATURE_RDP",            "CSP_USE_RDP");
    feat_define(&mut build, "CARGO_FEATURE_RDP_FAST_CLOSE", "CSP_USE_RDP_FAST_CLOSE");
    feat_define(&mut build, "CARGO_FEATURE_CRC32",          "CSP_USE_CRC32");
    feat_define(&mut build, "CARGO_FEATURE_HMAC",           "CSP_USE_HMAC");
    feat_define(&mut build, "CARGO_FEATURE_XTEA",           "CSP_USE_XTEA");
    feat_define(&mut build, "CARGO_FEATURE_QOS",            "CSP_USE_QOS");
    feat_define(&mut build, "CARGO_FEATURE_PROMISC",        "CSP_USE_PROMISC");
    feat_define(&mut build, "CARGO_FEATURE_DEDUP",          "CSP_USE_DEDUP");
    feat_define(&mut build, "CARGO_FEATURE_DEBUG",          "CSP_DEBUG");
    feat_define(&mut build, "CARGO_FEATURE_DEBUG_TIMESTAMP","CSP_DEBUG_TIMESTAMP");

    if env::var("CARGO_FEATURE_EXTERNAL_ARCH").is_ok() {
        // Force-include our external arch header.
        // The header defines guards to prevent libcsp's arch headers from being included.
        build.flag("-include").flag("csp/csp_external_arch.h");
    }

    build.define("CSP_USE_RTABLE", "1");

    let debug = if env::var("CARGO_FEATURE_DEBUG").is_ok() { "1" } else { "0" };
    build.define("CSP_LOG_LEVEL_DEBUG", if debug == "1" { "1" } else { "0" });
    build.define("CSP_LOG_LEVEL_INFO",  if debug == "1" { "1" } else { "0" });
    build.define("CSP_LOG_LEVEL_WARN",  if debug == "1" { "1" } else { "0" });
    build.define("CSP_LOG_LEVEL_ERROR", "1");

    // ── Core source files ──────────────────────────────────────────────────
    let core = [
        "csp_buffer.c",
        "csp_bridge.c",
        "csp_conn.c",
        "csp_crc32.c",
        "csp_debug.c",
        "csp_dedup.c",
        "csp_endian.c",
        "csp_hex_dump.c",
        "csp_iflist.c",
        "csp_init.c",
        "csp_io.c",
        "csp_port.c",
        "csp_promisc.c",
        "csp_qfifo.c",
        "csp_route.c",
        "csp_service_handler.c",
        "csp_services.c",
        "csp_sfp.c",
    ];
    for f in &core {
        build.file(src_dir.join(f));
    }

    // Debug wrapper for Rust callback (handles va_list formatting)
    if env::var("CARGO_FEATURE_DEBUG").is_ok() {
        build.file("csp_debug_wrapper.c");
    }

    // Compile mini-scanf for external-arch (sscanf with varargs support)
    if env::var("CARGO_FEATURE_EXTERNAL_ARCH").is_ok() {
        compile_mini_scanf();
    }

    // Transport
    build.file(src_dir.join("transport/csp_rdp.c"));
    build.file(src_dir.join("transport/csp_udp.c"));

    // Crypto
    build.file(src_dir.join("crypto/csp_hmac.c"));
    build.file(src_dir.join("crypto/csp_sha1.c"));
    build.file(src_dir.join("crypto/csp_xtea.c"));

    // Interfaces
    let mut interfaces = vec![
        "interfaces/csp_if_can.c",
        "interfaces/csp_if_can_pbuf.c",
        "interfaces/csp_if_i2c.c",
        "interfaces/csp_if_kiss.c",
        "interfaces/csp_if_lo.c",
    ];
    if env::var("CARGO_FEATURE_ZMQ").is_ok() {
        interfaces.push("interfaces/csp_if_zmqhub.c");
    }
    for f in &interfaces {
        build.file(src_dir.join(f));
    }

    // Routing table
    build.file(src_dir.join("rtable/csp_rtable.c"));
    if env::var("CARGO_FEATURE_CIDR_RTABLE").is_ok() {
        build.file(src_dir.join("rtable/csp_rtable_cidr.c"));
    } else {
        build.file(src_dir.join("rtable/csp_rtable_static.c"));
    }

    // Generic arch files (not OS-specific)
    if env::var("CARGO_FEATURE_EXTERNAL_ARCH").is_err() {
        build.file(src_dir.join("arch/csp_system.c"));
        build.file(src_dir.join("arch/csp_time.c"));
    }

    // OS-specific arch files
    if env::var("CARGO_FEATURE_EXTERNAL_ARCH").is_err() {
        match target_os.as_str() {
            "windows" => {
                build.define("CSP_WINDOWS", "1");
                let win_src = src_dir.join("arch/windows");
                for f in &[
                    "csp_clock.c",
                    "csp_malloc.c",
                    "csp_queue.c",
                    "csp_semaphore.c",
                    "csp_system.c",
                    "csp_thread.c",
                    "csp_time.c",
                    "windows_queue.c",
                ] {
                    build.file(win_src.join(f));
                }
            }
            "macos" => {
                build.define("CSP_MACOSX", "1");
                let mac_src = src_dir.join("arch/macosx");
                for f in &[
                    "csp_clock.c",
                    "csp_malloc.c",
                    "csp_queue.c",
                    "csp_semaphore.c",
                    "csp_system.c",
                    "csp_thread.c",
                    "csp_time.c",
                    "pthread_queue.c",
                ] {
                    build.file(mac_src.join(f));
                }
            }
            _ => {
                // Default: POSIX (Linux, etc.)
                build.define("CSP_POSIX", "1");
                let posix_src = src_dir.join("arch/posix");
                for f in &[
                    "csp_clock.c",
                    "csp_malloc.c",
                    "csp_queue.c",
                    "csp_semaphore.c",
                    "csp_system.c",
                    "csp_thread.c",
                    "csp_time.c",
                    "pthread_queue.c",
                ] {
                    build.file(posix_src.join(f));
                }
            }
        }
    } else {
        // When using external-arch, the user must provide these symbols.
        // We define CSP_POSIX as a sensible fallback for shared headers,
        // but no arch-specific C files are compiled.
        build.define("CSP_POSIX", "1");
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
    if env::var("CARGO_FEATURE_USART_WINDOWS").is_ok() && target_os == "windows" {
        build.file(src_dir.join("drivers/usart/usart_kiss.c"));
        build.file(src_dir.join("drivers/usart/usart_windows.c"));
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
        .define("C_SSCANF", None)  // Enable sscanf mode
        .compile("mini_scanf");

    println!("cargo:rerun-if-changed=libcsp-sys/mini-scanf/c_scan.c");
    println!("cargo:rerun-if-changed=libcsp-sys/mini-scanf/c_scan.h");
    println!("cargo:rerun-if-changed=libcsp-sys/sscanf_wrapper.c");
}

/// Return the GCC/clang built-in include directory so bindgen can find
/// `stddef.h`, `stdint.h`, etc. when libclang doesn't locate them by itself.
fn gcc_builtin_include() -> Vec<String> {
    let mut paths = Vec::new();

    // Use the cross-compiler if CC is set (typical for cross-compilation)
    let cc = env::var("CC").unwrap_or_else(|_| "cc".to_string());

    // `cc -print-file-name=include` prints the compiler's internal include dir.
    if let Ok(output) = std::process::Command::new(&cc)
        .arg("-print-file-name=include")
        .output()
    {
        let path = std::str::from_utf8(&output.stdout).unwrap_or_default().trim().to_owned();
        if !path.is_empty() && path != "include" {
            paths.push(path);
        }
    }

    // Special case for arm-none-eabi newlib
    let target = env::var("TARGET").unwrap_or_default();
    if target.contains("thumb") || target.contains("arm-none-eabi") {
        if std::path::Path::new("/usr/include/newlib").exists() {
            paths.push("/usr/include/newlib".into());
        }
    }

    if paths.is_empty() {
        // Fallback: try the standard system location
        if std::path::Path::new("/usr/include").exists() {
            paths.push("/usr/include".into());
        }
    }
    paths
}

/// Use bindgen to generate Rust FFI bindings from `libcsp/include/csp/csp.h`.
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

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/
// AUTO-GENERATED FILE — DO NOT EDIT
// Generated by bindgen from libcsp/include/csp/csp.h"#;

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_endian = env::var("CARGO_CFG_TARGET_ENDIAN").unwrap_or_else(|_| "little".into());

    let os_define = match target_os.as_str() {
        "windows" => "CSP_WINDOWS=1",
        "macos"   => "CSP_MACOSX=1",
        _         => "CSP_POSIX=1",
    };

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
                .join("csp/arch/csp_malloc.h")
                .to_str()
                .expect("include path is not valid UTF-8"),
        )
        .header(
            include_dir
                .join("csp/arch/csp_system.h")
                .to_str()
                .expect("include path is not valid UTF-8"),
        )
        .header(
            include_dir
                .join("csp/interfaces/csp_if_can.h")
                .to_str()
                .expect("include path is not valid UTF-8"),
        )
        .header(
            include_dir
                .join("csp/drivers/can_socketcan.h")
                .to_str()
                .expect("include path is not valid UTF-8"),
        )
        .header(
            include_dir
                .join("csp/crypto/csp_xtea.h")
                .to_str()
                .expect("include path is not valid UTF-8"),
        )
        .header(
            include_dir
                .join("csp/crypto/csp_hmac.h")
                .to_str()
                .expect("include path is not valid UTF-8"),
        )
        // Include paths
        .clang_arg(format!("-I{}", include_dir.display()))
        .clang_arg(format!("-I{}", gen_include_dir.display()))
        // OS + endian defines so bindgen sees the correct conditional branches
        .clang_arg(format!("-D{os_define}"))
        .clang_arg(format!("-D{endian_define}"))
        .clang_arg("-DCSP_USE_RTABLE=1");

    // On some Linux systems libclang cannot locate GCC's built-in headers
    // (stddef.h, stdint.h …) on its own.  Ask the C compiler where they live
    // and forward that as a -isystem path to clang.
    for gcc_include in gcc_builtin_include() {
        builder = builder.clang_arg(format!("-isystem{gcc_include}"));
    }

    let bindings = builder
        // Inject the LGPL header into the generated file
        .raw_line(license_header)
        // Allow-list: only emit CSP symbols
        .allowlist_function("csp_.*")
        .allowlist_type("csp_.*")
        .allowlist_var("CSP_.*")
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
