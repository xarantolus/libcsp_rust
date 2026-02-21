/*
Cubesat Space Protocol - A small network-layer protocol designed for Cubesats

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.
*/

//! CSP debug output and logging integration.
//!
//! This module provides safe Rust bindings to libcsp's debug system, allowing you to:
//! - Enable/disable debug levels
//! - Set custom debug hooks to capture log messages
//! - Control debug output programmatically
//!
//! # Example
//!
//! ```no_run
//! use libcsp::debug::{DebugLevel, set_debug_level, set_debug_hook};
//! use std::ffi::CStr;
//!
//! // Enable INFO level logging
//! set_debug_level(DebugLevel::Info, true);
//!
//! // Set a custom debug hook
//! set_debug_hook(|level, message| {
//!     println!("[CSP {:?}] {}", level, message);
//! });
//! ```

use core::ffi::{c_char, c_uint, CStr};
use crate::sys;

/// CSP debug/log levels.
///
/// These correspond to the `csp_debug_level_t` enum in `csp_debug.h`.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DebugLevel {
    /// Error messages (always enabled by default)
    Error = sys::csp_debug_level_t_CSP_ERROR,
    /// Warning messages (enabled by default)
    Warn = sys::csp_debug_level_t_CSP_WARN,
    /// Informational messages (disabled by default)
    Info = sys::csp_debug_level_t_CSP_INFO,
    /// Buffer allocation/deallocation (disabled by default)
    Buffer = sys::csp_debug_level_t_CSP_BUFFER,
    /// Packet processing (disabled by default)
    Packet = sys::csp_debug_level_t_CSP_PACKET,
    /// Protocol state machine (disabled by default)
    Protocol = sys::csp_debug_level_t_CSP_PROTOCOL,
    /// Lock operations (disabled by default)
    Lock = sys::csp_debug_level_t_CSP_LOCK,
}

/// Enable or disable a specific debug level.
///
/// This is only available when the `debug` feature is enabled at compile time.
///
/// # Example
///
/// ```no_run
/// use libcsp::debug::{DebugLevel, set_debug_level};
///
/// // Enable INFO level
/// set_debug_level(DebugLevel::Info, true);
///
/// // Disable PACKET level
/// set_debug_level(DebugLevel::Packet, false);
/// ```
#[cfg(feature = "debug")]
pub fn set_debug_level(level: DebugLevel, enabled: bool) {
    unsafe {
        sys::csp_debug_set_level(level as u32, enabled);
    }
}

/// Get the current state of a debug level.
///
/// Returns `true` if the level is enabled, `false` otherwise.
///
/// This is only available when the `debug` feature is enabled.
#[cfg(feature = "debug")]
pub fn get_debug_level(level: DebugLevel) -> bool {
    unsafe {
        sys::csp_debug_get_level(level as u32) != 0
    }
}

/// Toggle a debug level (enable if disabled, disable if enabled).
///
/// This is only available when the `debug` feature is enabled.
#[cfg(feature = "debug")]
pub fn toggle_debug_level(level: DebugLevel) {
    unsafe {
        sys::csp_debug_toggle_level(level as u32);
    }
}

/// Type signature for debug hook callbacks.
///
/// The callback receives:
/// - `level`: The debug level of the message
/// - `message`: The formatted log message as a string
pub type DebugHookFn = fn(DebugLevel, &str);

/// Global storage for the Rust debug hook (if any)
static mut RUST_DEBUG_HOOK: Option<DebugHookFn> = None;

/// External C functions from csp_debug_wrapper.c
#[cfg(feature = "debug")]
extern "C" {
    fn csp_debug_set_rust_callback(callback: Option<extern "C" fn(c_uint, *const c_char)>);
    fn csp_debug_hook_install_wrapper();
    fn csp_debug_hook_clear();
}

/// Rust callback that receives formatted debug messages from the C wrapper.
///
/// This function is called by csp_debug_wrapper.c after it has formatted
/// the va_list arguments into a string.
#[cfg(feature = "debug")]
extern "C" fn rust_debug_callback(level: c_uint, message: *const c_char) {
    unsafe {
        if let Some(hook) = RUST_DEBUG_HOOK {
            // Convert C string to Rust string
            if !message.is_null() {
                if let Ok(msg) = CStr::from_ptr(message).to_str() {
                    // Map the C level to Rust enum
                    let debug_level = match level {
                        sys::csp_debug_level_t_CSP_ERROR => DebugLevel::Error,
                        sys::csp_debug_level_t_CSP_WARN => DebugLevel::Warn,
                        sys::csp_debug_level_t_CSP_INFO => DebugLevel::Info,
                        sys::csp_debug_level_t_CSP_BUFFER => DebugLevel::Buffer,
                        sys::csp_debug_level_t_CSP_PACKET => DebugLevel::Packet,
                        sys::csp_debug_level_t_CSP_PROTOCOL => DebugLevel::Protocol,
                        sys::csp_debug_level_t_CSP_LOCK => DebugLevel::Lock,
                        _ => DebugLevel::Info, // Fallback
                    };

                    hook(debug_level, msg);
                }
            }
        }
    }
}

/// Set a custom debug hook to capture CSP log messages.
///
/// The hook function will be called for every debug message that passes the
/// enabled debug level filters.
///
/// This is only available when the `debug` feature is enabled.
///
/// # Example
///
/// ```no_run
/// use libcsp::debug::{DebugLevel, set_debug_hook, set_debug_level};
///
/// // Set up custom logging
/// set_debug_hook(|level, message| {
///     match level {
///         DebugLevel::Error => eprintln!("[CSP ERROR] {}", message),
///         DebugLevel::Warn => eprintln!("[CSP WARN] {}", message),
///         _ => println!("[CSP] {}", message),
///     }
/// });
///
/// // Enable the levels you want to see
/// set_debug_level(DebugLevel::Info, true);
/// ```
///
/// # Safety
///
/// Only one debug hook can be active at a time. Setting a new hook replaces the previous one.
#[cfg(feature = "debug")]
pub fn set_debug_hook(hook: DebugHookFn) {
    unsafe {
        RUST_DEBUG_HOOK = Some(hook);
        // Set our Rust callback in the C wrapper
        csp_debug_set_rust_callback(Some(rust_debug_callback));
        // Install the C wrapper as the CSP debug hook
        csp_debug_hook_install_wrapper();
    }
}

/// Remove the custom debug hook, reverting to default CSP debug output.
///
/// This is only available when the `debug` feature is enabled.
#[cfg(feature = "debug")]
pub fn clear_debug_hook() {
    unsafe {
        RUST_DEBUG_HOOK = None;
        csp_debug_set_rust_callback(None);
        csp_debug_hook_clear();
    }
}

/// Helper to enable common debug levels for development.
///
/// Enables: Error, Warn, Info
/// Disables: Buffer, Packet, Protocol, Lock
///
/// This is only available when the `debug` feature is enabled.
#[cfg(feature = "debug")]
pub fn enable_dev_debug() {
    set_debug_level(DebugLevel::Error, true);
    set_debug_level(DebugLevel::Warn, true);
    set_debug_level(DebugLevel::Info, true);
    set_debug_level(DebugLevel::Buffer, false);
    set_debug_level(DebugLevel::Packet, false);
    set_debug_level(DebugLevel::Protocol, false);
    set_debug_level(DebugLevel::Lock, false);
}

/// Helper to enable verbose debug levels for deep debugging.
///
/// Enables all debug levels.
///
/// This is only available when the `debug` feature is enabled.
#[cfg(feature = "debug")]
pub fn enable_verbose_debug() {
    for level in [
        DebugLevel::Error,
        DebugLevel::Warn,
        DebugLevel::Info,
        DebugLevel::Buffer,
        DebugLevel::Packet,
        DebugLevel::Protocol,
        DebugLevel::Lock,
    ] {
        set_debug_level(level, true);
    }
}

/// Helper to disable all debug output.
///
/// This is only available when the `debug` feature is enabled.
#[cfg(feature = "debug")]
pub fn disable_all_debug() {
    for level in [
        DebugLevel::Error,
        DebugLevel::Warn,
        DebugLevel::Info,
        DebugLevel::Buffer,
        DebugLevel::Packet,
        DebugLevel::Protocol,
        DebugLevel::Lock,
    ] {
        set_debug_level(level, false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "debug")]
    fn test_debug_level_enum() {
        // Verify enum values match C constants (using generated constants)
        assert_eq!(DebugLevel::Error as u32, sys::csp_debug_level_t_CSP_ERROR);
        assert_eq!(DebugLevel::Warn as u32, sys::csp_debug_level_t_CSP_WARN);
        assert_eq!(DebugLevel::Info as u32, sys::csp_debug_level_t_CSP_INFO);
        assert_eq!(DebugLevel::Buffer as u32, sys::csp_debug_level_t_CSP_BUFFER);
        assert_eq!(DebugLevel::Packet as u32, sys::csp_debug_level_t_CSP_PACKET);
        assert_eq!(DebugLevel::Protocol as u32, sys::csp_debug_level_t_CSP_PROTOCOL);
        assert_eq!(DebugLevel::Lock as u32, sys::csp_debug_level_t_CSP_LOCK);
    }

    #[test]
    #[cfg(feature = "debug")]
    fn test_debug_level_ordering() {
        // Verify severity ordering
        assert!(DebugLevel::Error < DebugLevel::Warn);
        assert!(DebugLevel::Warn < DebugLevel::Info);
        assert!(DebugLevel::Info < DebugLevel::Buffer);
    }
}
