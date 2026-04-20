/*
Cubesat Space Protocol - A small network-layer protocol designed for Cubesats

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.
*/

//! CSP debug counters and log-level toggles.
//!
//! libcsp exposes error counters through a handful of `extern` globals plus
//! two `uint8_t` toggles that control whether RDP and packet events call
//! `csp_print_func()`. This module wraps them in a typed API.
//!
//! There is no message-formatting hook; if you need captured log output,
//! wrap libcsp with a C-level override of `csp_print_func`.

use crate::sys;

/// Global error counters.
///
/// Each field increments atomically whenever libcsp hits the corresponding
/// error path. They never decrement and wrap at `u8::MAX`.
#[derive(Debug, Clone, Copy)]
pub struct Counters {
    pub buffer_out: u8,
    pub conn_out: u8,
    pub conn_ovf: u8,
    pub conn_noroute: u8,
    pub inval_reply: u8,
    pub errno: u8,
    pub can_errno: u8,
    pub eth_errno: u8,
}

/// Snapshot the current debug counters.
pub fn counters() -> Counters {
    unsafe {
        Counters {
            buffer_out: sys::csp_dbg_buffer_out,
            conn_out: sys::csp_dbg_conn_out,
            conn_ovf: sys::csp_dbg_conn_ovf,
            conn_noroute: sys::csp_dbg_conn_noroute,
            inval_reply: sys::csp_dbg_inval_reply,
            errno: sys::csp_dbg_errno,
            can_errno: sys::csp_dbg_can_errno,
            eth_errno: sys::csp_dbg_eth_errno,
        }
    }
}

/// Reset all debug counters to zero.
pub fn reset_counters() {
    unsafe {
        sys::csp_dbg_buffer_out = 0;
        sys::csp_dbg_conn_out = 0;
        sys::csp_dbg_conn_ovf = 0;
        sys::csp_dbg_conn_noroute = 0;
        sys::csp_dbg_inval_reply = 0;
        sys::csp_dbg_errno = 0;
        sys::csp_dbg_can_errno = 0;
        sys::csp_dbg_eth_errno = 0;
    }
}

/// Verbosity levels for the RDP trace (`csp_dbg_rdp_print`).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdpTrace {
    /// Silent.
    Off = 0,
    /// Log RDP error paths only.
    Errors = 1,
    /// Log RDP errors plus every protocol transition.
    Protocol = 2,
}

/// Set the RDP trace level.
pub fn set_rdp_trace(level: RdpTrace) {
    unsafe { sys::csp_dbg_rdp_print = level as u8 };
}

/// Enable or disable per-packet trace prints.
pub fn set_packet_trace(enabled: bool) {
    unsafe { sys::csp_dbg_packet_print = if enabled { 1 } else { 0 } };
}
