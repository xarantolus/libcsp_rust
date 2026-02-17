/*
Cubesat Space Protocol - A small network-layer protocol designed for Cubesats
Copyright (C) 2012 GomSpace ApS (http://www.gomspace.com)
Copyright (C) 2012 AAUSAT3 Project (http://aausat3.space.aau.dk)

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.
*/

//! Safe wrapper for `csp_socket_t` (server-side listening socket).

use crate::error::csp_result;
use crate::sys;
use crate::{Connection, Packet, Result};

/// A CSP server socket.
///
/// In libcsp, `csp_socket_t` is a typedef for the same struct as
/// `csp_conn_t`, but used on the *server* side. After calling
/// [`bind`](Socket::bind) and [`listen`](Socket::listen), you call
/// [`accept`](Socket::accept) in a loop to receive incoming connections.
///
/// ## Lifetime
///
/// libcsp does not expose an explicit socket-free function. Sockets are
/// released when [`csp_free_resources()`](crate::CspNode) is called (i.e.
/// when [`CspNode`](crate::CspNode) is dropped). Therefore `Socket` has **no
/// `Drop` implementation** — ownership is tied to the `CspNode`.
pub struct Socket {
    inner: *mut sys::csp_socket_t,
}

impl Socket {
    /// Create a new server socket.
    ///
    /// `opts` is a bitmask of `CSP_SO_*` constants (see [`SocketOpts`] or the
    /// raw constants in `sys`).  Use `0` for no options.
    ///
    /// Returns `None` if libcsp is out of resources.
    pub fn new(opts: u32) -> Option<Self> {
        let ptr = unsafe { sys::csp_socket(opts) };
        if ptr.is_null() {
            None
        } else {
            Some(Socket { inner: ptr })
        }
    }

    /// Bind a port to this socket.
    ///
    /// Use `CSP_ANY` (255) to accept packets on all unbound ports.
    /// A specific-port bind takes precedence over `CSP_ANY`.
    pub fn bind(&self, port: u8) -> Result<()> {
        csp_result(unsafe { sys::csp_bind(self.inner, port) })
    }

    /// Begin listening for incoming connections.
    ///
    /// `backlog` is the maximum number of connections queued waiting for
    /// [`accept`](Socket::accept).
    pub fn listen(&self, backlog: usize) -> Result<()> {
        csp_result(unsafe { sys::csp_listen(self.inner, backlog) })
    }

    /// Wait for and return the next incoming connection.
    ///
    /// Blocks for up to `timeout` milliseconds.  Use `0xFFFF_FFFF`
    /// (`CSP_MAX_TIMEOUT`) to block indefinitely.
    ///
    /// Returns `None` on timeout or error.
    pub fn accept(&self, timeout: u32) -> Option<Connection> {
        let ptr = unsafe { sys::csp_accept(self.inner, timeout) };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { Connection::from_raw(ptr) })
        }
    }

    /// Receive a single packet on a **connection-less** socket.
    ///
    /// This is the connectionless server path: bind the socket with
    /// `CSP_SO_CONN_LESS`, then call this method instead of
    /// [`accept`](Socket::accept).
    ///
    /// Returns `None` on timeout or error.
    pub fn recvfrom(&self, timeout: u32) -> Option<Packet> {
        let ptr =
            unsafe { sys::csp_recvfrom(self.inner, timeout) as *mut sys::csp_packet_t };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { Packet::from_raw(ptr) })
        }
    }
}

// The inner pointer is always accessed through libcsp's own thread-safe
// mechanisms (OS mutexes / semaphores), so moving a Socket is safe.
unsafe impl Send for Socket {}

impl core::fmt::Debug for Socket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Socket")
            .field("ptr", &(self.inner as usize))
            .finish()
    }
}
