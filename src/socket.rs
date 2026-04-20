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

extern crate alloc;

use alloc::boxed::Box;

use crate::error::csp_result;
use crate::sys;
use crate::{Connection, Packet, Result};

/// A CSP server socket.
///
/// `csp_socket_t` owns the receive queue's static storage inline; moving the
/// struct after it has been bound would invalidate the `rx_queue` handle that
/// libcsp stashes into the port table. The socket is therefore heap-allocated
/// and never moved after construction.
pub struct Socket {
    inner: Box<sys::csp_socket_t>,
}

impl Socket {
    /// Create a new server socket.
    ///
    /// `opts` is a bitmask of `CSP_SO_*` constants (see [`crate::socket_opts`]).
    /// Use `0` for no options.
    pub fn new(opts: u32) -> Self {
        // Safety: `csp_socket_t` is POD (inline rx queue storage + opts field);
        // a fully-zeroed instance is a valid uninitialised socket.
        let mut inner: Box<sys::csp_socket_t> = Box::new(unsafe { core::mem::zeroed() });
        inner.opts = opts;
        Socket { inner }
    }

    fn as_ptr(&self) -> *mut sys::csp_socket_t {
        &*self.inner as *const sys::csp_socket_t as *mut sys::csp_socket_t
    }

    /// Bind a port to this socket.
    ///
    /// Use `CSP_ANY` (255) to accept packets on all unbound ports.
    /// A specific-port bind takes precedence over `CSP_ANY`.
    ///
    /// libcsp requires the receive-queue to be initialised before
    /// `accept`/`recvfrom` will return anything, and it only does that
    /// inside `csp_listen`. To keep the Rust API ergonomic we call
    /// `csp_listen` here as well; the `backlog` argument to [`listen`] is
    /// therefore only needed if you want to re-initialise the queue.
    ///
    /// [`listen`]: Self::listen
    pub fn bind(&mut self, port: u8) -> Result<()> {
        csp_result(unsafe { sys::csp_bind(self.as_ptr(), port) })?;
        csp_result(unsafe { sys::csp_listen(self.as_ptr(), 0) })
    }

    /// Re-initialise the receive queue (normally unnecessary — [`bind`]
    /// already does this).
    ///
    /// [`bind`]: Self::bind
    pub fn listen(&mut self, backlog: usize) -> Result<()> {
        csp_result(unsafe { sys::csp_listen(self.as_ptr(), backlog) })
    }

    /// Wait for and return the next incoming connection.
    ///
    /// Blocks for up to `timeout` milliseconds. Use `CSP_MAX_TIMEOUT` to block
    /// indefinitely. Returns `None` on timeout.
    pub fn accept(&self, timeout: u32) -> Option<Connection> {
        let ptr = unsafe { sys::csp_accept(self.as_ptr(), timeout) };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { Connection::from_raw(ptr) })
        }
    }

    /// Receive a single packet on a **connection-less** socket.
    ///
    /// Bind with `CSP_SO_CONN_LESS`, then call this instead of
    /// [`accept`](Self::accept).
    pub fn recvfrom(&self, timeout: u32) -> Option<Packet> {
        let ptr = unsafe { sys::csp_recvfrom(self.as_ptr(), timeout) };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { Packet::from_raw(ptr) })
        }
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        unsafe { sys::csp_socket_close(self.as_ptr()) };
    }
}

// libcsp guards socket access with internal OS primitives.
unsafe impl Send for Socket {}
unsafe impl Sync for Socket {}

impl core::fmt::Debug for Socket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Socket")
            .field("ptr", &(self.as_ptr() as usize))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{socket_opts, test_helpers::with_csp_node};

    #[test]
    fn test_socket_create_bind_listen() {
        with_csp_node(|_node| {
            let mut sock = Socket::new(socket_opts::NONE);
            sock.bind(10).expect("Failed to bind");
            sock.listen(5).expect("Failed to listen");
        });
    }

    #[test]
    fn test_socket_bind_any_port() {
        with_csp_node(|_node| {
            let mut sock = Socket::new(socket_opts::NONE);
            sock.bind(crate::ANY_PORT).expect("Failed to bind to ANY");
            sock.listen(10).expect("Failed to listen");
        });
    }

    #[test]
    fn test_socket_connectionless() {
        with_csp_node(|_node| {
            let mut sock = Socket::new(socket_opts::CONN_LESS);
            sock.bind(20).expect("Failed to bind");

            let result = sock.recvfrom(10);
            assert!(
                result.is_none(),
                "Expected timeout with no incoming packets"
            );
        });
    }

    #[test]
    fn test_socket_with_options() {
        with_csp_node(|_node| {
            let mut sock = Socket::new(socket_opts::NONE);
            sock.bind(22).expect("Failed to bind");
            sock.listen(5).expect("Failed to listen");
        });
    }

    #[test]
    #[cfg(feature = "rdp")]
    fn test_socket_with_rdp() {
        with_csp_node(|_node| {
            let mut sock = Socket::new(crate::conn_opts::RDP);
            sock.bind(21).expect("Failed to bind");
            sock.listen(5).expect("Failed to listen");
        });
    }

    #[test]
    fn test_socket_accept_timeout() {
        with_csp_node(|_node| {
            let mut sock = Socket::new(socket_opts::NONE);
            sock.bind(23).expect("Failed to bind");
            sock.listen(5).expect("Failed to listen");

            let result = sock.accept(10);
            assert!(result.is_none(), "Expected timeout when no connections");
        });
    }
}
