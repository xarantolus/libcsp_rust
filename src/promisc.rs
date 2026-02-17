//! Promiscuous mode support.
//!
//! When promiscuous mode is enabled, the CSP router clones all incoming packets
//! and places them in a dedicated queue for monitoring and sniffing.

use crate::sys;
use crate::{Packet, error::csp_result};

/// An active promiscuous mode handle.
///
/// Promiscuous mode is disabled automatically when this handle is dropped.
pub struct Sniffer {
    _private: (),
}

impl Sniffer {
    /// Enable promiscuous mode and return a handle.
    ///
    /// `queue_size` is the maximum number of packets to hold in the sniffer queue.
    pub fn open(queue_size: u32) -> crate::Result<Self> {
        csp_result(unsafe { sys::csp_promisc_enable(queue_size) })?;
        Ok(Sniffer { _private: () })
    }

    /// Read a packet from the promiscuous queue.
    ///
    /// Returns `None` if the queue is empty or the timeout expires.
    pub fn read(&self, timeout: u32) -> Option<Packet> {
        let ptr = unsafe { sys::csp_promisc_read(timeout) };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { Packet::from_raw(ptr) })
        }
    }
}

impl Drop for Sniffer {
    fn drop(&mut self) {
        unsafe { sys::csp_promisc_disable() }
    }
}

/// Enable promiscuous mode (legacy functional API).
pub fn enable(queue_size: u32) -> crate::Result<()> {
    csp_result(unsafe { sys::csp_promisc_enable(queue_size) })
}

/// Disable promiscuous mode (legacy functional API).
pub fn disable() {
    unsafe { sys::csp_promisc_disable() }
}

/// Read a packet from the promiscuous queue (legacy functional API).
pub fn read(timeout: u32) -> Option<Packet> {
    let ptr = unsafe { sys::csp_promisc_read(timeout) };
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { Packet::from_raw(ptr) })
    }
}
