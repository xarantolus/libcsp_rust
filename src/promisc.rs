//! Promiscuous mode support.
//!
//! When promiscuous mode is enabled, the CSP router clones all incoming packets
//! and places them in a dedicated queue for monitoring and sniffing.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::sys;
use crate::{error::csp_result, CspError, Packet};

static SNIFFER_ACTIVE: AtomicBool = AtomicBool::new(false);

/// An active promiscuous mode handle.
///
/// At most one `Sniffer` may exist at a time per process — libcsp's sniffer
/// queue is a single global, so a second [`Sniffer::open`] call returns
/// [`CspError::ResourceInUse`]. Promiscuous mode is disabled automatically
/// when the handle is dropped.
pub struct Sniffer {
    _private: (),
}

impl Sniffer {
    /// Enable promiscuous mode and return a handle.
    ///
    /// `queue_size` is the maximum number of packets to hold in the sniffer queue.
    pub fn open(queue_size: u32) -> crate::Result<Self> {
        if SNIFFER_ACTIVE.swap(true, Ordering::SeqCst) {
            return Err(CspError::ResourceInUse);
        }
        // Safety: `sys::csp_promisc_enable` is thread-safe.
        if let Err(e) = csp_result(unsafe { sys::csp_promisc_enable(queue_size) }) {
            SNIFFER_ACTIVE.store(false, Ordering::SeqCst);
            return Err(e);
        }
        Ok(Sniffer { _private: () })
    }

    /// Read a packet from the promiscuous queue.
    ///
    /// Returns `None` if the queue is empty or the timeout expires.
    pub fn read(&self, timeout: u32) -> Option<Packet> {
        // Safety: `sys::csp_promisc_read` returns a valid packet pointer or NULL.
        let ptr = unsafe { sys::csp_promisc_read(timeout) };
        if ptr.is_null() {
            None
        } else {
            // Safety: `ptr` is a valid packet pointer returned by libcsp.
            Some(unsafe { Packet::from_raw(ptr) })
        }
    }
}

impl Drop for Sniffer {
    fn drop(&mut self) {
        // Safety: `sys::csp_promisc_disable` is thread-safe.
        unsafe { sys::csp_promisc_disable() }
        SNIFFER_ACTIVE.store(false, Ordering::SeqCst);
    }
}
