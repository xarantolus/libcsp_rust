//! High-level service and protocol support.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use core::ffi::CStr;

use crate::{sys, Packet, CspError, Result, Connection, Socket, Port};

// ── CMP (CSP Management Protocol) ───────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Ident {
    pub hostname: String,
    pub model: String,
    pub revision: String,
    pub date: String,
    pub time: String,
}

#[derive(Debug, Clone)]
pub struct IfStats {
    pub interface: String,
    pub tx: u32,
    pub rx: u32,
    pub tx_error: u32,
    pub rx_error: u32,
    pub drop: u32,
    pub autherr: u32,
    pub frame: u32,
    pub txbytes: u32,
    pub rxbytes: u32,
    pub irq: u32,
}

impl crate::CspNode {
    pub fn ident(&self, node: u8, timeout: u32) -> Result<Ident> {
        let mut msg: sys::csp_cmp_message = unsafe { core::mem::zeroed() };
        // CMP_SIZE(ident) = 2 (type+code) + sizeof(ident struct)
        let size = 2 + core::mem::size_of_val(unsafe { &msg.__bindgen_anon_1.ident });
        
        let ret = unsafe { sys::csp_cmp(node, timeout, sys::CSP_CMP_IDENT as u8, size as i32, &mut msg) };
        if ret == 0 {
            let ident = unsafe { &msg.__bindgen_anon_1.ident };
            Ok(Ident {
                hostname: unsafe { CStr::from_ptr(ident.hostname.as_ptr()) }.to_string_lossy().into_owned(),
                model:    unsafe { CStr::from_ptr(ident.model.as_ptr()) }.to_string_lossy().into_owned(),
                revision: unsafe { CStr::from_ptr(ident.revision.as_ptr()) }.to_string_lossy().into_owned(),
                date:     unsafe { CStr::from_ptr(ident.date.as_ptr()) }.to_string_lossy().into_owned(),
                time:     unsafe { CStr::from_ptr(ident.time.as_ptr()) }.to_string_lossy().into_owned(),
            })
        } else {
            Err(CspError::from_code(ret))
        }
    }

    pub fn peek(&self, node: u8, address: u32, len: u8, timeout: u32) -> Result<Vec<u8>> {
        if len as u32 > sys::CSP_CMP_PEEK_MAX_LEN {
            return Err(CspError::InvalidArgument);
        }
        let mut msg: sys::csp_cmp_message = unsafe { core::mem::zeroed() };
        msg.__bindgen_anon_1.peek.addr = address;
        msg.__bindgen_anon_1.peek.len = len;

        let size = 2 + 4 + 1 + len as usize;
        let ret = unsafe { sys::csp_cmp(node, timeout, sys::CSP_CMP_PEEK as u8, size as i32, &mut msg) };
        if ret == 0 {
            Ok(unsafe { msg.__bindgen_anon_1.peek.data[..len as usize].iter().map(|&c| c as u8).collect() })
        } else {
            Err(CspError::from_code(ret))
        }
    }

    pub fn poke(&self, node: u8, address: u32, data: &[u8], timeout: u32) -> Result<()> {
        if data.len() as u32 > sys::CSP_CMP_POKE_MAX_LEN {
            return Err(CspError::InvalidArgument);
        }
        let mut msg: sys::csp_cmp_message = unsafe { core::mem::zeroed() };
        msg.__bindgen_anon_1.poke.addr = address;
        msg.__bindgen_anon_1.poke.len = data.len() as u8;
        for (i, &b) in data.iter().enumerate() {
            // Array indexing through a union field requires unsafe.
            unsafe { msg.__bindgen_anon_1.poke.data[i] = b as core::ffi::c_char; }
        }

        let size = 2 + 4 + 1 + data.len();
        let ret = unsafe { sys::csp_cmp(node, timeout, sys::CSP_CMP_POKE as u8, size as i32, &mut msg) };
        if ret == 0 { Ok(()) } else { Err(CspError::from_code(ret)) }
    }
}

// ── Dispatcher ──────────────────────────────────────────────────────────────

pub type ServiceHandler = Box<dyn FnMut(&Connection, Packet) -> Option<Packet> + Send>;

pub struct Dispatcher {
    socket: Socket,
    handlers: BTreeMap<u8, ServiceHandler>,
}

impl Dispatcher {
    pub fn new() -> Option<Self> {
        let socket = Socket::new(crate::socket_opts::NONE)?;
        Some(Dispatcher {
            socket,
            handlers: BTreeMap::new(),
        })
    }

    pub fn register<P: Into<Port>, F>(&mut self, port: P, handler: F) -> Result<()>
    where
        F: FnMut(&Connection, Packet) -> Option<Packet> + Send + 'static,
    {
        let port: Port = port.into();
        let port_num: u8 = port.into();
        self.socket.bind(port_num)?;
        self.handlers.insert(port_num, Box::new(handler));
        Ok(())
    }

    pub fn bind_service<P: Into<Port>>(&mut self, port: P) -> Result<()> {
        let port: Port = port.into();
        let port_num: u8 = port.into();
        self.socket.bind(port_num)
    }

    pub fn run(&mut self, timeout: u32) {
        let _ = self.socket.listen(10);
        while let Some(conn) = self.socket.accept(timeout) {
            let dport = conn.dst_port() as u8;
            while let Some(pkt) = conn.read(100) {
                if let Some(handler) = self.handlers.get_mut(&dport) {
                    if let Some(reply) = handler(&conn, pkt) {
                        // Ignore send errors — if it fails the reply packet
                        // is freed automatically by send_discard.
                        let _ = conn.send_discard(reply, 100);
                    }
                } else if Port::from(dport).is_service_port() {
                    unsafe {
                        sys::csp_service_handler(conn.as_raw(), pkt.into_raw());
                    }
                }
            }
        }
    }
}
