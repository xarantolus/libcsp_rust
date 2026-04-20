//! High-level service and protocol support.

extern crate alloc;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::CStr;

use crate::{sys, Connection, CspError, Packet, Port, Result, Socket};

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
    pub fn ident(&self, node: u16, timeout: u32) -> Result<Ident> {
        // Safety: Creating a zeroed struct is safe as it's passed to C.
        let mut msg: sys::csp_cmp_message = unsafe { core::mem::zeroed() };
        // CMP_SIZE(ident) = 2 (type+code) + sizeof(ident struct)
        // Safety: Union access is safe here because we're just calculating size.
        let size = 2 + core::mem::size_of_val(unsafe { &msg.__bindgen_anon_1.ident });

        // Safety: CSP_CMP_IDENT is 1, size fits in i32. `msg` is valid.
        let ret = unsafe {
            sys::csp_cmp(
                node,
                timeout,
                sys::CSP_CMP_IDENT as u8,
                size as i32,
                &mut msg,
            )
        };
        if ret == 0 {
            // Safety: The command succeeded, so the ident union field is valid.
            let ident = unsafe { &msg.__bindgen_anon_1.ident };
            Ok(Ident {
                // Safety: libcsp guarantees these strings are NUL-terminated.
                hostname: unsafe { CStr::from_ptr(ident.hostname.as_ptr()) }
                    .to_string_lossy()
                    .into_owned(),
                model: unsafe { CStr::from_ptr(ident.model.as_ptr()) }
                    .to_string_lossy()
                    .into_owned(),
                revision: unsafe { CStr::from_ptr(ident.revision.as_ptr()) }
                    .to_string_lossy()
                    .into_owned(),
                date: unsafe { CStr::from_ptr(ident.date.as_ptr()) }
                    .to_string_lossy()
                    .into_owned(),
                time: unsafe { CStr::from_ptr(ident.time.as_ptr()) }
                    .to_string_lossy()
                    .into_owned(),
            })
        } else {
            Err(CspError::from_code(ret))
        }
    }

    pub fn peek(&self, node: u16, address: u32, len: u8, timeout: u32) -> Result<Vec<u8>> {
        if len as u32 > sys::CSP_CMP_PEEK_MAX_LEN {
            return Err(CspError::InvalidArgument);
        }
        // Safety: Creating a zeroed struct is safe.
        let mut msg: sys::csp_cmp_message = unsafe { core::mem::zeroed() };
        msg.__bindgen_anon_1.peek.addr = address;
        msg.__bindgen_anon_1.peek.len = len;

        let size = 2 + 4 + 1 + len as usize;
        // Safety: CMP codes and sizes fit in their target types. `msg` is valid.
        let ret = unsafe {
            sys::csp_cmp(
                node,
                timeout,
                sys::CSP_CMP_PEEK as u8,
                size as i32,
                &mut msg,
            )
        };
        if ret == 0 {
            // Safety: The command succeeded, so the peek union field is valid.
            Ok(unsafe {
                msg.__bindgen_anon_1.peek.data[..len as usize]
                    .iter()
                    .map(|&c| c as u8)
                    .collect()
            })
        } else {
            Err(CspError::from_code(ret))
        }
    }

    pub fn poke(&self, node: u16, address: u32, data: &[u8], timeout: u32) -> Result<()> {
        if data.len() as u32 > sys::CSP_CMP_POKE_MAX_LEN {
            return Err(CspError::InvalidArgument);
        }
        // Safety: Creating a zeroed struct is safe.
        let mut msg: sys::csp_cmp_message = unsafe { core::mem::zeroed() };
        msg.__bindgen_anon_1.poke.addr = address;
        msg.__bindgen_anon_1.poke.len = data.len() as u8;
        for (i, &b) in data.iter().enumerate() {
            // Safety: b fits in c_char. Union access is safe for initialization.
            unsafe {
                msg.__bindgen_anon_1.poke.data[i] = b as core::ffi::c_char;
            }
        }

        let size = 2 + 4 + 1 + data.len();
        // Safety: CMP codes and sizes fit in their target types. `msg` is valid.
        let ret = unsafe {
            sys::csp_cmp(
                node,
                timeout,
                sys::CSP_CMP_POKE as u8,
                size as i32,
                &mut msg,
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(CspError::from_code(ret))
        }
    }
}

// ── Dispatcher ──────────────────────────────────────────────────────────────

/// Service handler function type.
///
/// Takes a connection and request packet, returns an optional reply packet.
/// If you need error handling, use [`ServiceHandlerResult`] instead.
///
/// [`ServiceHandlerResult`]: type.ServiceHandlerResult.html
pub type ServiceHandler = Box<dyn FnMut(&Connection, Packet) -> Option<Packet> + Send>;

/// Service handler with error result.
///
/// Similar to [`ServiceHandler`], but returns `Result<Option<Packet>, Box<dyn std::error::Error>>`.
/// Errors are reported via the error callback set with [`Dispatcher::on_error`].
///
/// [`ServiceHandler`]: type.ServiceHandler.html
/// [`Dispatcher::on_error`]: struct.Dispatcher.html#method.on_error
#[cfg(feature = "std")]
pub type ServiceHandlerResult = Box<
    dyn FnMut(
            &Connection,
            Packet,
        ) -> core::result::Result<Option<Packet>, Box<dyn std::error::Error>>
        + Send,
>;

/// Error callback type for [`Dispatcher`].
///
/// Called when:
/// - A handler returns an error (if using [`register_with_result`](Dispatcher::register_with_result))
/// - Sending a reply packet fails
///
/// [`Dispatcher`]: struct.Dispatcher.html
#[cfg(feature = "std")]
pub type ErrorCallback = Box<dyn FnMut(&str, Box<dyn std::error::Error>) + Send>;

pub struct Dispatcher {
    socket: Socket,
    handlers: BTreeMap<u8, ServiceHandler>,
    #[cfg(feature = "std")]
    result_handlers: BTreeMap<u8, ServiceHandlerResult>,
    #[cfg(feature = "std")]
    error_callback: Option<ErrorCallback>,
}

impl Dispatcher {
    pub fn new() -> Self {
        Dispatcher {
            socket: Socket::new(crate::socket_opts::NONE),
            handlers: BTreeMap::new(),
            #[cfg(feature = "std")]
            result_handlers: BTreeMap::new(),
            #[cfg(feature = "std")]
            error_callback: None,
        }
    }

    /// Set an error callback.
    ///
    /// This callback is invoked when:
    /// - A result-based handler returns an error
    /// - Sending a reply packet fails
    ///
    /// Requires the `std` feature.
    #[cfg(feature = "std")]
    pub fn on_error<F>(&mut self, callback: F)
    where
        F: FnMut(&str, Box<dyn std::error::Error>) + Send + 'static,
    {
        self.error_callback = Some(Box::new(callback));
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

    /// Register a service handler that can return errors.
    ///
    /// Unlike [`register`](Self::register), this allows handlers to return
    /// `Result<Option<Packet>, E>` where errors are reported via the error callback.
    ///
    /// Requires the `std` feature.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use libcsp::{CspConfig, service::Dispatcher};
    /// let node = CspConfig::new().init().unwrap();
    /// let mut dispatcher = Dispatcher::new();
    ///
    /// dispatcher.on_error(|context, err| {
    ///     eprintln!("Error in {}: {}", context, err);
    /// });
    ///
    /// dispatcher.register_with_result(10, |_conn, pkt| {
    ///     if pkt.length() == 0 {
    ///         Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Empty packet"))
    ///     } else {
    ///         Ok(Some(pkt)) // echo back
    ///     }
    /// }).unwrap();
    /// ```
    #[cfg(feature = "std")]
    pub fn register_with_result<P: Into<Port>, F, E>(
        &mut self,
        port: P,
        mut handler: F,
    ) -> Result<()>
    where
        F: FnMut(&Connection, Packet) -> core::result::Result<Option<Packet>, E> + Send + 'static,
        E: std::error::Error + 'static,
    {
        let port: Port = port.into();
        let port_num: u8 = port.into();
        self.socket.bind(port_num)?;

        // Wrap the handler to convert errors to Box<dyn Error>
        let wrapped: ServiceHandlerResult = Box::new(move |conn, pkt| {
            handler(conn, pkt).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
        });

        self.result_handlers.insert(port_num, wrapped);
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
            let dport = conn.dst_port();
            while let Some(pkt) = conn.read(100) {
                // Dispatch to the appropriate handler
                // Check which handler exists first to avoid moving pkt multiple times
                let has_regular_handler = self.handlers.contains_key(&dport);
                #[cfg(feature = "std")]
                let has_result_handler = self.result_handlers.contains_key(&dport);
                #[cfg(not(feature = "std"))]
                let has_result_handler = false;

                if has_regular_handler {
                    let handler = self.handlers.get_mut(&dport).unwrap();
                    if let Some(reply) = handler(&conn, pkt) {
                        conn.send(reply);
                    }
                } else if has_result_handler {
                    #[cfg(feature = "std")]
                    {
                        let handler = self.result_handlers.get_mut(&dport).unwrap();
                        match handler(&conn, pkt) {
                            Ok(Some(reply)) => conn.send(reply),
                            Ok(None) => {}
                            Err(err) => {
                                if let Some(ref mut cb) = self.error_callback {
                                    cb("handler", err);
                                }
                            }
                        }
                    }
                } else if Port::from(dport).is_service_port() {
                    conn.handle_service(pkt);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_helpers::with_csp_node, Packet, Port, Priority};

    // NOTE: CMP service tests (ident, ping, peek/poke) require a service handler
    // to be running. Full integration tests should use Dispatcher or a service thread.
    // These unit tests just verify the APIs are callable.

    #[test]
    fn test_cmp_ident_api() {
        with_csp_node(|node| {
            // Test that the ident API is callable
            // Will timeout without a service handler, but that's expected for a unit test
            let result = node.ident(1, 10); // Short timeout

            // Should timeout without a service handler (expected behavior)
            // If it doesn't timeout, validate the ident structure
            match result {
                Ok(_ident) => {
                    // If we got a response, we successfully parsed the ident structure
                    // The fact that it returned Ok means all fields are valid UTF-8 strings
                    // (This would only succeed if there's a service handler running)
                }
                Err(crate::CspError::TimedOut) => {
                    // Expected without a service handler - this is the normal case
                }
                Err(e) => {
                    panic!("Unexpected error from ident: {:?}", e);
                }
            }
        });
    }

    #[test]
    fn test_cmp_ping_api() {
        with_csp_node(|node| {
            // Test that the ping API is callable
            // Will timeout without a service handler, but that's expected for a unit test
            let result = node.ping(1, 10, 100, 0); // Short timeout
                                                   // Any result is acceptable - we're just testing the API is callable
            let _ = result; // Ignore the result
        });
    }

    #[test]
    fn test_cmp_peek_poke() {
        with_csp_node(|node| {
            // Peek/poke operations require the service handler to support them
            // These are typically not implemented in the default service handler,
            // so we just test that the API is callable
            let address = 0x1000;
            let test_data = vec![0x12, 0x34, 0x56, 0x78];

            // These will likely timeout, but the API should be callable
            let _ = node.poke(1, address, &test_data, 100);
            let _ = node.peek(1, address, test_data.len() as u8, 100);
        });
    }

    #[test]
    fn test_dispatcher_basic() {
        with_csp_node(|_node| {
            let mut dispatcher = Dispatcher::new();

            // Register a simple echo handler on a unique port
            let port = 15;
            dispatcher
                .register(port, |_conn, pkt| {
                    // Echo back the packet
                    Some(pkt)
                })
                .expect("Failed to register handler on port 15");

            // Verify we can bind another handler on a different port
            dispatcher
                .register(16, |_conn, _pkt| {
                    // No reply
                    None
                })
                .expect("Failed to register handler on port 16");

            // Attempting to register on an already-bound port should fail
            let duplicate_result = dispatcher.register(15, |_conn, pkt| Some(pkt));
            assert!(
                duplicate_result.is_err(),
                "Should not allow duplicate port binding"
            );
        });
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_dispatcher_with_result() {
        with_csp_node(|_node| {
            let mut dispatcher = Dispatcher::new();

            // Set error callback
            dispatcher.on_error(|context, err| {
                eprintln!("Error in {}: {}", context, err);
            });

            // Register a handler that can return errors
            dispatcher
                .register_with_result(17, |_conn, pkt| {
                    if pkt.length() == 0 {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Empty packet",
                        ))
                    } else {
                        Ok(Some(pkt))
                    }
                })
                .expect("Failed to register result handler");
        });
    }

    #[test]
    fn test_dispatcher_bind_service() {
        with_csp_node(|_node| {
            let mut dispatcher = Dispatcher::new();

            // Bind to a service port without a custom handler (uses built-in)
            dispatcher
                .bind_service(Port::Ping)
                .expect("Failed to bind service port");
        });
    }

    #[test]
    fn test_packet_service_handler() {
        with_csp_node(|node| {
            // Connect to ourselves on a service port
            let conn = node
                .connect(Priority::Norm, 1, Port::Ping.into(), 100, 0)
                .expect("Failed to connect");

            // Create a packet
            let pkt = Packet::get(16).unwrap();

            // The service handler would process this
            // For this test, we just verify the API works
            conn.handle_service(pkt);
        });
    }
}
