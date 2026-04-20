//! Compile-time sizing constants.
//!
//! Mirrors the `#define` entries in the build-generated `csp/autoconfig.h`.
//! Override them by setting the matching `LIBCSP_*` environment variable at
//! build time, e.g.
//!
//! ```shell
//! LIBCSP_BUFFER_SIZE=512 cargo build
//! ```
//!
//! The values are also exposed as string literals via `env!()` for use in
//! const-evaluation contexts (see the build-time `cargo:rustc-env=` emission
//! in `build.rs`).

use crate::sys;

/// Maximum payload bytes per packet buffer.
pub const BUFFER_SIZE: usize = sys::CSP_BUFFER_SIZE as usize;

/// Number of pre-allocated packet buffers.
pub const BUFFER_COUNT: usize = sys::CSP_BUFFER_COUNT as usize;

/// Maximum simultaneous connections.
pub const CONN_MAX: usize = sys::CSP_CONN_MAX as usize;

/// Per-connection receive queue depth.
pub const CONN_RXQUEUE_LEN: usize = sys::CSP_CONN_RXQUEUE_LEN as usize;

/// Router incoming FIFO depth.
pub const QFIFO_LEN: usize = sys::CSP_QFIFO_LEN as usize;

/// Highest port number usable with `csp_bind`.
pub const PORT_MAX_BIND: usize = sys::CSP_PORT_MAX_BIND as usize;

/// Maximum RDP window size.
pub const RDP_MAX_WINDOW: usize = sys::CSP_RDP_MAX_WINDOW as usize;

/// Bytes reserved in the packet header for protocol-layer scratch space
/// (e.g. encryption IVs, CSP v2 header).
pub const PACKET_PADDING_BYTES: usize = sys::CSP_PACKET_PADDING_BYTES as usize;
