//! Shared test scaffolding for the node-level differential tests.
//!
//! The C boundary is abstracted by the `c_*` functions in the crate root; this module does
//! the same for the *port* side of a scenario — the plumbing every node test repeats:
//! injecting a received frame, draining what the port wants to send, and simulating a CAN
//! driver (fragment on the way out, reassemble on the way in). Before it existed, `inject`
//! was copied byte-for-byte into seven test files and the CAN driver into five, and the v1
//! CAN composite could not reuse the v2 one at all. The helpers are generic over the
//! `Node` const parameters, so a test keeps its own storage sizing.
//!
//! What is deliberately *not* here: `drain` variants that match specific `Routed` arms by
//! test intent. Those differ on purpose; [`work_until_idle`] gives them a shared shell
//! without flattening the differences.

use csp::router::Routed;
use csp::Node;
use csp_core::{cfp, Id, Version};

use crate::CanFrame;

/// One reassembled port packet, framed for injection back into a node.
const HDR_V1: usize = 4;
const HDR_V2: usize = 6;

/// Feed a received frame to a node's router, exactly as an interface driver would.
pub fn inject<
    'a,
    const CONNS: usize,
    const BUFS: usize,
    const BUFSZ: usize,
    const PORTS: usize,
    const QF: usize,
    const RXQ: usize,
>(
    node: &mut Node<'a, CONNS, BUFS, BUFSZ, PORTS, QF, RXQ>,
    version: Version,
    iface: u8,
    frame: &[u8],
) {
    let mut p = node.packet().expect("a free buffer for the injected frame");
    p.set_frame(version, frame)
        .expect("a frame the node accepts");
    node.router.receive(p, iface);
}

/// Run `node.work` until it goes idle, handing each non-idle [`Routed`] to `f` together
/// with the node (the work borrow is released before `f` runs, so `f` may take packets).
pub fn work_until_idle<
    'a,
    const CONNS: usize,
    const BUFS: usize,
    const BUFSZ: usize,
    const PORTS: usize,
    const QF: usize,
    const RXQ: usize,
    F,
>(
    node: &mut Node<'a, CONNS, BUFS, BUFSZ, PORTS, QF, RXQ>,
    now_ms: u32,
    mut f: F,
) where
    F: FnMut(&mut Node<'a, CONNS, BUFS, BUFSZ, PORTS, QF, RXQ>, Routed),
{
    loop {
        let r = node.work(now_ms);
        if matches!(r, Routed::Idle) {
            break;
        }
        f(node, r);
    }
}

/// Drain every frame the node wants to put on the wire (`Routed::Respond`), framed. The
/// common case; tests that also need `Delivered` use [`work_until_idle`] directly.
pub fn drain_respond<
    'a,
    const CONNS: usize,
    const BUFS: usize,
    const BUFSZ: usize,
    const PORTS: usize,
    const QF: usize,
    const RXQ: usize,
>(
    node: &mut Node<'a, CONNS, BUFS, BUFSZ, PORTS, QF, RXQ>,
    version: Version,
    now_ms: u32,
) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    work_until_idle(node, now_ms, |node, r| {
        if let Routed::Respond { packet, .. } = r {
            if let Some(mut p) = node.take_forwarded(packet) {
                p.prepend_header(version)
                    .expect("a header for the response");
                out.push(p.with_frame(|f| f.to_vec()));
            }
        }
    });
    out
}

/// A CAN driver for one side of a link: fragments a port packet into CAN frames on the way
/// out, and reassembles the peer's frames back into packets on the way in — with the pool
/// duties a real driver has (a broken transfer is dropped and its slot released, quiet
/// transfers expire). Generic over the CFP version via [`CfpKind`].
pub struct CanLink<K: CfpKind> {
    /// The CAN interface's own address — the CFP source field.
    pub addr: u16,
    sender_count: u32,
    pool: cfp::Pbufs<K::Reassembler, 4>,
}

/// The per-version pieces of CFP framing: v1 (4-byte header, 10-bit ident) and v2 (6-byte
/// header, connection-keyed). One `impl` per wire version keeps [`CanLink`] version-free.
pub trait CfpKind {
    /// The reassembler this version's pool holds.
    type Reassembler: Default + Copy;
    /// This version's `Version` tag.
    const VERSION: Version;
    /// This version's CSP header length.
    const HDR: usize;
    /// Cut one packet into CAN frames.
    fn fragment(id: Id, addr: u16, sender_count: u32, payload: &[u8]) -> Vec<CanFrame>;
    /// The reassembly key for a CAN id (what groups frames of one transfer).
    fn key(can_id: u32) -> u32;
    /// Push one CAN frame into a reassembler; `Some((header, len))` on completion.
    fn push(
        re: &mut Self::Reassembler,
        can_id: u32,
        data: &[u8],
        out: &mut [u8],
    ) -> csp_core::Result<Option<(Id, usize)>>;
}

/// CSP v2 framing.
pub struct V2;
impl CfpKind for V2 {
    type Reassembler = cfp::V2Reassembler;
    const VERSION: Version = Version::V2;
    const HDR: usize = HDR_V2;
    fn fragment(id: Id, addr: u16, sender_count: u32, payload: &[u8]) -> Vec<CanFrame> {
        cfp::V2Fragmenter::new(id, addr, sender_count, payload)
            .map(|f| (f.id, f.data().to_vec()))
            .collect()
    }
    fn key(can_id: u32) -> u32 {
        can_id & cfp::V2_CONN_MASK
    }
    fn push(
        re: &mut Self::Reassembler,
        can_id: u32,
        data: &[u8],
        out: &mut [u8],
    ) -> csp_core::Result<Option<(Id, usize)>> {
        re.push(can_id, data, out)
    }
}

/// CSP v1 framing.
pub struct V1;
impl CfpKind for V1 {
    type Reassembler = cfp::V1Reassembler;
    const VERSION: Version = Version::V1;
    const HDR: usize = HDR_V1;
    fn fragment(id: Id, addr: u16, sender_count: u32, payload: &[u8]) -> Vec<CanFrame> {
        let mut header = [0u8; HDR_V1];
        id.encode(Version::V1, &mut header).expect("a v1 header");
        cfp::V1Fragmenter::new(header, addr, id.dst, (sender_count & 0x3FF) as u16, payload)
            .map(|f| (f.id, f.data().to_vec()))
            .collect()
    }
    fn key(can_id: u32) -> u32 {
        let f = cfp::v1_parse(can_id);
        (u32::from(f.src) << 10) | u32::from(f.ident)
    }
    fn push(
        re: &mut Self::Reassembler,
        can_id: u32,
        data: &[u8],
        out: &mut [u8],
    ) -> csp_core::Result<Option<(Id, usize)>> {
        let hdr = re.push(can_id, data, out)?;
        Ok(hdr.map(|h| (h, re.received())))
    }
}

impl<K: CfpKind> CanLink<K> {
    /// A link whose CAN interface sits at `addr`.
    pub fn new(addr: u16) -> Self {
        CanLink {
            addr,
            sender_count: 0,
            pool: cfp::Pbufs::new(),
        }
    }

    /// Cut one port packet into CAN frames, advancing this link's transfer counter.
    pub fn fragment(&mut self, id: Id, payload: &[u8]) -> Vec<CanFrame> {
        let frames = K::fragment(id, self.addr, self.sender_count, payload);
        self.sender_count += 1;
        frames
    }

    /// Reassemble `frames` and route each completed packet into `node` as arriving on
    /// `iface`. Quiet transfers expire and broken ones release their slot — a driver's job.
    pub fn deliver<
        'a,
        const CONNS: usize,
        const BUFS: usize,
        const BUFSZ: usize,
        const PORTS: usize,
        const QF: usize,
        const RXQ: usize,
    >(
        &mut self,
        node: &mut Node<'a, CONNS, BUFS, BUFSZ, PORTS, QF, RXQ>,
        frames: &[CanFrame],
        iface: u8,
        now_ms: u32,
    ) {
        let mut buf = [0u8; 512];
        self.pool.expire(now_ms, 1000);
        for (id, data) in frames {
            let key = K::key(*id);
            let Some(re) = self.pool.get_or_create(key, now_ms) else {
                continue;
            };
            match K::push(re, *id, data, &mut buf) {
                Ok(Some((hdr, n))) => {
                    self.pool.release(key);
                    let mut v = vec![0u8; K::HDR + n];
                    hdr.encode(K::VERSION, &mut v)
                        .expect("a header the port emitted");
                    v[K::HDR..].copy_from_slice(&buf[..n]);
                    inject(node, K::VERSION, iface, &v);
                }
                Ok(None) => {}
                Err(_) => self.pool.release(key),
            }
        }
    }
}
