//! **libcsp's own `csp_cmp_peek` and `csp_cmp_poke`** — the 32-bit-address memory codes —
//! reading and writing the port's memory.
//!
//! # Why this one
//!
//! `node_cmp_peek_v2.rs` drives the 64-bit codes through a real `csp_transaction` and found
//! a reply three bytes short. The 32-bit codes — the ones every pre-v2 ground tool speaks —
//! had seven corpus records for the *server* side and no C client at all. `csp_cmp_peek`
//! asks `csp_cmp` for a reply of exactly `CMP_PEEK_SIZE(len)` = `10 + len`, and
//! `csp_transaction_persistent` refuses any other length (`csp_io.c:352`), so the length
//! rule is only evidenced by a client that waits.
//!
//! # The address echo
//!
//! `csp_cmp_peek_handler` (`csp_cmp_peek_poke.c:16`) does `cmp->addr = htobe32(cmp->addr)`
//! in place and never converts back, so a C node's reply carries the address in the host's
//! byte order. The port echoes it as it arrived — big-endian — for the reason
//! `node_cmp_peek_v2.rs` gives: a sans-io library cannot know a peer's endianness. The
//! client reads that field back as the bytes it wrote, which this test pins.

use csp::{Config, CspStorage, Node, Outbound, Routed};
use csp_core::Version;
use difftest::*;

const VERSION: Version = Version::V2;
const C_ADDR: u16 = 9;
const R_ADDR: u16 = 10;
const NETMASK: u16 = 12;
const EGRESS_ADDR: u16 = 20;
const THIRD_ADDR: u16 = 40;

/// Where the port's peekable region lives. Fits 32 bits and differs in every byte.
const BASE: u32 = 0x8A1B_2C00;
const REGION_LEN: usize = 64;
/// `CMP_PEEK_SIZE(len)`: `sizeof(struct csp_cmp_peek_msg)` (7) + 3 bytes of tail + data.
const fn peek_size(len: usize) -> usize {
    7 + 3 + len
}

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;

/// The integrator's memory: one bounded region. Anything outside it is refused.
struct Region {
    mem: Vec<u8>,
}

impl Region {
    fn new() -> Self {
        Region {
            mem: (0..REGION_LEN as u8).map(|i| 0x30 + i).collect(),
        }
    }

    fn slice(&self, addr: u64, n: usize) -> Option<core::ops::Range<usize>> {
        let off = addr.checked_sub(BASE as u64)? as usize;
        (off + n <= self.mem.len()).then_some(off..off + n)
    }
}

impl csp::hooks::Hooks<24, 300> for Region {
    fn mem_read(&self, addr: u64, out: &mut [u8]) -> csp_core::Result<()> {
        let r = self
            .slice(addr, out.len())
            .ok_or(csp_core::Error::Truncated)?;
        out.copy_from_slice(&self.mem[r]);
        Ok(())
    }

    fn mem_write(&mut self, addr: u64, data: &[u8]) -> csp_core::Result<()> {
        let r = self
            .slice(addr, data.len())
            .ok_or(csp_core::Error::Truncated)?;
        self.mem[r].copy_from_slice(data);
        Ok(())
    }
}

/// Serve one CMP request and return the reply frames, which may be none.
fn serve(node: &mut TestNode, request: &[u8], hooks: &mut Region) -> Vec<Vec<u8>> {
    let mut p = node.packet().expect("pool");
    p.set_frame(VERSION, request)
        .expect("the C client's own frame");
    node.router.receive(p, 0);

    let identity = node.identity();
    let mut replies = Vec::new();
    loop {
        match node.work(0) {
            Routed::Delivered { conn, .. } => {
                while let Ok(Some(pkt)) = node.read(conn) {
                    let mut out = [0u8; 256];
                    let answered = pkt.with_payload(|body| {
                        let q = csp_core::cmp::parse_request(body).ok()?;
                        csp::service::respond_cmp(q, &identity, VERSION, hooks, &mut out)
                            .ok()
                            .flatten()
                    });
                    let Some(n) = answered else {
                        drop(pkt);
                        continue;
                    };
                    let mut reply = node.packet().expect("pool");
                    reply.set_payload(&out[..n]).unwrap();
                    match node.reply_to(&pkt, reply) {
                        Ok(Outbound::Transmit { mut packet, .. }) => {
                            packet.prepend_header(VERSION).unwrap();
                            replies.push(packet.with_frame(|f| f.to_vec()));
                        }
                        other => panic!("the reply did not reach a wire: {other:?}"),
                    }
                    drop(pkt);
                }
            }
            Routed::Idle => break,
            _ => continue,
        }
    }
    replies
}

fn fresh<'a>(storage: &'a CspStorage<8, 24, 300, 64, 8>) -> TestNode<'a> {
    let mut node: TestNode = Node::new(storage, Config::new(VERSION).address(R_ADDR));
    node.ifaces.add("test", R_ADDR, NETMASK, true).unwrap();
    node.bind(csp_core::ports::CMP).unwrap();
    node
}

/// The CMP body of a v2 frame: after the 6-byte header, before the 4-byte CRC32 `csp_cmp`
/// asks for.
fn cmp_body(frame: &[u8]) -> &[u8] {
    &frame[6..frame.len() - 4]
}

#[test]
fn libcsps_own_peek_client_reads_the_ports_memory() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(
        c_node_init(VERSION, C_ADDR, NETMASK, EGRESS_ADDR, THIRD_ADDR),
        "C node came up at v2"
    );

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node = fresh(&storage);
    let mut region = Region::new();

    const AT: u32 = 16;
    const LEN: usize = 4;
    let req = c_cmp_peek_start(R_ADDR, BASE + AT, LEN as u8);
    assert_eq!(req.len(), 1, "one request frame");
    let replies = serve(&mut node, &req[0], &mut region);
    assert_eq!(replies.len(), 1, "a peek inside the region is answered");

    let body = cmp_body(&replies[0]);
    assert_eq!(
        body.len(),
        peek_size(LEN),
        "the reply is CMP_PEEK_SIZE(len) bytes -- what csp_cmp_peek demands and \
         csp_transaction_persistent refuses to be off by one"
    );
    assert_eq!(
        &body[7 + LEN..],
        &[0, 0, 0],
        "the three alignment-tail bytes are zero, not stale pool contents"
    );

    c_node_exchange(&replies[0], &[]);
    let (addr, data) = c_cmp_peek_join().unwrap_or_else(|e| {
        panic!("libcsp refused the port's PEEK reply: {e} (CSP_ERR_TIMEDOUT is -3)")
    });
    assert_eq!(
        data,
        &region.mem[AT as usize..AT as usize + LEN],
        "the bytes at the asked address, from the asked address"
    );
    assert_eq!(
        addr,
        (BASE + AT).to_be_bytes(),
        "the address comes back as the client wrote it (big-endian). A C node would hand \
         back htobe32 of that -- host order -- and the port deliberately does not emulate \
         a peer's endianness"
    );
}

#[test]
fn libcsps_own_poke_client_writes_the_ports_memory() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(
        VERSION,
        C_ADDR,
        NETMASK,
        EGRESS_ADDR,
        THIRD_ADDR
    ));

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node = fresh(&storage);
    let mut region = Region::new();
    let before = region.mem.clone();

    const AT: u32 = 40;
    let payload = [0xDE, 0xAD, 0xBE, 0xEF, 0x01];
    let req = c_cmp_poke_start(R_ADDR, BASE + AT, &payload);
    assert_eq!(req.len(), 1, "one request frame");
    let replies = serve(&mut node, &req[0], &mut region);
    assert_eq!(replies.len(), 1, "a poke inside the region is answered");
    assert_eq!(
        cmp_body(&replies[0]).len(),
        peek_size(payload.len()),
        "CMP_POKE_SIZE(len), the same rule as peek"
    );

    c_node_exchange(&replies[0], &[]);
    let (_, echoed) = c_cmp_peek_join().expect("libcsp must accept the port's POKE reply");
    assert_eq!(echoed, &payload[..], "the reply echoes what was written");

    let at = AT as usize;
    assert_eq!(
        &region.mem[at..at + payload.len()],
        &payload[..],
        "and it was written"
    );
    assert_eq!(&region.mem[..at], &before[..at], "nothing before it moved");
    assert_eq!(
        &region.mem[at + payload.len()..],
        &before[at + payload.len()..],
        "nothing after it either"
    );
}

#[test]
fn a_peek_outside_the_region_is_silence_not_a_reply() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(
        VERSION,
        C_ADDR,
        NETMASK,
        EGRESS_ADDR,
        THIRD_ADDR
    ));

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node = fresh(&storage);
    let mut region = Region::new();

    // Starts inside, runs off the end.
    let req = c_cmp_peek_start(R_ADDR, BASE + REGION_LEN as u32 - 2, 4);
    assert_eq!(req.len(), 1, "one request frame");
    let replies = serve(&mut node, &req[0], &mut region);
    assert_eq!(
        replies.len(),
        0,
        "a refused read must send nothing: the C returns csp_cmp_memcpy's error and \
         csp_service_handler discards the reply"
    );
    assert_eq!(
        c_cmp_peek_join(),
        Err(-3),
        "libcsp must report CSP_ERR_TIMEDOUT rather than hand ground bytes it never read"
    );
}
