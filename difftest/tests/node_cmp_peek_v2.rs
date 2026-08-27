//! CMP `PEEK_V2` / `POKE_V2` — the 64-bit-address memory codes — against a real C node.
//!
//! # Nothing had ever driven them
//!
//! The 32-bit `PEEK`/`POKE` have seven corpus records and a bounded memory region in
//! `ctest/`. The 64-bit codes had neither: measured on this branch, `csp_cmp_peek_v2`,
//! `csp_cmp_poke_v2`, `csp_cmp_memread64` and `csp_cmp_memwrite64` were called by no
//! harness, and no corpus case names v2.
//!
//! # The reply was three bytes short, and a stock client refuses it
//!
//! `CMP_VARIABLE_SIZE` rounds a CMP payload up to a multiple of four. For the v2 struct the
//! payload is nine bytes (8-byte address + length), so `CMP_PEEK_V2_SIZE(len)` is
//! `11 + 3 + len`. `Peek::encode` implements that rule for the 32-bit codes, with a doc
//! comment saying why — *"the port emits the same wire length so a C peer sees the size it
//! expects"* — and `PeekV2::encode` did not. Measured, a four-byte peek:
//!
//! ```text
//! C:    ff 08 | 10 00 00 00 ef be 00 00 | 04 | 20 21 22 23 | 00 00 00     18 bytes
//! port: ff 08 | 00 00 be ef 00 00 00 10 | 04 | 20 21 22 23               15 bytes
//! ```
//!
//! That is not cosmetic. `csp_cmp_peek_v2` asks `csp_cmp` for a reply of exactly
//! `CMP_PEEK_V2_SIZE(len)`, and `csp_transaction_persistent` refuses any other length
//! (`csp_io.c:352`). A ground station could not peek a node running this port at all — the
//! reply arrived and was thrown away. The last assertion here is that refusal, driven
//! through libcsp's own client.
//!
//! # The address field is echoed differently, and that one stays
//!
//! `csp_cmp_peek_v2_handler` does `cmp->vaddr = htobe64(cmp->vaddr)` **in place** and never
//! converts back, so the reply carries the address in the *host's* byte order — which a
//! same-endian client casting the struct reads back correctly, and nobody else does. A
//! sans-io `no_std` library cannot know a peer's endianness, so the port echoes the address
//! as it arrived, big-endian. Asserted as a divergence below rather than emulated.

use csp::{Config, CspStorage, Node, Outbound, Routed};
use csp_core::{Id, Version};
use difftest::*;

const VERSION: Version = Version::V2;
const C_ADDR: u16 = 9;
const R_ADDR: u16 = 10;
const NETMASK: u16 = 12;
const HDR: usize = 6;

const PEEK_V2: u8 = 8;
const POKE_V2: u8 = 9;
/// `CSP_CMP_PEEK_V2_MAX_LEN`.
const V2_MAX: u8 = 196;
/// `sizeof(struct csp_cmp_peek_v2_msg)` — type, code, 8-byte address, length.
const V2_HEADER: usize = 11;
/// The padding `CMP_VARIABLE_SIZE` rounds up to.
const V2_TAIL: usize = 3;
/// `CMP_PEEK_V2_SIZE(len)`.
fn v2_size(len: usize) -> usize {
    V2_HEADER + V2_TAIL + len
}

/// The region both stacks answer from, filled identically.
fn region() -> Vec<u8> {
    (0..256u32).map(|i| 0x10u8.wrapping_add(i as u8)).collect()
}

struct MemHooks {
    base: u64,
    mem: Vec<u8>,
}

impl MemHooks {
    fn slice(&self, addr: u64, n: usize) -> Option<core::ops::Range<usize>> {
        let off = usize::try_from(addr.checked_sub(self.base)?).ok()?;
        let end = off.checked_add(n)?;
        (end <= self.mem.len()).then_some(off..end)
    }
}

impl csp::hooks::Hooks<24, 300> for MemHooks {
    fn mem_read(&self, addr: u64, out: &mut [u8]) -> csp_core::Result<()> {
        let r = self
            .slice(addr, out.len())
            .ok_or(csp_core::Error::AddressRefused { addr })?;
        out.copy_from_slice(&self.mem[r]);
        Ok(())
    }
    fn mem_write(&mut self, addr: u64, data: &[u8]) -> csp_core::Result<()> {
        let r = self
            .slice(addr, data.len())
            .ok_or(csp_core::Error::AddressRefused { addr })?;
        self.mem[r].copy_from_slice(data);
        Ok(())
    }
}

/// A `PEEK_V2`/`POKE_V2` request body, `total` bytes long.
fn request(code: u8, addr: u64, len: u8, total: usize, data: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; total];
    v[0] = 0x00; // CSP_CMP_REQUEST
    v[1] = code;
    v[2..10].copy_from_slice(&addr.to_be_bytes());
    v[10] = len;
    let n = data.len().min(total.saturating_sub(V2_HEADER));
    v[V2_HEADER..V2_HEADER + n].copy_from_slice(&data[..n]);
    v
}

fn framed(body: &[u8]) -> Vec<u8> {
    let id = Id {
        pri: 2,
        flags: 0,
        src: R_ADDR,
        dst: C_ADDR,
        dport: csp_core::ports::CMP,
        sport: 40,
    };
    let mut v = vec![0u8; HDR + body.len()];
    id.encode(VERSION, &mut v).unwrap();
    v[HDR..].copy_from_slice(body);
    v
}

/// The reply bodies a port node produces for `body`, and the region afterwards.
fn port_serve(body: &[u8], base: u64) -> (Vec<Vec<u8>>, Vec<u8>) {
    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: Node<'_, 8, 24, 300, 64, 8, 8> =
        Node::new(&storage, Config::new(VERSION).address(C_ADDR));
    node.ifaces.add("test", C_ADDR, NETMASK, true).unwrap();
    node.bind(csp_core::ports::CMP).unwrap();

    let mut p = node.packet().expect("pool");
    p.set_frame(VERSION, &framed(body)).expect("frame");
    node.router.receive(p, 0);

    let identity = node.identity();
    let mut hooks = MemHooks {
        base,
        mem: region(),
    };
    let mut replies = Vec::new();
    loop {
        match node.work(0) {
            Routed::Delivered { conn, .. } => {
                while let Ok(Some(pkt)) = node.read(conn) {
                    let mut out = [0u8; 256];
                    let n = pkt.with_payload(|got| {
                        let q = csp_core::cmp::parse_request(got).ok()?;
                        csp::service::respond_cmp(q, &identity, VERSION, &mut hooks, &mut out)
                            .ok()
                            .flatten()
                    });
                    if let Some(n) = n {
                        let mut reply = node.packet().expect("pool");
                        reply.set_payload(&out[..n]).unwrap();
                        match node.reply_to(&pkt, reply) {
                            Ok(Outbound::Transmit { mut packet, .. }) => {
                                packet.prepend_header(VERSION).unwrap();
                                replies.push(packet.with_frame(|f| f[HDR..].to_vec()));
                            }
                            other => panic!("the reply did not reach a wire: {other:?}"),
                        }
                    }
                    drop(pkt);
                }
            }
            Routed::Idle => break,
            _ => continue,
        }
    }
    (replies, hooks.mem)
}

/// The reply bodies a real C node produces for `body`.
fn c_serve(body: &[u8]) -> Vec<Vec<u8>> {
    c_node_serve(&framed(body), csp_core::ports::CMP)
        .into_iter()
        .map(|f| f[HDR..].to_vec())
        .collect()
}

/// Both stacks answer a `PEEK_V2` with the same length, the same bytes and the same tail.
///
/// The address field is compared separately: it is the one place they differ, and the
/// difference is asserted so it cannot change silently.
#[test]
fn a_peek_v2_reply_is_the_length_and_the_bytes_a_real_node_sends() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(
        c_node_init(VERSION, C_ADDR, NETMASK, 20, 40),
        "C node came up at v2"
    );
    assert_eq!(c_node_bind(csp_core::ports::CMP), 0, "bind the CMP port");
    c_mem_fill(0x10, 1);
    let base = c_mem_base();

    for (len, total) in [
        (4usize, v2_size(4)),
        // The request that does not carry room for its own reply data. `csp_cmp_check_len`
        // passes on the fixed part alone, so a real node answers this one too.
        (4, V2_HEADER),
        (1, v2_size(1)),
    ] {
        let body = request(PEEK_V2, base + 16, len as u8, total, &[]);
        let c = c_serve(&body);
        let (port, _) = port_serve(&body, base);

        assert_eq!(c.len(), 1, "the C answers len {len} total {total}");
        assert_eq!(port.len(), 1, "and so does the port");
        let (c, port) = (&c[0], &port[0]);

        assert_eq!(
            port.len(),
            v2_size(len),
            "the port's reply must be CMP_PEEK_V2_SIZE({len})"
        );
        assert_eq!(c.len(), port.len(), "which is what the C sends");
        assert_eq!(
            (c[0], c[1]),
            (0xFF, PEEK_V2),
            "a reply carrying the code it answers"
        );
        assert_eq!((port[0], port[1]), (c[0], c[1]));
        assert_eq!(
            port[10], c[10],
            "the declared length is echoed the same way"
        );
        assert_eq!(
            &port[V2_HEADER..],
            &c[V2_HEADER..],
            "and the bytes read, plus the zeroed tail, are identical"
        );
        // Not vacuous: the payload really is the region's contents at that offset.
        assert_eq!(
            &port[V2_HEADER..V2_HEADER + len],
            &region()[16..16 + len],
            "the peek returns the region, not zeros"
        );

        // The one divergence. The C leaves the address in host byte order; the port echoes
        // it as it arrived.
        assert_eq!(
            &port[2..10],
            &(base + 16).to_be_bytes(),
            "the port echoes the address big-endian, as it arrived"
        );
        assert_ne!(
            &port[2..10],
            &c[2..10],
            "and the C does not -- htobe64 in place, never converted back (deliberate, \
             SCOPE.md 33)"
        );
    }

    // Above the maximum, neither answers.
    let body = request(PEEK_V2, base, V2_MAX + 1, v2_size(V2_MAX as usize + 1), &[]);
    assert_eq!(
        c_serve(&body).len(),
        0,
        "the C refuses more than the maximum"
    );
    assert_eq!(port_serve(&body, base).0.len(), 0, "and so does the port");
}

/// A `POKE_V2` writes the same bytes to the same place in both stacks.
#[test]
fn a_poke_v2_writes_what_a_real_node_writes() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(VERSION, C_ADDR, NETMASK, 20, 40));
    assert_eq!(c_node_bind(csp_core::ports::CMP), 0);
    c_mem_fill(0x10, 1);
    let base = c_mem_base();

    const AT: u32 = 32;
    let payload = [0xDEu8, 0xAD, 0xBE, 0xEF];
    let body = request(
        POKE_V2,
        base + AT as u64,
        payload.len() as u8,
        v2_size(payload.len()),
        &payload,
    );

    assert_eq!(c_serve(&body).len(), 1, "the C acknowledges the poke");
    assert_eq!(
        c_mem_read(AT, payload.len()).as_deref(),
        Some(&payload[..]),
        "and the bytes are in the C's memory"
    );

    let (replies, mem) = port_serve(&body, base);
    assert_eq!(replies.len(), 1, "and so does the port");
    assert_eq!(
        &mem[AT as usize..AT as usize + payload.len()],
        &payload,
        "with the same bytes in the same place"
    );
    // The rest of the region is untouched — a poke that wrote everywhere would pass above.
    assert_eq!(
        &mem[..AT as usize],
        &region()[..AT as usize],
        "and nothing before it moved"
    );
}

/// libcsp's own client accepts the port's reply, and refuses the length it used to send.
///
/// This is what makes the three missing bytes a defect rather than a detail:
/// `csp_cmp_peek_v2` asks for exactly `CMP_PEEK_V2_SIZE(len)` and
/// `csp_transaction_persistent` refuses anything else, so the old reply arrived at a ground
/// station and was discarded.
#[test]
fn a_stock_client_accepts_the_ports_reply_and_refuses_the_old_one() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(VERSION, C_ADDR, NETMASK, 20, 40));
    c_mem_fill(0x10, 1);
    let base = c_mem_base();

    const LEN: usize = 4;
    let body = request(PEEK_V2, base + 16, LEN as u8, v2_size(LEN), &[]);
    let (replies, _) = port_serve(&body, base);
    let reply = &replies[0];
    assert_eq!(reply.len(), v2_size(LEN));

    let want = v2_size(LEN) as i32;
    let (ret, got) = c_client_transaction(R_ADDR, csp_core::ports::CMP, reply, want);
    assert_eq!(
        ret, want,
        "libcsp's own transaction accepts the port's reply whole"
    );
    assert_eq!(&got[V2_HEADER..], &reply[V2_HEADER..], "bytes and all");

    // The length it used to send: the same reply without the tail.
    let short = &reply[..V2_HEADER + LEN];
    let (ret, _) = c_client_transaction(R_ADDR, csp_core::ports::CMP, short, want);
    assert_eq!(
        ret, 0,
        "and refuses the three-bytes-short reply the port used to send"
    );
}
