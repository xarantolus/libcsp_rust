# The API

Two crates. `csp-core` is pure protocol — codecs and state machines, no I/O, no clock, no
allocation. `csp` is the node built on it.

Both are `#![no_std]` and `#![forbid(unsafe_code)]`. **Zero `unsafe`, zero `static mut`,
zero raw pointers, zero `extern "C"` in the shipped crates.** They build for
`thumbv7em-none-eabihf` with no allocator.

## Starting a node

Storage is caller-owned, sized by const generics, so `no_std` needs no allocator:

```rust
use csp::{Config, CspStorage, Node};
use csp_core::Version;

// connections, buffers, buffer size, ports, queued packets, interfaces
// the flight configuration is <16, 64, 264, 48, 100, 4>
let storage = CspStorage::<8, 16, 264, 48, 32>::new();
let mut node: Node<8, 16, 264, 48, 32, 4> = Node::new(&storage, Config::new(Version::V1)
    .address(11)
    .hostname("move-iiia-adcs"));
```

`hostname`, `model` and `revision` are what a CMP `IDENT` request is answered with; reach
them as a set with `node.identity()`, which is what `service::respond_cmp` takes.

`Node::new` cannot fail and can be called once per storage. `csp_init()` is once per
*process* — it returns `CSP_ERR_INVAL` on a second call, because libcsp's state is ~38
file-scope statics. Two nodes with different addresses **and different wire versions**
coexisting is a test in this crate.

The wire version is fixed at construction. There is deliberately no setter: in the C it is
a mutable global that is silently init-only, and changing it after `csp_init()` leaks one
buffer per fragment sent until the pool empties.

## Packets

```rust
let mut p = node.packet().ok_or("pool exhausted")?;
p.set_id(Id { pri: 2, flags: 0, src: 11, dst: 8, dport: 20, sport: 10 });
p.set_payload(b"telemetry")?;
p.with_payload(|bytes| println!("{} bytes", bytes.len()));
```

A `Packet` is a handle carrying a **slot index**. It releases on `Drop`. There is no
`csp_buffer_free` to forget, and no way to free twice.

`frame_begin` is a `u16` **offset**, not a pointer into the packet's own array — so a
packet can be moved, and copying is exact rather than needing the pointer recomputed
afterwards. The refcount is an `AtomicU8`, not an `unsigned int` written from both ISR and
task context.

## Ports that accept either shape

The API's most important difference. A port does not declare in advance whether it wants a
datagram or a stream:

```rust
match Delivery::classify(first_packet, &mut connection) {
    Delivery::Datagram(packet) => {
        packet.with_payload(handle_request)      // whole message, one packet
    }
    Delivery::Stream(mut stream) => {
        let mut buf = [0u8; 1024];
        let n = stream.read_to_slice(1000, &mut buf)?;
        handle_request(&buf[..n])
    }
}
```

The `FRAG` bit decides it, and it is a **per-packet** header flag, so it is known from the
first packet. It becomes the `Delivery` you match on.

> **RDP is server-side only.** The node answers a handshake, acknowledges data and hands
> the payload up with its trailer removed — a peer can open an RDP connection *to* this
> node, and `Routed::Respond` is how the control frames reach the wire. It cannot yet open
> one *itself*: `Node::connect` refuses `RDP_REQ` with `Error::Unsupported` rather than
> setting a flag it will not honour. When it lands, it will be the second axis here:
> reliability changes *how* you read, and is known at accept.

Classifying costs one packet peek and **consumes nothing**. A narrow handler that gets the
wrong shape gets the delivery *back*:

```rust
let back = delivery.into_stream().unwrap_err();   // it was a datagram
let packet = back.into_datagram().ok().unwrap();  // still intact
```

In the C this case is destructive: `csp_sfp_header_remove` returns NULL the moment `FRAG`
is clear and its caller frees the packet, so a plain datagram sent to a stream port is
destroyed and the sender sees `-103 CSP_ERR_SFP` — "SFP problem", not "that port wanted
fragments".

`Stream` offers both shapes a real service needs:

```rust
stream.total_len()                              // known from fragment one
stream.read_chunk(timeout, |chunk, off, tot| …) // bounded memory — for a log dump
stream.read_to_slice(timeout, &mut buf)         // whole message, or BufferTooSmall{needed}
```

`read_to_slice` reports the size it needed. The C's flat receive sets an overflow flag the
caller must remember to check.

## Interfaces

```rust
struct MyRadio { /* … */ }

impl Transmit<'_, N, SZ> for MyRadio {
    fn transmit(&mut self, via: u16, packet: &Packet<'_, N, SZ>) -> Result<()> {
        packet.with_frame(|bytes| self.send_bytes(bytes))
    }
}

let mut iface = Interface::new("RADIO", 11, 5, MyRadio::new()).default_route();
iface.send(node.version(), 8, &mut packet)?;
```

`transmit` **borrows** the packet. The C's rule — the nexthop owns it on success and must
not free it on failure — is undocumented and uncheckable; getting it backwards double-frees
and getting it wrong the other way leaks. Here the caller frees, always.

`Interface::send` prepends the header before calling the driver. In the C that is the
driver's job, and a driver that forgets transmits a zero-length frame. (This bit the
golden-vector oracle in this repository: its capture interface skipped the prepend and
recorded 92 empty SFP frames that looked plausible.)

Typed driver state, not `void *`. `csp_iface_t` carries `void * interface_data` and
`void * driver_data` that every implementation casts back to its own type — 76 of
`c2rust-analyze`'s 190 unsupported casts were exactly these, because the type information
was thrown away by design.

## Errors say what went wrong

```rust
pub enum Error {
    BufferTooSmall { needed: usize },
    Truncated,
    FieldOutOfRange { field: Field },
    BadChecksum,
    TableFull,
    NotAFragment,
    UnexpectedOffset { expected: u32, got: u32 },
    InconsistentTotal { expected: u32, got: u32 },
    OffsetBeyondTotal { offset: u32, total: u32 },
    EmptyFragment,
    ZeroTotal,
    NoTransferInProgress,
    IdentMismatch { expected: u16, got: u16 },
    ZeroMtu,
    EmptyKey,
    LengthExceedsMaximum { got: usize, max: usize },
    InvalidRoute { reason: RouteError },
}
```

No catch-all variant. libcsp returns `CSP_ERR_INVAL` (-2) or `CSP_ERR_SFP` (-103) for a
dozen unrelated causes, which is why the flight code carries comments guessing at what a
return code meant. A caller here can always separate three things:

- **the peer sent nonsense** — `Truncated`, `BadChecksum`, `UnexpectedOffset`, …
- **I called this wrong** — `FieldOutOfRange`, `ZeroMtu`, `TableFull`
- **retry differently** — `BufferTooSmall` carries the size; `NotAFragment` means "deliver
  this as a datagram instead"

## `csp-core` — usable on its own

Everything below is a pure function. Useful without a node at all — the ground station
tooling in this repository hand-rolled the header codec **three times** because libcsp
exposes none.

| Module | What |
|---|---|
| `id` | CSP v1 + v2 header codec |
| `crc32` | CRC-32C, with `Coverage` explicit |
| `sha1`, `hmac` | SHA-1, HMAC-SHA1 (4-byte wire tag) |
| `kiss` | KISS framing — encoder plus a byte-at-a-time `Decoder` |
| `sfp` | Fragment codec, `Fragmenter`, `Reassembler` |
| `cfp` | CAN fragmentation, both CFP1 and CFP2 |
| `cmp` | Management protocol, **both directions** — the C has no decoder |
| `rtable` | CIDR table plus a hand-written route parser (no `sscanf`, no VLA) |
| `rdp` | Reliable delivery as `fn step(&mut self, event, now) -> Action` |
| `eth` | Ethernet + EFP segmentation |

`crc32::Coverage` is explicit because the C's verifier tries header-and-payload, then
silently falls back to payload-only — so a receiver can accept a frame whose checksum
covers different bytes than it believes. (For the record, `CSP_21` is defined by no build
system in the tree, so the header is never covered. The KISS golden vectors only match
byte-for-byte under `Coverage::PayloadOnly`, which settles it empirically.)

RDP options are **per connection** in `csp-core::rdp`. The C keeps its six RDP tunables in
file statics shared by every connection, so two connections with different timeouts are not
expressible there. (This is a property of the core type; the node uses the defaults for connections a peer opens.)

## The router

```rust
let mut router: Router<CONNS, RXQ, PORTS, QFIFO> = Router::new(address, version);
router.bind(20)?;

loop {
    match router.work(&pool, &ifaces, now_ms()) {
        Routed::Idle => { /* ordinary — csp_route_work returns an ERROR here */ }
        Routed::Delivered { port, conn } => dispatch(port, conn),
        // `packet` is the pool slot holding the frame, and it is now yours: claim it with
        // `Node::take_forwarded` and put it on the wire. An earlier version of this enum
        // carried only `iface` and `via`, which left the router no way to hand the packet
        // over — so it dropped it, and the node forwarded nothing at all.
        Routed::Forwarded { iface, via, packet } => send_on(iface, via, packet),
        Routed::Dropped(why) => log(why),
    }
    router.tick(&pool, now_ms(), conn_timeout);   // idle connection expiry
}
```

`Routed::Dropped` always says *why*: `Duplicate`, `NoRoute`, `PortNotBound`,
`ConnectionTableFull`, `ReceiveQueueFull`, `Malformed`. The C reports several of those
through one `uint8_t` counter that wraps at 256 and is written from ISR and task context
without synchronisation.

`Router::tick` is not optional: nothing else reclaims idle connections, and connection
slots are the scarcest resource on a node (8 by default, 16 in flight). It is also where
RDP's timers will be advanced, since the state machine reads no clock on purpose.

`Router::bridge_work(pool, a, b, now)` is the transparent bridge. A frame arriving on an
interface that is neither side is **refused**; the C's `if/else` has no third branch and
injects it into side A.

## Routing: a packet has destinations, plural

`csp_send_direct` does not pick one destination. It collects **every** routing-table entry
tied for the longest prefix and sends a clone to each, the last getting the original; if no
route matched, it does the same over every interface marked as a default. Redundant links
and broadcast-to-all-interfaces are both configured that way, so an API that resolves to
one destination silently makes both single-path.

```rust
let dests = node.resolve(dst, routed_from)?;   // Err(Unroutable::NoRoute | ::SplitHorizon)
for d in dests.as_slice() {
    // d.iface, d.via -- a named struct, because two small unsigned integers in a tuple
    // are one destructuring away from routing every packet to the wrong place
}
// dests.clones_needed() copies, then the original for the last
```

`route_from` keeps the single-destination shape for the common case and returns the first.

`resolve`, `Router::forward` and the RDP reply path are all one function —
`route_policy::destinations`. They were three copies, and the duplication cost three
defects before it was removed; see *One routing policy, not three* in `SCOPE.md`.

It follows `csp_send_direct`'s order: an interface whose **subnet owns** the
destination, then the routing table, then the defaults. Each stage that matches suppresses
the ones after it — even when split horizon leaves the match unusable — because the C
returns as soon as `local_found` or `route_found` is set. Skipping the subnet stage sends
locally-attached traffic out a default link instead of the link it is attached to.

**Split horizon** applies to all three: a destination on the interface the packet arrived
on is skipped, or a forwarded packet goes straight back where it came from.

Each `Destination` carries a `dst`, which is not always the address you asked for.
`convert_broadcast` turns a routed (L3) broadcast into the local (L2) one — the maximum
node id — as it reaches the interface, so a peer whose subnet is masked differently still
recognises it. The rewrite is **sticky across a fan-out**: `csp_send_direct` keeps one
`idout_copy` for the whole loop and only ever writes to it, so two interfaces owning a
destination that is the broadcast of only the first put the rewritten address on both
wires. That is measured, not inferred — `corpus/ctest.jsonl` records `[16383, 16383]`.

Note how this composes with `IfList::check_default` (`csp_iflist_check_dfl`): if nothing is
marked as a default, **every** interface except loopback becomes one. A node with no routes
and no configured default therefore floods every packet onto every link. That is libcsp's
intent for a zero-config node; it is not what the code looks like it does.

## Connections

`node.conn_info(handle)` returns src, dst, dport, sport and opts in **one** fallible
lookup. The C has five separate calls (`csp_conn_dst`, `csp_conn_src`, `csp_conn_dport`,
`csp_conn_sport`, `csp_conn_flags`) and the port mirrored them; a caller logging a
connection made and unwrapped all five. The individual accessors remain for the cases that
want one field.

Handles are generation-tagged. Closing a connection and opening a new one recycles the
index, so a caller holding the old handle would otherwise operate on someone else's
connection — the use-after-free a raw `csp_conn_t *` invites. A stale handle returns
`Error::NoTransferInProgress`.

## Built-in services, including CMP

Neither this crate nor libcsp serves the built-in ports by itself. The C's application
calls `csp_service_handler(packet)` from its own receive loop
(`libcsp/examples/csp_server.c:77`); here it classifies with `service::Request::decode` and
answers with `service::respond`, or `service::respond_cmp` for port 0.

```rust
match Request::decode(dport, payload)? {
    Request::Cmp => {
        let query = csp_core::cmp::parse_request(payload)?;
        service::respond_cmp(query, &node.identity(), node.version(), &mut hooks, out)?
    }
    req => service::respond(req, payload, &status, out)?,
}
```

`Ok(None)` means **send nothing**, and it is how every refusal is answered: an unknown
interface, a route the node will not install, a clock it could not set, a memory window the
application does not expose, a process list it cannot produce. That is the C's `goto
discard` in `csp_service_handler`, and it is deliberate — a peer cannot tell "refused" from
"not listening" without a timeout, and the port does not volunteer the difference.

The parts a CMP request can reach that are not the node's own — interface counters, the
routing table, the clock, node memory — come from [`Hooks`], and **every one of them
defaults to refusing**. `csp_cmp_route_set_v2_handler` installs whatever an unauthenticated
peer asks for, which is one packet away from pointing a node's default route at an
interface that goes nowhere; there is then no route left to be told otherwise over.

## Compile-time invariants

Anything the code *relies* on is an assertion, not a comment:

```rust
let _: Pool<4, 4> = Pool::new();
// error: buffer size must exceed the header padding; see pool::PADDING
```

`Pool` requires `SZ > PADDING` and `N > 0`; `Qfifo`, `conn::Table` and `rtable::Table`
require non-zero capacity; `Router` requires `PORTS` in `1..=256`. Everything a caller can
get wrong at *runtime* stays in the error enum.

## Testing

Every number here is printed by **`just numbers`**, which measures rather than remembers.
Three of them were wrong before that target existed — "449 tests" against 487 and "19
differential tests" against 33 had simply drifted, but **"922 golden vectors" never
matched anything measurable**: the vector files have never held more than 510 non-comment
lines, at any commit that touched them, and no count the tests print comes to 922 either.
It was carried in two documents. A coverage figure nobody can reproduce is the exact shape
of the claim that hid a third of the library. Run `just numbers` before changing any figure
below.

- **487 tests** across the crates, in 10 binaries, with `--all-features`.
- **510 golden vector lines** in `vectors/v{1,2}.tsv`, captured from the running C library
  — real wire bytes, after `csp_id_prepend`, after SFP headers, after CFP fragmentation.
  Each line carries several assertions; the tests print what they checked (`140 header
  decodes`, `36 sfp transfers, 184 fragments`, and so on).
- **113 corpus records** in `corpus/ctest.jsonl`, each one an exchange a real libcsp node
  performed under `ctest/`'s **135 checks**, replayed against the port. `just mutants`
  reports how many of them some deliberate breakage can actually move — 79 at the time of
  writing — and names the rest.
- **33 differential tests** in `difftest/`, millions of random inputs per run, linking the
  real C and comparing. Dev-only: the shipped crates contain no C. They cover the header
  codec, CRC32, SHA-1, HMAC, both CFP identifier layouts, the route-table parser and
  lookups, and the real `csp_kiss_rx` state machine.
- Every module carries a written audit in `AUDIT.md` rating it against the C
  function by function, and every intentional divergence is numbered in `SCOPE.md`.

Deliberate divergences are asserted **as divergences**, so a regression back toward C
behaviour fails rather than passes.

Every random generator carries an assertion on how much of its output actually reached the
code under test. Two versions of the KISS fuzz test passed while exercising nothing —
`CSP_ENABLE_KISS_CRC` is on by default, so random bytes are rejected essentially always —
and the coverage assertion is what caught it.
