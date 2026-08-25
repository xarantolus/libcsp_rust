# The API

Two crates. `csp-core` is pure protocol — codecs and state machines, no I/O, no clock, no
allocation. `csp` is the node built on it.

Both are `#![no_std]` and `#![forbid(unsafe_code)]`. **Zero `unsafe`, zero `static mut`,
zero raw pointers, zero `extern "C"` in the shipped crates.** They build for
`thumbv7em-none-eabihf` with no allocator.

## Starting a node

Storage is caller-owned, sized by const generics, so `no_std` needs no allocator:

```rust
use csp::{Csp, CspStorage, Config};
use csp_core::Version;

// connections, buffers, buffer size, ports, queued packets
// the flight configuration is <16, 64, 264, 48, 100>
let storage = CspStorage::<8, 16, 264, 48, 32>::new();
let node = Csp::new(&storage, Config::new(Version::V1)
    .address(11)
    .hostname("move-iiia-adcs"));
```

`Csp::new` cannot fail and can be called once per storage. `csp_init()` is once per
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

Two independent axes decide this, both self-describing on the wire:

| Axis | Signal | Known at | Affects |
|---|---|---|---|
| **RDP** | `RDP` bit, a connection option negotiated in the handshake | accept | *how* you read |
| **SFP** | `FRAG` bit, a **per-packet** header flag | first packet | *what the payload is* |

RDP is absorbed by the library and never reaches the handler, so all four combinations
behave identically from a handler's point of view. SFP becomes the `Delivery` you match on.

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

`crc32::Coverage` is explicit because the C's verifier tries header-and-payload, then
silently falls back to payload-only — so a receiver can accept a frame whose checksum
covers different bytes than it believes. (For the record, `CSP_21` is defined by no build
system in the tree, so the header is never covered. The KISS golden vectors only match
byte-for-byte under `Coverage::PayloadOnly`, which settles it empirically.)

RDP options are **per connection**. The C keeps its six RDP tunables in file statics shared
by every connection, so two connections with different timeouts are not expressible there.

## Testing

- **178 tests** across both crates.
- **922 golden vectors** captured from the running C library — real wire bytes, after
  `csp_id_prepend`, after SFP headers, after CFP fragmentation.
- **10 differential tests** in `difftest/`, ~2.4M random inputs per run, linking the real C
  and comparing. Dev-only: the shipped crates contain no C.

Deliberate divergences are asserted **as divergences**, so a regression back toward C
behaviour fails rather than passes.
