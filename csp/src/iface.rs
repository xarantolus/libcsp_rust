//! Interfaces: how a node gets packets onto a link.
//!
//! The C models an interface as a struct with a `nexthop` function pointer plus two
//! `void *`s (`interface_data`, `driver_data`) that every implementation casts back to its
//! own type. That is the pattern `c2rust-analyze` gave up on — 76 of its 190 unsupported
//! casts were these — because the type information was thrown away by design.
//!
//! Here an interface is a trait object or a generic, so the types survive.
//!
//! # The ownership contract, stated
//!
//! In the C, `csp_send_direct_iface` calls `nexthop` and frees the packet **only if it
//! returns an error**. So the nexthop owns the packet on success and must not free it on
//! failure — an undocumented, uncheckable rule every driver has to get right. Getting it
//! backwards double-frees; getting it wrong the other way leaks.
//!
//! [`Transmit::transmit`] takes the packet **by reference** and never takes ownership, so
//! the rule cannot be got wrong: the caller frees, always.

use crate::pool::Packet;
use csp_core::Result;

/// What happened to a packet handed to [`Interface::send`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sent {
    /// It went out on the link.
    Transmitted,
    /// It is addressed to this interface itself and must be fed back in with
    /// [`Router::receive`](crate::Router::receive) instead.
    ///
    /// `csp_can1_tx` and `csp_can2_tx` both open with this check, and it is easy to miss
    /// because the *node* address and an *interface* address are not the same thing — a
    /// node can hold several interfaces on different subnets. Without it, a packet
    /// addressed to an interface goes out on the wire and comes back, or does not come
    /// back at all.
    Loopback,
}

// I2C, UDP and LOOP need no module of their own. Each is a *datagram* interface: one CSP
// frame per link-layer frame, no segmentation, so the entire protocol logic is
// `Interface::send` (prepend the header, hand over the frame) on transmit and
// `Packet::set_frame` (decode the header, keep the payload) on receive. The C gives each
// one a file because each also owns its syscalls; here those live in the driver, which is
// the caller's.
//
// CAN and Ethernet are different in kind -- they segment, so they get csp_core::cfp and
// csp_core::eth. KISS is different again because it escapes, so it gets csp_core::kiss.

/// Statistics every interface keeps.
///
/// Plain counters. The C's equivalents are written from ISR and task context with no
/// synchronisation, which it documents as deliberate.
///
/// # `txbytes`/`rxbytes` count the frame, not the payload
///
/// The C counts `packet->length` on both sides — the **payload**, excluding the 4- or
/// 6-byte CSP header it just prepended (`csp_io.c:282`, `csp_route.c:230`). A field
/// documented as "Transmitted bytes" therefore under-reports what crossed the link by
/// `header_size` per packet, which for the 8-byte telemetry packets this fleet sends is a
/// third of the traffic. These count the framed length. Both sides use the same rule, so
/// tx and rx remain comparable.
///
/// # `irq` is never incremented
///
/// Nothing in libcsp writes `iface->irq` — not the core, not the interfaces. It is
/// declared, printed by `csp_iflist_print`, and reported over CMP `IF_STATS`
/// (`csp_cmp_if_stats.c:27`), and it is structurally always zero. It is left here because
/// a driver may fill it in, and [`Interface::note_irq`] is how.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct Stats {
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

/// The driver half of an interface: put a framed packet on the wire.
pub trait Transmit<'p, const N: usize, const SZ: usize> {
    /// Send `packet` to `via`.
    ///
    /// The packet is **borrowed**: the caller owns it and will release it, whatever
    /// happens here. `packet` has already had its header prepended, so
    /// [`Packet::with_frame`] yields the bytes to put on the link.
    fn transmit(&mut self, via: u16, packet: &Packet<'p, N, SZ>) -> Result<()>;
}

/// A registered interface: a name, an address, a netmask and its counters.
#[derive(Debug)]
pub struct Interface<T> {
    /// Name, as used by CMP `IF_STATS` and the route table text format.
    pub name: &'static str,
    /// This interface's own address on its subnet.
    pub addr: u16,
    /// Subnet prefix length.
    ///
    /// Careful: when this equals the version's `host_bits`, the node's *own* address
    /// reads as broadcast. The flight code carries a 15-line comment about this before
    /// assigning `csp_if_lo.addr`.
    pub netmask: u16,
    /// Whether this is a default route target.
    pub is_default: bool,
    /// Counters.
    pub stats: Stats,
    /// The driver.
    pub driver: T,
}

impl<T> Interface<T> {
    /// Register a driver as an interface.
    pub const fn new(name: &'static str, addr: u16, netmask: u16, driver: T) -> Self {
        Interface {
            name,
            addr,
            netmask,
            is_default: false,
            stats: Stats {
                tx: 0,
                rx: 0,
                tx_error: 0,
                rx_error: 0,
                drop: 0,
                autherr: 0,
                frame: 0,
                txbytes: 0,
                rxbytes: 0,
                irq: 0,
            },
            driver,
        }
    }

    /// Mark this interface as a default route target.
    pub const fn default_route(mut self) -> Self {
        self.is_default = true;
        self
    }

    /// True if `dst` is this interface's own address.
    ///
    /// Aliases are resolved through [`IfList`](crate::IfList), which is where they live;
    /// `csp_can2_tx` additionally consults `csp_addr_is_alias` here.
    pub const fn is_self(&self, dst: u16) -> bool {
        dst == self.addr
    }

    /// Frame and send a packet, updating the counters.
    ///
    /// Prepending the header is done here rather than left to the driver. In the C it is
    /// the interface's job and it is easy to forget — a `nexthop` that reads
    /// `frame_begin`/`frame_length` without calling `csp_id_prepend` first sees a
    /// zero-length frame and cheerfully transmits nothing.
    ///
    /// Returns [`Sent::Loopback`] for a packet addressed to this interface, which the
    /// caller must feed back in rather than transmit.
    pub fn send<'p, const N: usize, const SZ: usize>(
        &mut self,
        version: csp_core::Version,
        via: u16,
        packet: &mut Packet<'p, N, SZ>,
    ) -> Result<Sent>
    where
        T: Transmit<'p, N, SZ>,
    {
        if self.is_self(packet.id().dst) {
            return Ok(Sent::Loopback);
        }
        packet.prepend_header(version)?;
        let len = packet.with_frame(|f| f.len());
        match self.driver.transmit(via, packet) {
            Ok(()) => {
                self.stats.tx += 1;
                self.stats.txbytes += len as u32;
                Ok(Sent::Transmitted)
            }
            Err(e) => {
                self.stats.tx_error += 1;
                Err(e)
            }
        }
    }

    /// Record a received packet. `bytes` is the **framed** length, matching `txbytes`.
    pub fn note_rx(&mut self, bytes: usize) {
        self.stats.rx += 1;
        self.stats.rxbytes += bytes as u32;
    }

    /// Record a receive error: a packet that arrived but could not be used.
    pub fn note_rx_error(&mut self) {
        self.stats.rx_error += 1;
    }

    /// Record an authentication failure.
    ///
    /// Kept apart from [`note_rx_error`](Self::note_rx_error) because the two mean
    /// different things operationally: a rising `autherr` is someone talking to you who
    /// should not be, `rx_error` is usually a bad link.
    pub fn note_auth_error(&mut self) {
        self.stats.autherr += 1;
    }

    /// Record a refused packet against whichever counter it belongs to.
    ///
    /// This is the half the C leaves to each call site: `csp_route_security_check` returns
    /// an error and the *caller* picks the counter, at six separate sites in
    /// `csp_route.c`. Routing the decision through
    /// [`Refusal::counter`](csp_core::security::Refusal::counter) makes it one rule.
    pub fn note_refusal(&mut self, r: csp_core::security::Refusal) {
        match r.counter() {
            csp_core::security::Counter::AuthError => self.note_auth_error(),
            csp_core::security::Counter::RxError => self.note_rx_error(),
        }
    }

    /// Record an interrupt, for a driver that counts them.
    pub fn note_irq(&mut self) {
        self.stats.irq += 1;
    }

    /// Record a malformed frame.
    pub fn note_frame_error(&mut self) {
        self.stats.frame += 1;
    }

    /// Record a dropped packet.
    pub fn note_drop(&mut self) {
        self.stats.drop += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::Pool;
    use csp_core::{Id, Version};

    type P = Pool<4, 264>;

    /// Records what it was asked to send.
    struct Recorder {
        frames: [[u8; 64]; 4],
        lens: [usize; 4],
        n: usize,
        fail: bool,
    }

    impl Recorder {
        fn new() -> Self {
            Recorder {
                frames: [[0; 64]; 4],
                lens: [0; 4],
                n: 0,
                fail: false,
            }
        }
    }

    impl<'p> Transmit<'p, 4, 264> for Recorder {
        fn transmit(&mut self, _via: u16, packet: &Packet<'p, 4, 264>) -> Result<()> {
            if self.fail {
                return Err(csp_core::Error::Truncated);
            }
            packet.with_frame(|f| {
                self.frames[self.n][..f.len()].copy_from_slice(f);
                self.lens[self.n] = f.len();
            });
            self.n += 1;
            Ok(())
        }
    }

    fn packet<'p>(pool: &'p P) -> Packet<'p, 4, 264> {
        let mut p = pool.acquire(0).unwrap();
        p.set_id(Id {
            pri: 2,
            flags: 0,
            src: 1,
            dst: 8,
            dport: 20,
            sport: 10,
        });
        p.set_payload(b"payload").unwrap();
        p
    }

    #[test]
    fn send_frames_the_packet_before_handing_it_to_the_driver() {
        // The C leaves this to the driver, and a driver that forgets transmits nothing.
        let pool = P::new();
        let mut iface = Interface::new("TEST", 1, 5, Recorder::new());
        let mut p = packet(&pool);
        assert_eq!(
            iface.send(Version::V1, 8, &mut p).unwrap(),
            Sent::Transmitted
        );

        assert_eq!(iface.driver.n, 1);
        let len = iface.driver.lens[0];
        assert_eq!(len, 4 + 7, "header + payload, not just payload");
        assert_eq!(
            Id::decode(Version::V1, &iface.driver.frames[0][..len])
                .unwrap()
                .dst,
            8
        );
    }

    #[test]
    fn counters_follow_success_and_failure() {
        let pool = P::new();
        let mut iface = Interface::new("TEST", 1, 5, Recorder::new());

        let mut p = packet(&pool);
        iface.send(Version::V1, 8, &mut p).unwrap();
        assert_eq!(iface.stats.tx, 1);
        assert_eq!(iface.stats.txbytes, 11);
        assert_eq!(iface.stats.tx_error, 0);

        iface.driver.fail = true;
        let mut p2 = packet(&pool);
        assert!(iface.send(Version::V1, 8, &mut p2).is_err());
        assert_eq!(iface.stats.tx, 1, "a failed send is not a transmit");
        assert_eq!(iface.stats.tx_error, 1);
    }

    #[test]
    fn a_failed_transmit_does_not_take_the_packet() {
        // In the C the ownership rule is "nexthop owns it on success, must not free on
        // failure" -- undocumented and uncheckable. Here transmit borrows, so the caller
        // still holds the packet either way and the pool accounting proves it.
        let pool = P::new();
        let mut iface = Interface::new("TEST", 1, 5, Recorder::new());
        iface.driver.fail = true;
        let before = pool.available();
        {
            let mut p = packet(&pool);
            assert_eq!(pool.available(), before - 1);
            let _ = iface.send(Version::V1, 8, &mut p);
            assert_eq!(
                pool.available(),
                before - 1,
                "still ours after a failed send"
            );
        }
        assert_eq!(pool.available(), before, "and released exactly once");
    }

    #[test]
    fn both_wire_versions_produce_the_right_frame_length() {
        let pool = P::new();
        for (version, hdr) in [(Version::V1, 4usize), (Version::V2, 6)] {
            let mut iface = Interface::new("TEST", 1, 5, Recorder::new());
            let mut p = packet(&pool);
            iface.send(version, 8, &mut p).unwrap();
            assert_eq!(iface.driver.lens[0], hdr + 7, "{version:?}");
        }
    }

    /// A loopback driver: hands the frame straight back.
    ///
    /// This is the whole of `csp_if_lo`, and the same shape as I2C and UDP.
    struct Loopback {
        last: [u8; 64],
        len: usize,
    }

    impl<'p> Transmit<'p, 4, 264> for Loopback {
        fn transmit(&mut self, _via: u16, packet: &Packet<'p, 4, 264>) -> Result<()> {
            packet.with_frame(|f| {
                self.last[..f.len()].copy_from_slice(f);
                self.len = f.len();
            });
            Ok(())
        }
    }

    #[test]
    fn a_datagram_interface_round_trips_without_any_extra_protocol() {
        // I2C, UDP and LOOP are all this: frame out, decode back in.
        let pool = P::new();
        for version in [Version::V1, Version::V2] {
            let mut iface = Interface::new(
                "LOOP",
                1,
                5,
                Loopback {
                    last: [0; 64],
                    len: 0,
                },
            );
            let id = Id {
                pri: 1,
                flags: 0x10,
                src: 11,
                dst: 11,
                dport: 20,
                sport: 10,
            };

            let mut out = pool.acquire(0).unwrap();
            out.set_id(id);
            out.set_payload(b"round trip").unwrap();
            iface.send(version, 11, &mut out).unwrap();

            let n = iface.driver.len;
            let mut back = pool.acquire(0).unwrap();
            back.set_frame(version, &iface.driver.last[..n]).unwrap();

            assert_eq!(back.id(), id, "{version:?}: header must survive");
            back.with_payload(|d| assert_eq!(d, b"round trip", "{version:?}: payload"));
        }
    }

    #[test]
    fn a_packet_addressed_to_the_interface_loops_back_instead_of_transmitting() {
        // csp_can1_tx and csp_can2_tx both open with this check. Easy to miss, because
        // the NODE address and an INTERFACE address are not the same thing.
        let pool = P::new();
        let mut iface = Interface::new("CAN", 7, 5, Recorder::new());
        let mut p = pool.acquire(0).unwrap();
        p.set_id(Id {
            pri: 2,
            flags: 0,
            src: 1,
            dst: 7,
            dport: 20,
            sport: 10,
        });
        p.set_payload(b"to myself").unwrap();

        assert_eq!(iface.send(Version::V1, 7, &mut p).unwrap(), Sent::Loopback);
        assert_eq!(iface.driver.n, 0, "nothing may go out on the link");
        assert_eq!(iface.stats.tx, 0);
    }

    #[test]
    fn a_packet_for_anyone_else_still_transmits() {
        let pool = P::new();
        let mut iface = Interface::new("CAN", 7, 5, Recorder::new());
        let mut p = packet(&pool);
        assert_eq!(
            iface.send(Version::V1, 8, &mut p).unwrap(),
            Sent::Transmitted
        );
        assert_eq!(iface.driver.n, 1);
    }

    #[test]
    fn rx_and_error_counters_are_separate() {
        let mut iface = Interface::new("TEST", 1, 5, Recorder::new());
        iface.note_rx(42);
        iface.note_frame_error();
        iface.note_drop();
        assert_eq!(iface.stats.rx, 1);
        assert_eq!(iface.stats.rxbytes, 42);
        assert_eq!(iface.stats.frame, 1);
        assert_eq!(iface.stats.drop, 1);
        assert_eq!(iface.stats.rx_error, 0);
    }

    #[test]
    fn byte_counters_include_the_header_and_agree_across_a_loopback() {
        // The C counts packet->length on both sides -- the payload, excluding the header
        // it just prepended. For an 8-byte telemetry packet that under-reports the link by
        // a third. What matters most is that tx and rx use the same rule.
        let pool = P::new();
        let mut iface = Interface::new(
            "LOOP",
            1,
            5,
            Loopback {
                last: [0; 64],
                len: 0,
            },
        );
        let mut p = pool.acquire(0).unwrap();
        p.set_id(Id {
            pri: 1,
            flags: 0,
            src: 11,
            dst: 8,
            dport: 20,
            sport: 10,
        });
        p.set_payload(b"12345678").unwrap();
        iface.send(Version::V1, 8, &mut p).unwrap();

        assert_eq!(
            iface.stats.txbytes,
            4 + 8,
            "header counted, not just payload"
        );
        iface.note_rx(iface.driver.len);
        assert_eq!(
            iface.stats.rxbytes, iface.stats.txbytes,
            "same rule both ways"
        );
    }

    #[test]
    fn a_refusal_lands_on_the_counter_it_belongs_to() {
        // The C picks the counter at each of six call sites in csp_route.c. One rule here.
        use csp_core::security::Refusal;
        let mut iface = Interface::new("TEST", 1, 5, Recorder::new());

        iface.note_refusal(Refusal::BadAuthentication);
        iface.note_refusal(Refusal::AuthenticationRequired);
        assert_eq!(iface.stats.autherr, 2);
        assert_eq!(iface.stats.rx_error, 0, "auth failures are not link errors");

        iface.note_refusal(Refusal::BadChecksum);
        iface.note_refusal(Refusal::ChecksumRequired);
        iface.note_refusal(Refusal::ReliabilityRequired);
        iface.note_refusal(Refusal::Prohibited);
        iface.note_refusal(Refusal::Unsupported);
        assert_eq!(iface.stats.rx_error, 5);
        assert_eq!(iface.stats.autherr, 2, "and the auth count is untouched");
    }

    #[test]
    fn irq_is_zero_until_a_driver_reports_one() {
        // Nothing in libcsp ever writes iface->irq, yet it is printed and reported over
        // CMP IF_STATS. Here it is zero for the same reason but can actually be set.
        let mut iface = Interface::new("TEST", 1, 5, Recorder::new());
        assert_eq!(iface.stats.irq, 0);
        iface.note_irq();
        assert_eq!(iface.stats.irq, 1);
    }

    #[test]
    fn a_driver_that_reports_failure_is_counted_as_a_failure() {
        // csp_if_udp_tx ignores sendto's return value and returns CSP_ERR_NONE even when
        // the socket is missing, so a UDP interface counts every packet as transmitted and
        // its tx_error is structurally zero. Transmit returns Result, so a driver that
        // knows it failed can say so.
        let pool = P::new();
        let mut iface = Interface::new("UDP", 1, 5, Recorder::new());
        iface.driver.fail = true;
        for _ in 0..3 {
            let mut p = packet(&pool);
            let _ = iface.send(Version::V1, 8, &mut p);
        }
        assert_eq!(iface.stats.tx, 0, "nothing left the node");
        assert_eq!(iface.stats.tx_error, 3);
        assert_eq!(iface.stats.txbytes, 0, "and no bytes are claimed");
    }
}
