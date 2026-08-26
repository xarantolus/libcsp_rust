//! Application callbacks.
//!
//! One trait with defaults, rather than fifteen `__weak` C symbols.
//!
//! # Why this is a trait and not weak symbols
//!
//! libcsp declares fifteen overridable functions as `__attribute__((weak))`. Rust has no
//! equivalent, and that turns out to be a feature: while transpiling libcsp the build
//! failed with
//!
//! ```text
//! error: symbol `csp_input_hook` is already defined
//! ```
//!
//! because `csp_input_hook` is defined `__weak` **twice in one library** —
//! `csp_route.c:106` and `csp_bridge.c:19`, byte-identically. A C linker silently picks
//! one, so which implementation runs is link-order dependent and nothing reports it. A
//! trait method cannot be defined twice.
//!
//! The mixed linkage is worse than it sounds: `csp_reboot_hook`, `csp_shutdown_hook`,
//! `csp_memfree_hook` and `csp_ps_hook` are **non-weak** in the POSIX arch and weak in the
//! FreeRTOS and Zephyr ones, so whether an application can override them depends on which
//! platform it built for.
//!
//! # `csp_panic` has no counterpart here
//!
//! libcsp's fifteenth hook is `csp_panic(const char *)`, called when the library reaches a
//! state it cannot continue from. Rust already has that mechanism and the application
//! already owns it: in `no_std` the `#[panic_handler]` is the binary's to define, so a
//! `csp_panic` method would be a second, weaker way to do the same thing. The invariants
//! that would call it are compile-time assertions where they can be and typed errors
//! where they cannot.

//! # The input tap must be able to clone
//!
//! `csp_input_hook` is not a filter — the payload board's side-link relay uses it to
//! `csp_buffer_clone()` a broadcast and re-inject the copy onto CAN, and the DEDRA feed
//! uses it to learn reverse routes from every ingress packet. So the tap gets the packet
//! by reference and may copy it, but cannot consume it.

use crate::pool::Packet;
#[cfg(feature = "cmp")]
use csp_core::cmp::IfStats;
use csp_core::Id;

/// Wall-clock time, seconds and nanoseconds since the epoch.
///
/// A real type. The Rust arch shim in the flight tree mirrors `csp_timestamp_t` by hand
/// and casts through `*mut c_void`, with a comment explaining that bindgen never emitted
/// it because no bound signature named it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord)]
pub struct Timestamp {
    /// Seconds since the epoch.
    pub tv_sec: u32,
    /// Nanoseconds within the second.
    pub tv_nsec: u32,
}

impl Timestamp {
    /// A timestamp meaning "not set".
    ///
    /// `csp_cmp_clock_handler` treats `tv_sec == 0` as "report, do not set", so zero is
    /// already reserved on the wire.
    pub const UNSET: Timestamp = Timestamp {
        tv_sec: 0,
        tv_nsec: 0,
    };

    /// True if this is the unset value.
    pub const fn is_unset(&self) -> bool {
        self.tv_sec == 0
    }
}

/// What the node should do after a reboot or shutdown request.
///
/// Returned rather than performed, so a hook cannot be a diverging function the library
/// calls and never returns from. The C's hooks are `void` and expected never to come
/// back; a node that returns from `csp_reboot_hook` carries on running with no indication
/// anything failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerAction {
    /// Restart.
    Reboot,
    /// Power down.
    Shutdown,
    /// Refuse. The request is dropped.
    Refuse,
}

#[cfg(feature = "cmp")]
impl From<csp_core::cmp::Timestamp> for Timestamp {
    fn from(t: csp_core::cmp::Timestamp) -> Self {
        Timestamp {
            tv_sec: t.tv_sec,
            tv_nsec: t.tv_nsec,
        }
    }
}

#[cfg(feature = "cmp")]
impl From<Timestamp> for csp_core::cmp::Timestamp {
    fn from(t: Timestamp) -> Self {
        csp_core::cmp::Timestamp {
            tv_sec: t.tv_sec,
            tv_nsec: t.tv_nsec,
        }
    }
}

/// Application callbacks. Every method has a default, so an application implements only
/// what it needs.
pub trait Hooks<const B: usize, const SZ: usize> {
    /// Called for every packet the router accepts, before delivery.
    ///
    /// A tap, not a filter: the packet is borrowed and delivery proceeds regardless. To
    /// relay one, copy it with [`Packet::deep_copy`] and send the copy.
    fn on_input(&mut self, _iface: u8, _packet: &Packet<'_, B, SZ>) {}

    /// Called for every packet the node sends.
    fn on_output(&mut self, _iface: u8, _packet: &Packet<'_, B, SZ>) {}

    /// Free memory in bytes, for the `MEMFREE` service.
    ///
    /// Defaults to 0, meaning "unknown" — the same thing the C's default returns, and
    /// distinguishable from a genuine zero only by context either way.
    fn mem_free(&self) -> u32 {
        0
    }

    /// Uptime in seconds, for the `UPTIME` service.
    fn uptime_s(&self) -> u32 {
        0
    }

    /// The process list, for the `PS` service. Returns bytes written.
    fn process_list(&self, _out: &mut [u8]) -> usize {
        0
    }

    /// Asked to reboot or power down.
    ///
    /// Defaults to [`PowerAction::Refuse`]: a node that has not been told how to reboot
    /// should say so rather than appear to accept and do nothing.
    fn on_power_request(&mut self, _action: PowerAction) -> PowerAction {
        PowerAction::Refuse
    }

    /// Read the wall clock.
    fn clock(&self) -> Timestamp {
        Timestamp::UNSET
    }

    /// Set the wall clock. Returns whether it was accepted.
    ///
    /// Defaults to refusing: silently ignoring a clock set makes a spacecraft's timestamps
    /// wrong in a way that only shows up in the telemetry archive.
    fn set_clock(&mut self, _t: Timestamp) -> bool {
        false
    }

    /// Encrypt a payload in place for the tunnel interface.
    ///
    /// Returns the new length, or `None` if it cannot be encrypted — in which case the
    /// caller must **not** transmit it.
    ///
    /// Defaults to `None`, like every other hook here that can fail. It used to default to
    /// `Some(len)` with the payload untouched, which reports "encrypted" for plaintext: a
    /// node that switched on a tunnel without supplying crypto would have transmitted in
    /// the clear while every layer above it believed otherwise. The C's `__weak`
    /// `csp_crypto_encrypt` returns `-1` (`csp_if_tun.c:16`), so this was also the one
    /// default that disagreed with the C about which way to fail.
    fn encrypt(&mut self, _data: &mut [u8], _len: usize) -> Option<usize> {
        None
    }

    /// Decrypt a payload in place. Returns the new length, or `None` to drop the packet.
    ///
    /// Defaults to `None`: a node with no crypto cannot read ciphertext, and treating it as
    /// plaintext would hand the application whatever the peer sent. Matches the C's
    /// `__weak` `csp_crypto_decrypt`, which returns `-1`.
    fn decrypt(&mut self, _data: &mut [u8], _len: usize) -> Option<usize> {
        None
    }

    /// Read `out.len()` bytes of node memory at `addr`, for CMP `PEEK`.
    ///
    /// **Defaults to refusing.** In libcsp this is `csp_cmp_memcpy`, and its default
    /// implementation (`csp_cmp_mem.c:15`) is a bare `memcpy` with no validation
    /// whatsoever — the only check anywhere on the path is `len <= 200`. So a node built
    /// with CMP, which is the default, will read any 32-bit address a peer names and send
    /// the contents back. The 64-bit variants `csp_cmp_memread64`/`csp_cmp_memwrite64`
    /// default to `CSP_ERR_DRIVER`, i.e. refusing; that the 32-bit pair does not is the
    /// tell that its default is an oversight rather than a decision.
    ///
    /// A node that genuinely wants peek/poke — for a memory dump service, say — implements
    /// this for the specific region it is willing to expose.
    ///
    /// Note also that libcsp's `csp_cmp_set_memcpy`, the function an integrator would
    /// reach for to install a validating replacement, has an empty body: it takes the
    /// function pointer, discards it, and returns. It is marked `CSP_DEPRECATED`, so a
    /// compiler warning is the only thing standing between that call and a false sense of
    /// security.
    fn mem_read(&self, addr: u64, _out: &mut [u8]) -> csp_core::Result<()> {
        Err(csp_core::Error::AddressRefused { addr })
    }

    /// Write `data` to node memory at `addr`, for CMP `POKE`. **Defaults to refusing.**
    ///
    /// Same story as [`mem_read`](Self::mem_read), one step worse: the default C
    /// implementation lets a peer write arbitrary memory.
    fn mem_write(&mut self, addr: u64, _data: &[u8]) -> csp_core::Result<()> {
        Err(csp_core::Error::AddressRefused { addr })
    }

    /// Counters for the named interface, for CMP `IF_STATS`. **Defaults to refusing.**
    ///
    /// `None` means "no such interface", which the C answers by discarding the request
    /// rather than replying with zeros — a peer asking about an interface that does not
    /// exist gets silence, not a plausible-looking all-zero reply.
    #[cfg(feature = "cmp")]
    fn if_stats(&self, _name: &str) -> Option<IfStats> {
        None
    }

    /// Install a route, for CMP `ROUTE_SET`. **Defaults to refusing.**
    ///
    /// Refusing by default is the deliberate part. `csp_cmp_route_set_v2_handler` installs
    /// whatever an unauthenticated peer asks for, so one packet can point a node's default
    /// route at an interface that goes nowhere — and the node has then lost the route it
    /// would need to be told otherwise. An application that wants remote route management
    /// opts in.
    ///
    /// `netmask` is a prefix length. Return `false` to refuse, which sends no reply.
    #[cfg(feature = "cmp")]
    fn route_set(&mut self, _dest: u16, _netmask: u16, _iface: &str, _via: u16) -> bool {
        false
    }

    /// A routing decision was made for an ingress packet.
    ///
    /// The DEDRA feed uses this to learn reverse routes: both peer UARTs share a source
    /// address, so the return route has to follow the interface the packet arrived on.
    fn on_route_learn(&mut self, _id: Id, _iface: u8) {}
}

/// The do-nothing implementation, for a node that needs no callbacks.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoHooks;

impl<const B: usize, const SZ: usize> Hooks<B, SZ> for NoHooks {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::Pool;

    type P = Pool<4, 264>;

    #[test]
    fn the_default_hooks_are_safe_and_say_nothing() {
        let h = NoHooks;
        assert_eq!(Hooks::<4, 264>::mem_free(&h), 0);
        assert_eq!(Hooks::<4, 264>::uptime_s(&h), 0);
        assert_eq!(Hooks::<4, 264>::clock(&h), Timestamp::UNSET);
    }

    /// A node with no crypto must not claim to have encrypted anything.
    ///
    /// This is the direction that matters: every other fallible default here refuses, and
    /// this one returned `Some(len)` with the buffer untouched — "encrypted", for
    /// plaintext. The C's `__weak` csp_crypto_encrypt returns -1, so the port was also the
    /// more dangerous of the two. Neither default had a test; both were among the six the
    /// coverage run showed nothing entering.
    #[test]
    fn crypto_defaults_refuse_rather_than_passing_plaintext() {
        let mut h = NoHooks;
        let mut buf = *b"secret";

        assert_eq!(
            Hooks::<4, 264>::encrypt(&mut h, &mut buf, 6),
            None,
            "a node that cannot encrypt must not report success"
        );
        assert_eq!(
            Hooks::<4, 264>::decrypt(&mut h, &mut buf, 6),
            None,
            "a node that cannot decrypt must drop the packet, not pass ciphertext up"
        );
        // And it did not quietly alter the buffer either way.
        assert_eq!(&buf, b"secret");
    }

    /// The rest of the defaults that return a value, in one place.
    ///
    /// `the_default_hooks_are_safe_and_say_nothing` checked three of the fourteen. These
    /// are the others that can say something untrue by returning the wrong thing.
    #[test]
    fn every_fallible_default_refuses() {
        let mut h = NoHooks;
        let mut out = [0u8; 32];

        assert_eq!(Hooks::<4, 264>::process_list(&h, &mut out), 0);
        assert_eq!(
            Hooks::<4, 264>::on_power_request(&mut h, PowerAction::Reboot),
            PowerAction::Refuse
        );
        assert!(!Hooks::<4, 264>::set_clock(&mut h, Timestamp::UNSET));
        assert!(Hooks::<4, 264>::mem_read(&h, 0x1000, &mut out).is_err());
        assert!(Hooks::<4, 264>::mem_write(&mut h, 0x1000, &out).is_err());
    }

    #[test]
    fn a_node_that_cannot_reboot_refuses_rather_than_pretending() {
        // The C's hooks are void and expected never to return; a node that returns from
        // csp_reboot_hook carries on with nothing indicating the reboot did not happen.
        let mut h = NoHooks;
        assert_eq!(
            Hooks::<4, 264>::on_power_request(&mut h, PowerAction::Reboot),
            PowerAction::Refuse
        );
    }

    #[test]
    fn a_node_that_cannot_set_its_clock_says_so() {
        // Silently ignoring a clock set makes every later timestamp wrong in a way that
        // only shows up in the telemetry archive.
        let mut h = NoHooks;
        assert!(!Hooks::<4, 264>::set_clock(
            &mut h,
            Timestamp {
                tv_sec: 1_700_000_000,
                tv_nsec: 0
            }
        ));
    }

    #[test]
    fn an_unset_timestamp_is_recognisable() {
        assert!(Timestamp::UNSET.is_unset());
        assert!(!Timestamp {
            tv_sec: 1,
            tv_nsec: 0
        }
        .is_unset());
        // tv_sec == 0 is already reserved on the wire by csp_cmp_clock_handler.
        assert!(Timestamp {
            tv_sec: 0,
            tv_nsec: 999
        }
        .is_unset());
    }

    /// A tap that relays broadcasts, as the payload side-link relay does.
    #[derive(Default)]
    struct RelayTap {
        seen: u32,
        relayed: u32,
    }

    impl Hooks<4, 264> for RelayTap {
        fn on_input(&mut self, _iface: u8, packet: &Packet<'_, 4, 264>) {
            self.seen += 1;
            // The real relay clones a broadcast and re-injects the copy onto CAN.
            if packet.id().dst == 31 {
                if let Some(copy) = packet.deep_copy() {
                    self.relayed += 1;
                    drop(copy);
                }
            }
        }
    }

    #[test]
    fn the_input_tap_can_clone_without_consuming_the_packet() {
        // csp_input_hook is not a filter: the payload relay clones a broadcast and
        // re-injects it, and delivery of the original must proceed regardless.
        let pool = P::new();
        let mut tap = RelayTap::default();

        let mut p = pool.acquire(0).unwrap();
        p.set_id(Id {
            pri: 2,
            flags: 0,
            src: 1,
            dst: 31,
            dport: 20,
            sport: 10,
        });
        p.set_payload(b"broadcast").unwrap();

        tap.on_input(0, &p);
        assert_eq!(tap.seen, 1);
        assert_eq!(tap.relayed, 1);

        // The original is untouched and still ours.
        p.with_payload(|d| assert_eq!(d, b"broadcast"));
        assert_eq!(p.id().dst, 31);
    }

    #[test]
    fn a_tap_that_cannot_clone_does_not_break_delivery() {
        // Pool exhaustion during a relay must not cost the original packet.
        let pool = P::new();
        let mut tap = RelayTap::default();
        let mut p = pool.acquire(0).unwrap();
        p.set_id(Id {
            pri: 2,
            flags: 0,
            src: 1,
            dst: 31,
            dport: 20,
            sport: 10,
        });
        p.set_payload(b"broadcast").unwrap();
        let _rest: [_; 3] = core::array::from_fn(|_| pool.acquire(0).unwrap());

        tap.on_input(0, &p);
        assert_eq!(tap.seen, 1);
        assert_eq!(tap.relayed, 0, "the clone failed");
        p.with_payload(|d| assert_eq!(d, b"broadcast", "the original survives"));
    }

    /// A node that really can do things, to prove the defaults are overridable.
    struct RealNode {
        clock: Timestamp,
        rebooted: bool,
    }

    impl Hooks<4, 264> for RealNode {
        fn mem_free(&self) -> u32 {
            4096
        }
        fn uptime_s(&self) -> u32 {
            3600
        }
        fn clock(&self) -> Timestamp {
            self.clock
        }
        fn set_clock(&mut self, t: Timestamp) -> bool {
            self.clock = t;
            true
        }
        fn on_power_request(&mut self, action: PowerAction) -> PowerAction {
            self.rebooted = true;
            action
        }
    }

    #[test]
    fn overriding_a_hook_replaces_the_default() {
        let mut n = RealNode {
            clock: Timestamp::UNSET,
            rebooted: false,
        };
        assert_eq!(Hooks::<4, 264>::mem_free(&n), 4096);
        assert_eq!(Hooks::<4, 264>::uptime_s(&n), 3600);

        let t = Timestamp {
            tv_sec: 1_700_000_000,
            tv_nsec: 42,
        };
        assert!(Hooks::<4, 264>::set_clock(&mut n, t));
        assert_eq!(Hooks::<4, 264>::clock(&n), t);

        assert_eq!(
            Hooks::<4, 264>::on_power_request(&mut n, PowerAction::Shutdown),
            PowerAction::Shutdown
        );
        assert!(n.rebooted);
    }

    #[test]
    fn peek_and_poke_are_refused_until_a_node_opts_in() {
        // libcsp's default csp_cmp_memcpy is a bare memcpy with no validation, so a node
        // built with CMP -- the default -- reads and writes any address a peer names. The
        // 64-bit variants refuse by default; the 32-bit pair does not.
        let mut h = NoHooks;
        let mut out = [0u8; 8];
        assert_eq!(
            Hooks::<4, 264>::mem_read(&h, 0x2000_0000, &mut out),
            Err(csp_core::Error::AddressRefused { addr: 0x2000_0000 })
        );
        assert_eq!(out, [0u8; 8], "and nothing was written into the reply");
        assert_eq!(
            Hooks::<4, 264>::mem_write(&mut h, 0x0800_0000, &[0xff; 4]),
            Err(csp_core::Error::AddressRefused { addr: 0x0800_0000 }),
            "least of all a write into the flash image"
        );
    }

    /// A node that exposes exactly one region, which is how peek should be used.
    struct MemDump {
        base: u64,
        region: [u8; 16],
    }

    impl MemDump {
        fn window(&self, addr: u64, len: usize) -> Option<core::ops::Range<usize>> {
            let off = addr.checked_sub(self.base)? as usize;
            let end = off.checked_add(len)?;
            (end <= self.region.len()).then_some(off..end)
        }
    }

    impl Hooks<4, 264> for MemDump {
        fn mem_read(&self, addr: u64, out: &mut [u8]) -> csp_core::Result<()> {
            let r = self
                .window(addr, out.len())
                .ok_or(csp_core::Error::AddressRefused { addr })?;
            out.copy_from_slice(&self.region[r]);
            Ok(())
        }
    }

    #[test]
    fn a_node_that_opts_in_still_bounds_the_region() {
        let m = MemDump {
            base: 0x2000_0000,
            region: *b"0123456789abcdef",
        };
        let mut out = [0u8; 4];
        assert!(Hooks::<4, 264>::mem_read(&m, 0x2000_0004, &mut out).is_ok());
        assert_eq!(&out, b"4567");

        // One byte past the end.
        let mut big = [0u8; 4];
        assert!(Hooks::<4, 264>::mem_read(&m, 0x2000_000d, &mut big).is_err());
        // Below the base -- the subtraction must not wrap into a huge offset.
        assert!(Hooks::<4, 264>::mem_read(&m, 0x1fff_ffff, &mut big).is_err());
        // The whole region exactly.
        let mut all = [0u8; 16];
        assert!(Hooks::<4, 264>::mem_read(&m, 0x2000_0000, &mut all).is_ok());
        // And writes are still refused, because MemDump did not implement mem_write.
        let mut m2 = MemDump {
            base: 0x2000_0000,
            region: [0; 16],
        };
        assert!(Hooks::<4, 264>::mem_write(&mut m2, 0x2000_0000, &[1]).is_err());
    }

    #[test]
    fn there_is_exactly_one_input_hook() {
        // The whole point. csp_input_hook is defined __weak TWICE in one C library
        // (csp_route.c:106 and csp_bridge.c:19), byte-identically, so which one runs is
        // link-order dependent. A trait method cannot be defined twice -- this test
        // exists to document that, since there is no way to write the failing case.
        let mut a = RelayTap::default();
        let mut b = RelayTap::default();
        let pool = P::new();
        let p = pool.acquire(0).unwrap();
        a.on_input(0, &p);
        b.on_input(0, &p);
        assert_eq!(a.seen, 1);
        assert_eq!(
            b.seen, 1,
            "two implementations are two objects, not a link race"
        );
    }
}
