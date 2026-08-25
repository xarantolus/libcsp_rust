//! Endpoint security policy.
//!
//! A socket or connection can **require** that incoming packets be checksummed,
//! authenticated or delivered reliably. `csp_route_security_check` enforces that before a
//! packet reaches the application, and it is the only thing standing between a node
//! configured to demand HMAC and an unauthenticated peer.
//!
//! Two directions, and both matter:
//!
//! - a packet that **claims** a protection must actually pass it — a wrong CRC or a wrong
//!   MAC is rejected;
//! - a packet that **omits** a protection the endpoint requires is rejected even though
//!   nothing about the packet itself is malformed.
//!
//! The second is the part that is easy to leave out, and leaving it out is silent: every
//! packet still arrives, the endpoint just no longer requires anything.

use crate::crc32::{self, Coverage};
use crate::{flags, Id};

#[cfg(feature = "hmac")]
use crate::hmac;

/// Socket and connection option bits, from `csp_types.h`.
pub mod opts {
    /// Require RDP.
    pub const RDP_REQ: u32 = 0x0001;
    /// Prohibit RDP.
    pub const RDP_PROHIB: u32 = 0x0002;
    /// Require HMAC.
    pub const HMAC_REQ: u32 = 0x0004;
    /// Prohibit HMAC.
    pub const HMAC_PROHIB: u32 = 0x0008;
    /// Require CRC32.
    pub const CRC32_REQ: u32 = 0x0040;
    /// Prohibit CRC32.
    pub const CRC32_PROHIB: u32 = 0x0080;
    /// Connection-less delivery.
    pub const CONN_LESS: u32 = 0x0100;
    /// Copy options from the incoming packet — `csp_sendto_reply` only.
    pub const SAME: u32 = 0x8000;
}

/// Why a packet was refused by the endpoint's policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The packet carried a CRC32 and it did not match.
    BadChecksum,
    /// The endpoint requires CRC32 and the packet had none.
    ChecksumRequired,
    /// The packet carried a MAC and it did not verify.
    BadAuthentication,
    /// The endpoint requires HMAC and the packet had none.
    AuthenticationRequired,
    /// The endpoint requires reliable delivery and the packet was not RDP.
    ReliabilityRequired,
    /// The packet used a protection the endpoint prohibits.
    Prohibited,
    /// The packet used a feature this build does not support.
    Unsupported,
}

/// Which counter a refusal belongs to.
///
/// The C keeps these apart — `iface->autherr` for authentication and `iface->rx_error` for
/// everything else — and the distinction is worth preserving: a rising `autherr` means
/// someone is talking to you who should not be, while `rx_error` usually means a bad link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Counter {
    /// Authentication failure.
    AuthError,
    /// Any other receive error.
    RxError,
}

impl Refusal {
    /// The counter this refusal should increment.
    pub const fn counter(&self) -> Counter {
        match self {
            Refusal::BadAuthentication | Refusal::AuthenticationRequired => Counter::AuthError,
            _ => Counter::RxError,
        }
    }
}

/// What this build supports, so a packet asking for something absent is dropped rather
/// than silently accepted unverified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Support {
    /// Whether HMAC verification is compiled in.
    pub hmac: bool,
    /// Whether RDP is compiled in.
    pub rdp: bool,
}

impl Default for Support {
    fn default() -> Self {
        Support {
            hmac: cfg!(feature = "hmac"),
            rdp: cfg!(feature = "rdp"),
        }
    }
}

/// Apply the endpoint's policy to an incoming packet.
///
/// `header` is the encoded CSP header (needed only for header-covering checksums), and
/// `payload` is the packet payload including any trailing CRC and MAC. Returns the payload
/// with whatever it verified stripped.
///
/// `key` is the HMAC key; `None` means no key is configured, in which case a packet
/// claiming HMAC cannot be verified and is refused rather than trusted.
pub fn check<'a>(
    endpoint_opts: u32,
    id: &Id,
    header: &[u8],
    payload: &'a [u8],
    coverage: Coverage,
    key: Option<&[u8]>,
    support: Support,
) -> core::result::Result<&'a [u8], Refusal> {
    let mut body = payload;

    // --- unsupported features are dropped, not ignored ---
    if id.has_flag(flags::HMAC) && !support.hmac {
        return Err(Refusal::Unsupported);
    }
    if id.has_flag(flags::RDP) && !support.rdp {
        return Err(Refusal::Unsupported);
    }

    // --- prohibitions ---
    if id.has_flag(flags::CRC32) && endpoint_opts & opts::CRC32_PROHIB != 0 {
        return Err(Refusal::Prohibited);
    }
    if id.has_flag(flags::HMAC) && endpoint_opts & opts::HMAC_PROHIB != 0 {
        return Err(Refusal::Prohibited);
    }
    if id.has_flag(flags::RDP) && endpoint_opts & opts::RDP_PROHIB != 0 {
        return Err(Refusal::Prohibited);
    }

    // --- HMAC first: it authenticates the bytes the checksum then covers ---
    #[cfg(feature = "hmac")]
    if id.has_flag(flags::HMAC) {
        let Some(key) = key else {
            // No key configured, so nothing can be verified. Accepting would mean
            // treating an unverifiable packet as authentic.
            return Err(Refusal::BadAuthentication);
        };
        body = hmac::verify_over(key, header, body, Coverage::PayloadOnly)
            .map_err(|_| Refusal::BadAuthentication)?;
    } else if endpoint_opts & opts::HMAC_REQ != 0 {
        return Err(Refusal::AuthenticationRequired);
    }
    #[cfg(not(feature = "hmac"))]
    if endpoint_opts & opts::HMAC_REQ != 0 {
        return Err(Refusal::AuthenticationRequired);
    }
    let _ = key;

    // --- CRC32 ---
    if id.has_flag(flags::CRC32) {
        body = crc32::verify(header, body, coverage).map_err(|_| Refusal::BadChecksum)?;
    } else if endpoint_opts & opts::CRC32_REQ != 0 {
        return Err(Refusal::ChecksumRequired);
    }

    // --- reliability ---
    if !id.has_flag(flags::RDP) && endpoint_opts & opts::RDP_REQ != 0 {
        return Err(Refusal::ReliabilityRequired);
    }

    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"0123456789abcdef";

    fn id_with(f: u8) -> Id {
        Id {
            pri: 2,
            flags: f,
            src: 8,
            dst: 11,
            dport: 20,
            sport: 10,
        }
    }

    fn sup() -> Support {
        Support {
            hmac: true,
            rdp: true,
        }
    }

    #[test]
    fn a_plain_packet_to_a_permissive_endpoint_passes_through() {
        let id = id_with(0);
        assert_eq!(
            check(0, &id, &[], b"payload", Coverage::PayloadOnly, None, sup()).unwrap(),
            b"payload"
        );
    }

    #[test]
    fn an_endpoint_that_requires_a_checksum_refuses_a_packet_without_one() {
        // The part that is easy to leave out, and silent when you do: nothing about this
        // packet is malformed, the endpoint simply demanded a protection it lacks.
        let id = id_with(0);
        assert_eq!(
            check(
                opts::CRC32_REQ,
                &id,
                &[],
                b"payload",
                Coverage::PayloadOnly,
                None,
                sup()
            ),
            Err(Refusal::ChecksumRequired)
        );
    }

    #[test]
    fn an_endpoint_that_requires_authentication_refuses_a_packet_without_it() {
        let id = id_with(0);
        assert_eq!(
            check(
                opts::HMAC_REQ,
                &id,
                &[],
                b"payload",
                Coverage::PayloadOnly,
                Some(KEY),
                sup()
            ),
            Err(Refusal::AuthenticationRequired)
        );
    }

    #[test]
    fn an_endpoint_that_requires_reliability_refuses_a_plain_datagram() {
        let id = id_with(0);
        assert_eq!(
            check(
                opts::RDP_REQ,
                &id,
                &[],
                b"payload",
                Coverage::PayloadOnly,
                None,
                sup()
            ),
            Err(Refusal::ReliabilityRequired)
        );
        // and accepts one that is reliable
        let rdp = id_with(flags::RDP);
        assert!(check(
            opts::RDP_REQ,
            &rdp,
            &[],
            b"payload",
            Coverage::PayloadOnly,
            None,
            sup()
        )
        .is_ok());
    }

    #[test]
    fn a_good_checksum_is_verified_and_stripped() {
        let id = id_with(flags::CRC32);
        let mut buf = [0u8; 32];
        let n = crc32::append(&[], b"payload", Coverage::PayloadOnly, &mut buf).unwrap();
        assert_eq!(
            check(0, &id, &[], &buf[..n], Coverage::PayloadOnly, None, sup()).unwrap(),
            b"payload"
        );
    }

    #[test]
    fn a_bad_checksum_is_refused() {
        let id = id_with(flags::CRC32);
        let mut buf = [0u8; 32];
        let n = crc32::append(&[], b"payload", Coverage::PayloadOnly, &mut buf).unwrap();
        buf[0] ^= 0x01;
        assert_eq!(
            check(0, &id, &[], &buf[..n], Coverage::PayloadOnly, None, sup()),
            Err(Refusal::BadChecksum)
        );
    }

    #[cfg(feature = "hmac")]
    #[test]
    fn a_good_mac_is_verified_and_stripped() {
        let id = id_with(flags::HMAC);
        let mut buf = [0u8; 32];
        let n = hmac::append(KEY, &[], b"payload", Coverage::PayloadOnly, &mut buf).unwrap();
        assert_eq!(
            check(
                0,
                &id,
                &[],
                &buf[..n],
                Coverage::PayloadOnly,
                Some(KEY),
                sup()
            )
            .unwrap(),
            b"payload"
        );
    }

    #[cfg(feature = "hmac")]
    #[test]
    fn a_forged_mac_is_refused() {
        let id = id_with(flags::HMAC);
        let mut buf = [0u8; 32];
        let n = hmac::append(
            b"wrong key",
            &[],
            b"payload",
            Coverage::PayloadOnly,
            &mut buf,
        )
        .unwrap();
        assert_eq!(
            check(
                0,
                &id,
                &[],
                &buf[..n],
                Coverage::PayloadOnly,
                Some(KEY),
                sup()
            ),
            Err(Refusal::BadAuthentication)
        );
    }

    #[cfg(feature = "hmac")]
    #[test]
    fn a_packet_claiming_authentication_with_no_key_configured_is_refused() {
        // Accepting it would mean treating an unverifiable packet as authentic, which is
        // worse than refusing traffic.
        let id = id_with(flags::HMAC);
        assert_eq!(
            check(
                0,
                &id,
                &[],
                b"payloadXXXX",
                Coverage::PayloadOnly,
                None,
                sup()
            ),
            Err(Refusal::BadAuthentication)
        );
    }

    #[test]
    fn a_feature_this_build_lacks_is_dropped_not_silently_accepted() {
        // csp_route_check_options. Accepting an HMAC packet on a build without HMAC would
        // deliver it unverified.
        let no_support = Support {
            hmac: false,
            rdp: false,
        };
        assert_eq!(
            check(
                0,
                &id_with(flags::HMAC),
                &[],
                b"payload",
                Coverage::PayloadOnly,
                None,
                no_support
            ),
            Err(Refusal::Unsupported)
        );
        assert_eq!(
            check(
                0,
                &id_with(flags::RDP),
                &[],
                b"payload",
                Coverage::PayloadOnly,
                None,
                no_support
            ),
            Err(Refusal::Unsupported)
        );
    }

    #[test]
    fn prohibitions_are_enforced_as_well_as_requirements() {
        for (flag, opt) in [
            (flags::CRC32, opts::CRC32_PROHIB),
            (flags::HMAC, opts::HMAC_PROHIB),
            (flags::RDP, opts::RDP_PROHIB),
        ] {
            assert_eq!(
                check(
                    opt,
                    &id_with(flag),
                    &[],
                    b"payloadXXXXXXXX",
                    Coverage::PayloadOnly,
                    Some(KEY),
                    sup()
                ),
                Err(Refusal::Prohibited),
                "flag {flag:#x}"
            );
        }
    }

    #[test]
    fn authentication_failures_count_separately_from_link_errors() {
        // A rising autherr means someone is talking to you who should not be; a rising
        // rx_error usually means a bad link. Conflating them hides both.
        assert_eq!(Refusal::BadAuthentication.counter(), Counter::AuthError);
        assert_eq!(
            Refusal::AuthenticationRequired.counter(),
            Counter::AuthError
        );
        assert_eq!(Refusal::BadChecksum.counter(), Counter::RxError);
        assert_eq!(Refusal::ChecksumRequired.counter(), Counter::RxError);
        assert_eq!(Refusal::ReliabilityRequired.counter(), Counter::RxError);
    }

    #[cfg(feature = "hmac")]
    #[test]
    fn both_protections_together_verify_and_strip_in_order() {
        // HMAC is applied first on receive, because it authenticates the bytes the
        // checksum then covers.
        let id = id_with(flags::CRC32 | flags::HMAC);
        let mut inner = [0u8; 64];
        let n1 = crc32::append(&[], b"payload", Coverage::PayloadOnly, &mut inner).unwrap();
        let mut outer = [0u8; 64];
        let n2 = hmac::append(KEY, &[], &inner[..n1], Coverage::PayloadOnly, &mut outer).unwrap();

        assert_eq!(
            check(
                opts::CRC32_REQ | opts::HMAC_REQ,
                &id,
                &[],
                &outer[..n2],
                Coverage::PayloadOnly,
                Some(KEY),
                sup()
            )
            .unwrap(),
            b"payload"
        );
    }
}
