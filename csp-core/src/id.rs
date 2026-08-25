//! CSP header codec, both wire versions.
//!
//! This is deliberately public. The C library keeps its header packing private, and the
//! result is that this repository alone contains **three** hand-rolled reimplementations
//! of it — one in the Zephyr UART driver, one in the ground station's Python helpers, and
//! one in the CAN transport — each of which had to rediscover the bit layout from the
//! comments in `csp_id.c`.
//!
//! ```
//! use csp_core::{Id, Version};
//!
//! let id = Id { pri: 2, flags: 0, src: 1, dst: 8, dport: 20, sport: 10 };
//! let mut buf = [0u8; 4];
//! let n = id.encode(Version::V1, &mut buf).unwrap();
//! assert_eq!(n, 4);
//! assert_eq!(Id::decode(Version::V1, &buf).unwrap(), id);
//! ```

use crate::{Error, Field, Result};

/// CSP wire-format version.
///
/// This is a value, not a global. See the crate docs for why that matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Version {
    /// 4-byte header: 2 prio, 5 src, 5 dst, 6 dport, 6 sport, 8 flags.
    V1,
    /// 6-byte header: 2 prio, 14 dst, 14 src, 6 dport, 6 sport, 6 flags.
    V2,
}

// --- v1 layout, from csp_id.c ---
const V1_HEADER_SIZE: usize = 4;
const V1_HOST_BITS: u32 = 5;
const V1_PORT_BITS: u32 = 6;
const V1_PRIO_OFFSET: u32 = 30;
const V1_SRC_OFFSET: u32 = 25;
const V1_DST_OFFSET: u32 = 20;
const V1_DPORT_OFFSET: u32 = 14;
const V1_SPORT_OFFSET: u32 = 8;
const V1_FLAGS_OFFSET: u32 = 0;
const V1_FLAGS_BITS: u32 = 8;

// --- v2 layout, from csp_id.c ---
const V2_HEADER_SIZE: usize = 6;
const V2_HOST_BITS: u32 = 14;
const V2_PORT_BITS: u32 = 6;
const V2_PRIO_OFFSET: u32 = 46;
const V2_DST_OFFSET: u32 = 32;
const V2_SRC_OFFSET: u32 = 18;
const V2_DPORT_OFFSET: u32 = 12;
const V2_SPORT_OFFSET: u32 = 6;
const V2_FLAGS_OFFSET: u32 = 0;
const V2_FLAGS_BITS: u32 = 6;

const PRIO_BITS: u32 = 2;

impl Version {
    /// Bytes of header this version prepends to a packet.
    pub const fn header_size(self) -> usize {
        match self {
            Version::V1 => V1_HEADER_SIZE,
            Version::V2 => V2_HEADER_SIZE,
        }
    }

    /// Width of the address field in bits (5 for v1, 14 for v2).
    pub const fn host_bits(self) -> u32 {
        match self {
            Version::V1 => V1_HOST_BITS,
            Version::V2 => V2_HOST_BITS,
        }
    }

    /// Largest addressable node. Also the all-nodes broadcast address.
    pub const fn max_node_id(self) -> u16 {
        (1u16 << self.host_bits()) - 1
    }

    /// Largest usable port number.
    pub const fn max_port(self) -> u8 {
        match self {
            Version::V1 => (1u8 << V1_PORT_BITS) - 1,
            Version::V2 => (1u8 << V2_PORT_BITS) - 1,
        }
    }

    /// Width of the flags field in bits. **This differs between versions** — 8 in v1, 6
    /// in v2 — which is easy to miss and silently truncates `flags` on a v2 encode.
    pub const fn flags_bits(self) -> u32 {
        match self {
            Version::V1 => V1_FLAGS_BITS,
            Version::V2 => V2_FLAGS_BITS,
        }
    }

    /// Whether `addr` is a broadcast address as seen from an interface with this
    /// address and netmask.
    ///
    /// Mirrors `csp_id_is_broadcast`. Note the second clause: the all-ones node id is
    /// always broadcast regardless of interface. That is also why an interface whose
    /// `netmask` equals `host_bits` treats its *own* address as broadcast — the trap the
    /// flight code documents at length before assigning `csp_if_lo.addr`.
    pub const fn is_broadcast(self, addr: u16, iface_addr: u16, iface_netmask: u16) -> bool {
        let host_bits = self.host_bits() as u16;
        // A netmask wider than the address space would shift out of range.
        let shift = if iface_netmask > host_bits {
            0
        } else {
            host_bits - iface_netmask
        };
        let hostmask: u16 = (1u16 << shift) - 1;
        let netmask: u16 = ((1u32 << host_bits) - 1) as u16 - hostmask;

        if (addr & hostmask) == hostmask && (addr & netmask) == (iface_addr & netmask) {
            return true;
        }
        addr == self.max_node_id()
    }
}

/// A decoded CSP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Id {
    /// Priority, 0 (highest) to 3 (lowest).
    pub pri: u8,
    /// Header flags — see [`crate::flags`].
    pub flags: u8,
    /// Source address.
    pub src: u16,
    /// Destination address.
    pub dst: u16,
    /// Destination port.
    pub dport: u8,
    /// Source port.
    pub sport: u8,
}

impl Id {
    /// Check that every field fits `version`'s wire format.
    ///
    /// The C does no such check: `(uint32_t)(packet->id.dst) << CSP_ID1_DST_OFFSET` with
    /// no mask means a 14-bit address encoded as v1 quietly overwrites the low bit of the
    /// source address, producing a header that decodes as a *different, valid* packet.
    pub const fn validate(&self, version: Version) -> Result<()> {
        if self.pri >= (1u8 << PRIO_BITS) {
            return Err(Error::FieldOutOfRange {
                field: Field::Priority,
            });
        }
        let max_addr = version.max_node_id();
        if self.src > max_addr {
            return Err(Error::FieldOutOfRange {
                field: Field::Source,
            });
        }
        if self.dst > max_addr {
            return Err(Error::FieldOutOfRange {
                field: Field::Destination,
            });
        }
        let max_port = version.max_port();
        if self.sport > max_port {
            return Err(Error::FieldOutOfRange {
                field: Field::SourcePort,
            });
        }
        if self.dport > max_port {
            return Err(Error::FieldOutOfRange {
                field: Field::DestinationPort,
            });
        }
        if version.flags_bits() < 8 && self.flags >= (1u8 << V2_FLAGS_BITS) {
            return Err(Error::FieldOutOfRange {
                field: Field::Flags,
            });
        }
        Ok(())
    }

    /// Encode into `out`, returning the number of bytes written.
    ///
    /// Fails rather than truncating if a field does not fit — see [`Id::validate`].
    pub fn encode(&self, version: Version, out: &mut [u8]) -> Result<usize> {
        let n = version.header_size();
        if out.len() < n {
            return Err(Error::BufferTooSmall { needed: n });
        }
        self.validate(version)?;

        match version {
            Version::V1 => {
                let raw: u32 = ((self.pri as u32) << V1_PRIO_OFFSET)
                    | ((self.dst as u32) << V1_DST_OFFSET)
                    | ((self.src as u32) << V1_SRC_OFFSET)
                    | ((self.dport as u32) << V1_DPORT_OFFSET)
                    | ((self.sport as u32) << V1_SPORT_OFFSET)
                    | ((self.flags as u32) << V1_FLAGS_OFFSET);
                out[..n].copy_from_slice(&raw.to_be_bytes());
            }
            Version::V2 => {
                let raw: u64 = ((self.pri as u64) << V2_PRIO_OFFSET)
                    | ((self.dst as u64) << V2_DST_OFFSET)
                    | ((self.src as u64) << V2_SRC_OFFSET)
                    | ((self.dport as u64) << V2_DPORT_OFFSET)
                    | ((self.sport as u64) << V2_SPORT_OFFSET)
                    | ((self.flags as u64) << V2_FLAGS_OFFSET);
                // The 48-bit header sits in the top 48 bits of the u64, so the first six
                // big-endian bytes are the frame.
                let be = (raw << 16).to_be_bytes();
                out[..n].copy_from_slice(&be[..n]);
            }
        }
        Ok(n)
    }

    /// Decode a header from the front of `data`.
    pub fn decode(version: Version, data: &[u8]) -> Result<Id> {
        let n = version.header_size();
        if data.len() < n {
            return Err(Error::Truncated);
        }
        Ok(match version {
            Version::V1 => {
                let raw = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                Id {
                    pri: ((raw >> V1_PRIO_OFFSET) & mask32(PRIO_BITS)) as u8,
                    dst: ((raw >> V1_DST_OFFSET) & mask32(V1_HOST_BITS)) as u16,
                    src: ((raw >> V1_SRC_OFFSET) & mask32(V1_HOST_BITS)) as u16,
                    dport: ((raw >> V1_DPORT_OFFSET) & mask32(V1_PORT_BITS)) as u8,
                    sport: ((raw >> V1_SPORT_OFFSET) & mask32(V1_PORT_BITS)) as u8,
                    flags: ((raw >> V1_FLAGS_OFFSET) & mask32(V1_FLAGS_BITS)) as u8,
                }
            }
            Version::V2 => {
                let mut be = [0u8; 8];
                be[..n].copy_from_slice(&data[..n]);
                // from_be_bytes puts data[0] in the MSB; the two trailing zero bytes are
                // shifted back off to leave the 48-bit value.
                let raw = u64::from_be_bytes(be) >> 16;
                Id {
                    pri: ((raw >> V2_PRIO_OFFSET) & mask64(PRIO_BITS)) as u8,
                    dst: ((raw >> V2_DST_OFFSET) & mask64(V2_HOST_BITS)) as u16,
                    src: ((raw >> V2_SRC_OFFSET) & mask64(V2_HOST_BITS)) as u16,
                    dport: ((raw >> V2_DPORT_OFFSET) & mask64(V2_PORT_BITS)) as u8,
                    sport: ((raw >> V2_SPORT_OFFSET) & mask64(V2_PORT_BITS)) as u8,
                    flags: ((raw >> V2_FLAGS_OFFSET) & mask64(V2_FLAGS_BITS)) as u8,
                }
            }
        })
    }

    /// True if any of the given flag bits are set.
    pub const fn has_flag(&self, flag: u8) -> bool {
        (self.flags & flag) != 0
    }

    /// True if this packet carries an SFP fragment rather than a whole datagram.
    ///
    /// This single bit is what lets a port accept either shape without the sender having
    /// to declare which it will use.
    pub const fn is_fragment(&self) -> bool {
        self.has_flag(crate::flags::FRAG)
    }
}

const fn mask32(bits: u32) -> u32 {
    (1u32 << bits) - 1
}

const fn mask64(bits: u32) -> u64 {
    (1u64 << bits) - 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flags;

    const BOTH: [Version; 2] = [Version::V1, Version::V2];

    #[test]
    fn header_sizes_match_the_c() {
        assert_eq!(Version::V1.header_size(), 4);
        assert_eq!(Version::V2.header_size(), 6);
    }

    #[test]
    fn version_derived_parameters() {
        assert_eq!(Version::V1.host_bits(), 5);
        assert_eq!(Version::V1.max_node_id(), 31);
        assert_eq!(Version::V1.max_port(), 63);
        assert_eq!(Version::V2.host_bits(), 14);
        assert_eq!(Version::V2.max_node_id(), 16383);
        assert_eq!(Version::V2.max_port(), 63);
    }

    #[test]
    fn roundtrip_boundaries() {
        for v in BOTH {
            for id in [
                Id::default(),
                Id {
                    pri: 3,
                    flags: 0,
                    src: v.max_node_id(),
                    dst: v.max_node_id(),
                    dport: 63,
                    sport: 63,
                },
                Id {
                    pri: 1,
                    flags: flags::CRC32 | flags::RDP,
                    src: 1,
                    dst: 2,
                    dport: 10,
                    sport: 20,
                },
            ] {
                let mut buf = [0u8; 8];
                let n = id.encode(v, &mut buf).unwrap();
                assert_eq!(n, v.header_size());
                assert_eq!(Id::decode(v, &buf[..n]).unwrap(), id, "version {v:?}");
            }
        }
    }

    #[test]
    fn v1_rejects_addresses_that_only_fit_v2() {
        // The C would shift this into the source address field and produce a valid-looking
        // header for a different packet.
        let id = Id {
            pri: 0,
            flags: 0,
            src: 1,
            dst: 1000,
            dport: 0,
            sport: 0,
        };
        let mut buf = [0u8; 4];
        assert_eq!(
            id.encode(Version::V1, &mut buf),
            Err(Error::FieldOutOfRange {
                field: Field::Destination
            })
        );
        // ... and the same value is fine in v2.
        let mut buf6 = [0u8; 6];
        assert!(id.encode(Version::V2, &mut buf6).is_ok());
    }

    #[test]
    fn v2_flags_are_six_bits_not_eight() {
        let id = Id {
            pri: 0,
            flags: 0xff,
            src: 0,
            dst: 0,
            dport: 0,
            sport: 0,
        };
        let mut buf = [0u8; 6];
        assert_eq!(
            id.encode(Version::V2, &mut buf),
            Err(Error::FieldOutOfRange {
                field: Field::Flags
            })
        );
        // v1 has a full byte of flags.
        let mut buf4 = [0u8; 4];
        assert!(id.encode(Version::V1, &mut buf4).is_ok());
    }

    #[test]
    fn priority_is_two_bits() {
        let id = Id {
            pri: 4,
            ..Id::default()
        };
        let mut buf = [0u8; 6];
        for v in BOTH {
            assert_eq!(
                id.encode(v, &mut buf),
                Err(Error::FieldOutOfRange {
                    field: Field::Priority
                })
            );
        }
    }

    #[test]
    fn short_buffer_reports_what_it_needed() {
        let id = Id::default();
        let mut buf = [0u8; 3];
        assert_eq!(
            id.encode(Version::V1, &mut buf),
            Err(Error::BufferTooSmall { needed: 4 })
        );
        assert_eq!(
            id.encode(Version::V2, &mut buf),
            Err(Error::BufferTooSmall { needed: 6 })
        );
    }

    #[test]
    fn short_input_is_truncated_not_garbage() {
        for v in BOTH {
            let data = [0u8; 3];
            assert_eq!(Id::decode(v, &data), Err(Error::Truncated));
        }
    }

    #[test]
    fn decode_never_panics_on_arbitrary_input() {
        // Every bit pattern must decode to *something* — a malformed frame is data, not a
        // reason to abort a flight computer.
        for v in BOTH {
            for seed in 0u32..=0xffff {
                let b = [
                    seed as u8,
                    (seed >> 8) as u8,
                    (seed >> 3) as u8,
                    (seed >> 5) as u8,
                    (seed >> 7) as u8,
                    (seed >> 11) as u8,
                ];
                let id = Id::decode(v, &b).unwrap();
                // and whatever comes out must round-trip
                let mut out = [0u8; 6];
                let n = id.encode(v, &mut out).unwrap();
                assert_eq!(Id::decode(v, &out[..n]).unwrap(), id);
            }
        }
    }

    #[test]
    fn all_nodes_address_is_always_broadcast() {
        for v in BOTH {
            assert!(v.is_broadcast(v.max_node_id(), 1, v.host_bits() as u16));
            assert!(!v.is_broadcast(1, 1, 0));
        }
    }

    #[test]
    fn fragment_flag_is_readable_from_the_header() {
        let mut id = Id::default();
        assert!(!id.is_fragment());
        id.flags = flags::FRAG;
        assert!(id.is_fragment());
        // and survives a round trip, since that is how a port decides which shape arrived
        for v in BOTH {
            let mut buf = [0u8; 6];
            let n = id.encode(v, &mut buf).unwrap();
            assert!(Id::decode(v, &buf[..n]).unwrap().is_fragment());
        }
    }
}
