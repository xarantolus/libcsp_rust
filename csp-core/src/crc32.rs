//! CRC-32C (Castagnoli), as libcsp uses it.
//!
//! Public because it has to be: libcsp exposes no checksum helper, so the ground station
//! pulls CRC-32C from a separate Python package and the packet decoder brute-forces
//! payload lengths until one validates.
//!
//! The C ships a 256-entry table as a literal. Here it is derived at compile time from
//! the reflected polynomial, so there is one source of truth instead of 1 KiB of hex
//! nobody will ever re-derive.

/// Reflected CRC-32C polynomial.
const POLY: u32 = 0x82F6_3B78;

const INIT: u32 = 0xFFFF_FFFF;
const XOROUT: u32 = 0xFFFF_FFFF;

/// Width of the checksum appended to a packet.
pub const CRC32_LEN: usize = 4;

const fn build_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ POLY
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

static TABLE: [u32; 256] = build_table();

/// Incremental CRC-32C state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crc32(u32);

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32 {
    /// Start a new checksum.
    pub const fn new() -> Self {
        Crc32(INIT)
    }

    /// Feed bytes.
    pub fn update(&mut self, data: &[u8]) {
        let mut crc = self.0;
        for &b in data {
            crc = TABLE[((crc ^ b as u32) & 0xff) as usize] ^ (crc >> 8);
        }
        self.0 = crc;
    }

    /// Finish, producing the checksum value.
    pub const fn finalize(self) -> u32 {
        self.0 ^ XOROUT
    }
}

/// One-shot CRC-32C over `data`.
pub fn checksum(data: &[u8]) -> u32 {
    let mut c = Crc32::new();
    c.update(data);
    c.finalize()
}

/// Which bytes a packet's checksum covers.
///
/// libcsp changed this between releases, and its verifier papers over the change by
/// trying one and falling back to the other. That silent fallback means a receiver can
/// accept a frame whose checksum covers *different bytes than it thinks*, so the choice
/// is explicit here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    /// Checksum covers the payload only. Pre-2.1 behaviour.
    PayloadOnly,
    /// Checksum covers the encoded header followed by the payload. CSP 2.1 default.
    HeaderAndPayload,
}

/// Verify and strip a trailing CRC-32C.
///
/// Returns the payload with the checksum removed. `header` is the encoded CSP header, used
/// only when `coverage` is [`Coverage::HeaderAndPayload`].
pub fn verify<'a>(
    header: &[u8],
    payload_with_crc: &'a [u8],
    coverage: Coverage,
) -> crate::Result<&'a [u8]> {
    if payload_with_crc.len() < CRC32_LEN {
        return Err(crate::Error::Truncated);
    }
    let split = payload_with_crc.len() - CRC32_LEN;
    let (payload, tail) = payload_with_crc.split_at(split);

    let mut c = Crc32::new();
    if coverage == Coverage::HeaderAndPayload {
        c.update(header);
    }
    c.update(payload);
    let expected = c.finalize().to_be_bytes();

    if tail != expected {
        return Err(crate::Error::BadChecksum);
    }
    Ok(payload)
}

/// Append a CRC-32C to `payload` in `out`, returning the total length written.
pub fn append(header: &[u8], payload: &[u8], coverage: Coverage, out: &mut [u8]) -> crate::Result<usize> {
    let needed = payload.len() + CRC32_LEN;
    if out.len() < needed {
        return Err(crate::Error::BufferTooSmall { needed });
    }
    out[..payload.len()].copy_from_slice(payload);

    let mut c = Crc32::new();
    if coverage == Coverage::HeaderAndPayload {
        c.update(header);
    }
    c.update(payload);
    out[payload.len()..needed].copy_from_slice(&c.finalize().to_be_bytes());
    Ok(needed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_matches_the_c_literal() {
        // Spot-check against the values written out in csp_crc32.c. If the polynomial or
        // reflection were wrong these would diverge immediately.
        assert_eq!(TABLE[0], 0x0000_0000);
        assert_eq!(TABLE[1], 0xF26B_8303);
        assert_eq!(TABLE[2], 0xE13B_70F7);
        assert_eq!(TABLE[3], 0x1350_F3F4);
        assert_eq!(TABLE[8], 0x8AD9_58CF);
        assert_eq!(TABLE[16], 0x105E_C76F);
    }

    #[test]
    fn known_answers() {
        // CRC-32C reference vectors.
        assert_eq!(checksum(b""), 0x0000_0000);
        assert_eq!(checksum(b"a"), 0xC1D0_4330);
        assert_eq!(checksum(b"abc"), 0x364B_3FB7);
        assert_eq!(
            checksum(b"123456789"),
            0xE306_9283,
            "the standard CRC-32C check value"
        );
    }

    #[test]
    fn incremental_equals_one_shot() {
        let data: [u8; 64] = core::array::from_fn(|i| (i * 7) as u8);
        for split in 0..=data.len() {
            let mut c = Crc32::new();
            c.update(&data[..split]);
            c.update(&data[split..]);
            assert_eq!(c.finalize(), checksum(&data), "split at {split}");
        }
    }

    #[test]
    fn append_then_verify_roundtrips() {
        let header = [0xde, 0xad, 0xbe, 0xef];
        let payload = b"hello world";
        for coverage in [Coverage::PayloadOnly, Coverage::HeaderAndPayload] {
            let mut buf = [0u8; 32];
            let n = append(&header, payload, coverage, &mut buf).unwrap();
            assert_eq!(n, payload.len() + 4);
            assert_eq!(verify(&header, &buf[..n], coverage).unwrap(), payload);
        }
    }

    #[test]
    fn coverage_modes_are_not_interchangeable() {
        // This is the ambiguity the C verifier hides by trying both. A frame built with
        // one coverage must not silently validate under the other.
        let header = [0xde, 0xad, 0xbe, 0xef];
        let payload = b"hello world";
        let mut buf = [0u8; 32];
        let n = append(&header, payload, Coverage::PayloadOnly, &mut buf).unwrap();
        assert_eq!(
            verify(&header, &buf[..n], Coverage::HeaderAndPayload),
            Err(crate::Error::BadChecksum)
        );
    }

    #[test]
    fn corruption_is_detected() {
        let header = [0u8; 4];
        let payload = b"0123456789";
        let mut buf = [0u8; 32];
        let n = append(&header, payload, Coverage::PayloadOnly, &mut buf).unwrap();
        for i in 0..n {
            let mut bad = buf;
            bad[i] ^= 0x01;
            assert_eq!(
                verify(&header, &bad[..n], Coverage::PayloadOnly),
                Err(crate::Error::BadChecksum),
                "flipping a bit at {i} went undetected"
            );
        }
    }

    #[test]
    fn too_short_to_hold_a_checksum() {
        assert_eq!(
            verify(&[], &[1, 2, 3], Coverage::PayloadOnly),
            Err(crate::Error::Truncated)
        );
    }
}
