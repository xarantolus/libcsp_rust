//! HMAC-SHA1, truncated to 4 bytes, as libcsp appends it to packets.
//!
//! # A word about that truncation
//!
//! [`MAC_LEN`] is **4 bytes**. A 32-bit authentication tag means a blind forgery succeeds
//! roughly once in 4 billion attempts, which sounds comfortable until you notice a
//! spacecraft link has no rate limit an attacker must respect and no lockout. This is a
//! property of the CSP wire format, not a choice this crate makes, and it is why the
//! flight software does not rely on HMAC for anything that matters.
//!
//! The key is a **parameter**, not a global. The C keeps a single
//! `static uint8_t csp_hmac_key[16]` for the whole process, so two links cannot use
//! different keys.
//!
//! # Sharp edge in the C worth knowing about
//!
//! `csp_hmac_memory()` takes an unsized `uint8_t * hmac` out-parameter and writes the
//! **full 20-byte** SHA-1 digest, while `CSP_HMAC_LENGTH` is 4. Passing a
//! `uint8_t[CSP_HMAC_LENGTH]` — the obvious reading — overflows the caller's buffer by
//! 16 bytes. Here [`mac`] returns an array, so the size cannot be got wrong.

use crate::sha1::{self, Sha1, BLOCK_LEN, DIGEST_LEN};
use crate::{Error, Result};

/// Bytes of MAC appended to a packet. See the module docs before relying on this.
pub const MAC_LEN: usize = 4;

/// Length of the key libcsp derives and stores.
pub const KEY_LEN: usize = 16;

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

/// Full HMAC-SHA1 of `data` under `key`.
///
/// Returns [`Error::EmptyKey`] for an empty key, matching the C, which rejects
/// `keylen < 1` — and, unlike the C, without leaving the output buffer untouched for the
/// caller to misread as a result.
pub fn mac_full(key: &[u8], data: &[u8]) -> Result<[u8; DIGEST_LEN]> {
    if key.is_empty() {
        return Err(Error::EmptyKey);
    }

    // Keys longer than the block are hashed first; shorter keys are zero-padded.
    let mut k = [0u8; BLOCK_LEN];
    if key.len() > BLOCK_LEN {
        k[..DIGEST_LEN].copy_from_slice(&sha1::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0u8; BLOCK_LEN];
    let mut outer_pad = [0u8; BLOCK_LEN];
    for i in 0..BLOCK_LEN {
        inner_pad[i] = k[i] ^ IPAD;
        outer_pad[i] = k[i] ^ OPAD;
    }

    let mut inner = Sha1::new();
    inner.update(&inner_pad);
    inner.update(data);
    let inner_digest = inner.finalize();

    let mut outer = Sha1::new();
    outer.update(&outer_pad);
    outer.update(&inner_digest);
    Ok(outer.finalize())
}

/// HMAC-SHA1 truncated to the [`MAC_LEN`] bytes that go on the wire.
pub fn mac(key: &[u8], data: &[u8]) -> Result<[u8; MAC_LEN]> {
    let full = mac_full(key, data)?;
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&full[..MAC_LEN]);
    Ok(out)
}

/// Derive the stored key the way `csp_hmac_set_key` does: SHA-1 of the input, truncated
/// to [`KEY_LEN`].
pub fn derive_key(material: &[u8]) -> [u8; KEY_LEN] {
    let h = sha1::digest(material);
    let mut k = [0u8; KEY_LEN];
    k.copy_from_slice(&h[..KEY_LEN]);
    k
}

/// Verify a trailing MAC in constant time and return the payload without it.
pub fn verify<'a>(key: &[u8], payload_with_mac: &'a [u8]) -> Result<&'a [u8]> {
    if payload_with_mac.len() < MAC_LEN {
        return Err(Error::Truncated);
    }
    let split = payload_with_mac.len() - MAC_LEN;
    let (payload, tail) = payload_with_mac.split_at(split);
    let expected = mac(key, payload)?;

    // Constant time: a byte-by-byte early return leaks how much of the tag was right,
    // which turns a 2^32 forgery into 4 x 2^8.
    let mut diff = 0u8;
    for i in 0..MAC_LEN {
        diff |= tail[i] ^ expected[i];
    }
    if diff != 0 {
        return Err(Error::BadChecksum);
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(d: &[u8]) -> [u8; 4] {
        let mut o = [0u8; 4];
        o.copy_from_slice(&d[..4]);
        o
    }

    #[test]
    fn rfc2202_style_vector() {
        // The classic HMAC-SHA1 test vector, also emitted by the oracle.
        let m = mac_full(b"key", b"The quick brown fox jumps over the lazy dog").unwrap();
        assert_eq!(
            h(&m),
            [0xde, 0x7c, 0x9b, 0x85],
            "HMAC-SHA1(key, quick brown fox) should start de7c9b85"
        );
    }

    #[test]
    fn empty_key_is_refused_not_silently_accepted() {
        assert_eq!(mac(b"", b"anything"), Err(Error::EmptyKey));
        assert_eq!(mac_full(b"", b""), Err(Error::EmptyKey));
    }

    #[test]
    fn long_keys_are_hashed_first() {
        // Longer than the 64-byte block, so the key gets replaced by its digest.
        let long = [b'k'; 100];
        let a = mac(&long, b"abc").unwrap();
        let mut expected_key = [0u8; 64];
        expected_key[..20].copy_from_slice(&crate::sha1::digest(&long));
        let b = mac(&expected_key[..20], b"abc").unwrap();
        assert_eq!(a, b, "a >block key must equal its digest as a key");
    }

    #[test]
    fn truncation_is_the_prefix_of_the_full_mac() {
        let full = mac_full(b"secret", b"abc").unwrap();
        let short = mac(b"secret", b"abc").unwrap();
        assert_eq!(&full[..MAC_LEN], &short[..]);
    }

    #[test]
    fn verify_roundtrips_and_rejects_tampering() {
        let key = b"0123456789abcdef";
        let payload = b"telemetry";
        let mut buf = [0u8; 32];
        buf[..payload.len()].copy_from_slice(payload);
        let tag = mac(key, payload).unwrap();
        buf[payload.len()..payload.len() + MAC_LEN].copy_from_slice(&tag);
        let n = payload.len() + MAC_LEN;

        assert_eq!(verify(key, &buf[..n]).unwrap(), payload);

        for i in 0..n {
            let mut bad = buf;
            bad[i] ^= 0x01;
            assert_eq!(
                verify(key, &bad[..n]),
                Err(Error::BadChecksum),
                "tamper at {i} accepted"
            );
        }
        // and a different key must not validate
        assert_eq!(verify(b"wrong key", &buf[..n]), Err(Error::BadChecksum));
    }

    #[test]
    fn verify_rejects_input_too_short_for_a_tag() {
        assert_eq!(verify(b"k", &[1, 2, 3]), Err(Error::Truncated));
    }

    #[test]
    fn derive_key_is_the_sha1_prefix() {
        let k = derive_key(b"passphrase");
        assert_eq!(k[..], crate::sha1::digest(b"passphrase")[..KEY_LEN]);
    }
}
