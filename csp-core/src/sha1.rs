//! SHA-1, as required by libcsp's HMAC.
//!
//! SHA-1 is cryptographically broken for collision resistance. It is here because it is
//! what the CSP wire format specifies and what every deployed peer implements — not
//! because it is a good choice. HMAC-SHA1 is not affected by the known collision attacks,
//! but see [`crate::hmac`] for the part that actually should worry you.

/// Length of a SHA-1 digest.
pub const DIGEST_LEN: usize = 20;
/// SHA-1 compression block size.
pub const BLOCK_LEN: usize = 64;

const H0: [u32; 5] = [
    0x6745_2301,
    0xEFCD_AB89,
    0x98BA_DCFE,
    0x1032_5476,
    0xC3D2_E1F0,
];

/// Incremental SHA-1 state.
#[derive(Clone)]
pub struct Sha1 {
    h: [u32; 5],
    block: [u8; BLOCK_LEN],
    used: usize,
    len_bits: u64,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
    /// Start a new digest.
    pub const fn new() -> Self {
        Sha1 {
            h: H0,
            block: [0; BLOCK_LEN],
            used: 0,
            len_bits: 0,
        }
    }

    /// Feed bytes.
    pub fn update(&mut self, mut data: &[u8]) {
        self.len_bits = self.len_bits.wrapping_add((data.len() as u64) * 8);
        while !data.is_empty() {
            let take = core::cmp::min(BLOCK_LEN - self.used, data.len());
            self.block[self.used..self.used + take].copy_from_slice(&data[..take]);
            self.used += take;
            data = &data[take..];
            if self.used == BLOCK_LEN {
                let block = self.block;
                self.compress(&block);
                self.used = 0;
            }
        }
    }

    /// Finish, producing the digest.
    pub fn finalize(mut self) -> [u8; DIGEST_LEN] {
        let len_bits = self.len_bits;

        // 0x80, then zeroes, then the 64-bit big-endian bit length.
        self.update_raw(&[0x80]);
        while self.used != BLOCK_LEN - 8 {
            self.update_raw(&[0x00]);
        }
        self.update_raw(&len_bits.to_be_bytes());
        debug_assert_eq!(self.used, 0);

        let mut out = [0u8; DIGEST_LEN];
        for (i, word) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// Like `update` but does not count toward the length — used for padding.
    fn update_raw(&mut self, data: &[u8]) {
        for &b in data {
            self.block[self.used] = b;
            self.used += 1;
            if self.used == BLOCK_LEN {
                let block = self.block;
                self.compress(&block);
                self.used = 0;
            }
        }
    }

    fn compress(&mut self, block: &[u8; BLOCK_LEN]) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let [mut a, mut b, mut c, mut d, mut e] = self.h;

        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
    }
}

/// One-shot SHA-1 over `data`.
pub fn digest(data: &[u8]) -> [u8; DIGEST_LEN] {
    let mut s = Sha1::new();
    s.update(data);
    s.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_new() {
        assert_eq!(Sha1::default().finalize(), Sha1::new().finalize());
    }

    fn hex(d: &[u8]) -> heapless_hex::Hex {
        heapless_hex::Hex::new(d)
    }

    /// Tiny hex formatter so assertions read as hex without pulling in a dependency.
    mod heapless_hex {
        pub struct Hex([u8; 40], usize);
        impl Hex {
            pub fn new(d: &[u8]) -> Self {
                let mut buf = [0u8; 40];
                for (i, b) in d.iter().enumerate() {
                    const HEXD: &[u8; 16] = b"0123456789abcdef";
                    buf[i * 2] = HEXD[(b >> 4) as usize];
                    buf[i * 2 + 1] = HEXD[(b & 0xf) as usize];
                }
                Hex(buf, d.len() * 2)
            }
        }
        impl core::fmt::Debug for Hex {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                for &c in &self.0[..self.1] {
                    write!(f, "{}", c as char)?;
                }
                Ok(())
            }
        }
        impl PartialEq<&str> for Hex {
            fn eq(&self, other: &&str) -> bool {
                self.1 == other.len() && self.0[..self.1] == *other.as_bytes()
            }
        }
    }

    #[test]
    fn nist_vectors() {
        assert_eq!(
            hex(&digest(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            hex(&digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(&digest(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    #[test]
    fn padding_boundaries() {
        // 55/56 and 63/64 straddle the point where the length field forces an extra block.
        for n in [54usize, 55, 56, 57, 63, 64, 65, 119, 120, 128] {
            let data = [b'x'; 128];
            let d = digest(&data[..n]);
            // A digest is never all-zero for these inputs; the real check is against the
            // C in tests/vectors.rs. This just catches a padding loop that never ends.
            assert_ne!(d, [0u8; DIGEST_LEN], "n={n}");
        }
    }

    #[test]
    fn incremental_equals_one_shot() {
        let data: [u8; 200] = core::array::from_fn(|i| (i * 3) as u8);
        for split in [0usize, 1, 63, 64, 65, 100, 199, 200] {
            let mut s = Sha1::new();
            s.update(&data[..split]);
            s.update(&data[split..]);
            assert_eq!(s.finalize(), digest(&data), "split at {split}");
        }
    }
}
