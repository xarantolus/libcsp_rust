//! KISS framing (SLIP-style), as libcsp puts CSP frames on a serial line.
//!
//! A frame is `FEND, TNC_DATA, <escaped bytes>, FEND`, where `FEND` and `FESC` inside the
//! body are escaped. Both halves are sans-io: [`encode`] writes into a caller buffer and
//! [`Decoder`] is fed bytes as they arrive and hands back complete frames.
//!
//! # The CRC that is not what the source says it is
//!
//! With `CSP_ENABLE_KISS_CRC` (on by default) libcsp appends a CRC-32C before framing.
//! `csp_crc32_append` reads:
//!
//! ```c
//! #if CSP_21 // In CSP 2.1 we change to include header per default
//!     csp_id_prepend(packet);
//!     crc = csp_crc32_memory(packet->frame_begin, packet->frame_length);
//! #else
//!     crc = csp_crc32_memory(packet->data, packet->length);
//! #endif
//! ```
//!
//! **`CSP_21` is not defined by any build system in the tree** — not CMake, not meson,
//! not `csp_autoconfig.h.in`. So the header is never covered, and the receiver's
//! "try with header, fall back to without" always takes the fallback. Use
//! [`crc32::Coverage::PayloadOnly`](crate::crc32::Coverage::PayloadOnly) to interoperate.

use crate::{Error, Result};

/// Frame delimiter.
pub const FEND: u8 = 0xC0;
/// Escape byte.
pub const FESC: u8 = 0xDB;
/// Escaped `FEND`.
pub const TFEND: u8 = 0xDC;
/// Escaped `FESC`.
pub const TFESC: u8 = 0xDD;
/// KISS command byte for a data frame on port 0.
pub const TNC_DATA: u8 = 0x00;

/// Bytes an encoded frame needs, worst case, for a body of `n` bytes.
///
/// Every body byte can escape to two, plus the leading `FEND`+`TNC_DATA` and trailing
/// `FEND`.
pub const fn max_encoded_len(body_len: usize) -> usize {
    2 + body_len * 2 + 1
}

/// KISS-encode `body` into `out`, returning the number of bytes written.
///
/// `body` is the complete CSP frame — encoded header followed by payload (and the CRC, if
/// one is in use).
pub fn encode(body: &[u8], out: &mut [u8]) -> Result<usize> {
    let mut n = 0usize;
    let put = |b: u8, out: &mut [u8], n: &mut usize| -> Result<()> {
        if *n >= out.len() {
            return Err(Error::BufferTooSmall {
                needed: max_encoded_len(body.len()),
            });
        }
        out[*n] = b;
        *n += 1;
        Ok(())
    };

    put(FEND, out, &mut n)?;
    put(TNC_DATA, out, &mut n)?;
    for &b in body {
        match b {
            FEND => {
                put(FESC, out, &mut n)?;
                put(TFEND, out, &mut n)?;
            }
            FESC => {
                put(FESC, out, &mut n)?;
                put(TFESC, out, &mut n)?;
            }
            _ => put(b, out, &mut n)?,
        }
    }
    put(FEND, out, &mut n)?;
    Ok(n)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Waiting for a `FEND` to start a frame.
    Idle,
    /// Inside a frame.
    InFrame,
    /// Previous byte was `FESC`.
    Escaped,
    /// Frame overflowed the buffer; discard until the next `FEND`.
    Skip,
}

/// Incremental KISS decoder over a fixed-capacity buffer.
///
/// `N` is the largest frame body it will accept. A frame longer than that is dropped and
/// counted, not truncated into something that looks valid — see [`Decoder::overruns`].
pub struct Decoder<const N: usize> {
    buf: [u8; N],
    len: usize,
    mode: Mode,
    /// The byte after `FEND` is the KISS command; skip it once per frame.
    expect_command: bool,
    overruns: u32,
}

impl<const N: usize> Default for Decoder<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Decoder<N> {
    /// Create an idle decoder.
    pub const fn new() -> Self {
        Decoder {
            buf: [0; N],
            len: 0,
            mode: Mode::Idle,
            expect_command: false,
            overruns: 0,
        }
    }

    /// Number of frames dropped because they exceeded `N` bytes.
    pub const fn overruns(&self) -> u32 {
        self.overruns
    }

    /// Discard any partial frame and return to idle.
    pub fn reset(&mut self) {
        self.len = 0;
        self.mode = Mode::Idle;
        self.expect_command = false;
    }

    /// Feed one byte.
    ///
    /// Returns `Some(frame)` when a complete, non-empty frame has been assembled. The
    /// slice borrows the decoder's buffer and is valid until the next call.
    pub fn push(&mut self, b: u8) -> Option<&[u8]> {
        match self.mode {
            Mode::Idle => {
                if b == FEND {
                    self.len = 0;
                    self.mode = Mode::InFrame;
                    self.expect_command = true;
                }
                None
            }
            Mode::Skip => {
                if b == FEND {
                    // This FEND opens the next frame rather than closing the bad one.
                    self.len = 0;
                    self.mode = Mode::InFrame;
                    self.expect_command = true;
                }
                None
            }
            Mode::InFrame => {
                if b == FESC {
                    // Matches the C: the escape check precedes the command-byte skip, so
                    // a FESC immediately after FEND is an escape, not the command byte.
                    self.mode = Mode::Escaped;
                    return None;
                }
                if b == FEND {
                    let done = self.len > 0;
                    let n = self.len;
                    self.len = 0;
                    self.expect_command = true;
                    self.mode = Mode::InFrame;
                    return if done { Some(&self.buf[..n]) } else { None };
                }
                if self.expect_command {
                    self.expect_command = false;
                    return None;
                }
                self.append(b);
                None
            }
            Mode::Escaped => {
                // The C appends ONLY for TFESC and TFEND:
                //
                //     if (inputbyte == TFESC) ...frame_begin[rx_length++] = FESC;
                //     if (inputbyte == TFEND) ...frame_begin[rx_length++] = FEND;
                //
                // Any other byte after FESC is silently dropped, not passed through. That
                // is a real interop detail rather than a nicety: passing it through would
                // build a frame one byte longer than the peer built, so the two sides
                // would disagree about the payload (and, with the KISS CRC enabled,
                // disagree about the checksum too).
                self.mode = Mode::InFrame;
                let decoded = match b {
                    TFEND => FEND,
                    TFESC => FESC,
                    _ => return None,
                };
                if self.expect_command {
                    self.expect_command = false;
                    return None;
                }
                self.append(decoded);
                None
            }
        }
    }

    fn append(&mut self, b: u8) {
        if self.len >= N {
            self.overruns += 1;
            self.mode = Mode::Skip;
            self.len = 0;
            return;
        }
        self.buf[self.len] = b;
        self.len += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<const N: usize>(body: &[u8]) {
        let mut enc = [0u8; 1024];
        let n = encode(body, &mut enc).unwrap();
        let mut d = Decoder::<N>::new();
        let mut out = [0u8; 512];
        let mut got_len: Option<usize> = None;
        for (i, &b) in enc[..n].iter().enumerate() {
            if let Some(frame) = d.push(b) {
                assert!(got_len.is_none(), "two frames from one encode");
                assert_eq!(i, n - 1, "frame ended early");
                out[..frame.len()].copy_from_slice(frame);
                got_len = Some(frame.len());
            }
        }
        let len = got_len.expect("no frame decoded");
        assert_eq!(&out[..len], body, "roundtrip failed");
    }

    #[test]
    fn frame_structure_matches_the_c() {
        let mut out = [0u8; 16];
        let n = encode(&[0x41, 0x42], &mut out).unwrap();
        assert_eq!(&out[..n], &[FEND, TNC_DATA, 0x41, 0x42, FEND]);
    }

    #[test]
    fn an_empty_body_does_not_survive_a_round_trip() {
        // The C accepts a frame only when rx_length > 0, so FEND,TNC_DATA,FEND decodes to
        // nothing at all. Harmless in practice -- a real CSP frame always carries a
        // header -- but it means "encode then decode" is not total, and a caller that
        // assumes it is will wait forever for a frame that is never coming.
        let mut enc = [0u8; 8];
        let n = encode(&[], &mut enc).unwrap();
        assert_eq!(&enc[..n], &[FEND, TNC_DATA, FEND]);

        let mut d = Decoder::<64>::new();
        for &b in &enc[..n] {
            assert!(d.push(b).is_none(), "an empty frame must not be delivered");
        }
    }

    #[test]
    fn empty_body_is_still_framed() {
        let mut out = [0u8; 8];
        let n = encode(&[], &mut out).unwrap();
        assert_eq!(&out[..n], &[FEND, TNC_DATA, FEND]);
    }

    #[test]
    fn delimiters_in_the_body_are_escaped() {
        let mut out = [0u8; 32];
        let n = encode(&[FEND, FESC], &mut out).unwrap();
        assert_eq!(
            &out[..n],
            &[FEND, TNC_DATA, FESC, TFEND, FESC, TFESC, FEND]
        );
        // and no raw FEND appears inside the body
        assert!(!out[2..n - 1].contains(&FEND));
    }

    #[test]
    fn roundtrip_including_every_byte_value() {
        let all: [u8; 256] = core::array::from_fn(|i| i as u8);
        roundtrip::<512>(&all);
        roundtrip::<512>(&[FEND]);
        roundtrip::<512>(&[FESC]);
        roundtrip::<512>(&[FEND, FEND, FESC, FESC]);
        roundtrip::<512>(b"hello world");
    }

    #[test]
    fn encode_reports_the_worst_case_size_it_needed() {
        // Two escape-worthy bytes need 2 + 4 + 1 = 7.
        let mut small = [0u8; 6];
        assert_eq!(
            encode(&[FEND, FESC], &mut small),
            Err(Error::BufferTooSmall { needed: 7 })
        );
        assert_eq!(max_encoded_len(2), 7);
    }

    #[test]
    fn leading_garbage_before_the_first_fend_is_skipped() {
        let mut d = Decoder::<64>::new();
        for b in [0x11, 0x22, 0x33] {
            assert!(d.push(b).is_none());
        }
        for b in [FEND, TNC_DATA, 0x41] {
            assert!(d.push(b).is_none());
        }
        assert_eq!(d.push(FEND), Some(&[0x41][..]));
    }

    #[test]
    fn back_to_back_frames_share_a_delimiter() {
        // FEND closing one frame also opens the next.
        let mut d = Decoder::<64>::new();
        let stream = [FEND, TNC_DATA, 0x41, FEND, TNC_DATA, 0x42, FEND];
        let mut frames = [[0u8; 4]; 4];
        let mut n = 0usize;
        for &b in &stream {
            if let Some(f) = d.push(b) {
                frames[n][..f.len()].copy_from_slice(f);
                n += 1;
            }
        }
        assert_eq!(n, 2, "expected two frames");
        assert_eq!(frames[0][0], 0x41);
        assert_eq!(frames[1][0], 0x42);
    }

    #[test]
    fn repeated_fends_do_not_emit_empty_frames() {
        let mut d = Decoder::<64>::new();
        for _ in 0..5 {
            assert!(d.push(FEND).is_none());
        }
    }

    #[test]
    fn an_invalid_escape_drops_the_byte_as_the_c_does() {
        // The C appends only for TFESC and TFEND. Passing an unknown escape through would
        // build a frame one byte longer than the peer built.
        let mut d = Decoder::<64>::new();
        let stream = [FEND, TNC_DATA, 0x41, FESC, 0x99, 0x42, FEND];
        let mut out = [0u8; 8];
        let mut len = None;
        for &b in &stream {
            if let Some(f) = d.push(b) {
                out[..f.len()].copy_from_slice(f);
                len = Some(f.len());
            }
        }
        let n = len.expect("a frame should have been delivered");
        assert_eq!(
            &out[..n],
            &[0x41u8, 0x42],
            "the invalid escape byte must vanish, not appear as 0x99"
        );
    }

    #[test]
    fn oversized_frame_is_dropped_not_truncated() {
        // A truncated frame that still parses is worse than no frame: it would be
        // delivered as a short, valid-looking packet.
        let mut d = Decoder::<4>::new();
        assert!(d.push(FEND).is_none());
        assert!(d.push(TNC_DATA).is_none());
        for i in 0..10u8 {
            assert!(d.push(i).is_none());
        }
        assert!(d.push(FEND).is_none(), "overlong frame must not be emitted");
        assert_eq!(d.overruns(), 1);

        // and the decoder recovers for the next frame
        for b in [TNC_DATA, 0x41] {
            assert!(d.push(b).is_none());
        }
        assert_eq!(d.push(FEND), Some(&[0x41][..]));
    }

    #[test]
    fn reset_discards_a_partial_frame() {
        let mut d = Decoder::<64>::new();
        for b in [FEND, TNC_DATA, 0x41, 0x42] {
            d.push(b);
        }
        d.reset();
        assert!(d.push(FEND).is_none());
        // the 0x41,0x42 must be gone
        for b in [TNC_DATA, 0x43] {
            assert!(d.push(b).is_none());
        }
        assert_eq!(d.push(FEND), Some(&[0x43][..]));
    }

    #[test]
    fn decoder_never_panics_on_arbitrary_input() {
        let mut d = Decoder::<32>::new();
        let mut x: u32 = 0x1234_5678;
        for _ in 0..200_000 {
            // xorshift, so the stream is deterministic but covers the state machine
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            let _ = d.push(x as u8);
        }
    }
}
