//! KISS frames that share a delimiter, against the real `csp_kiss_rx`.
//!
//! The KISS specification lets one `FEND` close a frame and open the next. Every existing
//! comparison here feeds one frame at a time, so what the two decoders do with a *stream*
//! was a reading. Measured:
//!
//! - `csp_kiss_rx` goes to `KISS_MODE_NOT_STARTED` after accepting a frame, and in that
//!   mode skips everything up to the next `FEND`. A second frame that reuses the first's
//!   closing `FEND` is therefore **discarded whole** by the C.
//! - After an empty frame (`FEND 00 FEND`) the C stays in `STARTED` with `rx_first`
//!   already cleared, so the next frame's command byte is taken as data and the frame is
//!   rejected by the header parser.
//!
//! The port's decoder treats any `FEND` as a fresh start. It delivers both. That is a
//! deliberate deviation — a receiver that loses valid frames is worse than one that
//! accepts them — recorded in SCOPE.md with these measurements, and pinned here on both
//! sides so the difference stays measured rather than assumed.

use csp_core::kiss;
use csp_core::{Id, Version};
use difftest::*;

const VERSION: Version = Version::V1;

/// A complete CSP frame body: header, payload, and the CRC the C's KISS layer demands.
fn body(seed: u8) -> Vec<u8> {
    let id = Id {
        pri: 2,
        flags: 0,
        src: 3,
        dst: 4,
        dport: 10,
        sport: 20,
    };
    let payload = [seed, seed.wrapping_add(1), seed.wrapping_add(2)];
    let mut b = vec![0u8; 4 + payload.len() + 4];
    id.encode(VERSION, &mut b).unwrap();
    b[4..7].copy_from_slice(&payload);
    b[7..].copy_from_slice(&csp_core::crc32::checksum(&payload).to_be_bytes());
    b
}

fn framed(b: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; kiss::max_encoded_len(b.len())];
    let n = kiss::encode(b, &mut out).unwrap();
    out.truncate(n);
    out
}

fn port_frames(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut d = kiss::Decoder::<256>::new();
    let mut out = Vec::new();
    for &x in bytes {
        if let Some(f) = d.push(x) {
            out.push(f.to_vec());
        }
    }
    out
}

#[test]
fn two_frames_sharing_a_fend() {
    let _g = lock();
    c_set_version(VERSION);
    let (a, b) = (body(0x10), body(0x20));
    // `FEND 00 A FEND 00 B FEND`: B reuses A's closing delimiter.
    let mut stream = framed(&a);
    stream.push(kiss::TNC_DATA);
    stream.extend_from_slice(&framed(&b)[2..]);

    let c = c_kiss_decode(&stream);
    assert_eq!(
        c.frames, 1,
        "the C accepts A and, in NOT_STARTED, skips B up to its FEND"
    );
    assert_eq!(c.last.as_deref(), Some(&a[4..7]));

    let r = port_frames(&stream);
    assert_eq!(r, vec![a.clone(), b.clone()], "the port delivers both");
}

#[test]
fn an_empty_frame_then_a_frame_sharing_its_fend() {
    let _g = lock();
    c_set_version(VERSION);
    let a = body(0x30);
    // `FEND 00 FEND 00 A FEND`
    let mut stream = vec![kiss::FEND, kiss::TNC_DATA, kiss::FEND];
    stream.extend_from_slice(&framed(&a)[1..]);

    let c = c_kiss_decode(&stream);
    assert_eq!(
        c.frames, 0,
        "the C takes A's command byte as data and the header parser refuses the frame"
    );
    assert_eq!(c.frame_errors, 1);

    assert_eq!(
        port_frames(&stream),
        vec![a.clone()],
        "the port re-arms the command skip on every FEND"
    );
}
