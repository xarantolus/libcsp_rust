//! Frame conversion (`Packet::to_frame` / `Packet::from_frame`) and CRC32 with
//! wire format v1. Runs in its own process, so it owns the global stack.

use libcsp::{sys, CspConfig, CspError, CspInterface, CspNode, Packet};
use std::sync::OnceLock;

static NODE: OnceLock<CspNode> = OnceLock::new();

fn init() {
    NODE.get_or_init(|| CspConfig::new().address(1).version(1).init().expect("init"));
}

fn packet(id: sys::csp_id_t, payload: &[u8]) -> Packet {
    let mut p = Packet::get(0).expect("buffer");
    p.set_id(id);
    p.write(payload).unwrap();
    p
}

fn id(pri: u8, src: u16, dst: u16, dport: u8, sport: u8, flags: u8) -> sys::csp_id_t {
    sys::csp_id_t {
        pri,
        flags,
        src,
        dst,
        dport,
        sport,
    }
}

#[test]
fn frame_round_trip_keeps_header_fields_and_payload() {
    init();
    let mut out = packet(id(2, 5, 1, 20, 33, 0), &[0xde, 0xad, 0xbe, 0xef]);
    let frame = out.to_frame().unwrap().to_vec();

    let back = Packet::from_frame(&frame).unwrap();

    assert_eq!(frame.len(), 4 + 4, "v1 header is 4 bytes");
    assert_eq!(
        (
            back.priority() as u8,
            back.src_addr(),
            back.dst_addr(),
            back.dst_port(),
            back.src_port()
        ),
        (2, 5, 1, 20, 33)
    );
    assert_eq!(back.data(), &[0xde, 0xad, 0xbe, 0xef]);
}

/// Golden vector produced by libcsp 2.1 (wire format v1); guards against a
/// change in header encoding.
#[test]
fn v1_header_matches_the_golden_vector() {
    init();
    let mut p = packet(id(2, 5, 1, 20, 33, 0x01), &[0x01]);
    assert_eq!(p.to_frame().unwrap(), &[0x8a, 0x15, 0x21, 0x01, 0x01]);
}

#[test]
fn from_frame_rejects_frames_that_cannot_be_packets() {
    init();
    let too_short = [0u8; 3];
    let too_long = vec![0u8; 4 + libcsp::sys::CSP_BUFFER_SIZE as usize + 1];
    assert!(matches!(
        Packet::from_frame(&too_short),
        Err(CspError::InvalidArgument)
    ));
    assert!(matches!(
        Packet::from_frame(&too_long),
        Err(CspError::InvalidArgument)
    ));
    assert!(Packet::from_frame(&too_long[..4 + libcsp::sys::CSP_BUFFER_SIZE as usize]).is_ok());
}

#[test]
fn crc32_survives_the_frame_round_trip_and_detects_corruption() {
    init();
    let mut p = packet(id(2, 5, 1, 20, 33, 0x01), b"hello");
    p.crc32_append().unwrap();
    let frame = p.to_frame().unwrap().to_vec();

    let mut good = Packet::from_frame(&frame).unwrap();
    good.crc32_verify().unwrap();
    assert_eq!(good.data(), b"hello");

    let mut corrupt = frame.clone();
    corrupt[5] ^= 0xff;
    let mut bad = Packet::from_frame(&corrupt).unwrap();
    assert!(matches!(bad.crc32_verify(), Err(CspError::Crc32Failed)));
}

/// The packet CRC32 covers the payload only (CSP 1 convention, `CSP_21` unset).
#[test]
fn packet_crc32_covers_the_payload() {
    init();
    let mut p = packet(id(2, 5, 1, 20, 33, 0x01), b"hello");
    p.crc32_append().unwrap();
    let trailer = u32::from_be_bytes(p.data()[5..].try_into().unwrap());
    assert_eq!(libcsp::crc32::memory(b"hello"), trailer);
}

struct Named(&'static str);

impl CspInterface for Named {
    fn nexthop(&mut self, _via: u16, _packet: Packet, _from_me: bool) {}
    fn name(&self) -> &str {
        self.0
    }
}

#[test]
fn interface_name_with_nul_is_an_error() {
    init();
    assert!(matches!(
        libcsp::interface::try_register(Named("bad\0name")),
        Err(CspError::InvalidArgument)
    ));
}
