//! Differential tests against the golden vectors captured from the C library.
//!
//! These are the load-bearing tests: `vectors/v{1,2}.tsv` are the real wire bytes the C
//! produced, captured through a capture interface after `csp_id_prepend`, after SFP
//! headers, after CFP fragmentation. Passing here means the Rust encodes what libcsp
//! encodes, byte for byte.
//!
//! Regenerate with `oracle/gen_vectors.c` — see `oracle/README.md`.

use csp_core::{crc32, Id, Version};
use std::collections::HashMap;

/// One line of the vector file.
struct Vector {
    kind: String,
    /// Parsed `key=value` pairs from the input description.
    args: HashMap<String, String>,
    /// The raw description, for failure messages.
    desc: String,
    out: Vec<u8>,
}

impl Vector {
    fn get(&self, k: &str) -> Option<&str> {
        self.args.get(k).map(|s| s.as_str())
    }
    fn num(&self, k: &str) -> Option<u64> {
        let v = self.get(k)?;
        if let Some(hex) = v.strip_prefix("0x") {
            u64::from_str_radix(hex, 16).ok()
        } else {
            v.parse().ok()
        }
    }
    fn out_u32(&self) -> u32 {
        assert_eq!(self.out.len(), 4, "{}: expected a 4-byte value", self.desc);
        u32::from_be_bytes([self.out[0], self.out[1], self.out[2], self.out[3]])
    }
}

fn load() -> Vec<Vector> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("vectors");
    let mut all = Vec::new();
    for name in ["v1.tsv", "v2.tsv"] {
        let path = root.join(name);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        for line in text.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            let mut f = line.split('\t');
            let kind = f.next().unwrap().to_string();
            let desc = f.next().unwrap_or("").to_string();
            let hex = f.next().unwrap_or("");
            let out = (0..hex.len() / 2)
                .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
                .collect();
            let args = desc
                .split(',')
                .filter_map(|kv| kv.split_once('='))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            all.push(Vector {
                kind,
                args,
                desc,
                out,
            });
        }
    }
    assert!(!all.is_empty(), "no vectors loaded");
    all
}

fn version_of(v: &Vector) -> Version {
    match v.num("v") {
        Some(1) => Version::V1,
        Some(2) => Version::V2,
        other => panic!("{}: bad version {other:?}", v.desc),
    }
}

fn id_of(v: &Vector) -> Id {
    Id {
        pri: v.num("pri").unwrap() as u8,
        flags: v.num("flags").unwrap() as u8,
        src: v.num("src").unwrap() as u16,
        dst: v.num("dst").unwrap() as u16,
        dport: v.num("dport").unwrap() as u8,
        sport: v.num("sport").unwrap() as u8,
    }
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd-length hex: {s:?}");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

#[test]
fn header_encoding_matches_the_c_byte_for_byte() {
    let vectors = load();
    let mut checked = 0;
    for v in vectors.iter().filter(|v| v.kind.starts_with("id_v")) {
        let version = version_of(v);
        let id = id_of(v);
        let payload = unhex(v.get("payload").unwrap_or(""));

        // The oracle emitted the whole frame: header followed by payload.
        let hdr_len = version.header_size();
        assert_eq!(
            v.out.len(),
            hdr_len + payload.len(),
            "{}: unexpected frame length",
            v.desc
        );

        let mut buf = [0u8; 8];
        let n = id
            .encode(version, &mut buf)
            .unwrap_or_else(|e| panic!("{}: encode failed: {e:?}", v.desc));
        assert_eq!(
            &buf[..n],
            &v.out[..hdr_len],
            "{}: header mismatch\n  rust: {:02x?}\n  c:    {:02x?}",
            v.desc,
            &buf[..n],
            &v.out[..hdr_len]
        );

        // and the payload the C put after it is what we expect
        assert_eq!(&v.out[hdr_len..], &payload[..], "{}", v.desc);
        checked += 1;
    }
    assert!(checked >= 100, "only checked {checked} header vectors");
    println!("checked {checked} header vectors");
}

#[test]
fn header_decoding_matches_the_c() {
    let vectors = load();
    let mut checked = 0;
    for v in vectors.iter().filter(|v| v.kind.starts_with("id_v")) {
        let version = version_of(v);
        let expected = id_of(v);
        let decoded = Id::decode(version, &v.out).unwrap();
        assert_eq!(decoded, expected, "{}", v.desc);
        checked += 1;
    }
    println!("checked {checked} header decodes");
}

#[test]
fn version_derived_parameters_match_the_c() {
    let vectors = load();
    let mut checked = 0;
    for v in &vectors {
        let val = match v.kind.as_str() {
            "id_host_bits" => version_of(v).host_bits() as u64,
            "id_max_nodeid" => version_of(v).max_node_id() as u64,
            "id_max_port" => version_of(v).max_port() as u64,
            "id_header_size" => version_of(v).header_size() as u64,
            _ => continue,
        };
        assert_eq!(val, v.out_u32() as u64, "{} {}", v.kind, v.desc);
        checked += 1;
    }
    assert_eq!(checked, 8, "expected 4 parameters x 2 versions");
}

#[test]
fn broadcast_detection_matches_the_c() {
    let vectors = load();
    let mut checked = 0;
    for v in vectors.iter().filter(|v| v.kind == "id_is_broadcast") {
        let version = version_of(v);
        let addr = v.num("addr").unwrap() as u16;
        // The oracle used the capture interface: addr 0, netmask 0.
        let got = version.is_broadcast(addr, 0, 0);
        assert_eq!(
            got,
            v.out_u32() == 1,
            "{}: is_broadcast({addr}) disagrees",
            v.desc
        );
        checked += 1;
    }
    assert!(checked >= 10, "only checked {checked}");
}

#[test]
fn crc32_matches_the_c() {
    let vectors = load();
    let mut checked = 0;
    for v in vectors.iter().filter(|v| v.kind == "crc32") {
        let data = if let Some(s) = v.get("str") {
            s.trim_matches('"').as_bytes().to_vec()
        } else if let Some(hex) = v.get("payload") {
            unhex(hex)
        } else {
            panic!("{}: no input", v.desc);
        };
        assert_eq!(
            crc32::checksum(&data),
            v.out_u32(),
            "{}: crc32 mismatch",
            v.desc
        );
        checked += 1;
    }
    assert!(checked >= 10, "only checked {checked} crc32 vectors");
    println!("checked {checked} crc32 vectors");
}

#[test]
fn sha1_matches_the_c() {
    let vectors = load();
    let mut checked = 0;
    for v in vectors.iter().filter(|v| v.kind == "sha1") {
        let data: Vec<u8> = if let Some(s) = v.get("str") {
            s.trim_matches('"').as_bytes().to_vec()
        } else {
            // "x*N" -- N repetitions of 'x', used to straddle the padding boundaries
            let d = v.desc.trim();
            let n: usize = d.strip_prefix("x*").expect("unknown sha1 input").parse().unwrap();
            vec![b'x'; n]
        };
        assert_eq!(
            csp_core::sha1::digest(&data).to_vec(),
            v.out,
            "{}: sha1 mismatch",
            v.desc
        );
        checked += 1;
    }
    assert!(checked >= 15, "only checked {checked} sha1 vectors");
    println!("checked {checked} sha1 vectors");
}

#[test]
fn hmac_matches_the_c() {
    let vectors = load();
    let mut full = 0;
    let mut short = 0;
    for v in &vectors {
        let key = v.get("key").map(|s| s.trim_matches('"').as_bytes().to_vec());
        let data = v.get("data").map(|s| s.trim_matches('"').as_bytes().to_vec());
        let (Some(key), Some(data)) = (key, data) else { continue };
        match v.kind.as_str() {
            "hmac_full" => {
                assert_eq!(
                    csp_core::hmac::mac_full(&key, &data).unwrap().to_vec(),
                    v.out,
                    "{}: full hmac mismatch",
                    v.desc
                );
                full += 1;
            }
            "hmac" => {
                assert_eq!(
                    csp_core::hmac::mac(&key, &data).unwrap().to_vec(),
                    v.out,
                    "{}: truncated hmac mismatch",
                    v.desc
                );
                short += 1;
            }
            "hmac_err" => {
                // The C refuses an empty key; so must we, rather than returning a MAC
                // over an uninitialised buffer.
                assert!(
                    csp_core::hmac::mac(&key, &data).is_err(),
                    "{}: C refused this but we accepted it",
                    v.desc
                );
            }
            _ => continue,
        }
    }
    assert!(full >= 4 && short >= 4, "only checked {full}/{short} hmac vectors");
    println!("checked {full} full + {short} truncated hmac vectors");
}

/// End-to-end: the KISS vectors exercise header encoding, the CRC-32C append and the
/// framing together, so they are the strongest single check in the set.
#[test]
fn kiss_framing_matches_the_c() {
    use csp_core::{crc32, kiss};

    let vectors = load();
    let mut checked = 0;
    for v in vectors.iter().filter(|v| v.kind.starts_with("kiss_v")) {
        let version = version_of(v);
        // gen_vectors.c uses a fixed id for the KISS cases.
        let id = Id { pri: 2, flags: 0, src: 1, dst: 8, dport: 20, sport: 10 };
        let payload: Vec<u8> = match v.get("payload").unwrap() {
            "empty" => vec![],
            "abc" => vec![0x41, 0x42, 0x43],
            "escapes" => vec![0xc0, 0xdb, 0xc0, 0xdb],
            other => panic!("unknown payload {other}"),
        };

        // CSP_ENABLE_KISS_CRC appends a CRC before the header is prepended, and the
        // coverage is payload-only because CSP_21 is never defined.
        let mut with_crc = [0u8; 64];
        let crc_len =
            crc32::append(&[], &payload, crc32::Coverage::PayloadOnly, &mut with_crc).unwrap();

        let mut body = [0u8; 96];
        let hdr = id.encode(version, &mut body).unwrap();
        body[hdr..hdr + crc_len].copy_from_slice(&with_crc[..crc_len]);

        let mut framed = [0u8; 256];
        let n = kiss::encode(&body[..hdr + crc_len], &mut framed).unwrap();

        assert_eq!(
            &framed[..n],
            &v.out[..],
            "{}: kiss frame mismatch\n  rust: {:02x?}\n  c:    {:02x?}",
            v.desc,
            &framed[..n],
            &v.out
        );
        checked += 1;
    }
    assert!(checked >= 6, "only checked {checked} kiss vectors");
    println!("checked {checked} kiss vectors");
}
