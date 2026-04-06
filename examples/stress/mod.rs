//! Common logic for CSP stress tests.
#![allow(dead_code)]

pub const PRNG_SEED: u32 = 0x12345678;
pub const DATA_PORT: u8 = 10;
pub const SFP_PORT: u8 = 11;
pub const SYNC_INTERVAL: u32 = 1000;

/// Simple Xorshift32 PRNG for deterministic test data.
pub struct Prng {
    state: u32,
}

impl Prng {
    pub fn new(seed: u32) -> Self {
        Self {
            state: if seed == 0 { 1 } else { seed },
        }
    }

    pub fn next(&mut self) -> u32 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.state = x;
        x
    }

    pub fn next_with_seed(seed: u32) -> u32 {
        let mut x = if seed == 0 { 1 } else { seed };
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x
    }

    pub fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_exact_mut(4) {
            let val = self.next();
            chunk.copy_from_slice(&val.to_le_bytes());
        }
        let remaining = buf.len() % 4;
        if remaining > 0 {
            let val = self.next().to_le_bytes();
            let start = buf.len() - remaining;
            buf[start..].copy_from_slice(&val[..remaining]);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub enum ProtocolMode {
    Normal,
    Rdp,
    SFP,
    RdpSfp,
}

impl ProtocolMode {
    pub fn from_count(count: u64) -> Self {
        // Change mode every 5000 iterations
        match (count / 5000) % 4 {
            0 => ProtocolMode::Normal,
            1 => ProtocolMode::Rdp,
            2 => ProtocolMode::SFP,
            _ => ProtocolMode::RdpSfp,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ProtocolMode::Normal => "NORMAL (UDP-like)",
            ProtocolMode::Rdp => "RDP (Reliable)",
            ProtocolMode::SFP => "SFP (Fragmentation)",
            ProtocolMode::RdpSfp => "RDP + SFP",
        }
    }
}
