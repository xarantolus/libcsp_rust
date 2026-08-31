//! I2C interface: choosing the physical bus address, and the receive-length guard.
//!
//! Almost all of `csp_if_i2c.c` is what every interface does — loopback when the destination
//! is our own address, `csp_id_prepend` on the way out, `csp_id_strip` on the way in — and
//! `Interface` (in the `csp` crate) already does those. Two things are specific to I2C, and
//! neither existed here until they were compared against the C:
//!
//! - **The physical address is seven bits.** `csp_if_i2c.c:22` masks it: a CSP address of 200
//!   is addressed on the bus as `200 & 0x7F` = 72. Two CSP nodes 128 apart therefore share a
//!   bus address, and nothing anywhere reports it.
//! - **A frame shorter than four bytes is refused** before `csp_id_strip` runs, and counted
//!   as a framing error.
//!
//! Both are pure functions of the header, which is why they live here rather than in a
//! driver.

/// The C's `CSP_NO_VIA_ADDRESS` (`csp_rtable.h:18`).
pub const NO_VIA: u16 = 0xFFFF;

/// I2C addresses are seven bits.
pub const ADDR_MASK: u16 = 0x7F;

/// The shortest frame `csp_i2c_rx` will accept, in bytes.
///
/// `sizeof(uint32_t)`, which is **not** the CSP header size — a v2 header is six. A
/// five-byte frame therefore passes this guard and is handed to `csp_id_strip`. The guard is
/// reproduced as the C wrote it rather than as it presumably meant it: refusing more here
/// would drop frames a real libcsp peer accepts, and this module's job is to agree with the
/// bus, not to improve it. `Id::decode` refuses the short header afterwards, which is where
/// the port declines to read past the buffer.
pub const MIN_FRAME_LEN: usize = 4;

/// The bus address a frame is sent to.
///
/// `csp_i2c_tx` uses the route's next hop when there is one and the CSP destination
/// otherwise, then keeps the low seven bits:
///
/// ```text
/// packet->cfpid = (via != CSP_NO_VIA_ADDRESS) ? via : packet->id.dst;
/// packet->cfpid = packet->cfpid & 0x7F;
/// ```
///
/// The truncation is silent in the C and silent here, because a peer on the bus does the
/// same arithmetic and disagreeing would put frames somewhere libcsp would not.
pub const fn physical_addr(via: u16, dst: u16) -> u8 {
    let addr = if via != NO_VIA { via } else { dst };
    (addr & ADDR_MASK) as u8
}

/// Whether `csp_i2c_rx` would accept a frame of this length.
///
/// `false` means the C counts a framing error and frees the buffer without routing it.
pub const fn accepts(frame_len: usize) -> bool {
    frame_len >= MIN_FRAME_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_next_hop_wins_over_the_destination() {
        assert_eq!(physical_addr(5, 9), 5);
        assert_eq!(physical_addr(NO_VIA, 9), 9);
    }

    #[test]
    fn an_address_above_the_seven_bit_space_wraps_into_it() {
        // The case that matters operationally: two nodes 128 apart collide on the bus.
        assert_eq!(physical_addr(NO_VIA, 200), 72);
        assert_eq!(physical_addr(NO_VIA, 72), 72);
        assert_eq!(physical_addr(NO_VIA, 128), 0);
        assert_eq!(physical_addr(NO_VIA, 0x3FFF), 0x7F);
    }

    #[test]
    fn the_length_guard_is_four_bytes_not_a_header() {
        assert!(!accepts(3));
        assert!(accepts(4));
        // Five is shorter than a v2 header and the C still accepts it here.
        assert!(accepts(5));
    }
}
