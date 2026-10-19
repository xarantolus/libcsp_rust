//! CRC-32C (Castagnoli) as computed by libcsp (`csp_crc32_memory`), e.g. for
//! link-layer trailers such as a KISS frame CRC.

use crate::sys;

/// CRC-32C of `data`. Needs no initialised stack.
pub fn memory(data: &[u8]) -> u32 {
    let len = u32::try_from(data.len()).expect("CRC input larger than 4 GiB");
    unsafe { sys::csp_crc32_memory(data.as_ptr().cast(), len) }
}

#[cfg(test)]
mod tests {
    #[test]
    fn matches_the_crc32c_check_value() {
        // Standard CRC-32C check value for "123456789".
        assert_eq!(super::memory(b"123456789"), 0xE306_9283);
    }
}
