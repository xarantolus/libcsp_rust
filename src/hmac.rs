//! The HMAC key libcsp uses for packets sent or received with HMAC
//! (`CSP_O_HMAC` / `CSP_SO_HMACREQ`).

use crate::error::csp_result;
use crate::sys;

/// Bytes of the HMAC trailer libcsp appends.
pub const LENGTH: usize = sys::CSP_HMAC_LENGTH as usize;

/// Sets the process-wide HMAC key (`csp_hmac_set_key`). libcsp derives the
/// key it uses from `key` with SHA-1, so any length works.
pub fn set_key(key: &[u8]) -> crate::Result<()> {
    let len = u32::try_from(key.len()).map_err(|_| crate::CspError::InvalidArgument)?;
    csp_result(unsafe { sys::csp_hmac_set_key(key.as_ptr().cast(), len) })
}

/// The HMAC-SHA1 of `data` with `key`, truncated to libcsp's trailer (`CSP_HMAC_LENGTH` bytes)
/// as `csp_hmac_append` writes it (`csp_hmac_memory`).
pub fn memory(key: &[u8], data: &[u8]) -> crate::Result<[u8; LENGTH]> {
    let klen = u32::try_from(key.len()).map_err(|_| crate::CspError::InvalidArgument)?;
    let dlen = u32::try_from(data.len()).map_err(|_| crate::CspError::InvalidArgument)?;
    let mut out = [0u8; sys::CSP_SHA1_DIGESTSIZE as usize];
    csp_result(unsafe {
        sys::csp_hmac_memory(
            key.as_ptr().cast(),
            klen,
            data.as_ptr().cast(),
            dlen,
            out.as_mut_ptr(),
        )
    })?;
    let mut trailer = [0u8; LENGTH];
    trailer.copy_from_slice(&out[..LENGTH]);
    Ok(trailer)
}

#[cfg(test)]
mod tests {
    #[test]
    fn hmac_sha1_matches_rfc_2202() {
        // RFC 2202 test case 2: key "Jefe", "what do ya want for nothing?".
        let t = super::memory(b"Jefe", b"what do ya want for nothing?").unwrap();
        assert_eq!(t, [0xef, 0xfc, 0xdf, 0x6a]);
        super::set_key(b"any length of key material").unwrap();
    }
}
