/*
Cubesat Space Protocol - A small network-layer protocol designed for Cubesats
Copyright (C) 2012 GomSpace ApS (http://www.gomspace.com)
Copyright (C) 2012 AAUSAT3 Project (http://aausat3.space.aau.dk)

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.
*/

//! Error types mirroring the `CSP_ERR_*` constants from `csp_error.h`.

use core::fmt;

/// All error codes returned by libcsp functions.
///
/// Integer values are taken verbatim from `include/csp/csp_error.h`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CspError {
    /// Not enough memory (`CSP_ERR_NOMEM = -1`).
    NoMemory,
    /// Invalid argument (`CSP_ERR_INVAL = -2`).
    InvalidArgument,
    /// Operation timed out (`CSP_ERR_TIMEDOUT = -3`).
    TimedOut,
    /// Resource already in use (`CSP_ERR_USED = -4`).
    ResourceInUse,
    /// Operation not supported (`CSP_ERR_NOTSUP = -5`).
    NotSupported,
    /// Device or resource busy (`CSP_ERR_BUSY = -6`).
    Busy,
    /// Connection already in progress (`CSP_ERR_ALREADY = -7`).
    AlreadyInProgress,
    /// Connection reset (`CSP_ERR_RESET = -8`).
    ConnectionReset,
    /// No more buffer space available (`CSP_ERR_NOBUFS = -9`).
    NoBuffers,
    /// Transmission failed (`CSP_ERR_TX = -10`).
    TransmitFailed,
    /// Error in driver layer (`CSP_ERR_DRIVER = -11`).
    DriverError,
    /// Resource temporarily unavailable (`CSP_ERR_AGAIN = -12`).
    Again,
    /// HMAC verification failed (`CSP_ERR_HMAC = -100`).
    HmacFailed,
    /// XTEA decryption failed (`CSP_ERR_XTEA = -101`).
    XteaFailed,
    /// CRC32 check failed (`CSP_ERR_CRC32 = -102`).
    Crc32Failed,
    /// SFP protocol error or inconsistency (`CSP_ERR_SFP = -103`).
    SfpError,
    /// A CspNode has already been initialized in this process.
    AlreadyInitialized,
    /// An error code not covered by the variants above.
    Other(i32),
}

impl CspError {
    /// Convert a raw libcsp integer error code to a [`CspError`].
    ///
    /// `CSP_ERR_NONE` (0) is **not** mapped here; use [`csp_result`] for
    /// functions that return 0 on success.
    pub fn from_code(code: i32) -> Self {
        match code {
            -1   => CspError::NoMemory,
            -2   => CspError::InvalidArgument,
            -3   => CspError::TimedOut,
            -4   => CspError::ResourceInUse,
            -5   => CspError::NotSupported,
            -6   => CspError::Busy,
            -7   => CspError::AlreadyInProgress,
            -8   => CspError::ConnectionReset,
            -9   => CspError::NoBuffers,
            -10  => CspError::TransmitFailed,
            -11  => CspError::DriverError,
            -12  => CspError::Again,
            -100 => CspError::HmacFailed,
            -101 => CspError::XteaFailed,
            -102 => CspError::Crc32Failed,
            -103 => CspError::SfpError,
            other => CspError::Other(other),
        }
    }
}

impl From<i32> for CspError {
    fn from(code: i32) -> Self {
        Self::from_code(code)
    }
}

impl fmt::Display for CspError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CspError::NoMemory          => write!(f, "not enough memory"),
            CspError::InvalidArgument   => write!(f, "invalid argument"),
            CspError::TimedOut          => write!(f, "operation timed out"),
            CspError::ResourceInUse     => write!(f, "resource already in use"),
            CspError::NotSupported      => write!(f, "operation not supported"),
            CspError::Busy              => write!(f, "device or resource busy"),
            CspError::AlreadyInProgress => write!(f, "connection already in progress"),
            CspError::ConnectionReset   => write!(f, "connection reset"),
            CspError::NoBuffers         => write!(f, "no buffer space available"),
            CspError::TransmitFailed    => write!(f, "transmission failed"),
            CspError::DriverError       => write!(f, "driver layer error"),
            CspError::Again             => write!(f, "resource temporarily unavailable"),
            CspError::HmacFailed        => write!(f, "HMAC verification failed"),
            CspError::XteaFailed        => write!(f, "XTEA decryption failed"),
            CspError::Crc32Failed       => write!(f, "CRC32 check failed"),
            CspError::SfpError          => write!(f, "SFP protocol error"),
            CspError::AlreadyInitialized => write!(f, "CSP is already initialized"),
            CspError::Other(code)       => write!(f, "libcsp error code {code}"),
        }
    }
}

// std::error::Error requires std (not available in core).
#[cfg(feature = "std")]
impl std::error::Error for CspError {}

/// Convert a libcsp integer return code to a `Result<()>`.
///
/// Returns `Ok(())` if `code == 0` (`CSP_ERR_NONE`), otherwise wraps the
/// code in a [`CspError`].
#[inline]
pub fn csp_result(code: i32) -> crate::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(CspError::from_code(code))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_mapping() {
        assert_eq!(CspError::from_code(-1), CspError::NoMemory);
        assert_eq!(CspError::from_code(-2), CspError::InvalidArgument);
        assert_eq!(CspError::from_code(-3), CspError::TimedOut);
        assert_eq!(CspError::from_code(-100), CspError::HmacFailed);
        assert_eq!(CspError::from_code(-103), CspError::SfpError);
        assert_eq!(CspError::from_code(-999), CspError::Other(-999));
    }

    #[test]
    fn test_csp_result() {
        assert!(csp_result(0).is_ok());
        assert_eq!(csp_result(-1).unwrap_err(), CspError::NoMemory);
    }
}
