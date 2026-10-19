//! Before `init` there is no buffer pool and no wire version: packet
//! allocation and frame conversion fail cleanly instead of touching
//! uninitialised state. Own process, never initialises the stack.

use libcsp::{CspError, Packet};

#[test]
fn nothing_works_before_init_except_plain_crc() {
    assert!(Packet::get(0).is_none());
    assert!(matches!(
        Packet::from_frame(&[0u8; 8]),
        Err(CspError::NoBuffers)
    ));
    assert_eq!(libcsp::crc32::memory(b"123456789"), 0xE306_9283);
}
