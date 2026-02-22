//! Comprehensive tests for C string function implementations.
//!
//! These tests ensure our strnlen and strtok_r implementations are correct
//! and handle edge cases properly.

#[cfg(test)]
mod tests {
    use super::super::CspArch;
    use core::ffi::c_char;
    use core::ptr;

    // Test helper struct
    struct TestArch;
    unsafe impl CspArch for TestArch {
        fn get_ms(&self) -> u32 { 0 }
        fn get_s(&self) -> u32 { 0 }
        fn bin_sem_create(&self) -> *mut core::ffi::c_void { ptr::null_mut() }
        fn bin_sem_remove(&self, _: *mut core::ffi::c_void) {}
        fn bin_sem_wait(&self, _: *mut core::ffi::c_void, _: u32) -> bool { true }
        fn bin_sem_post(&self, _: *mut core::ffi::c_void) -> bool { true }
        fn mutex_create(&self) -> *mut core::ffi::c_void { ptr::null_mut() }
        fn mutex_remove(&self, _: *mut core::ffi::c_void) {}
        fn mutex_lock(&self, _: *mut core::ffi::c_void, _: u32) -> bool { true }
        fn mutex_unlock(&self, _: *mut core::ffi::c_void) -> bool { true }
        fn queue_create(&self, _: usize, _: usize) -> *mut core::ffi::c_void { ptr::null_mut() }
        fn queue_remove(&self, _: *mut core::ffi::c_void) {}
        fn queue_enqueue(&self, _: *mut core::ffi::c_void, _: *const core::ffi::c_void, _: u32) -> bool { true }
        fn queue_dequeue(&self, _: *mut core::ffi::c_void, _: *mut core::ffi::c_void, _: u32) -> bool { true }
        fn queue_size(&self, _: *mut core::ffi::c_void) -> usize { 0 }
        fn malloc(&self, _: usize) -> *mut core::ffi::c_void { ptr::null_mut() }
        fn free(&self, _: *mut core::ffi::c_void) {}
    }

    const ARCH: TestArch = TestArch;

    // ── strnlen tests ─────────────────────────────────────────────────────────

    #[test]
    fn test_strnlen_basic() {
        let s = b"hello\0";
        let len = unsafe { ARCH.strnlen(s.as_ptr() as *const c_char, 10) };
        assert_eq!(len, 5);
    }

    #[test]
    fn test_strnlen_exact_length() {
        let s = b"hello\0";
        let len = unsafe { ARCH.strnlen(s.as_ptr() as *const c_char, 5) };
        assert_eq!(len, 5);
    }

    #[test]
    fn test_strnlen_truncated() {
        let s = b"hello\0";
        let len = unsafe { ARCH.strnlen(s.as_ptr() as *const c_char, 3) };
        assert_eq!(len, 3);
    }

    #[test]
    fn test_strnlen_empty() {
        let s = b"\0";
        let len = unsafe { ARCH.strnlen(s.as_ptr() as *const c_char, 10) };
        assert_eq!(len, 0);
    }

    #[test]
    fn test_strnlen_no_null() {
        // String without null terminator within maxlen
        let s = b"hello";
        let len = unsafe { ARCH.strnlen(s.as_ptr() as *const c_char, 3) };
        assert_eq!(len, 3);
    }

    // ── strtok_r tests ────────────────────────────────────────────────────────

    #[test]
    fn test_strtok_r_basic() {
        let mut s = *b"hello,world\0";
        let delim = b",\0";
        let mut saveptr: *mut c_char = ptr::null_mut();

        // First token
        let token1 = unsafe {
            ARCH.strtok_r(
                s.as_mut_ptr() as *mut c_char,
                delim.as_ptr() as *const c_char,
                &mut saveptr,
            )
        };
        assert!(!token1.is_null());
        let token1_str = unsafe { core::ffi::CStr::from_ptr(token1) };
        assert_eq!(token1_str.to_bytes(), b"hello");

        // Second token
        let token2 = unsafe {
            ARCH.strtok_r(
                ptr::null_mut(),
                delim.as_ptr() as *const c_char,
                &mut saveptr,
            )
        };
        assert!(!token2.is_null());
        let token2_str = unsafe { core::ffi::CStr::from_ptr(token2) };
        assert_eq!(token2_str.to_bytes(), b"world");

        // No more tokens
        let token3 = unsafe {
            ARCH.strtok_r(
                ptr::null_mut(),
                delim.as_ptr() as *const c_char,
                &mut saveptr,
            )
        };
        assert!(token3.is_null());
    }

    #[test]
    fn test_strtok_r_multiple_delimiters() {
        let mut s = *b"one::two::three\0";
        let delim = b":\0";
        let mut saveptr: *mut c_char = ptr::null_mut();

        let token1 = unsafe {
            ARCH.strtok_r(
                s.as_mut_ptr() as *mut c_char,
                delim.as_ptr() as *const c_char,
                &mut saveptr,
            )
        };
        assert_eq!(
            unsafe { core::ffi::CStr::from_ptr(token1) }.to_bytes(),
            b"one"
        );

        let token2 = unsafe {
            ARCH.strtok_r(ptr::null_mut(), delim.as_ptr() as *const c_char, &mut saveptr)
        };
        assert_eq!(
            unsafe { core::ffi::CStr::from_ptr(token2) }.to_bytes(),
            b"two"
        );

        let token3 = unsafe {
            ARCH.strtok_r(ptr::null_mut(), delim.as_ptr() as *const c_char, &mut saveptr)
        };
        assert_eq!(
            unsafe { core::ffi::CStr::from_ptr(token3) }.to_bytes(),
            b"three"
        );
    }

    #[test]
    fn test_strtok_r_leading_delimiters() {
        let mut s = *b",,hello,world\0";
        let delim = b",\0";
        let mut saveptr: *mut c_char = ptr::null_mut();

        let token1 = unsafe {
            ARCH.strtok_r(
                s.as_mut_ptr() as *mut c_char,
                delim.as_ptr() as *const c_char,
                &mut saveptr,
            )
        };
        assert_eq!(
            unsafe { core::ffi::CStr::from_ptr(token1) }.to_bytes(),
            b"hello"
        );
    }

    #[test]
    fn test_strtok_r_trailing_delimiters() {
        let mut s = *b"hello,world,,\0";
        let delim = b",\0";
        let mut saveptr: *mut c_char = ptr::null_mut();

        let token1 = unsafe {
            ARCH.strtok_r(
                s.as_mut_ptr() as *mut c_char,
                delim.as_ptr() as *const c_char,
                &mut saveptr,
            )
        };
        assert_eq!(
            unsafe { core::ffi::CStr::from_ptr(token1) }.to_bytes(),
            b"hello"
        );

        let token2 = unsafe {
            ARCH.strtok_r(ptr::null_mut(), delim.as_ptr() as *const c_char, &mut saveptr)
        };
        assert_eq!(
            unsafe { core::ffi::CStr::from_ptr(token2) }.to_bytes(),
            b"world"
        );

        let token3 = unsafe {
            ARCH.strtok_r(ptr::null_mut(), delim.as_ptr() as *const c_char, &mut saveptr)
        };
        assert!(token3.is_null());
    }

    #[test]
    fn test_strtok_r_empty_string() {
        let mut s = *b"\0";
        let delim = b",\0";
        let mut saveptr: *mut c_char = ptr::null_mut();

        let token = unsafe {
            ARCH.strtok_r(
                s.as_mut_ptr() as *mut c_char,
                delim.as_ptr() as *const c_char,
                &mut saveptr,
            )
        };
        assert!(token.is_null());
    }

    #[test]
    fn test_strtok_r_only_delimiters() {
        let mut s = *b",,,\0";
        let delim = b",\0";
        let mut saveptr: *mut c_char = ptr::null_mut();

        let token = unsafe {
            ARCH.strtok_r(
                s.as_mut_ptr() as *mut c_char,
                delim.as_ptr() as *const c_char,
                &mut saveptr,
            )
        };
        assert!(token.is_null());
    }

    #[test]
    fn test_strtok_r_libcsp_routing_format() {
        // Test the actual format used by libcsp: "1/5 CAN,2 ETH"
        let mut s = *b"1/5 CAN,2 ETH\0";
        let delim = b",\0";
        let mut saveptr: *mut c_char = ptr::null_mut();

        let token1 = unsafe {
            ARCH.strtok_r(
                s.as_mut_ptr() as *mut c_char,
                delim.as_ptr() as *const c_char,
                &mut saveptr,
            )
        };
        assert_eq!(
            unsafe { core::ffi::CStr::from_ptr(token1) }.to_bytes(),
            b"1/5 CAN"
        );

        let token2 = unsafe {
            ARCH.strtok_r(ptr::null_mut(), delim.as_ptr() as *const c_char, &mut saveptr)
        };
        assert_eq!(
            unsafe { core::ffi::CStr::from_ptr(token2) }.to_bytes(),
            b"2 ETH"
        );
    }

    #[test]
    fn test_strtok_r_mixed_delimiters() {
        let mut s = *b"a b,c\td\0";
        let delim = b" ,\t\0";
        let mut saveptr: *mut c_char = ptr::null_mut();

        let tokens: Vec<&[u8]> = (0..4)
            .filter_map(|i| unsafe {
                let tok = if i == 0 {
                    ARCH.strtok_r(
                        s.as_mut_ptr() as *mut c_char,
                        delim.as_ptr() as *const c_char,
                        &mut saveptr,
                    )
                } else {
                    ARCH.strtok_r(
                        ptr::null_mut(),
                        delim.as_ptr() as *const c_char,
                        &mut saveptr,
                    )
                };
                if tok.is_null() {
                    None
                } else {
                    Some(core::ffi::CStr::from_ptr(tok).to_bytes())
                }
            })
            .collect();

        assert_eq!(tokens, vec![b"a", b"b", b"c", b"d"]);
    }
}
