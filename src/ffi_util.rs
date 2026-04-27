//! Tiny helpers shared by every `extern "C"` shim in the crate.
//!
//! The single responsibility is: **never let a Rust panic unwind across the
//! libcsp C frame**. Doing so is undefined behaviour in the standard
//! `extern "C"` ABI.
//!
//! On `std` builds we wrap the closure with [`std::panic::catch_unwind`] and
//! swallow the panic (after best-effort logging via `eprintln!`). On `no_std`
//! builds the user is expected to compile with `panic = "abort"`, so a panic
//! never returns and the closure is just invoked directly.

/// Run `f` in a context where a panic cannot propagate into the caller.
///
/// `name` is a short label included in the diagnostic if a panic is caught;
/// it is otherwise unused.
///
/// Internally wraps the closure with `AssertUnwindSafe` — FFI trampolines
/// rarely have anything sensible to recover, and propagating an unwind into
/// the C frame would be UB. Treat this as a fail-stop guard.
#[inline]
pub(crate) fn guard<F: FnOnce()>(name: &str, f: F) {
    #[cfg(feature = "std")]
    {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        if result.is_err() {
            eprintln!("libcsp: panic in {name} ffi callback (suppressed)");
        }
    }
    #[cfg(not(feature = "std"))]
    {
        let _ = name;
        f();
    }
}
