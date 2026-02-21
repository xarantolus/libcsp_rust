# Simple `export_arch` Documentation Enhancement

## Current Situation

The `CspArch` trait in `src/arch.rs` already has **excellent documentation** with:
- ✅ Clear indication of required vs optional methods
- ✅ Detailed doc comments for each method
- ✅ Examples in doc comments
- ✅ Stub example in `examples/custom_arch.rs`

**The problem**: Users might not know to look there!

## Simple Solution: Better Signposting

### 1. Update USAGE.md Section 8

Replace the current minimal example with a clear pointer to the comprehensive docs:

```markdown
## 8. Custom Arch and Time (RTOS/Bare-Metal)

For `no_std` or embedded environments, you need to provide OS primitives (mutexes, queues, time, etc.) to libcsp.

### Quick Start

Enable the `external-arch` feature and implement the [`CspArch`] trait:

```rust
use libcsp::{CspArch, export_arch};
use core::ffi::c_void;

struct MyRTOS;

impl CspArch for MyRTOS {
    fn get_ms(&self) -> u32 { /* your implementation */ 0 }
    fn get_s(&self) -> u32 { /* your implementation */ 0 }
    
    fn bin_sem_create(&self) -> *mut c_void { /* ... */ core::ptr::null_mut() }
    fn bin_sem_wait(&self, sem: *mut c_void, timeout: u32) -> bool { /* ... */ true }
    // ... see CspArch trait docs for all required methods
    
    fn malloc(&self, size: usize) -> *mut c_void { /* ... */ core::ptr::null_mut() }
    fn free(&self, ptr: *mut c_void) { /* ... */ }
}

static ARCH: MyRTOS = MyRTOS;
export_arch!(MyRTOS, ARCH);
```

### Complete Documentation

**See the [`CspArch`] trait documentation** for:
- Complete list of required methods
- Optional methods with defaults
- Detailed explanation of each method's semantics
- ISR-safe variant documentation
- System service functions

**See [`export_arch!`] macro documentation** for:
- How the macro generates C symbols
- FFI bridge implementation details

**See `examples/custom_arch.rs`** for:
- Complete stub implementation
- Commented template you can copy

[`CspArch`]: https://docs.rs/libcsp/latest/libcsp/arch/trait.CspArch.html
[`export_arch!`]: https://docs.rs/libcsp/latest/libcsp/macro.export_arch.html

### Platform-Specific Notes

**Embassy (async Rust)**:
- Use `embassy_time::block_on()` for blocking operations
- See `embassy-example/` directory for working implementation

**FreeRTOS**:
- Map to FreeRTOS semaphores/queues directly
- Use `xTaskGetTickCount()` for `get_ms()`

**RTIC**:
- Use `rtic_monotonic` for time
- Shared resources for mutexes
```

### 2. Add to README.md

Add a clear section in README under "Feature flags":

```markdown
## Custom Architecture (Bare-Metal / RTOS)

For embedded targets, enable `external-arch` and implement [`CspArch`]:

```toml
[dependencies]
libcsp = { version = "1.6", default-features = false, features = ["external-arch"] }
```

Then provide OS primitives:

```rust
use libcsp::{CspArch, export_arch};

struct MyRTOS;
impl CspArch for MyRTOS {
    // Implement required methods - see trait documentation
}

export_arch!(MyRTOS, MyRTOS);
```

**See [`CspArch` trait documentation](https://docs.rs/libcsp/latest/libcsp/arch/trait.CspArch.html) for complete API reference.**

Working examples:
- [`examples/custom_arch.rs`](examples/custom_arch.rs) - Stub template
- [`embassy-example/`](embassy-example/) - Full Embassy implementation
```

### 3. Improve `src/arch.rs` Module-Level Documentation

Add an example section at the top of `src/arch.rs`:

```rust
//! Traits and helpers for providing custom architecture implementations.
//!
//! ## Overview
//!
//! When building for bare-metal or RTOS targets, enable the `external-arch` feature
//! and implement the [`CspArch`] trait to provide OS primitives (mutexes, queues, time, etc.).
//!
//! ## Example
//!
//! ```no_run
//! use libcsp::{CspArch, export_arch};
//! use core::ffi::c_void;
//!
//! struct MyRTOS;
//!
//! impl CspArch for MyRTOS {
//!     fn get_ms(&self) -> u32 {
//!         // Return monotonic millisecond count
//!         embassy_time::Instant::now().as_millis() as u32
//!     }
//!     
//!     fn get_s(&self) -> u32 {
//!         self.get_ms() / 1000
//!     }
//!     
//!     fn bin_sem_create(&self) -> *mut c_void {
//!         // Create a binary semaphore using your RTOS
//!         let sem = Box::new(MySemaphore::new());
//!         Box::into_raw(sem) as *mut c_void
//!     }
//!     
//!     // ... implement all required methods (see trait docs below)
//!     # fn bin_sem_remove(&self, _sem: *mut c_void) {}
//!     # fn bin_sem_wait(&self, _sem: *mut c_void, _timeout: u32) -> bool { true }
//!     # fn bin_sem_post(&self, _sem: *mut c_void) -> bool { true }
//!     # fn mutex_create(&self) -> *mut c_void { core::ptr::null_mut() }
//!     # fn mutex_remove(&self, _mutex: *mut c_void) {}
//!     # fn mutex_lock(&self, _mutex: *mut c_void, _timeout: u32) -> bool { true }
//!     # fn mutex_unlock(&self, _mutex: *mut c_void) -> bool { true }
//!     # fn queue_create(&self, _len: usize, _size: usize) -> *mut c_void { core::ptr::null_mut() }
//!     # fn queue_remove(&self, _queue: *mut c_void) {}
//!     # fn queue_enqueue(&self, _queue: *mut c_void, _item: *const c_void, _timeout: u32) -> bool { true }
//!     # fn queue_dequeue(&self, _queue: *mut c_void, _item: *mut c_void, _timeout: u32) -> bool { true }
//!     # fn queue_size(&self, _queue: *mut c_void) -> usize { 0 }
//!     # fn malloc(&self, _size: usize) -> *mut c_void { core::ptr::null_mut() }
//!     # fn free(&self, _ptr: *mut c_void) {}
//! }
//!
//! // Export C symbols for libcsp to call
//! static ARCH: MyRTOS = MyRTOS;
//! export_arch!(MyRTOS, ARCH);
//! ```
//!
//! ## Required Methods
//!
//! You **must** implement:
//! - **Time**: [`get_ms`](CspArch::get_ms), [`get_s`](CspArch::get_s)
//! - **Mutexes**: create, remove, lock, unlock
//! - **Semaphores**: create, remove, wait, post
//! - **Queues**: create, remove, enqueue, dequeue, size
//! - **Memory**: [`malloc`](CspArch::malloc), [`free`](CspArch::free)
//!
//! ## Optional Methods
//!
//! These have sensible defaults or are only needed for specific features:
//! - ISR variants (default to non-ISR versions)
//! - Thread creation (only if using `route_start_task()`)
//! - System services (used by CMP services, default to no-ops)
//!
//! See the [`CspArch`] trait documentation below for complete details.
```

## Result

This approach:
- ✅ Keeps comprehensive documentation in **one place** (the trait itself)
- ✅ Provides clear signposting in user-facing docs
- ✅ Reduces duplication
- ✅ Makes it easy to find the detailed docs
- ✅ Adds visibility to the already-good documentation

Much better than creating parallel documentation that gets out of sync!
