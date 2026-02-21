# Comprehensive `export_arch` Documentation Enhancement Guide

## Current State

The existing documentation is good but minimal:
- ✅ Trait is well-documented in `src/arch.rs`
- ✅ Basic stub example in `examples/custom_arch.rs`
- ✅ Brief mention in USAGE.md §8
- ❌ Missing: Complete real-world implementations
- ❌ Missing: Platform-specific patterns
- ❌ Missing: Testing and debugging guidance
- ❌ Missing: Performance considerations

## Recommended Additions

### 1. Platform-Specific Implementation Guides

#### Add to `docs/arch/` directory:

**`docs/arch/EMBASSY.md`** - Complete Embassy implementation
**`docs/arch/FREERTOS.md`** - Complete FreeRTOS implementation
**`docs/arch/RTIC.md`** - Complete RTIC implementation
**`docs/arch/ZEPHYR.md`** - Zephyr RTOS implementation

### 2. Real Implementation Example for Embassy

```rust
//! Complete Embassy implementation for STM32
//! File: examples/embassy_arch.rs

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use embassy_sync::channel::Channel;
use embassy_time::{Instant, Duration, Timer};
use core::ffi::{c_void, c_char};
use libcsp::arch::CspArch;

struct EmbassyArch;

impl CspArch for EmbassyArch {
    // ── Time (Real Implementation) ─────────────────────────────────
    
    fn get_ms(&self) -> u32 {
        Instant::now().as_millis() as u32
    }
    
    fn get_s(&self) -> u32 {
        Instant::now().as_secs() as u32
    }
    
    fn sleep_ms(&self, ms: u32) {
        // Use async context or blocking wait
        // In real Embassy code, you'd use Timer::after()
        embassy_time::block_for(Duration::from_millis(ms as u64));
    }

    // ── Binary Semaphores (Embassy Channel Implementation) ──────────
    
    fn bin_sem_create(&self) -> *mut c_void {
        // Allocate a Channel<1> on the heap
        let sem = Box::new(Channel::<CriticalSectionRawMutex, (), 1>::new());
        Box::into_raw(sem) as *mut c_void
    }
    
    fn bin_sem_remove(&self, sem: *mut c_void) {
        if !sem.is_null() {
            unsafe {
                let _ = Box::from_raw(sem as *mut Channel<CriticalSectionRawMutex, (), 1>);
            }
        }
    }
    
    fn bin_sem_wait(&self, sem: *mut c_void, timeout_ms: u32) -> bool {
        if sem.is_null() {
            return false;
        }
        
        unsafe {
            let channel = &*(sem as *const Channel<CriticalSectionRawMutex, (), 1>);
            
            // For blocking wait in non-async context
            if timeout_ms == 0xFFFFFFFF {
                // Wait forever
                let _ = embassy_time::block_on(channel.receive());
                true
            } else {
                // Wait with timeout
                let result = embassy_time::with_timeout(
                    Duration::from_millis(timeout_ms as u64),
                    channel.receive()
                );
                match embassy_time::block_on(result) {
                    Ok(_) => true,
                    Err(_) => false,
                }
            }
        }
    }
    
    fn bin_sem_post(&self, sem: *mut c_void) -> bool {
        if sem.is_null() {
            return false;
        }
        
        unsafe {
            let channel = &*(sem as *const Channel<CriticalSectionRawMutex, (), 1>);
            channel.try_send(()).is_ok()
        }
    }

    // ── Mutexes (Embassy Mutex Implementation) ──────────────────────
    
    fn mutex_create(&self) -> *mut c_void {
        let mutex = Box::new(Mutex::<CriticalSectionRawMutex, ()>::new(()));
        Box::into_raw(mutex) as *mut c_void
    }
    
    fn mutex_remove(&self, mutex: *mut c_void) {
        if !mutex.is_null() {
            unsafe {
                let _ = Box::from_raw(mutex as *mut Mutex<CriticalSectionRawMutex, ()>);
            }
        }
    }
    
    fn mutex_lock(&self, mutex: *mut c_void, _timeout_ms: u32) -> bool {
        if mutex.is_null() {
            return false;
        }
        
        unsafe {
            let mtx = &*(mutex as *const Mutex<CriticalSectionRawMutex, ()>);
            // Note: Embassy mutex doesn't have timeout support
            // This blocks until lock is acquired
            let _guard = embassy_time::block_on(mtx.lock());
            // PROBLEM: We can't return the guard!
            // See "Common Pitfalls" section below
        }
        
        true
    }
    
    // ... continued in full example
}

// Export to C
static EMBASSY_ARCH: EmbassyArch = EmbassyArch;
libcsp::export_arch!(EmbassyArch, EMBASSY_ARCH);
```

### 3. Common Pitfalls Section

Add to USAGE.md:

```markdown
## Common Pitfalls with Custom Arch

### 1. Mutex Guard Lifetime

**Problem**: CSP's C API separates lock/unlock calls, but Rust RAII guards don't work this way.

```rust
// ❌ WRONG - Guard is dropped immediately
fn mutex_lock(&self, mutex: *mut c_void, timeout: u32) -> bool {
    let guard = my_mutex.lock();
    true  // Guard dropped here! Mutex unlocked!
}
```

**Solutions**:

**Option A**: Use raw mutexes (unsafe, but matches C semantics)
```rust
use core::sync::atomic::{AtomicBool, Ordering};

struct RawMutex {
    locked: AtomicBool,
}

fn mutex_lock(&self, mutex: *mut c_void, timeout: u32) -> bool {
    let mtx = unsafe { &*(mutex as *const RawMutex) };
    // Spin or wait until lock is acquired
    while mtx.locked.swap(true, Ordering::Acquire) {
        // Wait or yield
    }
    true
}

fn mutex_unlock(&self, mutex: *mut c_void) -> bool {
    let mtx = unsafe { &*(mutex as *const RawMutex) };
    mtx.locked.store(false, Ordering::Release);
    true
}
```

**Option B**: Store guards in a global registry (complex but safe)
```rust
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex as StdMutex;

static GUARD_REGISTRY: Lazy<StdMutex<HashMap<usize, MutexGuard>>> = 
    Lazy::new(|| StdMutex::new(HashMap::new()));

fn mutex_lock(&self, mutex: *mut c_void, timeout: u32) -> bool {
    let guard = acquire_mutex_guard(mutex, timeout);
    GUARD_REGISTRY.lock().unwrap().insert(mutex as usize, guard);
    true
}

fn mutex_unlock(&self, mutex: *mut c_void) -> bool {
    GUARD_REGISTRY.lock().unwrap().remove(&(mutex as usize));
    true
}
```

### 2. Async/Await in Blocking Context

**Problem**: CSP calls arch functions from C, which can't handle async.

**Solution**: Use `block_on` or dedicated blocking primitives
```rust
fn bin_sem_wait(&self, sem: *mut c_void, timeout: u32) -> bool {
    // ✅ CORRECT - Block the current task
    embassy_time::block_on(async {
        channel.receive().await;
    });
    true
}
```

### 3. Memory Allocation Alignment

**Problem**: libcsp assumes allocations are properly aligned.

```rust
// ❌ WRONG - May not be aligned
fn malloc(&self, size: usize) -> *mut c_void {
    let vec = vec![0u8; size];
    Box::into_raw(vec.into_boxed_slice()) as *mut c_void
}

// ✅ CORRECT - Properly aligned
fn malloc(&self, size: usize) -> *mut c_void {
    use core::alloc::{Layout, GlobalAlloc, System};
    
    let layout = Layout::from_size_align(size, 8).unwrap();
    unsafe { System.alloc(layout) as *mut c_void }
}

fn free(&self, ptr: *mut c_void) {
    use core::alloc::{Layout, GlobalAlloc, System};
    
    if !ptr.is_null() {
        // You need to know the size! Store it somewhere.
        let layout = get_layout_for_ptr(ptr);
        unsafe { System.dealloc(ptr as *mut u8, layout) }
    }
}
```

**Better Solution**: Use a heap allocator with metadata
```rust
use linked_list_allocator::LockedHeap;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

fn malloc(&self, size: usize) -> *mut c_void {
    let layout = Layout::from_size_align(size, 8).unwrap();
    unsafe { alloc::alloc::alloc(layout) as *mut c_void }
}

fn free(&self, ptr: *mut c_void) {
    // Deallocator knows the size from metadata
    unsafe { alloc::alloc::dealloc(ptr as *mut u8, stored_layout) }
}
```

### 4. Queue Item Size Mismatch

**Problem**: CSP passes item_size but you must use it correctly.

```rust
// ❌ WRONG - Assumes usize items
fn queue_create(&self, length: usize, item_size: usize) -> *mut c_void {
    let queue: VecDeque<usize> = VecDeque::with_capacity(length);
    // WRONG: item_size might be 4 bytes (pointer), not 8!
}

// ✅ CORRECT - Use raw bytes
fn queue_create(&self, length: usize, item_size: usize) -> *mut c_void {
    let queue: VecDeque<Vec<u8>> = VecDeque::with_capacity(length);
    // Store item_size for enqueue/dequeue
}
```

### 5. Timeout Handling

**Problem**: CSP uses millisecond timeouts, but 0xFFFFFFFF means "wait forever".

```rust
fn queue_dequeue(&self, queue: *mut c_void, item: *mut c_void, timeout: u32) -> bool {
    let timeout_duration = if timeout == 0xFFFF_FFFF {
        None  // Wait forever
    } else {
        Some(Duration::from_millis(timeout as u64))
    };
    
    match timeout_duration {
        None => {
            // Block forever
            let data = channel.receive_blocking();
            copy_to_item(item, &data);
            true
        }
        Some(duration) => {
            // Wait with timeout
            match channel.try_receive_timeout(duration) {
                Ok(data) => {
                    copy_to_item(item, &data);
                    true
                }
                Err(_) => false,
            }
        }
    }
}
```
```

### 4. Testing Custom Arch Implementations

Add to USAGE.md:

```markdown
## Testing Custom Arch

### Unit Testing Individual Functions

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_semaphore_basic() {
        let arch = MyArch;
        
        let sem = arch.bin_sem_create();
        assert!(!sem.is_null(), "Semaphore creation failed");
        
        // Post then wait
        assert!(arch.bin_sem_post(sem), "Post failed");
        assert!(arch.bin_sem_wait(sem, 1000), "Wait failed");
        
        // Timeout test
        assert!(!arch.bin_sem_wait(sem, 100), "Should timeout");
        
        arch.bin_sem_remove(sem);
    }
    
    #[test]
    fn test_queue_fifo_order() {
        let arch = MyArch;
        
        let queue = arch.queue_create(10, 4); // 10 items of 4 bytes
        assert!(!queue.is_null());
        
        // Enqueue 1, 2, 3
        let data1: u32 = 1;
        let data2: u32 = 2;
        let data3: u32 = 3;
        
        assert!(arch.queue_enqueue(queue, &data1 as *const _ as *const c_void, 0));
        assert!(arch.queue_enqueue(queue, &data2 as *const _ as *const c_void, 0));
        assert!(arch.queue_enqueue(queue, &data3 as *const _ as *const c_void, 0));
        
        assert_eq!(arch.queue_size(queue), 3);
        
        // Dequeue should return 1, 2, 3
        let mut out: u32 = 0;
        assert!(arch.queue_dequeue(queue, &mut out as *mut _ as *mut c_void, 0));
        assert_eq!(out, 1);
        
        assert!(arch.queue_dequeue(queue, &mut out as *mut _ as *mut c_void, 0));
        assert_eq!(out, 2);
        
        assert!(arch.queue_dequeue(queue, &mut out as *mut _ as *mut c_void, 0));
        assert_eq!(out, 3);
        
        assert_eq!(arch.queue_size(queue), 0);
        
        arch.queue_remove(queue);
    }
}
```

### Integration Testing with CSP

```rust
#[test]
fn test_arch_with_csp_init() {
    use libcsp::CspConfig;
    
    // This tests that your arch implementation works with real CSP
    let node = CspConfig::new()
        .address(1)
        .buffers(10, 256)
        .init()
        .expect("CSP init failed with custom arch");
    
    // Try basic operations
    node.route_start_task(4096, 0).expect("Router task failed");
    
    // Verify time works
    let start = ARCH.get_ms();
    std::thread::sleep(std::time::Duration::from_millis(100));
    let elapsed = ARCH.get_ms() - start;
    assert!(elapsed >= 90 && elapsed <= 150, "Time measurement inaccurate");
}
```
```

### 5. Performance Considerations

Add section to USAGE.md:

```markdown
## Performance Considerations

### Queue Implementation Choices

| Implementation | Speed | Memory | Thread-Safe | ISR-Safe |
|----------------|-------|--------|-------------|----------|
| `std::collections::VecDeque` | Fast | Medium | No | No |
| `heapless::spsc::Queue` | Fast | Low | Yes (SPSC) | Yes |
| `crossbeam::queue::ArrayQueue` | Very Fast | Medium | Yes (MPMC) | No |
| `embassy_sync::channel::Channel` | Medium | Low | Yes | Yes |

**Recommendation**: For embedded use `heapless` or `embassy_sync`.

### Mutex Contention

CSP uses mutexes for:
- Connection table access (~10 connections default)
- Port binding table
- Interface list

**High-contention paths**:
- Packet routing (on every packet!)
- Connection accept/close

**Optimization**: Use lock-free queues where possible.

### Memory Allocation

CSP allocates memory for:
- Packet buffers (pre-allocated pool)
- Connection structures (pre-allocated pool)
- Interface structures (few, allocated at init)

**Critical**: `malloc/free` are called from:
- ✅ Initialization (rare, can be slow)
- ✅ Interface registration (rare)
- ❌ Should NOT be called in fast path!

If you see malloc in packet processing, something is wrong.

### Timeout Precision

CSP timeout precision depends on your `get_ms()` implementation:

```rust
// ❌ LOW PRECISION - 1 second granularity
fn get_ms(&self) -> u32 {
    (self.get_s() * 1000)  // Only updates every second!
}

// ✅ HIGH PRECISION - Actual millisecond granularity
fn get_ms(&self) -> u32 {
    embassy_time::Instant::now().as_millis() as u32
}
```
```

### 6. Memory Safety Notes

Add to USAGE.md:

```markdown
## Memory Safety with Custom Arch

### Ownership Rules

**CSP takes ownership of**:
- Pointers returned by `bin_sem_create()`, `mutex_create()`, `queue_create()`
- Memory returned by `malloc()`

**You must not**:
- Free these pointers yourself
- Store references to them (CSP may call `remove()` at any time)

**CSP guarantees**:
- `*_create()` and `*_remove()` are paired (no leaks)
- `malloc()` and `free()` are paired
- No concurrent `*_remove()` calls on same handle

### Pointer Validity

```rust
// ✅ SAFE - Check for null before use
fn bin_sem_wait(&self, sem: *mut c_void, timeout: u32) -> bool {
    if sem.is_null() {
        return false;  // Fail gracefully
    }
    
    unsafe {
        let actual_sem = &*(sem as *const MySemaphore);
        actual_sem.wait(timeout)
    }
}

// ❌ UNSAFE - No null check
fn bin_sem_wait(&self, sem: *mut c_void, timeout: u32) -> bool {
    unsafe {
        let actual_sem = &*(sem as *const MySemaphore);  // CRASH if null!
        actual_sem.wait(timeout)
    }
}
```

### Type Safety

```rust
// ❌ DANGEROUS - No type checking
fn queue_create(&self, length: usize, item_size: usize) -> *mut c_void {
    let queue = Box::new(VecDeque::new());
    Box::into_raw(queue) as *mut c_void
    // item_size ignored! CSP will memcpy wrong size!
}

// ✅ SAFE - Enforce item_size
struct TypedQueue {
    queue: VecDeque<Vec<u8>>,
    item_size: usize,
}

fn queue_enqueue(&self, queue: *mut c_void, item: *const c_void, timeout: u32) -> bool {
    let q = unsafe { &mut *(queue as *mut TypedQueue) };
    
    // Copy exactly item_size bytes
    let mut data = vec![0u8; q.item_size];
    unsafe {
        core::ptr::copy_nonoverlapping(
            item as *const u8,
            data.as_mut_ptr(),
            q.item_size
        );
    }
    
    q.queue.push_back(data);
    true
}
```
```

### 7. Documentation Updates

**Add to README.md**:

```markdown
### Custom Architecture Support

For embedded/bare-metal targets, implement the `CspArch` trait:

```rust
use libcsp::{CspArch, export_arch};

struct MyRTOS;
impl CspArch for MyRTOS {
    // Implement required methods...
}

static ARCH: MyRTOS = MyRTOS;
export_arch!(MyRTOS, ARCH);
```

See [docs/arch/](docs/arch/) for complete platform-specific examples:
- [Embassy (async Rust)](docs/arch/EMBASSY.md)
- [FreeRTOS](docs/arch/FREERTOS.md)
- [RTIC](docs/arch/RTIC.md)
```

**Add to USAGE.md Table of Contents**:

```markdown
## 8. Custom Arch and Time (RTOS/Bare-Metal)
   - 8.1 Providing Time
   - 8.2 Implementing CspArch Trait
   - 8.3 Common Pitfalls ⭐ NEW
   - 8.4 Platform-Specific Examples ⭐ NEW
   - 8.5 Testing Custom Implementations ⭐ NEW
   - 8.6 Performance Considerations ⭐ NEW
   - 8.7 Memory Safety ⭐ NEW
```

## Summary

Current documentation is **minimal but correct**. To make it **comprehensive**:

1. ✅ **Add complete real-world examples** (Embassy, FreeRTOS, RTIC)
2. ✅ **Document common pitfalls** (mutex guards, async/blocking, alignment)
3. ✅ **Provide testing strategies** (unit tests, integration tests)
4. ✅ **Explain performance implications** (lock contention, allocation paths)
5. ✅ **Add safety guidelines** (pointer validity, type safety, ownership)

This transforms the documentation from "here's the API" to "here's how to actually implement it correctly and safely."
