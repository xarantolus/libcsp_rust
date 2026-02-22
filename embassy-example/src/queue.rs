//! Simple FIFO queue implementation for CSP in no_std embedded environment.
//!
//! Uses a fixed-size circular buffer with critical section protection for thread safety.

use core::cell::{Cell, UnsafeCell};
use core::ptr;

/// A simple FIFO queue with blocking enqueue/dequeue operations.
///
/// Uses a circular buffer internally. Thread-safe via critical sections.
pub struct Queue {
    pub(crate) buffer: UnsafeCell<*mut u8>,
    capacity: usize,
    item_size: usize,
    head: Cell<usize>,
    tail: Cell<usize>,
    count: Cell<usize>,
}

// Safety: Queue uses critical sections for all shared state access.
// All modifications to Cell fields happen within interrupt::free blocks.
unsafe impl Send for Queue {}
unsafe impl Sync for Queue {}

impl Queue {
    /// Create a new queue with the given capacity and item size.
    ///
    /// # Safety
    /// The caller must ensure that `buffer` points to at least `capacity * item_size` bytes
    /// of valid, initialized memory.
    pub unsafe fn new(buffer: *mut u8, capacity: usize, item_size: usize) -> Self {
        Queue {
            buffer: UnsafeCell::new(buffer),
            capacity,
            item_size,
            head: Cell::new(0),
            tail: Cell::new(0),
            count: Cell::new(0),
        }
    }

    /// Enqueue an item. Returns true on success, false if queue is full.
    ///
    /// # Safety
    /// `item` must point to at least `self.item_size` bytes of valid memory.
    pub unsafe fn enqueue(&self, item: *const u8, _timeout_ms: u32) -> bool {
        cortex_m::interrupt::free(|_cs| {
            let count = self.count.get();

            if count >= self.capacity {
                return false;  // Queue is full
            }

            // Get tail position and increment it
            let tail_pos = self.tail.get();
            self.tail.set((tail_pos + 1) % self.capacity);

            // Copy data to buffer
            let buffer = *self.buffer.get();
            let dest = buffer.add(tail_pos * self.item_size);
            ptr::copy_nonoverlapping(item, dest, self.item_size);

            // Increment count
            self.count.set(count + 1);

            true
        })
    }

    /// Dequeue an item. Returns true on success, false if queue is empty.
    ///
    /// # Safety
    /// `item` must point to at least `self.item_size` bytes of writable memory.
    pub unsafe fn dequeue(&self, item: *mut u8, _timeout_ms: u32) -> bool {
        cortex_m::interrupt::free(|_cs| {
            let count = self.count.get();

            if count == 0 {
                return false;  // Queue is empty
            }

            // Get head position and increment it
            let head_pos = self.head.get();
            self.head.set((head_pos + 1) % self.capacity);

            // Copy data from buffer
            let buffer = *self.buffer.get();
            let src = buffer.add(head_pos * self.item_size);
            ptr::copy_nonoverlapping(src, item, self.item_size);

            // Decrement count
            self.count.set(count - 1);

            true
        })
    }

    /// Get the current number of items in the queue.
    pub fn size(&self) -> usize {
        cortex_m::interrupt::free(|_cs| self.count.get())
    }
}

impl Drop for Queue {
    fn drop(&mut self) {
        // The buffer is externally managed (allocated via malloc),
        // so we don't free it here. The caller must free the buffer.
    }
}
