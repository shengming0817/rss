//! Test-only observation of live allocations, before System releases them.
//! ref: rust library/core/src/alloc/global.rs@1.96.0
#![allow(unsafe_code)]
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

struct Slot {
    address: AtomicUsize,
    size: AtomicUsize,
}
impl Slot {
    const fn new() -> Self {
        Self {
            address: AtomicUsize::new(0),
            size: AtomicUsize::new(0),
        }
    }
}
static SLOTS: [Slot; 64] = [const { Slot::new() }; 64];
static THRESHOLD: AtomicUsize = AtomicUsize::new(usize::MAX);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static RELEASES: AtomicUsize = AtomicUsize::new(0);
static DIRTY: AtomicUsize = AtomicUsize::new(0);
static REALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static OVERFLOW: AtomicUsize = AtomicUsize::new(0);

pub struct ProbeAllocator;
#[global_allocator]
static ALLOCATOR: ProbeAllocator = ProbeAllocator;

pub fn start(threshold: usize) {
    for slot in &SLOTS {
        assert_eq!(slot.address.load(SeqCst), 0);
    }
    for counter in [&ALLOCATIONS, &RELEASES, &DIRTY, &REALLOCATIONS, &OVERFLOW] {
        counter.store(0, SeqCst);
    }
    THRESHOLD.store(threshold, SeqCst);
}

/// Register an existing byte allocation before moving it into a public key constructor.
pub fn watch(bytes: &Vec<u8>) {
    track(bytes.as_ptr() as usize, bytes.capacity());
}
fn track(address: usize, size: usize) {
    if address == 0 || size == 0 {
        return;
    }
    for slot in &SLOTS {
        if slot.address.load(SeqCst) == 0 {
            slot.size.store(size, SeqCst);
            slot.address.store(address, SeqCst);
            ALLOCATIONS.fetch_add(1, SeqCst);
            return;
        }
    }
    OVERFLOW.fetch_add(1, SeqCst);
}

unsafe fn inspect(ptr: *mut u8, layout: Layout, reallocating: bool) {
    for slot in &SLOTS {
        if slot.address.load(SeqCst) == ptr as usize {
            let size = slot.size.load(SeqCst);
            if size != layout.size() {
                OVERFLOW.fetch_add(1, SeqCst);
            }
            // SAFETY: System has not released ptr yet. Every allocation (including realloc's
            // new tail) is zero-initialized by this allocator. Only u8/String buffers are
            // selected; their writes do not introduce uninitialized padding.
            let bytes = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            if bytes.iter().any(|b| *b != 0) {
                DIRTY.fetch_add(1, SeqCst);
            }
            RELEASES.fetch_add(1, SeqCst);
            if reallocating {
                REALLOCATIONS.fetch_add(1, SeqCst);
            }
            slot.address.store(0, SeqCst);
            break;
        }
    }
}

// SAFETY: All memory is provided/released by System with matching layouts. Metadata has fixed
// capacity, callbacks neither allocate nor unwind. The fixture executes measured calls serially.
unsafe impl GlobalAlloc for ProbeAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: GlobalAlloc caller provides a valid nonzero layout.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if layout.size() >= THRESHOLD.load(SeqCst) {
            track(ptr as usize, layout.size());
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: The caller owns this live allocation with its original layout.
        unsafe {
            inspect(ptr, layout, false);
            System.dealloc(ptr, layout);
        }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let Ok(next_layout) = Layout::from_size_align(new_size, layout.align()) else {
            return std::ptr::null_mut();
        };
        // SAFETY: new_size is nonzero by GlobalAlloc's contract. On failure the old block
        // remains untouched. On success copy its prefix before inspecting/releasing it.
        unsafe {
            let next = System.alloc_zeroed(next_layout);
            if next.is_null() {
                return next;
            }
            std::ptr::copy_nonoverlapping(ptr, next, layout.size().min(new_size));
            inspect(ptr, layout, true);
            System.dealloc(ptr, layout);
            if new_size >= THRESHOLD.load(SeqCst) {
                track(next as usize, new_size);
            }
            next
        }
    }
}

pub fn finish(expected: usize, dirty: usize) {
    THRESHOLD.store(usize::MAX, SeqCst);
    assert_eq!(
        OVERFLOW.load(SeqCst),
        0,
        "probe metadata overflow/layout mismatch"
    );
    assert_eq!(
        ALLOCATIONS.load(SeqCst),
        expected,
        "observation must actually hit every generation"
    );
    assert_eq!(
        RELEASES.load(SeqCst),
        expected,
        "every watched allocation must be released"
    );
    assert_eq!(DIRTY.load(SeqCst), dirty, "nonzero bytes before release");
    assert_eq!(
        REALLOCATIONS.load(SeqCst),
        0,
        "sensitive buffers must not reallocate"
    );
}
