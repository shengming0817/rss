//! Synchronous operation counters for isolated provider integration measurements.
use std::cell::Cell;

/// Actual report operations and major decoded buffer capacities in one synchronous call.
#[derive(Clone, Copy, Default)]
pub struct BatchWork {
    /// Entries into the decoder.
    pub decodes: u64,
    /// Canonical serializations.
    pub encodes: u64,
    /// Full scope-bound hashes.
    pub fingerprints: u64,
    /// Canonical Vec, Change array and value Vec capacities after decoding.
    pub buffers: usize,
}
thread_local! {static WORK: Cell<BatchWork> = const {Cell::new(BatchWork {decodes:0,encodes:0,fingerprints:0,buffers:0})};}

/// Measure a synchronous operation on the calling thread.
pub fn measure<R>(operation: impl FnOnce() -> R) -> (R, BatchWork) {
    let previous = WORK.take();
    let result = operation();
    (result, WORK.replace(previous))
}
pub(crate) fn update(f: impl FnOnce(&mut BatchWork)) {
    let mut current = WORK.get();
    f(&mut current);
    WORK.set(current);
}
