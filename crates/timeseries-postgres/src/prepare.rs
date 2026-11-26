//! Fixed-order batch and weighted-byte admission. No encoded data exists while waiting.
use crate::Limits;
use rss_timeseries::{Batch, Error};
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Two bounded JSON arenas and their SQLx copy. All selected definitions occur inside
/// distinct samples, so their combined JSON fits one input length. Per item cover
/// three digest arrays, two offset arrays, one definition binding (three words),
/// and binary bytea[] elements (76/sample and 40/definition). Fixed space covers
/// scalar identity strings, argument/array headers and fixed preparation state.
pub(crate) const fn charge(json: usize, count: usize) -> u32 {
    (4 * json + count * (116 + 96 + 5 * size_of::<usize>()) + 4096) as u32
}
pub(crate) struct Capacity {
    batches: Arc<Semaphore>,
    bytes: Arc<Semaphore>,
}

pub(crate) struct Permit {
    _batch: OwnedSemaphorePermit,
    _bytes: OwnedSemaphorePermit,
    #[cfg(feature = "integration")]
    weight: usize,
}
#[cfg(feature = "integration")]
impl Drop for Permit {
    fn drop(&mut self) {
        rss_timeseries::measurement::update(|r| r.reserved_bytes -= self.weight);
    }
}

impl Capacity {
    pub(crate) fn new(limits: &Limits) -> Result<Self, Error> {
        let batches = limits.max_prepare_batches.get() as usize;
        let bytes = limits.max_prepare_bytes.get() as usize;
        if limits.max_prepare_bytes.get() < Limits::MIN_PREPARE_BYTES
            || batches > Semaphore::MAX_PERMITS
            || bytes > Semaphore::MAX_PERMITS
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            batches: Arc::new(Semaphore::new(batches)),
            bytes: Arc::new(Semaphore::new(bytes)),
        })
    }
    pub(crate) async fn acquire(&self, batch: &Batch) -> Result<Permit, Error> {
        #[cfg(feature = "integration")]
        let start = rss_timeseries::measurement::timer();
        let weight = charge(batch.encoded_len(), batch.samples().len());
        let slot = self
            .batches
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Error::Unavailable)?;
        let bytes = self
            .bytes
            .clone()
            .acquire_many_owned(weight)
            .await
            .map_err(|_| Error::Unavailable)?;
        #[cfg(feature = "integration")]
        {
            rss_timeseries::measurement::record("permit_wait", start, 0, 0);
            rss_timeseries::measurement::update(|r| {
                r.reserved_bytes += weight as usize;
                r.peak_reserved_bytes = r.peak_reserved_bytes.max(r.reserved_bytes);
            });
        }
        Ok(Permit {
            _batch: slot,
            _bytes: bytes,
            #[cfg(feature = "integration")]
            weight: weight as usize,
        })
    }
    pub(crate) fn close(&self) {
        self.batches.close();
        self.bytes.close();
    }
    #[cfg(feature = "integration")]
    pub(crate) fn available(&self) -> (usize, usize) {
        (
            self.batches.available_permits(),
            self.bytes.available_permits(),
        )
    }
}
