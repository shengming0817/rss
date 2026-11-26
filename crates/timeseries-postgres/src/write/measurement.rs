//! Observe the real SQLx argument buffer while it still overlaps its input arrays.
use rss_timeseries::measurement::Session;
use sqlx::{
    Encode, Postgres, Type,
    encode::IsNull,
    error::BoxDynError,
    postgres::{PgArgumentBuffer, PgTypeInfo},
};
use std::cell::Cell;

pub(super) struct Buffers(Cell<usize>, Session);
impl Default for Buffers {
    fn default() -> Self {
        Self(Cell::new(0), Session::detailed())
    }
}

impl Buffers {
    pub(super) fn set(&self, bytes: usize) {
        let old = self.0.replace(bytes);
        self.1.update(|r| {
            r.live_bytes = r.live_bytes + bytes - old;
            r.peak_live_bytes = r.peak_live_bytes.max(r.live_bytes);
        });
    }
}

impl Drop for Buffers {
    fn drop(&mut self) {
        self.set(0);
    }
}

pub(super) struct Observed<'a, T> {
    pub value: T,
    pub buffers: &'a Buffers,
    pub scratch: usize,
}
impl<T: Type<Postgres>> Type<Postgres> for Observed<'_, T> {
    fn type_info() -> PgTypeInfo {
        T::type_info()
    }
}
impl<'q, T: Encode<'q, Postgres>> Encode<'q, Postgres> for Observed<'_, T> {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        let result = self.value.encode_by_ref(buf)?;
        self.buffers.set(self.scratch + buf.capacity());
        self.buffers.1.update(|r| r.bind_bytes += buf.len());
        Ok(result)
    }
}
