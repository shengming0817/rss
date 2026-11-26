//! Observe the real SQLx argument buffer while it still overlaps its input arrays.
use rss_timeseries::measurement::{record, timer, update};
use sqlx::{
    Encode, Postgres, Type,
    encode::IsNull,
    error::BoxDynError,
    postgres::{PgArgumentBuffer, PgTypeInfo},
};
use std::cell::Cell;

#[derive(Default)]
pub(super) struct Buffers(Cell<usize>);

impl Buffers {
    pub(super) fn set(&self, bytes: usize) {
        let old = self.0.replace(bytes);
        update(|r| {
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
    pub final_arg: bool,
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
        if self.final_arg {
            update(|r| r.bind_bytes += buf.len());
        }
        Ok(result)
    }
}

pub(super) fn raw<T: serde::Serialize>(
    name: &'static str,
    value: &T,
) -> Result<Vec<u8>, rss_timeseries::Error> {
    let start = timer();
    let bytes = crate::lifecycle::bytes(value)?;
    record(name, start, bytes.len(), 0);
    Ok(bytes)
}

pub(super) fn nested(values: &Vec<Vec<u8>>) -> usize {
    values.capacity() * size_of::<Vec<u8>>() + values.iter().map(Vec::capacity).sum::<usize>()
}
