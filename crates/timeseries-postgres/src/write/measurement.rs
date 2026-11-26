//! Observe the real SQLx argument buffer while it still overlaps its input arrays.
use rss_timeseries::measurement::Session;
use sqlx::{
    Encode, Postgres, Type,
    encode::IsNull,
    error::BoxDynError,
    postgres::{PgArgumentBuffer, PgTypeInfo},
};
use std::cell::Cell;

// Measure the submitted and unsubmitted envelopes separately. SQLx may retain the
// arguments through statement preparation; fetch completion is an observable upper bound.
pub(super) struct Buffers {
    live: Cell<usize>,
    arguments: Cell<usize>,
    submitted: Cell<bool>,
    session: Session,
}
impl Default for Buffers {
    fn default() -> Self {
        Self {
            live: Cell::new(0),
            arguments: Cell::new(0),
            submitted: Cell::new(false),
            session: Session::detailed(),
        }
    }
}
impl Buffers {
    pub(super) fn set(&self, bytes: usize) {
        let old = self.live.replace(bytes);
        self.session.update(|r| {
            r.live_bytes = r.live_bytes + bytes - old;
            r.peak_live_bytes = r.peak_live_bytes.max(r.live_bytes);
            if !self.submitted.get() {
                r.pre_submit_bytes = r.pre_submit_bytes + bytes - old;
                r.peak_pre_submit_bytes = r.peak_pre_submit_bytes.max(r.pre_submit_bytes);
            }
        });
    }
    pub(super) fn keep_arguments(&self) {
        self.set(self.arguments.get());
    }
    pub(super) fn submit(&self) {
        self.submitted.set(true);
        self.session
            .update(|r| r.pre_submit_bytes -= self.live.get());
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
        self.buffers.arguments.set(buf.capacity());
        self.buffers.set(self.scratch + buf.capacity());
        if rss_timeseries::measurement::main_workload() {
            self.buffers.session.update(|r| r.bind_bytes += buf.len());
        }
        Ok(result)
    }
}

/// Number of preparation futures currently inside the encoding phase.
pub(super) struct Encoding(Session);
impl Encoding {
    pub(super) fn enter() -> Self {
        let session = Session::current();
        session.update(|r| {
            r.encoders += 1;
            r.peak_encoders = r.peak_encoders.max(r.encoders);
        });
        Self(session)
    }
}
impl Drop for Encoding {
    fn drop(&mut self) {
        self.0.update(|r| r.encoders -= 1);
    }
}
