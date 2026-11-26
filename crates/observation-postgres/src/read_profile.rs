//! Task-scoped instrumentation for the real-provider cost fixture.
use std::{future::Future, sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed}, sync::Arc};

/// Successful workload counters, separated by page and transaction resolver.
#[derive(Default, Debug)]
pub struct ReadWork {
    /// Canonical bytes received by Rust for restoration.
    pub raw_bytes: AtomicU64,
    /// Report decodes (each successful decode performs one canonical serialization).
    pub decodes: AtomicU64,
    /// Full report fingerprints computed by Rust.
    pub fingerprints: AtomicU64,
    /// Current report fingerprints evaluated by PostgreSQL.
    pub database_fingerprints: AtomicU64,
}

/// Instrument only the caller's future, including any SQL and synchronous reconstruction.
#[derive(Default, Debug)]
pub struct ReadProfile {
    /// Page work.
    pub source: ReadWork,
    /// Borrowed transaction work.
    pub resolver: ReadWork,
    reading: AtomicBool,
}

tokio::task_local! {static PROFILE: Arc<ReadProfile>;}

impl ReadProfile {
    /// Run the measured operation under this profile.
    pub async fn run<F: Future>(self: &Arc<Self>, operation: F) -> F::Output {
        PROFILE.scope(self.clone(), operation).await
    }
    /// Whether the measured task is currently reading its source page.
    pub fn reading_page(&self) -> bool {
        self.reading.load(Relaxed)
    }
}

pub(crate) fn reading(value: bool) {
    let _ = PROFILE.try_with(|profile| profile.reading.store(value, Relaxed));
}
pub(crate) fn count(update: impl FnOnce(&ReadWork)) {
    let _ = PROFILE.try_with(|p| update(if p.reading_page() { &p.source } else { &p.resolver }));
}

