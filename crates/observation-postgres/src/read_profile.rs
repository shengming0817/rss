//! Task-scoped instrumentation for the real-provider cost fixture.
use std::{
    future::Future,
    sync::Arc,
    sync::atomic::{AtomicU64, Ordering::Relaxed},
};

/// Successful workload counters, separated by page and transaction resolver.
#[derive(Default, Debug)]
pub struct ReadWork {
    /// Canonical bytes received by Rust for restoration.
    pub raw_bytes: AtomicU64,
    /// Report decodes (each successful decode performs one canonical serialization).
    pub decodes: AtomicU64,
    /// Canonical serializations actually executed.
    pub encodes: AtomicU64,
    /// Largest PostgreSQL DataRow frame held for a single page or resolution row.
    pub largest_row: AtomicU64,
    /// Total major buffer capacities produced by this stage.
    pub decoded_buffers: AtomicU64,
    /// Maximum major buffer capacity for one restored report.
    pub largest_report: AtomicU64,
    /// Full report fingerprints computed by Rust.
    pub fingerprints: AtomicU64,
    /// Current report fingerprints evaluated by PostgreSQL.
    pub database_fingerprints: AtomicU64,
}

/// Instrument only the caller's future, including any SQL and synchronous reconstruction.
#[derive(Default)]
pub struct ReadProfile {
    /// Page work.
    pub source: ReadWork,
    /// Borrowed transaction work.
    pub resolver: ReadWork,
    phase: std::sync::Mutex<SamplingPhase>,
    page_end: Option<Box<dyn Fn() + Send + Sync>>,
}

#[derive(Default)]
struct SamplingPhase {
    active_pages: usize,
    transition: u64,
}

tokio::task_local! {static PROFILE: Arc<ReadProfile>;}
tokio::task_local! {static IN_PAGE: ();}

impl ReadProfile {
    /// Observe the page boundary before its owned results leave the reader.
    pub fn with_page_end(callback: impl Fn() + Send + Sync + 'static) -> Self {
        Self {
            page_end: Some(Box::new(callback)),
            ..Self::default()
        }
    }
    /// Monotone phase marker; odd values identify page reads.
    pub fn transition(&self) -> u64 {
        self.phase
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .transition
    }
    /// Run the measured operation under this profile.
    pub async fn run<F: Future>(self: &Arc<Self>, operation: F) -> F::Output {
        PROFILE.scope(self.clone(), operation).await
    }
    /// Whether the measured task is currently reading its source page.
    pub fn reading_page(&self) -> bool {
        self.transition() % 2 == 1
    }
}

// The guard owns the profile even if a pending future is dropped outside its task-local scope.
struct PageRead(Arc<ReadProfile>);
impl PageRead {
    fn enter(profile: Arc<ReadProfile>) -> Self {
        {
            let mut phase = profile.phase.lock().unwrap_or_else(|e| e.into_inner());
            if phase.active_pages == 0 {
                phase.transition += 1;
            }
            phase.active_pages += 1;
        }
        Self(profile)
    }
}
impl Drop for PageRead {
    fn drop(&mut self) {
        let mut phase = self.0.phase.lock().unwrap_or_else(|e| e.into_inner());
        phase.active_pages -= 1;
        if phase.active_pages == 0 {
            phase.transition += 1;
        }
    }
}
pub(crate) async fn page<F: Future>(work: F) -> F::Output {
    let Ok(profile) = PROFILE.try_with(Arc::clone) else {
        return work.await;
    };
    let guard = PageRead::enter(profile);
    let result = IN_PAGE.scope((), work).await;
    if let Some(observe) = &guard.0.page_end {
        observe();
    }
    result
}
pub(crate) fn count(update: impl FnOnce(&ReadWork)) {
    let _ = PROFILE.try_with(|p| {
        update(if IN_PAGE.try_with(|()| ()).is_ok() {
            &p.source
        } else {
            &p.resolver
        })
    });
}

pub(crate) fn measure<R>(operation: impl FnOnce() -> R) -> R {
    let (result, work) = rss_observation::measurement::measure(operation);
    count(|c| {
        c.decodes.fetch_add(work.decodes, Relaxed);
        c.encodes.fetch_add(work.encodes, Relaxed);
        c.fingerprints.fetch_add(work.fingerprints, Relaxed);
        c.decoded_buffers.fetch_add(work.buffers as u64, Relaxed);
        c.largest_report.fetch_max(work.buffers as u64, Relaxed);
    });
    result
}

pub(crate) fn row(row: &sqlx::postgres::PgRow) {
    use sqlx::{Row, ValueRef};
    count(|c| {
        // DataRow has a 5-byte message header, a 2-byte count and a 4-byte length per column.
        let bytes = (0..row.len())
            .filter_map(|i| row.try_get_raw(i).ok()?.as_bytes().ok())
            .map(<[u8]>::len)
            .sum::<usize>()
            + 7
            + row.len() * 4;
        c.largest_row.fetch_max(bytes as u64, Relaxed);
        if let Ok(raw) = row.try_get_raw("raw")
            && !raw.is_null()
            && let Ok(raw) = raw.as_bytes()
        {
            c.raw_bytes.fetch_add(raw.len() as u64, Relaxed);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dropping_a_pending_page_restores_the_sampling_phase() {
        let profile = Arc::new(ReadProfile::default());
        let mut stalled = Box::pin(profile.run(page(async {
            count(|c| {
                c.raw_bytes.fetch_add(7, Relaxed);
            });
            std::future::pending::<()>().await
        })));
        assert!(futures::poll!(stalled.as_mut()).is_pending());
        assert!(profile.reading_page());
        profile
            .run(async {
                count(|c| {
                    c.raw_bytes.fetch_add(2, Relaxed);
                });
            })
            .await;
        drop(stalled);
        assert!(!profile.reading_page());
        profile
            .run(async {
                count(|c| {
                    c.raw_bytes.fetch_add(3, Relaxed);
                });
            })
            .await;
        assert_eq!(
            (
                profile.source.raw_bytes.load(Relaxed),
                profile.resolver.raw_bytes.load(Relaxed)
            ),
            (7, 5)
        );
    }
}
