//! Opt-in, task-scoped counters for fixed-load provider integration tests.
use std::{cell::Cell, future::Future, time::Duration};

#[derive(Clone, Copy, Default, Debug)]
pub struct Counters {
    pub fence_rows: usize,
    pub fence_bytes: usize,
    pub build_cpu: Duration,
    pub match_cpu: Duration,
    pub comparisons: usize,
    pub candidates: usize,
    pub updated: u64,
    pub locked: Duration,
}

struct Run {
    cpu: fn() -> Duration,
    totals: Cell<Counters>,
}
tokio::task_local! { static RUN: Run; }

/// The caller supplies a calling-thread CPU clock. CPU spans contain no await points.
pub async fn measure<T>(cpu: fn() -> Duration, op: impl Future<Output = T>) -> (T, Counters) {
    RUN.scope(
        Run {
            cpu,
            totals: Cell::default(),
        },
        async {
            let result = op.await;
            (result, RUN.with(|run| run.totals.get()))
        },
    )
    .await
}

pub(crate) fn record(f: impl FnOnce(&mut Counters)) {
    let _ = RUN.try_with(|run| {
        let mut totals = run.totals.get();
        f(&mut totals);
        run.totals.set(totals);
    });
}

type CpuStart = (fn() -> Duration, Duration);

pub(crate) fn cpu_start() -> Option<CpuStart> {
    RUN.try_with(|run| (run.cpu, (run.cpu)())).ok()
}

pub(crate) fn elapsed(start: Option<CpuStart>) -> Duration {
    start.map_or(Duration::ZERO, |(clock, begin)| clock() - begin)
}
