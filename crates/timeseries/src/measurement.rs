//! Opt-in process-wide counters for isolated integration measurements.
use std::{
    collections::BTreeMap,
    io::Write,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Default)]
pub struct Total {
    pub calls: u64,
    pub json_bytes: u64,
    pub sha_bytes: u64,
    pub elapsed: Duration,
}

#[derive(Debug, Default)]
pub struct Report {
    pub stages: BTreeMap<&'static str, Total>,
    pub bind_bytes: usize,
    pub live_bytes: usize,
    pub peak_live_bytes: usize,
    pub reserved_bytes: usize,
    pub peak_reserved_bytes: usize,
}

static ENABLED: AtomicBool = AtomicBool::new(false);
static TOTALS: Mutex<Option<Report>> = Mutex::new(None);

/// Start after fixture setup. The benchmark runs alone in its test process.
pub fn start() {
    *TOTALS.lock().unwrap_or_else(|e| e.into_inner()) = Some(Report::default());
    ENABLED.store(true, Ordering::Relaxed);
}

pub fn finish() -> Report {
    ENABLED.store(false, Ordering::Relaxed);
    TOTALS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
        .unwrap_or_default()
}

pub fn update(f: impl FnOnce(&mut Report)) {
    if ENABLED.load(Ordering::Relaxed)
        && let Some(report) = TOTALS.lock().unwrap_or_else(|e| e.into_inner()).as_mut()
    {
        f(report);
    }
}

#[allow(clippy::disallowed_methods)] // reason: real elapsed time for isolated measurements.
pub fn timer() -> Option<Instant> {
    ENABLED.load(Ordering::Relaxed).then(Instant::now)
}

pub fn record(name: &'static str, time: Option<Instant>, json: usize, sha: usize) {
    if let Some(start) = time {
        let elapsed = start.elapsed();
        update(|report| {
            let total = report.stages.entry(name).or_default();
            total.calls += 1;
            total.elapsed += elapsed;
            total.json_bytes += json as u64;
            total.sha_bytes += sha as u64;
        });
    }
}

pub(crate) struct Count<W> {
    pub writer: W,
    pub bytes: usize,
}

impl<W: Write> Write for Count<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let n = self.writer.write(bytes)?;
        self.bytes += n;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}
