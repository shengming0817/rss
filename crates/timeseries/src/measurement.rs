//! Opt-in process-wide counters for isolated integration measurements.
use std::{
    collections::BTreeMap,
    io::Write,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
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

static NEXT: AtomicU64 = AtomicU64::new(1);
static CURRENT: AtomicU64 = AtomicU64::new(0);
static DETAIL: AtomicBool = AtomicBool::new(false);
static TOTALS: Mutex<(u64, Option<Report>)> = Mutex::new((0, None));

/// Each run starts after fixture setup. A handle from another run cannot debit this one.
pub fn start(detail: bool) {
    let mut guard = TOTALS.lock().unwrap_or_else(|e| e.into_inner());
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    *guard = (id, Some(Report::default()));
    DETAIL.store(detail, Ordering::Relaxed);
    CURRENT.store(id, Ordering::Release);
}

pub fn finish() -> Report {
    let mut guard = TOTALS.lock().unwrap_or_else(|e| e.into_inner());
    CURRENT.store(0, Ordering::Release);
    guard.1.take().unwrap_or_default()
}

#[derive(Clone, Copy)]
pub struct Session(u64);
impl Session {
    pub fn current() -> Self {
        Self(CURRENT.load(Ordering::Acquire))
    }
    pub fn detailed() -> Self {
        if DETAIL.load(Ordering::Relaxed) {
            Self::current()
        } else {
            Self(0)
        }
    }
    pub fn update(self, f: impl FnOnce(&mut Report)) {
        if self.0 == 0 {
            return;
        }
        let mut guard = TOTALS.lock().unwrap_or_else(|e| e.into_inner());
        if guard.0 == self.0
            && let Some(report) = &mut guard.1
        {
            f(report);
        }
    }
}

#[derive(Clone, Copy)]
pub struct Started(Session, Instant);
#[allow(clippy::disallowed_methods)] // reason: real elapsed time for isolated measurements.
fn observed_now() -> Instant {
    Instant::now()
}
pub fn timer() -> Option<Started> {
    let session = Session::current();
    (session.0 != 0).then(|| Started(session, observed_now()))
}
pub fn encoding_timer() -> Option<Started> {
    if DETAIL.load(Ordering::Relaxed) {
        timer()
    } else {
        None
    }
}

pub fn record(name: &'static str, time: Option<Started>, json: usize, sha: usize) {
    if let Some(Started(session, start)) = time {
        let elapsed = observed_now() - start;
        session.update(|report| {
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
