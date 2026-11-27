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

#[derive(Clone, Copy, Debug)]
pub struct CapacitySample {
    pub at: Instant,
    pub slots: u32,
    pub bytes: u32,
    pub queued: usize,
    pub granted: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct PreparationWait {
    pub class: Option<&'static str>,
    pub weight: u32,
    pub queued: Instant,
    pub granted: Instant,
    pub resumed: Instant,
}

#[derive(Debug, Default)]
pub struct Report {
    pub definition_bindings: usize,
    pub index_peak_bytes: usize,
    pub probe_stages: BTreeMap<(&'static str, &'static str), Total>,
    pub pre_submit_bytes: usize,
    pub peak_pre_submit_bytes: usize,
    pub stages: BTreeMap<&'static str, Total>,
    pub bind_bytes: usize,
    pub live_bytes: usize,
    pub peak_live_bytes: usize,
    pub reserved_bytes: usize,
    pub peak_reserved_bytes: usize,
    pub granted_batches: usize,
    /// Queue-full refusals returned while the caller still had time remaining.
    pub preparation_rejections: u64,
    pub capacity_samples: Vec<CapacitySample>,
    pub preparation_waits: Vec<PreparationWait>,
    pub encoders: usize,
    pub peak_encoders: usize,
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
    // Called under the adapter's capacity lock. Analyze the timeline after the
    // workload so recording a transition never walks outstanding waiters.
    pub fn capacity(self, slots: u32, bytes: u32, queued: usize) -> Option<Started> {
        let mut sampled = None;
        self.update(|r| {
            let at = observed_now();
            r.capacity_samples.push(CapacitySample {
                at,
                slots,
                bytes,
                queued,
                granted: r.granted_batches,
            });
            sampled = Some(Started(self, at));
        });
        sampled
    }
    pub fn preparation_wait(self, weight: u32, queued: Option<Started>, granted: Option<Started>) {
        if let (Some(queued), Some(granted)) = (queued, granted) {
            self.update(|r| {
                r.preparation_waits.push(PreparationWait {
                    class: PROBE.get(),
                    weight,
                    queued: queued.1,
                    granted: granted.1,
                    resumed: observed_now(),
                })
            });
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

// Probe futures may migrate between worker threads. Set their label only for each poll.
thread_local! {
    static PROBE: std::cell::Cell<Option<&'static str>> = const {std::cell::Cell::new(None)};
}
struct RestoreProbe(Option<&'static str>);
impl Drop for RestoreProbe {
    fn drop(&mut self) {
        PROBE.set(self.0);
    }
}
pub async fn probe<F: Future>(name: &'static str, future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    std::future::poll_fn(|cx| {
        let _restore = RestoreProbe(PROBE.replace(Some(name)));
        future.as_mut().poll(cx)
    })
    .await
}
pub fn main_workload() -> bool {
    PROBE.get().is_none()
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
            let total = match PROBE.get() {
                Some(probe) => report.probe_stages.entry((probe, name)).or_default(),
                None => report.stages.entry(name).or_default(),
            };
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
