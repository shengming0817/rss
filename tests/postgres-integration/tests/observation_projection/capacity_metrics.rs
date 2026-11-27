use super::fixture::rss_command;
use anyhow::{Context, ensure};
use rss_observation_postgres::read_profile::ReadWork;
use sqlx::{PgPool, Postgres, pool::PoolConnection};
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};
use std::{
    alloc::System,
    process::Stdio,
    sync::atomic::{AtomicU64, Ordering::Relaxed},
    time::Duration,
};
use tokio::{
    io::AsyncReadExt as _,
    process::{Child, Command},
    task::JoinHandle,
};
use tokio_util::sync::{CancellationToken, DropGuard};

#[global_allocator]
static ALLOCATOR: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;
const RSS_PROCESS_TIMEOUT: Duration = Duration::from_secs(5);
const RSS_OUTPUT_LIMIT: usize = 64;

async fn read_rss(
    child: &mut Child,
    stop: &CancellationToken,
    timeout: Duration,
) -> anyhow::Result<Option<u64>> {
    let mut stdout = child
        .stdout
        .take()
        .context("missing RSS probe stdout")?
        .take(RSS_OUTPUT_LIMIT as u64);
    let mut bytes = Vec::new();
    let operation = tokio::time::timeout(timeout, async {
        let (status, _) = tokio::try_join!(child.wait(), stdout.read_to_end(&mut bytes))?;
        Ok::<_, std::io::Error>(status)
    });
    let completion = tokio::select! {
        biased;
        () = stop.cancelled() => Ok(None),
        result = operation => result.context("RSS probe timed out").and_then(|status| status.map(Some).map_err(Into::into)),
    };
    drop(stdout);
    if !matches!(completion, Ok(Some(_))) {
        tokio::time::timeout(RSS_PROCESS_TIMEOUT, child.kill())
            .await
            .context("timed out reaping RSS probe")?
            .context("kill and reap RSS probe")?;
    }
    let Some(status) = completion? else {
        return Ok(None);
    };
    ensure!(status.success(), "RSS probe exited with {status}");
    ensure!(
        bytes.len() < RSS_OUTPUT_LIMIT,
        "RSS probe returned oversized output"
    );
    Ok(Some(std::str::from_utf8(&bytes)?.trim().parse()?))
}

#[derive(Clone, Copy)]
pub(super) struct Memory {
    heap: i64,
    rss: u64,
}

impl Memory {
    pub(super) async fn sample() -> anyhow::Result<Self> {
        Self::sample_until(&CancellationToken::new())
            .await?
            .context("RSS sample cancelled")
    }

    async fn sample_until(stop: &CancellationToken) -> anyhow::Result<Option<Self>> {
        if stop.is_cancelled() {
            return Ok(None);
        }
        let stats = ALLOCATOR.stats();
        let heap = i64::try_from(stats.bytes_allocated)? - i64::try_from(stats.bytes_deallocated)?;
        let mut child = Command::from(rss_command())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        Ok(read_rss(&mut child, stop, RSS_PROCESS_TIMEOUT)
            .await?
            .map(|rss| Self { heap, rss }))
    }

    fn max(self, other: Self) -> Self {
        Self {
            heap: self.heap.max(other.heap),
            rss: self.rss.max(other.rss),
        }
    }
}

pub(super) struct Sampler {
    stop: DropGuard,
    task: JoinHandle<anyhow::Result<Memory>>,
}

impl Sampler {
    pub(super) fn start(mut peak: Memory) -> Self {
        let token = CancellationToken::new();
        let stop = token.clone().drop_guard();
        let task = tokio::spawn(async move {
            while let Some(sample) = Memory::sample_until(&token).await? {
                peak = peak.max(sample);
                tokio::select! {
                    () = token.cancelled() => break,
                    () = tokio::time::sleep(Duration::from_millis(2)) => {}
                }
            }
            Ok(peak)
        });
        Self { stop, task }
    }

    pub(super) async fn finish(self) -> anyhow::Result<Memory> {
        drop(self.stop);
        self.task.await?
    }
}

// The counters are attached to sessions. Keep each lease until every backend has been sampled.
async fn connections(pool: &PgPool, count: u32) -> anyhow::Result<Vec<PoolConnection<Postgres>>> {
    let mut leases = Vec::new();
    for _ in 0..count {
        leases.push(pool.acquire().await?);
    }
    Ok(leases)
}

pub(super) async fn flush(pool: &PgPool, count: u32) -> anyhow::Result<()> {
    for connection in &mut connections(pool, count).await? {
        sqlx::query("SELECT pg_stat_force_next_flush()")
            .execute(&mut **connection)
            .await?;
    }
    Ok(())
}

pub(super) async fn resolver_calls(pool: &PgPool, count: u32) -> anyhow::Result<i64> {
    let mut calls = 0;
    for connection in &mut connections(pool, count).await? {
        calls += sqlx::query_scalar::<_, i64>(
            "SELECT coalesce(sum(custom_plans+generic_plans),0)::bigint
             FROM pg_prepared_statements
             WHERE statement LIKE 'SELECT %FROM rss_observation.batches%'
               AND statement NOT LIKE '%rss_observation.journals%'",
        )
        .fetch_one(&mut **connection)
        .await?;
    }
    Ok(calls)
}

// heap, index, TOAST heap and TOAST index, each as read then hit.
pub(super) type Io = [i64; 8];

pub(super) async fn io(observer: &PgPool) -> anyhow::Result<Io> {
    let (hr, hh, ir, ih, tr, th, tir, tih) =
        sqlx::query_as::<_, (i64, i64, i64, i64, i64, i64, i64, i64)>(
            "SELECT heap_blks_read,heap_blks_hit,idx_blks_read,idx_blks_hit,
                toast_blks_read,toast_blks_hit,tidx_blks_read,tidx_blks_hit
         FROM pg_statio_user_tables WHERE relid='rss_observation.batches'::regclass",
        )
        .fetch_one(observer)
        .await?;
    Ok([hr, hh, ir, ih, tr, th, tir, tih])
}

pub(super) fn delta_io(after: Io, before: Io) -> Io {
    std::array::from_fn(|index| after[index] - before[index])
}

#[derive(Default)]
pub(super) struct ResolverTime {
    total_nanos: AtomicU64,
    max_nanos: AtomicU64,
}

impl ResolverTime {
    pub(super) fn record(&self, elapsed: Duration) {
        // Resolver calls share a two-minute deadline.
        let nanos = elapsed.as_nanos() as u64;
        self.total_nanos.fetch_add(nanos, Relaxed);
        self.max_nanos.fetch_max(nanos, Relaxed);
    }

    pub(super) fn snapshot(&self) -> [u64; 2] {
        [
            self.total_nanos.load(Relaxed) / 1000,
            self.max_nanos.load(Relaxed) / 1000,
        ]
    }
}

pub(super) struct Work {
    bytes: u64,
    decoded: u64,
    decoded_buffer_bytes: u64,
    rust_hashes: u64,
    pg_hashes: u64,
}

impl From<&ReadWork> for Work {
    fn from(work: &ReadWork) -> Self {
        Self {
            bytes: work.raw_bytes.load(Relaxed),
            decoded: work.decodes.load(Relaxed),
            decoded_buffer_bytes: work.decoded_buffers.load(Relaxed),
            rust_hashes: work.fingerprints.load(Relaxed),
            pg_hashes: work.database_fingerprints.load(Relaxed),
        }
    }
}

pub(super) struct Sample {
    pub(super) canonical_bytes: u64,
    pub(super) source: Work,
    pub(super) resolver: Work,
    pub(super) resolver_calls: i64,
    pub(super) resolver_elapsed_us: [u64; 2],
    pub(super) source_io: Io,
    pub(super) resolver_io: Io,
    pub(super) baseline: Memory,
    pub(super) ready: Memory,
    pub(super) held: Memory,
    pub(super) peak: Memory,
    pub(super) settled: Memory,
    pub(super) pools_closed: Memory,
    pub(super) hold_max: Duration,
}

impl Sample {
    pub(super) fn assert_work(&self, mode: &str, reports: u64) {
        assert_eq!(self.source.bytes, self.canonical_bytes);
        assert_eq!(self.source.decoded, reports);
        assert_eq!(u64::try_from(self.resolver_calls).ok(), Some(reports));
        let expected = if mode == "local" {
            (0, 0, 0, reports)
        } else {
            (self.canonical_bytes, reports, reports, 0)
        };
        assert_eq!(
            (
                self.resolver.bytes,
                self.resolver.decoded,
                self.resolver.rust_hashes,
                self.resolver.pg_hashes
            ),
            expected
        );
    }

    pub(super) fn print(&self) {
        let stages = [
            self.baseline,
            self.ready,
            self.held,
            self.peak.max(self.ready).max(self.held).max(self.settled),
            self.settled,
            self.pools_closed,
        ];
        let heap = stages.map(|sample| sample.heap);
        let rss = stages.map(|sample| sample.rss);
        // Allocations and deallocations are separate counters sampled during concurrent work.
        println!(
            "capacity_memory stages=baseline,ready,held,sampled_peak,settled,pools_closed rust_live_heap_bytes_estimate={heap:?} rss_kib={rss:?} gated_page_hold_us_max={}",
            self.hold_max.as_micros()
        );
        println!(
            "capacity_work canonical_bytes={} source_decoded_buffers={} resolver_sql={} resolver_body_bytes={} resolver_rust_hashes={} resolver_pg_hashes={} resolver_elapsed_us_total_max={:?}",
            self.canonical_bytes,
            self.source.decoded_buffer_bytes,
            self.resolver_calls,
            self.resolver.bytes,
            self.resolver.rust_hashes,
            self.resolver.pg_hashes,
            self.resolver_elapsed_us,
        );
        println!(
            "capacity_io order=heap_read,heap_hit,index_read,index_hit,toast_read,toast_hit,toast_index_read,toast_index_hit source={:?} resolver={:?}",
            self.source_io, self.resolver_io
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stalled_probe() -> std::io::Result<Child> {
        Command::new("/bin/sleep")
            .arg("30")
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
    }

    #[tokio::test]
    async fn timed_out_rss_probe_is_reaped() -> anyhow::Result<()> {
        let mut child = stalled_probe()?;
        let error = read_rss(
            &mut child,
            &CancellationToken::new(),
            Duration::from_millis(25),
        )
        .await
        .err()
        .context("stalled probe unexpectedly finished")?;
        assert!(
            error.to_string().contains("RSS probe timed out"),
            "{error:#}"
        );
        assert!(child.id().is_none());
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_rss_probe_is_reaped() -> anyhow::Result<()> {
        let mut child = stalled_probe()?;
        let stop = CancellationToken::new();
        let (result, ()) = tokio::join!(read_rss(&mut child, &stop, RSS_PROCESS_TIMEOUT), async {
            tokio::task::yield_now().await;
            stop.cancel();
        });
        assert!(result?.is_none());
        assert!(child.id().is_none());
        Ok(())
    }
}
