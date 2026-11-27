use super::fixture::rss_kib;
use rss_observation_postgres::read_profile::ReadWork;
use sqlx::{PgPool, Postgres, pool::PoolConnection};
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};
use std::{alloc::System, sync::atomic::Ordering::Relaxed, time::Duration};
use tokio::task::JoinHandle;
use tokio_util::sync::{CancellationToken, DropGuard};

#[global_allocator]
static ALLOCATOR: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[derive(Clone, Copy)]
pub(super) struct Memory {
    heap: i64,
    rss: u64,
}

impl Memory {
    pub(super) fn sample() -> anyhow::Result<Self> {
        let stats = ALLOCATOR.stats();
        Ok(Self {
            heap: i64::try_from(stats.bytes_allocated)? - i64::try_from(stats.bytes_deallocated)?,
            rss: rss_kib()?,
        })
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
        let task = tokio::task::spawn_blocking(move || {
            while !token.is_cancelled() {
                peak = peak.max(Memory::sample()?);
                std::thread::sleep(Duration::from_millis(2));
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
    pub(super) source_io: Io,
    pub(super) resolver_io: Io,
    pub(super) baseline: Memory,
    pub(super) ready: Memory,
    pub(super) held: Memory,
    pub(super) peak: Memory,
    pub(super) settled: Memory,
    pub(super) hold_max: Duration,
}

impl Sample {
    pub(super) fn assert_work(&self, mode: &str, canonical_bytes: u64, reports: u64) {
        assert_eq!(self.source.bytes, canonical_bytes);
        assert_eq!(self.source.decoded, reports);
        assert_eq!(u64::try_from(self.resolver_calls).ok(), Some(reports));
        let expected = if mode == "local" {
            (0, 0, 0, reports)
        } else {
            (canonical_bytes, reports, reports, 0)
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
        ];
        let heap = stages.map(|sample| sample.heap);
        let rss = stages.map(|sample| sample.rss);
        println!(
            "capacity_memory stages=baseline,ready,held,sampled_peak,settled heap_bytes={heap:?} rss_kib={rss:?} longest_owned_us={}",
            self.hold_max.as_micros()
        );
        println!(
            "capacity_work canonical_bytes={} source_decoded_buffers={} resolver_sql={} resolver_body_bytes={} resolver_rust_hashes={} resolver_pg_hashes={}",
            self.canonical_bytes,
            self.source.decoded_buffer_bytes,
            self.resolver_calls,
            self.resolver.bytes,
            self.resolver.rust_hashes,
            self.resolver.pg_hashes,
        );
        println!(
            "capacity_io order=heap_read,heap_hit,index_read,index_hit,toast_read,toast_hit,toast_index_read,toast_index_hit source={:?} resolver={:?}",
            self.source_io, self.resolver_io
        );
    }
}
