//! Optional isolated-process sample: RSS_PROJECTION_SPACE=page_size,payload_bytes.
use super::*;
use std::{collections::HashSet, sync::atomic::AtomicUsize};

struct FilterAll;
impl PgEffect for FilterAll {
    async fn apply(
        &self,
        _: &mut PgTransaction<'_>,
        _: &ProjectionScope,
        _: &Event,
    ) -> Result<PgEffectOutcome, PgOperationError> {
        Ok(PgEffectOutcome::Filtered)
    }
}

// SQLx uses named statements and a single Execute per Bind. Count the actual
// Bind frames (including framing) for provider management on this connection.
fn bind_meter(bytes: Arc<AtomicUsize>) -> impl FnMut(&[u8]) {
    let mut management = HashSet::<Vec<u8>>::new();
    move |frame| {
        let mut fields = frame[5..].split(|&b| b == 0);
        let Some(first) = fields.next() else { return };
        let Some(second) = fields.next() else { return };
        match frame[0] {
            b'P' => {
                let counted = [
                    b"SELECT rss_projection.lock_".as_slice(),
                    b"SELECT rss_projection.finish_",
                    b"SELECT position,replay",
                ]
                .iter()
                .any(|prefix| second.starts_with(prefix));
                if counted {
                    management.insert(first.to_vec());
                } else {
                    management.remove(first);
                }
            }
            b'B' if management.contains(second) => {
                bytes.fetch_add(frame.len(), Ordering::Relaxed);
            }
            _ => {}
        }
    }
}

fn resident_kib() -> anyhow::Result<u64> {
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()?;
    anyhow::ensure!(output.status.success(), "ps could not sample this process");
    Ok(std::str::from_utf8(&output.stdout)?.trim().parse()?)
}

pub(super) async fn measure(
    fixture: &testkit::PgTlsFixture,
    owner: &PgPool,
    control: &Control<'_, Clock>,
    shape: &str,
) -> anyhow::Result<()> {
    let (n, size) = shape
        .split_once(',')
        .ok_or_else(|| anyhow::anyhow!("expected count,bytes"))?;
    let n = n.parse::<u32>()?;
    BatchLimit::new(n)?;
    let size = size.parse::<usize>()?;
    anyhow::ensure!(size <= 1_048_576);
    let bytes = Arc::new(AtomicUsize::new(0));
    let count = bytes.clone();
    let proxy = Proxy::observe(fixture, move || bind_meter(count.clone())).await?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(
            PgConnectOptions::new()
                .host("127.0.0.1")
                .port(proxy.port)
                .database(&fixture.params().database)
                .username("projection_runtime")
                .password("fixture-only")
                .ssl_mode(PgSslMode::Disable),
        )
        .await?;
    let store = PgStore::new(pool.clone(), control).await?;
    let s = scope("space-sample", TENANT)?;
    store
        .initialize(
            &s,
            &DEFINITION,
            GenerationStart::beginning(),
            ReplayBound::Live,
            control,
        )
        .await?;
    let exec = store.projection(store.takeover(&s, &DEFINITION, control).await?, FilterAll)?;
    let events = (0..n)
        .map(|i| {
            Event::new(
                s.source().clone(),
                Position::new(u64::from(i))?,
                format!("fact-{i:04}"),
                vec![17; size],
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let before_spill = flushed_temp_bytes(&pool, owner).await?;
    sqlx::raw_sql("BEGIN; SET LOCAL work_mem='64kB'; SELECT sum(i) FROM (SELECT i FROM generate_series(1,32768) i ORDER BY i DESC) ordered; COMMIT").execute(&pool).await?;
    let temp_before = flushed_temp_bytes(&pool, owner).await?;
    anyhow::ensure!(
        temp_before > before_spill,
        "observer must see the calibration spill"
    );
    let initial = resident_kib()?;
    let stop = CancellationToken::new();
    let done = stop.clone().drop_guard();
    let sample = std::thread::spawn(move || -> anyhow::Result<u64> {
        let mut peak = initial;
        loop {
            peak = peak.max(resident_kib()?);
            if stop.is_cancelled() {
                return Ok(peak);
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    });
    let result = exec.execute_batch(None, events, control).await;
    drop(done);
    let peak = sample
        .join()
        .map_err(|_| anyhow::anyhow!("RSS sampler failed"))??;
    assert_eq!(result?, vec![ApplyOutcome::Filtered; n as usize]);
    let temp_after = flushed_temp_bytes(&pool, owner).await?;
    assert_eq!(store.close(control).await, CloseOutcome::Drained);
    let bind = bytes.load(Ordering::Relaxed);
    anyhow::ensure!(bind > 0);
    println!(
        "projection_space events={n} payload_bytes={size} initial_kib={initial} peak_delta_kib={} management_bind_bytes={bind} pg_temp_bytes={}",
        peak - initial,
        temp_after - temp_before
    );
    Ok(())
}

async fn flushed_temp_bytes(runtime: &PgPool, observer: &PgPool) -> anyhow::Result<i64> {
    // The measured pool has exactly one connection. Publish its transaction's
    // pending database counters before opening the observer's statement snapshot.
    sqlx::query("SELECT pg_stat_force_next_flush()")
        .execute(runtime)
        .await?;
    Ok(sqlx::query_scalar(
        "SELECT temp_bytes FROM pg_stat_database WHERE datname=current_database()",
    )
    .fetch_one(observer)
    .await?)
}
