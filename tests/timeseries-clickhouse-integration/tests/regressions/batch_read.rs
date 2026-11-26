use super::*;

fn window(lo: i64, hi: i64) -> Result<Interval, Error> {
    Interval::new(Timestamp::new(lo)?, Timestamp::new(hi)?)
}

fn aggregate(
    spec: &SummarySpec,
    range: Interval,
    points: u32,
    op: AggregateOp,
) -> anyhow::Result<Authorized<AggregateQuery>> {
    Ok(Authorized::<AggregateQuery>::verify(
        &authority(TENANT)?,
        AggregateQuery::new(
            spec.clone(),
            range,
            QueryBudget {
                max_points: NonZeroU32::new(points).ok_or(Error::Invariant)?,
                max_series: NonZeroU32::MIN,
            },
            op,
        )?,
    )?)
}

async fn cache(f: &Fixture, spec: &SummarySpec, lo: i64, hi: i64) -> anyhow::Result<()> {
    assert!(matches!(
        f.maintain(
            &format!("cache-{}-{lo}-{hi}", spec.resolution_micros()),
            MaintenanceAction::Recompute {
                spec: spec.clone(),
                window: window(lo, hi)?
            }
        )
        .await?,
        MaintenanceProgress::Complete { .. }
    ));
    Ok(())
}

fn oracle(q: &AggregateQuery, samples: &[Sample]) -> anyhow::Result<serde_json::Value> {
    let mut buckets = Vec::new();
    let range = q.query().window();
    let mut at = range.start();
    while at < range.end() {
        let w = Interval::new(at, q.spec().bucket(at)?.end().min(range.end()))?;
        let mut rows = Vec::new();
        if let CoveragePolicy::HoldLast(t) = q.coverage()
            && let Some(p) = samples.iter().rev().find(|p| p.input().observed_at < at)
            && at.micros().abs_diff(p.input().observed_at.micros()) <= t.get()
        {
            rows.push(p.clone());
        }
        rows.extend(
            samples
                .iter()
                .filter(|s| at <= s.input().observed_at && s.input().observed_at < w.end())
                .cloned(),
        );
        buckets.push(Summary::compute(q.spec(), w, &rows, 512)?.project(q.operation())?);
        at = w.end();
    }
    Ok(serde_json::to_value(buckets)?)
}

struct Measure<'a> {
    f: &'a Fixture,
    proxy: &'a transport::Proxy,
    store: &'a OwnedStore,
}

impl Measure<'_> {
    async fn page(
        &self,
        label: &str,
        q: &Authorized<AggregateQuery>,
        samples: &[Sample],
        refreshed: Option<i64>,
        counts: (usize, usize),
    ) -> anyhow::Result<()> {
        let expected = oracle(q.request(), samples)?;
        self.store.aggregate(q, None, deadline()?).await?;
        self.proxy.take_page_reads().await;
        let mut pages = Vec::new();
        for _ in 0..5 {
            let before = self.proxy.wire_bytes();
            let start = Timer.now();
            let page = self.store.aggregate(q, None, deadline()?).await?;
            let elapsed = (Timer.now() - start).as_micros();
            let transferred = self.proxy.wire_bytes() - before;
            assert_eq!(serde_json::to_value(page.buckets)?, expected);
            assert!(page.next.is_none() && page.availability.excluded.is_empty());
            assert_eq!(page.refreshed_through.map(Timestamp::micros), refreshed);
            let reads = self.proxy.take_page_reads().await;
            let summary = reads.iter().filter(|(_, summary)| *summary).count();
            assert_eq!(
                (summary, reads.len() - summary),
                counts,
                "{label} summary/raw requests"
            );
            pages.push((reads, transferred, elapsed));
        }
        let ids: Vec<_> = pages
            .iter()
            .flat_map(|(reads, _, _)| reads.iter())
            .map(|(id, _)| {
                anyhow::ensure!(
                    id.len() == 36 && id.bytes().all(|b| b == b'-' || b.is_ascii_hexdigit()),
                    "fixture query id"
                );
                Ok(format!("'{id}'"))
            })
            .collect::<anyhow::Result<_>>()?;
        let rows = self.f.ch.sql(&format!("SYSTEM FLUSH LOGS; SELECT query_id,read_rows FROM system.query_log WHERE is_initial_query AND type='QueryFinish' AND query_id IN ({}) FORMAT TabSeparated",ids.join(","))).await?;
        let scanned: std::collections::HashMap<_, _> = rows
            .lines()
            .map(|line| {
                let (id, n) = line.split_once('\t').ok_or(Error::Invariant)?;
                Ok((id, n.parse::<u64>()?))
            })
            .collect::<anyhow::Result<_>>()?;
        for (reads, bytes, micros) in &pages {
            let n = reads
                .iter()
                .map(|(id, _)| scanned.get(id.as_str()).copied().ok_or(Error::Invariant))
                .sum::<Result<u64, _>>()?;
            eprintln!(
                "ch-page {label} summary={} raw={} scan_rows={n} http_bytes={bytes} latency_us={micros}",
                counts.0, counts.1
            );
        }
        let mut times: Vec<_> = pages.iter().map(|p| p.2).collect();
        times.sort_unstable();
        eprintln!("ch-page {label} median_us={} p95_us={}", times[2], times[4]);
        Ok(())
    }
}

#[tokio::test]
async fn page_io_matches_raw_mixed_full_and_fragmented_coverage() -> anyhow::Result<()> {
    let f = Fixture::new("ch-page-groups").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let samples = (0..128)
        .map(|n| sample(&d, &format!("p{n}"), n * 10 + 1, n as u64 + 1))
        .collect::<anyhow::Result<Vec<_>>>()?;
    for (i, part) in samples.chunks(32).enumerate() {
        confirmed(f.write(&batch(&format!("seed{i}"), part.to_vec())?).await?)?;
    }
    let mut caps = limits()?;
    caps.max_points = NonZeroU32::new(256).ok_or(Error::Invariant)?;
    let proxy = transport::Proxy::new(&f.ch).await?;
    let store = proxy
        .store_with_limits(f.pool.clone(), caps.clone())
        .await?;
    let measure = Measure {
        f: &f,
        proxy: &proxy,
        store: &store,
    };
    let spec = |step| {
        SummarySpec::new(
            samples[0].input().stream.clone(),
            samples[0].input().series.clone(),
            NonZeroU64::new(step).ok_or(Error::Invariant)?,
            CoveragePolicy::ObservedOnly,
            None,
        )
    };
    let fine = spec(10)?;
    let all = aggregate(&fine, window(0, 1280)?, 128, AggregateOp::Sum)?;
    measure.page("miss", &all, &samples, None, (0, 1)).await?;
    caps.max_bytes = NonZeroU32::new(48 * 1024).ok_or(Error::Invariant)?;
    let bounded = proxy.store_with_limits(f.pool.clone(), caps).await?;
    let before = proxy.requests().await.len();
    let split = bounded.aggregate(&all, None, deadline()?).await?;
    let requests = proxy.requests().await.len() - before;
    eprintln!("ch-page byte-limited raw requests={requests}");
    assert!(
        (2..=16).contains(&requests),
        "byte-limited raw requests: {requests}"
    );
    assert_eq!(
        serde_json::to_value(split.buckets)?,
        oracle(all.request(), &samples)?
    );
    // Populate separated islands, keeping a raw gap between them.
    cache(&f, &fine, 0, 160).await?;
    cache(&f, &fine, 320, 480).await?;
    measure
        .page("mixed", &all, &samples, Some(160), (1, 2))
        .await?;
    for start in (160..1280).step_by(160).filter(|&n| n != 320) {
        cache(&f, &fine, start, start + 160).await?;
    }
    measure
        .page("full", &all, &samples, Some(1280), (1, 0))
        .await?;
    let coarse = aggregate(&spec(20)?, window(0, 1280)?, 64, AggregateOp::Sum)?;
    measure
        .page("fragmented", &coarse, &samples, Some(1280), (1, 0))
        .await?;
    // A continuation starts at the first unpaid bucket.
    let paged = aggregate(&fine, window(0, 1280)?, 47, AggregateOp::Sum)?;
    let mut cursor = None;
    let mut decoded = Vec::new();
    loop {
        let page = store
            .aggregate(&paged, cursor.as_ref(), deadline()?)
            .await?;
        decoded.extend(page.buckets);
        cursor = page.next;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(
        serde_json::to_value(decoded)?,
        oracle(all.request(), &samples)?
    );
    // Both fine objects are required to return this single coarse bucket. Hold
    // their response past half of the caller's deadline and verify no retry.
    let one = aggregate(&spec(20)?, window(0, 20)?, 1, AggregateOp::Sum)?;
    let before = proxy.requests().await.len();
    let cutoff = Deadline::from_timeout(&Timer, Duration::from_secs(2))?;
    let delayed =
        pages::during_select_mode(&proxy, 6, store.aggregate(&one, None, cutoff), async {
            tokio::time::sleep(Duration::from_millis(1200)).await;
            Ok(())
        })
        .await??;
    assert_eq!(proxy.requests().await.len() - before, 1);
    assert_eq!(
        serde_json::to_value(delayed.buckets)?,
        oracle(one.request(), &samples)?
    );
    // A stricter installation-level SQL parser cap may still require narrower groups.
    f.ch.sql("ALTER USER ch_reader SETTINGS max_query_size=3072")
        .await?;
    let before = proxy.requests().await.len();
    let narrow = store.aggregate(&all, None, deadline()?).await?;
    let requests = proxy.requests().await.len() - before;
    eprintln!("ch-page parser-limited summary requests={requests}");
    assert!(
        (2..=10).contains(&requests),
        "parser-limited requests: {requests}"
    );
    assert_eq!(
        serde_json::to_value(narrow.buckets)?,
        oracle(all.request(), &samples)?
    );
    Ok(())
}

async fn sparse_state_reads(
    f: &Fixture,
    proxy: &transport::Proxy,
    store: &OwnedStore,
    samples: &[Sample],
) -> anyhow::Result<()> {
    const MINUTE: i64 = 60_000_000;
    let end = 12 * MINUTE;
    let first = samples.first().ok_or(Error::Invariant)?.input();
    let spec = SummarySpec::new(
        first.stream.clone(),
        first.series.clone(),
        NonZeroU64::new(MINUTE as u64).ok_or(Error::Invariant)?,
        CoveragePolicy::HoldLast(NonZeroU64::new(30).ok_or(Error::Invariant)?),
        None,
    )?;
    let all = aggregate(&spec, window(0, end)?, 96, AggregateOp::Timeline)?;
    let expected = oracle(all.request(), samples)?;
    // Keep all over-wide SELECTs slow for each entire call. The mixed page starts
    // in raw and ends in cache; neither a later bucket nor a new path can renew
    // a speculative allowance that timed out earlier in the page.
    for (label, fill) in [
        ("raw", None),
        ("mixed", Some((6 * MINUTE, end))),
        ("cached", Some((0, 6 * MINUTE))),
    ] {
        if let Some((lo, hi)) = fill {
            cache(f, &spec, lo, hi).await?;
        }
        let before = proxy.requests().await.len();
        let page = store.aggregate(&all, None, deadline()?).await?;
        let requests = proxy.requests().await.len() - before;
        eprintln!("ch-page sparse minute {label} requests={requests}");
        assert!(
            requests <= 6,
            "twelve sparse minute buckets should batch: {requests}"
        );
        assert_eq!(serde_json::to_value(page.buckets)?, expected);
        proxy.delay_wide_reads(MINUTE as u64);
        let cutoff = Deadline::from_timeout(&Timer, Duration::from_secs(2))?;
        let recovered = store.aggregate(&all, None, cutoff).await;
        proxy.arm(0);
        assert_eq!(
            proxy.slow_reads(),
            1,
            "{label}: only one timed-out optional read per page"
        );
        let recovered = recovered?;
        assert!(recovered.next.is_none());
        assert_eq!(serde_json::to_value(recovered.buckets)?, expected);
    }
    Ok(())
}

#[tokio::test]
async fn predecessor_survives_empty_buckets_and_unused_corruption_waits_for_its_page()
-> anyhow::Result<()> {
    let f = Fixture::new("ch-batched-prior").await?;
    let mut definition = definition(TENANT)?.spec().clone();
    definition.metric = Metric::Bool;
    let d = Definition::new(definition)?;
    f.register(&d).await?;
    let stream = Stream::new(d.spec().scope.clone(), id("sensor")?, id("generation")?);
    let series = Series::new(d, id("device")?, id("resource")?, Default::default())?;
    let samples = [
        (15, false),
        (22, true),
        (63, false),
        (81, true),
        (300_000_001, false),
        (540_000_001, true),
    ]
    .iter()
    .map(|&(at, value)| {
        Ok(Sample::new(SampleInput {
            stream: stream.clone(),
            series: series.clone(),
            id: id(&format!("s{at}"))?,
            sequence: at as u64,
            observed_at: Timestamp::new(at)?,
            interval: None,
            reading: Reading::Valid(Value::Bool(value)),
        })?)
    })
    .collect::<anyhow::Result<Vec<_>>>()?;
    confirmed(f.write(&batch("bool", samples.clone())?).await?)?;
    let spec = SummarySpec::new(
        stream,
        series,
        NonZeroU64::new(20).ok_or(Error::Invariant)?,
        CoveragePolicy::HoldLast(NonZeroU64::new(30).ok_or(Error::Invariant)?),
        None,
    )?;
    let range = window(20, 100)?;
    let all = aggregate(&spec, range, 64, AggregateOp::Timeline)?;
    let proxy = transport::Proxy::new(&f.ch).await?;
    let store = proxy.store(f.pool.clone()).await?;
    Measure {
        f: &f,
        proxy: &proxy,
        store: &store,
    }
    .page("prior", &all, &samples, None, (0, 2))
    .await?;
    assert!(matches!(
        store
            .aggregate(
                &aggregate(&spec, range, 1, AggregateOp::Timeline)?,
                None,
                deadline()?
            )
            .await,
        Err(Error::BudgetExceeded)
    ));
    sparse_state_reads(&f, &proxy, &store, &samples).await?;
    // The first Timeline bucket consumes all three points. A read containing
    // data from the next bucket would stall; the continuation must start at 40.
    let exact = aggregate(&spec, range, 3, AggregateOp::Timeline)?;
    for cached in [false, true] {
        let needle = if cached {
            cache(&f, &spec, 20, 100).await?;
            sqlx::query_scalar::<_, String>(
                "SELECT object_id::text FROM rss_ts_ch.summaries WHERE lo=40",
            )
            .fetch_one(&f.admin)
            .await?
        } else {
            "observed_at<80".to_owned()
        };
        proxy.hold_matching(needle).await;
        let cutoff = Deadline::from_timeout(&Timer, Duration::from_secs(2))?;
        let page = store.aggregate(&exact, None, cutoff).await?;
        assert!(
            proxy.matching_gate_unused(),
            "read beyond the first state bucket"
        );
        proxy.arm(0);
        assert_eq!(page.buckets.len(), 1);
        let next = page.next.ok_or(Error::Invariant)?;
        let second = store.aggregate(&exact, Some(&next), deadline()?).await?;
        assert_eq!(second.buckets[0].window.start().micros(), 40);
    }
    f.ch.sql("ALTER TABLE rss_ts_ch.summaries UPDATE digest=repeat('0',64) WHERE lo=80 SETTINGS mutations_sync=2").await?;
    let short = aggregate(&spec, range, 4, AggregateOp::Timeline)?;
    let first = store.aggregate(&short, None, deadline()?).await?;
    assert_eq!(first.buckets.len(), 1);
    assert!(first.next.is_some());
    assert!(matches!(
        store.aggregate(&all, None, deadline()?).await,
        Err(Error::Invariant)
    ));
    f.ch.sql("ALTER TABLE rss_ts_ch.summaries UPDATE payload=unhex('FF') WHERE lo=80 SETTINGS mutations_sync=2").await?;
    for cached in [true, false] {
        if !cached {
            sqlx::query("DELETE FROM rss_ts_ch.summaries")
                .execute(&f.admin)
                .await?;
            f.ch.sql("INSERT INTO rss_ts_ch.raw SELECT * REPLACE (unhex('FF') AS payload) FROM rss_ts_ch.raw FINAL WHERE observed_at=81").await?;
        }
        let mut page = store.aggregate(&short, None, deadline()?).await?;
        assert_eq!(page.buckets.len(), 1);
        loop {
            let next = page.next.ok_or(Error::Invariant)?;
            match store.aggregate(&short, Some(&next), deadline()?).await {
                Ok(p) => {
                    assert!(p.buckets.iter().all(|b| b.window.end().micros() <= 80));
                    page = p;
                }
                Err(e) => {
                    assert_eq!(e, Error::Unavailable);
                    break;
                }
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn bounded_groups_isolate_dense_buckets_and_release_a_cancelled_reader() -> anyhow::Result<()>
{
    let f = Fixture::new("ch-page-bounds").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let samples = (0..18)
        .map(|n| sample(&d, &format!("s{n}"), n + 2, n as u64))
        .collect::<anyhow::Result<Vec<_>>>()?;
    confirmed(f.write(&batch("many", samples.clone())?).await?)?;
    let spec = SummarySpec::new(
        samples[0].input().stream.clone(),
        samples[0].input().series.clone(),
        NonZeroU64::new(10).ok_or(Error::Invariant)?,
        CoveragePolicy::ObservedOnly,
        None,
    )?;
    let all = aggregate(&spec, window(0, 40)?, 4, AggregateOp::Sum)?;
    let proxy = transport::Proxy::new(&f.ch).await?;
    let mut caps = limits()?;
    caps.max_points = NonZeroU32::new(10).ok_or(Error::Invariant)?;
    caps.operation_permits = NonZeroU32::MIN;
    caps.max_waiters = 0;
    let store = proxy
        .store_with_limits(f.pool.clone(), caps.clone())
        .await?;
    let expected = oracle(all.request(), &samples)?;
    let page = store.aggregate(&all, None, deadline()?).await?;
    assert_eq!(serde_json::to_value(page.buckets)?, expected);
    // Isolate a true per-bucket failure from an over-budget merged scan.
    caps.max_points = NonZeroU32::new(7).ok_or(Error::Invariant)?;
    let small = proxy
        .store_with_limits(f.pool.clone(), caps.clone())
        .await?;
    assert!(matches!(
        small.aggregate(&all, None, deadline()?).await,
        Err(Error::BudgetExceeded)
    ));
    cache(&f, &spec, 0, 40).await?;
    // Enough for each object and the projected page, too small for every summary together.
    let largest: i64 = sqlx::query_scalar("SELECT max(payload_bytes) FROM rss_ts_ch.summaries")
        .fetch_one(&f.admin)
        .await?;
    caps.max_bytes = NonZeroU32::new(u32::try_from(largest)? + 320).ok_or(Error::Invariant)?;
    let tight = proxy.store_with_limits(f.pool.clone(), caps).await?;
    let page = tight.aggregate(&all, None, deadline()?).await?;
    assert_eq!(serde_json::to_value(page.buckets)?, expected);
    proxy.take_page_reads().await;
    proxy.arm(5);
    let mut read = Box::pin(tight.aggregate(&all, None, deadline()?));
    tokio::select! { result=&mut read=>anyhow::bail!("read completed before gate: {result:?}"), held=proxy.wait_held()=>held?, }
    drop(read);
    // The first SELECT reached CH; the caller must release the sole permit on drop.
    assert_eq!(proxy.take_page_reads().await.len(), 1);
    let resumed = tight.aggregate(&all, None, deadline()?).await?;
    assert_eq!(serde_json::to_value(resumed.buckets)?, expected);
    let reads = proxy.take_page_reads().await;
    assert!(reads.len() > 1 && reads.iter().all(|(_, summary)| *summary));
    proxy.release();
    assert!(proxy.take_page_reads().await.is_empty());
    // A second FINAL row with the same ID and a different sorting key survives deduplication.
    f.ch.sql("INSERT INTO rss_ts_ch.summaries SELECT * REPLACE (lo+1 AS lo) FROM rss_ts_ch.summaries FINAL WHERE lo=0").await?;
    assert!(matches!(
        store.aggregate(&all, None, deadline()?).await,
        Err(Error::Invariant)
    ));
    f.ch.sql("ALTER TABLE rss_ts_ch.summaries DELETE WHERE lo IN (0,1) SETTINGS mutations_sync=2")
        .await?;
    assert!(matches!(
        store.aggregate(&all, None, deadline()?).await,
        Err(Error::Invariant)
    ));
    Ok(())
}
