//! Fixed release-mode workload. Run with the testkit launcher, --ignored and --nocapture.
use super::*;
use rss_timeseries_clickhouse::measurement::{Counters, measure};
use rustix::time::{ClockId, clock_gettime};

fn thread_cpu() -> Duration {
    let t = clock_gettime(ClockId::ThreadCPUTime);
    Duration::new(t.tv_sec as u64, t.tv_nsec as u32)
}

async fn frontiers(
    f: &Fixture,
    d: &Definition,
    related: i32,
    noise: i32,
    hit: bool,
) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM rss_ts_ch.fences")
        .execute(&f.admin)
        .await?;
    let mut relevant = query(d, QueryMode::History, 1)?.selection().clone();
    let mut other = Selection::Resource {
        scope: d.spec().scope.clone(),
        subject: id("other")?,
        resource: id("resource")?,
        keys: Default::default(),
    };
    if std::env::var_os("RSS_CH_EXACT_COST").is_some() {
        let sample = sample(d, "selector", 1000, 1)?;
        let stream = sample.input().stream.clone();
        relevant = Selection::Exact {
            stream: stream.clone(),
            series: sample.input().series.clone(),
        };
        other = Selection::Exact {
            stream,
            series: Series::new(d.clone(), id("other")?, id("resource")?, Default::default())?,
        };
    }
    for (name, selection, count) in [("related", relevant, related), ("noise", other, noise)] {
        sqlx::query(
            "INSERT INTO rss_ts_ch.fences(tenant_id,namespace,id,kind,selection,lo,hi)
            SELECT $1::text::uuid,'metrics',$2::text||n,'delete',$3::text::jsonb,2*n,2*n+CASE WHEN $2::text='noise' THEN 1001 ELSE 1 END
            FROM generate_series(0,$4::int-1) n",
        )
        .bind(TENANT)
        .bind(name)
        .bind(serde_json::to_string(&selection)?)
        .bind(count)
        .execute(&f.admin)
        .await?;
    }
    if hit {
        sqlx::query("UPDATE rss_ts_ch.fences SET hi=1001 WHERE id='related0'")
            .execute(&f.admin)
            .await?;
    }
    Ok(())
}

fn print_write(name: &str, related: i32, noise: i32, c: Counters) {
    println!(
        "control-write case={name} related={related} noise={noise} rows={} field_bytes={} bind_field_bytes={} build_cpu_ns={} match_cpu_ns={} locked_us={}",
        c.fence_rows,
        c.fence_bytes,
        c.fence_input_bytes,
        c.build_cpu.as_nanos(),
        c.match_cpu.as_nanos(),
        c.locked.as_micros()
    );
}

#[tokio::test]
#[ignore = "isolated release-mode PostgreSQL + ClickHouse control workload"]
async fn fixed_admission() -> anyhow::Result<()> {
    let f = Fixture::new("ch-admit-cost").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let replay = (0..48)
        .map(|i| sample(&d, &format!("old-{i}"), 1000, 1))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let seed = batch("seed", replay.clone())?;
    confirmed(f.write(&seed).await?)?;
    for (related, noise) in [(0, 0), (1, 0), (1, 8), (1, 64), (8, 0), (64, 0)] {
        frontiers(&f, &d, related, noise, false).await?;
        for case in ["new", "gaps", "mixed", "replay", "receipt", "single"] {
            let tag = format!("{case}-{related}-{noise}");
            let new = if case == "single" { 1 } else { 48 };
            let mut items = if case == "mixed" || case == "replay" {
                replay.clone()
            } else {
                Vec::new()
            };
            if case != "replay" {
                for i in 0..new {
                    let at = if case == "gaps" {
                        i64::from(2 * i + 1)
                    } else {
                        1000
                    };
                    items.push(sample(&d, &format!("{tag}-{i}"), at, 1)?);
                }
            }
            let b = if case == "receipt" {
                seed.clone()
            } else {
                batch(&tag, items)?
            };
            let (result, c) = measure(thread_cpu, f.write(&b)).await;
            let receipt = confirmed(result?)?;
            assert_eq!(
                receipt.new_samples(),
                match case {
                    "replay" => 0,
                    "receipt" => 48,
                    _ => new,
                }
            );
            print_write(case, related, noise, c);
        }
        if related > 0 {
            frontiers(&f, &d, related, noise, true).await?;
            let b = batch("early", vec![sample(&d, "blocked", 1000, 1)?])?;
            let (result, c) = measure(thread_cpu, f.write(&b)).await;
            assert!(matches!(
                result.err().and_then(|e| e.downcast::<Error>().ok()),
                Some(Error::HistoryExpired)
            ));
            print_write("early", related, noise, c);
        }
    }
    frontiers(&f, &d, 1, 64, false).await?;
    let samples = (0..Batch::MAX_SAMPLES)
        .map(|n| sample(&d, &format!("capacity-{n}"), 1000 + n as i64, 1))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let b = batch("capacity", samples)?;
    let mut caps = limits()?;
    // The proof SELECT returns two SHA-256 hex strings and selector columns per row.
    caps.max_bytes = NonZeroU32::new(u32::try_from(b.encoded_len())?).ok_or(Error::Invariant)?;
    let store = Fixture::connect_options(
        &f.ch,
        f.pool.clone(),
        TENANT,
        "ch_reader",
        "ch_writer",
        caps,
    )
    .await?;
    let req = Authorized::<Batch>::verify(&authority(TENANT)?, b.clone())?;
    let (result, c) = measure(thread_cpu, store.write(&req, deadline()?)).await;
    assert_eq!(
        confirmed(result?)?.new_samples() as usize,
        Batch::MAX_SAMPLES
    );
    assert!(c.fence_rows == 0);
    print_write("max-samples", 1, 64, c);
    dense_fences(&f, &d, &store).await?;
    single_requested_key(&f, &d).await?;
    same_resource_cost(&f, &d).await?;
    Ok(())
}

// Two opposite ends of a batch span can intersect many fences with no requested keys.
async fn same_resource_cost(f: &Fixture, d: &Definition) -> anyhow::Result<()> {
    let exact = std::env::var_os("RSS_CH_EXACT_COST").is_some();
    let mut def = d.spec().clone();
    def.key = id("wide")?;
    def.dimensions.allowed = (0..64)
        .map(|i| id(&format!("dim-{i}")))
        .collect::<anyhow::Result<_>>()?;
    def.dimensions.max_count = 64;
    let d = Definition::new(def)?;
    f.register(&d).await?;
    let mut input = sample(&d, "wide", 1, 1)?.input().clone();
    let dimensions = d
        .spec()
        .dimensions
        .allowed
        .iter()
        .cloned()
        .map(|k| (k, id("value")))
        .map(|(k, v)| Ok((k, v?)))
        .collect::<anyhow::Result<_>>()?;
    input.series = Series::new(d, id("device")?, id("resource")?, dimensions)?;
    let (name, selection, count, samples) = if exact {
        (
            "dim64-gaps",
            Selection::Exact {
                stream: input.stream.clone(),
                series: input.series.clone(),
            },
            8,
            48,
        )
    } else {
        let keys = (0..64)
            .map(|i| id(&format!("unused-{i}")))
            .collect::<anyhow::Result<_>>()?;
        (
            "wide-keys",
            Selection::Resource {
                scope: input.stream.scope().clone(),
                subject: id("device")?,
                resource: id("resource")?,
                keys,
            },
            64,
            2,
        )
    };
    sqlx::query("DELETE FROM rss_ts_ch.fences")
        .execute(&f.admin)
        .await?;
    sqlx::query("INSERT INTO rss_ts_ch.fences(tenant_id,namespace,id,kind,selection,lo,hi)
        SELECT $1::text::uuid,'metrics','wide-'||n,'delete',$2::text::jsonb,2*n,2*n+1 FROM generate_series(0,$3::int-1) n")
        .bind(TENANT).bind(serde_json::to_string(&selection)?).bind(count).execute(&f.admin).await?;
    let mut points = Vec::new();
    for i in 0..samples {
        input.id = id(&format!("wide-{i}"))?;
        input.observed_at = Timestamp::new(if exact { 2 * i + 1 } else { i * 130 })?;
        points.push(Sample::new(input.clone())?);
    }
    let b = batch(name, points)?;
    let (result, c) = measure(thread_cpu, f.write(&b)).await;
    assert_eq!(confirmed(result?)?.new_samples(), samples as u32);
    print_write(
        name,
        if exact { count } else { 0 },
        if exact { 0 } else { count },
        c,
    );
    Ok(())
}

async fn calls(pool: &PgPool) -> anyhow::Result<(i64, i64)> {
    let mut leases = Vec::new();
    let mut total = (0, 0);
    for _ in 0..pool.options().get_max_connections() {
        let mut c = pool.acquire().await?;
        let (all, updates):(i64,i64)=sqlx::query_as(
            "SELECT coalesce(sum(custom_plans+generic_plans),0)::bigint,
              coalesce(sum(custom_plans+generic_plans) FILTER(WHERE statement LIKE 'UPDATE rss_ts_ch.summaries%'),0)::bigint
             FROM pg_prepared_statements WHERE statement NOT LIKE '%pg_prepared_statements%'"
        ).fetch_one(&mut *c).await?;
        total.0 += all;
        total.1 += updates;
        leases.push(c);
    }
    Ok(total)
}

async fn measured_step(
    f: &Fixture,
    name: &str,
    action: MaintenanceAction,
    hits: usize,
    noise: usize,
) -> anyhow::Result<()> {
    let before = calls(&f.pool).await?;
    let (result, c) = measure(thread_cpu, f.maintain(name, action)).await;
    assert!(matches!(result?, MaintenanceProgress::Complete { .. }));
    let after = calls(&f.pool).await?;
    assert_eq!((c.candidates, c.updated), (hits, hits as u64));
    println!(
        "control-maint case={name} hits={hits} noise={noise} candidates={} changed={} sql={} summary_updates={} transaction_us={} locked_us={}",
        c.candidates,
        c.updated,
        after.0 - before.0,
        after.1 - before.1,
        c.transaction.as_micros(),
        c.locked.as_micros()
    );
    Ok(())
}

#[tokio::test]
#[ignore = "isolated release-mode PostgreSQL + ClickHouse control workload"]
async fn fixed_invalidation() -> anyhow::Result<()> {
    for noise in [0, 8] {
        invalidation_load(noise).await?;
    }
    Ok(())
}

async fn invalidation_load(noise: usize) -> anyhow::Result<()> {
    let f = Fixture::new(&format!("ch-maint-cost-{noise}")).await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let b = batch("seed", vec![sample(&d, "seed", 1, 1)?])?;
    confirmed(f.write(&b).await?)?;
    let spec = SummarySpec::new(
        b.stream().clone(),
        b.samples()[0].input().series.clone(),
        NonZeroU64::new(10).ok_or(Error::Invariant)?,
        CoveragePolicy::ObservedOnly,
        None,
    )?;
    let window = |lo, hi| Interval::new(Timestamp::new(lo)?, Timestamp::new(hi)?);
    let cache = MaintenanceAction::Recompute {
        spec: spec.clone(),
        window: window(0, 80)?,
    };
    if noise > 0 {
        let other = Series::new(d.clone(), id("other")?, id("resource")?, Default::default())?;
        let spec = SummarySpec::new(
            b.stream().clone(),
            other,
            NonZeroU64::new(10).ok_or(Error::Invariant)?,
            CoveragePolicy::ObservedOnly,
            None,
        )?;
        f.maintain(
            "noise",
            MaintenanceAction::Recompute {
                spec,
                window: window(0, 80)?,
            },
        )
        .await?;
    }
    f.maintain("plan-clean", cache.clone()).await?;
    explain_maintenance(&f, &spec, noise).await?;
    for hits in [0, 1, 8] {
        let tag = format!("{noise}-{hits}");
        f.maintain(&format!("clean-{tag}"), cache.clone()).await?;
        let selected = if hits == 0 {
            window(100, 110)?
        } else {
            window(0, hits as i64 * 10)?
        };
        let deletion = format!("delete-{tag}");
        measured_step(
            &f,
            &deletion,
            MaintenanceAction::Delete {
                selection: spec.selection(),
                window: selected,
                restore_until: Timestamp::new(i64::MAX)?,
            },
            hits,
            noise,
        )
        .await?;
        f.maintain(&format!("masked-{tag}"), cache.clone()).await?;
        measured_step(
            &f,
            &format!("restore-{tag}"),
            MaintenanceAction::Restore {
                selection: spec.selection(),
                window: selected,
                deletion_fence: id(&deletion)?,
            },
            hits,
            noise,
        )
        .await?;
    }
    Ok(())
}

async fn explain_maintenance(f: &Fixture, spec: &SummarySpec, noise: usize) -> anyhow::Result<()> {
    let mut tx = f.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(TENANT)
        .execute(&mut *tx)
        .await?;
    let plan = concat!(
        "EXPLAIN (ANALYZE, BUFFERS) ",
        include_str!("../../../../crates/timeseries-clickhouse/src/invalidation_targets.sql")
    );
    let lines: Vec<String> = sqlx::query_scalar(plan)
        .bind(TENANT)
        .bind("metrics")
        .bind(0i64)
        .bind(101i64)
        .bind(serde_json::to_string(&spec.selection())?)
        .bind(10i64)
        .fetch_all(&mut *tx)
        .await?;
    println!("maint-plan noise={noise} {}", lines.join("\n"));
    tx.rollback().await?;
    Ok(())
}

// The input is identical for both plans; only the 64 co-located selector matches change.
async fn dense_fences(f: &Fixture, d: &Definition, store: &OwnedStore) -> anyhow::Result<()> {
    frontiers(f, d, 64, 0, false).await?;
    sqlx::query("UPDATE rss_ts_ch.fences SET lo=0,hi=10000")
        .execute(&f.admin)
        .await?;
    let points = (0..Batch::MAX_SAMPLES)
        .map(|n| sample(d, &format!("dense-{n}"), 1000 + n as i64, 1))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let b = batch("dense-witness", points)?;
    let req = Authorized::<Batch>::verify(&authority(TENANT)?, b.clone())?;
    let (blocked, c) = measure(thread_cpu, store.write(&req, deadline()?)).await;
    assert_eq!(blocked.err(), Some(Error::HistoryExpired));
    assert_eq!(c.fence_rows, 1);
    print_write("dense-hit", 64, 0, c);
    explain_write(f, &b, "dense-hit").await?;
    let input = b.samples()[0].input();
    let different = Selection::Resource {
        scope: d.spec().scope.clone(),
        subject: input.series.subject().clone(),
        resource: input.series.resource().clone(),
        keys: [id("other-key")?].into(),
    };
    sqlx::query("UPDATE rss_ts_ch.fences SET selection=$1::text::jsonb")
        .bind(serde_json::to_string(&different)?)
        .execute(&f.admin)
        .await?;
    explain_write(f, &b, "dense-miss").await?;
    let (accepted, c) = measure(thread_cpu, store.write(&req, deadline()?)).await;
    assert_eq!(
        confirmed(accepted?)?.new_samples() as usize,
        Batch::MAX_SAMPLES
    );
    assert_eq!(c.fence_rows, 0);
    print_write("dense-miss", 0, 64, c);
    Ok(())
}
async fn single_requested_key(f: &Fixture, d: &Definition) -> anyhow::Result<()> {
    // All 64 fences overlap the same sample. Returning no witness is valid only
    // if none of their 64 keys match; admitting an empty intersection as a wildcard is wrong.
    let point = sample(d, "key-probe", 1000, 1)?;
    let input = point.input();
    let mut keys = (0..64)
        .map(|n| id(&format!("unrequested-{n}")))
        .collect::<anyhow::Result<std::collections::BTreeSet<_>>>()?;
    let pair = (
        input.series.subject().clone(),
        input.series.resource().clone(),
    );
    let selection = |keys| Selection::Resource {
        scope: d.spec().scope.clone(),
        subject: pair.0.clone(),
        resource: pair.1.clone(),
        keys,
    };
    let original = batch("key-probe", vec![point])?;
    let replace = "UPDATE rss_ts_ch.fences SET selection=$1::text::jsonb";
    sqlx::query(replace)
        .bind(serde_json::to_string(&selection(keys.clone()))?)
        .execute(&f.admin)
        .await?;
    explain_write(f, &original, "one-key-disjoint").await?;
    let (accepted, c) = measure(thread_cpu, f.write(&original)).await;
    assert_eq!(confirmed(accepted?)?.new_samples(), 1);
    assert_eq!(c.fence_rows, 0);
    print_write("one-key-disjoint", 0, 64, c);
    keys.pop_last();
    keys.insert(d.spec().key.clone());
    sqlx::query(replace)
        .bind(serde_json::to_string(&selection(keys))?)
        .execute(&f.admin)
        .await?;
    let matched = batch("key-hit", vec![sample(d, "key-hit", 1000, 1)?])?;
    explain_write(f, &matched, "one-key-present").await?;
    let req = Authorized::<Batch>::verify(&authority(TENANT)?, matched)?;
    let (rejected, c) = measure(thread_cpu, f.store.write(&req, deadline()?)).await;
    assert_eq!(rejected.err(), Some(Error::HistoryExpired));
    assert_eq!(c.fence_rows, 1);
    print_write("one-key-present", 64, 0, c);
    Ok(())
}
async fn explain_write(f: &Fixture, b: &Batch, label: &str) -> anyhow::Result<()> {
    use sqlx::Row;
    let mut tx = f.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(TENANT)
        .execute(&mut *tx)
        .await?;
    let plan = concat!(
        "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ",
        include_str!("../../../../crates/timeseries-clickhouse/src/write/blocked_sample.sql")
    );
    let count = b.samples().len();
    let row = sqlx::query(plan)
        .bind(TENANT)
        .bind("metrics")
        .bind(serde_json::to_string(b.stream())?)
        .bind(vec![serde_json::to_string(&b.samples()[0].input().series)?])
        .bind(vec![1i32; count])
        .bind((1000..1000 + i64::try_from(count)?).collect::<Vec<_>>())
        .bind((0..i32::try_from(count)?).collect::<Vec<_>>())
        .fetch_one(&mut *tx)
        .await?;
    let plan: serde_json::Value = serde_json::from_slice(
        row.try_get_raw(0)?
            .as_bytes()
            .map_err(anyhow::Error::from_boxed)?,
    )?;
    let work = maximum_node_work(&plan[0]["Plan"]);
    // Individual passes fit within the input populations. Expanding point ×
    // fence (262144) or every unrelated key for a single probe (4096) exceeds the bound.
    assert!(
        work <= (count as u64 + 64) * 3,
        "{label} node visited {work}"
    );
    println!(
        "dense-plan {label} samples={count} node_work={work} ms={} buffers={} plan={}",
        plan[0]["Execution Time"], plan[0]["Plan"]["Shared Hit Blocks"], plan
    );
    tx.rollback().await?;
    Ok(())
}
fn maximum_node_work(plan: &serde_json::Value) -> u64 {
    let value = |key: &str| plan[key].as_u64().unwrap_or_default();
    let work = value("Actual Loops")
        * (value("Actual Rows")
            + value("Rows Removed by Filter")
            + value("Rows Removed by Join Filter"));
    plan["Plans"]
        .as_array()
        .into_iter()
        .flatten()
        .map(maximum_node_work)
        .fold(work, u64::max)
}

/// Same visible samples and two buckets in every case. Each fence lands between observations.
#[tokio::test]
#[ignore = "isolated release-mode aggregation and paged maintenance comparison"]
async fn aggregate_boundaries() -> anyhow::Result<()> {
    let f = Fixture::new("ch-boundary-cost").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let seed = batch(
        "seed",
        (0..32)
            .map(|i| sample(&d, &format!("s{i}"), 2 * i + 1, i as u64))
            .collect::<anyhow::Result<Vec<_>>>()?,
    )?;
    confirmed(f.write(&seed).await?)?;
    let end = Timestamp::new(64)?;
    let window = Interval::new(Timestamp::new(0)?, end)?;
    let spec = SummarySpec::new(
        seed.stream().clone(),
        seed.samples()[0].input().series.clone(),
        NonZeroU64::new(32).ok_or(Error::Invariant)?,
        CoveragePolicy::ObservedOnly,
        None,
    )?;
    let q = Authorized::<AggregateQuery>::verify(
        &authority(TENANT)?,
        AggregateQuery::new(
            spec.clone(),
            window,
            QueryBudget {
                max_series: NonZeroU32::MIN,
                max_points: NonZeroU32::new(2).ok_or(Error::Invariant)?,
            },
            AggregateOp::Count,
        )?,
    )?;
    for (case, related, noise, overlap) in [
        ("empty", 0, 0, false),
        ("one", 1, 0, false),
        ("related", 16, 0, false),
        ("noise", 1, 16, false),
        ("overlap", 16, 0, true),
    ] {
        frontiers(&f, &d, related, noise, false).await?;
        if overlap {
            sqlx::query("UPDATE rss_ts_ch.fences SET lo=0,hi=1")
                .execute(&f.admin)
                .await?;
        }
        // This fixture installs frontiers directly. Advance the same namespace
        // revision as the public Delete/Restore paths before the next matched run.
        sqlx::query("UPDATE rss_ts_ch.namespaces SET revision=revision+1")
            .execute(&f.admin)
            .await?;
        // Force the raw path on the isolated fixture for the next matched run.
        sqlx::query("DELETE FROM rss_ts_ch.summaries")
            .execute(&f.admin)
            .await?;
        let (raw, online) = measure(thread_cpu, f.store.aggregate(&q, None, deadline()?)).await;
        let raw = raw?;
        assert!(raw.refreshed_through.is_none() && raw.next.is_none());
        let (done, maintenance) = measure(
            thread_cpu,
            f.maintain_rows(
                case,
                MaintenanceAction::Recompute {
                    spec: spec.clone(),
                    window,
                },
                1,
            ),
        )
        .await;
        assert!(matches!(done?, MaintenanceProgress::Complete { .. }));
        let cached = f.store.aggregate(&q, None, deadline()?).await?;
        assert_eq!(cached.refreshed_through, Some(end));
        assert_eq!(
            serde_json::to_value(&raw.buckets)?,
            serde_json::to_value(&cached.buckets)?
        );
        assert_eq!(raw.buckets.iter().map(|b| b.valid_samples).sum::<u64>(), 32);
        let digests: Vec<String> = sqlx::query_scalar("SELECT a.digest FROM rss_ts_ch.summaries s JOIN rss_ts_ch.attempts a ON a.id=s.object_id ORDER BY s.lo").fetch_all(&f.admin).await?;
        assert_eq!(digests.len(), 2);
        assert_eq!(maintenance.namespace_counts, 1);
        assert_eq!(maintenance.aggregate_fence_rows, related as usize);
        if related == 16 {
            assert!(online.boundary_checks < 32 * 16 && maintenance.boundary_checks < 32 * 16);
        }
        for (path, c) in [("raw", online), ("recompute", maintenance)] {
            println!(
                "fences case={case} path={path} loaded={} checks={} namespace_rows={} build_cpu_ns={} match_cpu_ns={} digests={digests:?}",
                c.aggregate_fence_rows,
                c.boundary_checks,
                c.namespace_fence_rows,
                c.build_cpu.as_nanos(),
                c.match_cpu.as_nanos()
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn interleaved_recompute_plans_share_their_actual_scan_windows() -> anyhow::Result<()> {
    let f = Fixture::new("ch-interleaved-plans").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let b = batch(
        "seed",
        [1, 3, 5, 33, 35, 37]
            .into_iter()
            .map(|at| sample(&d, &format!("s{at}"), at, 1))
            .collect::<anyhow::Result<_>>()?,
    )?;
    confirmed(f.write(&b).await?)?;
    let spec = SummarySpec::new(
        b.stream().clone(),
        b.samples()[0].input().series.clone(),
        NonZeroU64::new(32).ok_or(Error::Invariant)?,
        CoveragePolicy::ObservedOnly,
        None,
    )?;
    let window = |lo, hi| Interval::new(Timestamp::new(lo)?, Timestamp::new(hi)?);
    f.maintain(
        "cut",
        MaintenanceAction::Delete {
            selection: spec.selection(),
            window: window(13, 34)?,
            restore_until: Timestamp::new(i64::MAX)?,
        },
    )
    .await?;
    let mut plans = Vec::new();
    let mut expected = Vec::new();
    for (name, range) in [
        ("left", window(0, 32)?),
        ("right", window(32, 64)?),
        ("left-again", window(0, 32)?),
    ] {
        let q = Authorized::<AggregateQuery>::verify(
            &authority(TENANT)?,
            AggregateQuery::new(
                spec.clone(),
                range,
                QueryBudget {
                    max_points: NonZeroU32::MIN,
                    max_series: NonZeroU32::MIN,
                },
                AggregateOp::Count,
            )?,
        )?;
        let raw = f.store.aggregate(&q, None, deadline()?).await?;
        assert!(raw.refreshed_through.is_none());
        expected.push((q, serde_json::to_value(raw.buckets)?));
        let req = Authorized::<MaintenanceRequest>::verify(
            &authority(TENANT)?,
            MaintenanceRequest::new(
                id(name)?,
                MaintenanceAction::Recompute {
                    spec: spec.clone(),
                    window: range,
                },
                MaintenanceBudget {
                    rows: NonZeroU32::MIN,
                    buckets: NonZeroU32::MIN,
                },
            )?,
        )?;
        plans.push((req, None, false));
    }
    let (done, cost) = measure(thread_cpu, async {
        for _ in 0..8 {
            for (r, after, done) in &mut plans {
                if *done {
                    continue;
                }
                match confirmed(f.store.step(r, after.as_ref(), deadline()?).await?)? {
                    MaintenanceProgress::More { next, .. } => *after = Some(next),
                    MaintenanceProgress::Complete { .. } => *done = true,
                    MaintenanceProgress::Blocked { .. } => {
                        anyhow::bail!("unexpected blocked recompute")
                    }
                }
            }
        }
        anyhow::Ok(plans.iter().all(|p| p.2))
    })
    .await;
    assert!(done?);
    assert_eq!((cost.namespace_counts, cost.aggregate_fence_rows), (2, 2));
    for (q, raw) in expected {
        let cached = f.store.aggregate(&q, None, deadline()?).await?;
        assert_eq!(
            cached.refreshed_through,
            Some(q.request().query().window().end())
        );
        assert_eq!(serde_json::to_value(cached.buckets)?, raw);
    }
    // Independently published objects for the same window have identical summaries.
    let counts = f
        .ch
        .sql("SELECT uniqExact(object_id),uniqExact(digest) FROM rss_ts_ch.summaries WHERE lo=0")
        .await?;
    assert_eq!(counts.trim(), "2\t1");
    Ok(())
}
