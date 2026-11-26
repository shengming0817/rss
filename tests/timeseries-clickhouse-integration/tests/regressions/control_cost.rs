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
    let relevant = query(d, QueryMode::History, 1)?.selection().clone();
    let other = Selection::Resource {
        scope: d.spec().scope.clone(),
        subject: id("other")?,
        resource: id("resource")?,
        keys: Default::default(),
    };
    for (name, selection, count) in [("related", relevant, related), ("noise", other, noise)] {
        sqlx::query(
            "INSERT INTO rss_ts_ch.fences(tenant_id,namespace,id,kind,selection,lo,hi)
            SELECT $1::text::uuid,'metrics',$2::text||n,'delete',$3::text::jsonb,2*n,2*n+1
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
        "control-write case={name} related={related} noise={noise} rows={} field_bytes={} comparisons={} build_cpu_ns={} match_cpu_ns={} locked_us={}",
        c.fence_rows,
        c.fence_bytes,
        c.comparisons,
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
        for case in ["new", "mixed", "replay", "receipt", "single"] {
            let tag = format!("{case}-{related}-{noise}");
            let new = if case == "single" { 1 } else { 48 };
            let mut items = if case == "mixed" || case == "replay" {
                replay.clone()
            } else {
                Vec::new()
            };
            if case != "replay" {
                for i in 0..new {
                    items.push(sample(&d, &format!("{tag}-{i}"), 1000, 1)?);
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
                result.unwrap_err().downcast_ref::<Error>(),
                Some(Error::HistoryExpired)
            ));
            print_write("early", related, noise, c);
        }
    }
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
        "control-maint case={name} hits={hits} noise={noise} candidates={} changed={} sql={} summary_updates={} locked_us={}",
        c.candidates,
        c.updated,
        after.0 - before.0,
        after.1 - before.1,
        c.locked.as_micros()
    );
    Ok(())
}

#[tokio::test]
#[ignore = "isolated release-mode PostgreSQL + ClickHouse control workload"]
async fn fixed_invalidation() -> anyhow::Result<()> {
    let f = Fixture::new("ch-maint-cost").await?;
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
    for noise in [0, 8] {
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
    }
    Ok(())
}
