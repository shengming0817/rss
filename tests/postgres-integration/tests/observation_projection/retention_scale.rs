use super::{
    fixture::*,
    retention::{EXPIRY, maintenance_role},
};
use anyhow::Context;
use rss_observation::{
    Body, MaintenanceGrant, ObservationMaintenance, Policy, ScanWindow, Scope, State,
};
use rss_observation_postgres::PgMaintenance;
use serde_json::Value;
use sqlx::{Connection, PgConnection};
use std::io::{Read, Seek};
use tracing_subscriber::util::SubscriberInitExt;

#[tokio::test]
async fn bounded_candidate_scan() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let store = f.store().await?;
    let maint = PgMaintenance::new(maintenance_role(&f).await?, Clock, deadline()).await?;
    for (tenant, total, history) in [
        (OTHER, 1024_u32, 1022_i32),
        (TENANT, 128, 510),
        (TENANT, 32768, 8190),
    ] {
        let object = format!("history-{total}");
        let s = scope(tenant, &object, "r", "s", "old")?;
        // Populate this family through the same lifecycle CAS as a real sequence of activations.
        let mut tx = f.pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant)
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT rss_observation.activate(jsonb_set($1::text::jsonb,'{epoch}',to_jsonb(n::text))::text,
            nullif(n-1,0),$3,$4) FROM generate_series(1,$2::integer) n ORDER BY n")
            .bind(s.encode()?).bind(history).bind(Policy::new(86400,3600,3600)?.encode()?)
            .bind(State::initial().encode()?).execute(&mut *tx).await?;
        tx.commit().await?;
        let prior = u64::try_from(history)?;
        activate(&store, &s, Some(prior)).await?;
        // A long prefix of already expired identities followed by a single live body.
        sqlx::query("INSERT INTO rss_observation.batches(tenant_id,scope,batch_id,sequence,fingerprint,received_at,applicable)
          SELECT $1::uuid,$2,n::text,n,sha256(convert_to(n::text,'utf8')),100,false FROM generate_series(0,$3-1) n")
            .bind(tenant).bind(s.encode()?).bind(i32::try_from(total)?).execute(&f.admin).await?;
        let last = batch(&s, "final", u64::from(total), "all", Body::Partial(vec![]))?;
        f.stage(&last).await?.0.commit().await?;
        activate(
            &store,
            &scope(tenant, &object, "r", "s", "new")?,
            Some(prior + 1),
        )
        .await?;
        sqlx::raw_sql("ANALYZE rss_observation.batches; ANALYZE rss_observation.streams")
            .execute(&f.admin)
            .await?;
        let after = u64::from(total - 4);
        for mode in ["force_custom_plan", "force_generic_plan"] {
            let plans = reclaim_plans(&f, &s, after, mode).await?;
            for (order, table, expected) in [
                ("ORDER BY sequence_key", "batches", 4),
                ("ORDER BY activation_revision DESC", "streams", 1),
            ] {
                let plan = plans
                    .iter()
                    .find(|p| p["Query Text"].as_str().is_some_and(|q| q.contains(order)))
                    .with_context(|| format!("missing nested plan for {table}"))?;
                let root = &plan["Plan"];
                let visited = examined(root, table);
                println!(
                    "history={total} epochs={} mode={mode} table={table} examined={visited} shared_hits={}",
                    history + 2,
                    root["Shared Hit Blocks"]
                );
                assert_eq!(visited, expected, "{root}");
            }
        }
        let grant = || MaintenanceGrant::verify(&Trusted, s.clone(), EXPIRY, 0);
        let empty = maint
            .reclaim(grant()?, ScanWindow::new(None, 4)?, deadline())
            .await?;
        assert_eq!(
            (empty.scanned, empty.reclaimed, empty.last_examined),
            (4, 0, Some(3))
        );
        let w = ScanWindow::new(Some(after), 4)?;
        let page = maint.reclaim(grant()?, w, deadline()).await?;
        assert_eq!(
            (page.scanned, page.reclaimed, page.released_bytes),
            (4, 1, last.batch().encode().len() as u64)
        );
        assert_eq!(maint.reclaim(grant()?, w, deadline()).await?.reclaimed, 0);
    }
    Ok(())
}

#[tokio::test]
async fn retention_window_cost() -> anyhow::Result<()> {
    use rss_observation::{Id, LookupOutcome, ObservationStore, ReadGrant};
    use rss_projection::Timer as _;
    let clock = ProjectionClock(rss_observation::Clock::now(&Clock));

    let f = Fixture::new().await?;
    let store = f.store().await?;
    let pool = maintenance_role(&f).await?;
    let maint = PgMaintenance::new(pool.clone(), Clock, deadline()).await?;
    let retired = scope(TENANT, "window", "r", "s", "old")?;
    activate(&store, &retired, None).await?;
    let mut sizes = Vec::new();
    for seq in 0..1155 {
        let input = batch(
            &retired,
            &seq.to_string(),
            seq,
            "all",
            Body::Snapshot(vec![]),
        )?;
        f.stage(&input).await?.0.commit().await?;
        sizes.push(input.batch().encode().len() as u64);
    }
    let active = scope(TENANT, "window", "r", "s", "new")?;
    activate(&store, &active, Some(1)).await?;

    for invalid in [0, 1025] {
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(TENANT)
            .execute(&mut *tx)
            .await?;
        let error = sqlx::query("SELECT * FROM rss_observation.reclaim($1,$2,1155,NULL,$3)")
            .bind(retired.encode()?)
            .bind(EXPIRY)
            .bind(invalid)
            .execute(&mut *tx)
            .await
            .err()
            .context("maintenance accepted an invalid SQL window")?;
        assert_eq!(
            error.as_database_error().and_then(|e| e.code()).as_deref(),
            Some("OB005")
        );
        tx.rollback().await?;
    }

    let grant = || MaintenanceGrant::verify(&Trusted, retired.clone(), EXPIRY, 1155);
    let read = ReadGrant::verify(&Trusted, retired.clone())?;
    let mut cursor = None;
    let mut start = 0;
    for limit in [1, 64, 65, 1024, 1024] {
        let window = ScanWindow::new(cursor, limit)?;
        let end = (start + usize::from(limit)).min(sizes.len());
        let count = u32::try_from(end - start)?;
        if count == 1024 {
            // Compare the same foreground lookup with and without an outstanding
            // full maintenance transaction. Roll back so the API times its own work.
            let id = Id::new(start.to_string())?;
            let lookup = || async {
                let started = clock.now();
                let outcome = store.lookup(&read, &id, deadline()).await?;
                assert!(matches!(outcome, LookupOutcome::Found(_)));
                Ok::<_, anyhow::Error>((clock.now() - started).as_micros())
            };
            let receive = async |seq: u64| -> anyhow::Result<u128> {
                let input = batch(
                    &active,
                    &seq.to_string(),
                    seq,
                    "all",
                    Body::Snapshot(vec![]),
                )?;
                let started = clock.now();
                let outcome = store.receive(&input, deadline()).await?;
                assert!(outcome.record().decision().outcome().is_applicable());
                Ok((clock.now() - started).as_micros())
            };
            let baseline = lookup().await?;
            let write_baseline = receive(0).await?;
            let mut tx = pool.begin().await?;
            let (blocker, _): (i32, String) =
                sqlx::query_as("SELECT pg_backend_pid(), set_config('rss.tenant_id',$1,true)")
                    .bind(TENANT)
                    .fetch_one(&mut *tx)
                    .await?;
            let staged: i32 = sqlx::query_scalar("SELECT reclaimed FROM rss_observation.reclaim($1,$2,1155,$3::bigint::numeric,1024)")
                .bind(retired.encode()?).bind(EXPIRY).bind(i64::try_from(start)? - 1)
                .fetch_one(&mut *tx).await?;
            assert_eq!(staged, 1024);
            let concurrent = lookup().await?;
            let (write_concurrent, ()) = tokio::try_join!(receive(1), async {
                f.wait_for_blocked(blocker, 1).await?;
                tx.rollback().await?;
                Ok(())
            })?;
            println!(
                "retention_foreground operation=receive candidates={count} baseline_us={write_baseline} held_transaction_us={write_concurrent} journal_wait_observed=true"
            );
            println!(
                "retention_foreground operation=lookup candidates={count} baseline_us={baseline} concurrent_us={concurrent}"
            );
        }
        let started = clock.now();
        let page = maint.reclaim(grant()?, window, deadline()).await?;
        println!(
            "retention_cost limit={limit} page={page:?} transaction_us={}",
            (clock.now() - started).as_micros()
        );
        assert_eq!((page.scanned, page.reclaimed), (count, count));
        assert_eq!(page.released_bytes, sizes[start..end].iter().sum::<u64>());
        assert_eq!(page.last_examined, Some(u64::try_from(end - 1)?));
        assert_eq!(page.finished, count < u32::from(limit));
        if count == 1024 {
            let repeat = maint.reclaim(grant()?, window, deadline()).await?;
            assert_eq!(
                (repeat.scanned, repeat.reclaimed, repeat.released_bytes),
                (1024, 0, 0)
            );
            assert_eq!(repeat.last_examined, page.last_examined);
        }
        cursor = page.last_examined;
        start = end;
    }
    assert_eq!(start, sizes.len());
    Ok(())
}

async fn reclaim_plans(
    f: &Fixture,
    scope: &Scope,
    after: u64,
    mode: &str,
) -> anyhow::Result<Vec<Value>> {
    let mut c = PgConnection::connect_with(f.admin.connect_options().as_ref()).await?;
    sqlx::raw_sql("LOAD 'auto_explain'; SET auto_explain.log_nested_statements=on;
        SET auto_explain.log_analyze=on; SET auto_explain.log_buffers=on; SET auto_explain.log_timing=off;
        SET auto_explain.log_format=json; SET auto_explain.log_level=notice;
        SET auto_explain.log_min_duration=0; SET SESSION AUTHORIZATION obs_maint")
        .execute(&mut c).await?;
    let mut tx = c.begin().await?;
    sqlx::query(
        "SELECT set_config('rss.tenant_id',$1,true), set_config('plan_cache_mode',$2,true)",
    )
    .bind(scope.tenant().to_string())
    .bind(mode)
    .execute(&mut *tx)
    .await?;
    let mut file = tempfile::tempfile()?;
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_level(false)
        .with_target(false)
        .with_ansi(false)
        .with_env_filter("sqlx::postgres::notice=info")
        .with_writer(file.try_clone()?)
        .finish();
    // The default current-thread test runtime keeps the subscriber local to this measured call.
    let guard = subscriber.set_default();
    let stats: (i32, i32) = sqlx::query_as(
        "SELECT scanned,reclaimed FROM rss_observation.reclaim($1,$2,0,$3::text::numeric,4)",
    )
    .bind(scope.encode()?)
    .bind(EXPIRY)
    .bind(after.to_string())
    .fetch_one(&mut *tx)
    .await?;
    tx.rollback().await?;
    drop(guard);
    assert_eq!(stats, (4, 1));
    file.rewind()?;
    let mut notices = String::new();
    file.read_to_string(&mut notices)?;
    notices
        .split("plan:\n")
        .skip(1)
        .map(|s| {
            serde_json::Deserializer::from_str(s)
                .into_iter::<Value>()
                .next()
                .context("empty plan notice")?
                .context("invalid plan notice")
        })
        .collect()
}

pub(super) fn examined(node: &Value, table: &str) -> u64 {
    let rows = if node["Relation Name"] == table {
        [
            "Actual Rows",
            "Rows Removed by Filter",
            "Rows Removed by Index Recheck",
        ]
        .iter()
        .filter_map(|key| node[*key].as_u64())
        .sum::<u64>()
            * node["Actual Loops"].as_u64().unwrap_or(1)
    } else {
        0
    };
    rows + node["Plans"]
        .as_array()
        .map_or(0, |nodes| nodes.iter().map(|n| examined(n, table)).sum())
}
