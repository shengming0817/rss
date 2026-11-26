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

fn examined(node: &Value, table: &str) -> u64 {
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
