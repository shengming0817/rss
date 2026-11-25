use super::{fixture::*, scenarios::model};
use anyhow::Context;
use rss_observation::{
    Access, Authority, Body, Error, ErrorKind, Id, LifecycleGrant, LookupOutcome, MaintenanceGrant,
    ObservationMaintenance, ObservationStore, Policy, ReadGrant, ScanWindow, Scope,
};
use rss_observation_postgres::{Fault, PgMaintenance, PgStore};
use rss_projection::{
    BatchLimit, Control, Execution, GenerationStart, ProjectionScope, ReplayBound, Source,
};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::time::Duration;

const EXPIRY: i64 = 100 + 86400 + 3600;

async fn maintenance_role(f: &Fixture) -> anyhow::Result<PgPool> {
    sqlx::raw_sql("CREATE ROLE obs_maint LOGIN PASSWORD 'fixture-only' NOSUPERUSER NOBYPASSRLS;
      GRANT USAGE ON SCHEMA rss_observation TO obs_maint;
      GRANT EXECUTE ON FUNCTION rss_observation.reclaim(text,bigint,bigint,numeric,integer) TO obs_maint")
        .execute(&f.admin).await?;
    Ok(PgPoolOptions::new()
        .max_connections(3)
        .connect_with(f.options.clone().username("obs_maint"))
        .await?)
}
fn grant(s: &Scope, cutoff: i64, through: i64) -> Result<MaintenanceGrant, Error> {
    MaintenanceGrant::verify(&Trusted, s.clone(), cutoff, through)
}
struct TenantMaintenance;
impl Authority for TenantMaintenance {
    fn authorize(&self, access: Access<'_>) -> Result<(), Error> {
        match access {
            Access::Maintain {
                scope,
                cutoff: EXPIRY,
                release_through: 1,
            } if scope.tenant().to_string() == TENANT => Ok(()),
            _ => Err(ErrorKind::Unauthorized.into()),
        }
    }
}
#[tokio::test]
async fn maintenance_permissions_and_tenant_isolation() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let maint_pool = maintenance_role(&f).await?;
    assert!(
        PgStore::new(maint_pool.clone(), Clock, deadline())
            .await
            .is_err()
    );
    assert!(
        PgMaintenance::new(f.pool.clone(), Clock, deadline())
            .await
            .is_err()
    );
    let s = scope(TENANT, "obj", "r", "src", "old")?;
    let other = scope(OTHER, "obj", "r", "src", "old")?;
    MaintenanceGrant::verify(&TenantMaintenance, s.clone(), EXPIRY, 1)?;
    for (s, t, p) in [(&other, EXPIRY, 1), (&s, EXPIRY + 1, 1), (&s, EXPIRY, 2)] {
        assert_eq!(
            MaintenanceGrant::verify(&TenantMaintenance, s.clone(), t, p)
                .err()
                .context("expected operation to fail")?
                .kind(),
            ErrorKind::Unauthorized
        );
    }
    let (permitted,raw_write):(bool,bool)=sqlx::query_as("SELECT has_function_privilege(current_user,'rss_observation.reclaim(text,bigint,bigint,numeric,integer)','EXECUTE'),has_table_privilege(current_user,'rss_observation.batches','UPDATE')").fetch_one(&f.pool).await?;
    assert_eq!((permitted, raw_write), (false, false));
    let mut tx = maint_pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(TENANT)
        .execute(&mut *tx)
        .await?;
    let rejected = sqlx::query("SELECT * FROM rss_observation.reclaim($1,100,0,NULL,1)")
        .bind(other.encode()?)
        .execute(&mut *tx)
        .await
        .err()
        .context("expected operation to fail")?;
    assert_eq!(
        rejected
            .as_database_error()
            .and_then(|e| e.code())
            .as_deref(),
        Some("OB007")
    );
    tx.rollback().await?;
    let store = f.store().await?;
    let maint = PgMaintenance::new(maint_pool, Clock, deadline()).await?;
    let w = ScanWindow::new(None, 4)?;
    assert_eq!(
        maint
            .reclaim(grant(&s, EXPIRY, 0)?, w, deadline())
            .await
            .err()
            .context("expected operation to fail")?
            .kind(),
        ErrorKind::UnknownStream
    );
    for stream in [&s, &other] {
        activate(&store, stream, None).await?;
        f.stage(&batch(stream, "same", 0, "all", Body::Snapshot(vec![]))?)
            .await?
            .0
            .commit()
            .await?;
    }
    assert_eq!(
        maint
            .reclaim(grant(&s, EXPIRY, 1)?, w, deadline())
            .await
            .err()
            .context("expected operation to fail")?
            .kind(),
        ErrorKind::LifecycleConflict
    );
    for tenant in [TENANT, OTHER] {
        activate(&store, &scope(tenant, "obj", "r2", "src", "new")?, Some(1)).await?;
    }
    maint.reclaim(grant(&s, EXPIRY, 1)?, w, deadline()).await?;
    assert!(matches!(
        store
            .lookup(
                &ReadGrant::verify(&Trusted, other.clone())?,
                &Id::new("same")?,
                deadline()
            )
            .await?,
        LookupOutcome::Found(_)
    ));
    let clock = ProjectionClock(rss_observation::Clock::now(&Clock));
    let token = tokio_util::sync::CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(30), &token);
    assert_eq!(
        f.source(store, OTHER)?
            .bounds(&control)
            .await?
            .expired_through,
        None
    );
    Ok(())
}

#[tokio::test]
async fn retired_receipts_and_interleaved_journal() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let store = f.store().await?;
    let pool = maintenance_role(&f).await?;
    let maint = PgMaintenance::new(pool.clone(), Clock, deadline()).await?;
    let clock = ProjectionClock(rss_observation::Clock::now(&Clock));
    let token = tokio_util::sync::CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(60), &token);
    let a = scope(TENANT, "A", "r", "s", "active")?;
    let b = scope(TENANT, "B", "r", "s", "retired")?;
    for stream in [&a, &b] {
        activate(&store, stream, None).await?;
    }
    let active = batch(&a, "snap", 0, "all", Body::Snapshot(vec![]))?;
    store.receive(&active, deadline()).await?;
    let old = batch(&b, "snap", 0, "all", Body::Snapshot(vec![]))?;
    f.stage(&old).await?.0.commit().await?;
    let delta = batch(
        &a,
        "delta",
        1,
        "all",
        Body::Delta {
            baseline: Id::new("snap")?,
            previous: 0,
            changes: vec![],
        },
    )?;
    assert!(
        store
            .receive(&delta, deadline())
            .await?
            .record()
            .decision()
            .outcome()
            .is_applicable()
    );
    let partial = batch(&b, "partial", u64::MAX, "all", Body::Partial(vec![]))?;
    f.stage(&partial).await?.0.commit().await?;
    let b_read = ReadGrant::verify(&Trusted, b.clone())?;
    let source = f.source(store.clone(), TENANT)?;
    let all = source
        .read(source.scope(), None, BatchLimit::new(4)?, &control)
        .await?;
    let [first, second, third] = all.as_slice() else {
        anyhow::bail!("expected three journal positions")
    };
    let next = scope(TENANT, "B", "r", "s", "new")?;
    activate(&store, &next, Some(1)).await?;
    let w = ScanWindow::new(None, 2)?;
    assert_eq!(
        maint
            .reclaim(grant(&b, EXPIRY - 1, 2)?, w, deadline())
            .await?
            .reclaimed,
        0
    );
    for (cutoff, through) in [(i64::MAX, 2), (EXPIRY, 4)] {
        assert_eq!(
            maint
                .reclaim(grant(&b, cutoff, through)?, w, deadline())
                .await
                .err()
                .context("expected operation to fail")?
                .kind(),
            ErrorKind::InvalidInput
        );
    }
    let g = || grant(&b, EXPIRY, 1);
    let protected = maint.reclaim(g()?, w, deadline()).await?;
    assert_eq!(
        (
            protected.scanned,
            protected.reclaimed,
            protected.last_examined
        ),
        (2, 1, Some(u64::MAX))
    );
    assert_eq!(source.bounds(&control).await?.expired_through, None);
    assert!(matches!(
        store.lookup(&b_read, old.batch().id(), deadline()).await?,
        LookupOutcome::Found(_)
    ));
    let projection = f.projection(&control).await?;
    let generation = ProjectionScope::new(source.scope().clone(), "facts", "fixed")?;
    projection
        .initialize(
            &generation,
            &model::DEFINITION,
            GenerationStart::beginning(),
            ReplayBound::Through(Some(third.position())),
            &control,
        )
        .await?;
    let execution = projection.projection(
        projection
            .takeover(&generation, &model::DEFINITION, &control)
            .await?,
        model::Facts::new(source.clone()),
    )?;
    execution.execute(None, first, &control).await?;
    let original: String =
        sqlx::query_scalar("SELECT policy FROM rss_observation.streams WHERE scope=$1")
            .bind(b.encode()?)
            .fetch_one(&f.admin)
            .await?;
    for damaged in [
        original.replace("\"version\":1", "\"version\":2"),
        original.replace("\"retrySeconds\":86400", "\"retrySeconds\":-1"),
    ] {
        assert_ne!(damaged, original);
        sqlx::query("UPDATE rss_observation.streams SET policy=$1 WHERE scope=$2")
            .bind(damaged)
            .bind(b.encode()?)
            .execute(&f.admin)
            .await?;
        assert_eq!(
            maint
                .reclaim(grant(&b, EXPIRY, 2)?, w, deadline())
                .await
                .err()
                .context("corrupt policy admitted")?
                .kind(),
            ErrorKind::Invariant
        );
        assert_eq!(source.bounds(&control).await?.expired_through, None);
    }
    sqlx::query("UPDATE rss_observation.streams SET policy=$1 WHERE scope=$2")
        .bind(original)
        .bind(b.encode()?)
        .execute(&f.admin)
        .await?;
    let release = || grant(&b, EXPIRY, 2);
    maint.inject_next_fault(Fault::BeforeCommit);
    assert_eq!(
        maint
            .reclaim(release()?, w, deadline())
            .await
            .err()
            .context("expected operation to fail")?
            .kind(),
        ErrorKind::Storage
    );
    assert_same_record(
        source.resolve(second, &control).await?.record(),
        store.receive(&old, deadline()).await?.record(),
    );
    // Hold a real cleanup after both writes, before settlement. Other connections must
    // still observe the original receipt and the complete page in the old MVCC snapshot.
    let mut staged = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(TENANT)
        .execute(&mut *staged)
        .await?;
    let staged_count: i32 =
        sqlx::query_scalar("SELECT reclaimed FROM rss_observation.reclaim($1,$2,2,NULL,2)")
            .bind(b.encode()?)
            .bind(EXPIRY)
            .fetch_one(&mut *staged)
            .await?;
    assert_eq!(staged_count, 1);
    let read_limit = BatchLimit::new(4)?;
    let (replay, resolved, page) = tokio::join!(
        store.receive(&old, deadline()),
        source.resolve(second, &control),
        source.read(source.scope(), Some(first.position()), read_limit, &control)
    );
    assert_same_record(replay?.record(), resolved?.record());
    assert_eq!(page?, vec![second.clone(), third.clone()]);
    staged.rollback().await?;
    maint.inject_next_fault(Fault::CommitAckLost);
    assert_eq!(
        maint
            .reclaim(release()?, w, deadline())
            .await
            .err()
            .context("expected operation to fail")?
            .kind(),
        ErrorKind::CommitUnknown
    );
    let repeat = maint.reclaim(release()?, w, deadline()).await?;
    assert_eq!(
        (repeat.scanned, repeat.reclaimed, repeat.released_bytes),
        (2, 0, 0)
    );
    assert!(
        maint
            .reclaim(
                release()?,
                ScanWindow::new(repeat.last_examined, 2)?,
                deadline()
            )
            .await?
            .finished
    );
    assert_eq!(
        source.bounds(&control).await?.expired_through,
        Some(second.position())
    );
    assert_eq!(
        source.high_water(source.scope(), &control).await?,
        Some(third.position())
    );
    for after in [None, Some(first.position())] {
        assert_eq!(
            source
                .read(source.scope(), after, BatchLimit::new(4)?, &control)
                .await
                .err()
                .context("expected operation to fail")?
                .kind(),
            rss_projection::ErrorKind::HistoryExpired
        );
    }
    assert_eq!(
        source
            .read(
                source.scope(),
                Some(second.position()),
                BatchLimit::new(4)?,
                &control
            )
            .await?,
        vec![third.clone()]
    );
    assert_same_record(
        source.resolve(first, &control).await?.record(),
        store.receive(&active, deadline()).await?.record(),
    );
    assert_eq!(
        source
            .resolve(second, &control)
            .await
            .err()
            .context("expected operation to fail")?
            .kind(),
        rss_projection::ErrorKind::HistoryExpired
    );
    let forged = rss_projection::Event::new(
        source.scope().clone(),
        second.position(),
        first.id(),
        first.payload().to_vec(),
    )?;
    assert_eq!(
        source
            .resolve(&forged, &control)
            .await
            .err()
            .context("expected operation to fail")?
            .kind(),
        rss_projection::ErrorKind::InvalidInput
    );
    assert_eq!(
        execution
            .execute(Some(first.position()), second, &control)
            .await
            .err()
            .context("expected operation to fail")?
            .kind(),
        rss_projection::ErrorKind::HistoryExpired
    );
    assert_eq!(
        execution.checkpoint(&control).await?.position,
        Some(first.position())
    );
    let run = rss_projection::run_batched(
        &*source,
        &execution,
        &control,
        rss_projection::RunLimit::new(BatchLimit::new(4)?, 4)?,
    )
    .await;
    assert_eq!(
        run.into_result()
            .err()
            .context("expected operation to fail")?
            .kind(),
        rss_projection::ErrorKind::HistoryExpired
    );
    assert!(matches!(
        store.lookup(&b_read, old.batch().id(), deadline()).await?,
        LookupOutcome::Expired
    ));
    assert!(matches!(
        store
            .lookup(&b_read, &Id::new("missing")?, deadline())
            .await?,
        LookupOutcome::NotFound
    ));
    assert_eq!(
        store
            .receive(&old, deadline())
            .await
            .err()
            .context("expected operation to fail")?
            .kind(),
        ErrorKind::HistoryExpired
    );
    let changed = batch(&b, "snap", 0, "all", Body::Partial(vec![]))?;
    assert_eq!(
        store
            .receive(&changed, deadline())
            .await
            .err()
            .context("expected operation to fail")?
            .kind(),
        ErrorKind::Conflict
    );
    assert_eq!(
        store
            .receive(
                &batch(&b, "new", 3, "all", Body::Partial(vec![]))?,
                deadline()
            )
            .await
            .err()
            .context("expected operation to fail")?
            .kind(),
        ErrorKind::StaleEpoch
    );
    assert_eq!(
        store
            .activate(
                &LifecycleGrant::verify(&Trusted, b)?,
                Some(2),
                &Policy::new(86400, 3600, 3600)?,
                deadline()
            )
            .await
            .err()
            .context("expected operation to fail")?
            .kind(),
        ErrorKind::LifecycleConflict
    );
    // The host supplied the complete empty read model and both processed receipts.
    let restored = ProjectionScope::new(source.scope().clone(), "facts", "baseline")?;
    let start = GenerationStart::after(
        second.position(),
        vec![
            rss_projection::BaselineReceipt::from_event(first),
            rss_projection::BaselineReceipt::from_event(second),
        ],
    )?;
    projection
        .initialize(
            &restored,
            &model::DEFINITION,
            start,
            ReplayBound::Through(Some(third.position())),
            &control,
        )
        .await?;
    let rebuilt = projection.projection(
        projection
            .takeover(&restored, &model::DEFINITION, &control)
            .await?,
        model::Facts::new(source.clone()),
    )?;
    let limits = rss_projection::RunLimit::new(BatchLimit::new(3)?, 3)?;
    let done = rss_projection::run(&*source, &rebuilt, &control, limits)
        .await
        .into_result()?;
    assert_eq!((done.position, done.applied), (Some(third.position()), 1));
    assert_eq!(
        rss_projection::run(&*source, &rebuilt, &control, limits)
            .await
            .into_result()?
            .applied,
        0
    );
    let next_delta = batch(
        &a,
        "next",
        2,
        "all",
        Body::Delta {
            baseline: Id::new("snap")?,
            previous: 1,
            changes: vec![],
        },
    )?;
    assert!(
        store
            .receive(&next_delta, deadline())
            .await?
            .record()
            .decision()
            .outcome()
            .is_applicable()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn settlement_and_competing_pages() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let store = f.store().await?;
    let maint = PgMaintenance::new(maintenance_role(&f).await?, Clock, deadline()).await?;
    let old = scope(TENANT, "obj", "r", "s", "old")?;
    let next = scope(TENANT, "obj", "r", "s", "new")?;
    activate(&store, &old, None).await?;
    let report = batch(&old, "snapshot", 0, "all", Body::Snapshot(vec![]))?;
    // Stage both the batch and a lifecycle switch on the same connection. The
    // object UPDATE lock makes the retry wait *after* it has observed Missing.
    let (mut pending, pid) = f.stage(&report).await?;
    sqlx::query("SELECT rss_observation.activate($1,1,$2,$3)")
        .bind(next.encode()?)
        .bind(Policy::new(86400, 3600, 3600)?.encode()?)
        .bind(rss_observation::State::initial().encode()?)
        .execute(&mut *pending)
        .await?;
    let retry_store = store.clone();
    let retry = batch(&old, "snapshot", 0, "all", Body::Snapshot(vec![]))?;
    let retry_task = tokio::spawn(async move { retry_store.receive(&retry, deadline()).await });
    f.wait_for_blocked(pid, 1).await?;
    pending.commit().await?;
    assert!(matches!(
        retry_task.await??,
        rss_observation::ReceiveOutcome::Replay(_)
    ));
    let authorized = || grant(&old, EXPIRY, 1);
    let window = ScanWindow::new(None, 1)?;
    let read = ReadGrant::verify(&Trusted, old.clone())?;
    for fault in [Fault::CommitPending, Fault::RollbackAckLost] {
        let expected = match fault {
            Fault::CommitPending => ErrorKind::CommitUnknown,
            _ => ErrorKind::RollbackFailed,
        };
        maint.inject_next_fault(fault);
        let budget = rss_request_context::Deadline::at(
            rss_observation::Clock::now(&Clock) + Duration::from_millis(400),
        );
        assert_eq!(
            maint
                .reclaim(authorized()?, window, budget)
                .await
                .err()
                .context("expected interruption")?
                .kind(),
            expected
        );
        assert!(matches!(
            store.lookup(&read, report.batch().id(), deadline()).await?,
            LookupOutcome::Found(_)
        ));
    }
    let (one, two) = tokio::try_join!(
        maint.reclaim(authorized()?, window, deadline()),
        maint.reclaim(authorized()?, window, deadline())
    )?;
    assert_eq!(one.reclaimed + two.reclaimed, 1);
    assert_eq!(
        one.released_bytes + two.released_bytes,
        report.batch().encode().len() as u64
    );
    assert_eq!((one.last_examined, two.last_examined), (Some(0), Some(0)));
    let clock = ProjectionClock(rss_observation::Clock::now(&Clock));
    let token = tokio_util::sync::CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(30), &token);
    let source = f.source(store, TENANT)?;
    let bounds = source.bounds(&control).await?;
    assert_eq!(bounds.high_water, bounds.expired_through);
    assert_eq!(bounds.high_water.map(|p| p.get()), Some(1));
    assert!(
        source
            .read(
                source.scope(),
                bounds.high_water,
                BatchLimit::new(1)?,
                &control
            )
            .await?
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn bounded_candidate_scan() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let store = f.store().await?;
    let maint = PgMaintenance::new(maintenance_role(&f).await?, Clock, deadline()).await?;
    // Inspect the same header selection used inside the installed maintenance function.
    let body:String=sqlx::query_scalar("SELECT prosrc FROM pg_proc WHERE oid='rss_observation.reclaim(text,bigint,bigint,numeric,integer)'::regprocedure")
        .fetch_one(&f.admin).await?;
    let (_, candidate) = body
        .split_once("FOR candidate IN ")
        .context("candidate cursor")?;
    let (candidate, _) = candidate.split_once(" LOOP").context("candidate body")?;
    let explain = format!(
        "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) {}",
        candidate
            .replace("tenant_id=t", "tenant_id=$1::uuid")
            .replace("scope=p_scope", "scope=$2")
            .replace("p_after", "$3::numeric")
            .replace("p_limit", "$4")
    );
    for (tenant, total) in [(OTHER, 1024_u32), (TENANT, 128), (TENANT, 2048)] {
        let object = format!("history-{total}");
        let s = scope(tenant, &object, "r", "s", "old")?;
        activate(&store, &s, None).await?;
        // A long prefix of already expired identities plus a final live body.
        // Retention must visit exactly the window even when most pages release nothing.
        sqlx::query("INSERT INTO rss_observation.batches(tenant_id,scope,batch_id,sequence,fingerprint,received_at,applicable)
          SELECT $1::uuid,$2,n::text,n,sha256(convert_to(n::text,'utf8')),100,false FROM generate_series(0,$3-1) n")
            .bind(tenant).bind(s.encode()?).bind(i32::try_from(total)?).execute(&f.admin).await?;
        let last = batch(&s, "final", u64::from(total), "all", Body::Partial(vec![]))?;
        f.stage(&last).await?.0.commit().await?;
        activate(&store, &scope(tenant, &object, "r", "s", "new")?, Some(1)).await?;
        sqlx::query("ANALYZE rss_observation.batches")
            .execute(&f.admin)
            .await?;
        let after = u64::from(total - 4);
        let mut tx = f.owner.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant)
            .execute(&mut *tx)
            .await?;
        let plan: serde_json::Value = sqlx::query_scalar(sqlx::AssertSqlSafe(explain.as_str()))
            .bind(tenant)
            .bind(s.encode()?)
            .bind(after.to_string())
            .bind(4_i32)
            .fetch_one(&mut *tx)
            .await?;
        tx.rollback().await?;
        let nodes = &plan[0]["Plan"];
        let visited = candidate_rows(nodes);
        let g = || grant(&s, EXPIRY, 0);
        let empty = maint
            .reclaim(g()?, ScanWindow::new(None, 4)?, deadline())
            .await?;
        assert_eq!(
            (empty.scanned, empty.reclaimed, empty.last_examined),
            (4, 0, Some(3))
        );
        let w = ScanWindow::new(Some(after), 4)?;
        let page = maint.reclaim(g()?, w, deadline()).await?;
        println!(
            "retired history size={total} examined={visited} scanned={} released={} bytes={} shared_hits={}",
            page.scanned, page.reclaimed, page.released_bytes, nodes["Shared Hit Blocks"]
        );
        assert!((1.0..=4.0).contains(&visited), "{nodes}");
        assert_eq!(
            (page.scanned, page.reclaimed, page.released_bytes),
            (4, 1, last.batch().encode().len() as u64)
        );
        assert_eq!(maint.reclaim(g()?, w, deadline()).await?.reclaimed, 0);
    }
    Ok(())
}
fn candidate_rows(node: &serde_json::Value) -> f64 {
    let rows = if node["Relation Name"] == "batches" {
        (node["Actual Rows"].as_f64().unwrap_or(0.0)
            + node["Rows Removed by Filter"].as_f64().unwrap_or(0.0))
            * node["Actual Loops"].as_f64().unwrap_or(1.0)
    } else {
        0.0
    };
    rows + node["Plans"]
        .as_array()
        .map_or(0.0, |nodes| nodes.iter().map(candidate_rows).sum())
}
