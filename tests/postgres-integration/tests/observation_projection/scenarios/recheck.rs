use super::super::retention::{EXPIRY, maintenance_role};
use super::*;
use anyhow::Context;
use rss_observation::{MaintenanceGrant, ObservationMaintenance, ScanWindow};
use rss_observation_postgres::{PgMaintenance, VerifiedObservation};
use rss_projection::{BatchExecution, ReceiptQuery, ReceiptStatus};
use rss_projection_postgres::{PgEffect, PgEffectOutcome, PgOperationError, PgTransaction};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Notify;

struct PausedFacts {
    facts: model::Facts<Clock>,
    applied: Arc<AtomicUsize>,
    staged: Arc<Notify>,
    released: Arc<Notify>,
}
impl PgEffect for PausedFacts {
    type Item = rss_projection::EventWith<VerifiedObservation>;
    const ISOLATION: rss_projection_postgres::EffectIsolation =
        <model::Facts<Clock> as PgEffect>::ISOLATION;
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        scope: &ProjectionScope,
        item: &Self::Item,
    ) -> Result<PgEffectOutcome, PgOperationError> {
        let result = self.facts.apply(tx, scope, item).await?;
        if self.applied.fetch_add(1, Ordering::SeqCst) == 0 {
            self.staged.notify_one();
            self.released.notified().await;
        }
        Ok(result)
    }
}

#[tokio::test]
async fn reclaim_after_first_effect_rolls_back_all_eight() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let store = f.store().await?;
    let active = scope(TENANT, "active", "r", "s", "e")?;
    let retired = scope(TENANT, "retired", "r", "s", "e")?;
    for stream in [&active, &retired] {
        activate(&store, stream, None).await?;
    }
    for i in 0..8 {
        let stream = if i == 7 { &retired } else { &active };
        let input = batch(
            stream,
            &format!("b{i}"),
            if i == 7 { 0 } else { i },
            "cost",
            Body::Snapshot(vec![up("key", i as u8)?]),
        )?;
        f.stage(&input).await?.0.commit().await?;
    }
    activate(&store, &scope(TENANT, "retired", "r", "s", "new")?, Some(1)).await?;
    let maint = PgMaintenance::new(maintenance_role(&f).await?, Clock, deadline()).await?;
    let window = ScanWindow::new(None, 1)?;
    let grant = |n| MaintenanceGrant::verify(&Trusted, retired.clone(), EXPIRY, n);
    assert_eq!(
        maint
            .reclaim(grant(7)?, window, deadline())
            .await?
            .reclaimed,
        0
    );
    let clock = ProjectionClock(rss_observation::Clock::now(&Clock));
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(30), &cancel);
    let source = f.source(store, TENANT)?;
    let events = expected_events(
        source
            .read(source.scope(), None, page_budget(8)?, &control)
            .await?,
    )?;
    assert_eq!(events.len(), 8);
    // This new projection pool inherits a stricter role default. Its effect transactions
    // must still observe commits that occur between ordered callbacks.
    sqlx::raw_sql("ALTER ROLE handoff_runtime SET default_transaction_isolation='repeatable read'")
        .execute(&f.admin)
        .await?;
    let pg = f.projection(&control).await?;
    let scope = ProjectionScope::new(source.scope().clone(), "facts", "mid-page")?;
    pg.initialize(
        &scope,
        &model::DEFINITION,
        GenerationStart::beginning(),
        ReplayBound::Live,
        &control,
    )
    .await?;
    let applied = Arc::new(AtomicUsize::new(0));
    let staged = Arc::new(Notify::new());
    let released = Arc::new(Notify::new());
    let exec = pg.projection(
        pg.takeover(&scope, &model::DEFINITION, &control).await?,
        PausedFacts {
            facts: model::Facts::new(source.clone()),
            applied: applied.clone(),
            staged: staged.clone(),
            released: released.clone(),
        },
    )?;
    let (error, ()) = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::try_join!(
            async {
                exec.execute_batch(None, events.clone(), &control)
                    .await
                    .err()
                    .context("eighth record expired")
            },
            async {
                staged.notified().await;
                assert_eq!(
                    maint
                        .reclaim(grant(8)?, window, deadline())
                        .await?
                        .reclaimed,
                    1
                );
                released.notify_one();
                Ok(())
            }
        )
    })
    .await??;
    assert_restore_error(
        &error,
        rss_projection::ErrorKind::HistoryExpired,
        Position::new(8)?,
    )?;
    assert_eq!(applied.load(Ordering::SeqCst), 7);
    let checkpoint = exec.checkpoint(&control).await?;
    assert_eq!(checkpoint.position, None);
    for item in &events {
        let q = ReceiptQuery::new(scope.clone(), model::DEFINITION, item.as_ref().id())?;
        assert_eq!(
            pg.receipt_status(&q, &control).await?,
            ReceiptStatus::Pending(checkpoint)
        );
    }
    assert!(values(&f, "mid-page", "cost").await?.is_empty());
    assert_eq!(
        source.bounds(&control).await?.expired_through,
        Some(Position::new(8)?)
    );
    Ok(())
}

#[tokio::test]
async fn changed_receipt_uses_current_row_and_retries_atomically() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let input = seed(&f).await?;
    let clock = ProjectionClock(rss_observation::Clock::now(&Clock));
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(30), &cancel);
    let pg = f.projection(&control).await?;
    let scope = ProjectionScope::new(input.source.scope().clone(), "facts", "changed-receipt")?;
    let exec = session(&pg, &scope, &input.source, &control).await?;
    let events = expected_events(
        input
            .source
            .read(input.source.scope(), None, page_budget(2)?, &control)
            .await?,
    )?;
    let current:i64=sqlx::query_scalar("UPDATE rss_observation.batches SET received_at=received_at+1 WHERE log_position=2 RETURNING received_at")
        .fetch_one(&f.admin).await?;
    let resolved = resolve_on(
        &pg,
        &control,
        input.source.scope(),
        &input.source,
        &events[1],
    )
    .await??;
    assert_eq!(resolved.record().received_at(), u64::try_from(current)?);
    let saved: String =
        sqlx::query_scalar("SELECT decision FROM rss_observation.batches WHERE log_position=2")
            .fetch_one(&f.admin)
            .await?;
    sqlx::query("UPDATE rss_observation.batches SET decision='{}' WHERE log_position=2")
        .execute(&f.admin)
        .await?;
    let e = exec
        .execute_batch(None, events.clone(), &control)
        .await
        .err()
        .context("changed transition")?;
    assert_restore_error(&e, rss_projection::ErrorKind::Rejected, Position::new(2)?)?;
    assert_eq!(exec.checkpoint(&control).await?.position, None);
    assert!(values(&f, "changed-receipt", "inside").await?.is_empty());
    sqlx::query("UPDATE rss_observation.batches SET decision=$1 WHERE log_position=2")
        .bind(saved)
        .execute(&f.admin)
        .await?;
    let outcomes = exec.execute_batch(None, events, &control).await?;
    assert_eq!(outcomes, vec![rss_projection::ApplyOutcome::Applied; 2]);
    assert_eq!(
        exec.checkpoint(&control).await?.position,
        Some(Position::new(2)?)
    );
    Ok(())
}

async fn resolve_on(
    pg: &rss_projection_postgres::PgStore,
    control: &Control<'_, ProjectionClock>,
    tx_scope: &rss_projection::SourceScope,
    source: &Arc<ObsSource>,
    item: &rss_projection::EventWith<VerifiedObservation>,
) -> anyhow::Result<Result<Arc<rss_observation::ApplicableRecord>, rss_projection::Error>> {
    let source = source.clone();
    let item = item.clone();
    Ok(pg
        .local_tx(tx_scope, control, move |tx| {
            Box::pin(async move { Ok(source.resolve_in_transaction(tx, &item).await) })
        })
        .await?)
}

#[tokio::test]
async fn exact_reference_is_checked_against_current_identity_and_tenant() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let input = seed(&f).await?;
    let clock = ProjectionClock(rss_observation::Clock::now(&Clock));
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(30), &cancel);
    let pg = f.projection(&control).await?;
    let source = &input.source;
    let page = expected_events(
        source
            .read(source.scope(), None, page_budget(1)?, &control)
            .await?,
    )?;
    let item = &page[0];
    let wrong = f.source(input.store.clone(), OTHER)?;
    let e = resolve_on(&pg, &control, wrong.scope(), source, item)
        .await?
        .err()
        .context("cross-tenant borrowed tx")?;
    assert_eq!(e.kind(), rss_projection::ErrorKind::ScopeMismatch);
    let diagnostic = e
        .diagnostic()
        .ok_or_else(|| anyhow::anyhow!("missing admission diagnostic"))?;
    assert_eq!(
        (diagnostic.phase(), diagnostic.position()),
        (rss_projection::Phase::Admission, None)
    );
    let replacement = batch(
        &input.stream,
        "snapshot",
        0,
        "inside",
        Body::Snapshot(vec![up("a", 91)?]),
    )?;
    let pos = item.as_ref().position();
    sqlx::query(
        "UPDATE rss_observation.batches SET raw=$1 WHERE tenant_id=$2::uuid AND log_position=$3",
    )
    .bind(replacement.batch().encode())
    .bind(TENANT)
    .bind(pos.get() as i64)
    .execute(&f.admin)
    .await?;
    let restore = || resolve_on(&pg, &control, source.scope(), source, item);
    assert_restore_error(
        &restore().await?.err().context("digest mismatch")?,
        rss_projection::ErrorKind::StorageContract,
        pos,
    )?;
    sqlx::query("UPDATE rss_observation.batches SET fingerprint=$1 WHERE tenant_id=$2::uuid AND log_position=$3")
        .bind(replacement.fingerprint().as_slice()).bind(TENANT).bind(pos.get() as i64).execute(&f.admin).await?;
    assert_restore_error(
        &restore().await?.err().context("valid replacement")?,
        rss_projection::ErrorKind::InvalidInput,
        pos,
    )?;
    sqlx::query("DELETE FROM rss_observation.batches WHERE tenant_id=$1::uuid AND log_position=$2")
        .bind(TENANT)
        .bind(pos.get() as i64)
        .execute(&f.admin)
        .await?;
    assert_restore_error(
        &restore().await?.err().context("missing row")?,
        rss_projection::ErrorKind::StorageContract,
        pos,
    )?;
    Ok(())
}

#[tokio::test]
async fn bounded_prefix_releases_records_and_resumes_at_exact_position() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    read_cost::seed_page(&f, "mixed").await?;
    let clock = ProjectionClock(rss_observation::Clock::now(&Clock));
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(90), &cancel);
    let store = f.store().await?;
    let tenant = rss_request_context::TenantId::parse(TENANT)?;
    let source = Arc::new(
        rss_observation_postgres::PgSource::new(
            store,
            rss_observation::JournalReadGrant::verify(&Trusted, tenant)?,
            rss_projection::SourceScope::new(tenant, "rss.observation.v1")?,
            rss_observation::Batch::MAX_ENCODED_BYTES,
        )?
        .into_local(),
    );
    let pg = f.projection(&control).await?;
    let s = ProjectionScope::new(source.scope().clone(), "facts", "tight")?;
    let exec = session(&pg, &s, &source, &control).await?;
    let mut after = None;
    for end in [2, 4, 6, 8] {
        let page = expected_events(
            source
                .read(source.scope(), after, page_budget(8)?, &control)
                .await?,
        )?;
        assert_eq!(page.len(), 2);
        assert_eq!(
            (page[0].as_ref().position(), page[1].as_ref().position()),
            (Position::new(end - 1)?, Position::new(end)?)
        );
        let record = resolve_on(&pg, &control, source.scope(), &source, &page[0]).await??;
        let weak = Arc::downgrade(&record);
        drop(record);
        assert!(weak.upgrade().is_some());
        assert_eq!(
            exec.execute_batch(after, page, &control).await?,
            vec![rss_projection::ApplyOutcome::Applied; 2]
        );
        assert!(weak.upgrade().is_none());
        after = Some(Position::new(end)?);
        assert_eq!(exec.checkpoint(&control).await?.position, after);
    }
    assert!(
        expected_events(
            source
                .read(source.scope(), after, page_budget(8)?, &control)
                .await?
        )?
        .is_empty()
    );
    Ok(())
}

struct InheritedEffect;
impl PgEffect for InheritedEffect {
    type Item = Event;
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        _: &ProjectionScope,
        _: &Event,
    ) -> Result<PgEffectOutcome, PgOperationError> {
        let level: String = tx
            .with_connection(|conn| {
                Box::pin(async move {
                    sqlx::query_scalar("SHOW transaction_isolation")
                        .fetch_one(conn)
                        .await
                })
            })
            .await?;
        assert_eq!(level, "serializable");
        Ok(PgEffectOutcome::Filtered)
    }
}
#[tokio::test]
async fn ordinary_sessions_inherit_fixed_snapshots_and_borrowed_resolve_rejects_them()
-> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let input = seed(&f).await?;
    let clock = ProjectionClock(rss_observation::Clock::now(&Clock));
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(30), &cancel);
    let source = &input.source;
    let items = expected_events(
        source
            .read(source.scope(), None, page_budget(2)?, &control)
            .await?,
    )?;
    sqlx::raw_sql("ALTER ROLE handoff_runtime SET default_transaction_isolation='serializable'")
        .execute(&f.admin)
        .await?;
    let pg = f.projection(&control).await?;
    let s = ProjectionScope::new(source.scope().clone(), "facts", "inherits")?;
    pg.initialize(
        &s,
        &model::DEFINITION,
        GenerationStart::beginning(),
        ReplayBound::Live,
        &control,
    )
    .await?;
    let exec = pg.projection(
        pg.takeover(&s, &model::DEFINITION, &control).await?,
        InheritedEffect,
    )?;
    exec.execute(None, items[0].as_ref(), &control).await?;
    exec.execute_batch(
        Some(items[0].as_ref().position()),
        vec![items[1].as_ref().clone()],
        &control,
    )
    .await?;
    let level: String = pg
        .local_tx(source.scope(), &control, |tx| {
            Box::pin(async move {
                tx.with_connection(|conn| {
                    Box::pin(async move {
                        sqlx::query_scalar("SHOW transaction_isolation")
                            .fetch_one(conn)
                            .await
                    })
                })
                .await
            })
        })
        .await?;
    assert_eq!(level, "serializable");
    let e = resolve_on(&pg, &control, source.scope(), source, &items[0])
        .await?
        .err()
        .context("fixed snapshot accepted")?;
    assert_eq!(e.kind(), rss_projection::ErrorKind::InvalidInput);
    assert_eq!(
        e.diagnostic().map(|d| d.phase()),
        Some(rss_projection::Phase::Admission)
    );
    Ok(())
}
