use super::super::retention::{EXPIRY, maintenance_role};
use super::*;
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
    type Item = VerifiedObservation;
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
    let events = source
        .read(source.scope(), None, BatchLimit::new(8)?, &control)
        .await?;
    assert_eq!(events.len(), 8);
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
                Ok::<_, anyhow::Error>(
                    exec.execute_batch(None, events.clone(), &control)
                        .await
                        .expect_err("eighth record expired"),
                )
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
    let events = input
        .source
        .read(input.source.scope(), None, BatchLimit::new(2)?, &control)
        .await?;
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
        .expect_err("changed transition");
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
    item: &VerifiedObservation,
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
    let page = source
        .read(source.scope(), None, BatchLimit::new(1)?, &control)
        .await?;
    let item = &page[0];
    let wrong = f.source(input.store.clone(), OTHER)?;
    let e = resolve_on(&pg, &control, wrong.scope(), source, item)
        .await?
        .expect_err("cross-tenant borrowed tx");
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
        &restore().await?.expect_err("digest mismatch"),
        rss_projection::ErrorKind::StorageContract,
        pos,
    )?;
    sqlx::query("UPDATE rss_observation.batches SET fingerprint=$1 WHERE tenant_id=$2::uuid AND log_position=$3")
        .bind(replacement.fingerprint().as_slice()).bind(TENANT).bind(pos.get() as i64).execute(&f.admin).await?;
    assert_restore_error(
        &restore().await?.expect_err("valid replacement"),
        rss_projection::ErrorKind::InvalidInput,
        pos,
    )?;
    sqlx::query("DELETE FROM rss_observation.batches WHERE tenant_id=$1::uuid AND log_position=$2")
        .bind(TENANT)
        .bind(pos.get() as i64)
        .execute(&f.admin)
        .await?;
    assert_restore_error(
        &restore().await?.expect_err("missing row"),
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
        )?
        .into_local(rss_observation::Batch::MAX_ENCODED_BYTES)?,
    );
    let pg = f.projection(&control).await?;
    let s = ProjectionScope::new(source.scope().clone(), "facts", "tight")?;
    let exec = session(&pg, &s, &source, &control).await?;
    let mut after = None;
    for end in [2, 4, 6, 8] {
        let page = source
            .read(source.scope(), after, BatchLimit::new(8)?, &control)
            .await?;
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
        source
            .read(source.scope(), after, BatchLimit::new(8)?, &control)
            .await?
            .is_empty()
    );
    Ok(())
}
