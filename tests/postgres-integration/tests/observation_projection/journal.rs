use super::fixture::*;
use rss_observation::{
    Body, ErrorKind, Id, ObservationStore, ReadGrant, ReceiveOutcome, State, VerifiedBatch,
};
use rss_observation_postgres::PgStore;
use rss_projection::Source;
use std::time::Duration;

async fn first(
    store: &PgStore<Clock>,
    tenant: &str,
    object: &str,
    body: Body,
) -> anyhow::Result<VerifiedBatch> {
    let stream = scope(tenant, object, "r", "agent", "e")?;
    activate(store, &stream, None).await?;
    batch(&stream, "first", 0, "all", body)
}

fn snapshot() -> Body {
    Body::Snapshot(vec![])
}
fn failed() -> anyhow::Result<Body> {
    Ok(Body::Failed {
        code: Id::new("offline")?,
    })
}

async fn seed_allocator(f: &Fixture, remaining: i64) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO rss_observation.journals(tenant_id,last_position) VALUES($1::uuid,$2)",
    )
    .bind(TENANT)
    .bind(i64::MAX - remaining)
    .execute(&f.admin)
    .await?;
    Ok(())
}

async fn position(f: &Fixture, input: &VerifiedBatch) -> anyhow::Result<Option<i64>> {
    Ok(sqlx::query_scalar("SELECT log_position FROM rss_observation.batches WHERE tenant_id=$1::uuid AND scope=$2 AND batch_id=$3")
        .bind(input.scope().tenant().to_string()).bind(input.scope().encode()?).bind(input.batch().id().as_str()).fetch_one(&f.admin).await?)
}

#[tokio::test]
async fn report_commits_while_allocator_is_locked() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let store = f.store().await?;
    store
        .receive(
            &first(&store, TENANT, "seed", snapshot()).await?,
            deadline(),
        )
        .await?;
    let partial = first(&store, TENANT, "partial", Body::Partial(vec![])).await?;
    let clock = ProjectionClock(rss_observation::Clock::now(&Clock));
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_projection::Control::new(&clock, Duration::from_secs(60), &cancel);
    let source = f.source(store.clone(), TENANT)?;

    let mut tx = f.admin.begin().await?;
    let head: i64 = sqlx::query_scalar(
        "SELECT last_position FROM rss_observation.journals WHERE tenant_id=$1::uuid FOR UPDATE",
    )
    .bind(TENANT)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(head, 1);
    let ReceiveOutcome::Accepted(accepted) = store.receive(&partial, deadline()).await? else {
        anyhow::bail!("expected first admission");
    };
    let grant = ReadGrant::verify(&Trusted, partial.scope().clone())?;
    let record = store
        .lookup(&grant, partial.batch().id(), deadline())
        .await?
        .ok_or_else(|| anyhow::anyhow!("missing partial report"))?;
    assert_same_record(&record, &accepted);
    assert_eq!(record.batch().encode(), partial.batch().encode());
    assert_eq!(
        &store.state(&grant, deadline()).await?,
        record.decision().state()
    );
    assert_eq!(position(&f, &partial).await?, None);
    assert_eq!(
        source
            .high_water(source.scope(), &control)
            .await?
            .map(|p| p.get()),
        Some(1)
    );
    tx.rollback().await?;
    Ok(())
}

#[tokio::test]
async fn final_allocation_waits_for_admitted_report() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let store = f.store().await?;
    let partial = first(&store, TENANT, "partial", Body::Partial(vec![])).await?;
    let penultimate = first(&store, TENANT, "penultimate", snapshot()).await?;
    let last = first(&store, TENANT, "last", snapshot()).await?;
    let independent = first(&store, OTHER, "foreign", snapshot()).await?;
    seed_allocator(&f, 2).await?;
    let (tx, pid) = f.stage(&partial).await?;
    store.receive(&penultimate, deadline()).await?;
    assert_eq!(position(&f, &penultimate).await?, Some(i64::MAX - 1));
    let (last_result, settled) = tokio::join!(store.receive(&last, deadline()), async {
        f.wait_for_blocked(pid, 1).await?;
        store.receive(&independent, deadline()).await?;
        assert_eq!(position(&f, &independent).await?, Some(1));
        tx.commit().await?;
        Ok::<_, anyhow::Error>(())
    });
    settled?;
    last_result?;
    assert_eq!(position(&f, &partial).await?, None);
    assert_eq!(position(&f, &last).await?, Some(i64::MAX));
    Ok(())
}

async fn assert_rejected(
    store: &PgStore<Clock>,
    input: &VerifiedBatch,
    result: Result<ReceiveOutcome, rss_observation::Error>,
) -> anyhow::Result<()> {
    assert_eq!(result.err().map(|e| e.kind()), Some(ErrorKind::Invariant));
    let grant = ReadGrant::verify(&Trusted, input.scope().clone())?;
    assert!(
        store
            .lookup(&grant, input.batch().id(), deadline())
            .await?
            .is_none()
    );
    assert_eq!(store.state(&grant, deadline()).await?, State::initial());
    Ok(())
}

#[tokio::test]
async fn last_commit_closes_current_and_future_streams() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let store = f.store().await?;
    let partial = first(&store, TENANT, "partial", Body::Partial(vec![])).await?;
    let competing = first(&store, TENANT, "snapshot", snapshot()).await?;
    let last = first(&store, TENANT, "last", snapshot()).await?;
    seed_allocator(&f, 1).await?;
    let (tx, pid) = f.stage(&last).await?;
    let (partial_result, snapshot_result, settled) = tokio::join!(
        store.receive(&partial, deadline()),
        store.receive(&competing, deadline()),
        async {
            f.wait_for_blocked(pid, 2).await?;
            tx.commit().await?;
            Ok::<_, anyhow::Error>(())
        }
    );
    settled?;
    assert_rejected(&store, &partial, partial_result).await?;
    assert_rejected(&store, &competing, snapshot_result).await?;
    // Activation after exhaustion must preserve the closed admission row.
    let late = first(&store, TENANT, "new-stream", failed()?).await?;
    assert_rejected(&store, &late, store.receive(&late, deadline()).await).await?;
    let late_partial = batch(late.scope(), "partial", 1, "all", Body::Partial(vec![]))?;
    assert_rejected(
        &store,
        &late_partial,
        store.receive(&late_partial, deadline()).await,
    )
    .await?;
    assert_eq!(position(&f, &last).await?, Some(i64::MAX));
    let grant = ReadGrant::verify(&Trusted, last.scope().clone())?;
    let saved = store
        .lookup(&grant, last.batch().id(), deadline())
        .await?
        .ok_or_else(|| anyhow::anyhow!("missing final receipt"))?;
    let ReceiveOutcome::Replay(replayed) = store.receive(&last, deadline()).await? else {
        anyhow::bail!("expected exact replay at exhaustion");
    };
    assert_same_record(&replayed, &saved);
    let changed = batch(
        last.scope(),
        last.batch().id().as_str(),
        0,
        "all",
        failed()?,
    )?;
    assert_eq!(
        store
            .receive(&changed, deadline())
            .await
            .err()
            .map(|e| e.kind()),
        Some(ErrorKind::Conflict)
    );
    Ok(())
}

#[tokio::test]
async fn last_rollback_releases_admission_and_position() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let store = f.store().await?;
    let last = first(&store, TENANT, "rolled-back", snapshot()).await?;
    let pending = first(&store, TENANT, "failed", failed()?).await?;
    let retry = first(&store, TENANT, "replacement", snapshot()).await?;
    seed_allocator(&f, 1).await?;
    let (tx, pid) = f.stage(&last).await?;
    let (received, settled) = tokio::join!(store.receive(&pending, deadline()), async {
        f.wait_for_blocked(pid, 1).await?;
        tx.rollback().await?;
        Ok::<_, anyhow::Error>(())
    });
    settled?;
    received?;
    assert_eq!(position(&f, &pending).await?, None);
    let grant = ReadGrant::verify(&Trusted, last.scope().clone())?;
    assert!(
        store
            .lookup(&grant, last.batch().id(), deadline())
            .await?
            .is_none()
    );
    assert_eq!(store.state(&grant, deadline()).await?, State::initial());
    store.receive(&retry, deadline()).await?;
    assert_eq!(position(&f, &retry).await?, Some(i64::MAX));
    Ok(())
}
