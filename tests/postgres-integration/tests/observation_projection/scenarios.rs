use super::fixture::*;
use rss_observation::{Body, Change, Id, ObservationStore, ReadGrant, ReceiveOutcome};
use rss_projection::{
    BatchLimit, Control, Event, Execution, GenerationStart, Position, ProjectionScope, ReplayBound,
    RunLimit, Source,
};
use rss_projection_postgres::PgFault;
use sqlx::Row;
use std::time::Duration;
#[path = "../../../../crates/observation-postgres/examples/handoff/model.rs"]
pub(super) mod model;
fn up(key: &str, n: u8) -> anyhow::Result<Change> {
    Ok(Change::upsert(Id::new(key)?, vec![n]))
}
async fn values(
    f: &Fixture,
    generation: &str,
    coverage: &str,
) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    Ok(sqlx::query_as("SELECT fact_key,value FROM public.observation_facts WHERE tenant_id=$1::uuid AND generation=$2 AND coverage=$3 ORDER BY fact_key")
        .bind(TENANT).bind(generation).bind(coverage).fetch_all(&f.admin).await?)
}
type ObsStore = rss_observation_postgres::PgStore<Clock>;
type ObsSource = rss_observation_postgres::PgSource<Clock>;
type Session = rss_projection_postgres::PgProjection<model::Facts<Clock>>;
use std::sync::Arc;
struct Inputs {
    store: Arc<ObsStore>,
    source: Arc<ObsSource>,
    stream: rss_observation::Scope,
    first: rss_observation::VerifiedBatch,
    saved: ReceiveOutcome,
}
async fn seed(f: &Fixture) -> anyhow::Result<Inputs> {
    let store = f.store().await?;
    let source = f.source(store.clone(), TENANT)?;
    let stream = scope(TENANT, "composition", "r1", "agent", "e1")?;
    activate(&store, &stream, None).await?;
    let first = first_snapshot(&stream)?;
    let saved = store.receive(&first, deadline()).await?;
    seed_delta(&store, &stream).await?;
    Ok(Inputs {
        store,
        source,
        stream,
        first,
        saved,
    })
}
fn first_snapshot(
    stream: &rss_observation::Scope,
) -> anyhow::Result<rss_observation::VerifiedBatch> {
    let first = batch(
        stream,
        "snapshot",
        0,
        "inside",
        Body::Snapshot(vec![up("a", 1)?, up("b", 2)?, up("c", 3)?]),
    )?;
    Ok(first)
}
async fn seed_delta(store: &ObsStore, stream: &rss_observation::Scope) -> anyhow::Result<()> {
    store
        .receive(
            &batch(
                stream,
                "delta",
                1,
                "inside",
                Body::Delta {
                    baseline: Id::new("snapshot")?,
                    previous: 0,
                    changes: vec![up("a", 3)?, Change::delete(Id::new("c")?)],
                },
            )?,
            deadline(),
        )
        .await?;
    Ok(())
}
async fn session(
    projection: &rss_projection_postgres::PgStore,
    scope: &ProjectionScope,
    source: &Arc<ObsSource>,
    control: &Control<'_, ProjectionClock>,
) -> anyhow::Result<Session> {
    projection
        .initialize(
            scope,
            GenerationStart::beginning(),
            ReplayBound::Live,
            control,
        )
        .await?;
    let execution = projection.projection(
        projection.takeover(scope, control).await?,
        model::Facts::new(source.clone()),
    )?;
    Ok(execution)
}
pub async fn composition(f: &Fixture) -> anyhow::Result<()> {
    let input = seed(f).await?;
    let projection = f.projection().await?;
    let clock = ProjectionClock(rss_observation::Clock::now(&Clock));
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(60), &cancel);
    let scope = ProjectionScope::new(input.source.scope().clone(), "facts", "live")?;
    let execution = session(&projection, &scope, &input.source, &control).await?;
    initial_projection(f, &input.source, &execution, &control).await?;
    reject_incomplete(&input).await?;
    queue_recovery(&input).await?;
    let execution = session(&projection, &scope, &input.source, &control).await?;
    recovered_projection(f, &input.source, &execution, &control).await?;
    queue_empty(&input).await?;
    fail_and_commit(f, &input.source, &execution, &projection, &clock, &cancel).await?;
    resumed_projection(f, &input, &execution, &scope, &control).await?;
    Ok(())
}
async fn initial_projection(
    f: &Fixture,
    source: &Arc<ObsSource>,
    execution: &Session,
    control: &Control<'_, ProjectionClock>,
) -> anyhow::Result<()> {
    assert_eq!(execution.checkpoint().await?.position, None);
    assert!(values(f, "live", "inside").await?.is_empty());
    let report = rss_projection::run(
        source.as_ref(),
        execution,
        control,
        RunLimit::new(BatchLimit::new(2)?, 50)?,
    )
    .await
    .into_result()?;
    assert_eq!(report.applied, 2);
    assert_eq!(
        values(f, "live", "inside").await?,
        vec![("a".into(), vec![3]), ("b".into(), vec![2])]
    );
    Ok(())
}
async fn reject_incomplete(input: &Inputs) -> anyhow::Result<()> {
    let Inputs {
        store,
        source,
        stream,
        ..
    } = input;
    let cursor = source.high_water(source.scope()).await?;
    store
        .receive(
            &batch(
                stream,
                "gap",
                3,
                "inside",
                Body::Delta {
                    baseline: Id::new("snapshot")?,
                    previous: 2,
                    changes: vec![Change::delete(Id::new("b")?)],
                },
            )?,
            deadline(),
        )
        .await?;
    store
        .receive(
            &batch(stream, "partial", 4, "inside", Body::Partial(vec![]))?,
            deadline(),
        )
        .await?;
    store
        .receive(
            &batch(
                stream,
                "failure",
                5,
                "inside",
                Body::Failed {
                    code: Id::new("offline")?,
                },
            )?,
            deadline(),
        )
        .await?;
    assert_eq!(source.high_water(source.scope()).await?, cursor);
    assert!(
        source
            .read(source.scope(), cursor, BatchLimit::new(10)?)
            .await?
            .is_empty()
    );
    Ok(())
}
async fn queue_recovery(input: &Inputs) -> anyhow::Result<()> {
    let Inputs { store, stream, .. } = input;
    store
        .receive(
            &batch(
                stream,
                "outside",
                6,
                "outside",
                Body::Snapshot(vec![up("z", 9)?]),
            )?,
            deadline(),
        )
        .await?;
    store
        .receive(
            &batch(
                stream,
                "recovery",
                7,
                "inside",
                Body::Snapshot(vec![up("a", 4)?]),
            )?,
            deadline(),
        )
        .await?;
    Ok(())
}
async fn recovered_projection(
    f: &Fixture,
    source: &Arc<ObsSource>,
    execution: &Session,
    control: &Control<'_, ProjectionClock>,
) -> anyhow::Result<()> {
    let recovered = rss_projection::run(
        source.as_ref(),
        execution,
        control,
        RunLimit::new(BatchLimit::new(2)?, 50)?,
    )
    .await
    .into_result()?;
    assert_eq!(recovered.applied, 2);
    assert_eq!(
        values(f, "live", "inside").await?,
        vec![("a".into(), vec![4])]
    );
    assert_eq!(
        values(f, "live", "outside").await?,
        vec![("z".into(), vec![9])]
    );
    Ok(())
}
async fn queue_empty(input: &Inputs) -> anyhow::Result<()> {
    let Inputs { store, stream, .. } = input;
    store
        .receive(
            &batch(stream, "empty", 8, "inside", Body::Snapshot(vec![]))?,
            deadline(),
        )
        .await?;
    Ok(())
}
async fn fail_and_commit(
    f: &Fixture,
    source: &Arc<ObsSource>,
    execution: &Session,
    projection: &rss_projection_postgres::PgStore,
    clock: &ProjectionClock,
    cancel: &tokio_util::sync::CancellationToken,
) -> anyhow::Result<()> {
    let control = Control::new(clock, Duration::from_secs(30), cancel);
    let checkpoint = execution.checkpoint().await?.position;
    let next = source
        .read(source.scope(), checkpoint, BatchLimit::new(1)?)
        .await?;
    projection.inject_next_fault(PgFault::CommitPending);
    let short = Control::new(
        clock,
        rss_projection::Timer::now(clock) + Duration::from_millis(100),
        cancel,
    );
    assert!(
        execution
            .execute(checkpoint, &next[0], &short)
            .await
            .is_err()
    );
    assert_eq!(execution.checkpoint().await?.position, checkpoint);
    assert_eq!(values(f, "live", "inside").await?.len(), 1);
    projection.inject_next_fault(PgFault::CommitUnknownAfterAck);
    assert!(
        execution
            .execute(checkpoint, &next[0], &control)
            .await
            .is_err()
    );
    assert!(values(f, "live", "inside").await?.is_empty());
    Ok(())
}
async fn resumed_projection(
    f: &Fixture,
    input: &Inputs,
    execution: &Session,
    scope: &ProjectionScope,
    control: &Control<'_, ProjectionClock>,
) -> anyhow::Result<()> {
    let Inputs {
        store,
        source,
        first,
        saved,
        ..
    } = input;
    let restart = f.projection().await?;
    let resumed = restart.projection(
        restart.takeover(scope, control).await?,
        model::Facts::new(source.clone()),
    )?;
    let report = rss_projection::run(
        source.as_ref(),
        &resumed,
        control,
        RunLimit::new(BatchLimit::new(10)?, 50)?,
    )
    .await
    .into_result()?;
    assert_eq!(report.applied, 0);
    assert!(execution.checkpoint().await.is_err());
    let retry = store.receive(first, deadline()).await?;
    assert!(matches!(retry, ReceiveOutcome::Replay(_)));
    assert_eq!(retry.record().received_at(), saved.record().received_at());
    assert_eq!(values(f, "live", "outside").await?.len(), 1);
    Ok(())
}
pub async fn ordered_visibility(f: &Fixture) -> anyhow::Result<()> {
    let store = f.store().await?;
    let source = f.source(store.clone(), TENANT)?;
    for rollback in [false, true] {
        concurrent_pair(f, &store, &source, rollback).await?;
    }
    Ok(())
}
async fn parallel_inputs(
    store: &ObsStore,
    rollback: bool,
) -> anyhow::Result<(
    rss_observation::VerifiedBatch,
    rss_observation::VerifiedBatch,
)> {
    let name = if rollback { "rollback" } else { "commit" };
    let a = scope(TENANT, &format!("first-{name}"), "r", "agent", "e")?;
    let b = scope(TENANT, &format!("second-{name}"), "r", "agent", "e")?;
    activate(store, &a, None).await?;
    activate(store, &b, None).await?;
    let input = batch(&a, "first", 0, "all", Body::Snapshot(vec![]))?;
    let other = batch(&b, "second", 0, "all", Body::Snapshot(vec![]))?;
    Ok((input, other))
}
async fn concurrent_pair(
    f: &Fixture,
    store: &ObsStore,
    source: &ObsSource,
    rollback: bool,
) -> anyhow::Result<()> {
    let (input, other) = parallel_inputs(store, rollback).await?;
    let before = source.high_water(source.scope()).await?;
    // Use the actual commit funnel, but deliberately hold the first transaction before COMMIT.
    let mut tx = f.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(TENANT)
        .execute(&mut *tx)
        .await?;
    stage(&mut tx, &input).await?;
    let pending = store.receive(&other, deadline());
    tokio::pin!(pending);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut pending)
            .await
            .is_err()
    );
    assert_invisible(source, before).await?;
    settle(tx, rollback).await?;
    pending.await?;
    let events = source
        .read(source.scope(), before, BatchLimit::new(10)?)
        .await?;
    assert_eq!(events.len(), if rollback { 1 } else { 2 });
    assert_positions(&events, before);
    Ok(())
}
async fn settle(tx: sqlx::Transaction<'_, sqlx::Postgres>, rollback: bool) -> anyhow::Result<()> {
    if rollback {
        tx.rollback().await?;
    } else {
        tx.commit().await?;
    }
    Ok(())
}
async fn assert_invisible(source: &ObsSource, before: Option<Position>) -> anyhow::Result<()> {
    assert_eq!(source.high_water(source.scope()).await?, before);
    assert!(
        source
            .read(source.scope(), before, BatchLimit::new(10)?)
            .await?
            .is_empty()
    );
    Ok(())
}
fn assert_positions(events: &[Event], before: Option<Position>) {
    let start = before.map_or(0, |p| p.get());
    for (offset, event) in events.iter().enumerate() {
        assert_eq!(event.position().get(), start + 1 + offset as u64);
    }
}
pub async fn stage(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    input: &rss_observation::VerifiedBatch,
) -> anyhow::Result<()> {
    let row = sqlx::query("SELECT state,policy FROM rss_observation.lock_stream($1)")
        .bind(input.scope().encode()?)
        .fetch_one(&mut **tx)
        .await?;
    let state = rss_observation::State::decode(row.try_get("state")?)?;
    let policy = rss_observation::Policy::decode(row.try_get("policy")?)?;
    let decision = state.advance(input.batch(), 100, &policy)?;
    sqlx::query(
        "SELECT rss_observation.commit_batch($1,$2,$3::numeric,$4,$5,$6,$7,$8,$9::numeric,$10)",
    )
    .bind(input.scope().encode()?)
    .bind(input.batch().id().as_str())
    .bind(input.batch().sequence().to_string())
    .bind(input.batch().encode())
    .bind(input.fingerprint().as_slice())
    .bind(100_i64)
    .bind(policy.encode()?)
    .bind(decision.encode()?)
    .bind(state.revision().to_string())
    .bind(decision.outcome().is_applicable())
    .execute(&mut **tx)
    .await?;
    Ok(())
}
struct Large {
    store: Arc<ObsStore>,
    source: Arc<ObsSource>,
    stream: rss_observation::Scope,
    input: rss_observation::VerifiedBatch,
    receipt: ReceiveOutcome,
    event: Event,
}
pub async fn references_and_isolation(f: &Fixture) -> anyhow::Result<()> {
    let large = seed_large(f).await?;
    validate_large(&large).await?;
    reject_changed(f, &large).await?;
    lifecycle_records(&large).await?;
    ack_loss(&large.store).await?;
    isolated_effects(f, &large.source).await?;
    Ok(())
}
async fn seed_large(f: &Fixture) -> anyhow::Result<Large> {
    let store = f.store().await?;
    let source = f.source(store.clone(), OTHER)?;
    let stream = scope(OTHER, "large", "注册一", "采集器", "epoch")?;
    activate(&store, &stream, None).await?;
    let changes = (0..15)
        .map(|n| Ok(Change::upsert(Id::new(format!("{n}"))?, vec![255; 65536])))
        .collect::<Result<Vec<_>, rss_observation::Error>>()?;
    let input = batch(&stream, &"批".repeat(80), 0, "all", Body::Snapshot(changes))?;
    assert!(input.batch().encode().len() > 3_000_000);
    let receipt = store.receive(&input, deadline()).await?;
    let events = source
        .read(source.scope(), None, BatchLimit::new(1000)?)
        .await?;
    assert_eq!(events.len(), 1);
    let event = events[0].clone();
    Ok(Large {
        store,
        source,
        stream,
        input,
        receipt,
        event,
    })
}
async fn validate_large(large: &Large) -> anyhow::Result<()> {
    let Large {
        source,
        receipt,
        event,
        ..
    } = large;
    assert!(event.payload().len() < 4096);
    assert_eq!(event.id().len(), 64);
    let resolved = source.resolve(event, deadline()).await?;
    assert_eq!(resolved.record().batch(), receipt.record().batch());
    assert_eq!(
        source
            .read(source.scope(), None, BatchLimit::new(1)?)
            .await?[0],
        *event
    );
    Ok(())
}
async fn reject_changed(f: &Fixture, large: &Large) -> anyhow::Result<()> {
    let Large {
        store,
        source,
        event,
        ..
    } = large;
    let wrong = f.source(store.clone(), TENANT)?;
    assert!(
        source
            .read(wrong.scope(), None, BatchLimit::new(1)?)
            .await
            .is_err()
    );
    assert!(wrong.resolve(event, deadline()).await.is_err());
    for payload in [
        b"{}".to_vec(),
        event.payload().iter().copied().chain([b' ']).collect(),
    ] {
        let changed = Event::new(
            event.source().clone(),
            event.position(),
            event.id(),
            payload,
        )?;
        assert!(source.resolve(&changed, deadline()).await.is_err());
    }
    let changed = Event::new(
        event.source().clone(),
        Position::new(event.position().get() + 1)?,
        event.id(),
        event.payload().to_vec(),
    )?;
    assert!(source.resolve(&changed, deadline()).await.is_err());
    Ok(())
}
async fn lifecycle_records(large: &Large) -> anyhow::Result<()> {
    let Large {
        store,
        source,
        stream,
        input,
        receipt,
        event,
    } = large;
    // Same batch identity across source/registration/epoch never aliases a prior fact.
    for (registration, producer, epoch, revision) in [
        ("注册一", "another", "epoch", 1),
        ("注册一", "another", "new-epoch", 2),
        ("注册二", "another", "epoch", 3),
    ] {
        let next = scope(OTHER, "large", registration, producer, epoch)?;
        activate(store, &next, Some(revision)).await?;
        store
            .receive(
                &batch(
                    &next,
                    input.batch().id().as_str(),
                    0,
                    "all",
                    Body::Snapshot(vec![up("0", 4)?]),
                )?,
                deadline(),
            )
            .await?;
    }
    let all = source
        .read(source.scope(), None, BatchLimit::new(10)?)
        .await?;
    let ids = all
        .iter()
        .map(|e| e.id())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(ids.len(), 4);
    assert!(source.resolve(event, deadline()).await.is_ok());
    assert_eq!(
        store
            .lookup(
                &ReadGrant::verify(&Trusted, stream.clone())?,
                input.batch().id(),
                deadline()
            )
            .await?
            .map(|r| r.received_at()),
        Some(receipt.record().received_at())
    );
    Ok(())
}
async fn ack_loss(store: &ObsStore) -> anyhow::Result<()> {
    store.inject_next_fault(rss_observation_postgres::Fault::CommitAckLost);
    let stream = scope(OTHER, "ack", "r", "agent", "e")?;
    activate(store, &stream, None).await?;
    store.inject_next_fault(rss_observation_postgres::Fault::CommitAckLost);
    let input = batch(&stream, "ack", 0, "all", Body::Snapshot(vec![]))?;
    assert!(matches!(
        store.receive(&input, deadline()).await?,
        ReceiveOutcome::Replay(_)
    ));
    Ok(())
}
async fn isolated_effects(f: &Fixture, source: &Arc<ObsSource>) -> anyhow::Result<()> {
    let projection = f.projection().await?;
    let clock = ProjectionClock(rss_observation::Clock::now(&Clock));
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(30), &cancel);
    let scope = ProjectionScope::new(source.scope().clone(), "facts", "isolation")?;
    projection
        .initialize(
            &scope,
            GenerationStart::beginning(),
            ReplayBound::Live,
            &control,
        )
        .await?;
    let execution = projection.projection(
        projection.takeover(&scope, &control).await?,
        model::Facts::new(source.clone()),
    )?;
    let report = rss_projection::run(
        source.as_ref(),
        &execution,
        &control,
        RunLimit::new(BatchLimit::new(10)?, 20)?,
    )
    .await
    .into_result()?;
    assert_eq!(report.applied, 5);
    let counts:(i64,i64)=sqlx::query_as("SELECT count(*),count(DISTINCT scope) FROM public.observation_facts WHERE tenant_id=$1::uuid AND generation='isolation'").bind(OTHER).fetch_one(&f.admin).await?;
    assert_eq!(counts, (18, 4));
    assert_eq!(values(f, "live", "outside").await?.len(), 1);
    Ok(())
}
