use super::fixture::*;
use rss_observation::{Body, ErrorKind, Id, ObservationStore, ReadGrant};
use rss_projection::{BatchLimit, Source};
#[tokio::test]
async fn required_permissions_are_checked() -> anyhow::Result<()> {
    let f = Fixture::new(false).await?;
    for (revoke, restore) in [
        (
            "REVOKE USAGE ON SCHEMA rss_observation FROM handoff_runtime",
            "GRANT USAGE ON SCHEMA rss_observation TO handoff_runtime",
        ),
        (
            "REVOKE SELECT ON rss_observation.journals FROM handoff_runtime",
            "GRANT SELECT ON rss_observation.journals TO handoff_runtime",
        ),
        (
            "REVOKE SELECT ON rss_observation.batches FROM handoff_runtime",
            "GRANT SELECT ON rss_observation.batches TO handoff_runtime",
        ),
        (
            "REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_observation FROM handoff_runtime",
            "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_observation TO handoff_runtime",
        ),
    ] {
        sqlx::raw_sql(revoke).execute(&f.owner).await?;
        let admitted = f.store().await;
        sqlx::raw_sql(restore).execute(&f.owner).await?;
        assert!(admitted.is_err());
        assert!(f.store().await.is_ok());
    }
    Ok(())
}
#[tokio::test]
async fn exhausted_journal_rejects_every_new_report() -> anyhow::Result<()> {
    let f = Fixture::new(false).await?;
    let store = f.store().await?;
    let stream = scope(TENANT, "exhausted", "r", "source", "e")?;
    activate(&store, &stream, None).await?;
    let input = batch(&stream, "first", 0, "all", Body::Snapshot(vec![]))?;
    store.receive(&input, deadline()).await?;
    let grant = ReadGrant::verify(&Trusted, stream.clone())?;
    let before = store.state(&grant, deadline()).await?;
    sqlx::query("UPDATE rss_observation.journals SET last_position=9223372036854775807 WHERE tenant_id=$1::uuid").bind(TENANT).execute(&f.admin).await?;
    reject_exhausted(&store, &stream).await?;
    assert_eq!(store.state(&grant, deadline()).await?, before);
    assert!(matches!(
        store.receive(&input, deadline()).await?,
        rss_observation::ReceiveOutcome::Replay(_)
    ));
    let source = f.source(store, TENANT)?;
    assert_eq!(
        source
            .read(source.scope(), None, BatchLimit::new(10)?)
            .await?
            .len(),
        1
    );
    Ok(())
}
async fn reject_exhausted(
    store: &rss_observation_postgres::PgStore<Clock>,
    scope: &rss_observation::Scope,
) -> anyhow::Result<()> {
    for (id, body) in [
        ("snapshot", Body::Snapshot(vec![])),
        (
            "failed",
            Body::Failed {
                code: Id::new("offline")?,
            },
        ),
        ("partial", Body::Partial(vec![])),
    ] {
        let result = store
            .receive(&batch(scope, id, 1, "all", body)?, deadline())
            .await;
        assert_eq!(result.err().map(|e| e.kind()), Some(ErrorKind::Invariant));
        assert!(
            store
                .lookup(
                    &ReadGrant::verify(&Trusted, scope.clone())?,
                    &Id::new(id)?,
                    deadline()
                )
                .await?
                .is_none()
        );
    }
    Ok(())
}

#[tokio::test]
async fn permanent_resolver_failures_reject_the_effect() -> anyhow::Result<()> {
    use rss_projection::{Control, GenerationStart, ProjectionScope, ReplayBound};
    let f = Fixture::new(false).await?;
    let (source, event) = resolver_record(&f).await?;
    let projection = f.projection().await?;
    let clock = ProjectionClock(rss_observation::Clock::now(&Clock));
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = Control::new(&clock, std::time::Duration::from_secs(30), &cancel);
    let scope = ProjectionScope::new(source.scope().clone(), "facts", "reject")?;
    projection
        .initialize(
            &scope,
            &super::scenarios::model::DEFINITION,
            GenerationStart::beginning(),
            ReplayBound::Live,
            &control,
        )
        .await?;
    let execution = projection.projection(
        projection
            .takeover(&scope, &super::scenarios::model::DEFINITION, &control)
            .await?,
        super::scenarios::model::Facts::new(source.clone()),
    )?;
    reject_permanent(&f, &source, &execution, &control, &event).await
}
async fn resolver_record(
    f: &Fixture,
) -> anyhow::Result<(
    std::sync::Arc<rss_observation_postgres::PgSource<Clock>>,
    rss_projection::Event,
)> {
    let store = f.store().await?;
    let scope = scope(TENANT, "resolver", "r", "source", "e")?;
    activate(&store, &scope, None).await?;
    store
        .receive(
            &batch(&scope, "snapshot", 0, "all", Body::Snapshot(vec![]))?,
            deadline(),
        )
        .await?;
    let source = f.source(store, TENANT)?;
    let events = source
        .read(source.scope(), None, BatchLimit::new(1)?)
        .await?;
    Ok((source, events[0].clone()))
}
async fn reject_permanent(
    f: &Fixture,
    source: &rss_observation_postgres::PgSource<Clock>,
    execution: &impl rss_projection::Execution,
    control: &rss_projection::Control<'_, ProjectionClock>,
    event: &rss_projection::Event,
) -> anyhow::Result<()> {
    let invalid = rss_projection::Event::new(
        event.source().clone(),
        event.position(),
        event.id(),
        br#"{"version":2}"#.to_vec(),
    )?;
    assert_eq!(
        execution
            .execute(None, &invalid, control)
            .await
            .err()
            .map(|e| e.kind()),
        Some(rss_projection::ErrorKind::Rejected)
    );
    sqlx::raw_sql("REVOKE SELECT ON rss_observation.batches FROM handoff_runtime")
        .execute(&f.owner)
        .await?;
    let independent = source.resolve(event, deadline()).await;
    let atomic = execution.execute(None, event, control).await;
    sqlx::raw_sql("GRANT SELECT ON rss_observation.batches TO handoff_runtime")
        .execute(&f.owner)
        .await?;
    assert_eq!(
        independent.err().map(|e| e.kind()),
        Some(rss_projection::ErrorKind::StorageContract)
    );
    assert_eq!(
        atomic.err().map(|e| e.kind()),
        Some(rss_projection::ErrorKind::Rejected)
    );
    assert_eq!(execution.checkpoint().await?.position, None);
    Ok(())
}
