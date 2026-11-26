use super::fixture::*;
use rss_observation::{Body, ObservationStore};
use rss_projection::Source;
#[tokio::test]
async fn required_permissions_are_checked() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let can_read_admissions: bool = sqlx::query_scalar(
        "SELECT has_any_column_privilege(current_user,'rss_observation.admissions','SELECT')",
    )
    .fetch_one(&f.pool)
    .await?;
    assert!(!can_read_admissions);
    for (revoke, restore) in [
        (
            "REVOKE USAGE ON SCHEMA rss_observation FROM handoff_runtime",
            "GRANT USAGE ON SCHEMA rss_observation TO handoff_runtime",
        ),
        (
            "REVOKE SELECT ON rss_observation.streams FROM handoff_runtime",
            "GRANT SELECT ON rss_observation.streams TO handoff_runtime",
        ),
        (
            "REVOKE SELECT ON rss_observation.batches FROM handoff_runtime",
            "GRANT SELECT ON rss_observation.batches TO handoff_runtime",
        ),
        (
            "REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_observation FROM handoff_runtime",
            "GRANT EXECUTE ON FUNCTION rss_observation.activate(text,numeric,text,text), rss_observation.lock_stream(text), rss_observation.commit_batch(text,text,numeric,bytea,bytea,bigint,text,text,numeric,boolean) TO handoff_runtime",
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
async fn permanent_resolver_failures_reject_the_effect() -> anyhow::Result<()> {
    use rss_projection::{Control, GenerationStart, ProjectionScope, ReplayBound};
    let f = Fixture::new().await?;
    let (source, event) = resolver_record(&f).await?;
    let clock = ProjectionClock(rss_observation::Clock::now(&Clock));
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = Control::new(&clock, std::time::Duration::from_secs(30), &cancel);
    let projection = f.projection(&control).await?;
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
    std::sync::Arc<rss_observation_postgres::PgSource<Clock, rss_observation_postgres::LocalPages>>,
    rss_projection::EventWith<rss_observation_postgres::VerifiedObservation>,
)> {
    let budget_clock = ProjectionClock(rss_observation::Clock::now(&Clock));
    let budget_cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_projection::Control::new(
        &budget_clock,
        std::time::Duration::from_secs(60),
        &budget_cancel,
    );
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
    let events = expected_events(
        source
            .read(source.scope(), None, page_budget(1)?, &control)
            .await?,
    )?;
    Ok((source, events[0].clone()))
}
async fn reject_permanent(
    f: &Fixture,
    source: &rss_observation_postgres::PgSource<Clock, rss_observation_postgres::LocalPages>,
    execution: &impl rss_projection::Execution<
        Item = rss_projection::EventWith<rss_observation_postgres::VerifiedObservation>,
    >,
    control: &rss_projection::Control<'_, ProjectionClock>,
    event: &rss_projection::EventWith<rss_observation_postgres::VerifiedObservation>,
) -> anyhow::Result<()> {
    let invalid = rss_projection::Event::new(
        event.as_ref().source().clone(),
        event.as_ref().position(),
        event.as_ref().id(),
        br#"{"version":2}"#.to_vec(),
    )?;
    assert_eq!(
        source
            .resolve(&invalid, control)
            .await
            .err()
            .map(|e| e.kind()),
        Some(rss_projection::ErrorKind::InvalidInput)
    );
    sqlx::raw_sql("REVOKE SELECT ON rss_observation.batches FROM handoff_runtime")
        .execute(&f.owner)
        .await?;
    let independent = source.resolve(event.as_ref(), control).await;
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
    assert_eq!(execution.checkpoint(control).await?.position, None);
    Ok(())
}
