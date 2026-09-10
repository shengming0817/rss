//! Run against an empty example database provisioned with handoff/setup.sql.
#[path = "observation/model.rs"]
mod model;
use rss_observation::{
    Access, Authority, Batch, Body, Change, Clock as _, Coverage, Epoch, Error, Id,
    JournalReadGrant, LifecycleGrant, ObservationStore, Policy, Registration, Scope, VerifiedBatch,
};
use rss_observation_postgres::{PgSource, PgStore};
use rss_projection::{
    BatchLimit, Control, GenerationStart, ProjectionScope, ReplayBound, RunLimit,
};
use rss_request_context::{Deadline, TenantId};

use std::{
    sync::Arc,
    time::{Duration, Instant},
};
struct Clock(Instant);
impl rss_observation::Clock for Clock {
    #[allow(clippy::disallowed_methods)] // reason: example host provides the actual monotonic clock.
    fn now(&self) -> Instant {
        Instant::now()
    }
}
impl rss_projection::Timer for Clock {
    #[allow(clippy::disallowed_methods)] // reason: injected host Timer owns its monotonic origin and elapsed-time calculation.
    fn now(&self) -> Duration {
        rss_observation::Clock::now(self).duration_since(self.0)
    }
    async fn sleep_until(&self, end: Duration) {
        tokio::time::sleep(end.saturating_sub(rss_projection::Timer::now(self))).await;
    }
}
struct DemoAuthority;
impl Authority for DemoAuthority {
    fn authorize(&self, _: Access<'_>) -> Result<(), Error> {
        Ok(())
    } // reason: local fixture; products must authenticate and authorize each request.
}
pub async fn run(input: crate::pg::Input) -> anyhow::Result<()> {
    let pool = input.pool().await?;
    #[allow(clippy::disallowed_methods)] // reason: this host owns the injected clock origin.
    let clock = Clock(Instant::now());
    let store = Arc::new(
        PgStore::new(
            pool,
            Clock(clock.0),
            Deadline::at(clock.now() + Duration::from_secs(30)),
        )
        .await?,
    );
    let tenant = TenantId::parse(&input.tenant)?;
    let scope = Scope::new(
        tenant,
        Id::new("example")?,
        Registration::new("registration-1")?,
        Id::new("agent")?,
        Id::new("facts")?,
        Epoch::new("epoch-1")?,
    );
    let deadline = Deadline::at(clock.now() + Duration::from_secs(60));
    store
        .activate(
            &LifecycleGrant::verify(&DemoAuthority, scope.clone())?,
            None,
            &Policy::new(86400, 3600, 3600)?,
            deadline,
        )
        .await?;
    receive_batches(store.as_ref(), &scope, deadline).await?;
    let source = Arc::new(PgSource::new(
        store.clone(),
        JournalReadGrant::verify(&DemoAuthority, tenant)?,
        rss_projection::SourceScope::new(tenant, "rss.observation.v1")?,
    )?);
    let projection = rss_projection_postgres::PgStore::new(input.pool().await?).await?;
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(30), &cancel);
    let scope = ProjectionScope::new(source.scope().clone(), "facts", "example-v1")?;
    projection
        .initialize(
            &scope,
            &model::DEFINITION,
            GenerationStart::beginning(),
            ReplayBound::Live,
            &control,
        )
        .await?;
    for expected in [3, 0] {
        let execution = projection.projection(
            projection
                .takeover(&scope, &model::DEFINITION, &control)
                .await?,
            model::Facts::new(source.clone()),
        )?;
        let report = rss_projection::run(
            source.as_ref(),
            &execution,
            &control,
            RunLimit::new(BatchLimit::new(10)?, 100)?,
        )
        .await
        .into_result()?;
        anyhow::ensure!(
            report.applied == expected && report.position.is_some(),
            "handoff progress mismatch: expected {expected}, got {} at {:?}",
            report.applied,
            report.position
        );
    }
    let projection_closed = projection.close(&control).await;
    let observation_closed = store.close(deadline).await;
    anyhow::ensure!(
        projection_closed == rss_projection_postgres::CloseOutcome::Drained,
        "projection pool did not drain: {projection_closed:?}"
    );
    observation_closed?;
    Ok(())
}

async fn receive_batches(
    store: &PgStore<Clock>,
    scope: &Scope,
    deadline: Deadline,
) -> anyhow::Result<()> {
    let coverage = Coverage::new(
        Id::new("all")?,
        Id::new("v1")?,
        Id::new("catalog")?,
        Id::new("bytes")?,
    );
    for (id, sequence, body) in [
        (
            "snapshot",
            0,
            Body::Snapshot(vec![
                Change::upsert(Id::new("a")?, vec![1]),
                Change::upsert(Id::new("b")?, vec![2]),
            ]),
        ),
        (
            "delta",
            1,
            Body::Delta {
                baseline: Id::new("snapshot")?,
                previous: 0,
                changes: vec![Change::delete(Id::new("b")?)],
            },
        ),
        (
            "gap",
            3,
            Body::Delta {
                baseline: Id::new("snapshot")?,
                previous: 2,
                changes: vec![],
            },
        ),
        ("recovery", 4, Body::Snapshot(vec![])),
    ] {
        let batch = Batch::new(
            Id::new(id)?,
            sequence,
            rss_contract::Timepoint::try_from(100)?,
            coverage.clone(),
            body,
        )?;
        let verified = VerifiedBatch::verify(&DemoAuthority, scope.clone(), batch)?;
        let first = store.receive(&verified, deadline).await?;
        let replay = store.receive(&verified, deadline).await?;
        anyhow::ensure!(
            matches!(first, rss_observation::ReceiveOutcome::Accepted(_))
                && matches!(replay, rss_observation::ReceiveOutcome::Replay(_))
                && first.record().decision().encode()? == replay.record().decision().encode()?,
            "duplicate observation changed its receipt"
        );
    }
    Ok(())
}
