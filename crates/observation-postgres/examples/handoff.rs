//! Run against an empty example database provisioned with handoff/setup.sql.
#[path = "handoff/model.rs"]
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
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
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
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let options = std::env::var("DATABASE_URL")?
        .parse::<PgConnectOptions>()?
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(options.clone())
        .await?;
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
    let tenant = TenantId::parse("00000000-0000-0000-0000-000000000071")?;
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
        store
            .receive(
                &VerifiedBatch::verify(&DemoAuthority, scope.clone(), batch)?,
                deadline,
            )
            .await?;
    }
    let source = Arc::new(PgSource::new(
        store.clone(),
        JournalReadGrant::verify(&DemoAuthority, tenant)?,
    )?);
    let projection = rss_projection_postgres::PgStore::new(
        PgPoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await?,
    )
    .await?;
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(30), &cancel);
    let scope = ProjectionScope::new(source.scope().clone(), "facts", "example-v1")?;
    projection
        .initialize(
            &scope,
            GenerationStart::beginning(),
            ReplayBound::Live,
            &control,
        )
        .await?;
    for _ in 0..2 {
        let execution = projection.projection(
            projection.takeover(&scope, &control).await?,
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
        println!(
            "applied={} checkpoint={:?}",
            report.applied, report.position
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
