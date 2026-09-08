//! The owning integration test provisions the application fixture; see rss-examples README.
// SHA-256 of the application declaration "counter:sum-first-payload-byte:schema-v1".
const DEFINITION: rss_projection::DefinitionIdentity = rss_projection::DefinitionIdentity::new([
    189, 214, 58, 242, 104, 235, 47, 212, 61, 133, 205, 45, 244, 157, 158, 222, 11, 5, 102, 165,
    56, 173, 45, 32, 8, 173, 6, 218, 162, 142, 19, 36,
]);
use rss_projection::{
    BatchLimit, Control, Event, GenerationStart, ProjectionScope, ReplayBound, RunLimit, Source,
    SourceScope, Timer,
};
use rss_projection_postgres::{
    PgEffect, PgEffectOutcome, PgOperationError, PgStore, PgTransaction,
};
use rss_request_context::TenantId;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

struct Clock(Instant);
impl Clock {
    #[allow(clippy::disallowed_methods)]
    // reason: concrete application clock owns its injected monotonic time origin.
    fn new() -> Self {
        Self(Instant::now())
    }
}
impl Timer for Clock {
    #[allow(clippy::disallowed_methods)]
    // reason: implementation of the caller-injected clock.
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
    async fn sleep_until(&self, deadline: Duration) {
        tokio::time::sleep(deadline.saturating_sub(self.now())).await;
    }
}
struct Counter;
impl PgEffect for Counter {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        scope: &ProjectionScope,
        event: &Event,
    ) -> Result<PgEffectOutcome, PgOperationError> {
        let scope = scope.clone();
        let amount = i64::from(
            *event
                .payload()
                .first()
                .ok_or(PgOperationError::rejected())?,
        );
        tx.with_connection(move |conn| Box::pin(async move {
            sqlx::query("INSERT INTO public.projection_demo_counts(tenant_id,generation,total) VALUES($1::uuid,$2,$3) ON CONFLICT(tenant_id,generation) DO UPDATE SET total=projection_demo_counts.total+EXCLUDED.total")
                .bind(scope.source().tenant().to_string()).bind(scope.generation()).bind(amount).execute(conn).await?;
            Ok(())
        })).await?;
        Ok(PgEffectOutcome::Applied)
    }
}
pub async fn demo(store: &PgStore, tenant: TenantId) -> anyhow::Result<()> {
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(30), &cancel);
    let source = SourceScope::new(tenant, "demo")?;
    for id in ["one", "two", "one"] {
        let source = source.clone();
        let tenant = source.tenant();
        store.local_tx(&source.clone(),&control,move |tx| Box::pin(async move {
            // Acquire the source allocator before business rows. Retries retain the same fact ID.
            tx.append(&source,id,&[1]).await?;
            tx.with_connection(move |conn| Box::pin(async move {
                sqlx::query("INSERT INTO public.projection_demo_facts(tenant_id,event_id) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING")
                    .bind(tenant.to_string()).bind(id).execute(conn).await?; Ok(())
            })).await
        })).await?;
    }
    let live = ProjectionScope::new(source.clone(), "counter", "v1")?;
    store
        .initialize(
            &live,
            &DEFINITION,
            GenerationStart::beginning(),
            ReplayBound::Live,
            &control,
        )
        .await?;
    let worker = store.projection(store.takeover(&live, &DEFINITION, &control).await?, Counter)?;
    use rss_projection::Execution as _;
    let high_water = control.run(store.high_water(&source)).await?;
    let limits = RunLimit::new(BatchLimit::new(100)?, 1000)?;
    let first = rss_projection::run(store, &worker, &control, limits)
        .await
        .into_result()?;
    anyhow::ensure!(
        first.applied == 2,
        "initial projection did not apply both events"
    );
    anyhow::ensure!(
        control.run(worker.checkpoint()).await?.position == high_water,
        "checkpoint not persisted"
    );
    // A second invocation resumes the same checkpoint and produces no extra effect.
    let resumed = rss_projection::run(store, &worker, &control, limits)
        .await
        .into_result()?;
    anyhow::ensure!(resumed.applied == 0, "resume duplicated effects");
    let replay = ProjectionScope::new(source.clone(), "counter", "v2")?;
    let bound = control.run(store.high_water(&source)).await?;
    store
        .initialize(
            &replay,
            &DEFINITION,
            GenerationStart::beginning(),
            ReplayBound::Through(bound),
            &control,
        )
        .await?;
    let worker = store.projection(
        store.takeover(&replay, &DEFINITION, &control).await?,
        Counter,
    )?;
    let replayed = rss_projection::run(store, &worker, &control, limits)
        .await
        .into_result()?;
    anyhow::ensure!(replayed.applied == 2, "replay did not apply both facts");
    anyhow::ensure!(
        control.run(worker.checkpoint()).await?.position == bound,
        "replay checkpoint missing"
    );
    let tenant = source.tenant();
    let totals=store.local_tx(&source,&control,move |tx| Box::pin(async move {
        tx.with_connection(move |conn| Box::pin(async move {
            sqlx::query_as::<_,(String,i64)>("SELECT generation,total FROM public.projection_demo_counts WHERE tenant_id=$1::uuid ORDER BY generation")
                .bind(tenant.to_string()).fetch_all(conn).await
        })).await
    })).await?;
    println!("generation totals: {totals:?}");
    anyhow::ensure!(
        totals == vec![("v1".into(), 2), ("v2".into(), 2)],
        "unexpected demo totals"
    );
    Ok(())
}

/// Application fixture, installed by the non-consumer test owner.
pub const FIXTURE_SQL: &str = include_str!("../fixtures/projection.sql");

pub async fn run(input: crate::pg::Input) -> anyhow::Result<()> {
    let store = PgStore::new(input.pool().await?).await?;
    let result = demo(&store, TenantId::parse(&input.tenant)?).await;
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(5), &cancel);
    let closed = store.close(&control).await;
    result?;
    anyhow::ensure!(
        closed == rss_projection_postgres::CloseOutcome::Drained,
        "projection close failed"
    );
    Ok(())
}
