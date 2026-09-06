//! Application composition example. Provision examples/setup.sql first; see README.
use rss_projection::{
    BatchLimit, Control, Event, GenerationStart, ProjectionScope, ReplayBound, RunLimit, Source,
    SourceScope, Timer, run,
};
use rss_projection_postgres::{
    PgEffect, PgEffectOutcome, PgOperationError, PgStore, PgTransaction,
};
use rss_request_context::TenantId;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

pub(super) struct Clock(Instant);
impl Clock {
    #[allow(clippy::disallowed_methods)]
    // reason: concrete application clock owns its injected monotonic time origin.
    pub(super) fn new() -> Self {
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
pub async fn demo(store: &PgStore) -> anyhow::Result<()> {
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(30), &cancel);
    let source = SourceScope::new(
        TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?,
        "demo",
    )?;
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
            GenerationStart::beginning(),
            ReplayBound::Live,
            &control,
        )
        .await?;
    let worker = store.projection(store.takeover(&live, &control).await?, Counter)?;
    let limits = RunLimit::new(BatchLimit::new(100)?, 1000)?;
    println!("live: {:?}", run(store, &worker, &control, limits).await);
    // A second invocation resumes the same checkpoint and produces no extra effect.
    println!("resume: {:?}", run(store, &worker, &control, limits).await);
    let replay = ProjectionScope::new(source.clone(), "counter", "v2")?;
    let bound = control.run(store.high_water(&source)).await?;
    store
        .initialize(
            &replay,
            GenerationStart::beginning(),
            ReplayBound::Through(bound),
            &control,
        )
        .await?;
    let worker = store.projection(store.takeover(&replay, &control).await?, Counter)?;
    println!("replay: {:?}", run(store, &worker, &control, limits).await);
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
