#[path = "../../../crates/projection-postgres/examples/counter/model.rs"]
mod counter_example;
mod process;
mod scenarios;
use rss_projection::*;
use rss_projection_postgres::*;
use rss_request_context::TenantId;
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

struct Clock(Instant);
impl Clock {
    #[allow(clippy::disallowed_methods)]
    // reason: concrete injected test clock owns the monotonic time source.
    fn new() -> Self {
        Self(Instant::now())
    }
}
impl Timer for Clock {
    #[allow(clippy::disallowed_methods)]
    // reason: concrete injected test clock reads its own monotonic origin.
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
    async fn sleep_until(&self, deadline: Duration) {
        tokio::time::sleep(deadline.saturating_sub(self.now())).await;
    }
}
fn scope(name: &str, tenant: &str) -> anyhow::Result<ProjectionScope> {
    Ok(ProjectionScope::new(
        SourceScope::new(TenantId::parse(tenant)?, name)?,
        "counter",
        "v1",
    )?)
}
const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const OTHER: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d478";
struct Counter;
impl PgEffect for Counter {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        scope: &ProjectionScope,
        _: &Event,
    ) -> Result<PgEffectOutcome, PgOperationError> {
        increment(tx, scope).await?;
        Ok(PgEffectOutcome::Applied)
    }
}
async fn increment(
    tx: &mut PgTransaction<'_>,
    scope: &ProjectionScope,
) -> Result<(), PgOperationError> {
    let scope = scope.clone();
    tx.with_connection(move |conn| Box::pin(async move {
        sqlx::query("INSERT INTO public.counts(tenant_id,source_id,projection_id,generation,n) VALUES($1::uuid,$2,$3,$4,1) ON CONFLICT(tenant_id,source_id,projection_id,generation) DO UPDATE SET n=counts.n+1")
            .bind(scope.source().tenant().to_string()).bind(scope.source().source()).bind(scope.projection()).bind(scope.generation()).execute(conn).await?;
        Ok(())
    })).await
}
async fn count(owner: &PgPool, scope: &ProjectionScope) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar::<_,i64>("SELECT n FROM public.counts WHERE tenant_id=$1::uuid AND source_id=$2 AND projection_id=$3 AND generation=$4")
        .bind(scope.source().tenant().to_string()).bind(scope.source().source()).bind(scope.projection()).bind(scope.generation()).fetch_optional(owner).await?.unwrap_or(0))
}
async fn append(
    store: &PgStore,
    scope: &ProjectionScope,
    id: &str,
    bytes: &[u8],
    control: &Control<'_, Clock>,
) -> Result<Position, Error> {
    let source = scope.source().clone();
    let id = id.to_owned();
    let bytes = bytes.to_vec();
    store
        .local_tx(scope.source(), control, move |tx| {
            Box::pin(async move { tx.append(&source, &id, &bytes).await })
        })
        .await
}
async fn session(
    store: &PgStore,
    scope: &ProjectionScope,
    control: &Control<'_, Clock>,
) -> Result<PgProjection<Counter>, Error> {
    store
        .initialize(
            scope,
            GenerationStart::beginning(),
            ReplayBound::Live,
            control,
        )
        .await?;
    store.projection(store.takeover(scope, control).await?, Counter)
}
fn event(scope: &ProjectionScope, position: u64, id: &str, bytes: &[u8]) -> Result<Event, Error> {
    Event::new(
        scope.source().clone(),
        Position::new(position)?,
        id,
        bytes.to_vec(),
    )
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn projection_postgres_suite() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(240), async {
        let network = testkit::bridge_network("projection-pg").await?;
        let fixture = testkit::postgres_tls(testkit::NetworkAttachment { network: network.name(), dns_name: "projection-pg" }, testkit::PgTlsServerIdentity::MatchingHost).await?;
        let params = fixture.params();
        let base = PgConnectOptions::new().host(&params.host).port(params.port).database(&params.database)
            .ssl_mode(PgSslMode::VerifyFull).ssl_root_cert_from_pem(fixture.ca_pem().as_bytes().to_vec());
        let owner = PgPoolOptions::new().max_connections(5).connect_with(base.clone().username(&params.username).password(&params.password)).await?;
        sqlx::raw_sql("CREATE ROLE projection_owner NOLOGIN NOSUPERUSER NOBYPASSRLS; CREATE ROLE projection_runtime LOGIN PASSWORD 'fixture-only' NOSUPERUSER NOBYPASSRLS; GRANT CREATE ON DATABASE rss_test TO projection_owner;").execute(&owner).await?;
        let mut migration = owner.acquire().await?;
        sqlx::raw_sql("SET ROLE projection_owner").execute(&mut *migration).await?;
        sqlx::raw_sql(MIGRATION_SQL).execute(&mut *migration).await?;
        sqlx::raw_sql("RESET ROLE; GRANT USAGE ON SCHEMA rss_projection TO projection_runtime; GRANT SELECT ON ALL TABLES IN SCHEMA rss_projection TO projection_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_projection TO projection_runtime;").execute(&mut *migration).await?;
        drop(migration);
        sqlx::raw_sql("CREATE TABLE public.counts(tenant_id uuid NOT NULL,source_id text NOT NULL,projection_id text NOT NULL,generation text NOT NULL,n bigint NOT NULL,PRIMARY KEY(tenant_id,source_id,projection_id,generation)); ALTER TABLE public.counts ENABLE ROW LEVEL SECURITY; ALTER TABLE public.counts FORCE ROW LEVEL SECURITY; CREATE POLICY tenant_scope ON public.counts USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid); GRANT SELECT,INSERT,UPDATE ON public.counts TO projection_runtime;").execute(&owner).await?;
        let disguised = PgPoolOptions::new().max_connections(1).after_connect(|conn, _| Box::pin(async move {
            sqlx::query("SET ROLE projection_runtime").execute(conn).await?; Ok(())
        })).connect_with(base.clone().username(&params.username).password(&params.password)).await?;
        let admission = PgStore::new(disguised.clone()).await;
        disguised.close().await;
        assert!(matches!(admission, Err(error) if error.kind() == ErrorKind::StorageContract), "administrator session must not hide behind SET ROLE");
        let runtime_options = base.username("projection_runtime").password("fixture-only");
        let pool = PgPoolOptions::new().max_connections(5).acquire_timeout(Duration::from_secs(5)).connect_with(runtime_options.clone()).await?;
        assert!(matches!(PgStore::new(owner.clone()).await, Err(error) if error.kind() == rss_projection::ErrorKind::StorageContract));
        let store = PgStore::new(pool.clone()).await?;
        let clock = Clock::new(); let cancel = CancellationToken::new();
        let control = Control::new(&clock, Duration::from_secs(180), &cancel);
        scenarios::rejects_dangerous_acl(&pool, &owner).await?;
        scenarios::borrowed_timeout_rolls_back(&pool, &store, &control).await?;
        scenarios::application_error_cannot_claim_settlement(&store, &control).await?;
        scenarios::filtered_receipts(&store, &owner, &control).await?;
        scenarios::atomic_recovery(&store, &owner, &control).await?;
        scenarios::external_recovery(&store, &control).await?;
        scenarios::direct_advance_obeys_control(&store, &control).await?;
        scenarios::baseline_receipts_prevent_cross_start_duplicates(&store,&owner,&control).await?;
        scenarios::invalid_baselines_are_atomic(&store,&owner,&control).await?;
        scenarios::isolation(&store, &pool, &owner, &control).await?;
        scenarios::ordered_append(&store, &control).await?;
        scenarios::borrowed_append_rolls_back(&pool, &store, &control).await?;
        scenarios::replay(&store, &owner, &control).await?;
        scenarios::takeover_waits_for_the_old_transaction(&store, &owner, &control).await?;
        scenarios::cancel_after_apply_discards_the_transaction(&store, &owner).await?;
        scenarios::interruption(&store, &owner).await?;
        process::crash(&store, &owner, &fixture, &control).await?;
        sqlx::raw_sql(include_str!("../../../crates/projection-postgres/examples/counter/read-model.sql")).execute(&owner).await?;
        counter_example::demo(&store).await?;
        scenarios::store_identity(&pool, &store, &control).await?;
        scenarios::bounded_close(&pool, &store, &control).await?;
        owner.close().await;
        drop(fixture); drop(network);
        Ok::<(),anyhow::Error>(())
    }).await??;
    Ok(())
}
