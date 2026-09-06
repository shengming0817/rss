mod messaging;
mod process;
mod scenarios;
mod transport;
use rss_reconcile::*;
use rss_reconcile_postgres::*;
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
    fn new() -> Self {
        Self(Instant::now())
    }
}
impl Timer for Clock {
    #[allow(clippy::disallowed_methods)]
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
    async fn sleep_until(&self, d: Duration) {
        tokio::time::sleep(d.saturating_sub(self.now())).await;
    }
}
const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const OTHER: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d478";
fn target(name: &str, tenant: &str) -> anyhow::Result<Target> {
    Ok(Target::new(
        Scope::new(TenantId::parse(tenant)?, name)?,
        "entity",
    )?)
}
async fn claim(
    store: &PgStore,
    t: &Target,
    lease: Duration,
    c: &Control<'_, Clock>,
) -> anyhow::Result<PgClaim> {
    let mut batch = store.claim_due(t.scope(), 1, lease, c).await?;
    anyhow::ensure!(
        batch.len() == 1,
        "expected one due claim for {}",
        t.scope().reconciler()
    );
    Ok(batch.remove(0))
}
async fn effect(tx: &mut PgTransaction<'_>, id: String) -> Result<(), PgOperationError> {
    let tenant = tx.tenant().to_string();
    tx.with_connection(move |conn|Box::pin(async move {
        sqlx::query("INSERT INTO public.effects(tenant_id,id,n) VALUES($1::uuid,$2,1) ON CONFLICT(tenant_id,id) DO UPDATE SET n=effects.n+1").bind(tenant).bind(id).execute(conn).await?;Ok(())
    })).await
}
async fn count(owner: &PgPool, id: &str) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT coalesce(sum(n),0)::bigint FROM public.effects WHERE id=$1",
    )
    .bind(id)
    .fetch_one(owner)
    .await?)
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconcile_postgres_suite() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(240),async {
        let network=testkit::bridge_network("reconcile-pg").await?;
        let fixture=testkit::postgres_tls(testkit::NetworkAttachment{network:network.name(),dns_name:"reconcile-pg"},testkit::PgTlsServerIdentity::MatchingHost).await?;
        let params=fixture.params();let base=PgConnectOptions::new().host(&params.host).port(params.port).database(&params.database).ssl_mode(PgSslMode::VerifyFull).ssl_root_cert_from_pem(fixture.ca_pem().as_bytes().to_vec());
        let owner=PgPoolOptions::new().max_connections(5).connect_with(base.clone().username(&params.username).password(&params.password)).await?;
        sqlx::raw_sql("CREATE ROLE reconcile_owner NOLOGIN NOSUPERUSER NOBYPASSRLS; CREATE ROLE reconcile_runtime LOGIN PASSWORD 'fixture-only' NOSUPERUSER NOBYPASSRLS; GRANT CREATE ON DATABASE rss_test TO reconcile_owner; CREATE TABLE public.reconcile_targets(legacy boolean);").execute(&owner).await?;
        let options=base.username("reconcile_runtime").password("fixture-only");let pool=PgPoolOptions::new().max_connections(6).acquire_timeout(Duration::from_secs(2)).connect_with(options.clone()).await?;
        let clock=Clock::new();let cancel=CancellationToken::new();let control=Control::new(&clock,Duration::from_secs(210),&cancel);
        assert!(matches!(PgStore::new(pool.clone(),&control).await,Err(e) if e.kind()==ErrorKind::StorageContract));
        let mut migration=owner.acquire().await?;sqlx::raw_sql("SET ROLE reconcile_owner").execute(&mut *migration).await?;
        sqlx::raw_sql(MIGRATION_SQL).execute(&mut *migration).await?;
        sqlx::raw_sql("RESET ROLE; GRANT USAGE ON SCHEMA rss_reconcile TO reconcile_runtime; GRANT SELECT ON ALL TABLES IN SCHEMA rss_reconcile TO reconcile_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_reconcile TO reconcile_runtime;").execute(&mut *migration).await?;drop(migration);
        sqlx::raw_sql("CREATE TABLE public.effects(tenant_id uuid NOT NULL,id text NOT NULL,n bigint NOT NULL,PRIMARY KEY(tenant_id,id)); ALTER TABLE public.effects ENABLE ROW LEVEL SECURITY; ALTER TABLE public.effects FORCE ROW LEVEL SECURITY; CREATE POLICY tenant_scope ON public.effects USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid); GRANT SELECT,INSERT,UPDATE ON public.effects TO reconcile_runtime;").execute(&owner).await?;
        let absent:Option<String>=sqlx::query_scalar("SELECT to_regnamespace('rss_transactional_messaging')::text").fetch_one(&owner).await?;assert!(absent.is_none());
        assert!(matches!(PgStore::new(owner.clone(),&control).await,Err(e) if e.kind()==ErrorKind::StorageContract));
        let store=PgStore::new(pool.clone(),&control).await?;
        scenarios::run(&store,&pool,&owner,&control).await?;
        process::run(&store,&owner,&fixture,&control).await?;
        transport::run(&owner,options.clone(),&control).await?;
        messaging::run(&store,&owner,&fixture,&control).await?;
        assert_eq!(store.close(&control).await,CloseOutcome::Drained);owner.close().await;drop(fixture);drop(network);Ok::<(),anyhow::Error>(())
    }).await??;
    Ok(())
}
