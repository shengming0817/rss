//! Count completed SQLx statements on just the measured operation's future.
use crate::{federation_support::*, support::*};
use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
    instrument::WithSubscriber,
};
use tracing_subscriber::{
    Layer,
    layer::{Context, SubscriberExt},
};

#[derive(Default)]
struct Sql {
    statements: AtomicUsize,
    candidates: AtomicUsize,
    transactions: AtomicUsize,
    writes: AtomicUsize,
}
struct Observer(Arc<Sql>);
#[derive(Default)]
struct Observed {
    binding: bool,
    scan: bool,
    rows: usize,
    write: bool,
}
impl Visit for Observed {
    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "rows_returned" {
            self.rows = value as usize;
        }
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if matches!(field.name(), "db.statement" | "summary") {
            let sql = format!("{value:?}");
            self.scan |= sql.contains("provider_id<=$3") || sql.contains("SELECT provider_id FROM identity_authority.providers WHERE tenant_id=$1::uuid ORDER BY provider_id LIMIT $2");
            self.binding |= sql.contains("set_config('rss.storage_target'");
            self.write |= sql.contains("identity_authority.tenants WHERE tenant_id=")
                && sql.contains("FOR UPDATE");
        }
    }
}
impl<S: Subscriber> Layer<S> for Observer {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        if event.metadata().target() == "sqlx::query" {
            let mut q = Observed::default();
            event.record(&mut q);
            if q.scan {
                self.0.candidates.fetch_add(q.rows, Ordering::Relaxed);
            }
            self.0.statements.fetch_add(1, Ordering::Relaxed);
            self.0
                .transactions
                .fetch_add(usize::from(q.binding), Ordering::Relaxed);
            self.0
                .writes
                .fetch_add(usize::from(q.write), Ordering::Relaxed);
        }
    }
}
async fn measure<T>(
    f: &Fixture,
    label: &str,
    n: usize,
    op: impl Future<Output = Result<T, rss_identity_postgres::AuthorityError>>,
) -> anyhow::Result<(T, usize, usize)> {
    let sql = Arc::new(Sql::default());
    let before = f.oidc.checks.load(Ordering::Relaxed);
    let result = op
        .with_subscriber(tracing_subscriber::registry().with(Observer(sql.clone())))
        .await?;
    let calls = f.oidc.checks.load(Ordering::Relaxed) - before;
    let queries = sql.statements.load(Ordering::Relaxed);
    let tx = sql.transactions.load(Ordering::Relaxed);
    let locked = sql.writes.load(Ordering::Relaxed);
    let candidates = sql.candidates.load(Ordering::Relaxed);
    println!(
        "federation {label} candidates={candidates} n={n} statements={queries} transactions={tx} collection_locks={locked} fingerprints={calls}"
    );
    assert!(queries > 0 && tx > 0);
    Ok((result, queries, calls))
}
pub async fn run(f: &Fixture) -> anyhow::Result<()> {
    let s = service(f);
    let scope = binding(f.key.tenant);
    let mut previous = 0;
    let mut list_costs = None;
    for n in [1_usize, 24, 1023] {
        sqlx::query("INSERT INTO identity_authority.providers(tenant_id,provider_id,config_version,revocation_epoch,enabled,settings,assurance_profile,credential_version)
            SELECT $1::uuid,gen_random_uuid(),1,1,true,$2,$3,1 FROM generate_series(1,$4)")
            .bind(f.key.tenant.to_string()).bind(serde_json::to_value(settings())?).bind([1u8;32].as_slice()).bind(i32::try_from(n-previous)?).execute(&f.owner).await?;
        previous = n;
        let (providers, list, _) = measure(
            f,
            "management",
            n,
            s.list_providers(f.actor().await?, deadline()),
        )
        .await?;
        assert_eq!(providers.len(), n);
        let (security, security_cost, _) = measure(
            f,
            "security",
            n,
            s.current_session_security(f.actor().await?, deadline()),
        )
        .await?;
        assert!(security.eligible_step_up_providers.is_empty());
        assert_eq!(
            *list_costs.get_or_insert((list, security_cost)),
            (list, security_cost)
        );
        for (label, changed) in [("unchanged", 0), ("sparse", 1), ("all", n)] {
            sqlx::query("UPDATE identity_authority.providers SET assurance_profile=$2 WHERE tenant_id=$1::uuid AND provider_id IN (SELECT provider_id FROM identity_authority.providers WHERE tenant_id=$1::uuid ORDER BY provider_id LIMIT $3)")
                .bind(f.key.tenant.to_string()).bind([0u8;32].as_slice()).bind(i64::try_from(changed)?).execute(&f.owner).await?;
            let events = f.events().await?;
            let (_, _, checks) = measure(
                f,
                label,
                n,
                s.reconcile_assurance_profiles(scope, deadline()),
            )
            .await?;
            assert_eq!(checks, n + changed);
            assert_eq!(f.events().await? - events, i64::try_from(changed)?);
        }
    }
    concurrent_edit(f, &s).await?;
    Ok(())
}

async fn concurrent_edit(f: &Fixture, s: &rss_identity_postgres::Federation) -> anyhow::Result<()> {
    let scope = binding(f.key.tenant);
    let tenant = f.key.tenant.to_string();
    let ids: Vec<uuid::Uuid>=sqlx::query_scalar("SELECT provider_id FROM identity_authority.providers WHERE tenant_id=$1::uuid ORDER BY provider_id LIMIT 2").bind(&tenant).fetch_all(&f.owner).await?;
    sqlx::query(
        "UPDATE identity_authority.providers SET assurance_profile=$2 WHERE provider_id=ANY($1)",
    )
    .bind(&ids)
    .bind([0u8; 32].as_slice())
    .execute(&f.owner)
    .await?;
    let count = f.events().await?;
    // A failed Audit insert must roll back both generation changes.
    sqlx::raw_sql("CREATE FUNCTION fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture'; END $$; CREATE TRIGGER fail_audit BEFORE INSERT ON rss_audit.records FOR EACH ROW EXECUTE FUNCTION fail_audit()").execute(&f.owner).await?;
    assert!(
        s.reconcile_assurance_profiles(scope, deadline())
            .await
            .is_err()
    );
    sqlx::raw_sql("DROP TRIGGER fail_audit ON rss_audit.records; DROP FUNCTION fail_audit()")
        .execute(&f.owner)
        .await?;
    assert_eq!(f.events().await?, count);
    let original:Vec<(i64,i64)>=sqlx::query_as("SELECT config_version,revocation_epoch FROM identity_authority.providers WHERE provider_id=ANY($1) ORDER BY provider_id").bind(&ids).fetch_all(&f.owner).await?;
    let mut editor = f.owner.begin().await?;
    sqlx::query(
        "SELECT tenant_id FROM identity_authority.tenants WHERE tenant_id=$1::uuid FOR UPDATE",
    )
    .bind(&tenant)
    .fetch_one(&mut *editor)
    .await?;
    let sync = |federation: rss_identity_postgres::Federation| {
        tokio::spawn(async move {
            federation
                .reconcile_assurance_profiles(scope, deadline())
                .await
        })
    };
    let before = f.oidc.checks.load(Ordering::SeqCst);
    let first = sync(s.clone());
    let second = sync(s.clone());
    tokio::time::timeout(std::time::Duration::from_secs(10),async {
        loop {
            let waiting:i64=sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%identity_authority.tenants%FOR UPDATE%'").fetch_one(&f.owner).await?;
            if waiting>=2 {break;}
            tokio::task::yield_now().await;
        }
        Ok::<_,anyhow::Error>(())
    }).await??;
    sqlx::query("UPDATE identity_authority.providers SET assurance_profile=$2,config_version=config_version+1,revocation_epoch=revocation_epoch+1 WHERE provider_id=$1").bind(ids[0]).bind([1u8;32].as_slice()).execute(&mut *editor).await?;
    // Below the first visited window: it must be seen on the next pass.
    sqlx::query("INSERT INTO identity_authority.providers SELECT tenant_id,$2,1,1,true,settings,$3,1 FROM identity_authority.providers WHERE provider_id=$1")
        .bind(ids[0]).bind(uuid::Uuid::from_u128(1)).bind([0u8;32].as_slice()).execute(&mut *editor).await?;
    editor.commit().await?;
    first.await??;
    second.await??;
    println!(
        "federation concurrent: fingerprints={}",
        f.oidc.checks.load(Ordering::SeqCst) - before
    );
    assert_eq!(f.events().await?, count + 1);
    let after:Vec<(i64,i64)>=sqlx::query_as("SELECT config_version,revocation_epoch FROM identity_authority.providers WHERE provider_id=ANY($1) ORDER BY provider_id").bind(&ids).fetch_all(&f.owner).await?;
    assert!(
        original
            .iter()
            .zip(after)
            .all(|((v, e), (v2, e2))| v + 1 == v2 && e + 1 == e2)
    );
    s.reconcile_assurance_profiles(scope, deadline()).await?;
    assert_eq!(f.events().await?, count + 2);
    Ok(())
}
