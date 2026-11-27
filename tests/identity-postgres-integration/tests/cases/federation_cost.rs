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
    transactions: AtomicUsize,
    writes: AtomicUsize,
}
struct Observer(Arc<Sql>);
#[derive(Default)]
struct Observed {
    deployment: bool,
    write: bool,
}
impl Visit for Observed {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if matches!(field.name(), "db.statement" | "summary") {
            let sql = format!("{value:?}");
            self.deployment |= sql.contains("FROM identity_authority.deployment");
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
            self.0.statements.fetch_add(1, Ordering::Relaxed);
            self.0
                .transactions
                .fetch_add(usize::from(q.deployment), Ordering::Relaxed);
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
    println!(
        "federation {label} n={n} statements={queries} transactions={tx} collection_locks={locked} fingerprints={calls}"
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
    Ok(())
}
