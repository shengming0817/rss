//! Observe executed SQL, not source symbols. Retain counts only, never query/parameter data.
use super::*;
mod verified;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
    instrument::WithSubscriber,
};
use tracing_subscriber::{
    Layer,
    layer::{Context, SubscriberExt},
};

#[derive(Clone, Default)]
struct Counts {
    queries: Arc<AtomicUsize>,
    catalog: Arc<AtomicUsize>,
    associations: Arc<AtomicUsize>,
    authenticated: Arc<AtomicUsize>,
    decoded: Arc<AtomicUsize>,
    cancel_on_decode: Option<CancellationToken>,
}
#[derive(Default)]
struct Query {
    catalog: bool,
    reads_audit: bool,
}
impl Visit for Query {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if matches!(field.name(), "db.statement" | "summary") {
            let sql = format!("{value:?}");
            self.reads_audit |= sql.contains("rss_audit.records");
            self.catalog |= [
                "pg_proc",
                "pg_class",
                "pg_attribute",
                "pg_roles",
                "pg_namespace",
                "pg_constraint",
            ]
            .iter()
            .any(|table| sql.contains(table));
        }
    }
}
impl<S: Subscriber> Layer<S> for Counts {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        match event.metadata().target() {
            "batch_cost::verify" => {
                self.authenticated.fetch_add(1, Ordering::Relaxed);
            }
            "read_cost::decode" => {
                self.decoded.fetch_add(1, Ordering::Relaxed);
                if let Some(cancel) = &self.cancel_on_decode {
                    cancel.cancel();
                }
            }
            "sqlx::query" => {
                let mut query = Query::default();
                event.record(&mut query);
                self.queries.fetch_add(1, Ordering::Relaxed);
                self.associations
                    .fetch_add(usize::from(query.reads_audit), Ordering::Relaxed);
                if query.catalog {
                    self.catalog.fetch_add(1, Ordering::Relaxed);
                }
            }
            _ => {}
        }
    }
}

pub(super) async fn run(
    ledger: &PgAudit,
    pool: &PgPool,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let cost_tenant = TenantId::parse("e09e9963-6bbc-48c4-9a25-0a1682e55762")?;
    for wide in [false, true] {
        if wide {
            sqlx::raw_sql("CREATE SCHEMA audit_cost_unrelated; DO $$ BEGIN FOR i IN 1..200 LOOP EXECUTE format('CREATE FUNCTION audit_cost_unrelated.f%s() RETURNS integer LANGUAGE sql AS %L', i, 'SELECT 1'); END LOOP; END $$")
                .execute(admin).await?;
        }
        for ledger in [false, true] {
            let counts = Counts::default();
            let subscriber = tracing_subscriber::registry().with(counts.clone());
            async {
                let store = PgAudit::new(
                    pool.clone(),
                    if ledger {
                        Integrity::Ledger(auth()?)
                    } else {
                        Integrity::Plain
                    },
                    write_budget()?,
                    control,
                )
                .await?;
                assert!(
                    counts.catalog.load(Ordering::Relaxed) > 0,
                    "observer must see startup validation"
                );
                counts.catalog.store(0, Ordering::Relaxed);
                counts.queries.store(0, Ordering::Relaxed);
                let e = event(
                    cost_tenant,
                    match (ledger, wide) {
                        (true, false) => "cost-ledger",
                        (false, false) => "cost-plain",
                        (true, true) => "cost-ledger-wide",
                        (false, true) => "cost-plain-wide",
                    },
                    "id",
                    vec![1],
                )?;
                let prepared = store.prepare(e, control).await?;
                let staged = committed(
                    store
                        .write_tx_with_context(cost_tenant, control, prepared, |prepared, tx| {
                            Box::pin(async move { tx.append(prepared).await })
                        })
                        .await,
                )?;
                assert!(staged.inserted());
                let replay = committed(store.append(staged.record().prepared(), control).await)?;
                assert!(!replay.inserted());
                let page = committed(
                    store
                        .read_page(
                            Cursor::start(cost_tenant),
                            ReadLimit::new(1024, 1048576)?,
                            control,
                        )
                        .await,
                )?;
                assert!(page.records().iter().any(|r| r.prepared().canonical_bytes()
                    == staged.record().prepared().canonical_bytes()));
                assert!(counts.queries.load(Ordering::Relaxed) > 0);
                assert_eq!(
                    counts.catalog.load(Ordering::Relaxed),
                    0,
                    "business operations must not inspect storage catalogs"
                );
                println!(
                    "audit query cost: ledger={ledger} wide={wide} queries={} catalog=0",
                    counts.queries.load(Ordering::Relaxed)
                );
                Ok::<_, anyhow::Error>(())
            }
            .with_subscriber(subscriber)
            .await?;
        }
    }
    verified::verified_reads(ledger, admin, control).await
}
