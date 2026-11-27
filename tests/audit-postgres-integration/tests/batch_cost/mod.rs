//! Isolated release fixture. The subscriber sees only operations inside the borrowed append.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
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
struct Cost {
    ledger_sql: AtomicUsize,
    scope_sql: AtomicUsize,
    ledger_writes: AtomicUsize,
    sign: AtomicUsize,
    verify: AtomicUsize,
    audit_body: AtomicUsize,
    ledger_body: AtomicUsize,
}
struct Observer(Arc<Cost>);
#[derive(Default)]
struct Fields {
    ledger: bool,
    scope: bool,
    write: bool,
    bytes: usize,
}
impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if matches!(field.name(), "summary" | "db.statement") {
            let sql = format!("{value:?}");
            self.scope |= sql.contains("current_setting(");
            self.ledger |= sql.contains("rss_ledger.");
            self.write |= sql.contains("rss_ledger.insert_entr");
        }
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "bytes" {
            self.bytes = value as usize;
        }
    }
}
impl<S: Subscriber> Layer<S> for Observer {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        let mut f = Fields::default();
        match event.metadata().target() {
            "sqlx::query" => {
                event.record(&mut f);
                self.0.scope_sql.fetch_add(usize::from(f.scope), Relaxed);
                self.0.ledger_sql.fetch_add(usize::from(f.ledger), Relaxed);
                self.0
                    .ledger_writes
                    .fetch_add(usize::from(f.write), Relaxed);
            }
            "batch_cost::verify" => {
                self.0.verify.fetch_add(1, Relaxed);
            }
            "batch_cost::sign" => {
                self.0.sign.fetch_add(1, Relaxed);
            }
            "batch_cost::audit_body" => {
                event.record(&mut f);
                self.0.audit_body.fetch_add(f.bytes, Relaxed);
            }
            "batch_cost::ledger_body" => {
                event.record(&mut f);
                self.0.ledger_body.fetch_add(f.bytes, Relaxed);
            }
            _ => {}
        }
    }
}
pub(super) async fn measure(
    plain: &PgAudit,
    ledger: &PgAudit,
    pool: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let at = Timepoint::try_from(321_i64)?;
    for (mode, owner, tenant) in [
        ("plain", plain, "3c54d1db-a1e9-42fc-b151-515263a11301"),
        ("ledger", ledger, "3c54d1db-a1e9-42fc-b151-515263a11302"),
    ] {
        let tenant = TenantId::parse(tenant)?;
        let seed = prepare(event(tenant, mode, "seed", vec![7])?, at)?;
        committed(owner.append(&seed, control).await)?;
        for profile in ["small", "large", "mixed"] {
            for n in [1_usize, 8, 32, 33, 64] {
                let rows = sample_rows(tenant, mode, profile, at, n)?;
                let sample = observe(owner, pool, control, &rows).await?;
                sample.print(mode, profile, "fresh", n);
                sample.check_fresh(mode, n, seed.canonical_bytes().len());
            }
        }
        let new = prepare(event(tenant, mode, "fresh", vec![8])?, at)?;
        for (case, inputs, inserted) in [
            (
                "mixed-replay",
                vec![new.clone(), seed.clone(), new, seed.clone()],
                1,
            ),
            ("all-replay", vec![seed.clone(), seed.clone()], 0),
        ] {
            let sample = observe(owner, pool, control, &inputs).await?;
            sample.print(mode, "small", case, inputs.len());
            assert_eq!(
                (
                    sample.audit_bytes,
                    sample.recovered,
                    sample.extra_copies,
                    sample.inserted
                ),
                (seed.canonical_bytes().len(), 0, 0, inserted)
            );
            if mode == "ledger" {
                assert_eq!(
                    (sample.writes, sample.sign, sample.scope),
                    (inserted, inserted, 1)
                );
            }
        }
    }
    Ok(())
}

fn sample_rows(
    tenant: TenantId,
    mode: &str,
    profile: &str,
    at: Timepoint,
    n: usize,
) -> anyhow::Result<Vec<PreparedAuditV1>> {
    let mut rows = Vec::with_capacity(n);
    for i in 0..n {
        let id = format!("r{i}");
        let header = canonical_len(&event(tenant, mode, &id, vec![])?)?;
        let bytes = if profile == "large" || (profile == "mixed" && i % 2 == 1) {
            MAX_RECORD_BYTES - header
        } else {
            32
        };
        rows.push(prepare(event(tenant, mode, &id, vec![3; bytes])?, at)?);
    }
    Ok(rows)
}

struct Sample {
    sql: usize,
    scope: usize,
    writes: usize,
    verify: usize,
    sign: usize,
    audit_bytes: usize,
    ledger_bytes: usize,
    inserted: usize,
    recovered: usize,
    extra_copies: usize,
}
impl Sample {
    fn check_fresh(&self, mode: &str, n: usize, seed_bytes: usize) {
        assert_eq!(
            (self.audit_bytes, self.recovered, self.extra_copies),
            (0, 0, 0)
        );
        assert_eq!(self.inserted, n);
        if mode == "ledger" {
            let chunks = n.div_ceil(32);
            assert_eq!((self.verify, self.sign, self.scope), (1, n, 1));
            assert_eq!((self.writes, self.sql), (chunks, 2 + 2 * chunks));
            assert_eq!(self.ledger_bytes, seed_bytes);
        } else {
            assert_eq!((self.sql, self.scope, self.verify, self.sign), (0, 0, 0, 0));
        }
    }
    fn print(&self, mode: &str, profile: &str, case: &str, n: usize) {
        let Self {
            sql,
            scope,
            writes,
            verify,
            sign,
            audit_bytes,
            ledger_bytes,
            inserted,
            recovered,
            extra_copies,
        } = self;
        println!(
            "BATCH {mode} {profile} {case} n={n} inserted={inserted} audit_bytes={audit_bytes} recovered={recovered} duplicate_copies={extra_copies} ledger_data_sql={sql} tenant_sql={scope} writes={writes} verify={verify} sign={sign} ledger_bytes={ledger_bytes}"
        );
    }
}
async fn observe(
    owner: &PgAudit,
    pool: &PgPool,
    control: &Control<'_, TestClock>,
    rows: &[PreparedAuditV1],
) -> anyhow::Result<Sample> {
    let tenant = rows[0].identity().tenant();
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let cost = Arc::new(Cost::default());
    let subscriber = tracing_subscriber::registry().with(Observer(cost.clone()));
    let receipts = owner
        .append_batch_in_transaction(&mut tx, owner.try_admit(rows)?, control)
        .with_subscriber(subscriber)
        .await?;
    let mut addresses = std::collections::HashMap::new();
    let (mut recovered, mut extra_copies) = (0, 0);
    for (receipt, input) in receipts.iter().zip(rows) {
        let address = receipt.record().prepared().canonical_bytes().as_ptr();
        match addresses.entry(receipt.record().position()) {
            std::collections::hash_map::Entry::Vacant(first) => {
                recovered += usize::from(address != input.canonical_bytes().as_ptr());
                first.insert(address);
            }
            std::collections::hash_map::Entry::Occupied(first) => {
                extra_copies += usize::from(*first.get() != address)
            }
        }
    }
    tx.rollback().await?;
    Ok(Sample {
        sql: cost.ledger_sql.load(Relaxed),
        scope: cost.scope_sql.load(Relaxed),
        writes: cost.ledger_writes.load(Relaxed),
        verify: cost.verify.load(Relaxed),
        sign: cost.sign.load(Relaxed),
        audit_bytes: cost.audit_body.load(Relaxed),
        ledger_bytes: cost.ledger_body.load(Relaxed),
        inserted: receipts.iter().filter(|r| r.inserted()).count(),
        recovered,
        extra_copies,
    })
}
