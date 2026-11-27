//! Explicit resource measurements; no latency threshold is imposed on ordinary CI.
use super::*;
use std::sync::{Mutex, atomic::AtomicU64};

struct Meter<'a> {
    store: &'a PgStore,
    clock: &'a Clock,
    write_ns: AtomicU64,
    writes: AtomicU64,
    snapshots: AtomicU64,
    rows: AtomicU64,
    searches: AtomicU64,
}
impl<'a> Meter<'a> {
    fn new(store: &'a PgStore, clock: &'a Clock) -> Self {
        Self {
            store,
            clock,
            write_ns: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            snapshots: AtomicU64::new(0),
            rows: AtomicU64::new(0),
            searches: AtomicU64::new(0),
        }
    }
}
impl Store for Meter<'_> {
    async fn register<T: Timer>(
        &self,
        s: Scope,
        d: &Definition,
        capacity: HistoryCapacity,
        c: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.store.register(s, d, capacity, c).await
    }
    async fn claim<T: Timer>(
        &self,
        s: Scope,
        ttl: Duration,
        c: &Control<'_, T>,
    ) -> Result<Lease, Error> {
        self.store.claim(s, ttl, c).await
    }
    async fn renew<T: Timer>(
        &self,
        l: &Lease,
        ttl: Duration,
        c: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.store.renew(l, ttl, c).await
    }
    async fn release<T: Timer>(&self, l: &Lease, c: &Control<'_, T>) -> Result<(), Error> {
        self.store.release(l, c).await
    }
    async fn history_head<T: Timer>(
        &self,
        l: &Lease,
        c: &Control<'_, T>,
    ) -> Result<HistoryHead, Error> {
        self.store.history_head(l, c).await
    }
    async fn extend_history<T: Timer>(
        &self,
        l: &Lease,
        q: u64,
        old: HistoryCapacity,
        new: HistoryCapacity,
        c: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.store.extend_history(l, q, old, new, c).await
    }
    async fn snapshot<T: Timer>(
        &self,
        l: &Lease,
        r: ReadBudget,
        c: &Control<'_, T>,
    ) -> Result<Snapshot, Error> {
        let snapshot = self.store.snapshot(l, r, c).await?;
        // PgStore::snapshot streams one PG journal row per replayed event on each fresh claim.
        self.rows
            .fetch_add(snapshot.events().len() as u64, Ordering::SeqCst);
        self.snapshots.fetch_add(1, Ordering::SeqCst);
        Ok(snapshot)
    }
    async fn candidates<T: Timer>(
        &self,
        filter: CandidateFilter,
        t: TenantId,
        after: Option<uuid::Uuid>,
        limit: u32,
        c: &Control<'_, T>,
    ) -> Result<Vec<Scope>, Error> {
        self.searches.fetch_add(1, Ordering::SeqCst);
        self.store.candidates(filter, t, after, limit, c).await
    }
    async fn commit<T: Timer>(
        &self,
        l: &Lease,
        m: &Mutation,
        c: &Control<'_, T>,
    ) -> Result<(), Error> {
        let start = self.clock.now();
        let result = self.store.commit(l, m, c).await;
        self.write_ns.fetch_add(
            self.clock.now().saturating_sub(start).as_nanos() as u64,
            Ordering::SeqCst,
        );
        self.writes.fetch_add(1, Ordering::SeqCst);
        result
    }
}
struct CryptoMeter<'a> {
    clock: &'a Clock,
    opens: &'a Mutex<Vec<Duration>>,
}
impl SagaReceiptProtector for CryptoMeter<'_> {
    async fn seal(&self, p: &[u8], c: &ReceiptContext) -> Result<Ciphertext, Error> {
        Crypto.seal(p, c).await
    }
    async fn open(
        &self,
        p: &Ciphertext,
        c: &ReceiptContext,
    ) -> Result<rss_data_protection::Plaintext, Error> {
        let start = self.clock.now();
        let result = Crypto.open(p, c).await;
        self.opens
            .lock()
            .map_err(|_| Error::new(ErrorKind::Store))?
            .push(self.clock.now().saturating_sub(start));
        result
    }
}
fn measured_protection<'a>(
    clock: &'a Clock,
    opens: &'a Mutex<Vec<Duration>>,
) -> Result<ReceiptProtection<CryptoMeter<'a>>, Error> {
    protection_with(CryptoMeter { clock, opens })
}
struct BigStep {
    name: &'static str,
}
impl Step for BigStep {
    type Receipt = String;
    fn name(&self) -> &str {
        self.name
    }
    fn receipt_schema(&self) -> &str {
        "receipt.v1"
    }
    async fn execute(&self, _: EffectContext) -> EffectOutcome<String> {
        if self.name == "one" {
            EffectOutcome::Applied("x".repeat(PLAINTEXT_BYTES as usize - 2))
        } else {
            EffectOutcome::Unknown
        }
    }
    async fn probe(&self, _: EffectContext) -> ProbeOutcome<String> {
        if self.name == "one" {
            ProbeOutcome::Applied("x".repeat(PLAINTEXT_BYTES as usize - 2))
        } else {
            ProbeOutcome::NotApplied
        }
    }
    async fn compensate(&self, _: EffectContext, _: String) -> EffectOutcome<()> {
        EffectOutcome::Applied(())
    }
    async fn probe_compensation(&self, _: EffectContext, _: String) -> ProbeOutcome<()> {
        ProbeOutcome::Applied(())
    }
}
fn big_registry(d: Definition) -> Result<Registry, Error> {
    Ok(Registry::builder()
        .register(
            DefinitionBuilder::new(d)?
                .step(BigStep { name: "one" })?
                .step(BigStep { name: "two" })?,
        )?
        .finish())
}
pub(super) async fn seed_entries(
    store: &PgStore,
    owner: &PgPool,
    s: Scope,
    d: &Definition,
    n: u64,
    read: ReadBudget,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    store.register(s, d, read.history(), c).await?;
    let mut snapshot = Snapshot::empty(d.clone(), read.history(), read)?;
    for seq in 0..n {
        snapshot.replay(Event {
            seq,
            step: 0,
            attempt: (seq / 2 + 1) as u32,
            kind: if seq % 2 == 0 {
                EventKind::ForwardIntent
            } else {
                EventKind::ForwardProbeNotApplied
            },
            receipt: None,
        })?;
    }
    // Fixture generation is excluded from measured load/run time; core replay proves the seeded projection.
    let mut transaction = owner.begin().await?;
    sqlx::query("INSERT INTO rss_saga.journal(tenant_id,saga_id,seq,step,attempt,kind,effect_key,encoded_bytes) SELECT $1::text::uuid,$2,q,0,q/2+1,CASE WHEN q%2=0 THEN 'ForwardIntent' ELSE 'ForwardProbeNotApplied' END,$3,256 FROM generate_series(0,$4::bigint-1) q")
        .bind(s.tenant().to_string()).bind(s.id()).bind(d.effect_key(s,0,Phase::Forward)?.as_bytes().as_slice()).bind(n as i64).execute(&mut *transaction).await?;
    sqlx::query("UPDATE rss_saga.instances SET revision=$3,history_encoded_bytes=$4,progress=$5->'progress' WHERE tenant_id=$1::text::uuid AND saga_id=$2")
        .bind(s.tenant().to_string()).bind(s.id()).bind(n as i64).bind(snapshot.head().encoded_bytes() as i64).bind(sqlx::types::Json(snapshot.head())).execute(&mut *transaction).await?;
    transaction.commit().await?;
    Ok(())
}
pub(super) async fn run(
    store: &PgStore,
    owner: &PgPool,
    clock: &Clock,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let profile = std::env::var("RSS_SAGA_HISTORY_PROFILE")?;
    if profile == "fair-sweep" {
        return fair_measurements(store, owner, clock, c).await;
    }
    history_profile(store, owner, clock, c, &profile).await
}
async fn history_profile(
    store: &PgStore,
    owner: &PgPool,
    clock: &Clock,
    c: &Control<'_, Clock>,
    profile: &str,
) -> anyhow::Result<()> {
    let entries = match profile {
        "entries-100" => Some(100),
        "entries-1000" => Some(1000),
        "entries-10000" => Some(10000),
        "bytes-50" | "bytes-95" | "bytes-100" => None,
        _ => anyhow::bail!("unknown measurement profile"),
    };
    let read = ReadBudget::new(
        HistoryCapacity::new(20_000, 256 * 1024 * 1024)?,
        3 * 1024 * 1024,
    )?;
    let s = scope("71717171-2222-4333-8444-555555555555")?;
    let d = definition(if entries.is_some() {
        &["one"]
    } else {
        &["one", "two"]
    })?;
    let registry = if let Some(n) = entries {
        seed_entries(store, owner, s, &d, n, read, c).await?;
        registry(d.clone(), Arc::new(Effects::default()), false)?
    } else {
        seed_bytes(store, s, &d, read, profile, c).await?
    };
    let lease = store.claim(s, Duration::from_secs(30), c).await?;
    let start = clock.now();
    let snapshot = store.snapshot(&lease, read, c).await?;
    let read_ms = clock.now().saturating_sub(start).as_secs_f64() * 1000.0;
    let head = snapshot.head().clone();
    assert_eq!(snapshot.events().len() as u64, head.revision());
    store.release(&lease, c).await?;
    let wire:i64=sqlx::query_scalar("SELECT coalesce(sum(100+octet_length(kind)+CASE WHEN protected IS NULL THEN 0 ELSE 1+octet_length(protected::text) END),0)::bigint FROM rss_saga.journal WHERE tenant_id=$1::text::uuid AND saga_id=$2").bind(s.tenant().to_string()).bind(s.id()).fetch_one(owner).await?;
    drop(snapshot);
    let opens = Mutex::new(Vec::new());
    let meter = Meter::new(store, clock);
    let executor = Executor::new(meter, measured_protection(clock, &opens)?, registry, read);
    let start = clock.now();
    let report = executor.run(s, 1, c).await?;
    let run_ms = clock.now().saturating_sub(start).as_secs_f64() * 1000.0;
    let durations = opens.lock().map_err(|_| Error::new(ErrorKind::Store))?;
    let auth_ms: f64 = durations
        .iter()
        .map(Duration::as_secs_f64)
        .sum::<f64>()
        .max(0.0)
        * 1000.0;
    assert_eq!(
        executor.store().writes.load(Ordering::SeqCst),
        if entries.is_some() { 2 } else { 1 }
    );
    assert_eq!(
        report.head().revision(),
        head.revision() + if entries.is_some() { 2 } else { 1 }
    );
    eprintln!(
        "SAGA_HISTORY_MEASURE profile={profile} entries={} charged_bytes={} reserved_bytes={} capacity_bytes={} journal_data_row_bytes={wire} snapshot_ms={read_ms:.3} run_ms={run_ms:.3} receipt_opens={} receipt_open_ms={auth_ms:.3} commits={} commit_ms={:.3}",
        head.revision(),
        head.encoded_bytes(),
        head.reserve()?.1,
        head.capacity().max_encoded_bytes(),
        durations.len(),
        executor.store().writes.load(Ordering::SeqCst),
        executor.store().write_ns.load(Ordering::SeqCst) as f64 / 1_000_000.0
    );
    Ok(())
}

async fn seed_bytes(
    store: &PgStore,
    s: Scope,
    d: &Definition,
    read: ReadBudget,
    profile: &str,
    c: &Control<'_, Clock>,
) -> anyhow::Result<Registry> {
    let executor = Executor::new(store.clone(), protection()?, big_registry(d.clone())?, read);
    executor
        .register(
            s,
            d,
            HistoryCapacity::new(20_000, 5 * EVENT_BYTES + RECEIPT_BYTES)?,
            c,
        )
        .await?;
    assert_eq!(executor.run(s, 1, c).await?.head().revision(), 2);
    let head = executor.history_head(s, c).await?;
    // The next ForwardIntent adds one event, max receipt settlement and three reserve events.
    let needed =
        head.encoded_bytes() + EVENT_BYTES + head.reserve()?.1 + 3 * EVENT_BYTES + RECEIPT_BYTES;
    let percent = match profile {
        "bytes-50" => 50,
        "bytes-95" => 95,
        _ => 100,
    };
    let capacity = HistoryCapacity::new(20_000, (needed * 100).div_ceil(percent))?;
    executor
        .extend_history(s, head.revision(), head.capacity(), capacity, c)
        .await?;
    assert!(matches!(executor.run(s,1,c).await,Err(e) if e.kind()==ErrorKind::EffectUnknown));
    Ok(big_registry(d.clone())?)
}

// All schedules execute the same ordered effects and return the same final receipt.
const NAMES: [&str; 32] = [
    "s01", "s02", "s03", "s04", "s05", "s06", "s07", "s08", "s09", "s10", "s11", "s12", "s13",
    "s14", "s15", "s16", "s17", "s18", "s19", "s20", "s21", "s22", "s23", "s24", "s25", "s26",
    "s27", "s28", "s29", "s30", "s31", "s32",
];

async fn fair_measurements(
    store: &PgStore,
    owner: &PgPool,
    clock: &Clock,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let d = definition(&NAMES)?;
    let read = read_budget()?;
    let tenant = TenantId::parse("63636363-2222-4333-8444-555555555555")?;
    for (index, (fair, budget, instances, expected)) in [
        (false, 32, 1, (1, 1000, 0)),
        (false, 1, 1, (32, 32992, 496)),
        (true, 1, 1, (32, 32992, 496)),
        (true, 32, 1, (1, 1000, 0)),
        (true, 32, 2, (64, 65984, 992)),
    ]
    .into_iter()
    .enumerate()
    {
        let effects = Arc::new(Effects::default());
        let action = |name| Action {
            name,
            effects: effects.clone(),
            fail: false,
        };
        let mut builder = DefinitionBuilder::new(d.clone())?;
        let (last, rest) = NAMES.split_last().ok_or(ErrorKind::Definition)?;
        for name in rest {
            builder = builder.step(action(name))?;
        }
        let (builder, completion) = builder.last_step(action(last))?;
        let mut scopes = Vec::new();
        for i in 0..instances {
            let s = Scope::new(tenant, uuid::Uuid::from_u128((10 * index + i + 1) as u128));
            seed_entries(store, owner, s, &d, 1000, read, c).await?;
            scopes.push(s);
        }
        let opens = Mutex::new(Vec::new());
        let executor = Executor::new(
            Meter::new(store, clock),
            measured_protection(clock, &opens)?,
            Registry::builder().register(builder)?.finish(),
            read,
        );
        let start = clock.now();
        let (done, advances) = drive_schedule(&executor, &scopes, fair, budget, c).await?;
        let ms = clock.now().saturating_sub(start).as_secs_f64() * 1000.0;
        let meter = executor.store();
        let counts = (
            meter.snapshots.load(Ordering::SeqCst),
            meter.rows.load(Ordering::SeqCst),
            opens.lock().map_err(|_| ErrorKind::Store)?.len(),
        );
        let commits = meter.writes.load(Ordering::SeqCst);
        let searches = meter.searches.load(Ordering::SeqCst);
        eprintln!(
            "SAGA_FAIR_MEASURE fair={fair} budget={budget} instances={instances} snapshots={} journal_rows={} receipt_opens={} advances={advances} commits={commits} searches={searches} elapsed_ms={ms:.3}",
            counts.0, counts.1, counts.2
        );
        assert_eq!(counts, expected);
        assert_eq!(advances as usize, 32 * instances);
        assert_eq!(commits as usize, 64 * instances);
        let expected_calls: Vec<_> = NAMES
            .iter()
            .flat_map(|name| std::iter::repeat_n(format!("execute:{name}"), instances))
            .collect();
        assert_eq!(
            *effects.calls.lock().map_err(|_| ErrorKind::Store)?,
            expected_calls
        );
        assert_eq!(
            done.iter().map(SuccessReference::scope).collect::<Vec<_>>(),
            scopes
        );
        for reference in done {
            assert_eq!(
                executor.success_receipt(&reference, &completion, c).await?,
                *last
            );
        }
    }
    Ok(())
}

async fn drive_schedule(
    executor: &Executor<Meter<'_>, CryptoMeter<'_>>,
    scopes: &[Scope],
    fair: bool,
    budget: u32,
    c: &Control<'_, Clock>,
) -> anyhow::Result<(Vec<SuccessReference>, u32)> {
    let instances = scopes.len();
    let mut done = Vec::new();
    let mut cursor = None;
    let mut advances = 0;
    while done.len() < instances {
        let reports = if fair {
            let page = executor
                .run_once(
                    scopes[0].tenant(),
                    cursor,
                    SweepBudget::new(instances as u32, budget)?,
                    c,
                )
                .await?;
            assert_eq!(page.stop, SweepStop::PageComplete);
            cursor = page.next_cursor;
            page.items
                .into_iter()
                .map(|item| item.result)
                .collect::<Result<Vec<_>, _>>()?
        } else {
            vec![executor.run(scopes[0], budget, c).await?]
        };
        for report in reports {
            if instances == 2 {
                assert_eq!(report.advances, 1);
            }
            advances += report.advances;
            if report.success.is_some() {
                assert_eq!(report.stop, RunStop::Completed);
                assert_eq!(report.head().revision(), 1064);
                done.push(report.success.ok_or(ErrorKind::ReceiptUnavailable)?);
            } else {
                assert_eq!(report.stop, RunStop::Yielded);
            }
        }
    }
    Ok((done, advances))
}
