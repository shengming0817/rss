use super::*;
use rss_transactional_messaging::{
    fence::{Epoch, ExecutionBinding, StorageIdentity},
    inbox::{ConsumerGroup, IdempotencyDisposition, InboxStore},
    message::*,
    policy::{LeaseRenewalPolicy, OperationDeadline},
    transaction::*,
};
use rss_transactional_messaging_postgres::*;
mod local;

fn execution() -> anyhow::Result<ExecutionBinding> {
    Ok(ExecutionBinding::new(
        StorageIdentity::new([1; 16], [2; 16])?,
        tenant()?,
        Epoch::new(1)?,
    ))
}
fn deadline() -> anyhow::Result<OperationDeadline> {
    Ok(OperationDeadline::from_cutoff(
        Deadline::from_timeout(&TestClock, Duration::from_secs(10))?,
        &TestClock,
    ))
}
struct Effect {
    capacity: rss_audit_postgres::WriteBudget,
    integrity: Integrity,
    request: PreparedAuditV1,
    reject: bool,
}
impl PgConsumerEffect<Vec<u8>> for Effect {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        _: &MessageEnvelope<Vec<u8>>,
        _: OperationDeadline,
    ) -> Result<TerminalDisposition, PgConsumerEffectFailure> {
        rss_audit_postgres::lock_head_in(tx, &self.integrity)
            .await
            .map_err(PgConsumerEffectFailure::infrastructure)?;
        self.capacity
            .append_in(tx, &self.integrity, &self.request)
            .await
            .map_err(PgConsumerEffectFailure::infrastructure)?;
        let id = decode_untrusted(self.request.canonical_bytes())
            .map_err(PgConsumerEffectFailure::infrastructure)?
            .event()
            .identity()
            .event_id()
            .as_str()
            .to_owned();
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query("INSERT INTO public.business_changes VALUES ($1)")
                    .bind(id)
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await
        .map_err(PgConsumerEffectFailure::infrastructure)?;
        if self.reject {
            Err(PgConsumerEffectFailure::infrastructure(
                std::io::Error::other("fixture business rejection"),
            ))
        } else {
            Ok(TerminalDisposition::Succeeded)
        }
    }
}
struct Validator;
impl IngressValidator<Vec<u8>> for Validator {
    fn validate(
        &self,
        challenge: IngressChallenge<'_, Vec<u8>>,
    ) -> Result<VerifiedIngress, EnvelopeValidationFailure> {
        // Explicit fixture authority; production source authentication remains host-owned.
        Ok(challenge
            .verified(execution().map_err(|_| EnvelopeValidationFailure::MalformedIdentity)?))
    }
}
fn message(id: &str, payload: Vec<u8>) -> anyhow::Result<MessageEnvelope<Vec<u8>>> {
    Ok(MessageEnvelope::new(
        MessageId::parse(id)?,
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                tenant()?,
                Timepoint::try_from(1_i64)?,
                MessagingDomain::parse("audit-test")?,
                MessageRoute::parse("recorded")?,
                ContractIdentity::new(
                    ContractId::parse("audit-fixture.recorded")?,
                    ContractVersion::from_major(1)?,
                    SchemaDigest::parse(&format!("sha256:{}", "a".repeat(64)))?,
                ),
            ),
            MessageMetadataExtensions::default(),
        ),
        payload,
    ))
}

#[allow(
    clippy::cognitive_complexity,
    reason = "Keep the borrowed transaction outcomes and their durable assertions together."
)]
pub(super) async fn run(
    plain: &PgAudit,
    ledger: &PgAudit,
    admin: &PgPool,
    fixture: &testkit::PgTlsFixture,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    install(admin).await?;
    let runtime = connect(fixture, "audit_runtime").await?;
    startup(plain, ledger, admin, fixture).await?;
    expired_conflict(fixture).await?;
    for (mode, integrity) in [
        ("borrowed-plain", Integrity::Plain),
        ("borrowed-ledger", Integrity::Ledger(auth()?)),
    ] {
        let prepared = plain
            .prepare(
                event(tenant()?, mode, "prepared-in-owner", vec![3])?,
                control,
            )
            .await?;
        let writer = integrity.clone();
        let charge = u32::try_from(prepared.canonical_bytes().len() * 8)?;
        let capacity = rss_audit_postgres::WriteBudget::new(8, charge, charge)?;
        let occupied = capacity.reserve(8, charge as usize, control).await?;
        let request = prepared.clone();
        runtime
            .local_tx(execution()?, deadline()?, move |tx| {
                Box::pin(async move {
                    rss_audit_postgres::validate_in(tx, &writer).await?;
                    rss_audit_postgres::lock_head_in(tx, &writer).await?;
                    assert!(matches!(
                        capacity.append_in(tx, &writer, &request).await,
                        Err(rss_audit_postgres::Error::WriteBusy)
                    ));
                    drop(occupied);
                    let records = vec![request; 8];
                    let added = capacity
                        .append_batch_in(tx, &writer, capacity.try_admit(&records)?)
                        .await?;
                    assert!(added[0].inserted());
                    assert!(!added[1].inserted());
                    Ok(())
                })
            })
            .await
            .fold(Ok, Err, Err, Err, Err, Err)?;
        let writer = integrity.clone();
        let capacity = write_budget()?;
        let z = prepare(
            event(tenant()?, mode, "z", vec![8])?,
            prepared.recorded_at(),
        )?;
        let b = prepare(
            event(tenant()?, mode, "b", vec![9])?,
            prepared.recorded_at(),
        )?;
        runtime
            .local_tx(execution()?, deadline()?, move |tx| {
                Box::pin(async move {
                    let inputs = [z.clone(), prepared.clone(), b, z, prepared.clone()];
                    let result = capacity
                        .append_batch_in(tx, &writer, capacity.try_admit(&inputs)?)
                        .await?;
                    assert_eq!(
                        result.iter().map(|r| r.inserted()).collect::<Vec<_>>(),
                        [true, false, true, false, false]
                    );
                    assert_eq!(result[0].record().position(), result[3].record().position());
                    assert_eq!(result[1].record().position(), result[4].record().position());
                    if let Some(seq) = result[0].record().ledger_sequence() {
                        assert_eq!(result[2].record().ledger_sequence(), Some(seq + 1));
                    }
                    assert_eq!(
                        result[1].record().prepared().recorded_at(),
                        prepared.recorded_at()
                    );
                    Ok(())
                })
            })
            .await
            .fold(Ok, Err, Err, Err, Err, Err)?;
        let wrong = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d480")?;
        let capacity = write_budget()?;
        let foreign = plain
            .prepare(event(wrong, "scope", "foreign", vec![])?, control)
            .await?;
        runtime
            .local_tx(execution()?, deadline()?, move |tx| {
                Box::pin(async move {
                    assert!(matches!(
                        capacity.append_in(tx, &integrity, &foreign).await,
                        Err(rss_audit_postgres::Error::ScopeMismatch)
                    ));
                    Ok(())
                })
            })
            .await
            .fold(Ok, Err, Err, Err, Err, Err)?;
    }
    let inbox = PgInboxStore::new(
        runtime.clone(),
        LeaseRenewalPolicy::from_ttl(Duration::from_secs(30))?,
    )?;
    for (mode, store, integrity) in [
        ("plain", plain, Integrity::Plain),
        ("ledger", ledger, Integrity::Ledger(auth()?)),
    ] {
        for (case, reject, unknown) in [
            ("commit", false, false),
            ("rollback", true, false),
            ("unknown", false, true),
        ] {
            let id = format!("message-{mode}-{case}");
            scenario(
                store,
                admin,
                control,
                &runtime,
                &inbox,
                (&id, reject, unknown),
                integrity.clone(),
            )
            .await?;
        }
    }
    Box::pin(local::run(ledger, admin, fixture, control, &runtime)).await?;
    fenced(ledger, admin, &runtime, control).await?;
    runtime.close().await;
    Ok(())
}

async fn claim_inbox(
    inbox: &PgInboxStore,
    binding: &VerifiedConsumerBinding,
) -> anyhow::Result<IdempotencyDisposition<PgInboxClaim>> {
    let permit = inbox
        .reserve_claim(binding.execution(), binding.identity(), deadline()?)?
        .acquire()
        .await?;
    Ok(inbox.claim(permit).await?)
}

async fn scenario(
    store: &PgAudit,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
    runtime: &Arc<PgRuntime>,
    inbox: &PgInboxStore,
    case: (&str, bool, bool),
    integrity: Integrity,
) -> anyhow::Result<()> {
    let (id, reject, unknown) = case;
    let request = store
        .prepare(event(tenant()?, "message", id, vec![1])?, control)
        .await?;
    let envelope = message(id, request.canonical_bytes().to_vec())?;
    let metadata = envelope.metadata();
    let binding = verify_ingress(
        &Validator,
        ConsumerGroup::parse("audit-test")?,
        &SubscriptionIdentity::new(
            metadata.domain().clone(),
            metadata.route().clone(),
            metadata.contract().clone(),
        ),
        &envelope,
    )
    .map_err(|_| anyhow::anyhow!("fixture ingress rejected"))?;

    let IdempotencyDisposition::Acquired(claim) = claim_inbox(inbox, &binding).await? else {
        anyhow::bail!("expected new claim")
    };
    if unknown {
        runtime.inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    }
    let outcome = PgConsumerTx::receipt_only(
        runtime.clone(),
        Effect {
            capacity: write_budget()?,
            integrity,
            request: request.clone(),
            reject,
        },
    )
    .execute(&claim, &envelope, binding.receipt_intent(), deadline()?)
    .await;
    assert_eq!(outcome.status(), expected_status(reject, unknown));
    assert_eq!(
        inbox
            .read_terminal(execution()?, binding.identity(), deadline()?)
            .await?
            .is_some(),
        !reject
    );
    let actual: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.business_changes WHERE id=$1")
            .bind(id)
            .fetch_one(admin)
            .await?;
    assert_eq!(actual, i64::from(!reject));
    let retry = committed(store.append(&request, control).await)?;
    assert_eq!(retry.inserted(), reject);
    if unknown {
        assert!(matches!(
            claim_inbox(inbox, &binding).await?,
            IdempotencyDisposition::Terminal(_)
        ));
    }
    Ok(())
}
fn expected_status(
    reject: bool,
    unknown: bool,
) -> rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus {
    use rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus as Status;
    match (reject, unknown) {
        (_, true) => Status::CommitUnknown,
        (true, false) => Status::InfrastructureTransient,
        (false, false) => Status::Committed,
    }
}
async fn fenced(
    store: &PgAudit,
    admin: &PgPool,
    runtime: &Arc<PgRuntime>,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE rss_transactional_messaging.tenant_epoch SET epoch=2 WHERE tenant_id=$1::uuid",
    )
    .bind(tenant()?.to_string())
    .execute(admin)
    .await?;
    let request = store
        .prepare(event(tenant()?, "message", "fenced", vec![])?, control)
        .await?;
    let capacity = write_budget()?;
    let staged = request.clone();
    let integrity = Integrity::Ledger(auth()?);
    let outcome = runtime
        .local_tx(execution()?, deadline()?, move |tx| {
            Box::pin(async move {
                capacity
                    .append_in(tx, &integrity, &staged)
                    .await
                    .map_err(PgError::from)
            })
        })
        .await;
    assert!(outcome.fold(
        |_| false,
        |_| false,
        |_| false,
        |_| false,
        |_| false,
        |e| e.kind() == rss_transactional_messaging::error::MessagingErrorKind::OwnershipLost
    ));
    assert!(committed(store.append(&request, control).await)?.inserted());
    sqlx::query(
        "UPDATE rss_transactional_messaging.tenant_epoch SET epoch=1 WHERE tenant_id=$1::uuid",
    )
    .bind(tenant()?.to_string())
    .execute(admin)
    .await?;
    Ok(())
}
async fn install(admin: &PgPool) -> anyhow::Result<()> {
    let mut tx = admin.begin().await?;
    sqlx::raw_sql("CREATE ROLE rss_tmsg_relay NOLOGIN NOBYPASSRLS;")
        .execute(&mut *tx)
        .await?;
    sqlx::raw_sql(MIGRATION_SQL).execute(&mut *tx).await?;
    grant_consumer(&mut tx, "audit_runtime").await?;
    sqlx::raw_sql("GRANT EXECUTE ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(jsonb),rss_transactional_messaging.append_outbox(bytea,jsonb) TO audit_runtime;").execute(&mut *tx).await?;
    sqlx::query("INSERT INTO rss_transactional_messaging.storage_lineage VALUES(true,$1,$2)")
        .bind([1_u8; 16].as_slice())
        .bind([2_u8; 16].as_slice())
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO rss_transactional_messaging.tenant_epoch VALUES($1::uuid,1)")
        .bind(tenant()?.to_string())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

async fn connect(fixture: &testkit::PgTlsFixture, role: &str) -> anyhow::Result<Arc<PgRuntime>> {
    connect_with(fixture, role, TestClock).await
}
async fn connect_with(
    fixture: &testkit::PgTlsFixture,
    role: &str,
    timer: impl ExecutionTimer + 'static,
) -> anyhow::Result<Arc<PgRuntime>> {
    let p = fixture.params();
    Ok(Arc::new(
        PgRuntime::connect(
            PgConfig::new(
                &p.host,
                p.port,
                &p.database,
                role,
                PgPassword::new("fixture-password"),
                PgPrivateCa::from_pem(fixture.ca_pem().as_bytes().to_vec())?,
            ),
            timer,
            StorageIdentity::new([1; 16], [2; 16])?,
        )
        .await?,
    ))
}

async fn startup(
    plain: &PgAudit,
    ledger: &PgAudit,
    admin: &PgPool,
    fixture: &testkit::PgTlsFixture,
) -> anyhow::Result<()> {
    sqlx::raw_sql("CREATE ROLE audit_borrower LOGIN PASSWORD 'fixture-password'; GRANT audit_runtime TO audit_borrower")
        .execute(admin).await?;
    let runtime = connect(fixture, "audit_borrower").await?;
    for (_store, grant, revoke, is_ledger) in [
        (
            plain,
            "GRANT UPDATE ON rss_audit.records TO audit_borrower",
            "REVOKE UPDATE ON rss_audit.records FROM audit_borrower",
            false,
        ),
        (
            ledger,
            "GRANT UPDATE ON rss_ledger.entries TO audit_borrower",
            "REVOKE UPDATE ON rss_ledger.entries FROM audit_borrower",
            true,
        ),
    ] {
        sqlx::raw_sql(grant).execute(admin).await?;
        let integrity = if is_ledger {
            Integrity::Ledger(auth()?)
        } else {
            Integrity::Plain
        };
        runtime
            .local_tx(execution()?, deadline()?, move |tx| {
                Box::pin(async move {
                    let result = rss_audit_postgres::validate_in(tx, &integrity).await;
                    if is_ledger {
                        assert!(matches!(
                            result,
                            Err(rss_audit_postgres::Error::Ledger(
                                rss_ledger_postgres::Error::Admission(_)
                            ))
                        ));
                    } else {
                        assert!(matches!(
                            result,
                            Err(rss_audit_postgres::Error::Admission(_))
                        ));
                    }
                    Ok(())
                })
            })
            .await
            .fold(Ok, Err, Err, Err, Err, Err)?;
        sqlx::raw_sql(revoke).execute(admin).await?;
        let integrity = if is_ledger {
            Integrity::Ledger(auth()?)
        } else {
            Integrity::Plain
        };
        runtime
            .local_tx(execution()?, deadline()?, move |tx| {
                Box::pin(async move {
                    rss_audit_postgres::validate_in(tx, &integrity)
                        .await
                        .map_err(PgError::from)
                })
            })
            .await
            .fold(Ok, Err, Err, Err, Err, Err)?;
    }
    runtime.close().await;
    Ok(())
}

async fn expired_conflict(fixture: &testkit::PgTlsFixture) -> anyhow::Result<()> {
    let cutoff = Deadline::from_timeout(&TestClock, Duration::from_secs(10))?;
    let advance = CancellationToken::new();
    let runtime = connect_with(
        fixture,
        "audit_runtime",
        super::write_capacity::StepClock {
            cutoff: Deadline::at(cutoff.instant() + Duration::from_secs(60)),
            advance: advance.clone(),
        },
    )
    .await?;
    let owner_deadline = OperationDeadline::from_cutoff(cutoff, &TestClock);
    let at = Timepoint::try_from(77_i64)?;
    let t = tenant()?;
    let rows = [
        prepare(event(t, "deadline", "dup", vec![1])?, at)?,
        prepare(event(t, "deadline", "dup", vec![2])?, at)?,
    ];
    let writer = write_budget()?;
    let observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let record = observed.clone();
    let attempt=runtime.local_tx(execution()?,owner_deadline,move |tx| Box::pin(async move {
        let batch=writer.try_admit(&rows)?;
        advance.cancel();
        let result=writer.append_batch_in(tx,&Integrity::Plain,batch).await;
        assert!(matches!(result,Err(rss_audit_postgres::Error::Messaging(ref err)) if err.kind()==rss_transactional_messaging::error::MessagingErrorKind::DeadlineElapsed));
        record.store(true,std::sync::atomic::Ordering::Relaxed);
        result.map(|_|()).map_err(PgError::from)
    })).await;
    assert!(observed.load(std::sync::atomic::Ordering::Relaxed));
    assert!(!attempt.fold(
        |_| true,
        |_| false,
        |_| false,
        |_| false,
        |_| false,
        |_| false
    ));
    Ok(())
}
