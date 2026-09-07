use super::*;
#[allow(clippy::cognitive_complexity)]
// reason: fixture assertions keep each failure beside its durable-state check.
pub async fn run(
    store: &PgLedger,
    pool: &PgPool,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let r = request("basic", "stable", b"exact\0payload")?;
    let first = committed(store.append(&r, control).await)?;
    assert!(first.inserted());
    let replay = committed(store.append(&r, control).await)?;
    assert!(!replay.inserted());
    assert_eq!(first.entry(), replay.entry());
    let conflict = request("basic", "stable", b"different")?;
    assert!(matches!(
        observe(store.append(&conflict, control).await),
        Observed::RolledBack(Error::Conflict)
    ));
    let mut tasks = Vec::new();
    for n in 0..12 {
        let store = store.clone();
        tasks.push(async move {
            let r = request("concurrent", &format!("r{n}"), &[n])?;
            committed(store.append(&r, control).await)?;
            Ok::<_, anyhow::Error>(())
        });
    }
    for result in futures::future::join_all(tasks).await {
        result?;
    }
    let scope = request("concurrent", "x", b"")?.ledger().clone();
    let page = committed(
        store
            .read_window(&scope, Sequence::new(0), ReadLimit::new(20)?, control)
            .await,
    )?;
    assert_eq!(page.entries().len(), 12);
    assert_eq!(page.observed_tail(), Some(Sequence::new(11)));
    let page = committed(
        store
            .read_window(&scope, Sequence::new(12), ReadLimit::new(1)?, control)
            .await,
    )?;
    assert!(page.entries().is_empty());
    assert!(page.predecessor().is_some());
    assert!(matches!(
        observe(
            store
                .read_window(&scope, Sequence::new(13), ReadLimit::new(1)?, control)
                .await
        ),
        Observed::RolledBack(Error::Protocol(rss_ledger::Error::SequenceGap))
    ));
    let rollback = request("rollback", "r", b"payload")?;
    let copy = rollback.clone();
    let result: LocalTxAttempt<Committed<()>, Error> = store
        .local_tx(copy.ledger().tenant(), control, move |tx| {
            Box::pin(async move {
                tx.append(&copy).await?;
                Err(Error::Rejected)
            })
        })
        .await;
    assert!(matches!(
        observe(result),
        Observed::RolledBack(Error::Rejected)
    ));
    assert!(
        committed(
            store
                .find(rollback.ledger(), rollback.record_id(), control)
                .await
        )?
        .is_none()
    );
    let unknown = request("unknown", "r", b"payload")?;
    store.inject_next_fault(PgFault::CommitUnknownAfterAck);
    assert!(matches!(
        observe(store.append(&unknown, control).await),
        Observed::CommitUnknown(_)
    ));
    let recovered = committed(store.append(&unknown, control).await)?;
    assert!(!recovered.inserted());
    assert_eq!(recovered.entry().sequence().get(), 0);
    let other = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d478")?;
    let copy = r.clone();
    assert!(matches!(
        observe(
            store
                .local_tx(other, control, move |tx| Box::pin(async move {
                    tx.append(&copy).await
                }))
                .await
        ),
        Observed::RolledBack(Error::Protocol(rss_ledger::Error::ScopeMismatch))
    ));
    let hidden = committed(
        store
            .local_tx(other, control, |tx| {
                Box::pin(async move {
                    tx.with_connection(|c| {
                        Box::pin(async move {
                            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM rss_ledger.entries")
                                .fetch_one(c)
                                .await
                        })
                    })
                    .await
                    .map_err(Error::from)
                })
            })
            .await,
    )?;
    assert_eq!(hidden, 0);
    assert!(
        sqlx::query("DELETE FROM rss_ledger.entries")
            .execute(pool)
            .await
            .is_err()
    );
    assert!(
        PgLedger::new(owner.clone(), auth()?, control)
            .await
            .is_err()
    );
    sqlx::raw_sql("GRANT UPDATE ON rss_ledger.entries TO ledger_runtime")
        .execute(owner)
        .await?;
    assert!(PgLedger::new(pool.clone(), auth()?, control).await.is_err());
    sqlx::raw_sql("REVOKE UPDATE ON rss_ledger.entries FROM ledger_runtime")
        .execute(owner)
        .await?;
    let wrong = PgLedger::new(
        pool.clone(),
        Authenticator::new(KeyId::parse("fixture-key")?, vec![9; 32])?,
        control,
    )
    .await?;
    assert!(matches!(
        observe(wrong.append(&r, control).await),
        Observed::RolledBack(Error::Protocol(rss_ledger::Error::Authentication))
    ));
    definer_scope(store, owner, control).await?;
    interruption(store, owner).await?;
    exhaustion(store, owner, control).await?;
    business_atomicity(store, owner, control).await?;
    Ok(())
}
async fn interruption(store: &PgLedger, owner: &PgPool) -> anyhow::Result<()> {
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(5), &cancel);
    let r = request("transport", "r", b"bytes")?;
    let copy = r.clone();
    let owner = owner.clone();
    let result = store
        .local_tx(r.ledger().tenant(), &control, move |tx| {
            Box::pin(async move {
                tx.append(&copy).await?;
                let pid = tx
                    .with_connection(|c| {
                        Box::pin(async move {
                            sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
                                .fetch_one(c)
                                .await
                        })
                    })
                    .await?;
                sqlx::query("SELECT pg_terminate_backend($1)")
                    .bind(pid)
                    .execute(&owner)
                    .await
                    .map_err(|_| Error::Rejected)?;
                Ok(())
            })
        })
        .await;
    assert!(matches!(observe(result), Observed::CommitUnknown(_)));
    let restored = committed(store.append(&r, &control).await)?;
    assert_eq!(restored.entry().sequence().get(), 0);
    store.inject_next_fault(PgFault::CommitPending);
    let cancel2 = CancellationToken::new();
    let short = Control::new(&clock, clock.now() + Duration::from_millis(100), &cancel2);
    let r = request("pending", "r", b"bytes")?;
    assert!(matches!(
        observe(store.append(&r, &short).await),
        Observed::CommitUnknown(_)
    ));
    let restored = committed(store.append(&r, &control).await)?;
    assert_eq!(restored.entry().sequence().get(), 0);
    operation_expiry(store, &control).await
}

async fn operation_expiry(store: &PgLedger, control: &Control<'_, Clock>) -> anyhow::Result<()> {
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let short = Control::new(&clock, Duration::from_millis(100), &cancel);
    let r = request("operation-expiry", "r", b"bytes")?;
    let copy = r.clone();
    let result = store
        .local_tx(r.ledger().tenant(), &short, move |tx| {
            Box::pin(async move {
                tx.append(&copy).await?;
                std::future::pending::<Result<(), Error>>().await
            })
        })
        .await;
    assert!(matches!(
        observe(result),
        Observed::CommitUnknown(Error::Deadline(LocalTxDeadlineStage::Operation))
    ));
    assert!(committed(store.find(r.ledger(), r.record_id(), control).await)?.is_none());
    Ok(())
}

#[allow(clippy::cognitive_complexity)]
// reason: explicit adversarial matrix pairs each mutation with its restoration and rejection.
pub async fn adversarial(
    store: &PgLedger,
    pool: &PgPool,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let r = request("same-id-race", "r", b"immutable")?;
    let mut inserted = 0;
    for outcome in futures::future::join_all((0..12).map(|_| store.append(&r, control))).await {
        let value = committed(outcome)?;
        if value.inserted() {
            inserted += 1;
        }
        assert_eq!(value.entry().sequence().get(), 0);
    }
    assert_eq!(inserted, 1);
    for (change, restore) in [
        (
            "GRANT USAGE ON SCHEMA rss_ledger TO ledger_runtime WITH GRANT OPTION",
            "REVOKE GRANT OPTION FOR USAGE ON SCHEMA rss_ledger FROM ledger_runtime",
        ),
        (
            "GRANT SELECT ON rss_ledger.entries TO ledger_runtime WITH GRANT OPTION",
            "REVOKE GRANT OPTION FOR SELECT ON rss_ledger.entries FROM ledger_runtime",
        ),
        (
            "GRANT SELECT(payload) ON rss_ledger.entries TO ledger_runtime WITH GRANT OPTION",
            "REVOKE SELECT(payload) ON rss_ledger.entries FROM ledger_runtime",
        ),
        (
            "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_ledger TO ledger_runtime WITH GRANT OPTION",
            "REVOKE GRANT OPTION FOR EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_ledger FROM ledger_runtime",
        ),
        (
            "CREATE ROLE ledger_delegate NOLOGIN; GRANT ledger_delegate TO ledger_runtime WITH ADMIN OPTION",
            "REVOKE ledger_delegate FROM ledger_runtime; DROP ROLE ledger_delegate",
        ),
        (
            "ALTER ROLE ledger_runtime REPLICATION",
            "ALTER ROLE ledger_runtime NOREPLICATION",
        ),
        (
            "GRANT SELECT(payload) ON rss_ledger.entries TO PUBLIC",
            "REVOKE SELECT(payload) ON rss_ledger.entries FROM PUBLIC",
        ),
        (
            "ALTER TABLE rss_ledger.entries SET UNLOGGED",
            "ALTER TABLE rss_ledger.entries SET LOGGED",
        ),
        (
            "GRANT SELECT ON rss_ledger.entries TO PUBLIC",
            "REVOKE SELECT ON rss_ledger.entries FROM PUBLIC",
        ),
        (
            "ALTER TABLE rss_ledger.entries NO FORCE ROW LEVEL SECURITY",
            "ALTER TABLE rss_ledger.entries FORCE ROW LEVEL SECURITY",
        ),
        (
            "ALTER TABLE rss_ledger.entries DROP CONSTRAINT entries_payload_check",
            "ALTER TABLE rss_ledger.entries ADD CONSTRAINT entries_payload_check CHECK(octet_length(payload)<=1048576)",
        ),
        (
            "ALTER FUNCTION rss_ledger.prepare_append(uuid,text,text,smallint) SET search_path=public",
            "ALTER FUNCTION rss_ledger.prepare_append(uuid,text,text,smallint) SET search_path=pg_catalog,rss_ledger",
        ),
        (
            "GRANT ledger_owner TO ledger_runtime",
            "REVOKE ledger_owner FROM ledger_runtime",
        ),
        (
            "ALTER TABLE rss_ledger.entries ADD COLUMN unexpected text",
            "ALTER TABLE rss_ledger.entries DROP COLUMN unexpected",
        ),
    ] {
        sqlx::raw_sql(change).execute(owner).await?;
        let rejected = PgLedger::new(pool.clone(), auth()?, control).await;
        let expected = if change.contains("REPLICATION") {
            AdmissionViolation::Role
        } else if change.contains("UNLOGGED") {
            AdmissionViolation::Schema
        } else if change.contains("ROW LEVEL") {
            AdmissionViolation::Rls
        } else if change.contains("CONSTRAINT") {
            AdmissionViolation::Constraints
        } else if change.contains("search_path") {
            AdmissionViolation::Functions
        } else if change.contains("COLUMN unexpected") {
            AdmissionViolation::Columns
        } else {
            AdmissionViolation::Permissions
        };
        sqlx::raw_sql(restore).execute(owner).await?;
        assert!(
            matches!(rejected, Err(Error::Admission(kind)) if kind == expected),
            "wrong admission diagnostic for {change}"
        );
    }
    PgLedger::new(pool.clone(), auth()?, control).await?;
    let r = request("tamper", "r", b"original")?;
    committed(store.append(&r, control).await)?;
    sqlx::query("UPDATE rss_ledger.entries SET payload=$1 WHERE chain_id='tamper'")
        .bind(b"tampered".as_slice())
        .execute(owner)
        .await?;
    assert!(matches!(
        observe(store.find(r.ledger(), r.record_id(), control).await),
        Observed::RolledBack(Error::Protocol(rss_ledger::Error::Authentication))
    ));
    assert!(matches!(
        observe(store.append(&r, control).await),
        Observed::RolledBack(Error::Protocol(rss_ledger::Error::Authentication))
    ));
    let r = request("rollback-ack", "r", b"bytes")?;
    let copy = r.clone();
    store.inject_next_fault(PgFault::RollbackFailedAfterAck);
    let result: LocalTxAttempt<Committed<()>, Error> = store
        .local_tx(r.ledger().tenant(), control, move |tx| {
            Box::pin(async move {
                tx.append(&copy).await?;
                Err(Error::Rejected)
            })
        })
        .await;
    assert!(matches!(observe(result),
        Observed::RollbackFailed(Error::Rollback { operation, settlement })
        if matches!(*operation, Error::Rejected) && matches!(*settlement, Error::Deadline(LocalTxDeadlineStage::Rollback))
    ));
    assert!(committed(store.find(r.ledger(), r.record_id(), control).await)?.is_none());
    let malformed = request("malformed", "r", b"bytes")?;
    let original = committed(store.append(&malformed, control).await)?;
    sqlx::raw_sql("ALTER TABLE rss_ledger.entries DROP CONSTRAINT entries_tag_check; UPDATE rss_ledger.entries SET tag='x'::bytea WHERE chain_id='malformed';").execute(owner).await?;
    let damaged = store
        .find(malformed.ledger(), malformed.record_id(), control)
        .await;
    sqlx::query("UPDATE rss_ledger.entries SET tag=$1 WHERE chain_id='malformed'")
        .bind(original.entry().tag().as_bytes().as_slice())
        .execute(owner)
        .await?;
    sqlx::raw_sql("ALTER TABLE rss_ledger.entries ADD CONSTRAINT entries_tag_check CHECK(octet_length(tag)=32)").execute(owner).await?;
    assert!(matches!(
        observe(damaged),
        Observed::RolledBack(Error::StorageContract)
    ));
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let budget = Control::new(&clock, Duration::from_secs(5), &cancel);
    let copy = r.clone();
    let signal = cancel.clone();
    let result = store
        .local_tx(r.ledger().tenant(), &budget, move |tx| {
            Box::pin(async move {
                tx.append(&copy).await?;
                signal.cancel();
                std::future::pending::<Result<(), Error>>().await
            })
        })
        .await;
    assert!(matches!(
        observe(result),
        Observed::CommitUnknown(Error::Cancelled(LocalTxDeadlineStage::Operation))
    ));
    assert!(committed(store.find(r.ledger(), r.record_id(), control).await)?.is_none());
    Ok(())
}

async fn exhaustion(
    store: &PgLedger,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    // Independently authenticated max-sequence fixture: exercise signed SQL range exhaustion.
    sqlx::query("INSERT INTO rss_ledger.heads VALUES($1::uuid,'exhausted','fixture-key',1,9223372036854775807,decode($2,'hex'))")
        .bind(TENANT).bind("393718760c147493c7e504e8753d2912e4a28c44d2aac6d8d8550debf55e2983").execute(owner).await?;
    sqlx::query("INSERT INTO rss_ledger.entries VALUES($1::uuid,'exhausted','last',9223372036854775807,decode(repeat('00',32),'hex'),decode($2,'hex'),''::bytea,1,'fixture-key')")
        .bind(TENANT).bind("393718760c147493c7e504e8753d2912e4a28c44d2aac6d8d8550debf55e2983").execute(owner).await?;
    let r = request("exhausted", "new", b"")?;
    assert!(matches!(
        observe(store.append(&r, control).await),
        Observed::RolledBack(Error::Protocol(rss_ledger::Error::SequenceExhausted))
    ));
    let last = request("exhausted", "last", b"")?;
    assert!(!committed(store.append(&last, control).await)?.inserted());
    let page = committed(
        store
            .read_window(
                last.ledger(),
                Sequence::new(i64::MAX as u64),
                ReadLimit::new(2)?,
                control,
            )
            .await,
    );
    assert!(page.is_err(), "missing predecessor must not be fabricated");
    Ok(())
}

async fn business_atomicity(
    store: &PgLedger,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    sqlx::raw_sql("CREATE TABLE public.ledger_business(tenant_id uuid NOT NULL,id text NOT NULL,PRIMARY KEY(tenant_id,id) DEFERRABLE INITIALLY IMMEDIATE); ALTER TABLE public.ledger_business ENABLE ROW LEVEL SECURITY; ALTER TABLE public.ledger_business FORCE ROW LEVEL SECURITY; CREATE POLICY tenant_scope ON public.ledger_business USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid); GRANT SELECT,INSERT ON public.ledger_business TO ledger_runtime;").execute(owner).await?;
    for fail in [false, true] {
        let id = if fail { "business-fail" } else { "business-ok" };
        let r = request("business", id, b"effect")?;
        let copy = r.clone();
        let outcome = store
            .local_tx(r.ledger().tenant(), control, move |tx| {
                Box::pin(async move {
                    let staged = tx.append(&copy).await?;
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            sqlx::query("INSERT INTO public.ledger_business VALUES($1::uuid,$2)")
                                .bind(TENANT)
                                .bind(id)
                                .execute(&mut *c)
                                .await?;
                            if fail {
                                sqlx::query(
                                    "INSERT INTO public.ledger_business VALUES($1::uuid,$2)",
                                )
                                .bind(TENANT)
                                .bind(id)
                                .execute(c)
                                .await?;
                            }
                            Ok::<_, sqlx::Error>(())
                        })
                    })
                    .await
                    .map_err(|error: sqlx::Error| {
                        assert!(fail);
                        assert_eq!(
                            error.as_database_error().and_then(|e| e.code()).as_deref(),
                            Some("23505")
                        );
                        Error::Rejected
                    })?;
                    Ok(staged)
                })
            })
            .await;
        if fail {
            assert!(matches!(
                observe(outcome),
                Observed::RolledBack(Error::Rejected)
            ));
        } else {
            committed(outcome)?;
        }
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM public.ledger_business WHERE id=$1")
                .bind(id)
                .fetch_one(owner)
                .await?;
        assert_eq!(count, if fail { 0 } else { 1 });
        assert_eq!(
            committed(store.find(r.ledger(), r.record_id(), control).await)?.is_some(),
            !fail
        );
    }
    business_deferred(store, control).await
}

async fn business_deferred(store: &PgLedger, control: &Control<'_, Clock>) -> anyhow::Result<()> {
    let r = request("business", "deferred", b"effect")?;
    let copy = r.clone();
    let outcome = store.local_tx(r.ledger().tenant(), control, move |tx| Box::pin(async move {
        tx.append(&copy).await?;
        tx.with_connection(|c| Box::pin(async move {
            sqlx::raw_sql("SET CONSTRAINTS ledger_business_pkey DEFERRED; INSERT INTO public.ledger_business VALUES('f47ac10b-58cc-4372-a567-0e02b2c3d479','deferred'),('f47ac10b-58cc-4372-a567-0e02b2c3d479','deferred');").execute(c).await?;
            Ok::<_, sqlx::Error>(())
        })).await?;
        Ok(())
    })).await;
    assert!(matches!(
        observe(outcome),
        Observed::CommitUnknown(Error::Storage(_))
    ));
    assert!(committed(store.find(r.ledger(), r.record_id(), control).await)?.is_none());
    Ok(())
}

async fn definer_scope(
    store: &PgLedger,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    for statement in [
        "SELECT rss_ledger.prepare_append($1::uuid,'cross-sql','fixture-key',1::smallint)",
        "SELECT rss_ledger.insert_entry($1::uuid,'cross-sql','r',0,decode(repeat('00',32),'hex'),decode(repeat('00',32),'hex'),''::bytea,'fixture-key',1::smallint)",
    ] {
        let result: LocalTxAttempt<Committed<()>, Error> = store
            .local_tx(TenantId::parse(TENANT)?, control, move |tx| {
                Box::pin(async move {
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            let Err(error) = sqlx::query(statement)
                                .bind("f47ac10b-58cc-4372-a567-0e02b2c3d478")
                                .execute(c)
                                .await
                            else {
                                return Ok(());
                            };
                            assert_eq!(
                                error.as_database_error().and_then(|e| e.code()).as_deref(),
                                Some("PL001")
                            );
                            Err(Error::Rejected)
                        })
                    })
                    .await
                })
            })
            .await;
        assert!(matches!(
            observe(result),
            Observed::RolledBack(Error::Rejected)
        ));
    }
    let count: i64 = sqlx::query_scalar("SELECT (SELECT count(*) FROM rss_ledger.heads WHERE chain_id='cross-sql')+(SELECT count(*) FROM rss_ledger.entries WHERE chain_id='cross-sql')").fetch_one(owner).await?;
    assert_eq!(count, 0);
    Ok(())
}
