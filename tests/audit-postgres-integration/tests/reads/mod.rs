use super::*;
use rss_ledger::Sequence;

pub(super) async fn run(
    plain: &PgAudit,
    ledger: &PgAudit,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let other = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d480")?;
    let one = plain
        .prepare(event(other, "read", "large", vec![5; 65536])?, control)
        .await?;
    committed(plain.append(&one, control).await)?;
    let bytes = one.canonical_bytes().len() as u64;
    assert_eq!(
        committed(
            plain
                .read_page(Cursor::start(other), ReadLimit::new(1, bytes)?, control)
                .await
        )?
        .records()
        .len(),
        1
    );
    rolled_back(
        plain
            .read_page(Cursor::start(other), ReadLimit::new(1, bytes - 1)?, control)
            .await,
        |e| matches!(e, Error::ReadBudgetExceeded),
    );
    let copy = one.clone();
    rolled_back(
        plain
            .write_tx_with_context(tenant()?, control, (), move |_, tx| {
                Box::pin(async move { tx.append(&copy).await })
            })
            .await,
        |e| matches!(e, TransactionError::Operation(Error::ScopeMismatch)),
    );
    let count = committed(
        plain
            .write_tx_with_context(tenant()?, control, (), move |_, tx| {
                Box::pin(async move {
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            Ok::<_, Error>(sqlx::query_scalar::<_, i64>(
                                "SELECT count(*) FROM rss_audit.records WHERE tenant_id=$1::uuid",
                            )
                            .bind(other.to_string())
                            .fetch_one(c)
                            .await?)
                        })
                    })
                    .await
                })
            })
            .await,
    )?;
    assert_eq!(count, 0);
    let verified = committed(
        ledger
            .read_verified(
                tenant()?,
                Sequence::new(0),
                rss_ledger_postgres::ReadLimit::new(1024, 1_000_000)?,
                control,
            )
            .await,
    )?;
    assert!(verified.records().len() >= 5);
    rolled_back(
        plain
            .read_verified(
                tenant()?,
                Sequence::new(0),
                rss_ledger_postgres::ReadLimit::new(1, 10000)?,
                control,
            )
            .await,
        |e| matches!(e, Error::IntegrityRequired),
    );
    rolled_back(
        ledger
            .read_verified(
                tenant()?,
                Sequence::new(1),
                rss_ledger_postgres::ReadLimit::new(1, 1)?,
                control,
            )
            .await,
        |e| {
            matches!(
                e,
                Error::Ledger(rss_ledger_postgres::Error::ReadBudgetExceeded)
            )
        },
    );
    capacity(plain, ledger, control).await?;
    corruption(plain, ledger, admin, control, &one).await
}

async fn corruption(
    plain: &PgAudit,
    ledger: &PgAudit,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
    one: &PreparedAuditV1,
) -> anyhow::Result<()> {
    ledger_metadata(ledger, admin, control).await?;
    let other = one.identity().tenant();
    sqlx::query("UPDATE rss_audit.records SET recorded_at=0 WHERE tenant_id=$1::uuid")
        .bind(other.to_string())
        .execute(admin)
        .await?;
    rolled_back(
        plain
            .read_page(Cursor::start(other), ReadLimit::new(1, 100000)?, control)
            .await,
        |e| matches!(e, Error::StorageContract),
    );
    sqlx::query("UPDATE rss_audit.records SET recorded_at=$1 WHERE tenant_id=$2::uuid")
        .bind(
            decode_untrusted(one.canonical_bytes())?
                .recorded_at()
                .unix_seconds(),
        )
        .bind(other.to_string())
        .execute(admin)
        .await?;
    let original: Vec<u8> = sqlx::query_scalar(
        "SELECT payload FROM rss_ledger.entries WHERE tenant_id=$1::uuid AND seq=0",
    )
    .bind(tenant()?.to_string())
    .fetch_one(admin)
    .await?;
    sqlx::query("UPDATE rss_ledger.entries SET payload=decode('010203','hex') WHERE tenant_id=$1::uuid AND seq=0").bind(tenant()?.to_string()).execute(admin).await?;
    rolled_back(
        ledger
            .read_verified(
                tenant()?,
                Sequence::new(0),
                rss_ledger_postgres::ReadLimit::new(1, 10000)?,
                control,
            )
            .await,
        |e| matches!(e, Error::Ledger(_)),
    );
    sqlx::query("UPDATE rss_ledger.entries SET payload=$1 WHERE tenant_id=$2::uuid AND seq=0")
        .bind(original)
        .bind(tenant()?.to_string())
        .execute(admin)
        .await?;
    sqlx::query("DELETE FROM rss_audit.records WHERE tenant_id=$1::uuid")
        .bind(other.to_string())
        .execute(admin)
        .await?;
    let empty = committed(
        plain
            .read_page(Cursor::start(other), ReadLimit::new(1, 100000)?, control)
            .await,
    )?;
    assert!(empty.records().is_empty());
    assert!(empty.next().is_none());
    mixed_corruption(ledger, admin, control).await
}

async fn ledger_metadata(
    ledger: &PgAudit,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let original: Vec<u8> = sqlx::query_scalar(
        "SELECT canonical FROM rss_audit.records WHERE tenant_id=$1::uuid AND ledger_sequence=0",
    )
    .bind(tenant()?.to_string())
    .fetch_one(admin)
    .await?;
    let decoded = decode_untrusted(&original)?;
    let identity = decoded.event().identity();
    for update in [
        "UPDATE rss_audit.records SET source_id='corrupted' WHERE tenant_id=$1::uuid AND ledger_sequence=0",
        "UPDATE rss_audit.records SET event_id='corrupted' WHERE tenant_id=$1::uuid AND ledger_sequence=0",
        "UPDATE rss_audit.records SET recorded_at=0 WHERE tenant_id=$1::uuid AND ledger_sequence=0",
    ] {
        sqlx::query(update)
            .bind(tenant()?.to_string())
            .execute(admin)
            .await?;
        rolled_back(
            ledger
                .read_verified(
                    tenant()?,
                    Sequence::new(0),
                    rss_ledger_postgres::ReadLimit::new(1, 10000)?,
                    control,
                )
                .await,
            |e| matches!(e, Error::StorageContract),
        );
        sqlx::query("UPDATE rss_audit.records SET source_id=$2,event_id=$3,recorded_at=$4 WHERE tenant_id=$1::uuid AND ledger_sequence=0")
            .bind(tenant()?.to_string())
            .bind(identity.source().source_id().as_str())
            .bind(identity.event_id().as_str())
            .bind(decoded.recorded_at().unix_seconds())
            .execute(admin)
            .await?;
    }
    Ok(())
}

async fn capacity(
    plain: &PgAudit,
    ledger: &PgAudit,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let token = "a".repeat(255);
    for (store, tenant_text, integrity) in [
        (plain, "f47ac10b-58cc-4372-a567-0e02b2c3d500", false),
        (ledger, "f47ac10b-58cc-4372-a567-0e02b2c3d501", true),
    ] {
        let tenant = TenantId::parse(tenant_text)?;
        let make = |payload| -> anyhow::Result<AuditEventV1> {
            let base = event(tenant, &token, &token, vec![])?;
            Ok(AuditEventV1::new(
                base.identity().clone(),
                EventFacts::new(
                    ActorRef::new(ActorKind::parse(&token)?, ActorId::parse(&"é".repeat(256))?),
                    Action::parse(&token)?,
                    ResourceRef::new(
                        ResourceKind::parse(&token)?,
                        ResourceId::parse(&"é".repeat(256))?,
                    ),
                    Outcome::Succeeded,
                    base.facts().occurred_at(),
                ),
                EventContext::new(
                    Coordinates::new(
                        Some(rss_diag_context::CorrelationId::parse(&token)?),
                        Some(rss_request_context::RequestId::parse(&"r".repeat(128))?),
                        Some(OperationId::parse(&token)?),
                    ),
                    AuditPayload::new(payload)?,
                ),
            ))
        };
        let stamp = Timepoint::try_from(456_i64)?;
        let overhead = prepare(make(vec![])?, stamp)?.canonical_bytes().len();
        let prepared = prepare(make(vec![7; MAX_RECORD_BYTES - overhead])?, stamp)?;
        let first = committed(store.append(&prepared, control).await)?;
        assert!(first.inserted());
        assert!(!committed(store.append(&prepared, control).await)?.inserted());
        let restored =
            PreparedAuditV1::from_canonical_bytes(first.record().prepared().canonical_bytes())?;
        assert_eq!(restored.canonical_bytes(), prepared.canonical_bytes());
        let page = committed(
            store
                .read_page(
                    Cursor::start(tenant),
                    ReadLimit::new(1, MAX_RECORD_BYTES as u64)?,
                    control,
                )
                .await,
        )?;
        assert_eq!(
            page.records()[0].prepared().canonical_bytes(),
            prepared.canonical_bytes()
        );
        let changed = prepare(make(vec![8])?, stamp)?;
        rolled_back(store.append(&changed, control).await, |e| {
            matches!(e, Error::Conflict)
        });
        if integrity {
            let request = prepared.append_request()?;
            assert_eq!(request.record_id().as_str().len(), 514);
            let bytes = auth()?.append(&request, None)?.encoded_len() as u64;
            let window = committed(
                store
                    .read_verified(
                        tenant,
                        Sequence::new(0),
                        rss_ledger_postgres::ReadLimit::new(1, bytes)?,
                        control,
                    )
                    .await,
            )?;
            assert_eq!(
                window.records()[0]
                    .record()
                    .event()
                    .context()
                    .coordinates()
                    .correlation_id()
                    .ok_or_else(|| anyhow::anyhow!("correlation missing"))?
                    .as_str(),
                token
            );
        }
    }
    Ok(())
}

/// An invalid Audit identity, a later decode error, and a missing association have distinct precedence.
async fn mixed_corruption(
    store: &PgAudit,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    use rss_ledger::{AppendRequest, RecordId};
    let tenant = TenantId::parse("5da916c9-f320-44aa-bac1-c891538fad53")?;
    let at = Timepoint::try_from(456_i64)?;
    let first = prepare(event(tenant, "mixed", "first", vec![])?, at)?;
    let second = prepare(event(tenant, "mixed", "second", vec![])?, at)?;
    for row in [&first, &second] {
        committed(store.append(row, control).await)?;
    }

    let auth = auth()?;
    let ledger = first.append_request()?.ledger().clone();
    let wrong_id = AppendRequest::new(
        ledger.clone(),
        RecordId::parse("wrong")?,
        first.canonical_bytes().to_vec(),
    )?;
    let first = auth.append(&wrong_id, None)?;
    let mut trailing = second.canonical_bytes().to_vec();
    trailing.push(0);
    let malformed = AppendRequest::new(
        ledger,
        second.append_request()?.record_id().clone(),
        trailing,
    )?;
    let second = auth.append(&malformed, Some(&first))?;
    let mut tx = admin.begin().await?;
    for entry in [&first, &second] {
        sqlx::query("UPDATE rss_ledger.entries SET record_id=$3, payload=$4, previous_tag=$5, tag=$6 WHERE tenant_id=$1::uuid AND seq=$2")
            .bind(tenant.to_string()).bind(i64::try_from(entry.sequence().get())?)
            .bind(entry.record_id().as_str()).bind(entry.payload()).bind(entry.previous_tag().as_bytes().as_slice())
            .bind(entry.tag().as_bytes().as_slice()).execute(&mut *tx).await?;
    }
    sqlx::query("UPDATE rss_ledger.heads SET tag=$2 WHERE tenant_id=$1::uuid")
        .bind(tenant.to_string())
        .bind(second.tag().as_bytes().as_slice())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    let read = async |count| {
        let limit = rss_ledger_postgres::ReadLimit::new(count, 10_000)?;
        Ok::<_, anyhow::Error>(
            store
                .read_verified(tenant, Sequence::new(0), limit, control)
                .await,
        )
    };
    rolled_back(read(1).await?, |e| {
        matches!(e, Error::Protocol(rss_audit_core::Error::IdentityMismatch))
    });
    rolled_back(read(2).await?, |e| {
        matches!(e, Error::Protocol(rss_audit_core::Error::UnknownField))
    });
    sqlx::query("DELETE FROM rss_audit.records WHERE tenant_id=$1::uuid AND ledger_sequence=0")
        .bind(tenant.to_string())
        .execute(admin)
        .await?;
    for count in [1, 2] {
        rolled_back(read(count).await?, |e| matches!(e, Error::StorageContract));
    }
    Ok(())
}
