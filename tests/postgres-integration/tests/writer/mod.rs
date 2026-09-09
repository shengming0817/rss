//! Writer behavior under the producer ACL, using the same transaction/fence owner as business SQL.
use super::{Timer, deadline, fence_fixture, message, outbox_budget};
use rss_request_context::TenantId;
use rss_transactional_messaging::{
    error::MessagingErrorKind,
    message::{MessageEnvelope, MessagingDomain},
    outbox::{AppendOutcome, OutboxWriter, PendingMessage},
};
use rss_transactional_messaging_postgres::{PgConfig, PgOutboxStore, PgOutboxWriter, PgRuntime};
use std::{sync::Arc, time::Duration};

pub(super) async fn run(
    runtime: Arc<PgRuntime>,
    config: PgConfig,
    owner: &sqlx::PgPool,
) -> anyhow::Result<()> {
    interoperability(runtime.clone()).await?;
    rejection(runtime.clone(), config).await?;
    let tenant = message("writer-fenced").metadata().tenant_id();
    sqlx::query(
        "UPDATE rss_transactional_messaging.tenant_epoch SET epoch=2 WHERE tenant_id=$1::uuid",
    )
    .bind(tenant.to_string())
    .execute(owner)
    .await?;
    let writer = PgOutboxWriter::new(runtime.clone(), MessagingDomain::parse("integration")?);
    let outcome = runtime
        .local_tx(tenant, deadline(), move |tx| {
            Box::pin(async move {
                writer
                    .append(tx, PendingMessage::new(message("writer-fenced")))
                    .await?;
                Ok(())
            })
        })
        .await
        .fold(Ok, Err, Err, Err, Err, Err);
    // Restore this isolated fixture even when the assertion would fail.
    sqlx::query(
        "UPDATE rss_transactional_messaging.tenant_epoch SET epoch=1 WHERE tenant_id=$1::uuid",
    )
    .bind(tenant.to_string())
    .execute(owner)
    .await?;
    assert_eq!(
        outcome.expect_err("stale producer is fenced").kind(),
        MessagingErrorKind::OwnershipLost
    );
    let rejected: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.outbox WHERE message_id IN ('writer-rejected','writer-fenced')")
        .fetch_one(owner).await?;
    assert_eq!(rejected, 0);
    sqlx::query("DELETE FROM rss_transactional_messaging.outbox WHERE message_id IN ('writer-first','writer-full-first')").execute(owner).await?;
    Ok(())
}

async fn interoperability(runtime: Arc<PgRuntime>) -> anyhow::Result<()> {
    for (id, full_first) in [("writer-first", false), ("writer-full-first", true)] {
        let writer = PgOutboxWriter::new(runtime.clone(), MessagingDomain::parse("integration")?);
        let full = PgOutboxStore::<()>::new(
            runtime.clone(),
            MessagingDomain::parse("integration")?,
            outbox_budget(Duration::from_secs(60)),
        )?;
        let tenant = message(id).metadata().tenant_id();
        runtime
            .local_tx(tenant, deadline(), move |tx| {
                Box::pin(async move {
                    let first = PendingMessage::new(message(id));
                    let second = PendingMessage::new(message(id));
                    let (inserted, repeated) = if full_first {
                        (
                            full.append(tx, first).await?,
                            writer.append(tx, second).await?,
                        )
                    } else {
                        (
                            writer.append(tx, first).await?,
                            full.append(tx, second).await?,
                        )
                    };
                    assert_eq!(inserted, AppendOutcome::Inserted);
                    assert_eq!(repeated, AppendOutcome::AlreadyPresent);
                    let original = message(id);
                    let conflict = MessageEnvelope::new(
                        original.id().clone(),
                        original.metadata().clone(),
                        vec![9],
                    );
                    assert_eq!(
                        writer
                            .append(tx, PendingMessage::new(conflict))
                            .await
                            .expect_err("same ID, different payload")
                            .kind(),
                        MessagingErrorKind::Conflict
                    );
                    Ok(())
                })
            })
            .await
            .fold(Ok, Err, Err, Err, Err, Err)?;
    }
    Ok(())
}

async fn rejection(runtime: Arc<PgRuntime>, config: PgConfig) -> anyhow::Result<()> {
    let foreign = Arc::new(
        PgRuntime::connect_producer(config, Timer::new(), fence_fixture::binding()).await?,
    );
    let tenant = message("writer-rejected").metadata().tenant_id();
    let other_tenant = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d480")?;
    for (owner, tx_tenant, domain) in [
        (foreign.clone(), tenant, "integration"),
        (runtime.clone(), other_tenant, "integration"),
        (runtime.clone(), tenant, "wrong-domain"),
    ] {
        let writer = PgOutboxWriter::new(owner, MessagingDomain::parse(domain)?);
        let outcome = runtime
            .local_tx(tx_tenant, deadline(), move |tx| {
                Box::pin(async move {
                    writer
                        .append(tx, PendingMessage::new(message("writer-rejected")))
                        .await?;
                    Ok(())
                })
            })
            .await
            .fold(Ok, Err, Err, Err, Err, Err);
        assert_eq!(
            outcome.expect_err("wrong writer authority").kind(),
            MessagingErrorKind::Invariant
        );
    }
    foreign.close().await;
    Ok(())
}

pub(super) async fn examples(fixture: &testkit::PgTlsFixture) -> anyhow::Result<()> {
    let params = fixture.params();
    let binaries: Vec<String> = match std::env::var("RSS_OUTBOX_WRITER_CONSUMERS") {
        Ok(value) => {
            let values: Vec<String> = serde_json::from_str(&value)?;
            anyhow::ensure!(!values.is_empty(), "empty writer selection");
            values
        }
        Err(std::env::VarError::NotPresent) => vec![String::new()],
        Err(error) => return Err(error.into()),
    };
    for (index, binary) in binaries.iter().enumerate() {
        let input = serde_json::json!({
            "host":params.host,"port":params.port,"database":params.database,
            "username":"tmsg_runtime","password":"fixture-only","pg_ca":fixture.ca_pem(),
            "tenant":"f47ac10b-58cc-4372-a567-0e02b2c3d479",
            "target":([1;16]),"lineage":([2;16]),"epoch":1,"id":format!("external-writer-{index}"),
        });
        if binary.is_empty() {
            rss_examples::outbox_writer::run(serde_json::from_value(input)?).await?;
        } else {
            testkit::example_process::run_binary(binary, &input, Duration::from_secs(60)).await?;
            eprintln!("external-provider-consumer PASS {binary}");
        }
    }
    Ok(())
}
