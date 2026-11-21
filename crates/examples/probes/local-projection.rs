//! Run a committed effect and an unknown-commit recovery using a fixed consumer login.
use futures::StreamExt as _;
use rss_examples::{
    ephemeral::EphemeralKey,
    pg,
    recovery::{Timer, binding, config, deadline},
};
use rss_transactional_messaging::{
    fence::ExecutionBinding,
    inbox::ConsumerGroup,
    message::{MessageEnvelope, MessagingDomain},
    observability::TransactionalMessagingTransactionStatus as Status,
    policy::*,
    transaction::*,
};
use rss_transactional_messaging_postgres::*;
use std::{num::NonZeroUsize, sync::Arc, time::Duration};

struct Validator(ExecutionBinding);
impl IngressValidator<Vec<u8>> for Validator {
    fn validate(
        &self,
        input: IngressChallenge<'_, Vec<u8>>,
    ) -> Result<VerifiedIngress, EnvelopeValidationFailure> {
        Ok(input.verified(self.0))
    }
}

struct Effect;
impl PgConsumerEffect<Vec<u8>> for Effect {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        message: &MessageEnvelope<Vec<u8>>,
        _: OperationDeadline,
    ) -> Result<TerminalDisposition, PgConsumerEffectFailure> {
        let mut id = message.id().as_str();
        tx.with_connection_context(&mut id, |id, conn| {
            Box::pin(async move {
                sqlx::query("INSERT INTO public.effect_a VALUES($1)")
                    .bind(*id)
                    .execute(conn)
                    .await?;
                Ok(())
            })
        })
        .await
        .map_err(PgConsumerEffectFailure::infrastructure)?;
        Ok(TerminalDisposition::Succeeded)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    #[derive(serde::Deserialize)]
    struct Input {
        #[serde(flatten)]
        pg: pg::Input,
        #[serde(default)]
        install: bool,
    }
    let Input { pg: input, install } = pg::read()?;
    if install {
        let pool = input.pool().await?;
        let mut tx = pool.begin().await?;
        sqlx::raw_sql(MIGRATION_SQL).execute(&mut *tx).await?;
        grant_local_projection(
            &mut tx,
            "projection_worker",
            &MessagingDomain::parse("orders")?,
            &ConsumerGroup::parse("projection")?,
        )
        .await?;
        tx.commit().await?;
        return Ok(());
    }
    let binding = binding(&input)?;
    let runtime =
        Arc::new(PgRuntime::connect_consumer(config(&input)?, Timer, binding.storage()).await?);
    let ttl = Duration::from_secs(8);
    let budget = DeliveryBudget::new(ttl, ttl / 8, ttl / 8, ttl / 8)?;
    let projection = async |domain: &str, group: &str| {
        let key = Arc::new(EphemeralKey::from_bytes(&[1; 32], "candidate")?);
        let capture = PgRecoveryCapture::new(runtime.clone(), key, deadline()?).await?;
        Ok::<_, anyhow::Error>(
            PgLocalProjection::new(
                capture,
                ConsumerGroup::parse(group)?,
                MessagingDomain::parse(domain)?,
                Effect,
                budget,
                LeaseRenewalPolicy::from_ttl(ttl)?,
                deadline()?,
            )
            .await?,
        )
    };
    for (domain, group) in [
        ("orders", "another-group"),
        ("another-domain", "projection"),
    ] {
        let result = projection(domain, group).await;
        anyhow::ensure!(matches!(
            result
                .as_ref()
                .err()
                .and_then(|e| e.downcast_ref::<PgError>()),
            Some(PgError::IncompatibleStorageContract(
                PgStorageContractFailure::RuntimeAcl
            ))
        ));
    }
    let worker = projection("orders", "projection").await?;
    let validator = Validator(binding);
    for (id, expected) in [
        ("candidate-success", Status::Committed),
        ("candidate-unknown", Status::CommitUnknown),
    ] {
        if expected == Status::CommitUnknown {
            worker.inject_next_projection_fault(
                PgTransactionFault::CommitUnknownAfterAck,
                std::future::ready(()),
            )?;
        }
        let stream = worker
            .project_batch(binding, &validator, NonZeroUsize::MIN, deadline()?, ttl)
            .await?;
        tokio::pin!(stream);
        let item = stream
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("missing candidate source"))?;
        anyhow::ensure!(item.message_id().as_str() == id);
        let PgProjectionOutcome::Attempt(attempt) = item.into_outcome()? else {
            anyhow::bail!("no transaction attempt")
        };
        let (outcome, pending) = attempt.into_parts();
        anyhow::ensure!(outcome.status() == expected);
        if expected == Status::CommitUnknown {
            anyhow::ensure!(
                worker
                    .resolve(&pending, deadline()?)
                    .await?
                    .map(|r| r.disposition())
                    == Some(TerminalDisposition::Succeeded)
            );
        }
    }
    runtime.close().await;
    Ok(())
}
