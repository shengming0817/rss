use super::*;
use crate::support::message_in_partition;
use rss_transactional_messaging::{inbox::*, message::*, transaction::*};
struct Validator(ExecutionBinding);
impl IngressValidator<Vec<u8>> for Validator {
    fn validate(
        &self,
        c: IngressChallenge<'_, Vec<u8>>,
    ) -> Result<VerifiedIngress, EnvelopeValidationFailure> {
        Ok(c.verified(self.0))
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
        let id = message.id().as_str().to_owned();
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query("INSERT INTO public.dr_effect VALUES($1)")
                    .bind(id)
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await
        .map_err(PgConsumerEffectFailure::infrastructure)?;
        Ok(TerminalDisposition::Succeeded)
    }
}
pub(super) fn consumer_binding(
    execution: ExecutionBinding,
    message: &MessageEnvelope<Vec<u8>>,
) -> anyhow::Result<VerifiedConsumerBinding> {
    let m = message.metadata();
    verify_ingress(
        &Validator(execution),
        ConsumerGroup::parse("test")?,
        &SubscriptionIdentity::new(m.domain().clone(), m.route().clone(), m.contract().clone()),
        message,
    )
    .map_err(|_| anyhow::anyhow!("ingress"))
}
#[allow(clippy::cognitive_complexity)] // reason: sequential committed-effect, rollback and physical-lineage evidence checks.
pub async fn run(config: PgConfig, operator: PgConfig, owner: &sqlx::PgPool) -> anyhow::Result<()> {
    let clock = Timer::new();
    let msg = message_in_partition("broker-member", "broker-member");
    let consumer = consumer_binding(binding(9)?, &msg)?;
    let plan = Plan::new(
        tenant(),
        OperationId::new(),
        binding(8)?.storage(),
        Epoch::new(8)?,
        RestoreEvidence::new([3; 32], [4; 32])?,
        vec![Member::Consumer {
            identity: consumer.identity().clone(),
            fingerprint: MessageFingerprint::of(&msg),
        }],
    )?;
    let request = authorize_dr(&Allow, plan, &clock, clock.cutoff()).await?;
    let store = PgDrStore::connect(operator.clone(), Timer::new(), (binding(8)?).storage()).await?;
    committed(store.apply(&request, deadline()).await)?;
    sqlx::raw_sql("CREATE TABLE public.dr_effect(id text PRIMARY KEY); GRANT SELECT,INSERT ON public.dr_effect TO dr_runtime;").execute(owner).await?;
    let runtime =
        Arc::new(PgRuntime::connect(config.clone(), Timer::new(), (binding(9)?).storage()).await?);
    let inbox = PgInboxStore::new(
        runtime.clone(),
        LeaseRenewalPolicy::from_ttl(Duration::from_secs(30))?,
    )?;
    let claim = match inbox.claim(&consumer, deadline()).await? {
        IdempotencyDisposition::Acquired(c) => c,
        _ => anyhow::bail!("consumer claim"),
    };
    let tx = PgConsumerTx::receipt_only(runtime.clone(), Effect);
    let result = tx
        .execute(&claim, &msg, consumer.receipt_intent(), deadline())
        .await;
    assert_eq!(result.status(),rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus::Committed);
    assert_eq!(
        store
            .progress(&request, deadline())
            .await?
            .ok_or_else(|| anyhow::anyhow!("progress"))?
            .members,
        vec![MemberStatus::Completed]
    );
    assert!(matches!(
        inbox.claim(&consumer, deadline()).await?,
        IdempotencyDisposition::Terminal(_)
    ));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM public.dr_effect")
        .fetch_one(owner)
        .await?;
    assert_eq!(count, 1);
    // Same tenant/id/group but different trusted authored facts must prevent admission and progress.
    let mismatch = message_in_partition("broker-mismatch", "broker-mismatch");
    let identity = consumer_binding(binding(10)?, &mismatch)?;
    let clock = Timer::new();
    let request = authorize_dr(
        &Allow,
        Plan::new(
            tenant(),
            OperationId::new(),
            binding(9)?.storage(),
            Epoch::new(9)?,
            RestoreEvidence::new([3; 32], [4; 32])?,
            vec![Member::Consumer {
                identity: identity.identity().clone(),
                fingerprint: MessageFingerprint::from_bytes([9; 32]),
            }],
        )?,
        &clock,
        clock.cutoff(),
    )
    .await?;
    let operator4 =
        PgDrStore::connect(operator.clone(), Timer::new(), (binding(9)?).storage()).await?;
    committed(operator4.apply(&request, deadline()).await)?;
    let inbox = PgInboxStore::new(
        runtime.clone(),
        LeaseRenewalPolicy::from_ttl(Duration::from_secs(30))?,
    )?;
    assert_eq!(
        inbox
            .claim(&identity, deadline())
            .await
            .err()
            .map(|error| error.kind()),
        Some(rss_transactional_messaging::error::MessagingErrorKind::Conflict)
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM public.dr_effect")
        .fetch_one(owner)
        .await?;
    assert_eq!(count, 1, "mismatched member never starts");
    assert_eq!(
        operator4
            .progress(&request, deadline())
            .await?
            .ok_or_else(|| anyhow::anyhow!("progress"))?
            .members,
        vec![MemberStatus::Pending]
    );
    // Simulate a restored old fence snapshot. The host's new lineage cannot self-validate from it.
    sqlx::raw_sql("UPDATE rss_transactional_messaging.tenant_epoch SET epoch=1;")
        .execute(owner)
        .await?;
    let new_binding = ExecutionBinding::new(
        StorageIdentity::new([1; 16], [3; 16])?,
        tenant(),
        Epoch::new(1)?,
    );
    let fresh = PgRuntime::connect(config.clone(), Timer::new(), (new_binding).storage()).await?;
    let attempt = fresh
        .local_tx(new_binding, deadline(), |_| Box::pin(async { Ok(()) }))
        .await;
    assert!(
        attempt.fold(
            |_| false,
            |_| false,
            |_| false,
            |_| false,
            |_| false,
            |_| true
        ),
        "restored DB is not evidence of the externally selected lineage"
    );
    // External migrator installs the verified lineage while traffic is isolated.
    sqlx::query("UPDATE rss_transactional_messaging.storage_lineage SET lineage=$1")
        .bind([3u8; 16].as_slice())
        .execute(owner)
        .await?;
    committed(
        fresh
            .local_tx(new_binding, deadline(), |_| Box::pin(async { Ok(()) }))
            .await,
    )?;
    let old = PgRuntime::connect(config, Timer::new(), (binding(1)?).storage()).await?;
    assert!(
        old.local_tx(crate::execution(tenant(), 1), deadline(), |_| Box::pin(
            async { Ok(()) }
        ))
        .await
        .fold(
            |_| false,
            |_| false,
            |_| false,
            |_| false,
            |_| false,
            |_| true
        )
    );
    old.close().await;
    fresh.close().await;
    operator4.close().await;
    runtime.close().await;
    store.close().await;
    Ok(())
}
