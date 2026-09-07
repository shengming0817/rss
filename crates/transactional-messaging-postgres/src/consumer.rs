//! Static trusted effect composition, with private ACK-only commit evidence.
use crate::{PgInboxClaim, PgRuntime, PgTransaction, transaction::stage};
use rss_redact::RedactedSource;
use rss_transactional_messaging::{
    message::{MessageEnvelope, MessageFingerprint},
    policy::{AbsoluteDeadline, OperationDeadline, within},
    transaction::{
        ConsumerTx, FailureClass, LocalTxDeadlineStage, ReceiptIntent, TerminalDisposition,
        TransactionOutcome,
    },
};
use std::sync::Arc;

/// An effect failed without a terminal business rejection. Provider diagnostics stay redacted.
#[derive(Debug, thiserror::Error)]
pub enum PgConsumerEffectFailure {
    /// The application handler may be retried after confirmed rollback.
    #[error("handler transient failure")]
    HandlerTransient(#[source] RedactedSource),
    /// Infrastructure failure is not a local handler retry.
    #[error("consumer infrastructure failure")]
    Infrastructure(#[source] RedactedSource),
}
impl PgConsumerEffectFailure {
    /// Preserve a handler-transient diagnostic without exposing its display text.
    pub fn handler_transient<E: std::error::Error + Send + Sync + 'static>(source: E) -> Self {
        Self::HandlerTransient(RedactedSource::new(source))
    }
    /// Preserve an infrastructure diagnostic without exposing its display text.
    pub fn infrastructure<E: std::error::Error + Send + Sync + 'static>(source: E) -> Self {
        Self::Infrastructure(RedactedSource::new(source))
    }
    fn class(&self) -> FailureClass {
        match self {
            Self::HandlerTransient(_) => FailureClass::Transient,
            Self::Infrastructure(_) => FailureClass::Infrastructure,
        }
    }
}

/// Trusted PG-specific infrastructure implementing application repositories in one transaction.
///
/// Business rejection is `Ok(TerminalDisposition::Rejected(_))`, never an infrastructure error.
pub trait PgConsumerEffect<P>: Send + Sync {
    /// Apply the effect while consuming the transaction's current remaining deadline.
    fn apply(
        &self,
        transaction: &mut PgTransaction<'_>,
        message: &MessageEnvelope<P>,
        deadline: OperationDeadline,
    ) -> impl Future<Output = Result<TerminalDisposition, PgConsumerEffectFailure>> + Send;
}
/// Consumer transaction composition. Application code does not receive this proof's constructor.
pub struct PgConsumerTx<H, M = ReceiptOnly> {
    runtime: Arc<PgRuntime>,
    effect: H,
    mode: M,
}
impl<H> PgConsumerTx<H> {
    /// Bind the pool owner and trusted, statically dispatched effect.
    pub const fn receipt_only(runtime: Arc<PgRuntime>, effect: H) -> Self {
        Self {
            runtime,
            effect,
            mode: ReceiptOnly,
        }
    }
}
/// Evidence minted only after SQLx acknowledged the encompassing database commit.
///
/// ```compile_fail
/// use rss_transactional_messaging_postgres::PgConsumerTxCommitProof;
/// let forged = PgConsumerTxCommitProof { _private: () };
/// ```
pub struct PgConsumerTxCommitProof {
    _private: (),
}

impl<P: AsRef<[u8]> + Sync, H: PgConsumerEffect<P>, M: ConsumerRecoveryMode<P>> ConsumerTx<P>
    for PgConsumerTx<H, M>
{
    type Claim = PgInboxClaim;
    type CommitProof = PgConsumerTxCommitProof;
    async fn execute(
        &self,
        claim: &Self::Claim,
        message: &MessageEnvelope<P>,
        intent: ReceiptIntent,
        deadline: OperationDeadline,
    ) -> TransactionOutcome<Self::CommitProof> {
        if !claim.matches(&self.runtime.binding) {
            return TransactionOutcome::fenced();
        }
        if !matches_message(claim, message, &intent) {
            return TransactionOutcome::not_started(FailureClass::Infrastructure);
        }
        execute_transaction(
            &self.runtime,
            &self.effect,
            &self.mode,
            claim,
            message,
            intent,
            deadline,
        )
        .await
    }
}

async fn execute_transaction<
    P: AsRef<[u8]> + Sync,
    H: PgConsumerEffect<P>,
    M: ConsumerRecoveryMode<P>,
>(
    runtime: &PgRuntime,
    effect: &H,
    mode: &M,
    claim: &PgInboxClaim,
    message: &MessageEnvelope<P>,
    intent: ReceiptIntent,
    deadline: OperationDeadline,
) -> TransactionOutcome<PgConsumerTxCommitProof> {
    let timer = &runtime.timer;
    let cutoff = match AbsoluteDeadline::from_timeout(timer, deadline.timeout()) {
        Ok(value) => value,
        Err(_) => return TransactionOutcome::not_started(FailureClass::Infrastructure),
    };
    let mut lease = match stage(
        timer,
        cutoff,
        LocalTxDeadlineStage::Acquire,
        runtime.acquire(),
    )
    .await
    {
        Ok(value) => value,
        _ => return TransactionOutcome::not_started(FailureClass::Infrastructure),
    };
    let mut transaction =
        match stage(timer, cutoff, LocalTxDeadlineStage::Begin, lease.begin()).await {
            Ok(value) => value,
            _ => return TransactionOutcome::not_started(FailureClass::Infrastructure),
        };
    let mut tx = PgTransaction::new(
        transaction.connection(),
        claim.identity.tenant_id(),
        cutoff,
        runtime,
    );
    let body = within(timer, cutoff, |_| {
        effect_body(effect, mode, &mut tx, claim, message, &intent)
    })
    .await;
    let body = match body {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(phase = "operation", kind = error.kind().as_label(), error = ?error, "consumer transaction deadline elapsed");
            return TransactionOutcome::commit_unknown();
        }
    };
    if cutoff.remaining(timer).is_zero() {
        return TransactionOutcome::commit_unknown();
    }
    finish(transaction, body, intent, timer, cutoff).await
}

fn matches_message<P: AsRef<[u8]>>(
    claim: &PgInboxClaim,
    message: &MessageEnvelope<P>,
    intent: &ReceiptIntent,
) -> bool {
    intent.consumer() == &claim.identity
        && intent.fingerprint() == MessageFingerprint::of(message)
        && claim.identity.tenant_id() == message.metadata().tenant_id()
        && claim.identity.message_id() == message.id()
        && claim.identity.contract() == message.metadata().contract()
}

async fn finish(
    transaction: crate::transaction::BorrowedTransaction<'_>,
    body: Result<Option<TerminalDisposition>, PgConsumerEffectFailure>,
    intent: ReceiptIntent,
    timer: &crate::transaction::PgTimer,
    cutoff: AbsoluteDeadline,
) -> TransactionOutcome<PgConsumerTxCommitProof> {
    match body {
        Ok(Some(disposition)) => match stage(
            timer,
            cutoff,
            LocalTxDeadlineStage::Commit,
            transaction.commit(),
        )
        .await
        {
            Ok(()) => intent.committed(PgConsumerTxCommitProof { _private: () }, disposition),
            _ => TransactionOutcome::commit_unknown(),
        },
        other => {
            let failure = other.err();
            if let Some(error) = &failure {
                tracing::warn!(error = ?error, "consumer transaction rolled back");
            }
            match stage(
                timer,
                cutoff,
                LocalTxDeadlineStage::Rollback,
                transaction.rollback(),
            )
            .await
            {
                Ok(()) => match failure {
                    Some(error) => TransactionOutcome::rolled_back(error.class()),
                    None => TransactionOutcome::fenced(),
                },
                _ => TransactionOutcome::rollback_failed(),
            }
        }
    }
}

async fn effect_body<P: AsRef<[u8]> + Sync, H: PgConsumerEffect<P>, M: ConsumerRecoveryMode<P>>(
    effect: &H,
    mode: &M,
    tx: &mut PgTransaction<'_>,
    claim: &PgInboxClaim,
    message: &MessageEnvelope<P>,
    intent: &ReceiptIntent,
) -> Result<Option<TerminalDisposition>, PgConsumerEffectFailure> {
    if let Err(error) = tx.setup().await {
        if error.kind() == rss_transactional_messaging::error::MessagingErrorKind::OwnershipLost {
            return Ok(None);
        }
        return Err(PgConsumerEffectFailure::infrastructure(error));
    }
    // No row lock across the handler: independent renewal must remain able to update Inbox.
    let held: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM rss_transactional_messaging.inbox WHERE tenant_id=$1::uuid AND message_id=$2 AND consumer_group=$3 AND lease_token=$4::uuid AND disposition IS NULL AND lease_until>clock_timestamp())")
                .bind(claim.identity.tenant_id().to_string()).bind(claim.identity.message_id().as_str()).bind(claim.identity.group().as_str()).bind(&claim.token)
                .fetch_one(&mut *tx.connection).await.map_err(PgConsumerEffectFailure::infrastructure)?;
    if !held {
        return Ok(None);
    }
    sqlx::query("SAVEPOINT rss_tmsg_effect")
        .execute(&mut *tx.connection)
        .await
        .map_err(PgConsumerEffectFailure::infrastructure)?;
    let remaining = tx.deadline();
    let disposition = effect.apply(tx, message, remaining).await?;
    if matches!(disposition, TerminalDisposition::Rejected(_)) {
        sqlx::query("ROLLBACK TO SAVEPOINT rss_tmsg_effect")
            .execute(&mut *tx.connection)
            .await
            .map_err(PgConsumerEffectFailure::infrastructure)?;
    }
    sqlx::query("RELEASE SAVEPOINT rss_tmsg_effect")
        .execute(&mut *tx.connection)
        .await
        .map_err(PgConsumerEffectFailure::infrastructure)?;
    if matches!(disposition, TerminalDisposition::Rejected(_)) {
        mode.record(tx, claim, message, intent, disposition).await?;
    }
    // Acquire the row lock only after effect completion; sample expiry in the next statement
    // so time spent waiting for another writer cannot authorize an expired commit.
    sqlx::query("SELECT 1 FROM rss_transactional_messaging.inbox WHERE tenant_id=$1::uuid AND message_id=$2 AND consumer_group=$3 FOR UPDATE")
                .bind(claim.identity.tenant_id().to_string()).bind(claim.identity.message_id().as_str()).bind(claim.identity.group().as_str())
                .execute(&mut *tx.connection).await.map_err(PgConsumerEffectFailure::infrastructure)?;
    let count = sqlx::query("UPDATE rss_transactional_messaging.inbox SET fingerprint=$5, disposition=$6 WHERE tenant_id=$1::uuid AND message_id=$2 AND consumer_group=$3 AND lease_token=$4::uuid AND disposition IS NULL AND lease_until>clock_timestamp()")
                .bind(claim.identity.tenant_id().to_string()).bind(claim.identity.message_id().as_str()).bind(claim.identity.group().as_str()).bind(&claim.token)
                .bind(intent.fingerprint().as_bytes().as_slice()).bind(disposition.as_label())
                .execute(&mut *tx.connection).await.map_err(PgConsumerEffectFailure::infrastructure)?.rows_affected();
    Ok::<_, PgConsumerEffectFailure>((count == 1).then_some(disposition))
}

/// Explicit receipt-only composition; application DLQ persistence is not selected.
pub struct ReceiptOnly;
pub(crate) mod sealed {
    pub trait Mode {}
}
impl sealed::Mode for ReceiptOnly {}
/// Closed static consumer composition. Applications cannot insert transaction hooks.
pub trait ConsumerRecoveryMode<P>: sealed::Mode + Send + Sync {
    /// Persist a rejected message after rollback of its business effect, inside the outer transaction.
    fn record(
        &self,
        tx: &mut PgTransaction<'_>,
        claim: &PgInboxClaim,
        message: &MessageEnvelope<P>,
        intent: &ReceiptIntent,
        disposition: TerminalDisposition,
    ) -> impl Future<Output = Result<(), PgConsumerEffectFailure>> + Send;
}
impl<P: Sync> ConsumerRecoveryMode<P> for ReceiptOnly {
    async fn record(
        &self,
        _: &mut PgTransaction<'_>,
        _: &PgInboxClaim,
        _: &MessageEnvelope<P>,
        _: &ReceiptIntent,
        _: TerminalDisposition,
    ) -> Result<(), PgConsumerEffectFailure> {
        // reason: receipt-only is an explicitly selected capability, not a failed recovery fallback.
        Ok(())
    }
}
#[cfg(feature = "recovery")]
impl<H> PgConsumerTx<H> {
    /// Select atomic protected dead letters using the capture capability's verified runtime.
    pub fn with_recovery<K>(
        effect: H,
        capture: crate::PgRecoveryCapture<K>,
    ) -> PgConsumerTx<H, crate::PgRecoveryCapture<K>> {
        PgConsumerTx {
            runtime: capture.runtime.clone(),
            effect,
            mode: capture,
        }
    }
}
