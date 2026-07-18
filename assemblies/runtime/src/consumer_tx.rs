//! ConsumerTx —— durable consumer transaction driver.
//!
//! This module keeps the existing ConsumerBase preflight/claim/lease/broker-settle contract, but
//! changes the Fresh success path: the assembly-private tx handler is implemented only for the
//! concrete Postgres providers selected by generated topology. The provider commits domain writes,
//! outgoing outbox rows, and inbox `done` in one storage transaction; only then can its opaque
//! proof reach this private driver and authorize broker settlement.
//!
//! ref: serverlesstechnology/cqrs persistence/postgres-es/src/event_repository.rs@main

use std::sync::Arc;

use consistency::idempotency::{IdemKey, LeaseToken, SeenState};
use consistency::{EngineErrorKind, InboxReceiptContext};
use diport::{EnvelopeHeaderError, Message};
use futures::StreamExt;
use futures::future::BoxFuture;
use tracing::Instrument as _;

use eventexec::MAX_REDELIVERY;
use eventexec::consumer::{
    ConsumerMeta, LeaseConfig, ReceiptContextBuildError, build_consume_span, dead_letter,
    emit_lease_lost, envelope_header_error_reason, log_lease_lost, receipt_context_error_reason,
    record_dead_letter_skip, renewal_loop, settle,
};

/// Closed ConsumerTx external-effect policies used as type-level handler capabilities.
pub(crate) mod policy {
    mod private {
        pub trait Sealed {}
    }

    /// Effects are confined to the durable database transaction.
    pub(crate) struct TransactionalOnly;
    /// External state is rebuilt from an authoritative source.
    pub(crate) struct Reconcile;

    impl private::Sealed for TransactionalOnly {}
    impl private::Sealed for Reconcile {}

    /// Sealed marker implemented only by currently activatable policies.
    pub(crate) trait Policy: private::Sealed + Send + Sync + 'static {}

    impl Policy for TransactionalOnly {}
    impl Policy for Reconcile {}
}

/// Assembly-owned durable consumer transaction handler.
///
/// This trait is crate-private and has implementations only for the five concrete Postgres
/// handlers selected by the closed generated plan. Downstream crates cannot add an implementation
/// or enter the Ack-authorizing runner.
pub(crate) trait ConsumerTxHandler<P: policy::Policy>: Send + Sync + 'static {
    /// Opaque proof minted by the provider only after its transaction is confirmed committed.
    type CommitProof: Send + 'static;

    /// Execute one claimed delivery while retaining the policy marker and provider proof type.
    fn handle(
        self: Arc<Self>,
        message: Message,
        context: InboxReceiptContext,
        key: IdemKey,
        lease: LeaseToken,
    ) -> BoxFuture<'static, ConsumerTxOutcome<Self::CommitProof>>;
}

fn map_postgres_outcome(outcome: postgres::PgConsumerTxOutcome) -> ConsumerTxOutcome<()> {
    match outcome {
        postgres::PgConsumerTxOutcome::Committed(_provider_proof) => {
            ConsumerTxOutcome::Committed(())
        }
        postgres::PgConsumerTxOutcome::Requeue(requeue) if requeue.is_commit_unknown() => {
            ConsumerTxOutcome::commit_unknown(requeue.summary())
        }
        postgres::PgConsumerTxOutcome::Requeue(requeue) => {
            ConsumerTxOutcome::handler_transient(requeue.summary())
        }
        postgres::PgConsumerTxOutcome::LeaseLost { summary } => {
            ConsumerTxOutcome::LeaseLost { summary }
        }
        postgres::PgConsumerTxOutcome::Reject { summary } => ConsumerTxOutcome::Reject { summary },
    }
}

impl<M> ConsumerTxHandler<policy::TransactionalOnly> for postgres::PgAuditConsumerTx<M>
where
    M: primitives::MacVerifier + Send + Sync + 'static,
{
    type CommitProof = ();

    fn handle(
        self: Arc<Self>,
        message: Message,
        context: InboxReceiptContext,
        key: IdemKey,
        lease: LeaseToken,
    ) -> BoxFuture<'static, ConsumerTxOutcome<Self::CommitProof>> {
        Box::pin(async move {
            map_postgres_outcome(
                postgres::PgAuditConsumerTx::handle(self, message, context, key, lease).await,
            )
        })
    }
}

impl ConsumerTxHandler<policy::Reconcile> for postgres::PgSettingsConsumerTx {
    type CommitProof = ();

    fn handle(
        self: Arc<Self>,
        message: Message,
        context: InboxReceiptContext,
        key: IdemKey,
        lease: LeaseToken,
    ) -> BoxFuture<'static, ConsumerTxOutcome<Self::CommitProof>> {
        Box::pin(async move {
            map_postgres_outcome(
                postgres::PgSettingsConsumerTx::handle(self, message, context, key, lease).await,
            )
        })
    }
}

/// Typed transactional requeue reason.
///
/// Fields are private so adapters must choose an explicit category instead of smuggling storage
/// uncertainty through a free-form retry summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConsumerTxRequeue {
    category: ConsumerTxRequeueCategory,
    summary: &'static str,
}

impl ConsumerTxRequeue {
    #[must_use]
    pub(crate) const fn handler_transient(summary: &'static str) -> Self {
        Self {
            category: ConsumerTxRequeueCategory::HandlerTransient,
            summary,
        }
    }

    #[must_use]
    pub(crate) const fn commit_unknown(summary: &'static str) -> Self {
        Self {
            category: ConsumerTxRequeueCategory::CommitUnknown,
            summary,
        }
    }

    const fn category(self) -> ConsumerTxRequeueCategory {
        self.category
    }

    const fn summary(self) -> &'static str {
        self.summary
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConsumerTxRequeueCategory {
    HandlerTransient,
    CommitUnknown,
}

/// Result of one transactional Fresh handling attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum ConsumerTxOutcome<C> {
    /// The transactional unit has committed; broker may be Acked.
    Committed(C),
    /// No transactional commit is confirmed; this driver may retry locally, then broker-requeues
    /// without app DLX, receipt commit, or Ack.
    Requeue(ConsumerTxRequeue),
    /// The storage transaction observed a lost lease. The current claim is no longer authoritative,
    /// so this driver immediately broker-requeues without app DLX or in-claim retry.
    LeaseLost { summary: &'static str },
    /// Permanent failure; this driver will write consumer DLX and mark the inbox receipt done via
    /// the existing DLX path.
    Reject { summary: &'static str },
}

impl<C> ConsumerTxOutcome<C> {
    #[must_use]
    pub(crate) const fn handler_transient(summary: &'static str) -> Self {
        Self::Requeue(ConsumerTxRequeue::handler_transient(summary))
    }

    #[must_use]
    pub(crate) const fn commit_unknown(summary: &'static str) -> Self {
        Self::Requeue(ConsumerTxRequeue::commit_unknown(summary))
    }
}

/// Ackable durable consumer runner using ConsumerTx for Fresh messages.
pub(crate) async fn run_consumer_ackable_tx<S, P, H>(
    mut stream: diport::DeliveryStream,
    idempotency: Arc<S>,
    dlx: Box<diport::DynDeadLetterStore<'static>>,
    meta: ConsumerMeta,
    handler: H,
    lease_cfg: LeaseConfig,
) where
    S: consistency::InboxStore + Send + Sync + 'static,
    P: policy::Policy,
    H: ConsumerTxHandler<P>,
{
    let handler = Arc::new(handler);
    while let Some(d) = stream.next().await {
        let diport::Delivery { message, acker } = d;
        consume_one_tx(
            &idempotency,
            dlx.as_ref(),
            &meta,
            &handler,
            message,
            Some(acker.as_ref()),
            lease_cfg,
        )
        .await;
    }
}

struct TxPreflight {
    key: IdemKey,
    ctx: InboxReceiptContext,
}

enum TxPreflightError {
    MalformedId,
    InvalidEnvelopeHeader(EnvelopeHeaderError),
    InvalidTenantAuthority(eventexec::TenantAuthorityError),
    InvalidReceiptContext(ReceiptContextBuildError),
}

#[allow(clippy::too_many_arguments)]
async fn consume_one_tx<S, P, H>(
    idempotency: &Arc<S>,
    dlx: &diport::DynDeadLetterStore<'static>,
    meta: &ConsumerMeta,
    handler: &Arc<H>,
    msg: Message,
    acker: Option<&diport::DynAcker<'static>>,
    lease_cfg: LeaseConfig,
) where
    S: consistency::InboxStore + Send + Sync + 'static,
    P: policy::Policy,
    H: ConsumerTxHandler<P>,
{
    let TxPreflight { key, ctx } = match tx_preflight(meta, &msg) {
        Ok(preflight) => preflight,
        Err(error) => {
            reject_tx_preflight(meta, &msg, acker, error).await;
            return;
        }
    };

    let lease = LeaseToken::mint();
    match idempotency.try_claim(&ctx, &key, &lease).await {
        Err(error) => {
            settle_tx_try_claim_error(meta, &msg, acker, &error).await;
        }
        Ok(SeenState::Duplicate) => {
            ack_tx_duplicate(meta, &msg, acker).await;
        }
        Ok(SeenState::Fresh) => {
            handle_fresh_tx(
                idempotency,
                dlx,
                meta,
                handler,
                msg,
                ctx,
                key,
                lease,
                acker,
                lease_cfg,
            )
            .await;
        }
        Ok(_) => {
            requeue_tx_unknown_seen_state(meta, &msg, acker).await;
        }
    }
}

fn tx_preflight(meta: &ConsumerMeta, msg: &Message) -> Result<TxPreflight, TxPreflightError> {
    let key = IdemKey::parse(msg.id.as_str()).map_err(|_| TxPreflightError::MalformedId)?;
    let header = meta
        .verify_envelope_header(msg)
        .map_err(TxPreflightError::InvalidEnvelopeHeader)?;
    let tenant = meta
        .verify_tenant_authority(msg)
        .map_err(TxPreflightError::InvalidTenantAuthority)?;
    let ctx = meta
        .receipt_context(tenant, &header)
        .map_err(TxPreflightError::InvalidReceiptContext)?;
    Ok(TxPreflight { key, ctx })
}

async fn reject_tx_preflight(
    meta: &ConsumerMeta,
    msg: &Message,
    acker: Option<&diport::DynAcker<'static>>,
    error: TxPreflightError,
) {
    match error {
        TxPreflightError::MalformedId => {
            record_dead_letter_skip(meta, "malformed_id");
            log_tx_parse_failed(msg);
        }
        TxPreflightError::InvalidEnvelopeHeader(error) => {
            record_dead_letter_skip(meta, envelope_header_error_reason(&error));
            log_tx_invalid_envelope_header(meta, msg, &error);
        }
        TxPreflightError::InvalidTenantAuthority(error) => {
            record_dead_letter_skip(meta, error.skip_reason());
            log_tx_invalid_tenant_authority(meta, msg, error);
        }
        TxPreflightError::InvalidReceiptContext(error) => {
            let reason = receipt_context_error_reason(error);
            record_dead_letter_skip(meta, reason);
            log_tx_invalid_receipt_context(meta, msg, reason);
        }
    }
    settle(
        acker,
        diport::AckAction::Reject,
        meta.domain(),
        msg.id.as_str(),
    )
    .await;
}

async fn settle_tx_try_claim_error(
    meta: &ConsumerMeta,
    msg: &Message,
    acker: Option<&diport::DynAcker<'static>>,
    error: &consistency::error::EngineError,
) {
    log_tx_try_claim_failed(meta, msg, error);
    settle(
        acker,
        tx_try_claim_error_action(error),
        meta.domain(),
        msg.id.as_str(),
    )
    .await;
}

fn tx_try_claim_error_action(error: &consistency::error::EngineError) -> diport::AckAction {
    if error.is_transient() {
        diport::AckAction::Requeue
    } else {
        diport::AckAction::Reject
    }
}

async fn ack_tx_duplicate(
    meta: &ConsumerMeta,
    msg: &Message,
    acker: Option<&diport::DynAcker<'static>>,
) {
    log_tx_duplicate(msg, meta);
    settle(
        acker,
        diport::AckAction::Ack,
        meta.domain(),
        msg.id.as_str(),
    )
    .await;
}

async fn requeue_tx_unknown_seen_state(
    meta: &ConsumerMeta,
    msg: &Message,
    acker: Option<&diport::DynAcker<'static>>,
) {
    log_tx_unknown_seen_state(msg);
    settle(
        acker,
        diport::AckAction::Requeue,
        meta.domain(),
        msg.id.as_str(),
    )
    .await;
}

fn log_tx_parse_failed(msg: &Message) {
    tracing::warn!(
        message_id = msg.id.as_str(),
        "consumer-tx: IdemKey parse failed, rejected"
    );
}

fn log_tx_invalid_envelope_header(meta: &ConsumerMeta, msg: &Message, error: &EnvelopeHeaderError) {
    tracing::warn!(
        message_id = msg.id.as_str(),
        domain = meta.domain(),
        contract_id = meta.contract_id(),
        topic = meta.topic(),
        error = %error,
        "consumer-tx: standard envelope header invalid, rejected"
    );
}

fn log_tx_invalid_tenant_authority(
    meta: &ConsumerMeta,
    msg: &Message,
    error: eventexec::TenantAuthorityError,
) {
    tracing::warn!(
        message_id = msg.id.as_str(),
        domain = meta.domain(),
        contract_id = meta.contract_id(),
        topic = meta.topic(),
        reason = error.skip_reason(),
        "consumer-tx: tenant authority invalid, rejected"
    );
}

fn log_tx_invalid_receipt_context(meta: &ConsumerMeta, msg: &Message, reason: &'static str) {
    tracing::warn!(
        message_id = msg.id.as_str(),
        domain = meta.domain(),
        contract_id = meta.contract_id(),
        topic = meta.topic(),
        reason,
        "consumer-tx: inbox receipt context invalid, rejected"
    );
}

fn log_tx_try_claim_failed(
    meta: &ConsumerMeta,
    msg: &Message,
    error: &consistency::error::EngineError,
) {
    tracing::warn!(
        message_id = msg.id.as_str(),
        domain = meta.domain(),
        contract_id = meta.contract_id(),
        topic = meta.topic(),
        consumer_group = meta.consumer_group(),
        error = %error,
        "consumer-tx: idempotency try_claim failed"
    );
}

fn log_tx_duplicate(msg: &Message, meta: &ConsumerMeta) {
    tracing::debug!(
        message_id = msg.id.as_str(),
        domain = meta.domain(),
        contract_id = meta.contract_id(),
        topic = meta.topic(),
        "consumer-tx: duplicate message, skipping"
    );
}

fn log_tx_unknown_seen_state(msg: &Message) {
    tracing::warn!(
        message_id = msg.id.as_str(),
        "consumer-tx: unknown SeenState variant, conservatively requeued"
    );
}

#[allow(clippy::too_many_arguments)]
async fn handle_fresh_tx<S, P, H>(
    idempotency: &Arc<S>,
    dlx: &diport::DynDeadLetterStore<'static>,
    meta: &ConsumerMeta,
    handler: &Arc<H>,
    msg: Message,
    ctx: InboxReceiptContext,
    key: IdemKey,
    lease: LeaseToken,
    acker: Option<&diport::DynAcker<'static>>,
    lease_cfg: LeaseConfig,
) where
    S: consistency::InboxStore + Send + Sync + 'static,
    P: policy::Policy,
    H: ConsumerTxHandler<P>,
{
    let message_id = msg.id.as_str().to_owned();
    let consume_span = build_consume_span(meta, &message_id, msg.metadata.get(diport::KEY_TRACE));
    tokio::select! {
        biased;
        () = run_tx_handler_loop(
            idempotency,
            dlx,
            meta,
            handler,
            msg,
            ctx.clone(),
            key.clone(),
            lease.clone(),
            acker,
        )
            .instrument(consume_span) => {}
        () = renewal_loop(idempotency, meta, &ctx, &key, &lease, lease_cfg, &message_id) => {
            log_lease_lost(meta, &message_id);
            emit_lease_lost(meta.domain());
            settle(acker, diport::AckAction::Requeue, meta.domain(), &message_id).await;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_tx_handler_loop<S, P, H>(
    idempotency: &Arc<S>,
    dlx: &diport::DynDeadLetterStore<'static>,
    meta: &ConsumerMeta,
    handler: &Arc<H>,
    msg: Message,
    ctx: InboxReceiptContext,
    key: IdemKey,
    lease: LeaseToken,
    acker: Option<&diport::DynAcker<'static>>,
) where
    S: consistency::InboxStore + Send + Sync + 'static,
    P: policy::Policy,
    H: ConsumerTxHandler<P>,
{
    let mut last_requeue_summary = EngineErrorKind::Transient.message();
    for attempt in 1..=MAX_REDELIVERY {
        match Arc::clone(handler)
            .handle(msg.clone(), ctx.clone(), key.clone(), lease.clone())
            .await
        {
            ConsumerTxOutcome::Committed(_proof) => {
                settle(
                    acker,
                    diport::AckAction::Ack,
                    meta.domain(),
                    msg.id.as_str(),
                )
                .await;
                return;
            }
            ConsumerTxOutcome::Reject { summary } => {
                dead_letter(
                    dlx,
                    idempotency,
                    &ctx,
                    &key,
                    &lease,
                    meta,
                    &msg,
                    attempt,
                    summary,
                    acker,
                )
                .await;
                return;
            }
            ConsumerTxOutcome::Requeue(requeue) => match requeue.category() {
                ConsumerTxRequeueCategory::HandlerTransient => {
                    last_requeue_summary = requeue.summary();
                }
                ConsumerTxRequeueCategory::CommitUnknown => {
                    log_tx_commit_unknown(meta, &msg, requeue.summary());
                    settle(
                        acker,
                        diport::AckAction::Requeue,
                        meta.domain(),
                        msg.id.as_str(),
                    )
                    .await;
                    return;
                }
            },
            ConsumerTxOutcome::LeaseLost { summary } => {
                log_lease_lost(meta, msg.id.as_str());
                emit_lease_lost(meta.domain());
                tracing::warn!(
                    message_id = msg.id.as_str(),
                    summary,
                    "consumer-tx: lease lost in transaction, requeued without app dlx"
                );
                settle(
                    acker,
                    diport::AckAction::Requeue,
                    meta.domain(),
                    msg.id.as_str(),
                )
                .await;
                return;
            }
        }
    }
    log_tx_handler_transient_exhausted(meta, &msg, last_requeue_summary);
    settle(
        acker,
        diport::AckAction::Requeue,
        meta.domain(),
        msg.id.as_str(),
    )
    .await;
}

fn log_tx_commit_unknown(meta: &ConsumerMeta, msg: &Message, summary: &'static str) {
    tracing::warn!(
        message_id = msg.id.as_str(),
        domain = meta.domain(),
        contract_id = meta.contract_id(),
        topic = meta.topic(),
        consumer_group = meta.consumer_group(),
        summary,
        "consumer-tx: transaction commit status unknown, requeued without app dlx"
    );
}

fn log_tx_handler_transient_exhausted(meta: &ConsumerMeta, msg: &Message, summary: &'static str) {
    tracing::warn!(
        message_id = msg.id.as_str(),
        domain = meta.domain(),
        contract_id = meta.contract_id(),
        topic = meta.topic(),
        consumer_group = meta.consumer_group(),
        attempts = MAX_REDELIVERY,
        summary,
        "consumer-tx: handler transient budget exhausted, requeued without app dlx"
    );
}

const CONSUMER_TX_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);

pub(crate) struct ConsumerTxWorker {
    name: String,
    inner: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
    token: tokio_util::sync::CancellationToken,
}

impl ConsumerTxWorker {
    fn adopt(
        name: String,
        handle: std::thread::JoinHandle<()>,
        token: tokio_util::sync::CancellationToken,
    ) -> Self {
        Self {
            name,
            inner: std::sync::Mutex::new(Some(handle)),
            token,
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("consumer tx worker thread panicked")]
struct ConsumerTxThreadPanicked;

#[allow(unknown_lints, rss_diport_impl_allowlist)]
// reason(rss_diport_impl_allowlist): assembly-private ConsumerTx driver owns its supervised worker;
// this is a lifecycle implementation, not an adapter provider.
impl diport::ManagedResource for ConsumerTxWorker {
    fn name(&self) -> &str {
        &self.name
    }

    fn shutdown_timeout(&self) -> std::time::Duration {
        CONSUMER_TX_SHUTDOWN_TIMEOUT
    }

    async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
        self.token.cancel();
        let handle = self
            .inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        let Some(handle) = handle else {
            return Ok(());
        };
        match tokio::task::spawn_blocking(move || handle.join()).await {
            Err(error) => Err(diport::ShutdownError::new(error)),
            Ok(Err(_)) => Err(diport::ShutdownError::new(ConsumerTxThreadPanicked)),
            Ok(Ok(())) => Ok(()),
        }
    }
}

struct HealthReportingDlx {
    inner: tokio::sync::Mutex<Box<diport::DynDeadLetterStore<'static>>>,
    health: Arc<eventexec::WorkerHealth>,
    domain: String,
}

#[allow(unknown_lints, rss_diport_impl_allowlist)]
// reason(rss_diport_impl_allowlist): assembly-private health wrapper around the injected DLX port;
// it does not construct or replace a provider.
impl diport::DeadLetterStore for HealthReportingDlx {
    async fn write_dead_letter(
        &self,
        record: diport::DeadLetterRecord,
    ) -> Result<(), diport::DeadLetterStoreError> {
        let inner = self.inner.lock().await;
        let result = inner.write_dead_letter(record).await;
        let outcome = if result.is_ok() {
            "ok"
        } else {
            self.health.mark_dlx_write_error();
            "error"
        };
        metrics::counter!(
            "consumer_dlx_write_total",
            "domain" => self.domain.clone(),
            "outcome" => outcome,
        )
        .increment(1);
        result
    }

    async fn shutdown(&self) -> Result<(), diport::DeadLetterStoreError> {
        let inner = self.inner.lock().await;
        inner.shutdown().await
    }
}

fn health_reporting_dlx(
    dlx: Box<diport::DynDeadLetterStore<'static>>,
    health: Arc<eventexec::WorkerHealth>,
    meta: &ConsumerMeta,
) -> Box<diport::DynDeadLetterStore<'static>> {
    diport::DynDeadLetterStore::new_box(HealthReportingDlx {
        inner: tokio::sync::Mutex::new(dlx),
        health,
        domain: meta.domain().to_owned(),
    })
}

fn spawn_consumer_tx_thread<Fut, M>(
    worker_name: &str,
    health: Arc<eventexec::WorkerHealth>,
    make_body: M,
) -> std::thread::JoinHandle<()>
where
    M: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()>,
{
    let worker_name = worker_name.to_owned();
    std::thread::spawn(move || {
        let _stopped = health.stopped_on_exit();
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                tracing::error!(
                    worker = worker_name,
                    error = %error,
                    "consumer-tx: worker runtime build failed"
                );
                return;
            }
        };
        runtime.block_on(make_body());
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_consumer_ackable_tx_subscriber<S, P, H>(
    name: String,
    subscriber: Box<diport::DynAckableSubscriber<'static>>,
    topic: diport::Topic,
    idempotency: Arc<S>,
    dlx: Box<diport::DynDeadLetterStore<'static>>,
    meta: ConsumerMeta,
    handler: H,
    lease_cfg: LeaseConfig,
    token: tokio_util::sync::CancellationToken,
    health: Arc<eventexec::WorkerHealth>,
) -> ConsumerTxWorker
where
    S: consistency::InboxStore + Send + Sync + 'static,
    P: policy::Policy,
    H: ConsumerTxHandler<P>,
{
    use diport::AckableSubscriber as _;

    let token_run = token.clone();
    let health_run = Arc::clone(&health);
    let dlx = health_reporting_dlx(dlx, Arc::clone(&health), &meta);
    let handle = spawn_consumer_tx_thread(&name, Arc::clone(&health), move || async move {
        match subscriber.subscribe_ackable(topic, token_run.clone()).await {
            Ok(stream) => {
                health_run.mark_healthy();
                run_consumer_ackable_tx(stream, idempotency, dlx, meta, handler, lease_cfg).await;
            }
            Err(error) => {
                health_run.mark_subscriber_unavailable();
                tracing::error!(
                    error = %error,
                    "consumer-tx: subscribe_ackable failed; worker exiting"
                );
            }
        }
    });
    ConsumerTxWorker::adopt(name, handle, token)
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::marker::PhantomData;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use consistency::error::{EngineError, EngineErrorKind};
    use consistency::idempotency::{IdemKey, LeaseOutcome, LeaseToken, SeenState};
    use consistency::{ConsumerGroup, InboxReceiptContext, InboxStore};
    use diport::dead_letter_store::{
        DeadLetterRecord, DeadLetterStore, DeadLetterStoreError, DynDeadLetterStore,
    };
    use diport::{
        AckAction, Acker, Delivery, DynAcker, EnvelopeMetadata, KEY_SCHEMA_HASH,
        KEY_SCHEMA_VERSION, KEY_TENANT_AUTHORITY, KEY_TENANT_ID, Message,
    };
    use primitives::{Mac, MacAlgorithm, MacKey, MacVerifier};

    use super::*;
    use eventexec::{TenantAuthority, TenantAuthorityBinding};

    const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const SCHEMA_HASH: &str =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

    struct TestCommitProof;

    struct TestHandler<P, F> {
        inner: F,
        policy: PhantomData<fn() -> P>,
    }

    impl<P, F> ConsumerTxHandler<P> for TestHandler<P, F>
    where
        P: policy::Policy,
        F: Fn(
                Message,
                InboxReceiptContext,
                IdemKey,
                LeaseToken,
            ) -> BoxFuture<'static, ConsumerTxOutcome<TestCommitProof>>
            + Send
            + Sync
            + 'static,
    {
        type CommitProof = TestCommitProof;

        fn handle(
            self: Arc<Self>,
            message: Message,
            context: InboxReceiptContext,
            key: IdemKey,
            lease: LeaseToken,
        ) -> BoxFuture<'static, ConsumerTxOutcome<Self::CommitProof>> {
            (self.inner)(message, context, key, lease)
        }
    }

    fn transactional_handler<F>(inner: F) -> TestHandler<policy::TransactionalOnly, F>
    where
        F: Fn(
                Message,
                InboxReceiptContext,
                IdemKey,
                LeaseToken,
            ) -> BoxFuture<'static, ConsumerTxOutcome<TestCommitProof>>
            + Send
            + Sync
            + 'static,
    {
        TestHandler {
            inner,
            policy: PhantomData,
        }
    }

    struct RecordingAcker(Arc<Mutex<Vec<AckAction>>>);

    impl Acker for RecordingAcker {
        async fn settle(&self, action: AckAction) -> Result<(), diport::AckError> {
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(action);
            Ok(())
        }
    }

    struct NoopDlx;

    impl DeadLetterStore for NoopDlx {
        async fn write_dead_letter(
            &self,
            _record: DeadLetterRecord,
        ) -> Result<(), DeadLetterStoreError> {
            Ok(())
        }

        async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
            Ok(())
        }
    }

    struct RecordingDlx(Arc<AtomicU32>);

    impl DeadLetterStore for RecordingDlx {
        async fn write_dead_letter(
            &self,
            _record: DeadLetterRecord,
        ) -> Result<(), DeadLetterStoreError> {
            self.0.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
            Ok(())
        }
    }

    struct TestMac;

    impl MacVerifier for TestMac {
        fn sign(&self, key: &MacKey, _algorithm: MacAlgorithm, message: &[u8]) -> Mac {
            let mut out = [0u8; 32];
            for (idx, byte) in key.as_bytes().iter().chain(message.iter()).enumerate() {
                out[idx % 32] ^= *byte;
            }
            Mac::from_bytes(out.to_vec())
        }

        fn verify(&self, key: &MacKey, algorithm: MacAlgorithm, message: &[u8], tag: &Mac) -> bool {
            self.sign(key, algorithm, message).as_bytes() == tag.as_bytes()
        }
    }

    fn tenant() -> TestResult<vocab::TenantId> {
        Ok(vocab::TenantId::parse(TENANT)?)
    }

    fn authority() -> TestResult<Arc<TenantAuthority>> {
        Ok(Arc::new(TenantAuthority::new(
            Arc::new(TestMac),
            MacKey::from_bytes(vec![7; 32]),
            3600,
            60,
            Arc::new(|| 42),
        )?))
    }

    fn meta() -> TestResult<ConsumerMeta> {
        Ok(ConsumerMeta::new(
            "audit",
            "identity",
            "identity.session-created",
            "identity.session-created",
            "audit.session-created",
            authority()?,
        )
        .with_expected_schema("v1", SCHEMA_HASH))
    }

    fn message(id: &str) -> TestResult<Message> {
        let authority = authority()?;
        let token = authority.sign(TenantAuthorityBinding::new(
            tenant()?,
            "identity",
            "identity.session-created",
            "identity.session-created",
            id,
        ))?;
        let mut md = EnvelopeMetadata::empty();
        md.insert_wire_pair(KEY_TENANT_ID, TENANT);
        md.insert_wire_pair(KEY_SCHEMA_VERSION, "v1");
        md.insert_wire_pair(KEY_SCHEMA_HASH, SCHEMA_HASH);
        md.insert_wire_pair(KEY_TENANT_AUTHORITY, &token);
        Ok(Message::new_with_metadata(id, b"{}".to_vec(), md))
    }

    fn delivery_stream(
        id: &str,
        actions: Arc<Mutex<Vec<AckAction>>>,
    ) -> TestResult<diport::DeliveryStream> {
        Ok(Box::pin(futures::stream::iter([Delivery::new(
            message(id)?,
            DynAcker::new_box(RecordingAcker(actions)),
        )])))
    }

    struct TxStore {
        state: SeenState,
        claim_error: Option<EngineErrorKind>,
        commits: AtomicU32,
        extends: AtomicU32,
    }

    impl TxStore {
        fn fresh() -> Arc<Self> {
            Arc::new(Self {
                state: SeenState::Fresh,
                claim_error: None,
                commits: AtomicU32::new(0),
                extends: AtomicU32::new(0),
            })
        }

        fn duplicate() -> Arc<Self> {
            Arc::new(Self {
                state: SeenState::Duplicate,
                claim_error: None,
                commits: AtomicU32::new(0),
                extends: AtomicU32::new(0),
            })
        }

        fn claim_error(kind: EngineErrorKind) -> Arc<Self> {
            Arc::new(Self {
                state: SeenState::Fresh,
                claim_error: Some(kind),
                commits: AtomicU32::new(0),
                extends: AtomicU32::new(0),
            })
        }
    }

    impl InboxStore for TxStore {
        async fn try_claim(
            &self,
            _ctx: &InboxReceiptContext,
            _key: &IdemKey,
            _lease: &LeaseToken,
        ) -> Result<SeenState, EngineError> {
            if let Some(kind) = self.claim_error {
                return Err(EngineError::new(kind));
            }
            Ok(self.state)
        }

        async fn extend(
            &self,
            _ctx: &InboxReceiptContext,
            _key: &IdemKey,
            _lease: &LeaseToken,
        ) -> Result<LeaseOutcome, EngineError> {
            self.extends.fetch_add(1, Ordering::AcqRel);
            Ok(LeaseOutcome::Held)
        }

        async fn commit(
            &self,
            _ctx: &InboxReceiptContext,
            _key: &IdemKey,
            _lease: &LeaseToken,
        ) -> Result<LeaseOutcome, EngineError> {
            self.commits.fetch_add(1, Ordering::AcqRel);
            Ok(LeaseOutcome::Held)
        }

        async fn release(
            &self,
            _ctx: &InboxReceiptContext,
            _key: &IdemKey,
            _lease: &LeaseToken,
        ) -> Result<(), EngineError> {
            Ok(())
        }
    }

    fn noop_dlx() -> Box<DynDeadLetterStore<'static>> {
        DynDeadLetterStore::new_box(NoopDlx)
    }

    fn recording_dlx(writes: Arc<AtomicU32>) -> Box<DynDeadLetterStore<'static>> {
        DynDeadLetterStore::new_box(RecordingDlx(writes))
    }

    fn lease_cfg() -> LeaseConfig {
        LeaseConfig::from_ttl(Duration::from_secs(60))
    }

    #[tokio::test]
    async fn tx_committed_acks_without_calling_inbox_commit() -> TestResult {
        let actions = Arc::new(Mutex::new(Vec::new()));
        let store = TxStore::fresh();
        let calls = Arc::new(AtomicU32::new(0));
        let handler_calls = Arc::clone(&calls);
        let handler = transactional_handler(move |_msg, _ctx, _key, _lease| {
            let handler_calls = Arc::clone(&handler_calls);
            Box::pin(async move {
                handler_calls.fetch_add(1, Ordering::AcqRel);
                ConsumerTxOutcome::Committed(TestCommitProof)
            })
        });

        run_consumer_ackable_tx(
            delivery_stream("evt-tx-ack", Arc::clone(&actions))?,
            Arc::clone(&store),
            noop_dlx(),
            meta()?,
            handler,
            lease_cfg(),
        )
        .await;

        assert_eq!(
            *actions.lock().unwrap_or_else(|e| e.into_inner()),
            vec![AckAction::Ack]
        );
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(
            store.commits.load(Ordering::Acquire),
            0,
            "ConsumerTx handler owns inbox done inside its transaction"
        );
        Ok(())
    }

    #[tokio::test]
    async fn tx_duplicate_acks_without_calling_handler() -> TestResult {
        let actions = Arc::new(Mutex::new(Vec::new()));
        let store = TxStore::duplicate();
        let calls = Arc::new(AtomicU32::new(0));
        let handler_calls = Arc::clone(&calls);
        let handler = transactional_handler(move |_msg, _ctx, _key, _lease| {
            let handler_calls = Arc::clone(&handler_calls);
            Box::pin(async move {
                handler_calls.fetch_add(1, Ordering::AcqRel);
                ConsumerTxOutcome::Committed(TestCommitProof)
            })
        });

        run_consumer_ackable_tx(
            delivery_stream("evt-tx-duplicate", Arc::clone(&actions))?,
            store,
            noop_dlx(),
            meta()?,
            handler,
            lease_cfg(),
        )
        .await;

        assert_eq!(
            *actions.lock().unwrap_or_else(|e| e.into_inner()),
            vec![AckAction::Ack]
        );
        assert_eq!(calls.load(Ordering::Acquire), 0);
        Ok(())
    }

    #[tokio::test]
    async fn tx_handler_transient_exhaustion_requeues_without_dead_letter_or_commit() -> TestResult
    {
        let actions = Arc::new(Mutex::new(Vec::new()));
        let store = TxStore::fresh();
        let dlx_writes = Arc::new(AtomicU32::new(0));
        let calls = Arc::new(AtomicU32::new(0));
        let handler_calls = Arc::clone(&calls);
        let handler = transactional_handler(move |_msg, _ctx, _key, _lease| {
            let handler_calls = Arc::clone(&handler_calls);
            Box::pin(async move {
                handler_calls.fetch_add(1, Ordering::AcqRel);
                ConsumerTxOutcome::handler_transient(EngineErrorKind::Transient.message())
            })
        });

        run_consumer_ackable_tx(
            delivery_stream("evt-tx-requeue", Arc::clone(&actions))?,
            Arc::clone(&store),
            recording_dlx(Arc::clone(&dlx_writes)),
            meta()?,
            handler,
            lease_cfg(),
        )
        .await;

        assert_eq!(calls.load(Ordering::Acquire), MAX_REDELIVERY);
        assert_eq!(dlx_writes.load(Ordering::Acquire), 0);
        assert_eq!(store.commits.load(Ordering::Acquire), 0);
        assert_eq!(
            *actions.lock().unwrap_or_else(|e| e.into_inner()),
            vec![AckAction::Requeue]
        );
        Ok(())
    }

    #[tokio::test]
    async fn tx_commit_unknown_requeues_without_retry_dead_letter_or_commit() -> TestResult {
        let actions = Arc::new(Mutex::new(Vec::new()));
        let store = TxStore::fresh();
        let dlx_writes = Arc::new(AtomicU32::new(0));
        let calls = Arc::new(AtomicU32::new(0));
        let handler_calls = Arc::clone(&calls);
        let handler = transactional_handler(move |_msg, _ctx, _key, _lease| {
            let handler_calls = Arc::clone(&handler_calls);
            Box::pin(async move {
                handler_calls.fetch_add(1, Ordering::AcqRel);
                ConsumerTxOutcome::commit_unknown(EngineErrorKind::Transient.message())
            })
        });

        run_consumer_ackable_tx(
            delivery_stream("evt-tx-commit-unknown", Arc::clone(&actions))?,
            Arc::clone(&store),
            recording_dlx(Arc::clone(&dlx_writes)),
            meta()?,
            handler,
            lease_cfg(),
        )
        .await;

        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(dlx_writes.load(Ordering::Acquire), 0);
        assert_eq!(store.commits.load(Ordering::Acquire), 0);
        assert_eq!(
            *actions.lock().unwrap_or_else(|e| e.into_inner()),
            vec![AckAction::Requeue]
        );
        Ok(())
    }

    #[tokio::test]
    async fn tx_reject_dead_letters_once_and_commits_receipt() -> TestResult {
        let actions = Arc::new(Mutex::new(Vec::new()));
        let store = TxStore::fresh();
        let dlx_writes = Arc::new(AtomicU32::new(0));
        let calls = Arc::new(AtomicU32::new(0));
        let handler_calls = Arc::clone(&calls);
        let handler = transactional_handler(move |_msg, _ctx, _key, _lease| {
            let handler_calls = Arc::clone(&handler_calls);
            Box::pin(async move {
                handler_calls.fetch_add(1, Ordering::AcqRel);
                ConsumerTxOutcome::Reject {
                    summary: consistency::PermanentErrorKind::Permanent.message(),
                }
            })
        });

        run_consumer_ackable_tx(
            delivery_stream("evt-tx-reject", Arc::clone(&actions))?,
            Arc::clone(&store),
            recording_dlx(Arc::clone(&dlx_writes)),
            meta()?,
            handler,
            lease_cfg(),
        )
        .await;

        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(dlx_writes.load(Ordering::Acquire), 1);
        assert_eq!(store.commits.load(Ordering::Acquire), 1);
        assert_eq!(
            *actions.lock().unwrap_or_else(|e| e.into_inner()),
            vec![AckAction::Ack]
        );
        Ok(())
    }

    #[tokio::test]
    async fn tx_lease_lost_requeues_without_retry_dead_letter_or_commit() -> TestResult {
        let actions = Arc::new(Mutex::new(Vec::new()));
        let store = TxStore::fresh();
        let dlx_writes = Arc::new(AtomicU32::new(0));
        let calls = Arc::new(AtomicU32::new(0));
        let handler_calls = Arc::clone(&calls);
        let handler = transactional_handler(move |_msg, _ctx, _key, _lease| {
            let handler_calls = Arc::clone(&handler_calls);
            Box::pin(async move {
                handler_calls.fetch_add(1, Ordering::AcqRel);
                ConsumerTxOutcome::LeaseLost {
                    summary: EngineErrorKind::Transient.message(),
                }
            })
        });

        run_consumer_ackable_tx(
            delivery_stream("evt-tx-lease-lost", Arc::clone(&actions))?,
            Arc::clone(&store),
            recording_dlx(Arc::clone(&dlx_writes)),
            meta()?,
            handler,
            lease_cfg(),
        )
        .await;

        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(dlx_writes.load(Ordering::Acquire), 0);
        assert_eq!(store.commits.load(Ordering::Acquire), 0);
        assert_eq!(
            *actions.lock().unwrap_or_else(|e| e.into_inner()),
            vec![AckAction::Requeue]
        );
        Ok(())
    }

    #[tokio::test]
    async fn tx_malformed_id_rejects_without_calling_handler() -> TestResult {
        let actions = Arc::new(Mutex::new(Vec::new()));
        let store = TxStore::fresh();
        let calls = Arc::new(AtomicU32::new(0));
        let handler_calls = Arc::clone(&calls);
        let handler = transactional_handler(move |_msg, _ctx, _key, _lease| {
            let handler_calls = Arc::clone(&handler_calls);
            Box::pin(async move {
                handler_calls.fetch_add(1, Ordering::AcqRel);
                ConsumerTxOutcome::Committed(TestCommitProof)
            })
        });

        run_consumer_ackable_tx(
            delivery_stream("", Arc::clone(&actions))?,
            store,
            noop_dlx(),
            meta()?,
            handler,
            lease_cfg(),
        )
        .await;

        assert_eq!(calls.load(Ordering::Acquire), 0);
        assert_eq!(
            *actions.lock().unwrap_or_else(|e| e.into_inner()),
            vec![AckAction::Reject]
        );
        Ok(())
    }

    #[tokio::test]
    async fn tx_try_claim_error_settles_by_error_kind_without_handler() -> TestResult {
        let cases = [
            (EngineErrorKind::Transient, AckAction::Requeue),
            (EngineErrorKind::Permanent, AckAction::Reject),
            (EngineErrorKind::Invariant, AckAction::Reject),
        ];
        for (kind, expected_action) in cases {
            let actions = Arc::new(Mutex::new(Vec::new()));
            let calls = Arc::new(AtomicU32::new(0));
            let handler_calls = Arc::clone(&calls);
            let handler = transactional_handler(move |_msg, _ctx, _key, _lease| {
                let handler_calls = Arc::clone(&handler_calls);
                Box::pin(async move {
                    handler_calls.fetch_add(1, Ordering::AcqRel);
                    ConsumerTxOutcome::Committed(TestCommitProof)
                })
            });

            run_consumer_ackable_tx(
                delivery_stream("evt-tx-claim-error", Arc::clone(&actions))?,
                TxStore::claim_error(kind),
                noop_dlx(),
                meta()?,
                handler,
                lease_cfg(),
            )
            .await;

            assert_eq!(calls.load(Ordering::Acquire), 0, "kind={kind:?}");
            assert_eq!(
                *actions.lock().unwrap_or_else(|e| e.into_inner()),
                vec![expected_action],
                "kind={kind:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn tx_try_claim_failed_log_includes_route_context() -> TestResult {
        use std::collections::HashMap;

        use tracing::field::{Field, Visit};
        use tracing::{Event, Subscriber};
        use tracing_subscriber::layer::{Context, Layer};
        use tracing_subscriber::prelude::*;

        struct CaptureLayer {
            events: Arc<Mutex<Vec<HashMap<String, String>>>>,
        }

        struct FieldVisitor {
            fields: HashMap<String, String>,
        }

        impl Visit for FieldVisitor {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                self.fields
                    .insert(field.name().to_string(), format!("{value:?}"));
            }

            fn record_str(&mut self, field: &Field, value: &str) {
                self.fields
                    .insert(field.name().to_string(), value.to_string());
            }

            fn record_u64(&mut self, field: &Field, value: u64) {
                self.fields
                    .insert(field.name().to_string(), value.to_string());
            }

            fn record_i64(&mut self, field: &Field, value: i64) {
                self.fields
                    .insert(field.name().to_string(), value.to_string());
            }
        }

        impl<S> Layer<S> for CaptureLayer
        where
            S: Subscriber,
        {
            fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
                if *event.metadata().level() != tracing::Level::WARN {
                    return;
                }
                let mut visitor = FieldVisitor {
                    fields: HashMap::new(),
                };
                event.record(&mut visitor);
                self.events
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(visitor.fields);
            }
        }

        let events = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(CaptureLayer {
            events: Arc::clone(&events),
        });
        let meta = meta()?;
        let msg = message("evt-tx-claim-log")?;
        let error = EngineError::new(EngineErrorKind::Transient);
        tracing::subscriber::with_default(subscriber, || {
            log_tx_try_claim_failed(&meta, &msg, &error);
        });

        let events = events.lock().unwrap_or_else(|e| e.into_inner());
        let event = events
            .iter()
            .find(|fields| {
                fields
                    .get("message_id")
                    .is_some_and(|value| value == "evt-tx-claim-log")
            })
            .ok_or_else(|| std::io::Error::other("try_claim log event not captured"))?;
        assert_eq!(event.get("domain").map(String::as_str), Some("audit"));
        assert_eq!(
            event.get("contract_id").map(String::as_str),
            Some("identity.session-created")
        );
        assert_eq!(
            event.get("topic").map(String::as_str),
            Some("identity.session-created")
        );
        assert_eq!(
            event.get("consumer_group").map(String::as_str),
            Some("audit.session-created")
        );
        Ok(())
    }

    #[test]
    fn receipt_context_clone_is_available_for_tx_handler_budget() -> TestResult {
        let ctx = InboxReceiptContext::new(
            tenant()?,
            ConsumerGroup::parse("audit.session-created")?,
            "audit",
            "identity.session-created",
            "identity.session-created",
            "v1",
            SCHEMA_HASH,
            None,
            None,
        )?;
        let cloned = ctx.clone();
        assert_eq!(ctx, cloned);
        Ok(())
    }
}
