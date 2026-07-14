//! Private settlement funnel.
//!
//! INVARIANT: PG-OUTBOX-SETTLEMENT-CAPABILITY-01 { level = "Hard", exec = "native-compile", source = "code", native = "private module plus sealed outcome proof types and exhaustive caller matches" }
//!
//! The private capability boundary owns lease-deadline selection, typed outcome decoding and
//! failure labels; callers cannot forge those values. Workspace-wide raw SQL execution uniqueness
//! is the separately rated Medium `PG-OUTBOX-SETTLEMENT-FUNNEL-01` guard.

use consistency::{EngineError, EngineErrorKind, OutboxMetricSubject};
use eventexec::RelayBudget;

use crate::dead_letter_payload::ProtectedDlxCapsule;

use super::{
    DLX_REPLAY_CAPSULE_ENCODING, DeadLetterSource, DlxPayloadContext, DlxPayloadProtector,
    PgClaimedOutboxEntry, PgTenantPool, RelayPublishFailure, SameIdDeliveryPhase,
    infra_tenant_scope, metadata_json_with_relay_failure, parse_tenant_id,
};

#[derive(Debug)]
pub(super) enum Settlement<T> {
    Settled(T, SettledSeal),
    Expired(ExpiredSeal),
    LostLease(LostLeaseSeal),
}

/// Each outcome carries a distinct unmintable proof. The parent can exhaustively match variants,
/// so adding a variant breaks every production consumer, but it cannot construct or swap outcomes.
#[derive(Debug)]
pub(super) struct SettledSeal(());
#[derive(Debug)]
pub(super) struct ExpiredSeal(());
#[derive(Debug)]
pub(super) struct LostLeaseSeal(());

impl<T> Settlement<T> {
    fn settled(value: T) -> Self {
        Self::Settled(value, SettledSeal(()))
    }

    fn expired() -> Self {
        Self::Expired(ExpiredSeal(()))
    }

    fn lost_lease() -> Self {
        Self::LostLease(LostLeaseSeal(()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SettlementDeadlineExpired;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SettlementOperation {
    Published,
    Retry,
    Dlx,
    SameIdExpiryDlx,
}

impl SettlementOperation {
    const fn as_label(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Retry => "retry",
            Self::Dlx => "dlx",
            Self::SameIdExpiryDlx => "same_id_expiry_dlx",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SettlementFailureReason {
    Timeout,
    Expired,
    LostLease,
    Storage,
    PayloadProtection,
    Invariant,
}

impl SettlementFailureReason {
    const fn as_label(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Expired => "expired",
            Self::LostLease => "lost_lease",
            Self::Storage => "storage",
            Self::PayloadProtection => "payload_protection",
            Self::Invariant => "invariant",
        }
    }
}

#[derive(Clone)]
struct MetricScope {
    domain: String,
    subject: OutboxMetricSubject,
}

impl MetricScope {
    fn from_claim(claimed: &PgClaimedOutboxEntry) -> Self {
        Self {
            domain: claimed.domain().as_str().to_owned(),
            subject: claimed.subject().clone(),
        }
    }

    fn record(&self, operation: SettlementOperation, reason: SettlementFailureReason) {
        metrics::counter!(
            "outbox_relay_settlement_failure_total",
            "domain" => self.domain.clone(),
            "contract_id" => self.subject.contract_id().as_str().to_owned(),
            "tenant_id" => self.subject.tenant_id().to_string(),
            "operation" => operation.as_label(),
            "reason" => reason.as_label(),
        )
        .increment(1);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SettlementAttemptError {
    Timeout,
    Storage,
    PayloadProtection,
    Invariant,
}

impl SettlementAttemptError {
    const fn reason(self) -> SettlementFailureReason {
        match self {
            Self::Timeout => SettlementFailureReason::Timeout,
            Self::Storage => SettlementFailureReason::Storage,
            Self::PayloadProtection => SettlementFailureReason::PayloadProtection,
            Self::Invariant => SettlementFailureReason::Invariant,
        }
    }

    const fn engine_kind(self) -> EngineErrorKind {
        match self {
            Self::Timeout | Self::Storage | Self::PayloadProtection => EngineErrorKind::Transient,
            Self::Invariant => EngineErrorKind::Invariant,
        }
    }
}

/// Every raw settlement executor returns this private attempt capability. The only conversion into
/// the public adapter result is [`SettlementAttempt::finalize`], which records exactly one sample
/// for every non-success outcome before recovering the existing `EngineError` surface.
struct SettlementAttempt<T>(Result<Settlement<T>, SettlementAttemptError>);

impl<T> SettlementAttempt<T> {
    fn outcome(outcome: Settlement<T>) -> Self {
        Self(Ok(outcome))
    }

    #[cfg(test)]
    fn failure(error: SettlementAttemptError) -> Self {
        Self(Err(error))
    }

    fn from_result(result: Result<Settlement<T>, SettlementAttemptError>) -> Self {
        Self(result)
    }

    fn finalize(
        self,
        scope: MetricScope,
        operation: SettlementOperation,
    ) -> Result<Settlement<T>, EngineError> {
        match self.0 {
            Ok(Settlement::Settled(value, seal)) => Ok(Settlement::Settled(value, seal)),
            Ok(Settlement::Expired(seal)) => {
                scope.record(operation, SettlementFailureReason::Expired);
                Ok(Settlement::Expired(seal))
            }
            Ok(Settlement::LostLease(seal)) => {
                scope.record(operation, SettlementFailureReason::LostLease);
                Ok(Settlement::LostLease(seal))
            }
            Err(error) => {
                scope.record(operation, error.reason());
                Err(EngineError::new(error.engine_kind()))
            }
        }
    }
}

fn parse_outcome(raw: &str) -> Result<Settlement<()>, SettlementAttemptError> {
    match raw {
        "settled" => Ok(Settlement::settled(())),
        "expired" => Ok(Settlement::expired()),
        "lost_lease" => Ok(Settlement::lost_lease()),
        _ => {
            tracing::error!(
                target: "postgres",
                outcome = raw,
                "outbox: unknown settlement outcome"
            );
            Err(SettlementAttemptError::Invariant)
        }
    }
}

fn is_timeout(error: &sqlx::Error) -> bool {
    match error {
        sqlx::Error::PoolTimedOut => true,
        sqlx::Error::Database(database) => {
            matches!(database.code().as_deref(), Some("57014" | "55P03"))
        }
        _ => false,
    }
}

fn map_storage_error(error: sqlx::Error, phase: &'static str) -> SettlementAttemptError {
    let reason = if is_timeout(&error) {
        SettlementAttemptError::Timeout
    } else {
        SettlementAttemptError::Storage
    };
    tracing::warn!(
        target: "postgres",
        phase,
        error = %secure::redact_error(&error),
        "outbox settlement storage error"
    );
    reason
}

fn settlement_timeout_error(phase: &'static str, settle_timeout_ms: i64) -> EngineError {
    tracing::warn!(
        target: "postgres",
        phase,
        settle_timeout_ms,
        delivery_outcome = "unknown",
        broker_may_have_received = true,
        "outbox settlement timed out"
    );
    EngineError::new(EngineErrorKind::Transient)
}

fn map_outer_timeout(phase: &'static str, relay_budget: RelayBudget) -> SettlementAttemptError {
    let _ = settlement_timeout_error(phase, relay_budget.settle_timeout_millis());
    SettlementAttemptError::Timeout
}

fn deadline_or_expired(
    claimed: &PgClaimedOutboxEntry,
    relay_budget: RelayBudget,
) -> Option<tokio::time::Instant> {
    select_deadline(claimed.lease.monotonic_deadline, relay_budget).ok()
}

fn select_deadline(
    monotonic_deadline: tokio::time::Instant,
    relay_budget: RelayBudget,
) -> Result<tokio::time::Instant, SettlementDeadlineExpired> {
    let now = crate::cotx::io_deadline_after(std::time::Duration::ZERO);
    if now >= monotonic_deadline {
        return Err(SettlementDeadlineExpired);
    }
    let timeout_deadline = crate::cotx::io_deadline_after(relay_budget.settle_timeout());
    Ok(monotonic_deadline.min(timeout_deadline))
}

pub(super) async fn published(
    tenant_pool: &PgTenantPool,
    claimed: &PgClaimedOutboxEntry,
    relay_budget: RelayBudget,
) -> Result<Settlement<()>, EngineError> {
    let operation = SettlementOperation::Published;
    let scope = MetricScope::from_claim(claimed);
    let deadline = match deadline_or_expired(claimed, relay_budget) {
        Some(deadline) => deadline,
        None => {
            return SettlementAttempt::outcome(Settlement::expired()).finalize(scope, operation);
        }
    };
    execute_scalar(
        tenant_pool,
        claimed,
        relay_budget,
        deadline,
        "settle_published",
        "SELECT rss_outbox_settle_published($1, $2::uuid, $3)::text",
    )
    .await
    .finalize(scope, operation)
}

pub(super) async fn retry(
    tenant_pool: &PgTenantPool,
    claimed: &PgClaimedOutboxEntry,
    relay_budget: RelayBudget,
) -> Result<Settlement<()>, EngineError> {
    let operation = SettlementOperation::Retry;
    let scope = MetricScope::from_claim(claimed);
    let deadline = match deadline_or_expired(claimed, relay_budget) {
        Some(deadline) => deadline,
        None => {
            return SettlementAttempt::outcome(Settlement::expired()).finalize(scope, operation);
        }
    };
    execute_scalar(
        tenant_pool,
        claimed,
        relay_budget,
        deadline,
        "settle_retry",
        "SELECT rss_outbox_settle_retry($1, $2::uuid, $3)::text",
    )
    .await
    .finalize(scope, operation)
}

async fn execute_scalar(
    tenant_pool: &PgTenantPool,
    claimed: &PgClaimedOutboxEntry,
    relay_budget: RelayBudget,
    deadline: tokio::time::Instant,
    phase: &'static str,
    sql: &'static str,
) -> SettlementAttempt<()> {
    let event_id = claimed.idem_key().as_str().to_owned();
    let tenant = claimed.subject().tenant_id();
    let lease_token = claimed.lease_token().to_owned();
    let lease_deadline_epoch_micros = claimed.lease_deadline_epoch_micros();
    SettlementAttempt::from_result(
        tenant_pool
            .deadline_write(
                infra_tenant_scope(tenant),
                deadline,
                move |connection| {
                    Box::pin(async move {
                        let raw: String = sqlx::query_scalar(sql)
                            .bind(event_id)
                            .bind(lease_token)
                            .bind(lease_deadline_epoch_micros)
                            .fetch_one(connection)
                            .await
                            .map_err(|error| map_storage_error(error, phase))?;
                        parse_outcome(&raw)
                    })
                },
                move |error| map_storage_error(error, phase),
                move || map_outer_timeout(phase, relay_budget),
            )
            .await,
    )
}

pub(super) async fn ordinary_dlx(
    tenant_pool: &PgTenantPool,
    payload_protector: &DlxPayloadProtector,
    tenant: vocab::TenantId,
    claimed: &PgClaimedOutboxEntry,
    failure: &RelayPublishFailure,
    relay_budget: RelayBudget,
) -> Result<Settlement<i32>, EngineError> {
    let operation = SettlementOperation::Dlx;
    let scope = MetricScope::from_claim(claimed);
    execute_dlx(
        tenant_pool,
        payload_protector,
        DlxInput {
            tenant,
            claimed,
            error_summary: failure.dlx_summary(),
            relay_failure_reason: failure.relay_failure_reason(),
        },
        relay_budget,
        "settle_dlx",
    )
    .await
    .finalize(scope, operation)
}

pub(super) async fn same_id_expiry_dlx(
    tenant_pool: &PgTenantPool,
    payload_protector: &DlxPayloadProtector,
    tenant: vocab::TenantId,
    claimed: &PgClaimedOutboxEntry,
    phase: SameIdDeliveryPhase,
    relay_budget: RelayBudget,
) -> Result<Settlement<i32>, EngineError> {
    let operation = SettlementOperation::SameIdExpiryDlx;
    let scope = MetricScope::from_claim(claimed);
    execute_dlx(
        tenant_pool,
        payload_protector,
        DlxInput {
            tenant,
            claimed,
            error_summary: phase.dlx_summary(),
            relay_failure_reason: Some(phase.failure_reason()),
        },
        relay_budget,
        "settle_delivery_window_expired",
    )
    .await
    .finalize(scope, operation)
}

struct DlxInput<'a> {
    tenant: vocab::TenantId,
    claimed: &'a PgClaimedOutboxEntry,
    error_summary: &'static str,
    relay_failure_reason: Option<&'static str>,
}

type MarkDlxRow = (
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<Vec<u8>>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<i32>,
);

async fn execute_dlx(
    tenant_pool: &PgTenantPool,
    payload_protector: &DlxPayloadProtector,
    input: DlxInput<'_>,
    relay_budget: RelayBudget,
    phase: &'static str,
) -> SettlementAttempt<i32> {
    let DlxInput {
        tenant,
        claimed,
        error_summary,
        relay_failure_reason,
    } = input;
    let deadline = match deadline_or_expired(claimed, relay_budget) {
        Some(deadline) => deadline,
        None => return SettlementAttempt::outcome(Settlement::expired()),
    };
    let payload_protector = payload_protector.clone();
    let event_id = claimed.idem_key().as_str().to_owned();
    let lease_token = claimed.lease_token().to_owned();
    let lease_deadline_epoch_micros = claimed.lease_deadline_epoch_micros();
    let outcome = tenant_pool
        .deadline_write(
            infra_tenant_scope(tenant),
            deadline,
            move |connection| {
                let payload_protector = payload_protector.clone();
                Box::pin(async move {
                    let row: MarkDlxRow = sqlx::query_as(
                        r#"
                        SELECT settlement_outcome::text, tenant_id, domain, contract_id, topic,
                               payload, metadata, contract_version, schema_hash, retry_count
                        FROM rss_outbox_mark_dlx($1, $2::uuid, $3)
                        "#,
                    )
                    .bind(&event_id)
                    .bind(&lease_token)
                    .bind(lease_deadline_epoch_micros)
                    .fetch_one(&mut *connection)
                    .await
                    .map_err(|error| map_storage_error(error, phase))?;
                    settle_dlx_row(
                        row,
                        connection,
                        DlxRowContext {
                            payload_protector: &payload_protector,
                            phase,
                            tenant,
                            event_id: &event_id,
                            error_summary,
                            relay_failure_reason,
                        },
                    )
                    .await
                })
            },
            move |error| map_storage_error(error, phase),
            move || map_outer_timeout(phase, relay_budget),
        )
        .await;
    SettlementAttempt::from_result(outcome)
}

struct DlxRowContext<'a> {
    payload_protector: &'a DlxPayloadProtector,
    phase: &'static str,
    tenant: vocab::TenantId,
    event_id: &'a str,
    error_summary: &'static str,
    relay_failure_reason: Option<&'static str>,
}

struct SettledDlxRow {
    domain: String,
    contract_id: String,
    topic: String,
    payload: Vec<u8>,
    metadata_json: String,
    contract_version: String,
    schema_hash: String,
    authoritative_retry_count: i32,
}

async fn protect_dlx_row(
    payload_protector: &DlxPayloadProtector,
    tenant: vocab::TenantId,
    event_id: &str,
    relay_failure_reason: Option<&'static str>,
    row: SettledDlxRow,
) -> Result<(SettledDlxRow, ProtectedDlxCapsule), SettlementAttemptError> {
    let metadata = metadata_json_with_relay_failure(
        &row.metadata_json,
        tenant,
        &row.contract_version,
        &row.schema_hash,
        relay_failure_reason,
    )
    .map_err(|_| SettlementAttemptError::Invariant)?;
    let protected = payload_protector
        .encrypt(
            DlxPayloadContext::new(
                tenant,
                DeadLetterSource::OutboxRelay.as_str(),
                &row.domain,
                None,
                &row.contract_id,
                &row.topic,
                None,
                event_id,
            ),
            &row.payload,
            &metadata,
        )
        .await
        .map_err(|error| {
            tracing::warn!(target: "postgres", error = %secure::redact_error(&error), "outbox: settle DLX encrypt error");
            SettlementAttemptError::PayloadProtection
        })?;
    Ok((row, protected))
}

fn decode_dlx_row(
    row: MarkDlxRow,
    expected_tenant: vocab::TenantId,
) -> Result<Settlement<SettledDlxRow>, SettlementAttemptError> {
    let (
        raw_outcome,
        tenant_id,
        domain,
        contract_id,
        topic,
        payload,
        metadata_json,
        contract_version,
        schema_hash,
        authoritative_retry_count,
    ) = row;
    match parse_outcome(&raw_outcome)? {
        Settlement::Expired(_) => ensure_empty_dlx_row(
            [
                tenant_id.as_ref(),
                domain.as_ref(),
                contract_id.as_ref(),
                topic.as_ref(),
                metadata_json.as_ref(),
                contract_version.as_ref(),
                schema_hash.as_ref(),
            ],
            payload.as_ref(),
            authoritative_retry_count.as_ref(),
            Settlement::expired(),
        ),
        Settlement::LostLease(_) => ensure_empty_dlx_row(
            [
                tenant_id.as_ref(),
                domain.as_ref(),
                contract_id.as_ref(),
                topic.as_ref(),
                metadata_json.as_ref(),
                contract_version.as_ref(),
                schema_hash.as_ref(),
            ],
            payload.as_ref(),
            authoritative_retry_count.as_ref(),
            Settlement::lost_lease(),
        ),
        Settlement::Settled((), _) => {
            let tenant_id = tenant_id.ok_or(SettlementAttemptError::Invariant)?;
            let row_tenant =
                parse_tenant_id(&tenant_id).map_err(|_| SettlementAttemptError::Invariant)?;
            if row_tenant != expected_tenant {
                return Err(SettlementAttemptError::Invariant);
            }
            Ok(Settlement::settled(SettledDlxRow {
                domain: domain.ok_or(SettlementAttemptError::Invariant)?,
                contract_id: contract_id.ok_or(SettlementAttemptError::Invariant)?,
                topic: topic.ok_or(SettlementAttemptError::Invariant)?,
                payload: payload.ok_or(SettlementAttemptError::Invariant)?,
                metadata_json: metadata_json.ok_or(SettlementAttemptError::Invariant)?,
                contract_version: contract_version.ok_or(SettlementAttemptError::Invariant)?,
                schema_hash: schema_hash.ok_or(SettlementAttemptError::Invariant)?,
                authoritative_retry_count: authoritative_retry_count
                    .ok_or(SettlementAttemptError::Invariant)?,
            }))
        }
    }
}

async fn settle_dlx_row(
    row: MarkDlxRow,
    connection: &mut sqlx::PgConnection,
    context: DlxRowContext<'_>,
) -> Result<Settlement<i32>, SettlementAttemptError> {
    let DlxRowContext {
        payload_protector,
        phase,
        tenant,
        event_id,
        error_summary,
        relay_failure_reason,
    } = context;
    match decode_dlx_row(row, tenant)? {
        Settlement::Expired(_) => Ok(Settlement::expired()),
        Settlement::LostLease(_) => Ok(Settlement::lost_lease()),
        Settlement::Settled(row, _) => {
            let (row, protected) = protect_dlx_row(
                payload_protector,
                tenant,
                event_id,
                relay_failure_reason,
                row,
            )
            .await?;
            sqlx::query(
                r#"
                INSERT INTO dead_letter
                    (tenant_id, message_id, producer_domain, consumer_domain,
                     contract_id, topic, consumer_group,
                     replay_capsule, replay_capsule_key_ref, payload_len,
                     replay_capsule_encoding, metadata_digest,
                     error_summary, num_attempts, source_kind)
                VALUES ($1::uuid, $2, $3, NULL, $4, $5, NULL, $6, $7, $8, $9, $10, $11, $12, $13)
                "#,
            )
            .bind(tenant.to_string())
            .bind(event_id)
            .bind(row.domain)
            .bind(row.contract_id)
            .bind(row.topic)
            .bind(sqlx::types::Json(protected.replay_capsule()))
            .bind(protected.key_ref())
            .bind(protected.payload_len())
            .bind(DLX_REPLAY_CAPSULE_ENCODING)
            .bind(protected.metadata_digest())
            .bind(error_summary)
            .bind(row.authoritative_retry_count)
            .bind(DeadLetterSource::OutboxRelay.as_str())
            .execute(connection)
            .await
            .map_err(|error| map_storage_error(error, phase))?;
            Ok(Settlement::settled(row.authoritative_retry_count))
        }
    }
}

fn ensure_empty_dlx_row<T>(
    text_fields: [Option<&String>; 7],
    payload: Option<&Vec<u8>>,
    retry_count: Option<&i32>,
    outcome: Settlement<T>,
) -> Result<Settlement<T>, SettlementAttemptError> {
    if text_fields.into_iter().any(|field| field.is_some())
        || payload.is_some()
        || retry_count.is_some()
    {
        return Err(SettlementAttemptError::Invariant);
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::fmt;
    use std::time::Duration;

    use diport::key_provider::KeyProviderErrorKind;
    use diport::{
        DynKeyProvider, EncryptOutput, KeyName, KeyProvider, KeyProviderError, KeyRef,
        RedactedBytes,
    };
    use secure::{DerivedAad, Plaintext};
    use sqlx::Error as SqlxError;
    use sqlx::error::{DatabaseError, ErrorKind};

    use super::{
        MarkDlxRow, MetricScope, Settlement, SettlementAttempt, SettlementAttemptError,
        SettlementDeadlineExpired, SettlementFailureReason, SettlementOperation, decode_dlx_row,
        is_timeout, select_deadline,
    };

    use crate::outbox::{
        ClaimedOutboxRow, OutboxProviderIdentity, RelayPublishFailure, SameIdDeliveryPhase,
        hydrate_claimed_outbox_row,
    };

    const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const HASH: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[allow(clippy::expect_used)]
    fn relay_budget() -> eventexec::RelayBudget {
        eventexec::RelayBudget::new(
            Duration::from_millis(20),
            Duration::from_millis(10),
            Duration::from_millis(3),
            Duration::from_millis(2),
        )
        .expect("valid test relay budget")
    }

    fn empty_dlx_row(outcome: &str) -> MarkDlxRow {
        (
            outcome.to_owned(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
    }

    fn settled_dlx_row() -> MarkDlxRow {
        (
            "settled".to_owned(),
            Some(TENANT.to_owned()),
            Some("identity".to_owned()),
            Some("identity.session-created".to_owned()),
            Some("identity.session-created".to_owned()),
            Some(b"settlement-payload".to_vec()),
            Some("{}".to_owned()),
            Some("v1".to_owned()),
            Some(HASH.to_owned()),
            Some(2),
        )
    }

    #[allow(clippy::expect_used)]
    fn claimed(monotonic_deadline: tokio::time::Instant) -> crate::outbox::PgClaimedOutboxEntry {
        let row = ClaimedOutboxRow {
            tenant_id: TENANT.to_owned(),
            contract_id: "identity.session-created".to_owned(),
            topic: "identity.session-created".to_owned(),
            event_id: "evt-settlement-unit".to_owned(),
            payload: b"payload".to_vec(),
            retry_count: 2,
            metadata: "{}".to_owned(),
            domain: "identity".to_owned(),
            contract_version: "v1".to_owned(),
            schema_hash: HASH.to_owned(),
            claimed_at_epoch_seconds: 1_700_000_000,
            lease_token: "550e8400-e29b-41d4-a716-446655440000".to_owned(),
            deadline_epoch_micros: 1_700_000_060_000_000,
        };
        let provider = std::sync::Arc::new(OutboxProviderIdentity {
            domain: vocab::DomainName::parse("identity").expect("valid domain"),
        });
        hydrate_claimed_outbox_row(row, &provider, monotonic_deadline).expect("valid claim")
    }

    #[allow(clippy::expect_used)]
    fn tenant() -> vocab::TenantId {
        vocab::TenantId::parse(TENANT).expect("valid tenant")
    }

    #[allow(clippy::expect_used)]
    fn lazy_tenant_pool() -> crate::cotx::PgTenantPool {
        let options = sqlx::postgres::PgConnectOptions::new()
            .host("127.0.0.1")
            .port(1)
            .database("rss")
            .username("rss")
            .password("rss");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_millis(1))
            .connect_lazy_with(options);
        crate::cotx::PgTenantPool::new(&crate::PgStore { pool })
    }

    async fn closed_tenant_pool() -> crate::cotx::PgTenantPool {
        let options = sqlx::postgres::PgConnectOptions::new()
            .host("127.0.0.1")
            .port(1)
            .database("rss")
            .username("rss")
            .password("rss");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy_with(options);
        let tenant_pool = crate::cotx::PgTenantPool::new(&crate::PgStore { pool: pool.clone() });
        pool.close().await;
        tenant_pool
    }

    fn publish_failure() -> RelayPublishFailure {
        RelayPublishFailure::Publisher(diport::PublisherError::permanent(std::io::Error::other(
            "settlement unit test",
        )))
    }

    struct RejectingKeyProvider;

    impl KeyProvider for RejectingKeyProvider {
        async fn encrypt(
            &self,
            _key: KeyName,
            _plaintext: Plaintext,
            _aad: DerivedAad,
        ) -> Result<EncryptOutput, KeyProviderError> {
            Err(KeyProviderError::new(
                KeyProviderErrorKind::Unavailable,
                std::io::Error::other("settlement payload protection fault"),
            ))
        }

        async fn decrypt(
            &self,
            _ciphertext: RedactedBytes,
            _key: KeyRef,
            _aad: DerivedAad,
        ) -> Result<Plaintext, KeyProviderError> {
            Err(KeyProviderError::new(
                KeyProviderErrorKind::Unavailable,
                std::io::Error::other("settlement payload protection fault"),
            ))
        }

        async fn rewrap(
            &self,
            _ciphertext: RedactedBytes,
            _key: KeyRef,
            _aad: DerivedAad,
        ) -> Result<EncryptOutput, KeyProviderError> {
            Err(KeyProviderError::new(
                KeyProviderErrorKind::Unavailable,
                std::io::Error::other("settlement payload protection fault"),
            ))
        }

        async fn shutdown(&self) -> Result<(), KeyProviderError> {
            Ok(())
        }
    }

    #[allow(clippy::expect_used)]
    fn rejecting_payload_protector() -> crate::DlxPayloadProtector {
        crate::DlxPayloadProtector::new(
            DynKeyProvider::new_box(RejectingKeyProvider),
            eventexec::DlxHotKeyName::try_new("settlement-rejecting").expect("valid test key name"),
        )
    }

    #[tokio::test(start_paused = true)]
    async fn expired_preflight_closes_all_four_entrypoints_without_database_io() {
        let claim = claimed(crate::cotx::io_deadline_after(Duration::ZERO));
        let pool = lazy_tenant_pool();
        let protector = crate::dead_letter_payload::tests::test_protector();
        let budget = relay_budget();

        assert!(matches!(
            super::published(&pool, &claim, budget).await,
            Ok(super::Settlement::Expired(_))
        ));
        assert!(matches!(
            super::retry(&pool, &claim, budget).await,
            Ok(super::Settlement::Expired(_))
        ));
        assert!(matches!(
            super::ordinary_dlx(
                &pool,
                &protector,
                tenant(),
                &claim,
                &publish_failure(),
                budget,
            )
            .await,
            Ok(super::Settlement::Expired(_))
        ));
        for phase in [SameIdDeliveryPhase::Automatic, SameIdDeliveryPhase::Redrive] {
            assert!(matches!(
                super::same_id_expiry_dlx(&pool, &protector, tenant(), &claim, phase, budget,)
                    .await,
                Ok(super::Settlement::Expired(_))
            ));
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::expect_used)]
    async fn closed_pool_errors_cross_every_fresh_settlement_entrypoint() {
        let pool = closed_tenant_pool().await;
        // Every production entry must enter the tenant transaction funnel and map its closed-pool
        // storage failure to Transient while emitting exactly one storage sample.
        let claim = claimed(crate::cotx::io_deadline_after(Duration::from_secs(1)));
        let protector = crate::dead_letter_payload::tests::test_protector();
        let budget = relay_budget();
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    for result in [
                        super::published(&pool, &claim, budget).await,
                        super::retry(&pool, &claim, budget).await,
                    ] {
                        assert_eq!(
                            result.expect_err("unreachable lazy pool must fail").kind(),
                            consistency::EngineErrorKind::Transient
                        );
                    }
                    assert_eq!(
                        super::ordinary_dlx(
                            &pool,
                            &protector,
                            tenant(),
                            &claim,
                            &publish_failure(),
                            budget,
                        )
                        .await
                        .expect_err("unreachable lazy pool must fail")
                        .kind(),
                        consistency::EngineErrorKind::Transient
                    );
                    assert_eq!(
                        super::same_id_expiry_dlx(
                            &pool,
                            &protector,
                            tenant(),
                            &claim,
                            SameIdDeliveryPhase::Automatic,
                            budget,
                        )
                        .await
                        .expect_err("unreachable lazy pool must fail")
                        .kind(),
                        consistency::EngineErrorKind::Transient
                    );
                });
            });
        });
        let rendered = handle.render();
        let samples = rendered
            .lines()
            .filter(|line| line.starts_with("outbox_relay_settlement_failure_total{"))
            .collect::<Vec<_>>();
        assert_eq!(samples.len(), 4, "{rendered}");
        assert!(
            samples
                .iter()
                .all(|sample| sample.contains(r#"reason="storage""#) && sample.ends_with(" 1")),
            "{rendered}"
        );
    }

    #[tokio::test(start_paused = true)]
    #[allow(clippy::expect_used)]
    async fn claim_deadline_is_conservative_and_equal_is_expired() {
        let budget = relay_budget();
        let claim_deadline = crate::cotx::io_deadline_after(Duration::from_millis(2));
        let selected = select_deadline(claim_deadline, budget).expect("claim is still fresh");
        assert_eq!(selected, claim_deadline);

        tokio::time::advance(Duration::from_millis(2)).await;
        assert_eq!(
            select_deadline(claim_deadline, budget),
            Err(SettlementDeadlineExpired)
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn settle_timeout_wins_only_when_it_precedes_claim_expiry() {
        let budget = relay_budget();
        let claim_deadline = crate::cotx::io_deadline_after(Duration::from_millis(10));
        let selected = select_deadline(claim_deadline, budget).expect("claim is still fresh");
        assert!(selected < claim_deadline);
    }

    #[test]
    fn settlement_timeout_is_transient() {
        let error = super::settlement_timeout_error("test_settlement", 5);
        assert_eq!(error.kind(), consistency::EngineErrorKind::Transient);
    }

    #[test]
    #[allow(clippy::cognitive_complexity, clippy::expect_used, clippy::panic)]
    fn dlx_row_decoder_is_closed_and_rejects_partial_outcomes() {
        assert!(matches!(
            decode_dlx_row(empty_dlx_row("expired"), tenant()),
            Ok(Settlement::Expired(_))
        ));
        assert!(matches!(
            decode_dlx_row(empty_dlx_row("lost_lease"), tenant()),
            Ok(Settlement::LostLease(_))
        ));

        let decoded = decode_dlx_row(settled_dlx_row(), tenant());
        let Settlement::Settled(row, _) = decoded.expect("complete settled row") else {
            panic!("settled discriminant must decode to settled row");
        };
        assert_eq!(row.domain, "identity");
        assert_eq!(row.contract_id, "identity.session-created");
        assert_eq!(row.topic, "identity.session-created");
        assert_eq!(row.payload, b"settlement-payload");
        assert_eq!(row.metadata_json, "{}");
        assert_eq!(row.contract_version, "v1");
        assert_eq!(row.schema_hash, HASH);
        assert_eq!(row.authoritative_retry_count, 2);

        let mut partial_expired = empty_dlx_row("expired");
        partial_expired.2 = Some("identity".to_owned());
        assert!(decode_dlx_row(partial_expired, tenant()).is_err());

        let mut partial_lost = empty_dlx_row("lost_lease");
        partial_lost.5 = Some(Vec::new());
        assert!(decode_dlx_row(partial_lost, tenant()).is_err());

        let mut missing = settled_dlx_row();
        missing.8 = None;
        assert!(decode_dlx_row(missing, tenant()).is_err());

        let mut wrong_tenant = settled_dlx_row();
        wrong_tenant.1 = Some("11111111-1111-4111-8111-111111111111".to_owned());
        assert!(decode_dlx_row(wrong_tenant, tenant()).is_err());

        let mut invalid_tenant = settled_dlx_row();
        invalid_tenant.1 = Some("not-a-tenant".to_owned());
        assert!(decode_dlx_row(invalid_tenant, tenant()).is_err());

        assert!(decode_dlx_row(empty_dlx_row("unknown"), tenant()).is_err());
    }

    #[tokio::test]
    #[allow(clippy::expect_used, clippy::panic)]
    async fn settled_dlx_row_protection_is_payload_bound_and_metadata_safe() {
        let Settlement::Settled(row, _) =
            decode_dlx_row(settled_dlx_row(), tenant()).expect("complete settled row")
        else {
            panic!("settled discriminant must decode to settled row");
        };
        let protector = crate::dead_letter_payload::tests::test_protector();
        let (row, protected) = super::protect_dlx_row(
            &protector,
            tenant(),
            "evt-settlement-unit",
            Some("envelope_missing_tenant_id"),
            row,
        )
        .await
        .expect("valid row must encrypt");

        assert_eq!(row.authoritative_retry_count, 2);
        assert_eq!(protected.payload_len(), b"settlement-payload".len() as i64);
        assert!(!protected.key_ref().is_empty());
        assert!(!protected.metadata_digest().is_empty());
        assert!(protected.replay_capsule().get("ciphertext").is_some());

        let Settlement::Settled(mut invalid_row, _) =
            decode_dlx_row(settled_dlx_row(), tenant()).expect("complete settled row")
        else {
            panic!("settled discriminant must decode to settled row");
        };
        invalid_row.metadata_json = "[]".to_owned();
        assert!(
            super::protect_dlx_row(
                &protector,
                tenant(),
                "evt-settlement-unit",
                None,
                invalid_row,
            )
            .await
            .is_err(),
            "non-object metadata must fail closed before persistence"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used, clippy::panic)]
    async fn payload_protection_fault_is_finalized_once_with_closed_reason() {
        let Settlement::Settled(row, _) =
            decode_dlx_row(settled_dlx_row(), tenant()).expect("complete settled row")
        else {
            panic!("settled discriminant must decode to settled row");
        };
        let error = match super::protect_dlx_row(
            &rejecting_payload_protector(),
            tenant(),
            "evt-settlement-unit",
            None,
            row,
        )
        .await
        {
            Ok(_) => panic!("rejecting key provider must fail"),
            Err(error) => error,
        };
        assert_eq!(error, SettlementAttemptError::PayloadProtection);

        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            let result = SettlementAttempt::<()>::failure(error)
                .finalize(metric_scope(), SettlementOperation::Dlx);
            assert!(result.is_err());
        });
        let rendered = handle.render();
        let samples = rendered
            .lines()
            .filter(|line| line.starts_with("outbox_relay_settlement_failure_total{"))
            .collect::<Vec<_>>();
        assert_eq!(samples.len(), 1, "{rendered}");
        assert!(samples[0].contains(r#"reason="payload_protection""#));
        assert!(samples[0].ends_with(" 1"));
    }

    #[test]
    fn typed_attempt_finalizer_counts_every_error_class_once() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            for error in [
                SettlementAttemptError::Timeout,
                SettlementAttemptError::Storage,
                SettlementAttemptError::PayloadProtection,
                SettlementAttemptError::Invariant,
            ] {
                let result = SettlementAttempt::<()>::failure(error)
                    .finalize(metric_scope(), SettlementOperation::Retry);
                assert!(result.is_err());
            }
        });
        let rendered = handle.render();
        assert_eq!(
            rendered
                .lines()
                .filter(|line| line.starts_with("outbox_relay_settlement_failure_total{"))
                .count(),
            4,
            "{rendered}"
        );
        assert!(rendered.contains(r#"operation="retry""#), "{rendered}");
        for reason in ["timeout", "storage", "payload_protection", "invariant"] {
            assert!(
                rendered.contains(&format!(r#"reason="{reason}""#)),
                "{rendered}"
            );
        }
    }

    #[test]
    fn settlement_discriminants_are_closed_and_fail_unknown() {
        assert!(matches!(
            super::parse_outcome("settled"),
            Ok(super::Settlement::Settled((), _))
        ));
        assert!(matches!(
            super::parse_outcome("expired"),
            Ok(super::Settlement::Expired(_))
        ));
        assert!(matches!(
            super::parse_outcome("lost_lease"),
            Ok(super::Settlement::LostLease(_))
        ));
        assert!(super::parse_outcome("unknown").is_err());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn migration_0066_recovery_is_forward_only() {
        let readme = include_str!("../../migrations/README.md");
        let section = readme
            .split("### 0066 sealed settlement outcome cutover")
            .nth(1)
            .and_then(|tail| tail.split("\n### ").next())
            .expect("0066 runbook section");

        assert!(
            !section.contains("回滚应用版本"),
            "0066 schema cannot be served by a rolled-back binary"
        );
        for required in ["数据库保持 0066", "0066-compatible", "forward migration"] {
            assert!(
                section.contains(required),
                "0066 recovery must state forward-only action `{required}`"
            );
        }
    }

    #[test]
    fn metric_labels_are_closed_and_low_cardinality() {
        assert_eq!(SettlementOperation::Published.as_label(), "published");
        assert_eq!(SettlementOperation::Retry.as_label(), "retry");
        assert_eq!(SettlementOperation::Dlx.as_label(), "dlx");
        assert_eq!(
            SettlementOperation::SameIdExpiryDlx.as_label(),
            "same_id_expiry_dlx"
        );
        assert_eq!(SettlementFailureReason::Timeout.as_label(), "timeout");
        assert_eq!(SettlementFailureReason::Expired.as_label(), "expired");
        assert_eq!(SettlementFailureReason::LostLease.as_label(), "lost_lease");
        assert_eq!(SettlementFailureReason::Storage.as_label(), "storage");
        assert_eq!(
            SettlementFailureReason::PayloadProtection.as_label(),
            "payload_protection"
        );
        assert_eq!(SettlementFailureReason::Invariant.as_label(), "invariant");
    }

    #[derive(Debug)]
    struct FakeDatabaseError {
        code: &'static str,
    }

    impl fmt::Display for FakeDatabaseError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("fake settlement database error")
        }
    }

    impl std::error::Error for FakeDatabaseError {}

    impl DatabaseError for FakeDatabaseError {
        fn message(&self) -> &str {
            "fake settlement database error"
        }

        fn code(&self) -> Option<Cow<'_, str>> {
            Some(Cow::Borrowed(self.code))
        }

        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }

        fn kind(&self) -> ErrorKind {
            ErrorKind::Other
        }
    }

    #[test]
    fn infrastructure_timeout_sources_are_classified_closed() {
        assert!(is_timeout(&SqlxError::PoolTimedOut));
        for code in ["57014", "55P03"] {
            assert!(is_timeout(&SqlxError::Database(Box::new(
                FakeDatabaseError { code }
            ))));
        }
        assert!(!is_timeout(&SqlxError::PoolClosed));
        assert!(!is_timeout(&SqlxError::Database(Box::new(
            FakeDatabaseError { code: "23505" }
        ))));
    }

    #[allow(clippy::expect_used)]
    fn metric_scope() -> MetricScope {
        MetricScope {
            domain: "identity".to_owned(),
            subject: consistency::OutboxMetricSubject::new(
                vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
                    .expect("valid tenant"),
                consistency::OutboxContractId::parse("identity.session-created")
                    .expect("valid contract"),
            ),
        }
    }

    #[test]
    fn finalizer_emits_exactly_once_for_every_non_success_outcome() {
        for reason in [
            SettlementFailureReason::Timeout,
            SettlementFailureReason::Expired,
            SettlementFailureReason::LostLease,
            SettlementFailureReason::Storage,
            SettlementFailureReason::PayloadProtection,
            SettlementFailureReason::Invariant,
        ] {
            let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
            let handle = recorder.handle();
            metrics::with_local_recorder(&recorder, || {
                let attempt = match reason {
                    SettlementFailureReason::Expired => {
                        SettlementAttempt::outcome(super::Settlement::<()>::expired())
                    }
                    SettlementFailureReason::LostLease => {
                        SettlementAttempt::outcome(super::Settlement::<()>::lost_lease())
                    }
                    SettlementFailureReason::Timeout => {
                        SettlementAttempt::failure(SettlementAttemptError::Timeout)
                    }
                    SettlementFailureReason::Storage => {
                        SettlementAttempt::failure(SettlementAttemptError::Storage)
                    }
                    SettlementFailureReason::PayloadProtection => {
                        SettlementAttempt::failure(SettlementAttemptError::PayloadProtection)
                    }
                    SettlementFailureReason::Invariant => {
                        SettlementAttempt::failure(SettlementAttemptError::Invariant)
                    }
                };
                let _ = attempt.finalize(metric_scope(), SettlementOperation::Published);
            });
            let rendered = handle.render();
            let samples = rendered
                .lines()
                .filter(|line| line.starts_with("outbox_relay_settlement_failure_total{"))
                .collect::<Vec<_>>();
            assert_eq!(samples.len(), 1, "{rendered}");
            assert!(samples[0].contains(reason.as_label()), "{rendered}");
            assert!(samples[0].ends_with(" 1"), "{rendered}");
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn failure_metric_emits_only_closed_scope_operation_and_reason_labels() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let scope = metric_scope();
        metrics::with_local_recorder(&recorder, || {
            for operation in [
                SettlementOperation::Published,
                SettlementOperation::Retry,
                SettlementOperation::Dlx,
                SettlementOperation::SameIdExpiryDlx,
            ] {
                for reason in [
                    SettlementFailureReason::Timeout,
                    SettlementFailureReason::Expired,
                    SettlementFailureReason::LostLease,
                    SettlementFailureReason::Storage,
                    SettlementFailureReason::PayloadProtection,
                    SettlementFailureReason::Invariant,
                ] {
                    scope.record(operation, reason);
                }
            }
        });

        let rendered = handle.render();
        assert!(rendered.contains("outbox_relay_settlement_failure_total"));
        let samples = rendered
            .lines()
            .filter(|line| line.starts_with("outbox_relay_settlement_failure_total{"))
            .collect::<Vec<_>>();
        assert_eq!(samples.len(), 24, "{rendered}");
        assert!(
            samples.iter().all(|sample| sample.ends_with(" 1")),
            "{rendered}"
        );
        for operation in ["published", "retry", "dlx", "same_id_expiry_dlx"] {
            assert!(rendered.contains(&format!(r#"operation="{operation}""#)));
        }
        for reason in [
            "timeout",
            "expired",
            "lost_lease",
            "storage",
            "payload_protection",
            "invariant",
        ] {
            assert!(rendered.contains(&format!(r#"reason="{reason}""#)));
        }
        for forbidden in ["event_id=", "lease_token=", "deadline=", "error="] {
            assert!(!rendered.contains(forbidden), "{forbidden}: {rendered}");
        }
    }
}
