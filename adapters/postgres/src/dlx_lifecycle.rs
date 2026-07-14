//! PostgreSQL repository for the fixed DLX archive-before-purge lifecycle.
//!
//! The repository owns independent archiver, verifier, and purger pools. It exposes no raw pool,
//! tenant transaction, retention input, or batch input; every cross-tenant operation is a call to
//! one of the eight fixed SECURITY DEFINER functions installed by migration 0063.

use diport::{
    ArchiveChecksum, ArchiveClaimSettleOutcome, ArchiveVersionId, ClaimedArchiveCandidate,
    DeadLetterSource, DlxArchiveBacklog, DlxLifecycleError, DlxLifecycleOperation,
    DlxLifecycleReason, DlxLifecycleRepository, ManagedResource, ReceiptCasOutcome,
};
use eventexec::{
    DlxArchiveCandidate, DlxArchiveSafeMetadata, DlxArchiveSafeMetadataInput, DlxMetadataDigest,
    ExpiredArchiveReceipt, MissingArchiveProof, VerifiedArchiveReceipt,
};
use sqlx::PgPool;

use crate::dead_letter_payload::{
    DLX_REPLAY_CAPSULE_ENCODING, DlxPayloadContext, DlxPayloadProtector, validate_replay_capsule,
};
use crate::{PgConfig, PgError, PgStore};

const EXPECTED_DLX_ARCHIVER_ROLE: &str = "rss_dlx_archiver";
const EXPECTED_DLX_VERIFIER_ROLE: &str = "rss_dlx_verifier";
const EXPECTED_DLX_PURGER_ROLE: &str = "rss_dlx_purger";

const ARCHIVER_FUNCTIONS: &[&str] = &[
    "rss_dlx_archive_backlog",
    "rss_dlx_claim_archive_candidates",
    "rss_dlx_quarantine_archive_candidate",
    "rss_dlx_settle_archive_retry",
];
const VERIFIER_FUNCTIONS: &[&str] = &["rss_dlx_record_archive_receipt"];
const PURGER_FUNCTIONS: &[&str] = &[
    "rss_dlx_delete_missing_archive_receipt",
    "rss_dlx_purge_verified",
    "rss_dlx_reconcile_expired_receipts",
];

/// Dedicated lifecycle pool owner. Runtime keeps this owner in its shutdown stack and injects a
/// cloned [`PgDlxLifecycleRepository`] into `eventexec::DlxLifecycle`.
pub struct PgDlxLifecycleRuntime {
    archiver_pool: PgPool,
    verifier_pool: PgPool,
    purger_pool: PgPool,
    payload_protector: DlxPayloadProtector,
}

impl PgDlxLifecycleRuntime {
    /// Connects before schema migration and verifies only the independently provisioned workload
    /// identity. This deliberately does not depend on 0063 functions or ACLs, so a destructive
    /// migration can be ordered after all external identity capability gates have passed.
    pub async fn preflight_identities(
        archiver_config: &PgConfig,
        verifier_config: &PgConfig,
        purger_config: &PgConfig,
    ) -> Result<(), PgError> {
        preflight_identity(archiver_config, EXPECTED_DLX_ARCHIVER_ROLE).await?;
        preflight_identity(verifier_config, EXPECTED_DLX_VERIFIER_ROLE).await?;
        preflight_identity(purger_config, EXPECTED_DLX_PURGER_ROLE).await
    }

    /// Connects the three independent pools and runs each exact-role/least-privilege startup gate
    /// before any lifecycle capability can be constructed.
    pub async fn setup(
        archiver_config: &PgConfig,
        verifier_config: &PgConfig,
        purger_config: &PgConfig,
        payload_protector: DlxPayloadProtector,
    ) -> Result<Self, PgError> {
        let archiver_pool = connect_verified_dlx_pool(
            archiver_config,
            EXPECTED_DLX_ARCHIVER_ROLE,
            ARCHIVER_FUNCTIONS,
        )
        .await?;
        let verifier_pool = match connect_verified_dlx_pool(
            verifier_config,
            EXPECTED_DLX_VERIFIER_ROLE,
            VERIFIER_FUNCTIONS,
        )
        .await
        {
            Ok(pool) => pool,
            Err(error) => {
                archiver_pool.close().await;
                return Err(error);
            }
        };
        let purger_pool = match connect_verified_dlx_pool(
            purger_config,
            EXPECTED_DLX_PURGER_ROLE,
            PURGER_FUNCTIONS,
        )
        .await
        {
            Ok(pool) => pool,
            Err(error) => {
                verifier_pool.close().await;
                archiver_pool.close().await;
                return Err(error);
            }
        };
        Ok(Self {
            archiver_pool,
            verifier_pool,
            purger_pool,
            payload_protector,
        })
    }

    /// Projects only the typed repository. The raw pool is intentionally not exposed.
    #[must_use]
    pub fn repository(&self) -> PgDlxLifecycleRepository {
        PgDlxLifecycleRepository {
            archiver_pool: self.archiver_pool.clone(),
            verifier_pool: self.verifier_pool.clone(),
            purger_pool: self.purger_pool.clone(),
            payload_protector: self.payload_protector.clone(),
        }
    }
}

async fn connect_verified_dlx_pool(
    config: &PgConfig,
    expected_role: &str,
    expected_functions: &[&str],
) -> Result<PgPool, PgError> {
    let store = PgStore::connect(config).await?;
    if let Err(error) = verify_dlx_capability(&store.pool, expected_role, expected_functions).await
    {
        store.pool.close().await;
        return Err(error);
    }
    Ok(store.pool)
}

impl ManagedResource for PgDlxLifecycleRuntime {
    fn name(&self) -> &str {
        "postgres-dlx-lifecycle"
    }

    async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
        self.purger_pool.close().await;
        self.verifier_pool.close().await;
        self.archiver_pool.close().await;
        tracing::info!(target: "postgres", "postgres DLX lifecycle pools closed");
        Ok(())
    }
}

/// Fixed-function lifecycle repository. Construction is confined to
/// [`PgDlxLifecycleRuntime::repository`].
#[derive(Clone)]
pub struct PgDlxLifecycleRepository {
    archiver_pool: PgPool,
    verifier_pool: PgPool,
    purger_pool: PgPool,
    payload_protector: DlxPayloadProtector,
}

/// Provider-owned durable archive claim. Token and deadline never cross the repository API.
pub struct PgDlxArchiveClaim {
    tenant_id: String,
    dead_letter_id: String,
    claim_token: String,
    _lease_until_epoch_micros: i64,
}

impl std::fmt::Debug for PgDlxArchiveClaim {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PgDlxArchiveClaim(<redacted>)")
    }
}

#[derive(sqlx::FromRow)]
#[cfg_attr(test, derive(Clone))]
struct ArchiveCandidateRow {
    tenant_id: String,
    dead_letter_id: String,
    message_id: String,
    producer_domain: String,
    consumer_domain: Option<String>,
    contract_id: String,
    topic: String,
    consumer_group: Option<String>,
    source_kind: String,
    error_summary: String,
    num_attempts: i32,
    first_attempt_epoch_micros: i64,
    last_attempt_epoch_micros: i64,
    replay_capsule: serde_json::Value,
    replay_capsule_key_ref: String,
    replay_capsule_encoding: String,
    payload_len: i64,
    metadata_digest: Vec<u8>,
    archive_claim_token: String,
    archive_lease_until_epoch_micros: i64,
}

#[derive(sqlx::FromRow)]
#[cfg_attr(test, derive(Clone))]
struct ExpiredReceiptRow {
    tenant_id: String,
    dead_letter_id: String,
    object_key: String,
    object_version_id: String,
    checksum_sha256: Vec<u8>,
}

impl ExpiredReceiptRow {
    fn decode(self) -> Result<ExpiredArchiveReceipt, DlxLifecycleError> {
        let tenant = parse_tenant(&self.tenant_id, DlxLifecycleOperation::DecodeExpiredReceipt)?;
        let id = eventexec::DeadLetterId::parse(&self.dead_letter_id)
            .map_err(|_| invalid_persisted(DlxLifecycleOperation::DecodeExpiredReceipt))?;
        let checksum = checksum_from_db(self.checksum_sha256)?;
        let version_id = ArchiveVersionId::try_from_provider(&self.object_version_id)?;
        ExpiredArchiveReceipt::from_persisted(id, tenant, &self.object_key, checksum, version_id)
    }
}

#[derive(sqlx::FromRow)]
struct ArchiveBacklogRow {
    pending_depth: i64,
    oldest_age_seconds: i64,
}

impl ArchiveBacklogRow {
    fn decode(self) -> Result<DlxArchiveBacklog, DlxLifecycleError> {
        let depth = u64::try_from(self.pending_depth).map_err(|_| {
            DlxLifecycleError::new(
                DlxLifecycleOperation::ArchiveBacklog,
                DlxLifecycleReason::ArithmeticOverflow,
            )
        })?;
        let oldest_age_seconds = u64::try_from(self.oldest_age_seconds).map_err(|_| {
            DlxLifecycleError::new(
                DlxLifecycleOperation::ArchiveBacklog,
                DlxLifecycleReason::ArithmeticOverflow,
            )
        })?;
        Ok(DlxArchiveBacklog::new(depth, oldest_age_seconds))
    }
}

#[derive(sqlx::FromRow)]
#[cfg_attr(test, derive(Clone))]
struct ArchiverRoleProbe {
    session_user: String,
    current_user: String,
    is_superuser: bool,
    bypasses_rls: bool,
    can_create_db: bool,
    can_create_role: bool,
    can_replicate: bool,
    inherits_privileges: bool,
    has_set_role_target: bool,
    inherited_by_other_role: bool,
}

#[derive(sqlx::FromRow)]
#[cfg_attr(test, derive(Clone))]
struct ArchiverPrivilegeProbe {
    has_relation_privilege: bool,
    can_create_in_public: bool,
    executable_functions: Vec<String>,
}

impl DlxLifecycleRepository for PgDlxLifecycleRepository {
    type ArchiveClaim = PgDlxArchiveClaim;
    type ArchiveCandidate = DlxArchiveCandidate;
    type VerifiedReceipt = VerifiedArchiveReceipt;
    type ExpiredReceipt = ExpiredArchiveReceipt;
    type MissingProof = MissingArchiveProof;

    async fn archive_backlog(&self) -> Result<DlxArchiveBacklog, DlxLifecycleError> {
        let row: ArchiveBacklogRow = sqlx::query_as(
            "SELECT pending_depth, oldest_age_seconds FROM rss_dlx_archive_backlog()",
        )
        .fetch_one(&self.archiver_pool)
        .await
        .map_err(transient_db(DlxLifecycleOperation::ArchiveBacklog))?;
        row.decode()
    }

    async fn claim_archive_candidates(
        &self,
    ) -> Result<
        Vec<ClaimedArchiveCandidate<PgDlxArchiveClaim, DlxArchiveCandidate>>,
        DlxLifecycleError,
    > {
        let rows: Vec<ArchiveCandidateRow> = sqlx::query_as(
            r#"
            SELECT tenant_id::text,
                   dead_letter_id::text,
                   message_id,
                   producer_domain,
                   consumer_domain,
                   contract_id,
                   topic,
                   consumer_group,
                   source_kind,
                   error_summary,
                   num_attempts,
                   (EXTRACT(EPOCH FROM first_attempt_at) * 1000000)::bigint
                       AS first_attempt_epoch_micros,
                   (EXTRACT(EPOCH FROM last_attempt_at) * 1000000)::bigint
                       AS last_attempt_epoch_micros,
                   replay_capsule,
                   replay_capsule_key_ref,
                   replay_capsule_encoding,
                   payload_len,
                   metadata_digest,
                   archive_claim_token::text,
                   (EXTRACT(EPOCH FROM archive_lease_until) * 1000000)::bigint
                       AS archive_lease_until_epoch_micros
            FROM rss_dlx_claim_archive_candidates()
            "#,
        )
        .fetch_all(&self.archiver_pool)
        .await
        .map_err(transient_db(DlxLifecycleOperation::ClaimArchiveCandidates))?;

        let mut candidates = Vec::with_capacity(rows.len());
        for row in rows {
            let claim = PgDlxArchiveClaim {
                tenant_id: row.tenant_id.clone(),
                dead_letter_id: row.dead_letter_id.clone(),
                claim_token: row.archive_claim_token.clone(),
                _lease_until_epoch_micros: row.archive_lease_until_epoch_micros,
            };
            match self.decode_candidate(row).await {
                Ok(candidate) => candidates.push(ClaimedArchiveCandidate::new(claim, candidate)),
                Err(error) => {
                    let outcome = self.settle_archive_failure(claim, error).await?;
                    tracing::warn!(
                        target: "postgres",
                        operation = DlxLifecycleOperation::DecodeArchiveCandidate.as_label(),
                        reason = error.reason().as_label(),
                        settlement = ?outcome,
                        "DLX lifecycle rejected and settled a claimed candidate"
                    );
                }
            }
        }
        Ok(candidates)
    }

    async fn record_verified_receipt(
        &self,
        claim: &PgDlxArchiveClaim,
        receipt: VerifiedArchiveReceipt,
    ) -> Result<ReceiptCasOutcome, DlxLifecycleError> {
        if claim.tenant_id != receipt.tenant().to_string()
            || claim.dead_letter_id != receipt.dead_letter_id().as_str()
        {
            return Err(DlxLifecycleError::new(
                DlxLifecycleOperation::RecordArchiveReceipt,
                DlxLifecycleReason::CasRejected,
            ));
        }
        let result: i64 = sqlx::query_scalar(
            r#"
            SELECT rss_dlx_record_archive_receipt(
                $1::uuid,
                $2::uuid,
                $3::uuid,
                $4,
                $5,
                $6,
                $7,
                to_timestamp($8)
            )
            "#,
        )
        .bind(&claim.tenant_id)
        .bind(&claim.dead_letter_id)
        .bind(&claim.claim_token)
        .bind(receipt.archive_version_id().as_str())
        .bind(receipt.checksum().as_bytes().as_slice())
        .bind(receipt.archive_key_ref().to_token())
        .bind(receipt.object_lock_mode().as_str())
        .bind(receipt.retain_until_epoch_secs())
        .fetch_one(&self.verifier_pool)
        .await
        .map_err(invariant_or_transient_db(
            DlxLifecycleOperation::RecordArchiveReceipt,
        ))?;
        receipt_outcome(result)
    }

    async fn settle_archive_failure(
        &self,
        claim: PgDlxArchiveClaim,
        failure: DlxLifecycleError,
    ) -> Result<ArchiveClaimSettleOutcome, DlxLifecycleError> {
        let operation = failure.operation();
        let result: i64 =
            match failure.kind() {
                diport::DlxLifecycleErrorKind::Transient => {
                    sqlx::query_scalar(
                        "SELECT rss_dlx_settle_archive_retry($1::uuid, $2::uuid, $3::uuid, $4)",
                    )
                    .bind(&claim.tenant_id)
                    .bind(&claim.dead_letter_id)
                    .bind(&claim.claim_token)
                    .bind(failure.reason().as_label())
                    .fetch_one(&self.archiver_pool)
                    .await
                }
                diport::DlxLifecycleErrorKind::Invariant => sqlx::query_scalar(
                    "SELECT rss_dlx_quarantine_archive_candidate($1::uuid, $2::uuid, $3::uuid, $4)",
                )
                .bind(&claim.tenant_id)
                .bind(&claim.dead_letter_id)
                .bind(&claim.claim_token)
                .bind(failure.reason().as_label())
                .fetch_one(&self.archiver_pool)
                .await,
            }
            .map_err(invariant_or_transient_db(operation))?;
        claim_settle_outcome(result)
    }

    async fn purge_verified(&self) -> Result<u64, DlxLifecycleError> {
        let deleted: i64 = sqlx::query_scalar("SELECT rss_dlx_purge_verified()")
            .fetch_one(&self.purger_pool)
            .await
            .map_err(transient_db(DlxLifecycleOperation::PurgeVerified))?;
        u64::try_from(deleted).map_err(|_| {
            DlxLifecycleError::new(
                DlxLifecycleOperation::PurgeVerified,
                DlxLifecycleReason::ArithmeticOverflow,
            )
        })
    }

    async fn claim_expired_receipts(
        &self,
    ) -> Result<Vec<ExpiredArchiveReceipt>, DlxLifecycleError> {
        let rows: Vec<ExpiredReceiptRow> = sqlx::query_as(
            r#"
            SELECT tenant_id::text,
                   dead_letter_id::text,
                   object_key,
                   object_version_id,
                   checksum_sha256
            FROM rss_dlx_reconcile_expired_receipts()
            "#,
        )
        .fetch_all(&self.purger_pool)
        .await
        .map_err(transient_db(DlxLifecycleOperation::ClaimExpiredReceipts))?;

        rows.into_iter().map(ExpiredReceiptRow::decode).collect()
    }

    async fn delete_expired_receipt(
        &self,
        proof: MissingArchiveProof,
    ) -> Result<ReceiptCasOutcome, DlxLifecycleError> {
        let result: i64 = sqlx::query_scalar(
            r#"
            SELECT rss_dlx_delete_missing_archive_receipt(
                $1::uuid,
                $2::uuid,
                $3,
                $4,
                $5
            )
            "#,
        )
        .bind(proof.tenant().to_string())
        .bind(proof.dead_letter_id().as_str())
        .bind(proof.object_key().as_str())
        .bind(proof.archive_version_id().as_str())
        .bind(proof.checksum().as_bytes().as_slice())
        .fetch_one(&self.purger_pool)
        .await
        .map_err(invariant_or_transient_db(
            DlxLifecycleOperation::DeleteExpiredReceipt,
        ))?;
        receipt_outcome(result)
    }
}

impl PgDlxLifecycleRepository {
    async fn decode_candidate(
        &self,
        row: ArchiveCandidateRow,
    ) -> Result<DlxArchiveCandidate, DlxLifecycleError> {
        if row.replay_capsule_encoding != DLX_REPLAY_CAPSULE_ENCODING {
            return Err(invalid_persisted(
                DlxLifecycleOperation::DecodeArchiveCandidate,
            ));
        }
        let tenant = parse_tenant(
            &row.tenant_id,
            DlxLifecycleOperation::DecodeArchiveCandidate,
        )?;
        let id = eventexec::DeadLetterId::parse(&row.dead_letter_id)
            .map_err(|_| invalid_persisted(DlxLifecycleOperation::DecodeArchiveCandidate))?;
        let context = DlxPayloadContext::new(
            tenant,
            &row.source_kind,
            &row.producer_domain,
            row.consumer_domain.as_deref(),
            &row.contract_id,
            &row.topic,
            row.consumer_group.as_deref(),
            &row.message_id,
        );
        let plaintext = self
            .payload_protector
            .decrypt_plaintext(context, &row.replay_capsule, &row.replay_capsule_key_ref)
            .await
            .map_err(|error| {
                key_provider_error(DlxLifecycleOperation::DecodeArchiveCandidate, error)
            })?;
        validate_replay_capsule(&plaintext, context, row.payload_len, &row.metadata_digest)
            .map_err(|error| {
                key_provider_error(DlxLifecycleOperation::DecodeArchiveCandidate, error)
            })?;
        let source = DeadLetterSource::parse(&row.source_kind)
            .ok_or_else(|| invalid_persisted(DlxLifecycleOperation::DecodeArchiveCandidate))?;
        let attempts = u32::try_from(row.num_attempts).map_err(|_| {
            DlxLifecycleError::new(
                DlxLifecycleOperation::DecodeArchiveCandidate,
                DlxLifecycleReason::ArithmeticOverflow,
            )
        })?;
        let payload_len = u64::try_from(row.payload_len).map_err(|_| {
            DlxLifecycleError::new(
                DlxLifecycleOperation::DecodeArchiveCandidate,
                DlxLifecycleReason::ArithmeticOverflow,
            )
        })?;
        let metadata_digest = metadata_digest_from_db(row.metadata_digest)?;
        let safe = DlxArchiveSafeMetadata::try_new(DlxArchiveSafeMetadataInput {
            message_id: row.message_id,
            producer_domain: row.producer_domain,
            consumer_domain: row.consumer_domain,
            contract_id: row.contract_id,
            topic: row.topic,
            consumer_group: row.consumer_group,
            source_kind: source,
            error_summary: row.error_summary,
            num_attempts: attempts,
            first_attempt_epoch_micros: row.first_attempt_epoch_micros,
            last_attempt_epoch_micros: row.last_attempt_epoch_micros,
            payload_len,
            metadata_digest,
        })?;
        DlxArchiveCandidate::try_new(id, tenant, safe, plaintext)
    }
}

fn receipt_outcome(result: i64) -> Result<ReceiptCasOutcome, DlxLifecycleError> {
    match result {
        1 => Ok(ReceiptCasOutcome::Applied),
        0 => Ok(ReceiptCasOutcome::AlreadyApplied),
        _ => Err(DlxLifecycleError::new(
            DlxLifecycleOperation::RecordArchiveReceipt,
            DlxLifecycleReason::UnexpectedProviderResponse,
        )),
    }
}

fn claim_settle_outcome(result: i64) -> Result<ArchiveClaimSettleOutcome, DlxLifecycleError> {
    match result {
        1 => Ok(ArchiveClaimSettleOutcome::Applied),
        0 => Ok(ArchiveClaimSettleOutcome::Stale),
        _ => Err(DlxLifecycleError::new(
            DlxLifecycleOperation::DecodeArchiveCandidate,
            DlxLifecycleReason::UnexpectedProviderResponse,
        )),
    }
}

fn invalid_persisted(operation: DlxLifecycleOperation) -> DlxLifecycleError {
    DlxLifecycleError::new(operation, DlxLifecycleReason::InvalidPersistedData)
}

fn parse_tenant(
    raw: &str,
    operation: DlxLifecycleOperation,
) -> Result<vocab::TenantId, DlxLifecycleError> {
    vocab::TenantId::parse(raw).map_err(|_| invalid_persisted(operation))
}

fn checksum_from_db(bytes: Vec<u8>) -> Result<ArchiveChecksum, DlxLifecycleError> {
    let checksum: [u8; 32] = bytes
        .try_into()
        .map_err(|_| invalid_persisted(DlxLifecycleOperation::DecodeExpiredReceipt))?;
    Ok(ArchiveChecksum::from_sha256_bytes(checksum))
}

fn metadata_digest_from_db(bytes: Vec<u8>) -> Result<DlxMetadataDigest, DlxLifecycleError> {
    let digest: [u8; 32] = bytes
        .try_into()
        .map_err(|_| invalid_persisted(DlxLifecycleOperation::DecodeArchiveCandidate))?;
    Ok(DlxMetadataDigest::from_sha256_bytes(digest))
}

fn transient_db(
    operation: DlxLifecycleOperation,
) -> impl Fn(sqlx::Error) -> DlxLifecycleError + Send + Sync + 'static {
    move |error| {
        tracing::warn!(
            target: "postgres",
            operation = operation.as_label(),
            error = %secure::redact_error(&error),
            "DLX lifecycle database operation failed"
        );
        DlxLifecycleError::new(operation, DlxLifecycleReason::ProviderUnavailable)
    }
}

fn invariant_or_transient_db(
    operation: DlxLifecycleOperation,
) -> impl Fn(sqlx::Error) -> DlxLifecycleError + Send + Sync + 'static {
    move |error| {
        let invariant = matches!(
            &error,
            sqlx::Error::Database(database) if database.code().as_deref() == Some("P0001")
        );
        tracing::warn!(
            target: "postgres",
            operation = operation.as_label(),
            error = %secure::redact_error(&error),
            "DLX lifecycle CAS failed"
        );
        if invariant {
            DlxLifecycleError::new(operation, DlxLifecycleReason::CasRejected)
        } else {
            DlxLifecycleError::new(operation, DlxLifecycleReason::ProviderUnavailable)
        }
    }
}

fn key_provider_error(
    operation: DlxLifecycleOperation,
    error: diport::KeyProviderError,
) -> DlxLifecycleError {
    tracing::warn!(
        target: "postgres",
        operation = operation.as_label(),
        key_provider_kind = ?error.kind(),
        "DLX lifecycle hot capsule rejected"
    );
    let reason = match error.kind() {
        diport::key_provider::KeyProviderErrorKind::Unavailable => {
            DlxLifecycleReason::ProviderUnavailable
        }
        diport::key_provider::KeyProviderErrorKind::Timeout => DlxLifecycleReason::ProviderTimeout,
        diport::key_provider::KeyProviderErrorKind::NotFound => DlxLifecycleReason::KeyNotFound,
        diport::key_provider::KeyProviderErrorKind::Forbidden => DlxLifecycleReason::KeyForbidden,
        diport::key_provider::KeyProviderErrorKind::Rejected => DlxLifecycleReason::KeyRejected,
        _ => DlxLifecycleReason::InternalInvariant,
    };
    DlxLifecycleError::new(operation, reason)
}

async fn preflight_identity(config: &PgConfig, expected_role: &str) -> Result<(), PgError> {
    let store = PgStore::connect(config).await?;
    let result = verify_dlx_identity(&store.pool, expected_role).await;
    store.pool.close().await;
    result
}

async fn verify_dlx_capability(
    pool: &PgPool,
    expected_role: &str,
    expected_functions: &[&str],
) -> Result<(), PgError> {
    verify_dlx_identity(pool, expected_role).await?;

    let base: (bool, bool) = sqlx::query_as(
        r#"
        SELECT EXISTS (
                   SELECT 1
                   FROM pg_class AS relation
                   JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
                   CROSS JOIN (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'),
                                      ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')) AS wanted(privilege)
                   WHERE namespace.nspname = 'public'
                     AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
                     AND has_table_privilege(
                         current_user,
                         format('%I.%I', namespace.nspname, relation.relname),
                         wanted.privilege
                     )
               ) AS has_relation_privilege,
               has_schema_privilege(current_user, 'public', 'CREATE')
                   AS can_create_in_public
        "#,
    )
    .fetch_one(pool)
    .await
    .map_err(PgError::DlxLifecycleCapability)?;
    let executable_functions: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT procedure.proname
        FROM pg_proc AS procedure
        JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
        WHERE namespace.nspname = 'public'
          AND has_function_privilege(current_user, procedure.oid, 'EXECUTE')
        ORDER BY procedure.proname
        "#,
    )
    .fetch_all(pool)
    .await
    .map_err(PgError::DlxLifecycleCapability)?;
    validate_dlx_privileges(
        &ArchiverPrivilegeProbe {
            has_relation_privilege: base.0,
            can_create_in_public: base.1,
            executable_functions,
        },
        expected_functions,
    )
}

async fn verify_dlx_identity(pool: &PgPool, expected_role: &str) -> Result<(), PgError> {
    let role: ArchiverRoleProbe = sqlx::query_as(
        r#"
        SELECT session_user,
               current_user,
               role.rolsuper AS is_superuser,
               role.rolbypassrls AS bypasses_rls,
               role.rolcreatedb AS can_create_db,
               role.rolcreaterole AS can_create_role,
               role.rolreplication AS can_replicate,
               role.rolinherit AS inherits_privileges,
               EXISTS (
                   SELECT 1
                   FROM pg_catalog.pg_roles AS granted_role
                   WHERE granted_role.rolname <> current_user
                     AND pg_catalog.pg_has_role(session_user, granted_role.oid, 'MEMBER')
               ) AS has_set_role_target,
               EXISTS (
                   SELECT 1
                   FROM pg_catalog.pg_auth_members AS membership
                   WHERE membership.roleid = role.oid
               ) AS inherited_by_other_role
        FROM pg_catalog.pg_roles AS role
        WHERE role.rolname = current_user
        "#,
    )
    .fetch_one(pool)
    .await
    .map_err(PgError::DlxLifecycleCapability)?;
    validate_dlx_role(&role, expected_role)
}

fn validate_dlx_role(role: &ArchiverRoleProbe, expected_role: &str) -> Result<(), PgError> {
    if role.session_user != expected_role || role.current_user != expected_role {
        return Err(PgError::DlxLifecycleUnexpectedRole);
    }
    if role.is_superuser
        || role.bypasses_rls
        || role.can_create_db
        || role.can_create_role
        || role.can_replicate
        || role.inherits_privileges
        || role.has_set_role_target
        || role.inherited_by_other_role
    {
        return Err(PgError::DlxLifecycleBypassRole);
    }
    Ok(())
}

fn validate_dlx_privileges(
    privileges: &ArchiverPrivilegeProbe,
    expected_functions: &[&str],
) -> Result<(), PgError> {
    let observed = privileges
        .executable_functions
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    if privileges.has_relation_privilege
        || privileges.can_create_in_public
        || observed != expected_functions
    {
        return Err(PgError::DlxLifecyclePrivileges);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::fmt;
    use std::sync::Mutex;
    use std::time::Duration;

    use diport::{
        DlxArchiveCiphertext, DlxArchiveHeadOutcome, DlxArchiveObjectMetadata,
        DlxArchivePutOutcome, DlxArchivePutRequest, DlxArchiveStore, DlxLifecycleErrorKind,
        DynKeyProvider, KeyProviderError, key_provider::KeyProviderErrorKind,
    };
    use eventexec::{DlxArchiveKeyName, DlxArchiveObjectKey, DlxLifecycle, DlxLifecycleHealth};
    use secure::Plaintext;
    use sqlx::error::{DatabaseError, ErrorKind};
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

    use super::*;
    use crate::PgPassword;
    use crate::dead_letter_payload::tests::TestKeyProvider;

    const TENANT_ID: &str = "11111111-2222-4333-8444-555555555555";
    const DEAD_LETTER_ID: &str = "018f31a8-893d-7a52-8e17-123456789abc";
    const NOW: i64 = 1_800_000_000;

    #[allow(clippy::expect_used)] // reason: compile-time fixed UUID fixture must remain readable.
    fn tenant() -> vocab::TenantId {
        vocab::TenantId::parse(TENANT_ID).expect("valid test tenant")
    }

    #[allow(clippy::expect_used)] // reason: compile-time fixed UUID fixture must remain readable.
    fn dead_letter_id() -> eventexec::DeadLetterId {
        eventexec::DeadLetterId::parse(DEAD_LETTER_ID).expect("valid test dead-letter id")
    }

    #[allow(clippy::expect_used)] // reason: compile-time fixed key-name fixture must remain readable.
    fn test_protector() -> DlxPayloadProtector {
        DlxPayloadProtector::new(
            DynKeyProvider::new_box(TestKeyProvider),
            eventexec::DlxHotKeyName::try_new("dlx-hot-test").expect("valid hot key"),
        )
    }

    #[allow(clippy::expect_used)] // reason: compile-time fixed key-name fixture must remain readable.
    fn archive_key() -> DlxArchiveKeyName {
        DlxArchiveKeyName::try_new("dlx-archive-test").expect("valid archive key")
    }

    fn lazy_pool() -> PgPool {
        let options = PgConnectOptions::new()
            .host("127.0.0.1")
            .port(1)
            .database("rss_dlx_unit")
            .username("rss_dlx_archiver")
            .password("unused");
        PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_millis(5))
            .connect_lazy_with(options)
    }

    fn repository(pool: PgPool, protector: DlxPayloadProtector) -> PgDlxLifecycleRepository {
        PgDlxLifecycleRepository {
            archiver_pool: pool.clone(),
            verifier_pool: pool.clone(),
            purger_pool: pool,
            payload_protector: protector,
        }
    }

    fn valid_role(expected_role: &str) -> ArchiverRoleProbe {
        ArchiverRoleProbe {
            session_user: expected_role.to_owned(),
            current_user: expected_role.to_owned(),
            is_superuser: false,
            bypasses_rls: false,
            can_create_db: false,
            can_create_role: false,
            can_replicate: false,
            inherits_privileges: false,
            has_set_role_target: false,
            inherited_by_other_role: false,
        }
    }

    fn valid_privileges() -> ArchiverPrivilegeProbe {
        ArchiverPrivilegeProbe {
            has_relation_privilege: false,
            can_create_in_public: false,
            executable_functions: ARCHIVER_FUNCTIONS
                .iter()
                .map(|function| (*function).to_owned())
                .collect(),
        }
    }

    #[test]
    fn lifecycle_role_decisions_are_fail_closed() {
        for (role, functions) in [
            (EXPECTED_DLX_ARCHIVER_ROLE, ARCHIVER_FUNCTIONS),
            (EXPECTED_DLX_VERIFIER_ROLE, VERIFIER_FUNCTIONS),
            (EXPECTED_DLX_PURGER_ROLE, PURGER_FUNCTIONS),
        ] {
            assert!(validate_dlx_role(&valid_role(role), role).is_ok());
            let privileges = ArchiverPrivilegeProbe {
                has_relation_privilege: false,
                can_create_in_public: false,
                executable_functions: functions
                    .iter()
                    .map(|function| (*function).to_owned())
                    .collect(),
            };
            assert!(validate_dlx_privileges(&privileges, functions).is_ok());
        }

        let mut wrong_session = valid_role(EXPECTED_DLX_ARCHIVER_ROLE);
        wrong_session.session_user = "postgres".to_owned();
        assert!(matches!(
            validate_dlx_role(&wrong_session, EXPECTED_DLX_ARCHIVER_ROLE),
            Err(PgError::DlxLifecycleUnexpectedRole)
        ));
        let mut wrong_current = valid_role(EXPECTED_DLX_ARCHIVER_ROLE);
        wrong_current.current_user = "rss_app".to_owned();
        assert!(matches!(
            validate_dlx_role(&wrong_current, EXPECTED_DLX_ARCHIVER_ROLE),
            Err(PgError::DlxLifecycleUnexpectedRole)
        ));

        for forbidden in 0..8 {
            let mut role = valid_role(EXPECTED_DLX_ARCHIVER_ROLE);
            match forbidden {
                0 => role.is_superuser = true,
                1 => role.bypasses_rls = true,
                2 => role.can_create_db = true,
                3 => role.can_create_role = true,
                4 => role.can_replicate = true,
                5 => role.inherits_privileges = true,
                6 => role.has_set_role_target = true,
                _ => role.inherited_by_other_role = true,
            }
            assert!(matches!(
                validate_dlx_role(&role, EXPECTED_DLX_ARCHIVER_ROLE),
                Err(PgError::DlxLifecycleBypassRole)
            ));
        }
    }

    #[test]
    fn lifecycle_privilege_decisions_are_fail_closed() {
        for forbidden in 0..3 {
            let mut privileges = valid_privileges();
            match forbidden {
                0 => privileges.has_relation_privilege = true,
                1 => privileges.can_create_in_public = true,
                _ => privileges
                    .executable_functions
                    .push("rss_dlx_extra".to_owned()),
            }
            assert!(matches!(
                validate_dlx_privileges(&privileges, ARCHIVER_FUNCTIONS),
                Err(PgError::DlxLifecyclePrivileges)
            ));
        }
    }

    #[test]
    #[allow(clippy::expect_used)] // reason: each branch asserts a fixed decoder fixture outcome.
    fn backlog_rows_reject_negative_database_values() {
        let backlog = ArchiveBacklogRow {
            pending_depth: 17,
            oldest_age_seconds: 31,
        }
        .decode()
        .expect("valid backlog");
        assert_eq!(backlog.depth(), 17);
        assert_eq!(backlog.oldest_age_seconds(), 31);
        assert_eq!(
            ArchiveBacklogRow {
                pending_depth: -1,
                oldest_age_seconds: 0,
            }
            .decode()
            .expect_err("negative depth must fail")
            .kind(),
            DlxLifecycleErrorKind::Invariant
        );
        assert_eq!(
            ArchiveBacklogRow {
                pending_depth: 0,
                oldest_age_seconds: -1,
            }
            .decode()
            .expect_err("negative age must fail")
            .kind(),
            DlxLifecycleErrorKind::Invariant
        );
    }

    #[test]
    #[allow(clippy::expect_used)] // reason: each branch asserts a fixed decoder fixture outcome.
    fn expired_receipt_rows_validate_every_persisted_coordinate() {
        let id = dead_letter_id();
        let object_key = DlxArchiveObjectKey::from_dead_letter(&id);
        let receipt = ExpiredReceiptRow {
            tenant_id: TENANT_ID.to_owned(),
            dead_letter_id: DEAD_LETTER_ID.to_owned(),
            object_key: object_key.as_str().to_owned(),
            object_version_id: "version-1".to_owned(),
            checksum_sha256: vec![0xAB; 32],
        }
        .decode()
        .expect("valid expired receipt");
        assert_eq!(receipt.tenant(), tenant());
        assert_eq!(receipt.dead_letter_id().as_str(), DEAD_LETTER_ID);
        assert_eq!(receipt.archive_version_id().as_str(), "version-1");
        assert_eq!(receipt.checksum().as_bytes(), &[0xAB; 32]);

        let invalid_rows = [
            ExpiredReceiptRow {
                tenant_id: "not-a-tenant".to_owned(),
                dead_letter_id: DEAD_LETTER_ID.to_owned(),
                object_key: object_key.as_str().to_owned(),
                object_version_id: "version-1".to_owned(),
                checksum_sha256: vec![0; 32],
            },
            ExpiredReceiptRow {
                tenant_id: TENANT_ID.to_owned(),
                dead_letter_id: "not-an-id".to_owned(),
                object_key: object_key.as_str().to_owned(),
                object_version_id: "version-1".to_owned(),
                checksum_sha256: vec![0; 32],
            },
            ExpiredReceiptRow {
                tenant_id: TENANT_ID.to_owned(),
                dead_letter_id: DEAD_LETTER_ID.to_owned(),
                object_key: "dead-letter/wrong.v1.enc".to_owned(),
                object_version_id: "version-1".to_owned(),
                checksum_sha256: vec![0; 32],
            },
            ExpiredReceiptRow {
                tenant_id: TENANT_ID.to_owned(),
                dead_letter_id: DEAD_LETTER_ID.to_owned(),
                object_key: object_key.as_str().to_owned(),
                object_version_id: "version-1".to_owned(),
                checksum_sha256: vec![0; 31],
            },
            ExpiredReceiptRow {
                tenant_id: TENANT_ID.to_owned(),
                dead_letter_id: DEAD_LETTER_ID.to_owned(),
                object_key: object_key.as_str().to_owned(),
                object_version_id: "bad\nversion".to_owned(),
                checksum_sha256: vec![0; 32],
            },
        ];
        for row in invalid_rows {
            assert_eq!(
                row.decode().expect_err("invalid row must fail").kind(),
                DlxLifecycleErrorKind::Invariant
            );
        }
    }

    #[test]
    #[allow(clippy::expect_used)] // reason: fixed-width decoder fixtures assert exact outcomes.
    fn scalar_database_decoders_are_closed_and_width_checked() {
        assert_eq!(
            receipt_outcome(1).expect("applied"),
            ReceiptCasOutcome::Applied
        );
        assert_eq!(
            receipt_outcome(0).expect("already applied"),
            ReceiptCasOutcome::AlreadyApplied
        );
        for invalid in [-1, 2, i64::MAX] {
            assert_eq!(
                receipt_outcome(invalid)
                    .expect_err("invalid CAS result")
                    .kind(),
                DlxLifecycleErrorKind::Invariant
            );
        }
        assert!(parse_tenant(TENANT_ID, DlxLifecycleOperation::DecodeArchiveCandidate).is_ok());
        assert_eq!(
            parse_tenant("invalid", DlxLifecycleOperation::DecodeArchiveCandidate)
                .expect_err("invalid tenant")
                .kind(),
            DlxLifecycleErrorKind::Invariant
        );
        assert_eq!(
            checksum_from_db(vec![1; 32]).expect("checksum").as_bytes(),
            &[1; 32]
        );
        assert_eq!(
            checksum_from_db(vec![1; 31])
                .expect_err("checksum length")
                .kind(),
            DlxLifecycleErrorKind::Invariant
        );
        assert_eq!(
            metadata_digest_from_db(vec![2; 32])
                .expect("metadata digest")
                .as_bytes(),
            &[2; 32]
        );
        assert_eq!(
            metadata_digest_from_db(vec![2; 33])
                .expect_err("digest length")
                .kind(),
            DlxLifecycleErrorKind::Invariant
        );
    }

    #[allow(clippy::expect_used)] // reason: the helper builds one known-valid encrypted fixture.
    async fn candidate_row(
        protector: &DlxPayloadProtector,
        source_kind: &str,
    ) -> ArchiveCandidateRow {
        let context = DlxPayloadContext::new(
            tenant(),
            source_kind,
            "identity",
            Some("audit"),
            "identity.session-created.v1",
            "identity.session.created",
            Some("audit.projector"),
            "message-17",
        );
        let protected = protector
            .encrypt(
                context,
                b"capsule-payload",
                &serde_json::json!({"attempt": 7, "correlation": "corr-17"}),
            )
            .await
            .expect("protect candidate");
        ArchiveCandidateRow {
            tenant_id: TENANT_ID.to_owned(),
            dead_letter_id: DEAD_LETTER_ID.to_owned(),
            message_id: "message-17".to_owned(),
            producer_domain: "identity".to_owned(),
            consumer_domain: Some("audit".to_owned()),
            contract_id: "identity.session-created.v1".to_owned(),
            topic: "identity.session.created".to_owned(),
            consumer_group: Some("audit.projector".to_owned()),
            source_kind: source_kind.to_owned(),
            error_summary: "retry budget exhausted".to_owned(),
            num_attempts: 10,
            first_attempt_epoch_micros: 1_700_000_000_123_456,
            last_attempt_epoch_micros: 1_700_000_100_654_321,
            replay_capsule: protected.replay_capsule().clone(),
            replay_capsule_key_ref: protected.key_ref().to_owned(),
            replay_capsule_encoding: DLX_REPLAY_CAPSULE_ENCODING.to_owned(),
            payload_len: protected.payload_len(),
            metadata_digest: protected.metadata_digest().to_vec(),
            archive_claim_token: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".to_owned(),
            archive_lease_until_epoch_micros: 1_800_000_000_000_000,
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: fixed crypto fixtures must fail at the asserted boundary.
    async fn candidate_decoder_authenticates_capsule_and_all_safe_columns() {
        let protector = test_protector();
        let repository = repository(lazy_pool(), protector.clone());
        let valid = candidate_row(&protector, DeadLetterSource::Consumer.as_str()).await;
        let candidate = repository
            .decode_candidate(valid.clone())
            .await
            .expect("valid candidate");
        assert_eq!(
            candidate.canonical().dead_letter_id().as_str(),
            DEAD_LETTER_ID
        );
        assert_eq!(candidate.canonical().tenant(), tenant());
        assert_eq!(
            candidate.canonical().safe_metadata().message_id(),
            "message-17"
        );
        assert_eq!(candidate.canonical().safe_metadata().payload_len(), 15);

        let mut invalid_encoding = valid.clone();
        invalid_encoding.replay_capsule_encoding = "unknown-provider".to_owned();
        let mut invalid_tenant = valid.clone();
        invalid_tenant.tenant_id = "not-a-tenant".to_owned();
        let mut invalid_id = valid.clone();
        invalid_id.dead_letter_id = "not-an-id".to_owned();
        let mut aad_tampered = valid.clone();
        aad_tampered.topic = "identity.session.tampered".to_owned();
        let mut invalid_payload_len = valid.clone();
        invalid_payload_len.payload_len += 1;
        let mut invalid_digest = valid.clone();
        invalid_digest.metadata_digest = vec![0; 32];
        let mut negative_attempts = valid.clone();
        negative_attempts.num_attempts = -1;
        let mut invalid_times = valid;
        invalid_times.first_attempt_epoch_micros = 0;

        for row in [
            invalid_encoding,
            invalid_tenant,
            invalid_id,
            aad_tampered,
            invalid_payload_len,
            invalid_digest,
            negative_attempts,
            invalid_times,
        ] {
            assert_eq!(
                repository
                    .decode_candidate(row)
                    .await
                    .expect_err("untrusted candidate must fail")
                    .kind(),
                DlxLifecycleErrorKind::Invariant
            );
        }

        let unknown_source = candidate_row(&protector, "unknown-source").await;
        assert_eq!(
            repository
                .decode_candidate(unknown_source)
                .await
                .expect_err("unknown source")
                .kind(),
            DlxLifecycleErrorKind::Invariant
        );
        let outbox_with_consumer =
            candidate_row(&protector, DeadLetterSource::OutboxRelay.as_str()).await;
        assert_eq!(
            repository
                .decode_candidate(outbox_with_consumer)
                .await
                .expect_err("invalid source/consumer shape")
                .kind(),
            DlxLifecycleErrorKind::Invariant
        );
    }

    #[derive(Debug)]
    struct FakeDatabaseError {
        code: &'static str,
    }

    impl fmt::Display for FakeDatabaseError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("fake database error")
        }
    }

    impl std::error::Error for FakeDatabaseError {}

    impl DatabaseError for FakeDatabaseError {
        fn message(&self) -> &str {
            "fake database error"
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
    fn provider_and_database_errors_have_closed_retry_classification() {
        assert_eq!(
            transient_db(DlxLifecycleOperation::ArchiveBacklog)(sqlx::Error::PoolClosed).kind(),
            DlxLifecycleErrorKind::Transient
        );
        assert_eq!(
            invariant_or_transient_db(DlxLifecycleOperation::RecordArchiveReceipt)(
                sqlx::Error::PoolClosed,
            )
            .kind(),
            DlxLifecycleErrorKind::Transient
        );
        assert_eq!(
            invariant_or_transient_db(DlxLifecycleOperation::RecordArchiveReceipt)(
                sqlx::Error::Database(Box::new(FakeDatabaseError { code: "P0001" })),
            )
            .kind(),
            DlxLifecycleErrorKind::Invariant
        );
        assert_eq!(
            invariant_or_transient_db(DlxLifecycleOperation::RecordArchiveReceipt)(
                sqlx::Error::Database(Box::new(FakeDatabaseError { code: "23505" })),
            )
            .kind(),
            DlxLifecycleErrorKind::Transient
        );

        for kind in [
            KeyProviderErrorKind::Unavailable,
            KeyProviderErrorKind::Timeout,
        ] {
            let error = KeyProviderError::new(kind, std::io::Error::other("test"));
            assert_eq!(
                key_provider_error(DlxLifecycleOperation::DecodeArchiveCandidate, error).kind(),
                DlxLifecycleErrorKind::Transient
            );
        }
        for kind in [
            KeyProviderErrorKind::NotFound,
            KeyProviderErrorKind::Forbidden,
            KeyProviderErrorKind::Rejected,
        ] {
            let error = KeyProviderError::new(kind, std::io::Error::other("test"));
            assert_eq!(
                key_provider_error(DlxLifecycleOperation::DecodeArchiveCandidate, error).kind(),
                DlxLifecycleErrorKind::Invariant
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: shutdown of an in-memory fixture is infallible by contract.
    async fn runtime_projection_shutdown_and_no_arg_queries_fail_closed_without_database() {
        let archiver_pool = lazy_pool();
        let verifier_pool = lazy_pool();
        let purger_pool = lazy_pool();
        let runtime = PgDlxLifecycleRuntime {
            archiver_pool,
            verifier_pool,
            purger_pool,
            payload_protector: test_protector(),
        };
        assert_eq!(runtime.name(), "postgres-dlx-lifecycle");
        let repository = runtime.repository();
        runtime.shutdown().await.expect("shutdown");
        assert!(repository.archiver_pool.is_closed());
        assert!(repository.verifier_pool.is_closed());
        assert!(repository.purger_pool.is_closed());

        assert_eq!(
            repository
                .archive_backlog()
                .await
                .expect_err("closed pool")
                .kind(),
            DlxLifecycleErrorKind::Transient
        );
        assert_eq!(
            repository
                .claim_archive_candidates()
                .await
                .expect_err("closed pool")
                .kind(),
            DlxLifecycleErrorKind::Transient
        );
        assert_eq!(
            repository
                .purge_verified()
                .await
                .expect_err("closed pool")
                .kind(),
            DlxLifecycleErrorKind::Transient
        );
        assert_eq!(
            repository
                .claim_expired_receipts()
                .await
                .expect_err("closed pool")
                .kind(),
            DlxLifecycleErrorKind::Transient
        );
        assert!(matches!(
            verify_dlx_capability(
                &repository.archiver_pool,
                EXPECTED_DLX_ARCHIVER_ROLE,
                ARCHIVER_FUNCTIONS,
            )
            .await,
            Err(PgError::DlxLifecycleCapability(_))
        ));

        let invalid = PgConfig::new(
            "",
            5432,
            "rss",
            "rss_dlx_archiver",
            PgPassword::new("unused"),
        );
        assert!(matches!(
            PgDlxLifecycleRuntime::setup(&invalid, &invalid, &invalid, test_protector()).await,
            Err(PgError::EmptyHost)
        ));
    }

    #[allow(clippy::expect_used)] // reason: compile-time fixed lifecycle fixture is known-valid.
    fn lifecycle_candidate() -> DlxArchiveCandidate {
        let safe = DlxArchiveSafeMetadata::try_new(DlxArchiveSafeMetadataInput {
            message_id: "message-17".to_owned(),
            producer_domain: "identity".to_owned(),
            consumer_domain: Some("audit".to_owned()),
            contract_id: "identity.session-created.v1".to_owned(),
            topic: "identity.session.created".to_owned(),
            consumer_group: Some("audit.projector".to_owned()),
            source_kind: DeadLetterSource::Consumer,
            error_summary: "retry budget exhausted".to_owned(),
            num_attempts: 10,
            first_attempt_epoch_micros: 1_700_000_000_123_456,
            last_attempt_epoch_micros: 1_700_000_100_654_321,
            payload_len: 15,
            metadata_digest: DlxMetadataDigest::from_sha256_bytes([0xAB; 32]),
        })
        .expect("valid safe metadata");
        DlxArchiveCandidate::try_new(
            dead_letter_id(),
            tenant(),
            safe,
            Plaintext::new(b"capsule-payload".to_vec()),
        )
        .expect("candidate stays below frozen archiveability limit")
    }

    struct ForwardingRepository {
        inner: PgDlxLifecycleRepository,
        candidates:
            Mutex<Option<Vec<ClaimedArchiveCandidate<PgDlxArchiveClaim, DlxArchiveCandidate>>>>,
        expired: Mutex<Option<Vec<ExpiredArchiveReceipt>>>,
    }

    impl ForwardingRepository {
        fn new(
            inner: PgDlxLifecycleRepository,
            candidates: Vec<DlxArchiveCandidate>,
            expired: Vec<ExpiredArchiveReceipt>,
        ) -> Self {
            let candidates = candidates
                .into_iter()
                .map(|candidate| ClaimedArchiveCandidate::new(test_claim(), candidate))
                .collect();
            Self {
                inner,
                candidates: Mutex::new(Some(candidates)),
                expired: Mutex::new(Some(expired)),
            }
        }
    }

    impl DlxLifecycleRepository for ForwardingRepository {
        type ArchiveClaim = PgDlxArchiveClaim;
        type ArchiveCandidate = DlxArchiveCandidate;
        type VerifiedReceipt = VerifiedArchiveReceipt;
        type ExpiredReceipt = ExpiredArchiveReceipt;
        type MissingProof = MissingArchiveProof;

        async fn archive_backlog(&self) -> Result<DlxArchiveBacklog, DlxLifecycleError> {
            Ok(DlxArchiveBacklog::new(0, 0))
        }

        async fn claim_archive_candidates(
            &self,
        ) -> Result<
            Vec<ClaimedArchiveCandidate<PgDlxArchiveClaim, DlxArchiveCandidate>>,
            DlxLifecycleError,
        > {
            let mut candidates = self.candidates.lock().map_err(|_| {
                DlxLifecycleError::new(
                    DlxLifecycleOperation::ClaimArchiveCandidates,
                    DlxLifecycleReason::InternalInvariant,
                )
            })?;
            Ok(candidates.take().unwrap_or_default())
        }

        async fn record_verified_receipt(
            &self,
            claim: &PgDlxArchiveClaim,
            receipt: VerifiedArchiveReceipt,
        ) -> Result<ReceiptCasOutcome, DlxLifecycleError> {
            self.inner.record_verified_receipt(claim, receipt).await
        }

        async fn settle_archive_failure(
            &self,
            claim: PgDlxArchiveClaim,
            failure: DlxLifecycleError,
        ) -> Result<ArchiveClaimSettleOutcome, DlxLifecycleError> {
            self.inner.settle_archive_failure(claim, failure).await
        }

        async fn purge_verified(&self) -> Result<u64, DlxLifecycleError> {
            self.inner.purge_verified().await
        }

        async fn claim_expired_receipts(
            &self,
        ) -> Result<Vec<ExpiredArchiveReceipt>, DlxLifecycleError> {
            let mut expired = self.expired.lock().map_err(|_| {
                DlxLifecycleError::new(
                    DlxLifecycleOperation::ClaimExpiredReceipts,
                    DlxLifecycleReason::InternalInvariant,
                )
            })?;
            Ok(expired.take().unwrap_or_default())
        }

        async fn delete_expired_receipt(
            &self,
            proof: MissingArchiveProof,
        ) -> Result<ReceiptCasOutcome, DlxLifecycleError> {
            self.inner.delete_expired_receipt(proof).await
        }
    }

    fn test_claim() -> PgDlxArchiveClaim {
        PgDlxArchiveClaim {
            tenant_id: TENANT_ID.to_owned(),
            dead_letter_id: DEAD_LETTER_ID.to_owned(),
            claim_token: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".to_owned(),
            _lease_until_epoch_micros: 1_800_000_000_000_000,
        }
    }

    struct CreatedThenMissingStore;

    impl DlxArchiveStore for CreatedThenMissingStore {
        type ObjectKey = DlxArchiveObjectKey;

        async fn put_if_absent(
            &self,
            request: DlxArchivePutRequest<Self::ObjectKey>,
        ) -> Result<DlxArchivePutOutcome, DlxLifecycleError> {
            Ok(DlxArchivePutOutcome::Created(
                DlxArchiveObjectMetadata::new(
                    request.checksum(),
                    ArchiveVersionId::try_from_provider("version-1")?,
                    NOW + 31 * 86_400,
                ),
            ))
        }

        async fn get_ciphertext(
            &self,
            _key: &DlxArchiveObjectKey,
            _version_id: &ArchiveVersionId,
        ) -> Result<Option<DlxArchiveCiphertext>, DlxLifecycleError> {
            Ok(None)
        }

        async fn head(
            &self,
            _key: &DlxArchiveObjectKey,
            _version_id: &ArchiveVersionId,
        ) -> Result<DlxArchiveHeadOutcome, DlxLifecycleError> {
            Ok(DlxArchiveHeadOutcome::Missing)
        }
    }

    async fn closed_repository() -> PgDlxLifecycleRepository {
        let pool = lazy_pool();
        pool.close().await;
        repository(pool, test_protector())
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: fixed private-proof fixture asserts bound SQL routing.
    async fn private_receipt_and_missing_proof_drive_bound_sql_failures() {
        let record_repository = ForwardingRepository::new(
            closed_repository().await,
            vec![lifecycle_candidate()],
            Vec::new(),
        );
        let lifecycle = DlxLifecycle::new(
            record_repository,
            CreatedThenMissingStore,
            TestKeyProvider,
            archive_key(),
        );
        assert_eq!(
            lifecycle.tick(NOW).await.health(),
            DlxLifecycleHealth::Degraded
        );

        let id = dead_letter_id();
        let key = DlxArchiveObjectKey::from_dead_letter(&id);
        let expired = ExpiredArchiveReceipt::from_persisted(
            id,
            tenant(),
            key.as_str(),
            ArchiveChecksum::from_sha256_bytes([0xCD; 32]),
            ArchiveVersionId::try_from_provider("version-1")
                .expect("valid provider version fixture"),
        )
        .expect("valid expired receipt");
        let delete_repository =
            ForwardingRepository::new(closed_repository().await, Vec::new(), vec![expired]);
        let lifecycle = DlxLifecycle::new(
            delete_repository,
            CreatedThenMissingStore,
            TestKeyProvider,
            archive_key(),
        );
        assert_eq!(
            lifecycle.tick(NOW).await.health(),
            DlxLifecycleHealth::Degraded
        );
    }
}
