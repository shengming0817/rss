//! PostgreSQL credential-security lifecycle.
//!
//! A sealed identity command is lowered once into exact CAS rows, then the projection and the
//! generated `identity.security-event` OutboxFact are committed through the sole producer
//! transaction funnel. This lifecycle deliberately has no retry entry: a stale snapshot or an
//! unknown commit acknowledgement requires the caller to observe state and construct a new
//! command.
//!
//! INVARIANT: IDENTITY-SECURITY-COTX-01 { level = "Hard", exec = "native-compile", source = "code", native = "sealed command plus ProducerFactAuthorization and one producer_tx" }.
//! INVARIANT: IDENTITY-SECURITY-LOCK-ORDER-01 { level = "Medium", exec = "manual/opt-in", source = "code" }.
//!
//! ref: launchbadge/sqlx sqlx-core/src/transaction.rs@main
//! ref: ory/fosite handler/oauth2/flow_refresh.go@master

use authn::{
    AuthGrant, AuthGrantCloseMutation, AuthGrantId, AuthGrantStatus, CredentialSecurityEventKind,
    GrantSecurityEventKind,
};
use identity::ports::{
    AccountReactivationLifecycle, AccountSecurityMutation, AccountSecurityState, Credential,
    CredentialSecurityCommand, CredentialSecurityEmissionParts, CredentialSecurityEvent,
    CredentialSecurityReceipt, IdentityError, IdentitySecurityLifecycle,
    PendingCredentialSecurityCommit, PendingRefreshRotationCommit, RefreshExecutionCommand,
    RefreshExecutionOutcome, RefreshRotation, RefreshStatus, RefreshTokenRecord,
    SECURITY_EVENT_CONTRACT, SECURITY_EVENT_FACT, TenantRepoScope,
};
use sqlx::Row;

use crate::account_security_repo::status_to_db;
use crate::auth_grant_lifecycle::{GrantCloseCas, apply_grant_close_cas};
use crate::cotx::identity::IdentityTx;
use crate::cotx::{ProducerFactAuthorization, ProducerTxOutcome, ServingWriteLane, TenantDb};
use crate::outbox::{OutboxEnvelope, metadata_with_ambient};
use crate::pool::VerifiedPgWriteStore;
use crate::projection_events::ProjectionWriteRegistry;

/// Durable provider for the active credential-security event protocol.
pub struct PgIdentitySecurityLifecycle {
    write_pool: TenantDb<ServingWriteLane>,
    pseudonym_keys: std::sync::Arc<secure::PseudonymKeyRing>,
    #[cfg(all(test, feature = "integration"))]
    fault: Option<IdentitySecurityFault>,
    #[cfg(any(
        all(test, feature = "integration"),
        feature = "journey-fault-support",
        feature = "test-support"
    ))]
    start_barrier: Option<std::sync::Arc<IdentitySecurityStartBarrier>>,
}

/// Narrow PostgreSQL account-reactivation writer.
///
/// This type intentionally does not implement [`IdentitySecurityLifecycle`]: production
/// composition can obtain the refresh/security writer only from the single AuthGrant provider,
/// while account reactivation receives only its plain-write capability.
pub struct PgAccountReactivationLifecycle {
    write_pool: TenantDb<ServingWriteLane>,
}

impl PgAccountReactivationLifecycle {
    pub(crate) fn new(
        writer: &VerifiedPgWriteStore,
        projection_registry: ProjectionWriteRegistry,
    ) -> Self {
        Self {
            write_pool: TenantDb::<ServingWriteLane>::with_projection_registry(
                writer,
                projection_registry,
            ),
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn from_unverified_for_test(store: &crate::PgStore) -> Self {
        Self {
            write_pool: TenantDb::<ServingWriteLane>::from_unverified_for_test(store),
        }
    }
}

#[cfg(any(
    all(test, feature = "integration"),
    feature = "journey-fault-support",
    feature = "test-support"
))]
struct IdentitySecurityStartBarrier {
    barrier: std::sync::Arc<tokio::sync::Barrier>,
    remaining: std::sync::atomic::AtomicU8,
}

#[cfg(any(
    all(test, feature = "integration"),
    feature = "journey-fault-support",
    feature = "test-support"
))]
impl IdentitySecurityStartBarrier {
    fn two_requests(barrier: std::sync::Arc<tokio::sync::Barrier>) -> Self {
        Self {
            barrier,
            remaining: std::sync::atomic::AtomicU8::new(2),
        }
    }

    async fn wait_once(&self) {
        if self
            .remaining
            .fetch_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |remaining| remaining.checked_sub(1),
            )
            .is_ok()
        {
            self.barrier.wait().await;
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum IdentitySecurityFault {
    AfterCredential,
    AfterAccount,
    AfterFamily,
    AfterGrant,
    AfterProjection,
    OutboxAppend,
    AfterOutboxBeforeCommit,
    CommitUnknown,
}

impl PgIdentitySecurityLifecycle {
    pub(crate) fn new(
        writer: &VerifiedPgWriteStore,
        projection_registry: ProjectionWriteRegistry,
        pseudonym_keys: std::sync::Arc<secure::PseudonymKeyRing>,
    ) -> Self {
        Self {
            write_pool: TenantDb::<ServingWriteLane>::with_projection_registry(
                writer,
                projection_registry,
            ),
            pseudonym_keys,
            #[cfg(all(test, feature = "integration"))]
            fault: None,
            #[cfg(any(
                all(test, feature = "integration"),
                feature = "journey-fault-support",
                feature = "test-support"
            ))]
            start_barrier: None,
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn from_unverified_for_test(store: &crate::PgStore) -> Self {
        Self {
            write_pool: TenantDb::<ServingWriteLane>::from_unverified_for_test(store),
            pseudonym_keys: test_pseudonym_keys(),
            fault: None,
            start_barrier: None,
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn with_fault(mut self, fault: IdentitySecurityFault) -> Self {
        self.fault = Some(fault);
        self
    }

    #[cfg(any(
        all(test, feature = "integration"),
        feature = "journey-fault-support",
        feature = "test-support"
    ))]
    pub(crate) fn with_start_barrier(
        mut self,
        barrier: std::sync::Arc<tokio::sync::Barrier>,
    ) -> Self {
        self.start_barrier = Some(std::sync::Arc::new(
            IdentitySecurityStartBarrier::two_requests(barrier),
        ));
        self
    }
}

#[cfg(all(test, feature = "integration"))]
fn test_pseudonym_keys() -> std::sync::Arc<secure::PseudonymKeyRing> {
    use std::num::NonZeroU16;

    let key_id = secure::PseudonymKeyId::new(NonZeroU16::MIN);
    let key = match secure::RedactionHashKey::from_bytes(vec![0x42; 32]) {
        Ok(key) => key,
        Err(error) => unreachable!("fixed integration pseudonym key is valid: {error}"),
    };
    let ring = match secure::PseudonymKeyRing::new(
        secure::VersionedPseudonymKey::new(key_id, key),
        Vec::new(),
    ) {
        Ok(ring) => ring,
        Err(error) => unreachable!("single integration pseudonym key is valid: {error}"),
    };
    std::sync::Arc::new(ring)
}

impl IdentitySecurityLifecycle for PgIdentitySecurityLifecycle {
    async fn execute_refresh(
        &self,
        receipt: identity::ports::RefreshProducerReceipt,
        scope: TenantRepoScope,
        command: RefreshExecutionCommand,
    ) -> Result<RefreshExecutionOutcome, IdentityError> {
        let emission =
            identity::ports::refresh_execution_emission(command, &self.pseudonym_keys).await?;
        let authorization = receipt
            .authorize(SECURITY_EVENT_FACT, SECURITY_EVENT_CONTRACT)
            .ok_or_else(|| corrupt("refresh receipt does not authorize security-event"))?;
        let (command, reviewed) = emission.into_parts();
        let (entry, envelope_parts, _occurred_at, _fact) = reviewed.into_parts();
        let (source, rotation, event, pending) = command.into_parts();
        validate_refresh_command(scope, &source, rotation.as_ref(), &event)?;
        let envelope = security_envelope(scope, &event, envelope_parts)?;
        #[cfg(all(test, feature = "integration"))]
        let fault = self.fault;
        #[cfg(not(all(test, feature = "integration")))]
        let fault = None;
        #[cfg(any(
            all(test, feature = "integration"),
            feature = "journey-fault-support",
            feature = "test-support"
        ))]
        let start_barrier = self.start_barrier.clone();

        metrics::counter!("identity_refresh_producer_attempt_total").increment(1);
        let (outcome, acknowledgement) = self
            .write_pool
            .identity_producer_tx(
                scope,
                &entry,
                &envelope,
                move |mut tx| {
                    Box::pin(async move {
                        #[cfg(any(
                            all(test, feature = "integration"),
                            feature = "journey-fault-support",
                            feature = "test-support"
                        ))]
                        if let Some(start_barrier) = start_barrier {
                            start_barrier.wait_once().await;
                        }
                        let result = apply_refresh_execution(
                            &mut tx,
                            &source,
                            rotation.as_ref(),
                            &event,
                            fault,
                        )
                        .await?;
                        #[cfg(all(test, feature = "integration"))]
                        let emitted = matches!(result, RefreshMutationResult::ReuseContained(_));
                        #[cfg(all(test, feature = "integration"))]
                        if emitted && matches!(fault, Some(IdentitySecurityFault::AfterProjection))
                        {
                            tx.inject_failure_after_projection_append()
                                .await
                                .map_err(storage)?;
                        }
                        #[cfg(all(test, feature = "integration"))]
                        if emitted && matches!(fault, Some(IdentitySecurityFault::OutboxAppend)) {
                            tx.identity()
                                .force_identity_outbox_failure(
                                    crate::cotx::identity::IdentityOutboxFault::RefreshSecurity,
                                )
                                .await
                                .map_err(storage)?;
                        }
                        #[cfg(all(test, feature = "integration"))]
                        if emitted
                            && matches!(fault, Some(IdentitySecurityFault::AfterOutboxBeforeCommit))
                        {
                            tx.inject_failure_after_outbox_append_before_commit()
                                .await
                                .map_err(storage)?;
                        }
                        #[cfg(all(test, feature = "integration"))]
                        if matches!(fault, Some(IdentitySecurityFault::CommitUnknown)) {
                            tx.inject_commit_unknown_after_commit()
                                .await
                                .map_err(storage)?;
                        }
                        Ok(match result {
                            RefreshMutationResult::ReuseContained(durable_mutations) => {
                                ProducerTxOutcome::Emitted(
                                    PendingRefreshOutcome::ReuseContained(durable_mutations),
                                    authorization,
                                )
                            }
                            RefreshMutationResult::Applied => {
                                ProducerTxOutcome::MutatedWithoutFact(
                                    PendingRefreshOutcome::Applied(pending, 2),
                                )
                            }
                            RefreshMutationResult::AlreadyContained(durable_mutations) => {
                                ProducerTxOutcome::MutatedWithoutFact(
                                    PendingRefreshOutcome::AlreadyContained(durable_mutations),
                                )
                            }
                            RefreshMutationResult::Stale => {
                                ProducerTxOutcome::MutatedWithoutFact(PendingRefreshOutcome::Stale)
                            }
                            RefreshMutationResult::Expired => {
                                ProducerTxOutcome::MutatedWithoutFact(
                                    PendingRefreshOutcome::Expired,
                                )
                            }
                        })
                    })
                },
                storage,
            )
            .await
            .into_refresh_commit_result()?;
        metrics::counter!("identity_refresh_producer_commit_total").increment(1);
        Ok(outcome.confirm(acknowledgement))
    }

    async fn execute_password_change(
        &self,
        receipt: identity::ports::PasswordChangeProducerReceipt,
        scope: TenantRepoScope,
        command: identity::ports::PasswordChangeCommand,
    ) -> Result<CredentialSecurityReceipt, IdentityError> {
        let emission =
            identity::ports::password_change_emission(command, &self.pseudonym_keys).await?;
        let authorization = receipt
            .authorize(SECURITY_EVENT_FACT, SECURITY_EVENT_CONTRACT)
            .ok_or_else(|| corrupt("password-change receipt does not authorize security-event"))?;
        let (command, reviewed) = emission.into_parts();
        let (entry, envelope_parts, _occurred_at, _fact) = reviewed.into_parts();
        let (expected, next, security) = command.into_parts();
        let (mutation, event, pending) = security.into_parts();
        let prepared = PreparedSecurityCommand {
            entry,
            envelope_parts,
            mutation: SecurityMutation::Password {
                credential: CredentialCasRow::try_from((&expected, &next, &event))?,
                account: AccountSecurityRow::try_from((mutation, &event))?,
            },
            event,
            pending,
        };
        self.execute_prepared(authorization, scope, prepared).await
    }

    async fn execute_account_status_set(
        &self,
        receipt: identity::ports::AccountStatusSetProducerReceipt,
        scope: TenantRepoScope,
        command: identity::ports::AccountStatusSetCommand,
    ) -> Result<CredentialSecurityReceipt, IdentityError> {
        let emission =
            identity::ports::account_status_set_emission(command, &self.pseudonym_keys).await?;
        let authorization = receipt
            .authorize(SECURITY_EVENT_FACT, SECURITY_EVENT_CONTRACT)
            .ok_or_else(|| {
                corrupt("account restriction receipt does not authorize security-event")
            })?;
        let prepared = PreparedSecurityCommand::try_from(emission.into_parts())?;
        self.execute_prepared(authorization, scope, prepared).await
    }

    async fn execute_logout_current(
        &self,
        receipt: identity::ports::LogoutCurrentProducerReceipt,
        scope: TenantRepoScope,
        command: identity::ports::LogoutCurrentCommand,
    ) -> Result<CredentialSecurityReceipt, IdentityError> {
        let emission =
            identity::ports::logout_current_emission(command, &self.pseudonym_keys).await?;
        let authorization = receipt
            .authorize(SECURITY_EVENT_FACT, SECURITY_EVENT_CONTRACT)
            .ok_or_else(|| corrupt("logout-current receipt does not authorize security-event"))?;
        let prepared = PreparedSecurityCommand::try_from(emission.into_parts())?;
        self.execute_prepared(authorization, scope, prepared).await
    }

    async fn execute_logout_all(
        &self,
        receipt: identity::ports::LogoutAllProducerReceipt,
        scope: TenantRepoScope,
        command: identity::ports::LogoutAllCommand,
    ) -> Result<CredentialSecurityReceipt, IdentityError> {
        let emission = identity::ports::logout_all_emission(command, &self.pseudonym_keys).await?;
        let authorization = receipt
            .authorize(SECURITY_EVENT_FACT, SECURITY_EVENT_CONTRACT)
            .ok_or_else(|| corrupt("logout-all receipt does not authorize security-event"))?;
        let prepared = PreparedSecurityCommand::try_from(emission.into_parts())?;
        self.execute_prepared(authorization, scope, prepared).await
    }
}

impl AccountReactivationLifecycle for PgAccountReactivationLifecycle {
    async fn execute_reactivation(
        &self,
        scope: TenantRepoScope,
        command: identity::ports::ReactivateAccountCommand,
    ) -> Result<AccountSecurityState, IdentityError> {
        let (expected, next) = command.into_mutation().into_parts();
        let row = AccountStateCasRow::from_states(expected, next.clone())?;
        self.write_pool
            .identity_write(
                scope,
                move |mut tx| Box::pin(async move { apply_account_state_cas(&mut tx, &row).await }),
                storage,
            )
            .await?;
        Ok(next)
    }
}

#[cfg(all(test, feature = "integration"))]
impl PgIdentitySecurityLifecycle {
    pub(crate) async fn execute_test_command(
        &self,
        scope: TenantRepoScope,
        command: CredentialSecurityCommand,
    ) -> Result<CredentialSecurityReceipt, IdentityError> {
        let prepared = PreparedSecurityCommand::try_from(
            identity::ports::credential_security_emission_for_test(command, &self.pseudonym_keys)
                .await?,
        )?;
        let authorization = crate::cotx::IntegrationCredentialSecurityAuthorization::new();
        self.execute_prepared(authorization, scope, prepared).await
    }
}

impl PgIdentitySecurityLifecycle {
    async fn execute_prepared<A>(
        &self,
        authorization: A,
        scope: TenantRepoScope,
        prepared: PreparedSecurityCommand,
    ) -> Result<CredentialSecurityReceipt, IdentityError>
    where
        A: ProducerFactAuthorization,
    {
        let PreparedSecurityCommand {
            entry,
            envelope_parts,
            mutation,
            event,
            pending,
        } = prepared;
        if scope.tenant() != event.tenant() {
            return Err(corrupt("credential security tenant scope mismatch"));
        }
        let (contract, envelope_tenant, subject_id, actor, partition_key, causation_id) =
            envelope_parts.into_parts();
        if envelope_tenant != scope.tenant() {
            return Err(corrupt("credential security envelope tenant mismatch"));
        }
        let envelope = OutboxEnvelope::new(
            contract.domain().to_owned(),
            contract.contract_id().to_owned(),
            metadata_with_ambient(
                rss_contract::Timepoint::saturating_from_system_time(event.occurred_at())
                    .unix_seconds(),
                event.tenant(),
                contract,
            )
            .with_subject_id(subject_id)
            .with_actor(actor),
        )
        .with_partition_key_opt(partition_key)
        .with_causation_id_opt(causation_id);
        #[cfg(all(test, feature = "integration"))]
        let fault = self.fault;
        #[cfg(not(all(test, feature = "integration")))]
        let fault = None;
        #[cfg(any(
            all(test, feature = "integration"),
            feature = "journey-fault-support",
            feature = "test-support"
        ))]
        let start_barrier = self.start_barrier.clone();

        self.write_pool
            .identity_producer_tx(
                scope,
                &entry,
                &envelope,
                move |mut tx| {
                    Box::pin(async move {
                        #[cfg(any(
                            all(test, feature = "integration"),
                            feature = "journey-fault-support",
                            feature = "test-support"
                        ))]
                        if let Some(start_barrier) = start_barrier {
                            start_barrier.wait_once().await;
                        }
                        apply_security_mutation(&mut tx, mutation, fault).await?;
                        #[cfg(all(test, feature = "integration"))]
                        if matches!(fault, Some(IdentitySecurityFault::AfterProjection)) {
                            tx.inject_failure_after_projection_append()
                                .await
                                .map_err(storage)?;
                        }
                        #[cfg(all(test, feature = "integration"))]
                        if matches!(fault, Some(IdentitySecurityFault::OutboxAppend)) {
                            tx.identity()
                                .force_identity_outbox_failure(
                                    crate::cotx::identity::IdentityOutboxFault::CredentialSecurity,
                                )
                                .await
                                .map_err(storage)?;
                        }
                        #[cfg(all(test, feature = "integration"))]
                        if matches!(fault, Some(IdentitySecurityFault::AfterOutboxBeforeCommit)) {
                            tx.inject_failure_after_outbox_append_before_commit()
                                .await
                                .map_err(storage)?;
                        }
                        #[cfg(all(test, feature = "integration"))]
                        if matches!(fault, Some(IdentitySecurityFault::CommitUnknown)) {
                            tx.inject_commit_unknown_after_commit()
                                .await
                                .map_err(storage)?;
                        }
                        Ok(ProducerTxOutcome::Emitted(pending, authorization))
                    })
                },
                storage,
            )
            .await
            .into_result()
            .map(PendingCredentialSecurityCommit::confirm)
    }
}

pub(crate) enum RefreshMutationResult {
    Applied,
    ReuseContained(u64),
    AlreadyContained(u64),
    Stale,
    Expired,
}

enum PendingRefreshOutcome {
    Applied(PendingRefreshRotationCommit, u64),
    ReuseContained(u64),
    AlreadyContained(u64),
    Stale,
    Expired,
}

impl PendingRefreshOutcome {
    fn confirm(
        self,
        acknowledgement: identity::ports::RefreshCommitAcknowledgement,
    ) -> RefreshExecutionOutcome {
        let durable_mutations = match &self {
            Self::Applied(_, durable_mutations)
            | Self::ReuseContained(durable_mutations)
            | Self::AlreadyContained(durable_mutations) => *durable_mutations,
            Self::Stale | Self::Expired => 0,
        };
        metrics::counter!("identity_refresh_durable_mutations_total").increment(durable_mutations);
        match self {
            Self::Applied(pending, _) => {
                RefreshExecutionOutcome::Applied(pending.confirm(acknowledgement))
            }
            Self::ReuseContained(_) => RefreshExecutionOutcome::ReuseContained,
            Self::AlreadyContained(_) => RefreshExecutionOutcome::AlreadyContained,
            Self::Stale => RefreshExecutionOutcome::Stale,
            Self::Expired => RefreshExecutionOutcome::Expired,
        }
    }
}

fn validate_refresh_command(
    scope: TenantRepoScope,
    source: &RefreshTokenRecord,
    rotation: Option<&RefreshRotation>,
    event: &CredentialSecurityEvent,
) -> Result<(), IdentityError> {
    if scope.tenant() != source.tenant()
        || event.tenant() != source.tenant()
        || event.user_id() != source.user_id()
        || event.kind()
            != CredentialSecurityEventKind::Grant(GrantSecurityEventKind::RefreshReuseDetected)
    {
        return Err(corrupt("refresh execution binding mismatch"));
    }
    if let Some(rotation) = rotation {
        let child = rotation.new_record();
        if rotation.old_id() != source.id()
            || child.tenant() != source.tenant()
            || child.auth_grant_id() != source.auth_grant_id()
            || child.user_id() != source.user_id()
            || child.issuance_epoch() != source.issuance_epoch()
            || child.parent_id() != Some(source.id())
            || child.lineage_id() != source.lineage_id()
            || child.status() != RefreshStatus::Active
            || child.auth_grant_status() != AuthGrantStatus::Active
        {
            return Err(corrupt("refresh rotation child binding mismatch"));
        }
    }
    Ok(())
}

fn security_envelope(
    scope: TenantRepoScope,
    event: &CredentialSecurityEvent,
    envelope_parts: diport::OutboxEnvelopeParts,
) -> Result<OutboxEnvelope, IdentityError> {
    let (contract, envelope_tenant, subject_id, actor, partition_key, causation_id) =
        envelope_parts.into_parts();
    if envelope_tenant != scope.tenant() {
        return Err(corrupt("credential security envelope tenant mismatch"));
    }
    Ok(OutboxEnvelope::new(
        contract.domain().to_owned(),
        contract.contract_id().to_owned(),
        metadata_with_ambient(
            rss_contract::Timepoint::saturating_from_system_time(event.occurred_at())
                .unix_seconds(),
            event.tenant(),
            contract,
        )
        .with_subject_id(subject_id)
        .with_actor(actor),
    )
    .with_partition_key_opt(partition_key)
    .with_causation_id_opt(causation_id))
}

pub(crate) struct LockedRefreshRow {
    pub(crate) id: String,
    pub(crate) user: String,
    pub(crate) epoch: i64,
    pub(crate) grant_status: String,
    pub(crate) token_hash: Vec<u8>,
    pub(crate) parent: Option<String>,
    pub(crate) lineage: String,
    pub(crate) status: String,
    pub(crate) issued_at_micros: i64,
    pub(crate) expires_at_micros: i64,
}

impl LockedRefreshRow {
    pub(crate) fn from_row(row: sqlx::postgres::PgRow) -> Result<Self, IdentityError> {
        Ok(Self {
            id: row.try_get("id").map_err(storage)?,
            user: row.try_get("user_id").map_err(storage)?,
            epoch: row.try_get("authn_epoch_at_issue").map_err(storage)?,
            grant_status: row.try_get("auth_grant_status").map_err(storage)?,
            token_hash: row.try_get("token_hash").map_err(storage)?,
            parent: row.try_get("parent_id").map_err(storage)?,
            lineage: row.try_get("lineage_id").map_err(storage)?,
            status: row.try_get("status").map_err(storage)?,
            issued_at_micros: row.try_get("issued_at_micros").map_err(storage)?,
            expires_at_micros: row.try_get("expires_at_micros").map_err(storage)?,
        })
    }

    fn matches_source(&self, source: &RefreshTokenRecord) -> Result<bool, IdentityError> {
        Ok(self.user == source.user_id().as_uuid().to_string()
            && self.epoch == persisted_counter(source.issuance_epoch().get(), "refresh epoch")?
            && self.token_hash.as_slice() == source.token_hash().as_bytes()
            && self.parent.as_deref() == source.parent_id().map(|id| id.as_str())
            && self.lineage == source.lineage_id().as_str()
            && self.issued_at_micros
                == persisted_time_micros(source.issued_at(), "refresh issued_at")?
            && self.expires_at_micros
                == persisted_time_micros(source.expires_at(), "refresh expires_at")?)
    }
}

pub(crate) struct LockedGrantRow {
    pub(crate) user: String,
    pub(crate) epoch: i64,
    pub(crate) status: String,
    pub(crate) expires_at_micros: i64,
}

async fn apply_refresh_execution(
    conn: &mut IdentityTx<'_, '_, ServingWriteLane>,
    source: &RefreshTokenRecord,
    rotation: Option<&RefreshRotation>,
    event: &CredentialSecurityEvent,
    fault: Option<IdentitySecurityFault>,
) -> Result<RefreshMutationResult, IdentityError> {
    let user = source.user_id().as_uuid().to_string();
    let grant_id = source.auth_grant_id();
    let expected_epoch = persisted_counter(source.issuance_epoch().get(), "refresh epoch")?;

    let account = conn
        .identity()
        .lock_refresh_account(&source.user_id())
        .await?;

    let family = conn.identity().lock_refresh_family(grant_id).await?;

    let Some(grant) = conn.identity().lock_refresh_grant(grant_id).await? else {
        return if family.is_empty() {
            Ok(RefreshMutationResult::Stale)
        } else {
            Err(corrupt("refresh family has no AuthGrant root"))
        };
    };
    if grant.user != user || grant.epoch != expected_epoch {
        return Err(corrupt("refresh AuthGrant binding is corrupt"));
    }

    let database_now_micros = conn.identity().database_now_micros().await?;
    let Some(presented) = family.iter().find(|row| row.id == source.id().as_str()) else {
        return Ok(RefreshMutationResult::Stale);
    };
    if !presented.matches_source(source)? {
        return Err(corrupt("refresh source binding is corrupt"));
    }
    if family.iter().any(|row| {
        row.user != user
            || row.epoch != expected_epoch
            || row.lineage != source.lineage_id().as_str()
            || row.grant_status != grant.status
    }) {
        return Err(corrupt("refresh family binding is corrupt"));
    }
    let mut roots = family
        .iter()
        .filter(|row| row.id == row.lineage && row.parent.is_none());
    let lineage_root = roots
        .next()
        .ok_or_else(|| corrupt("refresh family lineage root is missing"))?;
    if roots.next().is_some() {
        return Err(corrupt("refresh family has multiple lineage roots"));
    }

    let authoritative_status = RefreshStatus::from_db_str(&presented.status)
        .ok_or_else(|| corrupt("refresh source status is corrupt"))?;
    if authoritative_status != RefreshStatus::Active {
        return contain_refresh_reuse(
            conn,
            grant_id,
            &grant.status,
            database_now_micros,
            event,
            fault,
        )
        .await;
    }
    let Some(rotation) = rotation else {
        return Ok(RefreshMutationResult::Stale);
    };
    if account
        .as_ref()
        .is_none_or(|(status, epoch)| status != "active" || *epoch != expected_epoch)
        || grant.status != AuthGrantStatus::Active.as_db_str()
        || presented.grant_status != AuthGrantStatus::Active.as_db_str()
    {
        return Ok(RefreshMutationResult::Stale);
    }
    let child = rotation.new_record();
    let child_expires = persisted_time_micros(child.expires_at(), "refresh child expires_at")?;
    if presented.expires_at_micros <= database_now_micros
        || lineage_root.expires_at_micros <= database_now_micros
        || grant.expires_at_micros <= database_now_micros
        || child_expires > lineage_root.expires_at_micros
        || child_expires > grant.expires_at_micros
    {
        return Ok(RefreshMutationResult::Expired);
    }

    let consumed = conn.identity().consume_active_refresh(source.id()).await?;
    if consumed != 1 {
        return Err(corrupt("locked active refresh CAS did not apply"));
    }
    insert_rotated_refresh(conn, child).await?;
    inject_mutation_fault(fault, IdentitySecurityFault::AfterFamily)?;
    Ok(RefreshMutationResult::Applied)
}

async fn contain_refresh_reuse(
    conn: &mut IdentityTx<'_, '_, ServingWriteLane>,
    grant_id: &AuthGrantId,
    grant_status: &str,
    database_now_micros: i64,
    _event: &CredentialSecurityEvent,
    fault: Option<IdentitySecurityFault>,
) -> Result<RefreshMutationResult, IdentityError> {
    if grant_status == AuthGrantStatus::Compromised.as_db_str() {
        let durable_mutations = revoke_exact_refresh_family(conn, grant_id).await?;
        inject_mutation_fault(fault, IdentitySecurityFault::AfterFamily)?;
        return Ok(RefreshMutationResult::AlreadyContained(durable_mutations));
    }
    if grant_status != AuthGrantStatus::Active.as_db_str()
        && grant_status != AuthGrantStatus::Revoked.as_db_str()
    {
        return Err(corrupt("refresh AuthGrant status is corrupt"));
    }
    let family_mutations = revoke_exact_refresh_family(conn, grant_id).await?;
    inject_mutation_fault(fault, IdentitySecurityFault::AfterFamily)?;
    let changed = conn
        .identity()
        .mark_refresh_grant_compromised(grant_id, database_now_micros)
        .await?;
    if changed != 1 {
        return Err(corrupt("locked AuthGrant containment CAS did not apply"));
    }
    inject_mutation_fault(fault, IdentitySecurityFault::AfterGrant)?;
    Ok(RefreshMutationResult::ReuseContained(
        family_mutations + changed,
    ))
}

async fn revoke_exact_refresh_family(
    conn: &mut IdentityTx<'_, '_, ServingWriteLane>,
    grant_id: &AuthGrantId,
) -> Result<u64, IdentityError> {
    conn.identity().revoke_exact_refresh_family(grant_id).await
}

async fn insert_rotated_refresh(
    conn: &mut IdentityTx<'_, '_, ServingWriteLane>,
    record: &RefreshTokenRecord,
) -> Result<(), IdentityError> {
    conn.identity().insert_rotated_refresh(record).await
}

struct PreparedSecurityCommand {
    entry: consistency::EventEntry,
    envelope_parts: diport::OutboxEnvelopeParts,
    mutation: SecurityMutation,
    event: CredentialSecurityEvent,
    pending: PendingCredentialSecurityCommit,
}

impl TryFrom<CredentialSecurityEmissionParts> for PreparedSecurityCommand {
    type Error = IdentityError;

    fn try_from(emission: CredentialSecurityEmissionParts) -> Result<Self, Self::Error> {
        let (command, reviewed) = emission.into_parts();
        let (entry, envelope_parts, _occurred_at, _fact) = reviewed.into_parts();
        match command {
            CredentialSecurityCommand::Account(command) => {
                let (mutation, event, pending) = command.into_parts();
                Ok(Self {
                    entry,
                    envelope_parts,
                    mutation: SecurityMutation::Account(AccountSecurityRow::try_from((
                        mutation, &event,
                    ))?),
                    event,
                    pending,
                })
            }
            CredentialSecurityCommand::Grant(command) => {
                let (mutation, event, pending) = command.into_parts();
                Ok(Self {
                    entry,
                    envelope_parts,
                    mutation: SecurityMutation::Grant(prepare_grant_security(mutation, &event)?),
                    event,
                    pending,
                })
            }
        }
    }
}

pub(crate) enum SecurityMutation {
    Account(AccountSecurityRow),
    Grant(GrantCloseCas),
    Password {
        credential: CredentialCasRow,
        account: AccountSecurityRow,
    },
}

async fn apply_security_mutation(
    conn: &mut IdentityTx<'_, '_, ServingWriteLane>,
    mutation: SecurityMutation,
    fault: Option<IdentitySecurityFault>,
) -> Result<(), IdentityError> {
    match mutation {
        SecurityMutation::Account(row) => apply_account_security(conn, &row, fault).await,
        SecurityMutation::Grant(row) => {
            if apply_grant_close_cas(conn, &row).await.map_err(storage)? {
                Ok(())
            } else {
                Err(IdentityError::VersionConflict)
            }
        }
        SecurityMutation::Password {
            credential,
            account,
        } => {
            apply_credential_cas(conn, &credential).await?;
            inject_mutation_fault(fault, IdentitySecurityFault::AfterCredential)?;
            apply_account_security(conn, &account, fault).await
        }
    }
}

pub(crate) struct CredentialCasRow {
    pub(crate) tenant: rss_request_context::TenantId,
    pub(crate) user: String,
    pub(crate) login: String,
    pub(crate) expected_hash: String,
    pub(crate) expected_version: i64,
    pub(crate) next_hash: String,
    pub(crate) next_version: i64,
}

impl TryFrom<(&Credential, &Credential, &CredentialSecurityEvent)> for CredentialCasRow {
    type Error = IdentityError;

    fn try_from(
        (expected, next, event): (&Credential, &Credential, &CredentialSecurityEvent),
    ) -> Result<Self, Self::Error> {
        if expected.tenant() != event.tenant()
            || next.tenant() != event.tenant()
            || expected.user_id() != event.user_id()
            || next.user_id() != event.user_id()
            || expected.login().as_str() != next.login().as_str()
            || expected.version().checked_add(1) != Some(next.version())
        {
            return Err(corrupt("password credential mutation mismatch"));
        }
        Ok(Self {
            tenant: event.tenant(),
            user: event.user_id().as_uuid().to_string(),
            login: expected.login().as_str().to_owned(),
            expected_hash: expected.password_hash().as_str().to_owned(),
            expected_version: i64::from(expected.version()),
            next_hash: next.password_hash().as_str().to_owned(),
            next_version: i64::from(next.version()),
        })
    }
}

async fn apply_credential_cas(
    conn: &mut IdentityTx<'_, '_, ServingWriteLane>,
    row: &CredentialCasRow,
) -> Result<(), IdentityError> {
    if conn.identity().apply_credential_cas(row).await? {
        Ok(())
    } else {
        Err(IdentityError::VersionConflict)
    }
}

pub(crate) struct AccountSecurityRow {
    pub(crate) state: AccountStateCasRow,
    pub(crate) occurred_at: i64,
    pub(crate) reason: &'static str,
}

pub(crate) struct AccountStateCasRow {
    pub(crate) tenant: rss_request_context::TenantId,
    pub(crate) user: String,
    pub(crate) expected_status: &'static str,
    pub(crate) expected_epoch: i64,
    pub(crate) expected_version: i64,
    pub(crate) expected_status_changed_at_micros: i64,
    pub(crate) expected_updated_at_micros: i64,
    pub(crate) next_status: &'static str,
    pub(crate) next_epoch: i64,
    pub(crate) next_version: i64,
    pub(crate) status_changed_at_micros: i64,
    pub(crate) updated_at_micros: i64,
}

impl TryFrom<(AccountSecurityMutation, &CredentialSecurityEvent)> for AccountSecurityRow {
    type Error = IdentityError;

    fn try_from(
        (mutation, event): (AccountSecurityMutation, &CredentialSecurityEvent),
    ) -> Result<Self, Self::Error> {
        let (expected, next) = mutation.into_parts();
        if expected.tenant() != event.tenant()
            || next.tenant() != event.tenant()
            || expected.user_id() != event.user_id()
            || next.user_id() != event.user_id()
        {
            return Err(corrupt("credential security account mutation mismatch"));
        }
        Ok(Self {
            state: AccountStateCasRow::from_states(expected, next)?,
            occurred_at: rss_contract::Timepoint::saturating_from_system_time(event.occurred_at())
                .unix_seconds(),
            reason: event.kind().as_db_str(),
        })
    }
}

impl AccountStateCasRow {
    fn from_states(
        expected: AccountSecurityState,
        next: AccountSecurityState,
    ) -> Result<Self, IdentityError> {
        if expected.tenant() != next.tenant() || expected.user_id() != next.user_id() {
            return Err(corrupt("account security mutation identity mismatch"));
        }
        Ok(Self {
            tenant: expected.tenant(),
            user: expected.user_id().as_uuid().to_string(),
            expected_status: status_to_db(expected.status()),
            expected_epoch: persisted_counter(expected.authn_epoch().get(), "expected epoch")?,
            expected_version: persisted_counter(expected.version().get(), "expected version")?,
            expected_status_changed_at_micros: persisted_time_micros(
                expected.status_changed_at(),
                "expected status_changed_at",
            )?,
            expected_updated_at_micros: persisted_time_micros(
                expected.updated_at(),
                "expected updated_at",
            )?,
            next_status: status_to_db(next.status()),
            next_epoch: persisted_counter(next.authn_epoch().get(), "next epoch")?,
            next_version: persisted_counter(next.version().get(), "next version")?,
            status_changed_at_micros: persisted_time_micros(
                next.status_changed_at(),
                "next status_changed_at",
            )?,
            updated_at_micros: persisted_time_micros(next.updated_at(), "next updated_at")?,
        })
    }
}

async fn apply_account_security(
    conn: &mut IdentityTx<'_, '_, ServingWriteLane>,
    row: &AccountSecurityRow,
    fault: Option<IdentitySecurityFault>,
) -> Result<(), IdentityError> {
    apply_account_state_cas(conn, &row.state).await?;
    inject_mutation_fault(fault, IdentitySecurityFault::AfterAccount)?;

    revoke_refresh_families(conn, &row.state).await?;
    inject_mutation_fault(fault, IdentitySecurityFault::AfterFamily)?;

    revoke_auth_grants(conn, row).await?;
    inject_mutation_fault(fault, IdentitySecurityFault::AfterGrant)
}

async fn revoke_refresh_families(
    conn: &mut IdentityTx<'_, '_, ServingWriteLane>,
    state: &AccountStateCasRow,
) -> Result<(), IdentityError> {
    conn.identity()
        .revoke_refresh_families_for_account(state)
        .await
}

async fn revoke_auth_grants(
    conn: &mut IdentityTx<'_, '_, ServingWriteLane>,
    row: &AccountSecurityRow,
) -> Result<(), IdentityError> {
    conn.identity().revoke_auth_grants_for_account(row).await
}

fn inject_mutation_fault(
    fault: Option<IdentitySecurityFault>,
    stage: IdentitySecurityFault,
) -> Result<(), IdentityError> {
    if fault == Some(stage) {
        Err(corrupt("injected identity security mutation failure"))
    } else {
        Ok(())
    }
}

async fn apply_account_state_cas(
    conn: &mut IdentityTx<'_, '_, ServingWriteLane>,
    row: &AccountStateCasRow,
) -> Result<(), IdentityError> {
    if !conn.identity().apply_account_state_cas(row).await? {
        return Err(IdentityError::VersionConflict);
    }
    Ok(())
}

fn prepare_grant_security(
    mutation: AuthGrantCloseMutation,
    event: &CredentialSecurityEvent,
) -> Result<GrantCloseCas, IdentityError> {
    let (expected, next) = mutation.into_parts();
    validate_grant_binding(&expected, &next, event)?;
    GrantCloseCas::try_from((&expected, &next))
}

fn validate_grant_binding(
    expected: &AuthGrant,
    next: &AuthGrant,
    event: &CredentialSecurityEvent,
) -> Result<(), IdentityError> {
    if expected.id() != next.id()
        || expected.tenant() != event.tenant()
        || next.tenant() != event.tenant()
        || expected.user_id() != event.user_id()
        || next.user_id() != event.user_id()
        || expected.authn_epoch_at_issue() != next.authn_epoch_at_issue()
        || next.status() == AuthGrantStatus::Active
        || next.close_reason() != Some(event.kind())
    {
        return Err(corrupt("credential security grant mutation mismatch"));
    }
    Ok(())
}

fn persisted_counter(value: u64, field: &'static str) -> Result<i64, IdentityError> {
    i64::try_from(value).map_err(|_| corrupt(field))
}

fn persisted_time_micros(
    value: std::time::SystemTime,
    field: &'static str,
) -> Result<i64, IdentityError> {
    let duration = value
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_err(|_| corrupt(field))?;
    let micros = duration
        .as_secs()
        .checked_mul(1_000_000)
        .and_then(|seconds| seconds.checked_add(u64::from(duration.subsec_micros())))
        .ok_or_else(|| corrupt(field))?;
    i64::try_from(micros).map_err(|_| corrupt(field))
}

fn storage(error: impl std::error::Error + Send + Sync + 'static) -> IdentityError {
    crate::tx_retry::identity_storage_error(error)
}

fn corrupt(message: &'static str) -> IdentityError {
    storage(std::io::Error::other(message))
}
