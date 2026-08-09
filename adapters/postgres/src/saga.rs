//! PostgreSQL implementation of the closed durable Saga writer and recovery boundary.

use std::num::NonZeroUsize;
use std::sync::Arc;

use consistency::{
    LocalTxFinalStatus, SagaAttempt, SagaCompensationCause, SagaDefinitionIdentity,
    SagaEffectPhase, SagaId, SagaIdempotencyKey, SagaInstanceRecord, SagaInstanceRef,
    SagaInstanceStatus, SagaJournalRecord, SagaJournalStatus, SagaLease, SagaLeaseOutcome,
    SagaOperatorReason, SagaReceiptFormatVersion, SagaReceiptScope,
};
use diport::{
    DynKeyProvider, KeyName, KeyProvider, KeyRef, RedactedBytes, SagaClaimOutcome,
    SagaClaimRequest, SagaCompensationProgress, SagaContractId, SagaDurableMutation,
    SagaDurableMutationOutcome, SagaDurableStore, SagaDurableStoreError, SagaDurableStoreErrorKind,
    SagaForwardCompletion, SagaForwardProgress, SagaInstanceRegistration, SagaLeaseHolder,
    SagaLeaseTtl, SagaOperatorAuthorization, SagaOperatorCasOutcome, SagaOperatorClaimOutcome,
    SagaOperatorJournalExpectation, SagaOperatorRepair, SagaOperatorRepairClaim,
    SagaOperatorRepairReason, SagaOperatorStatusOutcome, SagaOperatorStatusSnapshot,
    SagaOperatorStore, SagaRecoveryOutcome, SagaRecoveryRequest, SagaRecoverySnapshot,
    SagaRunnableInstance, SagaStartAuthorization, SagaTenantCursor, SagaTenantPage,
    SagaTenantSource, SagaTerminalReceiptOutcome, SagaTerminalReceiptRequest,
    SagaUnresolvedObservation, SagaVerifiedTerminalReceipt, SagaWorkerIdentity, StoredSagaReceipt,
    saga_operator_action,
};
use primitives::constant_time_eq;
use secure::{
    SagaReceiptFingerprint, SagaReceiptIntegrityKeyId, SagaReceiptIntegrityKeyring,
    SagaReceiptProtectionContext, SagaReceiptProtectionCoordinates,
};
use vocab::StepName;
use zeroize::Zeroizing;

use crate::cotx::eventing::{
    SagaInstanceRow, SagaJournalExistingRow, SagaJournalRow, SagaLeaseMutation,
    SagaOperatorDecisionRow, SagaOperatorStatusRow, SagaReceiptRow, SagaRunnableRow,
};
use crate::cotx::{ServingReadLane, ServingWriteLane, TenantDb, infra_tenant_scope};
use crate::pool::{VerifiedPgReadStore, VerifiedPgWriteStore};
use crate::saga_candidates::PgSagaCandidateSource;
use crate::saga_receipt_capability::SagaReceiptCapabilityReceipt;

const HOLDER_ID_MAX_BYTES: usize = 256;

/// Closed, low-cardinality PostgreSQL operation stages for durable Saga diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SagaStorageStage {
    Register,
    Get,
    ListRunnable,
    ListCandidateTenants,
    ObserveUnresolved,
    Claim,
    LeaseMutation,
    JournalMutation,
    JournalCommitUnknownReadback,
    LifecycleMutation,
    RecoverySnapshot,
    TerminalReceipt,
    CompletionMutation,
    CompletionCommitUnknownReadback,
    OperatorStatus,
    OperatorRetryCompensation,
    OperatorRepairClaim,
}

impl SagaStorageStage {
    pub(crate) const fn as_label(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Get => "get",
            Self::ListRunnable => "list_runnable",
            Self::ListCandidateTenants => "list_candidate_tenants",
            Self::ObserveUnresolved => "observe_unresolved",
            Self::Claim => "claim",
            Self::LeaseMutation => "lease_mutation",
            Self::JournalMutation => "journal_mutation",
            Self::JournalCommitUnknownReadback => "journal_commit_unknown_readback",
            Self::LifecycleMutation => "lifecycle_mutation",
            Self::RecoverySnapshot => "recovery_snapshot",
            Self::TerminalReceipt => "terminal_receipt",
            Self::CompletionMutation => "completion_mutation",
            Self::CompletionCommitUnknownReadback => "completion_commit_unknown_readback",
            Self::OperatorStatus => "operator_status",
            Self::OperatorRetryCompensation => "operator_retry_compensation",
            Self::OperatorRepairClaim => "operator_repair_claim",
        }
    }

    const fn operation(self) -> SagaStorageOperation {
        match self {
            Self::JournalMutation
            | Self::JournalCommitUnknownReadback
            | Self::LifecycleMutation
            | Self::CompletionMutation
            | Self::CompletionCommitUnknownReadback => SagaStorageOperation::Mutate,
            Self::Register => SagaStorageOperation::Register,
            Self::Get => SagaStorageOperation::Get,
            Self::ListRunnable => SagaStorageOperation::ListRunnable,
            Self::ListCandidateTenants => SagaStorageOperation::ListCandidateTenants,
            Self::ObserveUnresolved => SagaStorageOperation::ObserveUnresolved,
            Self::Claim => SagaStorageOperation::Claim,
            Self::LeaseMutation => SagaStorageOperation::LeaseMutation,
            Self::RecoverySnapshot => SagaStorageOperation::RecoverySnapshot,
            Self::TerminalReceipt => SagaStorageOperation::TerminalReceipt,
            Self::OperatorStatus => SagaStorageOperation::OperatorStatus,
            Self::OperatorRetryCompensation => SagaStorageOperation::OperatorRetryCompensation,
            Self::OperatorRepairClaim => SagaStorageOperation::OperatorRepairClaim,
        }
    }
}

/// Closed outer operations. Unlike [`SagaStorageStage`], this identifies caller intent rather than
/// the inner SQL phase that happened to fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SagaStorageOperation {
    Register,
    Get,
    ListRunnable,
    ListCandidateTenants,
    ObserveUnresolved,
    Claim,
    LeaseMutation,
    Mutate,
    RecoverySnapshot,
    TerminalReceipt,
    OperatorStatus,
    OperatorRetryCompensation,
    OperatorRepairClaim,
    OperatorRepairCommit,
}

impl SagaStorageOperation {
    const fn as_label(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Get => "get",
            Self::ListRunnable => "list_runnable",
            Self::ListCandidateTenants => "list_candidate_tenants",
            Self::ObserveUnresolved => "observe_unresolved",
            Self::Claim => "claim",
            Self::LeaseMutation => "lease_mutation",
            Self::Mutate => "mutate",
            Self::RecoverySnapshot => "recovery_snapshot",
            Self::TerminalReceipt => "terminal_receipt",
            Self::OperatorStatus => "operator_status",
            Self::OperatorRetryCompensation => "operator_retry_compensation",
            Self::OperatorRepairClaim => "operator_repair_claim",
            Self::OperatorRepairCommit => "operator_repair_commit",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SagaStorageErrorClass {
    DatabaseTransient,
    DatabasePermanent,
    Io,
    Tls,
    Protocol,
    PoolTimedOut,
    PoolClosed,
    WorkerCrashed,
    Configuration,
    DataMapping,
    OtherPermanent,
}

impl SagaStorageErrorClass {
    const fn as_label(self) -> &'static str {
        match self {
            Self::DatabaseTransient => "database_transient",
            Self::DatabasePermanent => "database_permanent",
            Self::Io => "io",
            Self::Tls => "tls",
            Self::Protocol => "protocol",
            Self::PoolTimedOut => "pool_timed_out",
            Self::PoolClosed => "pool_closed",
            Self::WorkerCrashed => "worker_crashed",
            Self::Configuration => "configuration",
            Self::DataMapping => "data_mapping",
            Self::OtherPermanent => "other_permanent",
        }
    }

    const fn is_transient(self) -> bool {
        matches!(
            self,
            Self::DatabaseTransient | Self::Io | Self::PoolTimedOut | Self::WorkerCrashed
        )
    }
}

#[derive(Debug, Clone)]
struct SagaDiagnosticContext {
    tenant: vocab::TenantId,
    owner: Option<String>,
    contract: Option<String>,
}

impl SagaDiagnosticContext {
    fn for_instance(instance: SagaInstanceRef) -> Self {
        Self {
            tenant: instance.tenant(),
            owner: None,
            contract: None,
        }
    }

    fn for_worker(instance: SagaInstanceRef, identity: &SagaWorkerIdentity) -> Self {
        Self {
            tenant: instance.tenant(),
            owner: Some(identity.owner().to_owned()),
            contract: Some(identity.contract_id().as_str().to_owned()),
        }
    }
}

/// Mandatory protected-storage dependencies for durable Saga receipts.
pub struct PgSagaReceiptProtection {
    key_provider: Arc<DynKeyProvider<'static>>,
    integrity: Arc<SagaReceiptIntegrityKeyring>,
}

impl PgSagaReceiptProtection {
    pub fn new(
        key_provider: Box<DynKeyProvider<'static>>,
        integrity: SagaReceiptIntegrityKeyring,
    ) -> Self {
        Self {
            key_provider: Arc::from(key_provider),
            integrity: Arc::new(integrity),
        }
    }
}

/// PostgreSQL durable Saga aggregate.
pub struct PgSagaDurableStore {
    read_pool: TenantDb<ServingReadLane>,
    write_pool: TenantDb<ServingWriteLane>,
    candidate_source: PgSagaCandidateSource,
    protection: PgSagaReceiptProtection,
    _capability: SagaReceiptCapabilityReceipt,
    #[cfg(all(test, feature = "integration"))]
    inject_commit_unknown_after_next_completion: std::sync::atomic::AtomicBool,
}

/// Move-only operator claim minted exclusively by [`PgSagaDurableStore`].
pub struct PgSagaOperatorClaim {
    lease: SagaLease,
    authorization: SagaOperatorAuthorization<saga_operator_action::Repair>,
}

impl SagaOperatorRepairClaim for PgSagaOperatorClaim {
    fn instance(&self) -> SagaInstanceRef {
        self.authorization.instance()
    }

    fn expected_reason(&self) -> SagaOperatorRepairReason {
        self.authorization.evidence().reason()
    }
}

impl PgSagaDurableStore {
    pub(crate) fn new(
        reader: &VerifiedPgReadStore,
        writer: &VerifiedPgWriteStore,
        protection: PgSagaReceiptProtection,
        capability: SagaReceiptCapabilityReceipt,
    ) -> Self {
        Self {
            read_pool: TenantDb::<ServingReadLane>::new(reader),
            write_pool: TenantDb::<ServingWriteLane>::new(writer),
            candidate_source: PgSagaCandidateSource::new(writer),
            protection,
            _capability: capability,
            #[cfg(all(test, feature = "integration"))]
            inject_commit_unknown_after_next_completion: std::sync::atomic::AtomicBool::new(false),
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn inject_commit_unknown_after_next_completion(&self) {
        self.inject_commit_unknown_after_next_completion
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    async fn mutate_journal(
        &self,
        operation: SagaStorageOperation,
        lease: &SagaLease,
        entry: JournalEntryFields,
        lifecycle: Option<LifecycleFields>,
        required_intent: Option<SagaJournalStatus>,
        audit: Option<OperatorDecisionFields>,
    ) -> Result<SagaDurableMutationOutcome, SagaDurableStoreError> {
        let lease_fields = LeaseFields::from(lease)
            .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
        let journal_expectation = entry.clone();
        let lifecycle_expectation = lifecycle.clone();
        let audit_expectation = audit.clone();
        let repair_epoch = i64::try_from(lease.epoch())
            .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
        let duplicate_allowed = !lifecycle
            .as_ref()
            .is_some_and(|lifecycle| lifecycle.clear_lease);
        #[cfg(all(test, feature = "integration"))]
        let inject_commit_unknown = audit.is_some()
            && self
                .inject_commit_unknown_after_next_completion
                .swap(false, std::sync::atomic::Ordering::SeqCst);
        let attempt = self
            .write_pool
            .saga_write_attempt(
                infra_tenant_scope(lease.instance().tenant()),
                move |mut tx| {
                    Box::pin(async move {
                        if matches!(
                            entry.status.as_str(),
                            "forward_intent" | "compensation_intent"
                        ) {
                            match tx
                                .saga_intent_attempt_is_next(&lease_fields, &entry)
                                .await
                                .map_err(mutation_storage_error_for(
                                    operation,
                                    SagaStorageStage::JournalMutation,
                                ))? {
                                Some(true) => {}
                                Some(false) => {
                                    return Err(MutationTxError::abort(
                                        SagaDurableMutationOutcome::Conflict,
                                    ));
                                }
                                None => {
                                    return Err(MutationTxError::abort(
                                        SagaDurableMutationOutcome::LeaseLost,
                                    ));
                                }
                            }
                        }
                        if let Some(required_intent) = required_intent {
                            match tx
                                .saga_has_exact_prior_intent(&lease_fields, &entry, required_intent)
                                .await
                                .map_err(mutation_storage_error_for(
                                    operation,
                                    SagaStorageStage::JournalMutation,
                                ))? {
                                Some(true) => {}
                                Some(false) => {
                                    return Err(MutationTxError::abort(
                                        SagaDurableMutationOutcome::Conflict,
                                    ));
                                }
                                None => {
                                    return Err(MutationTxError::abort(
                                        SagaDurableMutationOutcome::LeaseLost,
                                    ));
                                }
                            }
                        }
                        if tx
                            .saga_insert_journal(&lease_fields, &entry)
                            .await
                            .map_err(mutation_storage_error_for(
                                operation,
                                SagaStorageStage::JournalMutation,
                            ))?
                        {
                            if let Some(audit) = audit
                                && !tx
                                    .saga_insert_operator_decision(&lease_fields, &entry, &audit)
                                    .await
                                    .map_err(mutation_storage_error_for(
                                        operation,
                                        SagaStorageStage::JournalMutation,
                                    ))?
                            {
                                return Err(MutationTxError::abort(
                                    SagaDurableMutationOutcome::Conflict,
                                ));
                            }
                            if let Some(lifecycle) = lifecycle
                                && !tx
                                    .saga_apply_lifecycle(&lease_fields, &lifecycle)
                                    .await
                                    .map_err(mutation_storage_error_for(
                                        operation,
                                        SagaStorageStage::JournalMutation,
                                    ))?
                            {
                                return Err(MutationTxError::abort(
                                    SagaDurableMutationOutcome::Conflict,
                                ));
                            }
                            #[cfg(all(test, feature = "integration"))]
                            if inject_commit_unknown {
                                tx.saga_inject_commit_unknown_after_commit().await.map_err(
                                    mutation_storage_error_for(
                                        operation,
                                        SagaStorageStage::JournalMutation,
                                    ),
                                )?;
                            }
                            return Ok(SagaDurableMutationOutcome::Applied);
                        }
                        if !tx.saga_lease_is_held(&lease_fields).await.map_err(
                            mutation_storage_error_for(
                                operation,
                                SagaStorageStage::JournalMutation,
                            ),
                        )? {
                            return Err(MutationTxError::abort(
                                SagaDurableMutationOutcome::LeaseLost,
                            ));
                        }
                        let existing = tx
                            .saga_load_journal_entry(
                                &InstanceFields::from(lease_fields.instance),
                                entry.seq,
                            )
                            .await
                            .map_err(mutation_storage_error_for(
                                operation,
                                SagaStorageStage::JournalMutation,
                            ))?;
                        let exact = existing.is_some_and(|row| {
                            row.step_name == entry.step_name
                                && row.status == entry.status
                                && row.error_summary == entry.error_summary
                                && row.attempt == entry.attempt
                                && constant_time_eq(&row.effect_key, &entry.effect_key)
                                && row.compensation_cause == entry.compensation_cause
                        });
                        Err(MutationTxError::abort(if exact && duplicate_allowed {
                            SagaDurableMutationOutcome::IdempotentDuplicate
                        } else {
                            SagaDurableMutationOutcome::Conflict
                        }))
                    })
                },
                mutation_storage_error_for(operation, SagaStorageStage::JournalMutation),
            )
            .await;
        let settlement = attempt.settlement();
        match attempt.into_result() {
            Ok(outcome) => Ok(outcome),
            Err(error) if settlement == Some(LocalTxFinalStatus::CommitUnknown) => {
                match self
                    .read_back_commit_unknown_journal(
                        lease.instance(),
                        &journal_expectation,
                        lifecycle_expectation.as_ref(),
                        audit_expectation.as_ref(),
                        repair_epoch,
                    )
                    .await?
                {
                    CommitUnknownReadback::Applied => Ok(SagaDurableMutationOutcome::Applied),
                    CommitUnknownReadback::NotApplied => {
                        Err(saga_error(SagaDurableStoreErrorKind::CommitUnknown, error))
                    }
                    CommitUnknownReadback::Integrity => Err(saga_error(
                        SagaDurableStoreErrorKind::Integrity,
                        InvariantError(
                            "commit-unknown journal read-back was partial or inconsistent",
                        ),
                    )),
                }
            }
            Err(MutationTxError::Abort { outcome })
                if settlement == Some(LocalTxFinalStatus::RolledBack) =>
            {
                Ok(outcome)
            }
            Err(error) => Err(saga_error(SagaDurableStoreErrorKind::Storage, error)),
        }
    }

    async fn read_back_commit_unknown_journal(
        &self,
        instance: SagaInstanceRef,
        journal_expected: &JournalEntryFields,
        lifecycle_expected: Option<&LifecycleFields>,
        audit_expected: Option<&OperatorDecisionFields>,
        repair_epoch: i64,
    ) -> Result<CommitUnknownReadback, SagaDurableStoreError> {
        let instance_fields = InstanceFields::from(instance);
        let decision_seq = journal_expected.seq;
        let (instance_row, journal, audit) = self
            .read_pool
            .saga_read_map(
                infra_tenant_scope(instance.tenant()),
                move |mut conn| {
                    Box::pin(async move {
                        let instance_row = conn.saga_get_instance(&instance_fields).await.map_err(
                            storage_error(SagaStorageStage::JournalCommitUnknownReadback),
                        )?;
                        let journal = conn
                            .saga_read_journal_entry(&instance_fields, decision_seq)
                            .await
                            .map_err(storage_error(
                                SagaStorageStage::JournalCommitUnknownReadback,
                            ))?;
                        let audit = conn
                            .saga_read_operator_decision(&instance_fields, decision_seq)
                            .await
                            .map_err(storage_error(
                                SagaStorageStage::JournalCommitUnknownReadback,
                            ))?;
                        Ok((instance_row, journal, audit))
                    })
                },
                storage_error(SagaStorageStage::JournalCommitUnknownReadback),
            )
            .await?;
        let Some(instance_row) = instance_row else {
            return Ok(CommitUnknownReadback::Integrity);
        };
        if journal.is_none() && audit.is_none() {
            return Ok(
                if commit_unknown_pre_state_matches(&instance_row, audit_expected) {
                    CommitUnknownReadback::NotApplied
                } else {
                    CommitUnknownReadback::Integrity
                },
            );
        }
        let Some(journal) = journal else {
            return Ok(CommitUnknownReadback::Integrity);
        };
        let exact = journal_row_matches(&journal, journal_expected)
            && lifecycle_row_matches(&instance_row, lifecycle_expected)
            && operator_audit_matches(audit.as_ref(), audit_expected, repair_epoch);
        Ok(if exact {
            CommitUnknownReadback::Applied
        } else {
            CommitUnknownReadback::Integrity
        })
    }

    async fn mutate_lifecycle(
        &self,
        lease: &SagaLease,
        lifecycle: LifecycleFields,
    ) -> Result<SagaDurableMutationOutcome, SagaDurableStoreError> {
        let lease_fields = LeaseFields::from(lease)
            .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
        let attempt = self
            .write_pool
            .saga_write_attempt(
                infra_tenant_scope(lease.instance().tenant()),
                move |mut tx| {
                    Box::pin(async move {
                        if tx
                            .saga_apply_lifecycle(&lease_fields, &lifecycle)
                            .await
                            .map_err(mutation_storage_error(SagaStorageStage::LifecycleMutation))?
                        {
                            return Ok(SagaDurableMutationOutcome::Applied);
                        }
                        let held = tx
                            .saga_lease_is_held(&lease_fields)
                            .await
                            .map_err(mutation_storage_error(SagaStorageStage::LifecycleMutation))?;
                        Err(MutationTxError::abort(if held {
                            SagaDurableMutationOutcome::Conflict
                        } else {
                            SagaDurableMutationOutcome::LeaseLost
                        }))
                    })
                },
                mutation_storage_error(SagaStorageStage::LifecycleMutation),
            )
            .await;
        settle_mutation_attempt(attempt)
    }
}

#[derive(Debug, thiserror::Error)]
enum MutationTxError {
    #[error("saga durable transaction storage operation failed")]
    Storage(#[source] sqlx::Error),
    #[error("saga durable transaction intentionally aborted")]
    Abort { outcome: SagaDurableMutationOutcome },
}

impl MutationTxError {
    const fn abort(outcome: SagaDurableMutationOutcome) -> Self {
        Self::Abort { outcome }
    }
}

fn settle_mutation_attempt(
    attempt: crate::cotx::LocalTxAttempt<SagaDurableMutationOutcome, MutationTxError>,
) -> Result<SagaDurableMutationOutcome, SagaDurableStoreError> {
    let settlement = attempt.settlement();
    match attempt.into_result() {
        Ok(outcome) => Ok(outcome),
        Err(error) if settlement == Some(LocalTxFinalStatus::CommitUnknown) => {
            Err(saga_error(SagaDurableStoreErrorKind::CommitUnknown, error))
        }
        Err(MutationTxError::Abort { outcome })
            if settlement == Some(LocalTxFinalStatus::RolledBack) =>
        {
            Ok(outcome)
        }
        Err(error) => Err(saga_error(SagaDurableStoreErrorKind::Storage, error)),
    }
}

impl SagaDurableStore for PgSagaDurableStore {
    async fn register(
        &self,
        authorization: SagaStartAuthorization,
        registration: SagaInstanceRegistration,
    ) -> Result<SagaInstanceRecord, SagaDurableStoreError> {
        if authorization.instance() != registration.instance()
            || authorization.identity() != registration.identity()
        {
            return Err(saga_error(
                SagaDurableStoreErrorKind::IdentityConflict,
                InvariantError("saga start authorization does not match registration"),
            ));
        }
        let diagnostic =
            SagaDiagnosticContext::for_worker(registration.instance(), registration.identity());
        let transaction_diagnostic = diagnostic.clone();
        let fields = RegistrationFields::authorized(authorization, registration);
        self.write_pool
            .saga_write(
                infra_tenant_scope(fields.instance.tenant()),
                move |mut tx| {
                    let diagnostic = diagnostic.clone();
                    Box::pin(async move {
                        tx.saga_register_instance(&fields).await.map_err(
                            storage_error_with_context(
                                SagaStorageOperation::Register,
                                SagaStorageStage::Register,
                                diagnostic.clone(),
                            ),
                        )?;
                        let row = tx
                            .saga_load_instance(&InstanceFields::from(fields.instance))
                            .await
                            .map_err(storage_error_with_context(
                                SagaStorageOperation::Register,
                                SagaStorageStage::Register,
                                diagnostic,
                            ))?;
                        let record = instance_from_row(fields.instance, &row)?;
                        if record.identity() != &fields.identity
                            || record.definition() != &fields.definition
                            || row.start_actor != fields.start_actor
                            || row.start_audit_id != fields.start_audit_id
                        {
                            return Err(saga_error(
                                SagaDurableStoreErrorKind::IdentityConflict,
                                InvariantError("saga instance definition identity conflict"),
                            ));
                        }
                        Ok(record)
                    })
                },
                storage_error_with_context(
                    SagaStorageOperation::Register,
                    SagaStorageStage::Register,
                    transaction_diagnostic,
                ),
            )
            .await
    }

    async fn get(
        &self,
        instance: &SagaInstanceRef,
    ) -> Result<Option<SagaInstanceRecord>, SagaDurableStoreError> {
        let diagnostic = SagaDiagnosticContext::for_instance(*instance);
        let read_diagnostic = diagnostic.clone();
        let fields = InstanceFields::from(*instance);
        self.read_pool
            .saga_read_map(
                infra_tenant_scope(instance.tenant()),
                move |mut conn| {
                    let diagnostic = diagnostic.clone();
                    Box::pin(async move {
                        conn.saga_get_instance(&fields)
                            .await
                            .map_err(storage_error_with_context(
                                SagaStorageOperation::Get,
                                SagaStorageStage::Get,
                                diagnostic,
                            ))?
                            .map(|row| instance_from_row(fields.instance, &row))
                            .transpose()
                    })
                },
                storage_error_with_context(
                    SagaStorageOperation::Get,
                    SagaStorageStage::Get,
                    read_diagnostic,
                ),
            )
            .await
    }

    async fn list_runnable(
        &self,
        identity: &SagaWorkerIdentity,
        tenant: vocab::TenantId,
        limit: NonZeroUsize,
    ) -> Result<Vec<SagaRunnableInstance>, SagaDurableStoreError> {
        let owner = identity.owner().to_string();
        let contract_id = identity.contract_id().as_str().to_string();
        let limit = i64::try_from(limit.get())
            .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
        self.read_pool
            .saga_read_map(
                infra_tenant_scope(tenant),
                move |mut conn| {
                    Box::pin(async move {
                        conn.saga_list_runnable(&owner, &contract_id, limit)
                            .await
                            .map_err(storage_error(SagaStorageStage::ListRunnable))?
                            .into_iter()
                            .map(|row| runnable_from_row(tenant, row))
                            .collect()
                    })
                },
                storage_error(SagaStorageStage::ListRunnable),
            )
            .await
    }

    async fn claim(
        &self,
        request: SagaClaimRequest,
    ) -> Result<SagaClaimOutcome, SagaDurableStoreError> {
        if request.holder_id().len() > HOLDER_ID_MAX_BYTES {
            return Err(saga_error(
                SagaDurableStoreErrorKind::Integrity,
                InvariantError("invalid saga lease holder_id"),
            ));
        }
        let fields = ClaimFields::from_request(&request)?;
        let instance = request.expected().instance();
        let holder_id = request.holder_id().to_string();
        self.write_pool
            .saga_write(
                infra_tenant_scope(instance.tenant()),
                move |mut tx| {
                    Box::pin(async move {
                        if let Some(row) = tx
                            .saga_claim(&fields)
                            .await
                            .map_err(storage_error(SagaStorageStage::Claim))?
                        {
                            return lease_from_row(instance, holder_id, row.lease_token, row.epoch)
                                .map(SagaClaimOutcome::Acquired)
                                .map_err(|error| {
                                    saga_error(SagaDurableStoreErrorKind::Integrity, error)
                                });
                        }
                        let Some(row) = tx
                            .saga_observe_claim(&InstanceFields::from(instance))
                            .await
                            .map_err(storage_error(SagaStorageStage::Claim))?
                        else {
                            return Ok(SagaClaimOutcome::Missing);
                        };
                        if row.owner != fields.owner
                            || row.contract_id != fields.contract_id
                            || row.definition_version != fields.definition_version
                            || row.definition_schema_digest != fields.definition_schema_digest
                            || row.action_registry_generation != fields.action_registry_generation
                        {
                            return Ok(SagaClaimOutcome::IdentityConflict);
                        }
                        let status = parse_instance_status(&row.status)?;
                        match status {
                            SagaInstanceStatus::OperatorRequired => {
                                let reason = row
                                    .operator_reason
                                    .as_deref()
                                    .and_then(SagaOperatorReason::parse)
                                    .ok_or_else(|| {
                                        saga_error(
                                            SagaDurableStoreErrorKind::Integrity,
                                            InvariantError("invalid saga operator reason"),
                                        )
                                    })?;
                                Ok(SagaClaimOutcome::OperatorRequired(reason))
                            }
                            SagaInstanceStatus::Degraded => Ok(SagaClaimOutcome::Degraded),
                            SagaInstanceStatus::CompensationFailed => {
                                Ok(SagaClaimOutcome::Degraded)
                            }
                            status @ (SagaInstanceStatus::Succeeded
                            | SagaInstanceStatus::Compensated
                            | SagaInstanceStatus::Expired
                            | SagaInstanceStatus::Terminated) => {
                                Ok(SagaClaimOutcome::Terminal(status))
                            }
                            _ if row.lease_busy => Ok(SagaClaimOutcome::Busy),
                            _ => Ok(SagaClaimOutcome::Stale(status)),
                        }
                    })
                },
                storage_error(SagaStorageStage::Claim),
            )
            .await
    }

    async fn renew(
        &self,
        lease: &SagaLease,
        ttl: SagaLeaseTtl,
    ) -> Result<SagaLeaseOutcome, SagaDurableStoreError> {
        let ttl_micros = duration_micros(ttl)?;
        self.cas_lease(lease, SagaLeaseMutation::Extend { ttl_micros })
            .await
    }

    async fn release(&self, lease: &SagaLease) -> Result<SagaLeaseOutcome, SagaDurableStoreError> {
        self.cas_lease(lease, SagaLeaseMutation::Release).await
    }

    async fn recovery_snapshot(
        &self,
        request: SagaRecoveryRequest,
    ) -> Result<SagaRecoveryOutcome, SagaDurableStoreError> {
        let (lease, scopes) = request.into_parts();
        let lease_fields = LeaseFields::from(&lease)
            .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
        let instance_fields = InstanceFields::from(lease.instance());
        let raw = self
            .write_pool
            .saga_write(
                infra_tenant_scope(lease.instance().tenant()),
                move |mut tx| {
                    Box::pin(async move {
                        if !tx
                            .saga_lease_is_held(&lease_fields)
                            .await
                            .map_err(storage_error(SagaStorageStage::RecoverySnapshot))?
                        {
                            return Ok(None);
                        }
                        let instance = tx
                            .saga_load_instance(&instance_fields)
                            .await
                            .map_err(storage_error(SagaStorageStage::RecoverySnapshot))?;
                        let journal = tx
                            .saga_read_journal_locked(&instance_fields)
                            .await
                            .map_err(storage_error(SagaStorageStage::RecoverySnapshot))?;
                        let mut receipts = Vec::with_capacity(scopes.len());
                        for scope in scopes {
                            let row = tx
                                .saga_load_receipt(&SagaReceiptScopeFields::from_scope(&scope))
                                .await
                                .map_err(storage_error(SagaStorageStage::RecoverySnapshot))?;
                            receipts.push((scope, row));
                        }
                        Ok(Some((instance, journal, receipts)))
                    })
                },
                storage_error(SagaStorageStage::RecoverySnapshot),
            )
            .await?;
        let Some((instance_row, journal_rows, receipt_rows)) = raw else {
            return Ok(SagaRecoveryOutcome::LeaseLost);
        };
        let instance = instance_from_row(lease.instance(), &instance_row)?;
        let journal = journal_rows
            .into_iter()
            .map(journal_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        let mut receipts = Vec::new();
        for (scope, row) in receipt_rows {
            if let Some(row) = row {
                receipts.push(
                    stored_receipt_from_row(
                        &scope,
                        &row,
                        self.protection.key_provider.as_ref(),
                        &self.protection.integrity,
                    )
                    .await?,
                );
            }
        }
        let operator_reason =
            parse_optional_operator_reason(instance_row.operator_reason.as_deref())?;
        let compensation_cause =
            parse_optional_compensation_cause(instance_row.compensation_cause.as_deref())?;
        Ok(SagaRecoveryOutcome::Available(SagaRecoverySnapshot::new(
            instance,
            journal,
            receipts,
            operator_reason,
            compensation_cause,
        )))
    }

    async fn terminal_receipt(
        &self,
        request: SagaTerminalReceiptRequest,
    ) -> Result<SagaTerminalReceiptOutcome, SagaDurableStoreError> {
        let scope = request.into_scope();
        let instance = scope.instance();
        let instance_fields = InstanceFields::from(instance);
        let scope_fields = SagaReceiptScopeFields::from_scope(&scope);
        let raw = self
            .write_pool
            .saga_write(
                infra_tenant_scope(instance.tenant()),
                move |mut tx| {
                    Box::pin(async move {
                        let row = match tx.saga_load_instance(&instance_fields).await {
                            Ok(row) => row,
                            Err(sqlx::Error::RowNotFound) => return Ok(None),
                            Err(error) => {
                                return Err(storage_error(SagaStorageStage::TerminalReceipt)(
                                    error,
                                ));
                            }
                        };
                        let journal = tx
                            .saga_read_journal_locked(&instance_fields)
                            .await
                            .map_err(storage_error(SagaStorageStage::TerminalReceipt))?;
                        let receipt = tx
                            .saga_load_receipt(&scope_fields)
                            .await
                            .map_err(storage_error(SagaStorageStage::TerminalReceipt))?;
                        Ok(Some((row, journal, receipt)))
                    })
                },
                storage_error(SagaStorageStage::TerminalReceipt),
            )
            .await?;
        let Some((row, journal_rows, receipt_row)) = raw else {
            return Ok(SagaTerminalReceiptOutcome::Missing);
        };
        let record = instance_from_row(instance, &row)?;
        if record.status() != SagaInstanceStatus::Succeeded {
            return Ok(SagaTerminalReceiptOutcome::NotSucceeded(record.status()));
        }
        if record.identity() != scope.worker() || record.definition() != scope.definition() {
            return Err(saga_error(
                SagaDurableStoreErrorKind::Integrity,
                InvariantError("terminal saga receipt identity mismatch"),
            ));
        }
        let journal = journal_rows
            .into_iter()
            .map(journal_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        let receipt_row = receipt_row.ok_or_else(|| {
            saga_error(
                SagaDurableStoreErrorKind::Integrity,
                InvariantError("succeeded saga final receipt is missing"),
            )
        })?;
        let receipt = stored_receipt_from_row(
            &scope,
            &receipt_row,
            self.protection.key_provider.as_ref(),
            &self.protection.integrity,
        )
        .await?;
        let last = journal.last().ok_or_else(|| {
            saga_error(
                SagaDurableStoreErrorKind::Integrity,
                InvariantError("succeeded saga has no journal"),
            )
        })?;
        if last.status() != SagaJournalStatus::ForwardCompleted
            || last.seq() != receipt.completed_seq()
            || last.step_name() != scope.step_name()
        {
            return Err(saga_error(
                SagaDurableStoreErrorKind::Integrity,
                InvariantError("succeeded saga final receipt is not terminal"),
            ));
        }
        Ok(SagaTerminalReceiptOutcome::Verified(Box::new(
            SagaVerifiedTerminalReceipt::new(record, journal, receipt),
        )))
    }

    async fn mutate(
        &self,
        lease: &SagaLease,
        mutation: SagaDurableMutation,
    ) -> Result<SagaDurableMutationOutcome, SagaDurableStoreError> {
        match mutation {
            SagaDurableMutation::ForwardIntent(intent) => {
                let entry = JournalEntryFields::new(
                    intent.seq(),
                    intent.step(),
                    SagaJournalStatus::ForwardIntent,
                    intent.attempt(),
                    intent.effect_key(),
                    None,
                    None,
                )?;
                self.mutate_journal(SagaStorageOperation::Mutate, lease, entry, None, None, None)
                    .await
            }
            SagaDurableMutation::ForwardCompleted(completion) => {
                self.commit_forward_completion(lease, completion).await
            }
            SagaDurableMutation::CompensationIntent(intent) => {
                let entry = JournalEntryFields::new(
                    intent.seq(),
                    intent.step(),
                    SagaJournalStatus::CompensationIntent,
                    intent.attempt(),
                    intent.effect_key(),
                    None,
                    Some(intent.cause()),
                )?;
                self.mutate_journal(
                    SagaStorageOperation::Mutate,
                    lease,
                    entry,
                    Some(LifecycleFields::compensating(intent.cause())),
                    None,
                    None,
                )
                .await
            }
            SagaDurableMutation::CompensationCompleted(completion) => {
                let entry = JournalEntryFields::new(
                    completion.seq(),
                    completion.step(),
                    SagaJournalStatus::CompensationCompleted,
                    completion.attempt(),
                    completion.effect_key(),
                    None,
                    None,
                )?;
                let lifecycle = match completion.progress() {
                    SagaCompensationProgress::Continue => LifecycleFields::compensating_existing(),
                    SagaCompensationProgress::Compensated => {
                        LifecycleFields::terminal(SagaInstanceStatus::Compensated, None)
                    }
                    SagaCompensationProgress::Expired => LifecycleFields::terminal(
                        SagaInstanceStatus::Expired,
                        Some(SagaCompensationCause::Expired),
                    ),
                    _ => return Ok(SagaDurableMutationOutcome::Conflict),
                };
                self.mutate_journal(
                    SagaStorageOperation::Mutate,
                    lease,
                    entry,
                    Some(lifecycle),
                    Some(SagaJournalStatus::CompensationIntent),
                    None,
                )
                .await
            }
            SagaDurableMutation::CompensationFailed(failure) => {
                let entry = JournalEntryFields::new(
                    failure.seq(),
                    failure.step(),
                    SagaJournalStatus::CompensationFailed,
                    failure.attempt(),
                    failure.effect_key(),
                    Some(failure.error_summary()),
                    None,
                )?;
                self.mutate_journal(
                    SagaStorageOperation::Mutate,
                    lease,
                    entry,
                    Some(LifecycleFields::terminal(
                        SagaInstanceStatus::CompensationFailed,
                        None,
                    )),
                    Some(SagaJournalStatus::CompensationIntent),
                    None,
                )
                .await
            }
            SagaDurableMutation::OperatorRequired(reason) => {
                self.mutate_lifecycle(lease, LifecycleFields::operator_required(reason))
                    .await
            }
            SagaDurableMutation::Degraded => {
                self.mutate_lifecycle(lease, LifecycleFields::degraded())
                    .await
            }
            _ => Ok(SagaDurableMutationOutcome::Conflict),
        }
    }

    async fn shutdown(&self) -> Result<(), SagaDurableStoreError> {
        self.protection
            .key_provider
            .shutdown()
            .await
            .map_err(|error| saga_error(SagaDurableStoreErrorKind::Protection, error))
    }
}

impl SagaOperatorStore for PgSagaDurableStore {
    type RepairClaim = PgSagaOperatorClaim;

    async fn operator_status(
        &self,
        authorization: SagaOperatorAuthorization<saga_operator_action::Status>,
    ) -> Result<SagaOperatorStatusOutcome, SagaDurableStoreError> {
        let instance = authorization.instance();
        let fields = InstanceFields::from(instance);
        let row = self
            .read_pool
            .saga_read_map(
                infra_tenant_scope(instance.tenant()),
                move |mut conn| {
                    Box::pin(async move {
                        conn.saga_operator_status(&fields)
                            .await
                            .map_err(storage_error(SagaStorageStage::OperatorStatus))
                    })
                },
                storage_error(SagaStorageStage::OperatorStatus),
            )
            .await?;
        let Some(row) = row else {
            return Ok(SagaOperatorStatusOutcome::Missing);
        };
        if !operator_identity_matches(&row, authorization.identity()) {
            return Ok(SagaOperatorStatusOutcome::IdentityConflict);
        }
        Ok(SagaOperatorStatusOutcome::Found(Box::new(
            operator_status_snapshot(instance, &row)?,
        )))
    }

    async fn retry_compensation(
        &self,
        authorization: SagaOperatorAuthorization<saga_operator_action::RetryCompensation>,
    ) -> Result<SagaOperatorCasOutcome, SagaDurableStoreError> {
        let instance = authorization.instance();
        let fields = InstanceFields::from(instance);
        let owner = authorization.identity().owner().to_string();
        let contract_id = authorization.identity().contract_id().as_str().to_string();
        let journal = authorization.evidence().journal();
        let failure_seq = i64::try_from(journal.record().seq())
            .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
        let failure_step_name = journal.record().step_name().as_str().to_string();
        let failure_attempt = i32::try_from(journal.attempt().get())
            .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
        let failure_effect_key = journal.effect_key().as_bytes().to_vec();
        let operator_actor = authorization.caller().as_str().to_string();
        let reason_text = authorization.evidence().reason_text().as_str().to_string();
        let change_ticket = authorization
            .evidence()
            .change_ticket()
            .as_str()
            .to_string();
        let start_audit_id = authorization.start_audit_id().as_str().to_string();
        let observed = self
            .write_pool
            .saga_write(
                infra_tenant_scope(instance.tenant()),
                move |mut tx| {
                    Box::pin(async move {
                        if tx
                            .saga_retry_compensation(
                                &fields,
                                &owner,
                                &contract_id,
                                failure_seq,
                                &failure_step_name,
                                failure_attempt,
                                &failure_effect_key,
                                &operator_actor,
                                &reason_text,
                                &change_ticket,
                                &start_audit_id,
                            )
                            .await
                            .map_err(storage_error(SagaStorageStage::OperatorRetryCompensation))?
                        {
                            return Ok((true, None));
                        }
                        let row = tx
                            .saga_operator_status(&fields)
                            .await
                            .map_err(storage_error(SagaStorageStage::OperatorRetryCompensation))?;
                        Ok((false, row))
                    })
                },
                storage_error(SagaStorageStage::OperatorRetryCompensation),
            )
            .await?;
        let (applied, row) = observed;
        if applied {
            return Ok(SagaOperatorCasOutcome::Applied);
        }
        let Some(row) = row else {
            return Ok(SagaOperatorCasOutcome::Missing);
        };
        classify_retry_rejection(&authorization, &row)
    }

    async fn claim_repair(
        &self,
        authorization: SagaOperatorAuthorization<saga_operator_action::Repair>,
        holder: SagaLeaseHolder,
        ttl: SagaLeaseTtl,
    ) -> Result<SagaOperatorClaimOutcome<Self::RepairClaim>, SagaDurableStoreError> {
        if holder.as_str().len() > HOLDER_ID_MAX_BYTES {
            return Err(saga_error(
                SagaDurableStoreErrorKind::Integrity,
                InvariantError("invalid saga operator holder_id"),
            ));
        }
        let instance = authorization.instance();
        let fields = InstanceFields::from(instance);
        let reason = authorization.evidence().reason().as_operator_reason();
        let reason_label = reason.as_str().to_string();
        let owner = authorization.identity().owner().to_string();
        let contract_id = authorization.identity().contract_id().as_str().to_string();
        let holder_id = holder.as_str().to_string();
        let ttl_micros = duration_micros(ttl)?;
        let observed = self
            .write_pool
            .saga_write(
                infra_tenant_scope(instance.tenant()),
                move |mut tx| {
                    Box::pin(async move {
                        if let Some(row) = tx
                            .saga_claim_operator(
                                &fields,
                                &owner,
                                &contract_id,
                                &reason_label,
                                &holder_id,
                                ttl_micros,
                            )
                            .await
                            .map_err(storage_error(SagaStorageStage::OperatorRepairClaim))?
                        {
                            return Ok(Ok((holder_id, row)));
                        }
                        let row = match tx.saga_load_instance(&fields).await {
                            Ok(row) => row,
                            Err(sqlx::Error::RowNotFound) => return Ok(Err(None)),
                            Err(error) => {
                                return Err(storage_error(SagaStorageStage::OperatorRepairClaim)(
                                    error,
                                ));
                            }
                        };
                        Ok(Err(Some(row)))
                    })
                },
                storage_error(SagaStorageStage::OperatorRepairClaim),
            )
            .await?;
        match observed {
            Ok((holder_id, row)) => {
                let lease = lease_from_row(instance, holder_id, row.lease_token, row.epoch)
                    .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
                Ok(SagaOperatorClaimOutcome::Acquired(PgSagaOperatorClaim {
                    lease,
                    authorization,
                }))
            }
            Err(None) => Ok(SagaOperatorClaimOutcome::Missing),
            Err(Some(row)) => {
                let record = instance_from_row(instance, &row)?;
                if record.identity() != authorization.identity() {
                    return Ok(SagaOperatorClaimOutcome::Missing);
                }
                let status = record.status();
                if status != SagaInstanceStatus::OperatorRequired {
                    return Ok(SagaOperatorClaimOutcome::StaleStatus(status));
                }
                let actual = parse_optional_operator_reason(row.operator_reason.as_deref())?
                    .ok_or_else(|| {
                        saga_error(
                            SagaDurableStoreErrorKind::Integrity,
                            InvariantError("operator-required saga has no reason"),
                        )
                    })?;
                if actual != reason {
                    Ok(SagaOperatorClaimOutcome::StaleReason(actual))
                } else {
                    Ok(SagaOperatorClaimOutcome::Busy)
                }
            }
        }
    }

    async fn repair_snapshot(
        &self,
        claim: &Self::RepairClaim,
        scopes: Vec<SagaReceiptScope>,
    ) -> Result<SagaRecoveryOutcome, SagaDurableStoreError> {
        let request = SagaRecoveryRequest::new(claim.lease.clone(), scopes)
            .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
        SagaDurableStore::recovery_snapshot(self, request).await
    }

    async fn release_repair(
        &self,
        claim: Self::RepairClaim,
    ) -> Result<SagaLeaseOutcome, SagaDurableStoreError> {
        SagaDurableStore::release(self, &claim.lease).await
    }

    async fn commit_repair(
        &self,
        claim: Self::RepairClaim,
        decision: SagaOperatorRepair,
    ) -> Result<SagaOperatorCasOutcome, SagaDurableStoreError> {
        let reason = claim.expected_reason().as_operator_reason();
        let outcome = match decision {
            SagaOperatorRepair::ForwardApplied(completion) => {
                if !matches!(
                    reason,
                    SagaOperatorReason::ForwardOutcomeUnknown
                        | SagaOperatorReason::CompletionCommitUnknown
                ) {
                    return Ok(SagaOperatorCasOutcome::StaleReason(reason));
                }
                self.commit_operator_forward_completion(&claim, *completion)
                    .await
            }
            SagaOperatorRepair::ForwardNotApplied(not_applied) => {
                if !matches!(
                    reason,
                    SagaOperatorReason::ForwardOutcomeUnknown
                        | SagaOperatorReason::CompletionCommitUnknown
                ) {
                    return Ok(SagaOperatorCasOutcome::StaleReason(reason));
                }
                let entry = JournalEntryFields::new(
                    not_applied.seq(),
                    not_applied.step(),
                    SagaJournalStatus::ForwardNotApplied,
                    not_applied.attempt(),
                    not_applied.effect_key(),
                    None,
                    None,
                )?;
                let audit = OperatorDecisionFields::new(
                    &claim,
                    consistency::SagaEffectPhase::Forward,
                    "confirmed_not_applied",
                );
                self.mutate_journal(
                    SagaStorageOperation::OperatorRepairCommit,
                    &claim.lease,
                    entry,
                    Some(LifecycleFields::operator_forward_not_applied()),
                    Some(SagaJournalStatus::ForwardIntent),
                    Some(audit),
                )
                .await
            }
            SagaOperatorRepair::CompensationApplied(completion) => {
                if reason != SagaOperatorReason::CompensationOutcomeUnknown {
                    return Ok(SagaOperatorCasOutcome::StaleReason(reason));
                }
                let progress = completion.progress();
                let entry = JournalEntryFields::new(
                    completion.seq(),
                    completion.step(),
                    SagaJournalStatus::CompensationCompleted,
                    completion.attempt(),
                    completion.effect_key(),
                    None,
                    None,
                )?;
                let audit = OperatorDecisionFields::new(
                    &claim,
                    consistency::SagaEffectPhase::Compensation,
                    "confirmed_applied",
                );
                self.mutate_journal(
                    SagaStorageOperation::OperatorRepairCommit,
                    &claim.lease,
                    entry,
                    Some(LifecycleFields::operator_compensation(progress, None)),
                    Some(SagaJournalStatus::CompensationIntent),
                    Some(audit),
                )
                .await
            }
            SagaOperatorRepair::CompensationNotApplied(not_applied) => {
                if reason != SagaOperatorReason::CompensationOutcomeUnknown {
                    return Ok(SagaOperatorCasOutcome::StaleReason(reason));
                }
                let entry = JournalEntryFields::new(
                    not_applied.seq(),
                    not_applied.step(),
                    SagaJournalStatus::CompensationNotApplied,
                    not_applied.attempt(),
                    not_applied.effect_key(),
                    None,
                    Some(not_applied.cause()),
                )?;
                let audit = OperatorDecisionFields::new(
                    &claim,
                    consistency::SagaEffectPhase::Compensation,
                    "confirmed_not_applied",
                );
                self.mutate_journal(
                    SagaStorageOperation::OperatorRepairCommit,
                    &claim.lease,
                    entry,
                    Some(LifecycleFields::operator_compensation(
                        SagaCompensationProgress::Continue,
                        Some(not_applied.cause()),
                    )),
                    Some(SagaJournalStatus::CompensationIntent),
                    Some(audit),
                )
                .await
            }
            _ => return Ok(SagaOperatorCasOutcome::StaleJournal),
        }?;
        Ok(operator_cas_from_mutation(outcome))
    }
}

impl SagaTenantSource for PgSagaDurableStore {
    async fn list_runnable_tenants(
        &self,
        identity: &SagaWorkerIdentity,
        cursor: Option<SagaTenantCursor>,
        limit: NonZeroUsize,
    ) -> Result<SagaTenantPage, SagaDurableStoreError> {
        self.candidate_source.list(identity, cursor, limit).await
    }

    async fn observe_unresolved(
        &self,
        identity: &SagaWorkerIdentity,
    ) -> Result<SagaUnresolvedObservation, SagaDurableStoreError> {
        self.candidate_source.observe_unresolved(identity).await
    }
}

impl PgSagaDurableStore {
    async fn cas_lease(
        &self,
        lease: &SagaLease,
        mutation: SagaLeaseMutation,
    ) -> Result<SagaLeaseOutcome, SagaDurableStoreError> {
        let fields = LeaseFields::from(lease)
            .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
        self.write_pool
            .saga_write(
                infra_tenant_scope(lease.instance().tenant()),
                move |mut tx| {
                    Box::pin(async move {
                        tx.saga_cas_lease(&fields, mutation)
                            .await
                            .map(|held| {
                                if held {
                                    SagaLeaseOutcome::Held
                                } else {
                                    SagaLeaseOutcome::Lost
                                }
                            })
                            .map_err(storage_error(SagaStorageStage::LeaseMutation))
                    })
                },
                storage_error(SagaStorageStage::LeaseMutation),
            )
            .await
    }
}

const SAGA_RECEIPT_KEY_NAME: &str = "rss-saga-receipt";
const SAGA_RECEIPT_INTEGRITY_MESSAGE: &[u8] = b"rss.saga-receipt.content.v1";

impl PgSagaDurableStore {
    async fn commit_forward_completion(
        &self,
        lease: &SagaLease,
        completion: SagaForwardCompletion,
    ) -> Result<SagaDurableMutationOutcome, SagaDurableStoreError> {
        self.commit_forward_completion_inner(SagaStorageOperation::Mutate, lease, completion, None)
            .await
    }

    async fn commit_operator_forward_completion(
        &self,
        operator: &PgSagaOperatorClaim,
        completion: SagaForwardCompletion,
    ) -> Result<SagaDurableMutationOutcome, SagaDurableStoreError> {
        let audit = OperatorDecisionFields::new(
            operator,
            consistency::SagaEffectPhase::Forward,
            "confirmed_applied",
        );
        self.commit_forward_completion_inner(
            SagaStorageOperation::OperatorRepairCommit,
            &operator.lease,
            completion,
            Some(audit),
        )
        .await
    }

    async fn commit_forward_completion_inner(
        &self,
        operation: SagaStorageOperation,
        lease: &SagaLease,
        completion: SagaForwardCompletion,
        operator_audit: Option<OperatorDecisionFields>,
    ) -> Result<SagaDurableMutationOutcome, SagaDurableStoreError> {
        let progress = completion.progress();
        let (completion, _) = completion.into_parts();
        let lease_fields = LeaseFields::from(lease)
            .map_err(|error| receipt_error(SagaDurableStoreErrorKind::Integrity, error))?;
        let (scope, attempt, format, plaintext, completed_seq) = completion.into_parts();
        if lease.instance() != scope.instance() {
            return Err(receipt_error(
                SagaDurableStoreErrorKind::Integrity,
                ReceiptInvariantError("saga receipt lease scope mismatch"),
            ));
        }
        let message =
            canonical_receipt_message(&scope, attempt, format, completed_seq, plaintext.expose());
        let current_plaintext = Zeroizing::new(plaintext.expose().to_vec());
        let fingerprint = self.protection.integrity.current(&[message.as_slice()]);
        let aad = receipt_aad(&scope, format)
            .map_err(|error| receipt_error(SagaDurableStoreErrorKind::Integrity, error))?;
        let key_name = saga_receipt_key_name()
            .map_err(|error| receipt_error(SagaDurableStoreErrorKind::Protection, error))?;
        let encrypted = self
            .protection
            .key_provider
            .encrypt(key_name.clone(), plaintext, aad)
            .await
            .map_err(|error| receipt_error(SagaDurableStoreErrorKind::Protection, error))?;
        if !encrypted.key().name().ct_eq(&key_name) {
            return Err(receipt_error(
                SagaDurableStoreErrorKind::Protection,
                ReceiptInvariantError("saga receipt provider returned a foreign key reference"),
            ));
        }
        let receipt_fields = SagaReceiptInsertFields::new(
            &scope,
            attempt,
            format,
            completed_seq,
            encrypted.ciphertext().to_vec(),
            encrypted.key().to_token(),
            fingerprint,
        )
        .map_err(|error| receipt_error(SagaDurableStoreErrorKind::Integrity, error))?;
        let journal_fields = JournalEntryFields {
            seq: receipt_fields.completed_seq,
            step_name: receipt_fields.step_name.clone(),
            status: SagaJournalStatus::ForwardCompleted.as_str().to_string(),
            error_summary: None,
            attempt: receipt_fields.successful_attempt,
            effect_key: receipt_fields.effect_key.clone(),
            compensation_cause: None,
        };
        let lifecycle = if operator_audit.is_some() {
            Some(LifecycleFields::operator_forward(progress))
        } else {
            (progress == SagaForwardProgress::Succeeded).then(LifecycleFields::succeeded)
        };
        let journal_expectation = journal_fields.clone();
        let lifecycle_expectation = lifecycle.clone();
        let audit_expectation = operator_audit.clone();
        let repair_epoch = i64::try_from(lease.epoch())
            .map_err(|error| receipt_error(SagaDurableStoreErrorKind::Integrity, error))?;
        #[cfg(all(test, feature = "integration"))]
        let inject_commit_unknown = self
            .inject_commit_unknown_after_next_completion
            .swap(false, std::sync::atomic::Ordering::SeqCst);
        let attempt_result = self
            .write_pool
            .saga_write_attempt(
                infra_tenant_scope(scope.instance().tenant()),
                move |mut tx| {
                    Box::pin(async move {
                        if tx
                            .saga_has_exact_prior_intent(
                                &lease_fields,
                                &journal_fields,
                                SagaJournalStatus::ForwardIntent,
                            )
                            .await
                            .map_err(receipt_storage_error_for(
                                operation,
                                SagaStorageStage::CompletionMutation,
                            ))?
                            != Some(true)
                        {
                            let held = tx.saga_lease_is_held(&lease_fields).await.map_err(
                                receipt_storage_error_for(
                                    operation,
                                    SagaStorageStage::CompletionMutation,
                                ),
                            )?;
                            return Err(ReceiptTxError::abort(if held {
                                SagaDurableMutationOutcome::Conflict
                            } else {
                                SagaDurableMutationOutcome::LeaseLost
                            }));
                        }
                        if tx
                            .saga_insert_receipt(&lease_fields, &receipt_fields)
                            .await
                            .map_err(receipt_storage_error_for(
                                operation,
                                SagaStorageStage::CompletionMutation,
                            ))?
                        {
                            if tx
                                .saga_insert_journal(&lease_fields, &journal_fields)
                                .await
                                .map_err(receipt_storage_error_for(
                                    operation,
                                    SagaStorageStage::CompletionMutation,
                                ))?
                            {
                                if let Some(audit) = operator_audit
                                    && !tx
                                        .saga_insert_operator_decision(
                                            &lease_fields,
                                            &journal_fields,
                                            &audit,
                                        )
                                        .await
                                        .map_err(receipt_storage_error_for(
                                            operation,
                                            SagaStorageStage::CompletionMutation,
                                        ))?
                                {
                                    return Err(ReceiptTxError::abort(
                                        SagaDurableMutationOutcome::Conflict,
                                    ));
                                }
                                if let Some(lifecycle) = lifecycle
                                    && !tx
                                        .saga_apply_lifecycle(&lease_fields, &lifecycle)
                                        .await
                                        .map_err(receipt_storage_error_for(
                                            operation,
                                            SagaStorageStage::CompletionMutation,
                                        ))?
                                {
                                    return Err(ReceiptTxError::abort(
                                        SagaDurableMutationOutcome::Conflict,
                                    ));
                                }
                                #[cfg(all(test, feature = "integration"))]
                                if inject_commit_unknown {
                                    tx.saga_inject_commit_unknown_after_commit().await.map_err(
                                        receipt_storage_error_for(
                                            operation,
                                            SagaStorageStage::CompletionMutation,
                                        ),
                                    )?;
                                }
                                return Ok(SagaDurableMutationOutcome::Applied);
                            }
                            if !tx.saga_lease_is_held(&lease_fields).await.map_err(
                                receipt_storage_error_for(
                                    operation,
                                    SagaStorageStage::CompletionMutation,
                                ),
                            )? {
                                return Err(ReceiptTxError::abort(
                                    SagaDurableMutationOutcome::LeaseLost,
                                ));
                            }
                            return Err(ReceiptTxError::abort(
                                SagaDurableMutationOutcome::Conflict,
                            ));
                        }

                        if !tx.saga_lease_is_held(&lease_fields).await.map_err(
                            receipt_storage_error_for(
                                operation,
                                SagaStorageStage::CompletionMutation,
                            ),
                        )? {
                            return Err(ReceiptTxError::abort(
                                SagaDurableMutationOutcome::LeaseLost,
                            ));
                        }

                        let stored = tx
                            .saga_load_receipt(&receipt_fields.scope_fields())
                            .await
                            .map_err(receipt_storage_error_for(
                                operation,
                                SagaStorageStage::CompletionMutation,
                            ))?;
                        let journal = tx
                            .saga_load_journal_entry(
                                &InstanceFields::from(lease_fields.instance),
                                receipt_fields.completed_seq,
                            )
                            .await
                            .map_err(receipt_storage_error_for(
                                operation,
                                SagaStorageStage::CompletionMutation,
                            ))?;
                        let Some(stored) = stored else {
                            return Err(ReceiptTxError::abort(
                                SagaDurableMutationOutcome::Conflict,
                            ));
                        };
                        let exact_journal = journal.is_some_and(|row| {
                            row.step_name == journal_fields.step_name
                                && row.status == journal_fields.status
                                && row.error_summary.is_none()
                                && row.attempt == journal_fields.attempt
                                && constant_time_eq(&row.effect_key, &journal_fields.effect_key)
                        });
                        Err(ReceiptTxError::duplicate_candidate(stored, exact_journal))
                    })
                },
                receipt_storage_error_for(operation, SagaStorageStage::CompletionMutation),
            )
            .await;
        let settlement = attempt_result.settlement();
        match attempt_result.into_result() {
            Ok(outcome) => Ok(outcome),
            Err(error) if settlement == Some(LocalTxFinalStatus::CommitUnknown) => {
                let expectation = ReceiptDuplicateExpectation {
                    scope: &scope,
                    attempt,
                    format,
                    completed_seq,
                    plaintext: current_plaintext.as_slice(),
                };
                match self
                    .read_back_commit_unknown_completion(
                        operation,
                        &expectation,
                        &journal_expectation,
                        lifecycle_expectation.as_ref(),
                        audit_expectation.as_ref(),
                        repair_epoch,
                    )
                    .await?
                {
                    CommitUnknownReadback::Applied => Ok(SagaDurableMutationOutcome::Applied),
                    CommitUnknownReadback::NotApplied => Err(receipt_error(
                        SagaDurableStoreErrorKind::CommitUnknown,
                        error,
                    )),
                    CommitUnknownReadback::Integrity => Err(receipt_error(
                        SagaDurableStoreErrorKind::Integrity,
                        ReceiptInvariantError(
                            "commit-unknown read-back was partial or inconsistent",
                        ),
                    )),
                }
            }
            Err(ReceiptTxError::DuplicateCandidate { candidate })
                if settlement == Some(LocalTxFinalStatus::RolledBack) =>
            {
                let expectation = ReceiptDuplicateExpectation {
                    scope: &scope,
                    attempt,
                    format,
                    completed_seq,
                    plaintext: current_plaintext.as_slice(),
                };
                let exact_receipt = receipt_duplicate_matches(
                    &candidate.stored,
                    &expectation,
                    self.protection.key_provider.as_ref(),
                    &self.protection.integrity,
                )
                .await?;
                if exact_receipt
                    && candidate.exact_journal
                    && progress == SagaForwardProgress::Continue
                {
                    Ok(SagaDurableMutationOutcome::IdempotentDuplicate)
                } else {
                    Ok(SagaDurableMutationOutcome::Conflict)
                }
            }
            Err(ReceiptTxError::Abort { outcome })
                if settlement == Some(LocalTxFinalStatus::RolledBack) =>
            {
                Ok(outcome)
            }
            Err(error) => Err(receipt_error(SagaDurableStoreErrorKind::Storage, error)),
        }
    }

    async fn read_back_commit_unknown_completion(
        &self,
        operation: SagaStorageOperation,
        expectation: &ReceiptDuplicateExpectation<'_>,
        journal_expected: &JournalEntryFields,
        lifecycle_expected: Option<&LifecycleFields>,
        audit_expected: Option<&OperatorDecisionFields>,
        repair_epoch: i64,
    ) -> Result<CommitUnknownReadback, SagaDurableStoreError> {
        let instance = expectation.scope.instance();
        let instance_fields = InstanceFields::from(instance);
        let scope_fields = SagaReceiptScopeFields::from_scope(expectation.scope);
        let decision_seq = journal_expected.seq;
        let (instance_row, journal, receipt, audit) = self
            .read_pool
            .saga_read_map(
                infra_tenant_scope(instance.tenant()),
                move |mut conn| {
                    Box::pin(async move {
                        let instance_row = conn.saga_get_instance(&instance_fields).await.map_err(
                            storage_error_for(
                                operation,
                                SagaStorageStage::CompletionCommitUnknownReadback,
                            ),
                        )?;
                        let journal = conn
                            .saga_read_journal_entry(&instance_fields, decision_seq)
                            .await
                            .map_err(storage_error_for(
                                operation,
                                SagaStorageStage::CompletionCommitUnknownReadback,
                            ))?;
                        let receipt = conn.saga_load_receipt(&scope_fields).await.map_err(
                            storage_error_for(
                                operation,
                                SagaStorageStage::CompletionCommitUnknownReadback,
                            ),
                        )?;
                        let audit = conn
                            .saga_read_operator_decision(&instance_fields, decision_seq)
                            .await
                            .map_err(storage_error_for(
                                operation,
                                SagaStorageStage::CompletionCommitUnknownReadback,
                            ))?;
                        Ok((instance_row, journal, receipt, audit))
                    })
                },
                storage_error_for(operation, SagaStorageStage::CompletionCommitUnknownReadback),
            )
            .await?;
        let Some(instance_row) = instance_row else {
            return Ok(CommitUnknownReadback::Integrity);
        };
        if journal.is_none() && receipt.is_none() && audit.is_none() {
            return Ok(
                if commit_unknown_pre_state_matches(&instance_row, audit_expected) {
                    CommitUnknownReadback::NotApplied
                } else {
                    CommitUnknownReadback::Integrity
                },
            );
        }
        let (Some(journal), Some(receipt)) = (journal, receipt) else {
            return Ok(CommitUnknownReadback::Integrity);
        };
        let exact_receipt = receipt_duplicate_matches(
            &receipt,
            expectation,
            self.protection.key_provider.as_ref(),
            &self.protection.integrity,
        )
        .await?;
        let exact = exact_receipt
            && journal_row_matches(&journal, journal_expected)
            && lifecycle_row_matches(&instance_row, lifecycle_expected)
            && operator_audit_matches(audit.as_ref(), audit_expected, repair_epoch);
        Ok(if exact {
            CommitUnknownReadback::Applied
        } else {
            CommitUnknownReadback::Integrity
        })
    }
}

#[derive(Debug, thiserror::Error)]
enum ReceiptTxError {
    #[error("saga receipt transaction storage operation failed")]
    Storage(#[source] sqlx::Error),
    #[error("saga receipt transaction intentionally aborted")]
    Abort { outcome: SagaDurableMutationOutcome },
    #[error("saga receipt duplicate candidate requires post-rollback verification")]
    DuplicateCandidate {
        candidate: ReceiptDuplicateCandidate,
    },
}

enum CommitUnknownReadback {
    Applied,
    NotApplied,
    Integrity,
}

fn journal_row_matches(row: &SagaJournalExistingRow, expected: &JournalEntryFields) -> bool {
    row.step_name == expected.step_name
        && row.status == expected.status
        && row.error_summary == expected.error_summary
        && row.attempt == expected.attempt
        && constant_time_eq(&row.effect_key, &expected.effect_key)
        && row.compensation_cause == expected.compensation_cause
}

fn lifecycle_row_matches(row: &SagaInstanceRow, expected: Option<&LifecycleFields>) -> bool {
    if let Some(expected) = expected {
        return row.status == expected.status
            && row.operator_reason == expected.operator_reason
            && (expected.preserve_compensation_cause
                || row.compensation_cause == expected.compensation_cause);
    }
    row.status == SagaInstanceStatus::Running.as_str()
        && row.operator_reason.is_none()
        && row.compensation_cause.is_none()
}

fn commit_unknown_pre_state_matches(
    row: &SagaInstanceRow,
    audit: Option<&OperatorDecisionFields>,
) -> bool {
    audit.map_or_else(
        || {
            row.status == SagaInstanceStatus::Running.as_str()
                && row.operator_reason.is_none()
                && row.compensation_cause.is_none()
        },
        |audit| {
            row.status == SagaInstanceStatus::OperatorRequired.as_str()
                && row.operator_reason.as_deref() == Some(audit.reason.as_str())
        },
    )
}

fn operator_audit_matches(
    row: Option<&SagaOperatorDecisionRow>,
    expected: Option<&OperatorDecisionFields>,
    repair_epoch: i64,
) -> bool {
    match (row, expected) {
        (None, None) => true,
        (Some(row), Some(expected)) => {
            row.phase == expected.phase
                && row.decision == expected.decision
                && row.operator_reason == expected.reason
                && row.reason_text == expected.reason_text
                && row.operator_actor == expected.actor
                && row.change_ticket == expected.change_ticket
                && row.start_audit_id == expected.start_audit_id
                && row.repair_epoch == repair_epoch
        }
        _ => false,
    }
}

impl ReceiptTxError {
    const fn abort(outcome: SagaDurableMutationOutcome) -> Self {
        Self::Abort { outcome }
    }

    const fn duplicate_candidate(stored: SagaReceiptRow, exact_journal: bool) -> Self {
        Self::DuplicateCandidate {
            candidate: ReceiptDuplicateCandidate {
                stored,
                exact_journal,
            },
        }
    }
}

struct ReceiptDuplicateCandidate {
    stored: SagaReceiptRow,
    exact_journal: bool,
}

impl std::fmt::Debug for ReceiptDuplicateCandidate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReceiptDuplicateCandidate")
            .field("stored", &"<redacted>")
            .field("exact_journal", &self.exact_journal)
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct ReceiptInvariantError(&'static str);

fn receipt_error<E>(kind: SagaDurableStoreErrorKind, source: E) -> SagaDurableStoreError
where
    E: std::error::Error + Send + Sync + 'static,
{
    SagaDurableStoreError::new(kind, source)
}

fn saga_receipt_key_name() -> Result<KeyName, diport::KeyParseError> {
    KeyName::try_new(SAGA_RECEIPT_KEY_NAME)
}

fn receipt_aad(
    scope: &SagaReceiptScope,
    format: SagaReceiptFormatVersion,
) -> Result<secure::DerivedAad, secure::AadError> {
    let saga_id = scope.instance().saga_id().as_uuid().to_string();
    SagaReceiptProtectionContext::trusted(SagaReceiptProtectionCoordinates {
        tenant: scope.instance().tenant(),
        saga_id: &saga_id,
        owner: scope.worker().owner(),
        contract_id: scope.definition().contract_id(),
        definition_version: scope.definition().version(),
        definition_schema_digest: scope.definition().schema_digest(),
        action_registry_generation: scope.definition().action_registry_generation(),
        step_name: scope.step_name().as_str(),
        effect_key: *scope.effect_key().as_bytes(),
        receipt_schema: scope.receipt_schema(),
        format_version: u16::from(format),
    })
    .map(|context| context.derive())
}

fn canonical_receipt_message(
    scope: &SagaReceiptScope,
    attempt: SagaAttempt,
    format: SagaReceiptFormatVersion,
    completed_seq: u64,
    plaintext: &[u8],
) -> Zeroizing<Vec<u8>> {
    let tenant = scope.instance().tenant().to_string();
    let saga_id = scope.instance().saga_id().as_uuid();
    let attempt = attempt.get().to_be_bytes();
    let format = u16::from(format).to_be_bytes();
    let completed_seq = completed_seq.to_be_bytes();
    let mut message = Zeroizing::new(Vec::new());
    for component in [
        SAGA_RECEIPT_INTEGRITY_MESSAGE,
        tenant.as_bytes(),
        saga_id.as_bytes(),
        scope.worker().owner().as_bytes(),
        scope.definition().contract_id().as_bytes(),
        scope.definition().version().as_bytes(),
        scope.definition().schema_digest().as_bytes(),
        scope.definition().action_registry_generation().as_bytes(),
        scope.step_name().as_str().as_bytes(),
        scope.effect_key().as_bytes(),
        scope.receipt_schema().as_bytes(),
        &format,
        &attempt,
        &completed_seq,
        plaintext,
    ] {
        message.extend_from_slice(&(component.len() as u64).to_be_bytes());
        message.extend_from_slice(component);
    }
    message
}

fn stored_fingerprint(
    row: &SagaReceiptRow,
) -> Result<SagaReceiptFingerprint, SagaDurableStoreError> {
    let key_id = SagaReceiptIntegrityKeyId::parse(row.content_hmac_key_id.clone())
        .map_err(|error| receipt_error(SagaDurableStoreErrorKind::Integrity, error))?;
    SagaReceiptFingerprint::from_stored(key_id, row.content_hmac.clone())
        .map_err(|error| receipt_error(SagaDurableStoreErrorKind::Integrity, error))
}

async fn receipt_duplicate_matches(
    row: &SagaReceiptRow,
    expected: &ReceiptDuplicateExpectation<'_>,
    key_provider: &DynKeyProvider<'static>,
    keyring: &SagaReceiptIntegrityKeyring,
) -> Result<bool, SagaDurableStoreError> {
    let opened = open_stored_receipt(expected.scope, row, key_provider, keyring).await?;
    Ok(opened.format == expected.format
        && opened.attempt == expected.attempt
        && opened.completed_seq == expected.completed_seq
        && constant_time_eq(opened.plaintext.expose(), expected.plaintext))
}

struct ReceiptDuplicateExpectation<'a> {
    scope: &'a SagaReceiptScope,
    attempt: SagaAttempt,
    format: SagaReceiptFormatVersion,
    completed_seq: u64,
    plaintext: &'a [u8],
}

struct OpenedSagaReceipt {
    attempt: SagaAttempt,
    format: SagaReceiptFormatVersion,
    plaintext: secure::Plaintext,
    completed_seq: u64,
}

async fn open_stored_receipt(
    scope: &SagaReceiptScope,
    row: &SagaReceiptRow,
    key_provider: &DynKeyProvider<'static>,
    keyring: &SagaReceiptIntegrityKeyring,
) -> Result<OpenedSagaReceipt, SagaDurableStoreError> {
    validate_loaded_metadata(scope, row)?;
    let format = parse_receipt_format(row.format_version)?;
    let attempt = parse_receipt_attempt(row.successful_attempt)?;
    let completed_seq = parse_completed_seq(row.completed_seq)?;
    let key_ref = KeyRef::parse(&row.key_ref)
        .map_err(|error| receipt_error(SagaDurableStoreErrorKind::Integrity, error))?;
    let expected_key = saga_receipt_key_name()
        .map_err(|error| receipt_error(SagaDurableStoreErrorKind::Protection, error))?;
    if !key_ref.name().ct_eq(&expected_key) {
        return Err(receipt_error(
            SagaDurableStoreErrorKind::Integrity,
            ReceiptInvariantError("saga receipt key reference is invalid"),
        ));
    }
    let aad = receipt_aad(scope, format)
        .map_err(|error| receipt_error(SagaDurableStoreErrorKind::Integrity, error))?;
    let fingerprint = stored_fingerprint(row)?;
    let plaintext = key_provider
        .decrypt(RedactedBytes::new(row.ciphertext.clone()), key_ref, aad)
        .await
        .map_err(|error| receipt_error(SagaDurableStoreErrorKind::Protection, error))?;
    let message =
        canonical_receipt_message(scope, attempt, format, completed_seq, plaintext.expose());
    if !keyring.verify(&[message.as_slice()], &fingerprint) {
        return Err(receipt_error(
            SagaDurableStoreErrorKind::Integrity,
            ReceiptInvariantError("saga receipt keyed fingerprint mismatch"),
        ));
    }
    Ok(OpenedSagaReceipt {
        attempt,
        format,
        plaintext,
        completed_seq,
    })
}

async fn stored_receipt_from_row(
    scope: &SagaReceiptScope,
    row: &SagaReceiptRow,
    key_provider: &DynKeyProvider<'static>,
    keyring: &SagaReceiptIntegrityKeyring,
) -> Result<StoredSagaReceipt, SagaDurableStoreError> {
    if row.journal_step_name.as_deref() != Some(scope.step_name().as_str())
        || row.journal_status.as_deref() != Some(SagaJournalStatus::ForwardCompleted.as_str())
    {
        return Err(receipt_error(
            SagaDurableStoreErrorKind::Integrity,
            ReceiptInvariantError("saga receipt journal pair is invalid"),
        ));
    }
    let opened = open_stored_receipt(scope, row, key_provider, keyring).await?;
    Ok(StoredSagaReceipt::new(
        scope.clone(),
        opened.attempt,
        opened.format,
        opened.plaintext,
        opened.completed_seq,
    ))
}

fn validate_loaded_metadata(
    scope: &SagaReceiptScope,
    row: &SagaReceiptRow,
) -> Result<(), SagaDurableStoreError> {
    if row.receipt_schema != scope.receipt_schema()
        || !constant_time_eq(&row.effect_key, scope.effect_key().as_bytes())
    {
        return Err(receipt_error(
            SagaDurableStoreErrorKind::Integrity,
            ReceiptInvariantError("saga receipt durable scope mismatch"),
        ));
    }
    Ok(())
}

fn parse_receipt_format(raw: i16) -> Result<SagaReceiptFormatVersion, SagaDurableStoreError> {
    u16::try_from(raw)
        .ok()
        .and_then(|value| SagaReceiptFormatVersion::try_from(value).ok())
        .ok_or_else(|| {
            receipt_error(
                SagaDurableStoreErrorKind::UnsupportedFormat,
                ReceiptInvariantError("saga receipt format is unsupported"),
            )
        })
}

fn parse_receipt_attempt(raw: i32) -> Result<SagaAttempt, SagaDurableStoreError> {
    u32::try_from(raw)
        .ok()
        .and_then(|value| SagaAttempt::new(value).ok())
        .ok_or_else(|| {
            receipt_error(
                SagaDurableStoreErrorKind::Integrity,
                ReceiptInvariantError("saga receipt attempt is invalid"),
            )
        })
}

fn parse_completed_seq(raw: i64) -> Result<u64, SagaDurableStoreError> {
    u64::try_from(raw).map_err(|_| {
        receipt_error(
            SagaDurableStoreErrorKind::Integrity,
            ReceiptInvariantError("saga receipt completed sequence is invalid"),
        )
    })
}

#[derive(Clone)]
pub(crate) struct SagaReceiptScopeFields {
    pub(crate) instance: SagaInstanceRef,
    pub(crate) saga_id: String,
    pub(crate) owner: String,
    pub(crate) contract_id: String,
    pub(crate) definition_version: String,
    pub(crate) definition_schema_digest: String,
    pub(crate) action_registry_generation: String,
    pub(crate) step_name: String,
}

impl SagaReceiptScopeFields {
    fn from_scope(scope: &SagaReceiptScope) -> Self {
        Self {
            instance: scope.instance(),
            saga_id: scope.instance().saga_id().as_uuid().to_string(),
            owner: scope.worker().owner().to_string(),
            contract_id: scope.definition().contract_id().to_string(),
            definition_version: scope.definition().version().to_string(),
            definition_schema_digest: scope.definition().schema_digest().to_string(),
            action_registry_generation: scope.definition().action_registry_generation().to_string(),
            step_name: scope.step_name().as_str().to_string(),
        }
    }
}

pub(crate) struct SagaReceiptInsertFields {
    pub(crate) scope: SagaReceiptScopeFields,
    pub(crate) effect_key: Vec<u8>,
    pub(crate) receipt_schema: String,
    pub(crate) format_version: i16,
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) key_ref: String,
    pub(crate) content_hmac_key_id: String,
    pub(crate) content_hmac: Vec<u8>,
    pub(crate) successful_attempt: i32,
    pub(crate) completed_seq: i64,
    pub(crate) step_name: String,
}

impl SagaReceiptInsertFields {
    #[allow(clippy::too_many_arguments)]
    fn new(
        scope: &SagaReceiptScope,
        attempt: SagaAttempt,
        format: SagaReceiptFormatVersion,
        completed_seq: u64,
        ciphertext: Vec<u8>,
        key_ref: String,
        fingerprint: SagaReceiptFingerprint,
    ) -> Result<Self, ReceiptInvariantError> {
        let format_version = i16::try_from(u16::from(format))
            .map_err(|_| ReceiptInvariantError("saga receipt format overflow"))?;
        let successful_attempt = i32::try_from(attempt.get())
            .map_err(|_| ReceiptInvariantError("saga receipt attempt overflow"))?;
        let completed_seq = i64::try_from(completed_seq)
            .map_err(|_| ReceiptInvariantError("saga receipt sequence overflow"))?;
        Ok(Self {
            scope: SagaReceiptScopeFields::from_scope(scope),
            effect_key: scope.effect_key().as_bytes().to_vec(),
            receipt_schema: scope.receipt_schema().to_string(),
            format_version,
            ciphertext,
            key_ref,
            content_hmac_key_id: fingerprint.key_id().as_str().to_string(),
            content_hmac: fingerprint.as_bytes().to_vec(),
            successful_attempt,
            completed_seq,
            step_name: scope.step_name().as_str().to_string(),
        })
    }

    fn scope_fields(&self) -> SagaReceiptScopeFields {
        self.scope.clone()
    }
}

pub(crate) struct RegistrationFields {
    pub(crate) instance: SagaInstanceRef,
    pub(crate) saga_id: String,
    pub(crate) owner: String,
    pub(crate) contract_id: String,
    pub(crate) identity: SagaWorkerIdentity,
    pub(crate) definition: SagaDefinitionIdentity,
    pub(crate) definition_version: String,
    pub(crate) definition_schema_digest: String,
    pub(crate) action_registry_generation: String,
    pub(crate) start_actor: String,
    pub(crate) start_audit_id: String,
}

pub(crate) struct ClaimFields {
    pub(crate) instance: SagaInstanceRef,
    pub(crate) saga_id: String,
    pub(crate) owner: String,
    pub(crate) contract_id: String,
    pub(crate) definition_version: String,
    pub(crate) definition_schema_digest: String,
    pub(crate) action_registry_generation: String,
    pub(crate) expected_status: String,
    pub(crate) holder_id: String,
    pub(crate) ttl_micros: i64,
}

impl ClaimFields {
    fn from_request(request: &SagaClaimRequest) -> Result<Self, SagaDurableStoreError> {
        let expected = request.expected();
        Ok(Self {
            instance: expected.instance(),
            saga_id: expected.instance().saga_id().as_uuid().to_string(),
            owner: expected.identity().owner().to_string(),
            contract_id: expected.identity().contract_id().as_str().to_string(),
            definition_version: expected.definition().version().to_string(),
            definition_schema_digest: expected.definition().schema_digest().to_string(),
            action_registry_generation: expected
                .definition()
                .action_registry_generation()
                .to_string(),
            expected_status: expected.status().as_str().to_string(),
            holder_id: request.holder_id().to_string(),
            ttl_micros: duration_micros(request.ttl())?,
        })
    }
}

impl RegistrationFields {
    fn authorized(
        authorization: SagaStartAuthorization,
        registration: SagaInstanceRegistration,
    ) -> Self {
        let instance = registration.instance();
        let definition = registration.definition().clone();
        let identity = registration.identity().clone();
        Self {
            instance,
            saga_id: instance.saga_id().as_uuid().to_string(),
            owner: identity.owner().to_string(),
            contract_id: identity.contract_id().as_str().to_string(),
            identity,
            definition_version: definition.version().to_string(),
            definition_schema_digest: definition.schema_digest().to_string(),
            action_registry_generation: definition.action_registry_generation().to_string(),
            start_actor: authorization.caller().as_str().to_string(),
            start_audit_id: authorization.start_audit_id().as_str().to_string(),
            definition,
        }
    }
}

#[cfg(all(test, feature = "integration"))]
impl From<SagaInstanceRegistration> for RegistrationFields {
    fn from(registration: SagaInstanceRegistration) -> Self {
        let instance = registration.instance();
        let definition = registration.definition().clone();
        let identity = registration.identity().clone();
        Self {
            instance,
            saga_id: instance.saga_id().as_uuid().to_string(),
            owner: identity.owner().to_string(),
            contract_id: identity.contract_id().as_str().to_string(),
            identity,
            definition_version: definition.version().to_string(),
            definition_schema_digest: definition.schema_digest().to_string(),
            action_registry_generation: definition.action_registry_generation().to_string(),
            start_actor: "integration-mismatch-proof".to_string(),
            start_audit_id: "integration-mismatch-proof".to_string(),
            definition,
        }
    }
}

#[derive(Clone)]
pub(crate) struct InstanceFields {
    pub(crate) instance: SagaInstanceRef,
    pub(crate) saga_id: String,
}

impl From<SagaInstanceRef> for InstanceFields {
    fn from(instance: SagaInstanceRef) -> Self {
        Self {
            instance,
            saga_id: instance.saga_id().as_uuid().to_string(),
        }
    }
}

pub(crate) struct LeaseFields {
    pub(crate) instance: SagaInstanceRef,
    pub(crate) saga_id: String,
    pub(crate) lease_token: String,
    pub(crate) epoch: i64,
}

impl LeaseFields {
    fn from(lease: &SagaLease) -> Result<Self, InvariantError> {
        Ok(Self {
            instance: lease.instance(),
            saga_id: lease.instance().saga_id().as_uuid().to_string(),
            lease_token: lease.lease_token().to_string(),
            epoch: i64::try_from(lease.epoch())
                .map_err(|_| InvariantError("lease epoch overflow"))?,
        })
    }
}

#[derive(Clone)]
pub(crate) struct JournalEntryFields {
    pub(crate) seq: i64,
    pub(crate) step_name: String,
    pub(crate) status: String,
    pub(crate) error_summary: Option<String>,
    pub(crate) attempt: i32,
    pub(crate) effect_key: Vec<u8>,
    pub(crate) compensation_cause: Option<String>,
}

#[derive(Clone)]
pub(crate) struct OperatorDecisionFields {
    pub(crate) reason: String,
    pub(crate) reason_text: String,
    pub(crate) phase: String,
    pub(crate) decision: String,
    pub(crate) actor: String,
    pub(crate) change_ticket: String,
    pub(crate) start_audit_id: String,
}

impl OperatorDecisionFields {
    fn new(
        claim: &PgSagaOperatorClaim,
        phase: consistency::SagaEffectPhase,
        decision: &'static str,
    ) -> Self {
        Self {
            reason: claim
                .expected_reason()
                .as_operator_reason()
                .as_str()
                .to_string(),
            reason_text: claim
                .authorization
                .evidence()
                .reason_text()
                .as_str()
                .to_string(),
            phase: phase.as_str().to_string(),
            decision: decision.to_string(),
            actor: claim.authorization.caller().as_str().to_string(),
            change_ticket: claim
                .authorization
                .evidence()
                .change_ticket()
                .as_str()
                .to_string(),
            start_audit_id: claim.authorization.start_audit_id().as_str().to_string(),
        }
    }
}

impl JournalEntryFields {
    fn new(
        seq: u64,
        step: &StepName,
        status: SagaJournalStatus,
        attempt: SagaAttempt,
        effect_key: &consistency::SagaIdempotencyKey,
        error_summary: Option<&'static str>,
        compensation_cause: Option<SagaCompensationCause>,
    ) -> Result<Self, SagaDurableStoreError> {
        Ok(Self {
            seq: i64::try_from(seq)
                .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))?,
            step_name: step.as_str().to_string(),
            status: status.as_str().to_string(),
            error_summary: error_summary.map(str::to_string),
            attempt: i32::try_from(attempt.get())
                .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))?,
            effect_key: effect_key.as_bytes().to_vec(),
            compensation_cause: compensation_cause
                .map(|compensation_cause| compensation_cause.as_str().to_string()),
        })
    }
}

#[derive(Clone)]
pub(crate) struct LifecycleFields {
    pub(crate) status: String,
    pub(crate) operator_reason: Option<String>,
    pub(crate) compensation_cause: Option<String>,
    pub(crate) clear_lease: bool,
    pub(crate) expected_statuses: Vec<String>,
    pub(crate) preserve_compensation_cause: bool,
}

impl LifecycleFields {
    fn succeeded() -> Self {
        Self::terminal(SagaInstanceStatus::Succeeded, None)
    }

    fn compensating(cause: SagaCompensationCause) -> Self {
        Self {
            status: SagaInstanceStatus::Compensating.as_str().to_string(),
            operator_reason: None,
            compensation_cause: Some(cause.as_str().to_string()),
            clear_lease: false,
            expected_statuses: vec![
                SagaInstanceStatus::Running.as_str().to_string(),
                SagaInstanceStatus::Compensating.as_str().to_string(),
            ],
            preserve_compensation_cause: false,
        }
    }

    fn compensating_existing() -> Self {
        Self {
            status: SagaInstanceStatus::Compensating.as_str().to_string(),
            operator_reason: None,
            compensation_cause: None,
            clear_lease: false,
            expected_statuses: vec![SagaInstanceStatus::Compensating.as_str().to_string()],
            preserve_compensation_cause: true,
        }
    }

    fn terminal(status: SagaInstanceStatus, cause: Option<SagaCompensationCause>) -> Self {
        Self {
            status: status.as_str().to_string(),
            operator_reason: None,
            compensation_cause: cause.map(|cause| cause.as_str().to_string()),
            clear_lease: true,
            expected_statuses: match status {
                SagaInstanceStatus::Succeeded => {
                    vec![SagaInstanceStatus::Running.as_str().to_string()]
                }
                _ => vec![SagaInstanceStatus::Compensating.as_str().to_string()],
            },
            preserve_compensation_cause: !matches!(status, SagaInstanceStatus::Succeeded)
                && cause.is_none(),
        }
    }

    fn operator_required(reason: SagaOperatorReason) -> Self {
        let compensation_unknown = reason == SagaOperatorReason::CompensationOutcomeUnknown;
        Self {
            status: SagaInstanceStatus::OperatorRequired.as_str().to_string(),
            operator_reason: Some(reason.as_str().to_string()),
            compensation_cause: None,
            clear_lease: true,
            expected_statuses: vec![
                if compensation_unknown {
                    SagaInstanceStatus::Compensating
                } else {
                    SagaInstanceStatus::Running
                }
                .as_str()
                .to_string(),
            ],
            preserve_compensation_cause: compensation_unknown,
        }
    }

    fn degraded() -> Self {
        Self {
            status: SagaInstanceStatus::Degraded.as_str().to_string(),
            operator_reason: None,
            compensation_cause: None,
            clear_lease: true,
            expected_statuses: vec![
                SagaInstanceStatus::Running.as_str().to_string(),
                SagaInstanceStatus::Compensating.as_str().to_string(),
            ],
            preserve_compensation_cause: false,
        }
    }

    fn operator_forward(progress: SagaForwardProgress) -> Self {
        Self {
            status: match progress {
                SagaForwardProgress::Continue => SagaInstanceStatus::Running,
                SagaForwardProgress::Succeeded => SagaInstanceStatus::Succeeded,
                _ => SagaInstanceStatus::Degraded,
            }
            .as_str()
            .to_string(),
            operator_reason: None,
            compensation_cause: None,
            clear_lease: true,
            expected_statuses: vec![SagaInstanceStatus::OperatorRequired.as_str().to_string()],
            preserve_compensation_cause: false,
        }
    }

    fn operator_forward_not_applied() -> Self {
        Self::operator_forward(SagaForwardProgress::Continue)
    }

    fn operator_compensation(
        progress: SagaCompensationProgress,
        cause: Option<SagaCompensationCause>,
    ) -> Self {
        let status = match progress {
            SagaCompensationProgress::Continue => SagaInstanceStatus::Compensating,
            SagaCompensationProgress::Compensated => SagaInstanceStatus::Compensated,
            SagaCompensationProgress::Expired => SagaInstanceStatus::Expired,
            _ => SagaInstanceStatus::Degraded,
        };
        Self {
            status: status.as_str().to_string(),
            operator_reason: None,
            compensation_cause: cause.map(|cause| cause.as_str().to_string()),
            clear_lease: true,
            expected_statuses: vec![SagaInstanceStatus::OperatorRequired.as_str().to_string()],
            preserve_compensation_cause: cause.is_none(),
        }
    }
}

fn duration_micros(ttl: SagaLeaseTtl) -> Result<i64, SagaDurableStoreError> {
    i64::try_from(ttl.as_micros())
        .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))
}

fn parse_instance_status(raw: &str) -> Result<SagaInstanceStatus, SagaDurableStoreError> {
    SagaInstanceStatus::parse(raw).ok_or_else(|| {
        saga_error(
            SagaDurableStoreErrorKind::Integrity,
            InvariantError("invalid saga instance status"),
        )
    })
}

fn instance_from_row(
    instance: SagaInstanceRef,
    row: &SagaInstanceRow,
) -> Result<SagaInstanceRecord, SagaDurableStoreError> {
    let identity = parse_worker_identity(&row.owner, &row.contract_id)?;
    let definition = parse_definition_identity(
        &row.contract_id,
        &row.definition_version,
        &row.definition_schema_digest,
        &row.action_registry_generation,
    )?;
    let status = parse_instance_status(&row.status)?;
    let record = SagaInstanceRecord::new(instance, status, identity, definition)
        .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
    match parse_optional_operator_reason(row.operator_reason.as_deref())? {
        Some(reason) => record
            .with_operator_reason(reason)
            .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error)),
        None => Ok(record),
    }
}

fn journal_from_row(row: SagaJournalRow) -> Result<SagaJournalRecord, SagaDurableStoreError> {
    let seq = u64::try_from(row.seq)
        .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
    let step = StepName::parse(&row.step_name)
        .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
    let status = SagaJournalStatus::parse(&row.status).ok_or_else(|| {
        saga_error(
            SagaDurableStoreErrorKind::Integrity,
            InvariantError("invalid saga journal status"),
        )
    })?;
    Ok(SagaJournalRecord::replayed(seq, step, status))
}

fn parse_optional_operator_reason(
    raw: Option<&str>,
) -> Result<Option<SagaOperatorReason>, SagaDurableStoreError> {
    raw.map(|raw| {
        SagaOperatorReason::parse(raw).ok_or_else(|| {
            saga_error(
                SagaDurableStoreErrorKind::Integrity,
                InvariantError("invalid saga operator reason"),
            )
        })
    })
    .transpose()
}

fn parse_optional_compensation_cause(
    raw: Option<&str>,
) -> Result<Option<SagaCompensationCause>, SagaDurableStoreError> {
    raw.map(|raw| {
        SagaCompensationCause::parse(raw).ok_or_else(|| {
            saga_error(
                SagaDurableStoreErrorKind::Integrity,
                InvariantError("invalid saga compensation cause"),
            )
        })
    })
    .transpose()
}

fn classify_storage_error(error: &sqlx::Error) -> SagaStorageErrorClass {
    match error {
        sqlx::Error::Database(_) => {
            if crate::tx_retry::classify_sqlx_error(error) == consistency::TxRetryClass::Transient {
                SagaStorageErrorClass::DatabaseTransient
            } else {
                SagaStorageErrorClass::DatabasePermanent
            }
        }
        sqlx::Error::Io(_) => SagaStorageErrorClass::Io,
        sqlx::Error::Tls(_) => SagaStorageErrorClass::Tls,
        sqlx::Error::Protocol(_) => SagaStorageErrorClass::Protocol,
        sqlx::Error::PoolTimedOut => SagaStorageErrorClass::PoolTimedOut,
        sqlx::Error::PoolClosed => SagaStorageErrorClass::PoolClosed,
        sqlx::Error::WorkerCrashed => SagaStorageErrorClass::WorkerCrashed,
        sqlx::Error::Configuration(_) => SagaStorageErrorClass::Configuration,
        sqlx::Error::RowNotFound
        | sqlx::Error::TypeNotFound { .. }
        | sqlx::Error::ColumnIndexOutOfBounds { .. }
        | sqlx::Error::ColumnNotFound(_)
        | sqlx::Error::ColumnDecode { .. }
        | sqlx::Error::Encode(_)
        | sqlx::Error::Decode(_)
        | sqlx::Error::AnyDriverError(_) => SagaStorageErrorClass::DataMapping,
        _ => SagaStorageErrorClass::OtherPermanent,
    }
}

fn record_storage_error(
    operation: SagaStorageOperation,
    stage: SagaStorageStage,
    context: Option<&SagaDiagnosticContext>,
    error: &sqlx::Error,
) {
    let sqlstate = error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .filter(|code| is_safe_sqlstate(code.as_ref()));
    let sqlstate = sqlstate.as_deref().unwrap_or("none");
    let error_class = classify_storage_error(error);
    let tenant = context
        .map(|context| context.tenant.to_string())
        .unwrap_or_else(|| "none".to_owned());
    let owner = context
        .and_then(|context| context.owner.as_deref())
        .unwrap_or("none");
    let contract = context
        .and_then(|context| context.contract.as_deref())
        .unwrap_or("none");
    if error_class.is_transient() {
        record_transient_storage_error(
            operation,
            stage,
            error_class,
            sqlstate,
            &tenant,
            owner,
            contract,
        );
    } else {
        record_permanent_storage_error(
            operation,
            stage,
            error_class,
            sqlstate,
            &tenant,
            owner,
            contract,
        );
    }
}

fn record_transient_storage_error(
    operation: SagaStorageOperation,
    stage: SagaStorageStage,
    error_class: SagaStorageErrorClass,
    sqlstate: &str,
    tenant: &str,
    owner: &str,
    contract: &str,
) {
    tracing::warn!(
        target: "postgres",
        operation = operation.as_label(),
        stage = stage.as_label(),
        error_class = error_class.as_label(),
        severity = "warn",
        sqlstate,
        tenant,
        owner,
        contract,
        "saga durable storage operation failed"
    );
}

fn record_permanent_storage_error(
    operation: SagaStorageOperation,
    stage: SagaStorageStage,
    error_class: SagaStorageErrorClass,
    sqlstate: &str,
    tenant: &str,
    owner: &str,
    contract: &str,
) {
    tracing::error!(
        target: "postgres",
        operation = operation.as_label(),
        stage = stage.as_label(),
        error_class = error_class.as_label(),
        severity = "error",
        sqlstate,
        tenant,
        owner,
        contract,
        "saga durable storage operation failed"
    );
}

fn is_safe_sqlstate(code: &str) -> bool {
    code.len() == 5
        && code
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

pub(crate) fn storage_error(
    stage: SagaStorageStage,
) -> impl Fn(sqlx::Error) -> SagaDurableStoreError + Copy {
    move |error| {
        record_storage_error(stage.operation(), stage, None, &error);
        saga_error(SagaDurableStoreErrorKind::Storage, error)
    }
}

fn storage_error_for(
    operation: SagaStorageOperation,
    stage: SagaStorageStage,
) -> impl Fn(sqlx::Error) -> SagaDurableStoreError + Copy {
    move |error| {
        record_storage_error(operation, stage, None, &error);
        saga_error(SagaDurableStoreErrorKind::Storage, error)
    }
}

fn storage_error_with_context(
    operation: SagaStorageOperation,
    stage: SagaStorageStage,
    context: SagaDiagnosticContext,
) -> impl Fn(sqlx::Error) -> SagaDurableStoreError + Clone {
    move |error| {
        record_storage_error(operation, stage, Some(&context), &error);
        saga_error(SagaDurableStoreErrorKind::Storage, error)
    }
}

fn mutation_storage_error(
    stage: SagaStorageStage,
) -> impl Fn(sqlx::Error) -> MutationTxError + Copy {
    move |error| {
        record_storage_error(stage.operation(), stage, None, &error);
        MutationTxError::Storage(error)
    }
}

fn mutation_storage_error_for(
    operation: SagaStorageOperation,
    stage: SagaStorageStage,
) -> impl Fn(sqlx::Error) -> MutationTxError + Copy {
    move |error| {
        record_storage_error(operation, stage, None, &error);
        MutationTxError::Storage(error)
    }
}

fn receipt_storage_error_for(
    operation: SagaStorageOperation,
    stage: SagaStorageStage,
) -> impl Fn(sqlx::Error) -> ReceiptTxError + Copy {
    move |error| {
        record_storage_error(operation, stage, None, &error);
        ReceiptTxError::Storage(error)
    }
}

fn saga_error<E>(kind: SagaDurableStoreErrorKind, source: E) -> SagaDurableStoreError
where
    E: std::error::Error + Send + Sync + 'static,
{
    SagaDurableStoreError::new(kind, source)
}

fn runnable_from_row(
    tenant: vocab::TenantId,
    row: SagaRunnableRow,
) -> Result<SagaRunnableInstance, SagaDurableStoreError> {
    let saga_id = uuid::Uuid::parse_str(&row.saga_id)
        .map(SagaId::new)
        .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
    let instance = SagaInstanceRef::new(tenant, saga_id)
        .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
    let status = parse_instance_status(&row.status)?;
    let identity = parse_worker_identity(&row.owner, &row.contract_id)?;
    let definition = parse_definition_identity(
        &row.contract_id,
        &row.definition_version,
        &row.definition_schema_digest,
        &row.action_registry_generation,
    )?;
    SagaRunnableInstance::new(instance, status, identity, definition)
        .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))
}

fn operator_identity_matches(row: &SagaOperatorStatusRow, expected: &SagaWorkerIdentity) -> bool {
    row.owner == expected.owner() && row.contract_id == expected.contract_id().as_str()
}

fn operator_status_snapshot(
    instance: SagaInstanceRef,
    row: &SagaOperatorStatusRow,
) -> Result<SagaOperatorStatusSnapshot, SagaDurableStoreError> {
    let instance_row = SagaInstanceRow {
        owner: row.owner.clone(),
        contract_id: row.contract_id.clone(),
        definition_version: row.definition_version.clone(),
        definition_schema_digest: row.definition_schema_digest.clone(),
        action_registry_generation: row.action_registry_generation.clone(),
        status: row.status.clone(),
        operator_reason: row.operator_reason.clone(),
        compensation_cause: row.compensation_cause.clone(),
        start_actor: row.start_actor.clone(),
        start_audit_id: row.start_audit_id.clone(),
    };
    let unresolved_at = row
        .unresolved_at_epoch_seconds
        .map(|seconds| {
            u64::try_from(seconds).map(|seconds| {
                std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(seconds)
            })
        })
        .transpose()
        .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
    Ok(SagaOperatorStatusSnapshot::new(
        instance_from_row(instance, &instance_row)?,
        operator_latest_journal(row)?,
        row.has_effect_intent,
        unresolved_at,
    ))
}

fn operator_latest_journal(
    row: &SagaOperatorStatusRow,
) -> Result<Option<SagaOperatorJournalExpectation>, SagaDurableStoreError> {
    let (seq, step_name, status, attempt, effect_key) = match (
        row.latest_seq,
        row.latest_step_name.as_deref(),
        row.latest_status.as_deref(),
        row.latest_attempt,
        row.latest_effect_key.as_deref(),
    ) {
        (None, None, None, None, None) => return Ok(None),
        (Some(seq), Some(step_name), Some(status), Some(attempt), Some(effect_key)) => {
            (seq, step_name, status, attempt, effect_key)
        }
        _ => {
            return Err(saga_error(
                SagaDurableStoreErrorKind::Integrity,
                InvariantError("partial saga operator journal projection"),
            ));
        }
    };
    let seq = u64::try_from(seq)
        .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
    let step_name = StepName::parse(step_name)
        .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
    let status = SagaJournalStatus::parse(status).ok_or_else(|| {
        saga_error(
            SagaDurableStoreErrorKind::Integrity,
            InvariantError("invalid saga operator journal status"),
        )
    })?;
    let phase = match status {
        SagaJournalStatus::ForwardIntent
        | SagaJournalStatus::ForwardCompleted
        | SagaJournalStatus::ForwardNotApplied => SagaEffectPhase::Forward,
        SagaJournalStatus::CompensationIntent
        | SagaJournalStatus::CompensationCompleted
        | SagaJournalStatus::CompensationNotApplied
        | SagaJournalStatus::CompensationFailed => SagaEffectPhase::Compensation,
        _ => {
            return Err(saga_error(
                SagaDurableStoreErrorKind::Integrity,
                InvariantError("unsupported saga operator journal status"),
            ));
        }
    };
    let attempt = u32::try_from(attempt)
        .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
    let attempt = SagaAttempt::new(attempt)
        .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
    let effect_key: [u8; 32] = effect_key.try_into().map_err(|_| {
        saga_error(
            SagaDurableStoreErrorKind::Integrity,
            InvariantError("invalid saga operator effect key width"),
        )
    })?;
    SagaOperatorJournalExpectation::new(
        SagaJournalRecord::replayed(seq, step_name, status),
        attempt,
        SagaIdempotencyKey::from_storage(effect_key, phase),
    )
    .map(Some)
    .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))
}

fn operator_latest_matches(
    row: &SagaOperatorStatusRow,
    expected: &SagaOperatorJournalExpectation,
) -> bool {
    row.latest_seq == i64::try_from(expected.record().seq()).ok()
        && row.latest_step_name.as_deref() == Some(expected.record().step_name().as_str())
        && row.latest_status.as_deref() == Some(expected.record().status().as_str())
        && row.latest_attempt == i32::try_from(expected.attempt().get()).ok()
        && row.latest_effect_key.as_deref() == Some(expected.effect_key().as_bytes().as_slice())
}

fn classify_retry_rejection(
    authorization: &SagaOperatorAuthorization<saga_operator_action::RetryCompensation>,
    row: &SagaOperatorStatusRow,
) -> Result<SagaOperatorCasOutcome, SagaDurableStoreError> {
    if !operator_identity_matches(row, authorization.identity()) {
        return Ok(SagaOperatorCasOutcome::IdentityConflict);
    }
    let status = parse_instance_status(&row.status)?;
    if status != SagaInstanceStatus::CompensationFailed {
        return Ok(SagaOperatorCasOutcome::StaleStatus(status));
    }
    if row.lease_busy {
        return Ok(SagaOperatorCasOutcome::Busy);
    }
    if !operator_latest_matches(row, authorization.evidence().journal()) {
        return Ok(SagaOperatorCasOutcome::StaleJournal);
    }
    Ok(SagaOperatorCasOutcome::StaleJournal)
}

const fn operator_cas_from_mutation(outcome: SagaDurableMutationOutcome) -> SagaOperatorCasOutcome {
    match outcome {
        SagaDurableMutationOutcome::Applied => SagaOperatorCasOutcome::Applied,
        SagaDurableMutationOutcome::LeaseLost => SagaOperatorCasOutcome::LeaseLost,
        SagaDurableMutationOutcome::IdempotentDuplicate | SagaDurableMutationOutcome::Conflict => {
            SagaOperatorCasOutcome::StaleJournal
        }
        _ => SagaOperatorCasOutcome::StaleJournal,
    }
}

fn parse_worker_identity(
    owner: &str,
    contract_id: &str,
) -> Result<SagaWorkerIdentity, SagaDurableStoreError> {
    let contract_id = SagaContractId::parse(contract_id)
        .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
    SagaWorkerIdentity::new(owner, contract_id)
        .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))
}

fn parse_definition_identity(
    contract_id: &str,
    version: &str,
    schema_digest: &str,
    action_generation: &str,
) -> Result<SagaDefinitionIdentity, SagaDurableStoreError> {
    SagaDefinitionIdentity::new(contract_id, version, schema_digest, action_generation)
        .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))
}

fn lease_from_row(
    instance: SagaInstanceRef,
    holder_id: String,
    token: String,
    epoch: i64,
) -> Result<SagaLease, InvariantError> {
    let token = uuid::Uuid::parse_str(&token).map_err(|_| InvariantError("invalid lease token"))?;
    let epoch = u64::try_from(epoch).map_err(|_| InvariantError("invalid lease epoch"))?;
    SagaLease::new(instance, holder_id, token, epoch)
        .map_err(|_| InvariantError("invalid saga lease row"))
}

#[derive(Debug)]
struct InvariantError(&'static str);

impl std::fmt::Display for InvariantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for InvariantError {}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::collections::BTreeMap;
    use std::fmt;
    use std::sync::{Arc, Mutex};

    use sqlx::error::{DatabaseError, ErrorKind};
    use tracing::field::Visit;
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Metadata, Subscriber};

    use super::{
        SagaDiagnosticContext, SagaStorageOperation, SagaStorageStage, classify_storage_error,
        storage_error, storage_error_for, storage_error_with_context,
    };

    const CANARY: &str = "postgres://operator:canary-secret@database/saga";

    #[derive(Debug)]
    struct FakeDatabaseError {
        code: &'static str,
    }

    impl fmt::Display for FakeDatabaseError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(CANARY)
        }
    }

    impl std::error::Error for FakeDatabaseError {}

    impl DatabaseError for FakeDatabaseError {
        fn message(&self) -> &str {
            CANARY
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

    #[derive(Default)]
    struct CapturedFields(BTreeMap<String, String>);

    impl Visit for CapturedFields {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.insert(field.name().to_owned(), value.to_owned());
        }

        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
            self.0.insert(field.name().to_owned(), format!("{value:?}"));
        }
    }

    #[derive(Clone, Default)]
    struct StorageEventCapture {
        records: Arc<Mutex<Vec<BTreeMap<String, String>>>>,
    }

    impl Subscriber for StorageEventCapture {
        fn enabled(&self, metadata: &Metadata<'_>) -> bool {
            matches!(
                *metadata.level(),
                tracing::Level::WARN | tracing::Level::ERROR
            )
        }

        fn new_span(&self, _: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }

        fn record(&self, _: &Id, _: &Record<'_>) {}

        fn record_follows_from(&self, _: &Id, _: &Id) {}

        fn event(&self, event: &Event<'_>) {
            let mut fields = CapturedFields::default();
            event.record(&mut fields);
            self.records
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(fields.0);
        }

        fn enter(&self, _: &Id) {}

        fn exit(&self, _: &Id) {}
    }

    #[test]
    fn storage_stage_labels_are_closed_and_stable() {
        let stages = [
            (SagaStorageStage::Register, "register"),
            (SagaStorageStage::Get, "get"),
            (SagaStorageStage::ListRunnable, "list_runnable"),
            (
                SagaStorageStage::ListCandidateTenants,
                "list_candidate_tenants",
            ),
            (SagaStorageStage::ObserveUnresolved, "observe_unresolved"),
            (SagaStorageStage::Claim, "claim"),
            (SagaStorageStage::LeaseMutation, "lease_mutation"),
            (SagaStorageStage::JournalMutation, "journal_mutation"),
            (
                SagaStorageStage::JournalCommitUnknownReadback,
                "journal_commit_unknown_readback",
            ),
            (SagaStorageStage::LifecycleMutation, "lifecycle_mutation"),
            (SagaStorageStage::RecoverySnapshot, "recovery_snapshot"),
            (SagaStorageStage::TerminalReceipt, "terminal_receipt"),
            (SagaStorageStage::CompletionMutation, "completion_mutation"),
            (
                SagaStorageStage::CompletionCommitUnknownReadback,
                "completion_commit_unknown_readback",
            ),
            (SagaStorageStage::OperatorStatus, "operator_status"),
            (
                SagaStorageStage::OperatorRetryCompensation,
                "operator_retry_compensation",
            ),
            (
                SagaStorageStage::OperatorRepairClaim,
                "operator_repair_claim",
            ),
        ];

        for (stage, label) in stages {
            assert_eq!(stage.as_label(), label);
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn storage_diagnostic_has_exact_safe_fields_and_redacts_source() {
        let capture = StorageEventCapture::default();
        let records = Arc::clone(&capture.records);
        let dispatch = tracing::Dispatch::new(capture);
        let _guard = tracing::dispatcher::set_default(&dispatch);

        let tenant = vocab::TenantId::parse("00000000-0000-0000-0000-000000000123")
            .expect("tenant fixture is valid");
        let instance = consistency::SagaInstanceRef::new(
            tenant,
            consistency::SagaId::new(
                uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000456")
                    .expect("saga fixture is valid"),
            ),
        )
        .expect("instance fixture is valid");
        let identity = diport::SagaWorkerIdentity::new(
            "billing",
            diport::SagaContractId::parse("billing.checkout").expect("contract fixture is valid"),
        )
        .expect("worker fixture is valid");
        let error = storage_error_with_context(
            SagaStorageOperation::Register,
            SagaStorageStage::Register,
            SagaDiagnosticContext::for_worker(instance, &identity),
        )(sqlx::Error::Database(Box::new(FakeDatabaseError {
            code: "42501",
        })));

        assert_eq!(error.kind(), diport::SagaDurableStoreErrorKind::Storage);
        assert!(!format!("{error:?}").contains(CANARY));
        assert!(!error.to_string().contains(CANARY));

        let records = records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fields = records.first().expect("storage failure is logged");
        assert_eq!(
            fields.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "contract",
                "error_class",
                "message",
                "operation",
                "owner",
                "severity",
                "sqlstate",
                "stage",
                "tenant"
            ]
        );
        assert_eq!(
            fields.get("operation").map(|value| value.trim_matches('"')),
            Some("register")
        );
        assert_eq!(
            fields.get("owner").map(|value| value.trim_matches('"')),
            Some("billing")
        );
        assert_eq!(
            fields.get("contract").map(|value| value.trim_matches('"')),
            Some("billing.checkout")
        );
        assert_eq!(
            fields.get("tenant").map(|value| value.trim_matches('"')),
            Some("00000000-0000-0000-0000-000000000123")
        );
        assert_eq!(
            fields.get("stage").map(|value| value.trim_matches('"')),
            Some("register")
        );
        assert_eq!(
            fields.get("sqlstate").map(|value| value.trim_matches('"')),
            Some("42501")
        );
        assert_eq!(
            fields
                .get("error_class")
                .map(|value| value.trim_matches('"')),
            Some("database_permanent")
        );
        assert_eq!(
            fields.get("severity").map(|value| value.trim_matches('"')),
            Some("error")
        );
        assert!(
            !fields.values().any(|value| value.contains(CANARY)),
            "database source must remain redacted"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn storage_diagnostic_rejects_non_sqlstate_provider_codes() {
        let capture = StorageEventCapture::default();
        let records = Arc::clone(&capture.records);
        let dispatch = tracing::Dispatch::new(capture);
        let _guard = tracing::dispatcher::set_default(&dispatch);

        let _ = storage_error(SagaStorageStage::ObserveUnresolved)(sqlx::Error::Database(
            Box::new(FakeDatabaseError { code: CANARY }),
        ));

        let records = records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fields = records.first().expect("storage failure is logged");
        assert_eq!(
            fields.get("sqlstate").map(|value| value.trim_matches('"')),
            Some("none")
        );
        assert!(
            !fields.values().any(|value| value.contains(CANARY)),
            "invalid provider code must remain redacted"
        );
    }

    #[test]
    fn storage_error_classes_cover_non_database_provider_failures() {
        let cases = [
            (sqlx::Error::PoolTimedOut, "pool_timed_out", true),
            (sqlx::Error::PoolClosed, "pool_closed", false),
            (sqlx::Error::Protocol(CANARY.to_owned()), "protocol", false),
            (sqlx::Error::Io(std::io::Error::other(CANARY)), "io", true),
            (
                sqlx::Error::Tls(Box::new(std::io::Error::other(CANARY))),
                "tls",
                false,
            ),
        ];
        for (error, label, transient) in cases {
            let class = classify_storage_error(&error);
            assert_eq!(class.as_label(), label);
            assert_eq!(class.is_transient(), transient);
        }

        let transient_database =
            sqlx::Error::Database(Box::new(FakeDatabaseError { code: "08006" }));
        let class = classify_storage_error(&transient_database);
        assert_eq!(class.as_label(), "database_transient");
        assert!(class.is_transient());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn operator_repair_commit_keeps_outer_operation_across_inner_stage() {
        let capture = StorageEventCapture::default();
        let records = Arc::clone(&capture.records);
        let dispatch = tracing::Dispatch::new(capture);
        let _guard = tracing::dispatcher::set_default(&dispatch);

        let _ = storage_error_for(
            SagaStorageOperation::OperatorRepairCommit,
            SagaStorageStage::CompletionMutation,
        )(sqlx::Error::PoolTimedOut);

        let records = records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fields = records.first().expect("storage failure is logged");
        assert_eq!(
            fields.get("operation").map(|value| value.trim_matches('"')),
            Some("operator_repair_commit")
        );
        assert_eq!(
            fields.get("stage").map(|value| value.trim_matches('"')),
            Some("completion_mutation")
        );
    }
}
