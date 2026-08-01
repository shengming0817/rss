//! PostgreSQL implementation of the closed durable Saga writer and recovery boundary.

use std::num::NonZeroUsize;
use std::sync::Arc;

use consistency::{
    LocalTxFinalStatus, SagaAttempt, SagaCompensationCause, SagaDefinitionIdentity, SagaId,
    SagaInstanceRecord, SagaInstanceRef, SagaInstanceStatus, SagaJournalRecord, SagaJournalStatus,
    SagaLease, SagaLeaseOutcome, SagaOperatorReason, SagaReceiptFormatVersion, SagaReceiptScope,
};
use diport::{
    DynKeyProvider, KeyName, KeyProvider, KeyRef, RedactedBytes, SagaClaimOutcome,
    SagaClaimRequest, SagaCompensationProgress, SagaContractId, SagaDurableMutation,
    SagaDurableMutationOutcome, SagaDurableStore, SagaDurableStoreError, SagaDurableStoreErrorKind,
    SagaForwardCompletion, SagaForwardProgress, SagaInstanceRegistration, SagaLeaseHolder,
    SagaLeaseTtl, SagaOperatorClaim, SagaOperatorClaimOutcome, SagaOperatorInspectionAuthorization,
    SagaOperatorRepair, SagaOperatorRepairAuthorization, SagaOperatorRequiredInstance,
    SagaOperatorStore, SagaRecoveryOutcome, SagaRecoveryRequest, SagaRecoverySnapshot,
    SagaRunnableInstance, SagaTenantCursor, SagaTenantPage, SagaTenantSource,
    SagaTerminalReceiptOutcome, SagaTerminalReceiptRequest, SagaUnresolvedState,
    SagaVerifiedTerminalReceipt, SagaWorkerIdentity, StoredSagaReceipt,
};
use primitives::constant_time_eq;
use secure::{
    SagaReceiptFingerprint, SagaReceiptIntegrityKeyId, SagaReceiptIntegrityKeyring,
    SagaReceiptProtectionContext, SagaReceiptProtectionCoordinates,
};
use vocab::StepName;
use zeroize::Zeroizing;

#[cfg(all(test, feature = "integration"))]
use crate::PgStore;
use crate::cotx::eventing::{
    SagaInstanceRow, SagaJournalExistingRow, SagaJournalRow, SagaLeaseMutation,
    SagaOperatorDecisionRow, SagaOperatorRequiredRow, SagaReceiptRow, SagaRunnableRow,
};
use crate::cotx::{ServingReadLane, ServingWriteLane, TenantDb, infra_tenant_scope};
use crate::pool::{VerifiedPgReadStore, VerifiedPgWriteStore};
use crate::saga_candidates::PgSagaCandidateSource;
use crate::saga_receipt_capability::SagaReceiptCapabilityReceipt;

const HOLDER_ID_MAX_BYTES: usize = 256;

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
    authorization: SagaOperatorRepairAuthorization,
}

impl SagaOperatorClaim for PgSagaOperatorClaim {
    fn instance(&self) -> SagaInstanceRef {
        self.authorization.instance()
    }

    fn expected_reason(&self) -> SagaOperatorReason {
        self.authorization.expected_reason()
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
                                .map_err(MutationTxError::Storage)?
                            {
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
                                .map_err(MutationTxError::Storage)?
                            {
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
                            .map_err(MutationTxError::Storage)?
                        {
                            if let Some(audit) = audit
                                && !tx
                                    .saga_insert_operator_decision(&lease_fields, &entry, &audit)
                                    .await
                                    .map_err(MutationTxError::Storage)?
                            {
                                return Err(MutationTxError::abort(
                                    SagaDurableMutationOutcome::Conflict,
                                ));
                            }
                            if let Some(lifecycle) = lifecycle
                                && !tx
                                    .saga_apply_lifecycle(&lease_fields, &lifecycle)
                                    .await
                                    .map_err(MutationTxError::Storage)?
                            {
                                return Err(MutationTxError::abort(
                                    SagaDurableMutationOutcome::Conflict,
                                ));
                            }
                            #[cfg(all(test, feature = "integration"))]
                            if inject_commit_unknown {
                                tx.saga_inject_commit_unknown_after_commit()
                                    .await
                                    .map_err(MutationTxError::Storage)?;
                            }
                            return Ok(SagaDurableMutationOutcome::Applied);
                        }
                        if !tx
                            .saga_lease_is_held(&lease_fields)
                            .await
                            .map_err(MutationTxError::Storage)?
                        {
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
                            .map_err(MutationTxError::Storage)?;
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
                MutationTxError::Storage,
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
                        let instance_row = conn
                            .saga_get_instance(&instance_fields)
                            .await
                            .map_err(storage_error)?;
                        let journal = conn
                            .saga_read_journal_entry(&instance_fields, decision_seq)
                            .await
                            .map_err(storage_error)?;
                        let audit = conn
                            .saga_read_operator_decision(&instance_fields, decision_seq)
                            .await
                            .map_err(storage_error)?;
                        Ok((instance_row, journal, audit))
                    })
                },
                storage_error,
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
                            .map_err(MutationTxError::Storage)?
                        {
                            return Ok(SagaDurableMutationOutcome::Applied);
                        }
                        let held = tx
                            .saga_lease_is_held(&lease_fields)
                            .await
                            .map_err(MutationTxError::Storage)?;
                        Err(MutationTxError::abort(if held {
                            SagaDurableMutationOutcome::Conflict
                        } else {
                            SagaDurableMutationOutcome::LeaseLost
                        }))
                    })
                },
                MutationTxError::Storage,
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

#[cfg(all(test, feature = "integration"))]
impl PgStore {
    pub(crate) fn saga_durable_store(
        &self,
        protection: PgSagaReceiptProtection,
    ) -> PgSagaDurableStore {
        PgSagaDurableStore {
            read_pool: TenantDb::<ServingReadLane>::from_unverified_for_test(self),
            write_pool: TenantDb::<ServingWriteLane>::from_unverified_for_test(self),
            candidate_source: PgSagaCandidateSource::from_unverified_for_test(self),
            protection,
            _capability: SagaReceiptCapabilityReceipt::for_test(),
            inject_commit_unknown_after_next_completion: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl SagaDurableStore for PgSagaDurableStore {
    async fn register(
        &self,
        registration: SagaInstanceRegistration,
    ) -> Result<SagaInstanceRecord, SagaDurableStoreError> {
        let fields = RegistrationFields::from(registration);
        self.write_pool
            .saga_write(
                infra_tenant_scope(fields.instance.tenant()),
                move |mut tx| {
                    Box::pin(async move {
                        tx.saga_register_instance(&fields)
                            .await
                            .map_err(storage_error)?;
                        let row = tx
                            .saga_load_instance(&InstanceFields::from(fields.instance))
                            .await
                            .map_err(storage_error)?;
                        let record = instance_from_row(fields.instance, &row)?;
                        if record.identity() != &fields.identity
                            || record.definition() != &fields.definition
                        {
                            return Err(saga_error(
                                SagaDurableStoreErrorKind::IdentityConflict,
                                InvariantError("saga instance definition identity conflict"),
                            ));
                        }
                        Ok(record)
                    })
                },
                storage_error,
            )
            .await
    }

    async fn get(
        &self,
        instance: &SagaInstanceRef,
    ) -> Result<Option<SagaInstanceRecord>, SagaDurableStoreError> {
        let fields = InstanceFields::from(*instance);
        self.read_pool
            .saga_read_map(
                infra_tenant_scope(instance.tenant()),
                move |mut conn| {
                    Box::pin(async move {
                        conn.saga_get_instance(&fields)
                            .await
                            .map_err(storage_error)?
                            .map(|row| instance_from_row(fields.instance, &row))
                            .transpose()
                    })
                },
                storage_error,
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
                            .map_err(storage_error)?
                            .into_iter()
                            .map(|row| runnable_from_row(tenant, row))
                            .collect()
                    })
                },
                storage_error,
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
                        if let Some(row) = tx.saga_claim(&fields).await.map_err(storage_error)? {
                            return lease_from_row(instance, holder_id, row.lease_token, row.epoch)
                                .map(SagaClaimOutcome::Acquired)
                                .map_err(|error| {
                                    saga_error(SagaDurableStoreErrorKind::Integrity, error)
                                });
                        }
                        let Some(row) = tx
                            .saga_observe_claim(&InstanceFields::from(instance))
                            .await
                            .map_err(storage_error)?
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
                            status @ (SagaInstanceStatus::Succeeded
                            | SagaInstanceStatus::Compensated
                            | SagaInstanceStatus::Expired
                            | SagaInstanceStatus::CompensationFailed) => {
                                Ok(SagaClaimOutcome::Terminal(status))
                            }
                            _ if row.lease_busy => Ok(SagaClaimOutcome::Busy),
                            _ => Ok(SagaClaimOutcome::Stale(status)),
                        }
                    })
                },
                storage_error,
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
                            .map_err(storage_error)?
                        {
                            return Ok(None);
                        }
                        let instance = tx
                            .saga_load_instance(&instance_fields)
                            .await
                            .map_err(storage_error)?;
                        let journal = tx
                            .saga_read_journal_locked(&instance_fields)
                            .await
                            .map_err(storage_error)?;
                        let mut receipts = Vec::with_capacity(scopes.len());
                        for scope in scopes {
                            let row = tx
                                .saga_load_receipt(&SagaReceiptScopeFields::from_scope(&scope))
                                .await
                                .map_err(storage_error)?;
                            receipts.push((scope, row));
                        }
                        Ok(Some((instance, journal, receipts)))
                    })
                },
                storage_error,
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
                            Err(error) => return Err(storage_error(error)),
                        };
                        let journal = tx
                            .saga_read_journal_locked(&instance_fields)
                            .await
                            .map_err(storage_error)?;
                        let receipt = tx
                            .saga_load_receipt(&scope_fields)
                            .await
                            .map_err(storage_error)?;
                        Ok(Some((row, journal, receipt)))
                    })
                },
                storage_error,
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
                self.mutate_journal(lease, entry, None, None, None).await
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
    type Claim = PgSagaOperatorClaim;

    async fn list_operator_required(
        &self,
        authorization: SagaOperatorInspectionAuthorization,
        limit: NonZeroUsize,
    ) -> Result<Vec<SagaOperatorRequiredInstance>, SagaDurableStoreError> {
        let identity = authorization.identity();
        let tenant = authorization.tenant();
        let owner = identity.owner().to_string();
        let contract_id = identity.contract_id().as_str().to_string();
        let limit = i64::try_from(limit.get())
            .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
        self.read_pool
            .saga_read_map(
                infra_tenant_scope(tenant),
                move |mut conn| {
                    Box::pin(async move {
                        conn.saga_list_operator_required(&owner, &contract_id, limit)
                            .await
                            .map_err(storage_error)?
                            .into_iter()
                            .map(|row| operator_required_from_row(tenant, row))
                            .collect()
                    })
                },
                storage_error,
            )
            .await
    }

    async fn claim_operator(
        &self,
        authorization: SagaOperatorRepairAuthorization,
        holder: SagaLeaseHolder,
        ttl: SagaLeaseTtl,
    ) -> Result<SagaOperatorClaimOutcome<Self::Claim>, SagaDurableStoreError> {
        if holder.as_str().len() > HOLDER_ID_MAX_BYTES {
            return Err(saga_error(
                SagaDurableStoreErrorKind::Integrity,
                InvariantError("invalid saga operator holder_id"),
            ));
        }
        let instance = authorization.instance();
        let fields = InstanceFields::from(instance);
        let reason = authorization.expected_reason();
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
                            .map_err(storage_error)?
                        {
                            return Ok(Ok((holder_id, row)));
                        }
                        let row = match tx.saga_load_instance(&fields).await {
                            Ok(row) => row,
                            Err(sqlx::Error::RowNotFound) => return Ok(Err(None)),
                            Err(error) => return Err(storage_error(error)),
                        };
                        Ok(Err(Some(row)))
                    })
                },
                storage_error,
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

    async fn operator_recovery_snapshot(
        &self,
        claim: &Self::Claim,
        scopes: Vec<SagaReceiptScope>,
    ) -> Result<SagaRecoveryOutcome, SagaDurableStoreError> {
        let request = SagaRecoveryRequest::new(claim.lease.clone(), scopes)
            .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
        SagaDurableStore::recovery_snapshot(self, request).await
    }

    async fn release_operator(
        &self,
        claim: Self::Claim,
    ) -> Result<SagaLeaseOutcome, SagaDurableStoreError> {
        SagaDurableStore::release(self, &claim.lease).await
    }

    async fn repair(
        &self,
        claim: Self::Claim,
        decision: SagaOperatorRepair,
    ) -> Result<SagaDurableMutationOutcome, SagaDurableStoreError> {
        let reason = claim.expected_reason();
        match decision {
            SagaOperatorRepair::ForwardApplied(completion) => {
                if !matches!(
                    reason,
                    SagaOperatorReason::ForwardOutcomeUnknown
                        | SagaOperatorReason::CompletionCommitUnknown
                ) {
                    return Ok(SagaDurableMutationOutcome::Conflict);
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
                    return Ok(SagaDurableMutationOutcome::Conflict);
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
                    return Ok(SagaDurableMutationOutcome::Conflict);
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
                    return Ok(SagaDurableMutationOutcome::Conflict);
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
            _ => Ok(SagaDurableMutationOutcome::Conflict),
        }
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
    ) -> Result<SagaUnresolvedState, SagaDurableStoreError> {
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
                            .map_err(storage_error)
                    })
                },
                storage_error,
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
        self.commit_forward_completion_inner(lease, completion, None)
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
        self.commit_forward_completion_inner(&operator.lease, completion, Some(audit))
            .await
    }

    async fn commit_forward_completion_inner(
        &self,
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
                            .map_err(ReceiptTxError::Storage)?
                            != Some(true)
                        {
                            let held = tx
                                .saga_lease_is_held(&lease_fields)
                                .await
                                .map_err(ReceiptTxError::Storage)?;
                            return Err(ReceiptTxError::abort(if held {
                                SagaDurableMutationOutcome::Conflict
                            } else {
                                SagaDurableMutationOutcome::LeaseLost
                            }));
                        }
                        if tx
                            .saga_insert_receipt(&lease_fields, &receipt_fields)
                            .await
                            .map_err(ReceiptTxError::Storage)?
                        {
                            if tx
                                .saga_insert_journal(&lease_fields, &journal_fields)
                                .await
                                .map_err(ReceiptTxError::Storage)?
                            {
                                if let Some(audit) = operator_audit
                                    && !tx
                                        .saga_insert_operator_decision(
                                            &lease_fields,
                                            &journal_fields,
                                            &audit,
                                        )
                                        .await
                                        .map_err(ReceiptTxError::Storage)?
                                {
                                    return Err(ReceiptTxError::abort(
                                        SagaDurableMutationOutcome::Conflict,
                                    ));
                                }
                                if let Some(lifecycle) = lifecycle
                                    && !tx
                                        .saga_apply_lifecycle(&lease_fields, &lifecycle)
                                        .await
                                        .map_err(ReceiptTxError::Storage)?
                                {
                                    return Err(ReceiptTxError::abort(
                                        SagaDurableMutationOutcome::Conflict,
                                    ));
                                }
                                #[cfg(all(test, feature = "integration"))]
                                if inject_commit_unknown {
                                    tx.saga_inject_commit_unknown_after_commit()
                                        .await
                                        .map_err(ReceiptTxError::Storage)?;
                                }
                                return Ok(SagaDurableMutationOutcome::Applied);
                            }
                            if !tx
                                .saga_lease_is_held(&lease_fields)
                                .await
                                .map_err(ReceiptTxError::Storage)?
                            {
                                return Err(ReceiptTxError::abort(
                                    SagaDurableMutationOutcome::LeaseLost,
                                ));
                            }
                            return Err(ReceiptTxError::abort(
                                SagaDurableMutationOutcome::Conflict,
                            ));
                        }

                        if !tx
                            .saga_lease_is_held(&lease_fields)
                            .await
                            .map_err(ReceiptTxError::Storage)?
                        {
                            return Err(ReceiptTxError::abort(
                                SagaDurableMutationOutcome::LeaseLost,
                            ));
                        }

                        let stored = tx
                            .saga_load_receipt(&receipt_fields.scope_fields())
                            .await
                            .map_err(ReceiptTxError::Storage)?;
                        let journal = tx
                            .saga_load_journal_entry(
                                &InstanceFields::from(lease_fields.instance),
                                receipt_fields.completed_seq,
                            )
                            .await
                            .map_err(ReceiptTxError::Storage)?;
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
                ReceiptTxError::Storage,
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
                        let instance_row = conn
                            .saga_get_instance(&instance_fields)
                            .await
                            .map_err(storage_error)?;
                        let journal = conn
                            .saga_read_journal_entry(&instance_fields, decision_seq)
                            .await
                            .map_err(storage_error)?;
                        let receipt = conn
                            .saga_load_receipt(&scope_fields)
                            .await
                            .map_err(storage_error)?;
                        let audit = conn
                            .saga_read_operator_decision(&instance_fields, decision_seq)
                            .await
                            .map_err(storage_error)?;
                        Ok((instance_row, journal, receipt, audit))
                    })
                },
                storage_error,
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
            reason: claim.expected_reason().as_str().to_string(),
            phase: phase.as_str().to_string(),
            decision: decision.to_string(),
            actor: claim.authorization.caller().as_str().to_string(),
            change_ticket: claim.authorization.change_ticket().as_str().to_string(),
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

fn storage_error(error: sqlx::Error) -> SagaDurableStoreError {
    saga_error(SagaDurableStoreErrorKind::Storage, error)
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

fn operator_required_from_row(
    tenant: vocab::TenantId,
    row: SagaOperatorRequiredRow,
) -> Result<SagaOperatorRequiredInstance, SagaDurableStoreError> {
    let saga_id = uuid::Uuid::parse_str(&row.saga_id)
        .map(SagaId::new)
        .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
    let instance = SagaInstanceRef::new(tenant, saga_id)
        .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
    let identity = parse_worker_identity(&row.owner, &row.contract_id)?;
    let definition = parse_definition_identity(
        &row.contract_id,
        &row.definition_version,
        &row.definition_schema_digest,
        &row.action_registry_generation,
    )?;
    let reason = SagaOperatorReason::parse(&row.operator_reason).ok_or_else(|| {
        saga_error(
            SagaDurableStoreErrorKind::Integrity,
            InvariantError("invalid saga operator reason"),
        )
    })?;
    let record = SagaInstanceRecord::new(
        instance,
        SagaInstanceStatus::OperatorRequired,
        identity,
        definition,
    )
    .and_then(|record| record.with_operator_reason(reason))
    .map_err(|error| saga_error(SagaDurableStoreErrorKind::Integrity, error))?;
    Ok(SagaOperatorRequiredInstance::new(record, reason))
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
