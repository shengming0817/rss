#![allow(clippy::panic)]

use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use consistency::{
    CompensationOutcome, SagaEffectPhase, SagaId, SagaIdempotencyKey, SagaInstanceRecord,
    SagaInstanceRef, SagaInstanceStatus, SagaJournalRecord, SagaJournalStatus, SagaLease,
    SagaLeaseOutcome, SagaOperatorReason, SagaReceiptFormatVersion, SagaReceiptScope,
};
use diport::{
    CheckpointOwner, DeadLetterRecord, DeadLetterStore, DeadLetterStoreError, SagaClaimOutcome,
    SagaClaimRequest, SagaDurableMutation, SagaDurableMutationOutcome, SagaDurableStore,
    SagaDurableStoreError, SagaDurableStoreErrorKind, SagaInstanceRegistration, SagaLeaseHolder,
    SagaLeaseTtl, SagaOperatorChangeTicket, SagaOperatorClaim, SagaOperatorClaimOutcome,
    SagaOperatorInspectionAuthorization, SagaOperatorRepair, SagaOperatorRepairAuthorization,
    SagaOperatorRequiredInstance, SagaOperatorStartAuditId, SagaOperatorStore, SagaRecoveryOutcome,
    SagaRecoveryRequest, SagaRecoverySnapshot, SagaRunnableInstance, SagaTerminalReceiptOutcome,
    SagaTerminalReceiptRequest, SagaVerifiedTerminalReceipt, SagaWorkerIdentity, StoredSagaReceipt,
};
use generated::saga::billing_v1::{
    BillingCaptureReceipt, BillingReserveFundsReceipt, CaptureStep, Definition, ReserveFundsStep,
};

use super::{
    SagaAttemptOutcome, SagaCompensationContext, SagaExecutor, SagaExecutorConfig,
    SagaExecutorDeps, SagaExecutorImpl, SagaForwardContext, SagaOperatorRecoveryOutcome,
    SagaOutcome, SagaProbeOutcome, SagaStep, SagaSuccessReceiptError, SagaSuccessReference,
    TypedSagaActionFactory,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReserveMode {
    Applied,
    TransientThenApplied,
    ProbeApplied,
    ProbeUnknown,
    CompensationProbeUnknown,
    CompensationProbeApplied,
    CompensationTransientThenApplied,
    CompensationPermanent,
}

#[derive(Debug)]
struct Reserve {
    mode: ReserveMode,
    calls: Arc<Mutex<Vec<&'static str>>>,
}

impl SagaStep<ReserveFundsStep> for Reserve {
    async fn execute(
        &self,
        _context: SagaForwardContext,
    ) -> SagaAttemptOutcome<BillingReserveFundsReceipt> {
        let previous_attempts = {
            let mut calls = self.calls.lock().unwrap_or_else(|error| error.into_inner());
            let previous_attempts = calls
                .iter()
                .filter(|call| **call == "reserve.execute")
                .count();
            calls.push("reserve.execute");
            previous_attempts
        };
        match self.mode {
            ReserveMode::Applied
            | ReserveMode::CompensationProbeUnknown
            | ReserveMode::CompensationProbeApplied
            | ReserveMode::CompensationTransientThenApplied
            | ReserveMode::CompensationPermanent => {
                SagaAttemptOutcome::Applied(BillingReserveFundsReceipt {
                    reservation_id: "reservation-1".into(),
                })
            }
            ReserveMode::TransientThenApplied if previous_attempts == 0 => {
                SagaAttemptOutcome::NotApplied(consistency::EngineError::new(
                    consistency::EngineErrorKind::Transient,
                ))
            }
            ReserveMode::TransientThenApplied => {
                SagaAttemptOutcome::Applied(BillingReserveFundsReceipt {
                    reservation_id: "reservation-retried".into(),
                })
            }
            ReserveMode::ProbeApplied | ReserveMode::ProbeUnknown => SagaAttemptOutcome::Unknown,
        }
    }

    async fn probe(
        &self,
        _context: SagaForwardContext,
    ) -> SagaProbeOutcome<BillingReserveFundsReceipt> {
        self.calls
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push("reserve.probe");
        match self.mode {
            ReserveMode::ProbeApplied => SagaProbeOutcome::Applied(BillingReserveFundsReceipt {
                reservation_id: "reservation-probed".into(),
            }),
            ReserveMode::Applied
            | ReserveMode::TransientThenApplied
            | ReserveMode::CompensationProbeUnknown
            | ReserveMode::CompensationProbeApplied
            | ReserveMode::CompensationTransientThenApplied
            | ReserveMode::CompensationPermanent => SagaProbeOutcome::NotApplied,
            ReserveMode::ProbeUnknown => SagaProbeOutcome::Unknown,
        }
    }

    async fn compensate(
        &self,
        _context: SagaCompensationContext,
        _receipt: BillingReserveFundsReceipt,
    ) -> SagaAttemptOutcome<CompensationOutcome> {
        let previous_attempts = {
            let mut calls = self.calls.lock().unwrap_or_else(|error| error.into_inner());
            let previous_attempts = calls
                .iter()
                .filter(|call| **call == "reserve.compensate")
                .count();
            calls.push("reserve.compensate");
            previous_attempts
        };
        match self.mode {
            ReserveMode::CompensationProbeUnknown => SagaAttemptOutcome::Unknown,
            ReserveMode::CompensationTransientThenApplied if previous_attempts == 0 => {
                SagaAttemptOutcome::NotApplied(consistency::EngineError::new(
                    consistency::EngineErrorKind::Transient,
                ))
            }
            ReserveMode::CompensationPermanent => SagaAttemptOutcome::NotApplied(
                consistency::EngineError::new(consistency::EngineErrorKind::Permanent),
            ),
            _ => SagaAttemptOutcome::Applied(CompensationOutcome::Compensated),
        }
    }

    async fn probe_compensation(
        &self,
        _context: SagaCompensationContext,
        _receipt: BillingReserveFundsReceipt,
    ) -> SagaProbeOutcome<CompensationOutcome> {
        self.calls
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push("reserve.probe_compensation");
        match self.mode {
            ReserveMode::CompensationProbeUnknown => SagaProbeOutcome::Unknown,
            ReserveMode::CompensationProbeApplied => {
                SagaProbeOutcome::Applied(CompensationOutcome::Compensated)
            }
            _ => SagaProbeOutcome::NotApplied,
        }
    }
}

struct TerminalReceiptEvidence {
    scope: SagaReceiptScope,
    attempt: consistency::SagaAttempt,
    format: SagaReceiptFormatVersion,
    plaintext: Vec<u8>,
    completed_seq: u64,
}

#[derive(Debug)]
struct Capture {
    calls: Arc<Mutex<Vec<&'static str>>>,
    mode: CaptureMode,
}

#[derive(Debug, Clone, Copy)]
enum CaptureMode {
    Applied,
    Permanent,
    Transient,
}

impl SagaStep<CaptureStep> for Capture {
    async fn execute(
        &self,
        _context: SagaForwardContext,
    ) -> SagaAttemptOutcome<BillingCaptureReceipt> {
        self.calls
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push("capture.execute");
        if !matches!(self.mode, CaptureMode::Applied) {
            return SagaAttemptOutcome::NotApplied(consistency::EngineError::new(
                match self.mode {
                    CaptureMode::Transient => consistency::EngineErrorKind::Transient,
                    CaptureMode::Permanent => consistency::EngineErrorKind::Permanent,
                    CaptureMode::Applied => unreachable!(),
                },
            ));
        }
        SagaAttemptOutcome::Applied(BillingCaptureReceipt {
            capture_id: "capture-1".into(),
        })
    }

    async fn probe(&self, _context: SagaForwardContext) -> SagaProbeOutcome<BillingCaptureReceipt> {
        SagaProbeOutcome::NotApplied
    }

    async fn compensate(
        &self,
        _context: SagaCompensationContext,
        _receipt: BillingCaptureReceipt,
    ) -> SagaAttemptOutcome<CompensationOutcome> {
        self.calls
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push("capture.compensate");
        SagaAttemptOutcome::Applied(CompensationOutcome::Compensated)
    }

    async fn probe_compensation(
        &self,
        _context: SagaCompensationContext,
        _receipt: BillingCaptureReceipt,
    ) -> SagaProbeOutcome<CompensationOutcome> {
        SagaProbeOutcome::NotApplied
    }
}

#[derive(Default)]
struct FakeDurableStore {
    row: Mutex<Option<SagaInstanceRecord>>,
    snapshots: Mutex<VecDeque<SagaRecoverySnapshot>>,
    journal: Mutex<Vec<SagaJournalRecord>>,
    terminal: Mutex<Option<TerminalReceiptEvidence>>,
    mutations: Mutex<Vec<&'static str>>,
    journal_writes: Mutex<Vec<RecordedJournalWrite>>,
    operator_reasons: Mutex<Vec<SagaOperatorReason>>,
    repairs: Mutex<Vec<&'static str>>,
    mutation_results:
        Mutex<VecDeque<Result<SagaDurableMutationOutcome, SagaDurableStoreErrorKind>>>,
    renew_results: Mutex<VecDeque<Result<SagaLeaseOutcome, SagaDurableStoreErrorKind>>>,
    claim_busy: bool,
    force_terminal_missing: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordedJournalWrite {
    status: SagaJournalStatus,
    attempt: u32,
    effect_key: Vec<u8>,
}

impl FakeDurableStore {
    fn with_row(row: SagaInstanceRecord) -> Self {
        Self {
            row: Mutex::new(Some(row)),
            snapshots: Mutex::new(VecDeque::new()),
            journal: Mutex::new(Vec::new()),
            terminal: Mutex::new(None),
            mutations: Mutex::new(Vec::new()),
            journal_writes: Mutex::new(Vec::new()),
            operator_reasons: Mutex::new(Vec::new()),
            repairs: Mutex::new(Vec::new()),
            mutation_results: Mutex::new(VecDeque::new()),
            renew_results: Mutex::new(VecDeque::new()),
            claim_busy: false,
            force_terminal_missing: false,
        }
    }

    fn with_row_and_busy_claim(row: SagaInstanceRecord) -> Self {
        Self {
            claim_busy: true,
            ..Self::with_row(row)
        }
    }

    fn with_row_and_lost_mutation(row: SagaInstanceRecord) -> Self {
        let mut store = Self::with_row(row);
        store.mutation_results =
            Mutex::new(VecDeque::from([Ok(SagaDurableMutationOutcome::LeaseLost)]));
        store
    }

    fn with_snapshot(snapshot: SagaRecoverySnapshot) -> Self {
        let store = Self {
            row: Mutex::new(Some(snapshot.instance().clone())),
            snapshots: Mutex::new(VecDeque::from([snapshot])),
            journal: Mutex::new(Vec::new()),
            terminal: Mutex::new(None),
            mutations: Mutex::new(Vec::new()),
            journal_writes: Mutex::new(Vec::new()),
            operator_reasons: Mutex::new(Vec::new()),
            repairs: Mutex::new(Vec::new()),
            mutation_results: Mutex::new(VecDeque::new()),
            renew_results: Mutex::new(VecDeque::new()),
            claim_busy: false,
            force_terminal_missing: false,
        };
        store.capture_front_snapshot();
        store
    }

    fn with_recovery_script(
        snapshots: impl IntoIterator<Item = SagaRecoverySnapshot>,
        mutation_results: impl IntoIterator<
            Item = Result<SagaDurableMutationOutcome, SagaDurableStoreErrorKind>,
        >,
    ) -> Self {
        let snapshots = VecDeque::from_iter(snapshots);
        let row = snapshots
            .front()
            .map(|snapshot| snapshot.instance().clone());
        Self {
            row: Mutex::new(row),
            snapshots: Mutex::new(snapshots),
            journal: Mutex::new(Vec::new()),
            terminal: Mutex::new(None),
            mutations: Mutex::new(Vec::new()),
            journal_writes: Mutex::new(Vec::new()),
            operator_reasons: Mutex::new(Vec::new()),
            repairs: Mutex::new(Vec::new()),
            mutation_results: Mutex::new(VecDeque::from_iter(mutation_results)),
            renew_results: Mutex::new(VecDeque::new()),
            claim_busy: false,
            force_terminal_missing: false,
        }
    }

    fn with_mutation_results(
        mutation_results: impl IntoIterator<
            Item = Result<SagaDurableMutationOutcome, SagaDurableStoreErrorKind>,
        >,
    ) -> Self {
        Self {
            mutation_results: Mutex::new(VecDeque::from_iter(mutation_results)),
            ..Self::default()
        }
    }

    fn with_renew_results(
        renew_results: impl IntoIterator<Item = Result<SagaLeaseOutcome, SagaDurableStoreErrorKind>>,
    ) -> Self {
        Self {
            renew_results: Mutex::new(VecDeque::from_iter(renew_results)),
            ..Self::default()
        }
    }

    fn with_forced_terminal_missing() -> Self {
        Self {
            force_terminal_missing: true,
            ..Self::default()
        }
    }

    fn capture_front_snapshot(&self) {
        let snapshots = self
            .snapshots
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(snapshot) = snapshots.front() {
            self.capture_snapshot(snapshot);
        }
    }

    fn capture_snapshot(&self, snapshot: &SagaRecoverySnapshot) {
        *self.row.lock().unwrap_or_else(|error| error.into_inner()) =
            Some(snapshot.instance().clone());
        *self
            .journal
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = snapshot.journal().to_vec();
        let terminal = if snapshot.instance().status() == SagaInstanceStatus::Succeeded {
            snapshot
                .receipts()
                .iter()
                .max_by_key(|receipt| receipt.completed_seq())
                .map(terminal_evidence)
        } else {
            None
        };
        *self
            .terminal
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = terminal;
    }

    fn mutations(&self) -> Vec<&'static str> {
        self.mutations
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    fn journal_writes(&self) -> Vec<RecordedJournalWrite> {
        self.journal_writes
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    fn operator_reasons(&self) -> Vec<SagaOperatorReason> {
        self.operator_reasons
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    fn repairs(&self) -> Vec<&'static str> {
        self.repairs
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    fn apply_mutation(&self, mutation: SagaDurableMutation) -> Result<(), SagaDurableStoreError> {
        match mutation {
            SagaDurableMutation::ForwardIntent(intent) => {
                self.push_journal(
                    intent.seq(),
                    intent.step().clone(),
                    SagaJournalStatus::ForwardIntent,
                );
            }
            SagaDurableMutation::ForwardCompleted(completion) => {
                let (completion, progress) = completion.into_parts();
                let (scope, attempt, format, plaintext, completed_seq) = completion.into_parts();
                self.push_journal(
                    completed_seq,
                    scope.step_name().clone(),
                    SagaJournalStatus::ForwardCompleted,
                );
                if progress == diport::SagaForwardProgress::Succeeded {
                    *self
                        .terminal
                        .lock()
                        .unwrap_or_else(|error| error.into_inner()) =
                        Some(TerminalReceiptEvidence {
                            scope,
                            attempt,
                            format,
                            plaintext: plaintext.expose().to_vec(),
                            completed_seq,
                        });
                    self.set_status(SagaInstanceStatus::Succeeded, None)?;
                } else {
                    self.set_status(SagaInstanceStatus::Running, None)?;
                }
            }
            SagaDurableMutation::CompensationIntent(intent) => {
                self.push_journal(
                    intent.seq(),
                    intent.step().clone(),
                    SagaJournalStatus::CompensationIntent,
                );
                self.set_status(SagaInstanceStatus::Compensating, None)?;
            }
            SagaDurableMutation::CompensationCompleted(completion) => {
                self.push_journal(
                    completion.seq(),
                    completion.step().clone(),
                    SagaJournalStatus::CompensationCompleted,
                );
            }
            SagaDurableMutation::CompensationFailed(failure) => {
                self.push_journal(
                    failure.seq(),
                    failure.step().clone(),
                    SagaJournalStatus::CompensationFailed,
                );
                self.set_status(SagaInstanceStatus::OperatorRequired, None)?;
            }
            SagaDurableMutation::OperatorRequired(reason) => {
                self.set_status(SagaInstanceStatus::OperatorRequired, Some(reason))?;
            }
            SagaDurableMutation::Degraded => {
                self.set_status(SagaInstanceStatus::Degraded, None)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn push_journal(&self, seq: u64, step: vocab::StepName, status: SagaJournalStatus) {
        self.journal
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(SagaJournalRecord::replayed(seq, step, status));
    }

    fn set_status(
        &self,
        status: SagaInstanceStatus,
        operator_reason: Option<SagaOperatorReason>,
    ) -> Result<(), SagaDurableStoreError> {
        let current = self
            .row
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
            .ok_or_else(|| store_error("missing row"))?;
        let next = SagaInstanceRecord::new(
            current.instance(),
            status,
            current.identity().clone(),
            current.definition().clone(),
        )
        .map_err(|error| SagaDurableStoreError::new(SagaDurableStoreErrorKind::Integrity, error))?;
        let next = match operator_reason {
            Some(reason) => next.with_operator_reason(reason).map_err(|error| {
                SagaDurableStoreError::new(SagaDurableStoreErrorKind::Integrity, error)
            })?,
            None => next,
        };
        *self.row.lock().unwrap_or_else(|error| error.into_inner()) = Some(next);
        Ok(())
    }
}

fn terminal_evidence(receipt: &StoredSagaReceipt) -> TerminalReceiptEvidence {
    TerminalReceiptEvidence {
        scope: receipt.scope().clone(),
        attempt: receipt.attempt(),
        format: receipt.format(),
        plaintext: receipt.plaintext().expose().to_vec(),
        completed_seq: receipt.completed_seq(),
    }
}

impl SagaDurableStore for FakeDurableStore {
    async fn register(
        &self,
        registration: SagaInstanceRegistration,
    ) -> Result<SagaInstanceRecord, SagaDurableStoreError> {
        let row = SagaInstanceRecord::new(
            registration.instance(),
            SagaInstanceStatus::Ready,
            registration.identity().clone(),
            registration.definition().clone(),
        )
        .map_err(|error| SagaDurableStoreError::new(SagaDurableStoreErrorKind::Integrity, error))?;
        *self.row.lock().unwrap_or_else(|error| error.into_inner()) = Some(row.clone());
        Ok(row)
    }

    async fn get(
        &self,
        _instance: &SagaInstanceRef,
    ) -> Result<Option<SagaInstanceRecord>, SagaDurableStoreError> {
        Ok(self
            .row
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone())
    }

    async fn list_runnable(
        &self,
        _identity: &SagaWorkerIdentity,
        _tenant: vocab::TenantId,
        _limit: NonZeroUsize,
    ) -> Result<Vec<SagaRunnableInstance>, SagaDurableStoreError> {
        Ok(Vec::new())
    }

    async fn claim(
        &self,
        request: SagaClaimRequest,
    ) -> Result<SagaClaimOutcome, SagaDurableStoreError> {
        if self.claim_busy {
            return Ok(SagaClaimOutcome::Busy);
        }
        if let Some(row) = self
            .row
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            && row.status() == SagaInstanceStatus::Succeeded
        {
            return Ok(SagaClaimOutcome::Terminal(SagaInstanceStatus::Succeeded));
        }
        Ok(SagaClaimOutcome::Acquired(
            SagaLease::new(
                request.expected().instance(),
                request.holder_id(),
                uuid::Uuid::from_u128(7),
                1,
            )
            .map_err(|error| {
                SagaDurableStoreError::new(SagaDurableStoreErrorKind::Integrity, error)
            })?,
        ))
    }

    async fn renew(
        &self,
        _lease: &SagaLease,
        _ttl: SagaLeaseTtl,
    ) -> Result<SagaLeaseOutcome, SagaDurableStoreError> {
        match self
            .renew_results
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .pop_front()
        {
            Some(Ok(outcome)) => Ok(outcome),
            Some(Err(kind)) => Err(SagaDurableStoreError::new(
                kind,
                std::io::Error::other("scripted renew failure"),
            )),
            None => Ok(SagaLeaseOutcome::Held),
        }
    }

    async fn release(&self, _lease: &SagaLease) -> Result<SagaLeaseOutcome, SagaDurableStoreError> {
        Ok(SagaLeaseOutcome::Held)
    }

    async fn recovery_snapshot(
        &self,
        _request: SagaRecoveryRequest,
    ) -> Result<SagaRecoveryOutcome, SagaDurableStoreError> {
        let snapshot = self
            .snapshots
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .pop_front()
            .ok_or_else(|| store_error("missing snapshot"))?;
        self.capture_snapshot(&snapshot);
        Ok(SagaRecoveryOutcome::Available(snapshot))
    }

    async fn terminal_receipt(
        &self,
        request: SagaTerminalReceiptRequest,
    ) -> Result<SagaTerminalReceiptOutcome, SagaDurableStoreError> {
        let row = self
            .row
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
            .ok_or_else(|| store_error("missing row"))?;
        if row.status() != SagaInstanceStatus::Succeeded {
            return Ok(SagaTerminalReceiptOutcome::NotSucceeded(row.status()));
        }
        if self.force_terminal_missing {
            return Ok(SagaTerminalReceiptOutcome::Missing);
        }
        let terminal = self
            .terminal
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some(terminal) = terminal.as_ref() else {
            return Ok(SagaTerminalReceiptOutcome::Missing);
        };
        if terminal.scope != *request.scope() {
            return Ok(SagaTerminalReceiptOutcome::Missing);
        }
        let receipt = StoredSagaReceipt::new(
            terminal.scope.clone(),
            terminal.attempt,
            terminal.format,
            secure::Plaintext::new(terminal.plaintext.clone()),
            terminal.completed_seq,
        );
        let journal = self
            .journal
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        Ok(SagaTerminalReceiptOutcome::Verified(Box::new(
            SagaVerifiedTerminalReceipt::new(row, journal, receipt),
        )))
    }

    async fn mutate(
        &self,
        _lease: &SagaLease,
        mutation: SagaDurableMutation,
    ) -> Result<SagaDurableMutationOutcome, SagaDurableStoreError> {
        let journal_write = match &mutation {
            SagaDurableMutation::ForwardIntent(intent) => Some(RecordedJournalWrite {
                status: SagaJournalStatus::ForwardIntent,
                attempt: intent.attempt().get(),
                effect_key: intent.effect_key().as_bytes().to_vec(),
            }),
            SagaDurableMutation::ForwardCompleted(completion) => {
                let completion = completion.completion();
                Some(RecordedJournalWrite {
                    status: SagaJournalStatus::ForwardCompleted,
                    attempt: completion.attempt().get(),
                    effect_key: completion.scope().effect_key().as_bytes().to_vec(),
                })
            }
            SagaDurableMutation::CompensationIntent(intent) => Some(RecordedJournalWrite {
                status: SagaJournalStatus::CompensationIntent,
                attempt: intent.attempt().get(),
                effect_key: intent.effect_key().as_bytes().to_vec(),
            }),
            SagaDurableMutation::CompensationCompleted(completion) => Some(RecordedJournalWrite {
                status: SagaJournalStatus::CompensationCompleted,
                attempt: completion.attempt().get(),
                effect_key: completion.effect_key().as_bytes().to_vec(),
            }),
            SagaDurableMutation::CompensationFailed(failure) => Some(RecordedJournalWrite {
                status: SagaJournalStatus::CompensationFailed,
                attempt: failure.attempt().get(),
                effect_key: failure.effect_key().as_bytes().to_vec(),
            }),
            _ => None,
        };
        if let Some(journal_write) = journal_write {
            self.journal_writes
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push(journal_write);
        }
        let label = match &mutation {
            SagaDurableMutation::ForwardIntent(_) => "forward_intent",
            SagaDurableMutation::ForwardCompleted(_) => "forward_completed",
            SagaDurableMutation::CompensationIntent(_) => "compensation_intent",
            SagaDurableMutation::CompensationCompleted(_) => "compensation_completed",
            SagaDurableMutation::CompensationFailed(_) => "compensation_failed",
            SagaDurableMutation::OperatorRequired(reason) => {
                self.operator_reasons
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .push(*reason);
                "operator_required"
            }
            SagaDurableMutation::Degraded => "degraded",
            _ => "unknown",
        };
        self.mutations
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(label);
        let result = match self
            .mutation_results
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .pop_front()
        {
            Some(Ok(outcome)) => Ok(outcome),
            Some(Err(kind)) => Err(SagaDurableStoreError::new(
                kind,
                std::io::Error::other("scripted mutation failure"),
            )),
            None => Ok(SagaDurableMutationOutcome::Applied),
        };
        if matches!(
            result,
            Ok(SagaDurableMutationOutcome::Applied
                | SagaDurableMutationOutcome::IdempotentDuplicate)
        ) {
            self.apply_mutation(mutation)?;
        }
        result
    }

    async fn shutdown(&self) -> Result<(), SagaDurableStoreError> {
        Ok(())
    }
}

struct FakeOperatorClaim {
    lease: SagaLease,
    authorization: SagaOperatorRepairAuthorization,
}

impl SagaOperatorClaim for FakeOperatorClaim {
    fn instance(&self) -> SagaInstanceRef {
        self.authorization.instance()
    }
    fn expected_reason(&self) -> SagaOperatorReason {
        self.authorization.expected_reason()
    }
}

impl SagaOperatorStore for FakeDurableStore {
    type Claim = FakeOperatorClaim;

    async fn list_operator_required(
        &self,
        _authorization: SagaOperatorInspectionAuthorization,
        _limit: NonZeroUsize,
    ) -> Result<Vec<SagaOperatorRequiredInstance>, SagaDurableStoreError> {
        Ok(Vec::new())
    }

    async fn claim_operator(
        &self,
        authorization: SagaOperatorRepairAuthorization,
        holder: SagaLeaseHolder,
        _ttl: SagaLeaseTtl,
    ) -> Result<SagaOperatorClaimOutcome<Self::Claim>, SagaDurableStoreError> {
        if self.claim_busy {
            return Ok(SagaOperatorClaimOutcome::Busy);
        }
        let row = self
            .row
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        let Some(row) = row else {
            return Ok(SagaOperatorClaimOutcome::Missing);
        };
        if row.identity() != authorization.identity() {
            return Ok(SagaOperatorClaimOutcome::Missing);
        }
        if row.status() != SagaInstanceStatus::OperatorRequired {
            return Ok(SagaOperatorClaimOutcome::StaleStatus(row.status()));
        }
        let Some(reason) = row.operator_reason() else {
            return Ok(SagaOperatorClaimOutcome::StaleStatus(row.status()));
        };
        if reason != authorization.expected_reason() {
            return Ok(SagaOperatorClaimOutcome::StaleReason(reason));
        }
        let lease = SagaLease::new(
            authorization.instance(),
            holder.as_str(),
            uuid::Uuid::from_u128(17),
            2,
        )
        .map_err(|error| SagaDurableStoreError::new(SagaDurableStoreErrorKind::Integrity, error))?;
        Ok(SagaOperatorClaimOutcome::Acquired(FakeOperatorClaim {
            lease,
            authorization,
        }))
    }

    async fn operator_recovery_snapshot(
        &self,
        claim: &Self::Claim,
        scopes: Vec<SagaReceiptScope>,
    ) -> Result<SagaRecoveryOutcome, SagaDurableStoreError> {
        let request = SagaRecoveryRequest::new(claim.lease.clone(), scopes).map_err(|error| {
            SagaDurableStoreError::new(SagaDurableStoreErrorKind::Integrity, error)
        })?;
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
        _claim: Self::Claim,
        decision: SagaOperatorRepair,
    ) -> Result<SagaDurableMutationOutcome, SagaDurableStoreError> {
        let label = match decision {
            SagaOperatorRepair::ForwardApplied(_) => "forward_applied",
            SagaOperatorRepair::ForwardNotApplied(_) => "forward_not_applied",
            SagaOperatorRepair::CompensationApplied(_) => "compensation_applied",
            SagaOperatorRepair::CompensationNotApplied(_) => "compensation_not_applied",
            _ => "unknown",
        };
        self.repairs
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(label);
        Ok(SagaDurableMutationOutcome::Applied)
    }
}

#[derive(Default)]
struct NoopDeadLetterStore {
    writes: Mutex<usize>,
    fail_writes: bool,
}

impl NoopDeadLetterStore {
    fn failing() -> Self {
        Self {
            writes: Mutex::new(0),
            fail_writes: true,
        }
    }

    fn writes(&self) -> usize {
        *self
            .writes
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }
}

impl DeadLetterStore for NoopDeadLetterStore {
    async fn write_dead_letter(
        &self,
        _record: DeadLetterRecord,
    ) -> Result<(), DeadLetterStoreError> {
        *self
            .writes
            .lock()
            .unwrap_or_else(|error| error.into_inner()) += 1;
        if self.fail_writes {
            Err(DeadLetterStoreError::new(std::io::Error::other(
                "injected saga DLX failure",
            )))
        } else {
            Ok(())
        }
    }

    async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
        Ok(())
    }
}

#[tokio::test]
async fn intent_precedes_each_effect_and_success_is_a_redacted_reference() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let store = Arc::new(FakeDurableStore::default());
    let executor = executor(Arc::clone(&store), ReserveMode::Applied, Arc::clone(&calls));

    let outcome = executor.run(instance()).await;

    let SagaOutcome::Succeeded { reference } = outcome else {
        panic!("expected success")
    };
    assert_eq!(reference.step_name().as_str(), "capture");
    assert_eq!(format!("{reference:?}"), "SagaSuccessReference(<redacted>)");
    assert_eq!(
        store.mutations(),
        vec![
            "forward_intent",
            "forward_completed",
            "forward_intent",
            "forward_completed"
        ]
    );
    assert_eq!(
        *calls.lock().unwrap_or_else(|error| error.into_inner()),
        vec!["reserve.execute", "capture.execute"]
    );
}

#[tokio::test]
async fn success_reference_resolves_only_the_exact_typed_terminal_receipt() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let store = Arc::new(FakeDurableStore::default());
    let executor = executor(Arc::clone(&store), ReserveMode::Applied, calls);

    let SagaOutcome::Succeeded { reference } = executor.run(instance()).await else {
        panic!("expected success")
    };
    let receipt = reference
        .resolve_receipt::<CaptureStep, _>(store.as_ref())
        .await
        .unwrap_or_else(|error| panic!("resolve receipt: {error}"));

    assert_eq!(receipt.capture_id, "capture-1");
    assert!(matches!(
        reference
            .resolve_receipt::<ReserveFundsStep, _>(store.as_ref())
            .await,
        Err(SagaSuccessReceiptError::MarkerMismatch)
    ));
}

#[tokio::test]
async fn succeeded_status_without_exact_terminal_proof_is_not_success() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let store = Arc::new(FakeDurableStore::with_row(row(
        SagaInstanceStatus::Succeeded,
    )));
    let executor = executor(Arc::clone(&store), ReserveMode::Applied, calls);

    assert!(matches!(
        executor.resume(instance(), definition()).await,
        SagaOutcome::Interrupted {
            reason: super::SagaInterruption::ReceiptUnavailable
        }
    ));
}

#[tokio::test]
async fn completion_without_exact_terminal_proof_enters_operator_required() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let store = Arc::new(FakeDurableStore::with_forced_terminal_missing());
    let executor = executor(Arc::clone(&store), ReserveMode::Applied, calls);

    assert!(matches!(
        executor.run(instance()).await,
        SagaOutcome::Interrupted {
            reason: super::SagaInterruption::OperatorRequired
        }
    ));
    assert_eq!(
        store.operator_reasons(),
        vec![SagaOperatorReason::ReceiptMissing]
    );
}

#[tokio::test]
async fn operator_recovery_repairs_confirmed_forward_outcomes_and_keeps_unknown_fenced() {
    let cases = [
        (
            ReserveMode::ProbeApplied,
            SagaOperatorRecoveryOutcome::Repaired,
            vec!["forward_applied"],
        ),
        (
            ReserveMode::Applied,
            SagaOperatorRecoveryOutcome::Repaired,
            vec!["forward_not_applied"],
        ),
        (
            ReserveMode::ProbeUnknown,
            SagaOperatorRecoveryOutcome::StillUnknown,
            Vec::new(),
        ),
    ];

    for (mode, expected, repairs) in cases {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let store = Arc::new(FakeDurableStore::with_snapshot(operator_forward_snapshot(
            SagaOperatorReason::ForwardOutcomeUnknown,
        )));
        let executor = executor(Arc::clone(&store), mode, calls);

        assert_eq!(
            executor
                .recover_operator(operator_authorization(
                    SagaOperatorReason::ForwardOutcomeUnknown
                ),)
                .await,
            expected
        );
        assert_eq!(store.repairs(), repairs);
    }
}

#[tokio::test]
async fn operator_recovery_repairs_confirmed_compensation_outcome() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let store = Arc::new(FakeDurableStore::with_snapshot(
        operator_compensation_snapshot(),
    ));
    let executor = executor(
        Arc::clone(&store),
        ReserveMode::CompensationProbeApplied,
        calls,
    );

    assert_eq!(
        executor
            .recover_operator(operator_authorization(
                SagaOperatorReason::CompensationOutcomeUnknown
            ),)
            .await,
        SagaOperatorRecoveryOutcome::Repaired
    );
    assert_eq!(store.repairs(), vec!["compensation_applied"]);
}

#[tokio::test]
async fn lost_or_failed_lease_renewal_after_the_first_intent_never_calls_the_effect_provider() {
    let cases = [
        ("lost", Ok(SagaLeaseOutcome::Lost)),
        ("store-failure", Err(SagaDurableStoreErrorKind::Storage)),
    ];

    for (case, renewal_result) in cases {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let store = Arc::new(FakeDurableStore::with_renew_results([
            Ok(SagaLeaseOutcome::Held),
            renewal_result,
        ]));
        let executor = executor(Arc::clone(&store), ReserveMode::Applied, Arc::clone(&calls));

        assert!(
            matches!(
                executor.run(instance()).await,
                SagaOutcome::Interrupted {
                    reason: super::SagaInterruption::LeaseLost
                }
            ),
            "case {case}"
        );
        assert_eq!(store.mutations(), vec!["forward_intent"], "case {case}");
        assert!(
            calls
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .is_empty(),
            "case {case}"
        );
    }
}

#[tokio::test]
async fn lost_lease_after_a_retry_intent_never_calls_the_second_effect_attempt() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let store = Arc::new(FakeDurableStore::with_renew_results([
        Ok(SagaLeaseOutcome::Held),
        Ok(SagaLeaseOutcome::Held),
        Ok(SagaLeaseOutcome::Lost),
    ]));
    let executor = executor(
        Arc::clone(&store),
        ReserveMode::TransientThenApplied,
        Arc::clone(&calls),
    );

    assert!(matches!(
        executor.run(instance()).await,
        SagaOutcome::Interrupted {
            reason: super::SagaInterruption::LeaseLost
        }
    ));
    assert_eq!(store.mutations(), vec!["forward_intent", "forward_intent"]);
    assert_eq!(
        *calls.lock().unwrap_or_else(|error| error.into_inner()),
        vec!["reserve.execute"]
    );
}

#[tokio::test]
async fn run_preserves_forward_completion_integrity_classification_for_operator_recovery() {
    let cases = [
        (
            "conflict",
            Ok(SagaDurableMutationOutcome::Conflict),
            SagaOperatorReason::ReceiptIntegrity,
        ),
        (
            "integrity",
            Err(SagaDurableStoreErrorKind::Integrity),
            SagaOperatorReason::ReceiptIntegrity,
        ),
        (
            "unsupported-format",
            Err(SagaDurableStoreErrorKind::UnsupportedFormat),
            SagaOperatorReason::ReceiptFormatUnsupported,
        ),
    ];

    for (case, completion_result, expected_reason) in cases {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let store = Arc::new(FakeDurableStore::with_mutation_results([
            Ok(SagaDurableMutationOutcome::Applied),
            completion_result,
        ]));
        let executor = executor(Arc::clone(&store), ReserveMode::Applied, Arc::clone(&calls));

        assert!(
            matches!(
                executor.run(instance()).await,
                SagaOutcome::Interrupted {
                    reason: super::SagaInterruption::OperatorRequired
                }
            ),
            "case {case}"
        );
        assert_eq!(
            store.mutations(),
            vec!["forward_intent", "forward_completed", "operator_required"],
            "case {case}"
        );
        assert_eq!(
            store.operator_reasons(),
            vec![expected_reason],
            "case {case}"
        );
        assert_eq!(
            *calls.lock().unwrap_or_else(|error| error.into_inner()),
            vec!["reserve.execute"],
            "case {case}"
        );
    }
}

#[tokio::test]
async fn resume_preserves_forward_completion_integrity_classification_for_operator_recovery() {
    let cases = [
        (
            "conflict",
            Ok(SagaDurableMutationOutcome::Conflict),
            SagaOperatorReason::ReceiptIntegrity,
        ),
        (
            "integrity",
            Err(SagaDurableStoreErrorKind::Integrity),
            SagaOperatorReason::ReceiptIntegrity,
        ),
        (
            "unsupported-format",
            Err(SagaDurableStoreErrorKind::UnsupportedFormat),
            SagaOperatorReason::ReceiptFormatUnsupported,
        ),
    ];

    for (case, completion_result, expected_reason) in cases {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let store = Arc::new(FakeDurableStore::with_recovery_script(
            [inflight_reserve_snapshot()],
            [completion_result],
        ));
        let executor = executor(
            Arc::clone(&store),
            ReserveMode::ProbeApplied,
            Arc::clone(&calls),
        );

        assert!(
            matches!(
                executor.resume(instance(), definition()).await,
                SagaOutcome::Interrupted {
                    reason: super::SagaInterruption::OperatorRequired
                }
            ),
            "case {case}"
        );
        assert_eq!(
            store.mutations(),
            vec!["forward_completed", "operator_required"],
            "case {case}"
        );
        assert_eq!(
            store.operator_reasons(),
            vec![expected_reason],
            "case {case}"
        );
        assert_eq!(
            *calls.lock().unwrap_or_else(|error| error.into_inner()),
            vec!["reserve.probe"],
            "case {case}"
        );
    }
}

#[tokio::test]
async fn run_marks_a_missing_pinned_definition_with_the_typed_operator_reason() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let pinned = unsupported_definition();
    let store = Arc::new(FakeDurableStore::with_row(
        SagaInstanceRecord::new(
            instance(),
            SagaInstanceStatus::Ready,
            identity(),
            pinned.clone(),
        )
        .unwrap_or_else(|error| panic!("row: {error}")),
    ));
    let executor = executor(Arc::clone(&store), ReserveMode::Applied, calls);

    assert!(matches!(
        executor.run(instance()).await,
        SagaOutcome::Interrupted {
            reason: super::SagaInterruption::UnsupportedDefinition
        }
    ));
    assert_eq!(store.mutations(), vec!["operator_required"]);
    assert_eq!(
        store.operator_reasons(),
        vec![SagaOperatorReason::DefinitionUnsupported]
    );
}

#[tokio::test]
async fn resume_marks_a_missing_pinned_definition_with_the_typed_operator_reason() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let pinned = unsupported_definition();
    let store = Arc::new(FakeDurableStore::with_row(
        SagaInstanceRecord::new(
            instance(),
            SagaInstanceStatus::Running,
            identity(),
            pinned.clone(),
        )
        .unwrap_or_else(|error| panic!("row: {error}")),
    ));
    let executor = executor(Arc::clone(&store), ReserveMode::Applied, calls);

    assert!(matches!(
        executor.resume(instance(), pinned).await,
        SagaOutcome::Interrupted {
            reason: super::SagaInterruption::UnsupportedDefinition
        }
    ));
    assert_eq!(store.mutations(), vec!["operator_required"]);
    assert_eq!(
        store.operator_reasons(),
        vec![SagaOperatorReason::DefinitionUnsupported]
    );
}

#[tokio::test]
async fn missing_pinned_definition_never_bypasses_a_busy_fenced_lease() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let pinned = unsupported_definition();
    let store = Arc::new(FakeDurableStore::with_row_and_busy_claim(
        SagaInstanceRecord::new(
            instance(),
            SagaInstanceStatus::Running,
            identity(),
            pinned.clone(),
        )
        .unwrap_or_else(|error| panic!("row: {error}")),
    ));
    let executor = executor(Arc::clone(&store), ReserveMode::Applied, calls);

    assert!(matches!(
        executor.resume(instance(), pinned).await,
        SagaOutcome::Interrupted {
            reason: super::SagaInterruption::UnsupportedDefinition
        }
    ));
    assert!(store.mutations().is_empty());
    assert!(store.operator_reasons().is_empty());
}

#[tokio::test]
async fn missing_pinned_definition_does_not_retry_after_a_stale_fenced_mutation() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let pinned = unsupported_definition();
    let store = Arc::new(FakeDurableStore::with_row_and_lost_mutation(
        SagaInstanceRecord::new(
            instance(),
            SagaInstanceStatus::Running,
            identity(),
            pinned.clone(),
        )
        .unwrap_or_else(|error| panic!("row: {error}")),
    ));
    let executor = executor(Arc::clone(&store), ReserveMode::Applied, calls);

    assert!(matches!(
        executor.resume(instance(), pinned).await,
        SagaOutcome::Interrupted {
            reason: super::SagaInterruption::UnsupportedDefinition
        }
    ));
    assert_eq!(store.mutations(), vec!["operator_required"]);
    assert_eq!(
        store.operator_reasons(),
        vec![SagaOperatorReason::DefinitionUnsupported]
    );
}

#[tokio::test]
async fn uncertain_effect_with_unknown_probe_enters_operator_required_without_retry() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let store = Arc::new(FakeDurableStore::default());
    let executor = executor(
        Arc::clone(&store),
        ReserveMode::ProbeUnknown,
        Arc::clone(&calls),
    );

    assert!(matches!(
        executor.run(instance()).await,
        SagaOutcome::Interrupted { .. }
    ));
    assert_eq!(
        store.mutations(),
        vec!["forward_intent", "operator_required"]
    );
    assert_eq!(
        *calls.lock().unwrap_or_else(|error| error.into_inner()),
        vec!["reserve.execute", "reserve.probe"]
    );
}

#[tokio::test]
async fn commit_unknown_intent_is_read_back_before_the_effect_is_authorized() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let store = Arc::new(FakeDurableStore::with_recovery_script(
        [
            inflight_reserve_snapshot(),
            retried_reserve_intent_snapshot(),
        ],
        [Err(SagaDurableStoreErrorKind::CommitUnknown)],
    ));
    let executor = executor(Arc::clone(&store), ReserveMode::Applied, Arc::clone(&calls));

    assert!(matches!(
        executor.resume(instance(), definition()).await,
        SagaOutcome::Succeeded { .. }
    ));
    assert_eq!(
        *calls.lock().unwrap_or_else(|error| error.into_inner()),
        vec!["reserve.probe", "reserve.execute", "capture.execute"]
    );
    assert_eq!(
        store.mutations(),
        vec![
            "forward_intent",
            "forward_completed",
            "forward_intent",
            "forward_completed"
        ]
    );
}

#[tokio::test]
async fn recovery_does_not_exceed_the_durable_attempt_budget() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let store = Arc::new(FakeDurableStore::with_snapshot(
        exhausted_reserve_intents_snapshot(),
    ));
    let executor = executor(Arc::clone(&store), ReserveMode::Applied, Arc::clone(&calls));

    assert!(matches!(
        executor.resume(instance(), definition()).await,
        SagaOutcome::Failed { .. }
    ));
    assert_eq!(
        *calls.lock().unwrap_or_else(|error| error.into_inner()),
        vec!["reserve.probe"]
    );
    assert_eq!(
        store.mutations(),
        vec!["compensation_intent", "compensation_completed"]
    );
}

#[tokio::test]
async fn commit_unknown_completion_is_read_back_before_success_is_returned() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let store = Arc::new(FakeDurableStore::with_recovery_script(
        [completed_reserve_snapshot(), successful_capture_snapshot()],
        [
            Ok(SagaDurableMutationOutcome::Applied),
            Err(SagaDurableStoreErrorKind::CommitUnknown),
        ],
    ));
    let executor = executor(Arc::clone(&store), ReserveMode::Applied, Arc::clone(&calls));

    assert!(matches!(
        executor.resume(instance(), definition()).await,
        SagaOutcome::Succeeded { .. }
    ));
    assert_eq!(
        *calls.lock().unwrap_or_else(|error| error.into_inner()),
        vec!["capture.execute"]
    );
    assert_eq!(
        store.mutations(),
        vec!["forward_intent", "forward_completed"]
    );
}

#[tokio::test]
async fn uncertain_compensation_with_unknown_probe_enters_operator_required_without_retry() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let store = Arc::new(FakeDurableStore::default());
    let executor = executor_with_capture(
        Arc::clone(&store),
        ReserveMode::CompensationProbeUnknown,
        Arc::clone(&calls),
        true,
    );

    assert!(matches!(
        executor.run(instance()).await,
        SagaOutcome::Interrupted { .. }
    ));
    assert_eq!(
        store.mutations(),
        vec![
            "forward_intent",
            "forward_completed",
            "forward_intent",
            "compensation_intent",
            "operator_required"
        ]
    );
    assert_eq!(
        *calls.lock().unwrap_or_else(|error| error.into_inner()),
        vec![
            "reserve.execute",
            "capture.execute",
            "reserve.compensate",
            "reserve.probe_compensation"
        ]
    );
}

#[tokio::test]
async fn resume_retries_a_proven_not_applied_compensation_then_finishes_reverse_order() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let store = Arc::new(FakeDurableStore::with_snapshot(
        interrupted_compensation_snapshot(),
    ));
    let executor = executor(Arc::clone(&store), ReserveMode::Applied, Arc::clone(&calls));

    assert!(matches!(
        executor.resume(instance(), definition()).await,
        SagaOutcome::Failed { .. }
    ));
    assert_eq!(
        *calls.lock().unwrap_or_else(|error| error.into_inner()),
        vec!["capture.compensate", "reserve.compensate"]
    );
    assert_eq!(
        store.mutations(),
        vec![
            "compensation_intent",
            "compensation_completed",
            "compensation_intent",
            "compensation_completed"
        ]
    );
}

#[tokio::test]
async fn resume_requires_a_durable_receipt_after_completion_failure_and_compensation_crash() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let store = Arc::new(FakeDurableStore::with_snapshot(
        compensation_intent_without_forward_receipt_snapshot(),
    ));
    let executor = executor(Arc::clone(&store), ReserveMode::Applied, Arc::clone(&calls));

    assert!(matches!(
        executor.resume(instance(), definition()).await,
        SagaOutcome::Interrupted {
            reason: super::SagaInterruption::OperatorRequired
        }
    ));
    assert_eq!(store.mutations(), vec!["operator_required"]);
    assert_eq!(
        store.operator_reasons(),
        vec![SagaOperatorReason::ReceiptMissing]
    );
    assert!(
        calls
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .is_empty()
    );
}

#[tokio::test]
async fn permanent_forward_failure_compensates_hydrated_receipts_in_reverse_order() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let store = Arc::new(FakeDurableStore::default());
    let executor = executor_with_capture(
        Arc::clone(&store),
        ReserveMode::Applied,
        Arc::clone(&calls),
        true,
    );

    assert!(matches!(
        executor.run(instance()).await,
        SagaOutcome::Failed { .. }
    ));
    assert_eq!(
        store.mutations(),
        vec![
            "forward_intent",
            "forward_completed",
            "forward_intent",
            "compensation_intent",
            "compensation_completed"
        ]
    );
    assert_eq!(
        *calls.lock().unwrap_or_else(|error| error.into_inner()),
        vec!["reserve.execute", "capture.execute", "reserve.compensate"]
    );
}

#[tokio::test]
async fn retry_policy_matrix() {
    let cases = [
        (
            "forward transient succeeds within budget",
            ReserveMode::TransientThenApplied,
            CaptureMode::Applied,
            true,
            2,
        ),
        (
            "retryClass never does not retry transient failure",
            ReserveMode::Applied,
            CaptureMode::Transient,
            false,
            1,
        ),
    ];

    for (case, reserve_mode, capture_mode, succeeds, expected_reserve_calls) in cases {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let store = Arc::new(FakeDurableStore::default());
        let executor = executor_with_modes_and_dlx(
            Arc::clone(&store),
            reserve_mode,
            Arc::clone(&calls),
            capture_mode,
            Arc::new(NoopDeadLetterStore::default()),
        );

        let outcome = executor.run(instance()).await;
        assert_eq!(
            matches!(outcome, SagaOutcome::Succeeded { .. }),
            succeeds,
            "{case}"
        );
        let calls = calls.lock().unwrap_or_else(|error| error.into_inner());
        assert_eq!(
            calls
                .iter()
                .filter(|call| **call == "reserve.execute")
                .count(),
            expected_reserve_calls,
            "{case}",
        );
        if matches!(capture_mode, CaptureMode::Transient) {
            assert_eq!(
                calls
                    .iter()
                    .filter(|call| **call == "capture.execute")
                    .count(),
                1,
                "{case}",
            );
        }
        drop(calls);

        let forward_intents = store
            .journal_writes()
            .into_iter()
            .filter(|write| write.status == SagaJournalStatus::ForwardIntent)
            .collect::<Vec<_>>();
        if matches!(reserve_mode, ReserveMode::TransientThenApplied) {
            assert_eq!(forward_intents[0].attempt, 1, "{case}");
            assert_eq!(forward_intents[1].attempt, 2, "{case}");
            assert_eq!(
                forward_intents[0].effect_key, forward_intents[1].effect_key,
                "{case}"
            );
        } else {
            assert_eq!(
                forward_intents.last().map(|write| write.attempt),
                Some(1),
                "{case}"
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn retry_time_budget_is_one_phase_deadline() {
    let deadline = super::SagaPhaseDeadline::new(Duration::from_millis(10));
    tokio::time::advance(Duration::from_millis(4)).await;
    assert_eq!(deadline.remaining(), Duration::from_millis(6));
    assert!(deadline.sleep(Duration::from_millis(5)).await);
    assert_eq!(deadline.remaining(), Duration::from_millis(1));
    assert!(!deadline.sleep(Duration::from_millis(2)).await);
    assert!(deadline.remaining().is_zero());
}

#[tokio::test]
async fn compensation_dlx_matrix() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let store = Arc::new(FakeDurableStore::default());
    let executor = executor_with_modes_and_dlx(
        Arc::clone(&store),
        ReserveMode::CompensationTransientThenApplied,
        Arc::clone(&calls),
        CaptureMode::Permanent,
        Arc::new(NoopDeadLetterStore::default()),
    );
    assert!(matches!(
        executor.run(instance()).await,
        SagaOutcome::Failed { .. }
    ));
    assert_eq!(
        calls
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
            .filter(|call| **call == "reserve.compensate")
            .count(),
        2,
    );
    let compensation_intents = store
        .journal_writes()
        .into_iter()
        .filter(|write| write.status == SagaJournalStatus::CompensationIntent)
        .collect::<Vec<_>>();
    assert_eq!(
        compensation_intents
            .iter()
            .map(|write| write.attempt)
            .collect::<Vec<_>>(),
        vec![1, 2],
    );
    assert_eq!(
        compensation_intents[0].effect_key,
        compensation_intents[1].effect_key
    );

    for fail_dlx in [false, true] {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let store = Arc::new(FakeDurableStore::default());
        let dead_letter = Arc::new(if fail_dlx {
            NoopDeadLetterStore::failing()
        } else {
            NoopDeadLetterStore::default()
        });
        let executor = executor_with_modes_and_dlx(
            Arc::clone(&store),
            ReserveMode::CompensationPermanent,
            calls,
            CaptureMode::Permanent,
            Arc::clone(&dead_letter),
        );
        assert!(matches!(
            executor.run(instance()).await,
            SagaOutcome::Failed { .. }
        ));
        assert_eq!(dead_letter.writes(), 1, "fail_dlx={fail_dlx}");
        assert!(
            store
                .journal_writes()
                .iter()
                .any(|write| write.status == SagaJournalStatus::CompensationFailed),
            "durable compensation failure must survive DLX outcome; fail_dlx={fail_dlx}",
        );
    }
}

#[tokio::test]
async fn resume_hydrates_completed_receipt_and_skips_the_completed_effect() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let snapshot = completed_reserve_snapshot();
    let store = Arc::new(FakeDurableStore::with_snapshot(snapshot));
    let executor = executor(Arc::clone(&store), ReserveMode::Applied, Arc::clone(&calls));

    assert!(matches!(
        executor.resume(instance(), definition()).await,
        SagaOutcome::Succeeded { .. }
    ));
    assert_eq!(
        *calls.lock().unwrap_or_else(|error| error.into_inner()),
        vec!["capture.execute"]
    );
}

#[tokio::test]
async fn resume_probes_an_inflight_intent_before_authorizing_any_new_effect() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let snapshot = inflight_reserve_snapshot();
    let store = Arc::new(FakeDurableStore::with_snapshot(snapshot));
    let executor = executor(
        Arc::clone(&store),
        ReserveMode::ProbeApplied,
        Arc::clone(&calls),
    );

    assert!(matches!(
        executor.resume(instance(), definition()).await,
        SagaOutcome::Succeeded { .. }
    ));
    assert_eq!(
        *calls.lock().unwrap_or_else(|error| error.into_inner()),
        vec!["reserve.probe", "capture.execute"]
    );
}

#[test]
fn success_reference_never_exposes_receipt_or_effect_key() {
    let reference = SagaSuccessReference::for_test(
        instance(),
        identity(),
        definition(),
        generated::saga::billing_v1::STEP_1,
    );
    let rendered = format!("{reference:?}");
    assert_eq!(rendered, "SagaSuccessReference(<redacted>)");
    assert!(!rendered.contains("capture-1"));
}

fn executor(
    store: Arc<FakeDurableStore>,
    reserve_mode: ReserveMode,
    calls: Arc<Mutex<Vec<&'static str>>>,
) -> SagaExecutorImpl<FakeDurableStore, NoopDeadLetterStore> {
    executor_with_capture(store, reserve_mode, calls, false)
}

fn executor_with_capture(
    store: Arc<FakeDurableStore>,
    reserve_mode: ReserveMode,
    calls: Arc<Mutex<Vec<&'static str>>>,
    capture_fails: bool,
) -> SagaExecutorImpl<FakeDurableStore, NoopDeadLetterStore> {
    executor_with_modes_and_dlx(
        store,
        reserve_mode,
        calls,
        if capture_fails {
            CaptureMode::Permanent
        } else {
            CaptureMode::Applied
        },
        Arc::new(NoopDeadLetterStore::default()),
    )
}

fn executor_with_modes_and_dlx(
    store: Arc<FakeDurableStore>,
    reserve_mode: ReserveMode,
    calls: Arc<Mutex<Vec<&'static str>>>,
    capture_mode: CaptureMode,
    dead_letter: Arc<NoopDeadLetterStore>,
) -> SagaExecutorImpl<FakeDurableStore, NoopDeadLetterStore> {
    let factory = TypedSagaActionFactory::<Definition>::builder()
        .register::<Reserve, _>({
            let calls = Arc::clone(&calls);
            move || Reserve {
                mode: reserve_mode,
                calls: Arc::clone(&calls),
            }
        })
        .register::<Capture, _>({
            let calls = Arc::clone(&calls);
            move || Capture {
                calls: Arc::clone(&calls),
                mode: capture_mode,
            }
        })
        .finish();
    let config = SagaExecutorConfig::from_typed_factory(
        CheckpointOwner::new("billing"),
        "test-holder",
        Duration::from_secs(30),
        &factory,
    )
    .unwrap_or_else(|error| panic!("config: {error}"));
    let registry = super::SagaDefinitionRegistry::builder()
        .register(factory)
        .unwrap_or_else(|error| panic!("registry: {error}"))
        .finish();
    SagaExecutorImpl::new(SagaExecutorDeps::new(store, dead_letter, registry), config)
        .unwrap_or_else(|error| panic!("executor: {error}"))
}

fn completed_reserve_snapshot() -> SagaRecoverySnapshot {
    let scope = receipt_scope(generated::saga::billing_v1::STEP_0);
    let receipt = BillingReserveFundsReceipt {
        reservation_id: "durable-reservation".into(),
    };
    let plaintext = serde_json_canonicalizer::to_vec(&receipt)
        .unwrap_or_else(|error| panic!("receipt: {error}"));
    SagaRecoverySnapshot::new(
        row(SagaInstanceStatus::Running),
        vec![
            SagaJournalRecord::replayed(
                0,
                vocab::StepName::parse("reserve_funds")
                    .unwrap_or_else(|error| panic!("step: {error}")),
                SagaJournalStatus::ForwardIntent,
            ),
            SagaJournalRecord::replayed(
                1,
                vocab::StepName::parse("reserve_funds")
                    .unwrap_or_else(|error| panic!("step: {error}")),
                SagaJournalStatus::ForwardCompleted,
            ),
        ],
        vec![StoredSagaReceipt::new(
            scope,
            consistency::SagaAttempt::new(1).unwrap_or_else(|error| panic!("attempt: {error}")),
            SagaReceiptFormatVersion::V1,
            secure::Plaintext::new(plaintext),
            1,
        )],
        None,
        None,
    )
}

fn inflight_reserve_snapshot() -> SagaRecoverySnapshot {
    SagaRecoverySnapshot::new(
        row(SagaInstanceStatus::Running),
        vec![SagaJournalRecord::replayed(
            0,
            vocab::StepName::parse("reserve_funds").unwrap_or_else(|error| panic!("step: {error}")),
            SagaJournalStatus::ForwardIntent,
        )],
        Vec::new(),
        None,
        None,
    )
}

fn retried_reserve_intent_snapshot() -> SagaRecoverySnapshot {
    let step =
        vocab::StepName::parse("reserve_funds").unwrap_or_else(|error| panic!("step: {error}"));
    SagaRecoverySnapshot::new(
        row(SagaInstanceStatus::Running),
        vec![
            SagaJournalRecord::replayed(0, step.clone(), SagaJournalStatus::ForwardIntent),
            SagaJournalRecord::replayed(1, step, SagaJournalStatus::ForwardIntent),
        ],
        Vec::new(),
        None,
        None,
    )
}

fn exhausted_reserve_intents_snapshot() -> SagaRecoverySnapshot {
    let step =
        vocab::StepName::parse("reserve_funds").unwrap_or_else(|error| panic!("step: {error}"));
    SagaRecoverySnapshot::new(
        row(SagaInstanceStatus::Running),
        vec![
            SagaJournalRecord::replayed(0, step.clone(), SagaJournalStatus::ForwardIntent),
            SagaJournalRecord::replayed(1, step.clone(), SagaJournalStatus::ForwardIntent),
            SagaJournalRecord::replayed(2, step, SagaJournalStatus::ForwardIntent),
        ],
        Vec::new(),
        None,
        None,
    )
}

fn successful_capture_snapshot() -> SagaRecoverySnapshot {
    let reserve =
        vocab::StepName::parse("reserve_funds").unwrap_or_else(|error| panic!("step: {error}"));
    let capture = vocab::StepName::parse("capture").unwrap_or_else(|error| panic!("step: {error}"));
    let receipt = BillingCaptureReceipt {
        capture_id: "durable-capture".into(),
    };
    let plaintext = serde_json_canonicalizer::to_vec(&receipt)
        .unwrap_or_else(|error| panic!("receipt: {error}"));
    SagaRecoverySnapshot::new(
        row(SagaInstanceStatus::Succeeded),
        vec![
            SagaJournalRecord::replayed(0, reserve.clone(), SagaJournalStatus::ForwardIntent),
            SagaJournalRecord::replayed(1, reserve, SagaJournalStatus::ForwardCompleted),
            SagaJournalRecord::replayed(2, capture.clone(), SagaJournalStatus::ForwardIntent),
            SagaJournalRecord::replayed(3, capture, SagaJournalStatus::ForwardCompleted),
        ],
        vec![StoredSagaReceipt::new(
            receipt_scope(generated::saga::billing_v1::STEP_1),
            consistency::SagaAttempt::new(1).unwrap_or_else(|error| panic!("attempt: {error}")),
            SagaReceiptFormatVersion::V1,
            secure::Plaintext::new(plaintext),
            3,
        )],
        None,
        None,
    )
}

fn interrupted_compensation_snapshot() -> SagaRecoverySnapshot {
    let reserve =
        vocab::StepName::parse("reserve_funds").unwrap_or_else(|error| panic!("step: {error}"));
    let capture = vocab::StepName::parse("capture").unwrap_or_else(|error| panic!("step: {error}"));
    let reserve_plaintext = serde_json_canonicalizer::to_vec(&BillingReserveFundsReceipt {
        reservation_id: "durable-reservation".into(),
    })
    .unwrap_or_else(|error| panic!("receipt: {error}"));
    let capture_plaintext = serde_json_canonicalizer::to_vec(&BillingCaptureReceipt {
        capture_id: "durable-capture".into(),
    })
    .unwrap_or_else(|error| panic!("receipt: {error}"));
    SagaRecoverySnapshot::new(
        row(SagaInstanceStatus::Compensating),
        vec![
            SagaJournalRecord::replayed(0, reserve.clone(), SagaJournalStatus::ForwardIntent),
            SagaJournalRecord::replayed(1, reserve.clone(), SagaJournalStatus::ForwardCompleted),
            SagaJournalRecord::replayed(2, capture.clone(), SagaJournalStatus::ForwardIntent),
            SagaJournalRecord::replayed(3, capture.clone(), SagaJournalStatus::ForwardCompleted),
            SagaJournalRecord::replayed(4, capture, SagaJournalStatus::CompensationIntent),
        ],
        vec![
            StoredSagaReceipt::new(
                receipt_scope(generated::saga::billing_v1::STEP_0),
                consistency::SagaAttempt::new(1).unwrap_or_else(|error| panic!("attempt: {error}")),
                SagaReceiptFormatVersion::V1,
                secure::Plaintext::new(reserve_plaintext),
                1,
            ),
            StoredSagaReceipt::new(
                receipt_scope(generated::saga::billing_v1::STEP_1),
                consistency::SagaAttempt::new(1).unwrap_or_else(|error| panic!("attempt: {error}")),
                SagaReceiptFormatVersion::V1,
                secure::Plaintext::new(capture_plaintext),
                3,
            ),
        ],
        None,
        Some(consistency::SagaCompensationCause::BusinessFailure),
    )
}

fn compensation_intent_without_forward_receipt_snapshot() -> SagaRecoverySnapshot {
    let reserve =
        vocab::StepName::parse("reserve_funds").unwrap_or_else(|error| panic!("step: {error}"));
    SagaRecoverySnapshot::new(
        row(SagaInstanceStatus::Compensating),
        vec![
            SagaJournalRecord::replayed(0, reserve.clone(), SagaJournalStatus::ForwardIntent),
            SagaJournalRecord::replayed(1, reserve, SagaJournalStatus::CompensationIntent),
        ],
        Vec::new(),
        None,
        Some(consistency::SagaCompensationCause::BusinessFailure),
    )
}

fn operator_forward_snapshot(reason: SagaOperatorReason) -> SagaRecoverySnapshot {
    SagaRecoverySnapshot::new(
        operator_row(reason),
        vec![SagaJournalRecord::replayed(
            0,
            vocab::StepName::parse("reserve_funds").unwrap_or_else(|error| panic!("step: {error}")),
            SagaJournalStatus::ForwardIntent,
        )],
        Vec::new(),
        Some(reason),
        None,
    )
}

fn operator_compensation_snapshot() -> SagaRecoverySnapshot {
    let reserve =
        vocab::StepName::parse("reserve_funds").unwrap_or_else(|error| panic!("step: {error}"));
    let plaintext = serde_json_canonicalizer::to_vec(&BillingReserveFundsReceipt {
        reservation_id: "durable-reservation".into(),
    })
    .unwrap_or_else(|error| panic!("receipt: {error}"));
    SagaRecoverySnapshot::new(
        operator_row(SagaOperatorReason::CompensationOutcomeUnknown),
        vec![
            SagaJournalRecord::replayed(0, reserve.clone(), SagaJournalStatus::ForwardIntent),
            SagaJournalRecord::replayed(1, reserve.clone(), SagaJournalStatus::ForwardCompleted),
            SagaJournalRecord::replayed(2, reserve, SagaJournalStatus::CompensationIntent),
        ],
        vec![StoredSagaReceipt::new(
            receipt_scope(generated::saga::billing_v1::STEP_0),
            consistency::SagaAttempt::new(1).unwrap_or_else(|error| panic!("attempt: {error}")),
            SagaReceiptFormatVersion::V1,
            secure::Plaintext::new(plaintext),
            1,
        )],
        Some(SagaOperatorReason::CompensationOutcomeUnknown),
        Some(consistency::SagaCompensationCause::BusinessFailure),
    )
}

fn operator_row(reason: SagaOperatorReason) -> SagaInstanceRecord {
    row(SagaInstanceStatus::OperatorRequired)
        .with_operator_reason(reason)
        .unwrap_or_else(|error| panic!("operator row: {error}"))
}

fn operator_authorization(reason: SagaOperatorReason) -> SagaOperatorRepairAuthorization {
    let ticket = SagaOperatorChangeTicket::parse("CHG-1925")
        .unwrap_or_else(|error| panic!("change ticket: {error}"));
    let start_audit_id = SagaOperatorStartAuditId::parse("audit-1925")
        .unwrap_or_else(|error| panic!("start audit id: {error}"));
    diport::test_support::saga_operator_repair_authorization(
        vocab::ServiceCallerDomain::MaintenanceOperator,
        identity(),
        instance(),
        reason,
        ticket,
        start_audit_id,
    )
}

fn receipt_scope(binding: vocab::SagaStepBinding) -> SagaReceiptScope {
    let effect_key =
        SagaIdempotencyKey::derive(instance(), &definition(), binding, SagaEffectPhase::Forward);
    SagaReceiptScope::new(instance(), identity(), definition(), binding, effect_key)
        .unwrap_or_else(|error| panic!("scope: {error}"))
}

fn row(status: SagaInstanceStatus) -> SagaInstanceRecord {
    SagaInstanceRecord::new(instance(), status, identity(), definition())
        .unwrap_or_else(|error| panic!("row: {error}"))
}

fn instance() -> SagaInstanceRef {
    SagaInstanceRef::new(
        vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .unwrap_or_else(|error| panic!("tenant: {error}")),
        SagaId::new(uuid::Uuid::from_u128(42)),
    )
    .unwrap_or_else(|error| panic!("instance: {error}"))
}

fn definition() -> consistency::SagaDefinitionIdentity {
    consistency::SagaDefinitionIdentity::from_binding(generated::saga::billing_v1::SPEC)
}

fn unsupported_definition() -> consistency::SagaDefinitionIdentity {
    consistency::SagaDefinitionIdentity::new(
        "billing.checkout",
        "v404",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )
    .unwrap_or_else(|error| panic!("definition: {error}"))
}

fn identity() -> SagaWorkerIdentity {
    SagaWorkerIdentity::new(
        "billing",
        diport::SagaContractId::parse("billing.checkout")
            .unwrap_or_else(|error| panic!("contract: {error}")),
    )
    .unwrap_or_else(|error| panic!("identity: {error}"))
}

fn store_error(message: &'static str) -> SagaDurableStoreError {
    SagaDurableStoreError::new(
        SagaDurableStoreErrorKind::Storage,
        std::io::Error::other(message),
    )
}
