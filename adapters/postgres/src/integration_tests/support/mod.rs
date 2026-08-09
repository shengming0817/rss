//! Shared private helpers for postgres integration seam tests.

pub(super) use audit::ports::AuditListTenantAppender as _;

pub(super) use authn::{AccountSecurityEventKind, AuthGrant, AuthnEpoch, GrantSecurityEventKind};

pub(super) use consistency::{
    BacklogObservation, CommandErrorSummary, CommandJournalOutcome, CommandJournalTerminalSummary,
    CommandResultSummary, ConsumerGroup, ConvergeAction, IdemKey, InboxBacklog, InboxBacklogScope,
    InboxReceiptContext, InboxStore, LeaseToken, OutboxPayload, Outcome, SeenState,
};

pub(super) use diport::{CertNotAfter, CertScope, CertSerial, ManagedResource, RevocationStore};

pub(super) use eventexec::command::{
    CommandAliasKey, CommandIdempotencyKeyring, CommandJournalStore, CommandStoreError,
    JournaledCommandDispatcher, ReviewedCommandJournal,
};

pub(super) use eventexec::reconcile::{
    AttemptSchedule, ClaimedTarget, ClaimedTargetRestore, FailureStreak, ReconcileAttempt,
    ReconcileWake, ReviewedFencedCommand, ScheduleResultOutcome, WakeVersion,
};

pub(super) use eventexec::{
    AttemptResult, AttemptTrigger, OperatorReconcileCapability, ReconcileMaxInFlight,
    ReconcileOperatorStore, ReconcileQuarantineReason, ReconcileScheduleErrorKind,
    ReconcileScheduleStore, ReconcileTargetStatus, ScheduleActionOutcome, ScheduleAttemptOutcome,
};

pub(super) use futures::future::{BoxFuture, poll_fn};

pub(super) use identity::ports::AccountReactivationLifecycle as _;

pub(super) use identity::ports::device_certificate::{
    AcceptDesiredPolicy, ArtifactAppendAuthorization, ArtifactAppendOutcome, ArtifactDigest,
    AuthorizedDeviceCertificateStatusRead, CertificateArtifactId, CertificateArtifactRequest,
    CertificateAttemptFence, CertificatePublicKeyDigest, CertificateReadyProof,
    CertificateReconcileRepository as _, CertificateRevocationObservation, ConditionStateBatch,
    DesiredPolicyAcceptOutcome, DeviceCertificateRepository as _, DeviceCertificateScope,
    DeviceCertificateStatusStore as _, DevicePolicyIdempotencyKey, ExpectedGeneration,
    PersistedCertificateArtifactSnapshot, PolicyHash, ProductionEligibility,
    ProviderCertificateCandidate, ReportedStateHash,
};

pub(super) use settings::ports::SettingsProjectionReadRepoLocal as _;

pub(super) use sha2::{Digest as _, Sha256};

pub(super) use std::future::Future;

pub(super) use testkit::projection_conformance::{
    ProjectionConformanceBinding, ProjectionConformanceFixture,
};
pub(super) use testkit::{await_delay, await_map, await_try};

pub(super) use crate::reconcile::{
    ReconcileActionErrorKind, ReconcileAttemptResultInsert, ReconcileLeaseOutcome,
    ReconcileTargetKey,
};

pub(super) use crate::{PgConfig, PgError, PgPassword, PgRuntimeDeps, PgSslMode, PgStore};

/// The only owner allowed to mint arbitrary contract identities for synthetic test fixtures.
///
/// Keeping the constructors inside this inline `cfg(test)` module makes the capability absent
/// from every production rustc graph while allowing support fixtures to exercise negative and
/// multi-binding cases that intentionally have no generated contract.
#[cfg(test)]
mod binding_fixture_mint {
    pub(crate) const fn contract(
        domain: &'static str,
        contract_id: &'static str,
        version: &'static str,
        schema_hash: &'static str,
    ) -> vocab::ContractBinding {
        vocab::ContractBinding::from_static(domain, contract_id, version, schema_hash)
    }

    pub(crate) const fn projection_input(
        projection_id: &'static str,
        domain: &'static str,
        contract_id: &'static str,
        version: &'static str,
        schema_hash: &'static str,
        topic: &'static str,
    ) -> vocab::ProjectionInputBinding {
        vocab::ProjectionInputBinding::from_static(
            projection_id,
            domain,
            contract_id,
            version,
            schema_hash,
            topic,
        )
    }
}

#[cfg(test)]
pub(super) use binding_fixture_mint::{
    contract as test_contract_binding, projection_input as test_projection_input_binding,
};

// 统一 Send+Sync 错误（= testkit::FixtureError）：sqlx::Error / PgError / FixtureError 均 Send+Sync，
// 全 `?` 无跨界转换（避免 Box<dyn Error+Send+Sync> → Box<dyn Error> 的 ? 转换 papercut）。
pub(super) type TestError = Box<dyn std::error::Error + Send + Sync>;

pub(super) type TestResult = Result<(), TestError>;

pub(super) use crate::SETTINGS_PROJECTION_ID;

mod audit_support;
mod device;
mod eventing;
mod identity_support;
mod runtime;
mod settings_support;

pub(super) use audit_support::*;
pub(super) use device::*;
pub(super) use eventing::*;
pub(super) use identity_support::*;
pub(super) use runtime::*;
pub(super) use settings_support::*;
