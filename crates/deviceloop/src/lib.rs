//! deviceloop — L4 设备长延迟收敛模型。
//!
//! 对标：
//! - kube-rs `kube-runtime/src/controller/mod.rs`（`reconcile(obj, ctx) -> Result<Action, E>` +
//!   `error_policy`；`Action::requeue / await_change`）
//! - statig `statig/src/lib.rs`（显式 state/event transition；RSS 使用手写闭值集，不引入宏）
//!
//! 分层：服务层（依赖基础 + 引擎；不依赖域 / adapters）。

pub mod command;
pub mod condition;
pub mod generation;
pub mod policy;
pub mod store;

pub use command::{
    CommandIntentDigest, CommandProgressRestore, CommandProgressSnapshot, CommandRestoreCommon,
    CommandSnapshotCommon, CommandTransitionOutcome, CommandVersion, DeviceCommandError,
    DeviceCommandId, DeviceCommandRestore, DeviceCommandScope, DeviceCommandSnapshot,
    DeviceCommandSnapshotView, DeviceCommandState, DeviceCommandStatus, DeviceCommandTransition,
    DeviceCommandTransitionError,
};
pub use condition::{
    AuthorizedArtifactDigest, ConditionRestoreError, ConditionStatus, CurrentCertificateStatus,
    DegradedCondition, DegradedConditionRestore, DegradedConditionSnapshot, DegradedConditionState,
    DegradedReason, DeletingCondition, DeletingConditionRestore, DeletingConditionSnapshot,
    DeletingConditionState, DeletingReason, DeviceCondition, DeviceConditionKind,
    DeviceConditionRestore, DeviceConditionSnapshot, DeviceConditionState, ExpectedStateHash,
    NotReadyStatus, PendingDeviceCondition, PendingDeviceConditionRestore,
    PendingDeviceConditionSnapshot, PendingDeviceConditionState, PendingDeviceReason,
    QuarantinedCondition, QuarantinedConditionRestore, QuarantinedConditionSnapshot,
    QuarantinedConditionState, QuarantinedReason, ReadyCondition, ReadyConditionRestore,
    ReadyConditionSnapshot, ReadyConditionState, ReadyProof, ReadyProofError, ReadyReason,
    ReadyStatus, ReconcilingCondition, ReconcilingConditionRestore, ReconcilingConditionSnapshot,
    ReconcilingConditionState, ReconcilingReason, ReportedArtifactDigest, ReportedStateHash,
    UpdateCommandState,
};
pub use generation::{
    CurrentFence, CurrentFenceReportRestore, DesiredAdvanceError, DesiredGeneration,
    FenceCoordinate, FenceEpoch, GenerationRestore, GenerationRestoreError, GenerationSnapshot,
    GenerationTracker, InvalidGenerationCoordinate, MatchingReportedState, ObservedGeneration,
    ObservedHighWaterRestore, ReportOutcome, SupersedingFence,
};
pub use policy::{
    CertificateKeyUsage, CertificatePolicy, CertificatePolicyDurations, CertificatePolicyError,
    CertificateRenewBeforeSeconds, CertificateSan, CertificateValiditySeconds,
};
pub use store::{
    AppendDeviceIngressOutcome, CreateDeviceCommand, CreateDeviceCommandOutcome,
    DeviceCommandCorruption, DeviceCommandDeadline, DeviceCommandDeadlineError,
    DeviceCommandMutation, DeviceCommandStore, DeviceCommandStoreError, DeviceIngressCorruption,
    DeviceIngressDisposition, DeviceIngressEnvelopeId, DeviceIngressError, DeviceIngressEvidence,
    DeviceIngressEvidenceView, DeviceIngressFingerprint, DeviceIngressReceipt, DeviceSequence,
    InvalidDeviceSequence, TransitionDeviceCommandOutcome,
};
