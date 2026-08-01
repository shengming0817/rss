//! Identity-owned persistence boundary for DeviceLatent certificate state.
//!
//! Certificate policy, generation/fence vocabulary, and condition state remain owned by
//! `deviceloop`. This module contains only authenticated persistence inputs, restored snapshots,
//! and the repository port for desired/reported/condition tables.
//!
//! ref: kube-rs/kube kube-runtime/src/controller/mod.rs@main

mod domain;
mod port;
mod reconcile;

pub use domain::{
    AcceptDesiredPolicy, ArtifactDigest, ConditionStateBatch, DesiredPolicyAccepted,
    DesiredPolicyAcceptedCondition, DesiredStateRestore, DesiredStateSnapshot,
    DeviceCertificateError, DeviceCertificateScope, DeviceCertificateStateSnapshot,
    DevicePolicyIdempotencyKey, DevicePolicyRequestDigest, DeviceSequence, ExpectedGeneration,
    PolicyHash, ReportEnvelopeId, ReportedStateHash, ReportedStateRestore, ReportedStateSnapshot,
    ReportedStateWrite, ReportedWriteOutcome,
};
pub use eventexec::reconcile::{DeviceCertificateCommandTtl, DeviceCertificateCommandTtlError};
pub use port::{
    ArtifactAppendOutcome, CertificateAttemptAuthority, CertificateAttemptFence,
    CertificateConditionMutation, CertificateReconcileRepository,
    CertificateReconcileRepositoryError, CertificateReconcileRepositoryLocal,
    CertificateReconcileView, CertificateTransportObservation, DeletionRequestOutcome,
    DesiredPolicyAcceptOutcome, DeviceCertificateRepository, DeviceCertificateRepositoryError,
    DeviceCertificateRepositoryLocal, DynCertificateReconcileRepository,
    DynDeviceCertificateRepository, FencedMutationOutcome, RotationOutcome,
};
pub use reconcile::{
    CertificateReadyProof, CertificateReadyProofError, CertificateRevocationObservation,
    DeviceCertificateReconciler,
};

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use std::time::SystemTime;

    use deviceloop::{
        CertificateKeyUsage, CertificatePolicy, CertificatePolicyDurations,
        CertificateRenewBeforeSeconds, CertificateSan, CertificateValiditySeconds, ConditionStatus,
        DegradedReason, DeviceConditionState, FenceEpoch, ObservedGeneration,
    };

    use super::*;

    fn scope() -> DeviceCertificateScope {
        DeviceCertificateScope::for_test(
            vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap(),
            ids::DeviceId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap(),
        )
    }

    fn policy() -> CertificatePolicy {
        CertificatePolicy::new(
            CertificatePolicyDurations::new(
                CertificateValiditySeconds::try_new(3_600).unwrap(),
                CertificateRenewBeforeSeconds::try_new(300).unwrap(),
            )
            .unwrap(),
            vec![CertificateKeyUsage::ClientAuth],
            vec![CertificateSan::parse("device.example").unwrap()],
        )
        .unwrap()
    }

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    #[test]
    fn desired_accept_input_derives_generation_and_canonical_request_digest() {
        let key = DevicePolicyIdempotencyKey::new(
            uuid::Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap(),
        );
        let input = AcceptDesiredPolicy::for_test(
            scope(),
            ExpectedGeneration::try_new(0).unwrap(),
            key,
            policy(),
        )
        .unwrap();
        assert_eq!(input.next_generation().unwrap().get(), 1);
        assert_eq!(input.policy().sans()[0].as_str(), "device.example");
        assert_eq!(input.idempotency_key(), key);
        assert_eq!(input.request_digest().as_bytes().len(), 32);
        assert_eq!(
            format!("{:?}", input.request_digest()),
            "DevicePolicyRequestDigest(<sha256>)"
        );

        let same = AcceptDesiredPolicy::for_test(
            scope(),
            ExpectedGeneration::try_new(0).unwrap(),
            key,
            policy(),
        )
        .unwrap();
        let changed_generation = AcceptDesiredPolicy::for_test(
            scope(),
            ExpectedGeneration::try_new(1).unwrap(),
            key,
            policy(),
        )
        .unwrap();
        assert_eq!(input.request_digest(), same.request_digest());
        assert_ne!(input.request_digest(), changed_generation.request_digest());
        assert!(
            AcceptDesiredPolicy::for_test(
                scope(),
                ExpectedGeneration::try_new(i64::MAX as u64).unwrap(),
                key,
                policy(),
            )
            .is_err()
        );
    }

    #[test]
    fn accepted_policy_result_has_closed_fresh_condition() {
        let result =
            DesiredPolicyAccepted::fresh(ExpectedGeneration::try_new(0).unwrap().next().unwrap());
        assert_eq!(result.accepted_generation().get(), 1);
        assert_eq!(
            result.condition(),
            DesiredPolicyAcceptedCondition::Reconciling
        );
        assert_eq!(result.condition().as_label(), "reconciling");
    }

    #[test]
    fn semantic_digests_are_exact_and_redacted() {
        let policy_hash = PolicyHash::parse(&digest('a')).unwrap();
        let state_hash = ReportedStateHash::parse(&digest('b')).unwrap();
        let artifact = ArtifactDigest::parse(&digest('c')).unwrap();
        assert_eq!(policy_hash.as_bytes().len(), 32);
        assert_ne!(state_hash.as_bytes(), artifact.as_bytes());
        assert_eq!(format!("{policy_hash:?}"), "PolicyHash(<sha256>)");
        assert!(ArtifactDigest::parse(&format!("sha256:{}", "A".repeat(64))).is_err());
    }

    #[test]
    fn condition_mutation_is_timestamp_free_and_duplicate_closed() {
        let state = DeviceConditionState::degraded(
            ConditionStatus::True,
            DegradedReason::ProtocolViolation,
            Some(ObservedGeneration::try_new(1).unwrap()),
        );
        assert_eq!(state.status_label(), "True");
        assert_eq!(state.reason_label(), "ProtocolViolation");
        assert!(ConditionStateBatch::for_test(vec![state.clone(), state]).is_err());
        assert_eq!(ConditionStateBatch::for_test(vec![]).unwrap().states(), &[]);
    }

    #[test]
    fn desired_and_reported_snapshots_restore_storage_invariants() {
        let desired = DesiredStateRestore::new(
            1,
            PolicyHash::parse(&digest('a')).unwrap(),
            policy(),
            SystemTime::UNIX_EPOCH,
            SystemTime::UNIX_EPOCH,
        );
        let reported = ReportedStateRestore::new(
            1,
            7,
            ReportedStateHash::parse(&digest('b')).unwrap(),
            ArtifactDigest::parse(&digest('c')).unwrap(),
            ReportEnvelopeId::parse("report-1").unwrap(),
            DeviceSequence::try_new(1).unwrap(),
            None,
            None,
            SystemTime::UNIX_EPOCH,
        );
        let state =
            DeviceCertificateStateSnapshot::restore(scope(), desired, Some(reported), vec![])
                .unwrap();
        assert_eq!(state.desired().generation().get(), 1);
        assert_eq!(state.reported().unwrap().fence_epoch().get(), 7);
    }

    #[test]
    fn reported_ahead_of_desired_fails_restore() {
        let desired = DesiredStateRestore::new(
            1,
            PolicyHash::parse(&digest('a')).unwrap(),
            policy(),
            SystemTime::UNIX_EPOCH,
            SystemTime::UNIX_EPOCH,
        );
        let reported = ReportedStateRestore::new(
            2,
            1,
            ReportedStateHash::parse(&digest('b')).unwrap(),
            ArtifactDigest::parse(&digest('c')).unwrap(),
            ReportEnvelopeId::parse("report-2").unwrap(),
            DeviceSequence::try_new(2).unwrap(),
            None,
            None,
            SystemTime::UNIX_EPOCH,
        );
        assert_eq!(
            DeviceCertificateStateSnapshot::restore(scope(), desired, Some(reported), vec![]),
            Err(DeviceCertificateError::ReportedAheadOfDesired)
        );
    }

    struct NoopRepository;

    impl DeviceCertificateRepository for NoopRepository {
        async fn accept_desired_policy(
            &self,
            input: AcceptDesiredPolicy,
        ) -> Result<DesiredPolicyAcceptOutcome, DeviceCertificateRepositoryError> {
            Ok(DesiredPolicyAcceptOutcome::ExpectedGenerationConflict {
                actual: input.expected_generation(),
            })
        }

        async fn advance_reported(
            &self,
            _input: ReportedStateWrite,
        ) -> Result<ReportedWriteOutcome, DeviceCertificateRepositoryError> {
            Ok(ReportedWriteOutcome::MissingDesired)
        }

        async fn load_state(
            &self,
            _scope: DeviceCertificateScope,
        ) -> Result<Option<DeviceCertificateStateSnapshot>, DeviceCertificateRepositoryError>
        {
            Ok(None)
        }
    }

    #[tokio::test]
    async fn repository_port_is_dyn_compatible() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<DynDeviceCertificateRepository>();
        let repository: Box<DynDeviceCertificateRepository> =
            DynDeviceCertificateRepository::new_box(NoopRepository);
        let desired = AcceptDesiredPolicy::for_test(
            scope(),
            ExpectedGeneration::try_new(0).unwrap(),
            DevicePolicyIdempotencyKey::new(
                uuid::Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap(),
            ),
            policy(),
        )
        .unwrap();
        assert!(matches!(
            DeviceCertificateRepository::accept_desired_policy(&repository, desired).await,
            Ok(DesiredPolicyAcceptOutcome::ExpectedGenerationConflict { .. })
        ));
    }

    #[test]
    fn report_input_records_epoch_but_does_not_claim_current_fence() {
        let report = ReportedStateWrite::for_test(
            scope(),
            ObservedGeneration::try_new(1).unwrap(),
            FenceEpoch::try_new(41).unwrap(),
            ReportedStateHash::parse(&digest('a')).unwrap(),
            ArtifactDigest::parse(&digest('b')).unwrap(),
            ReportEnvelopeId::parse("report-epoch").unwrap(),
            DeviceSequence::try_new(7).unwrap(),
            None,
            None,
        );
        assert_eq!(report.fence_epoch().get(), 41);
    }

    #[test]
    fn report_input_defers_provider_timestamp_range_to_storage() {
        let before_postgres_epoch = SystemTime::UNIX_EPOCH
            .checked_sub(std::time::Duration::from_micros(210_866_803_200_000_001))
            .unwrap();
        let report = ReportedStateWrite::for_test(
            scope(),
            ObservedGeneration::try_new(1).unwrap(),
            FenceEpoch::try_new(41).unwrap(),
            ReportedStateHash::parse(&digest('a')).unwrap(),
            ArtifactDigest::parse(&digest('b')).unwrap(),
            ReportEnvelopeId::parse("report-time").unwrap(),
            DeviceSequence::try_new(7).unwrap(),
            Some(before_postgres_epoch),
            None,
        );
        assert_eq!(report.expires_at(), Some(before_postgres_epoch));
    }
}
