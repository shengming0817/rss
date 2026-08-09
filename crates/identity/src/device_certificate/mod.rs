//! Identity-owned persistence boundary for DeviceLatent certificate state.
//!
//! Certificate policy, generation/fence vocabulary, and condition state remain owned by
//! `deviceloop`. This module contains only authenticated persistence inputs, restored snapshots,
//! and the repository port for desired/reported/condition tables.
//!
//! ref: kube-rs/kube kube-runtime/src/controller/mod.rs@main

mod domain;
mod ingress;
mod port;
mod reconcile;
mod status;

pub use domain::{
    AcceptDesiredPolicy, ArtifactDigest, ConditionStateBatch, DesiredPolicyAccepted,
    DesiredPolicyAcceptedCondition, DesiredStateRestore, DesiredStateSnapshot,
    DeviceCertificateError, DeviceCertificateScope, DeviceCertificateStateSnapshot,
    DevicePolicyIdempotencyKey, DevicePolicyRequestDigest, DeviceSequence, ExpectedGeneration,
    PolicyHash, ReportEnvelopeId, ReportedStateHash, ReportedStateRestore, ReportedStateSnapshot,
    ReportedStateWrite,
};
pub use eventexec::reconcile::{DeviceCertificateCommandTtl, DeviceCertificateCommandTtlError};
pub use ingress::{
    DeviceIngressApplicationReceipt, DeviceIngressContract, DeviceIngressDelivery,
    DeviceIngressDomainOutcome, DeviceIngressError, DeviceIngressPreparation,
    DeviceIngressReceiptMismatch, DeviceIngressRepository, DeviceIngressWrite,
    PendingDeviceIngress, PreparedDeviceIngress, UnaddressableDeviceIngress,
    UnaddressableDeviceIngressReason, application_receipt, device_ingress_receipt_fact,
    prepare_device_ingress,
};
pub use port::{
    ArtifactAppendOutcome, CertificateAttemptAuthority, CertificateAttemptFence,
    CertificateConditionMutation, CertificateReconcileRepository,
    CertificateReconcileRepositoryError, CertificateReconcileRepositoryLocal,
    CertificateReconcileView, CertificateTransportObservation, CurrentCommandExpiryOutcome,
    DeletionRequestOutcome, DesiredPolicyAcceptOutcome, DeviceCertificateRepository,
    DeviceCertificateRepositoryError, DeviceCertificateRepositoryLocal,
    DynDeviceCertificateRepository, FencedMutationOutcome, RotationOutcome,
};
pub use reconcile::{
    CertificateReadyProof, CertificateReadyProofError, CertificateRevocationObservation,
    DeviceCertificateReconciler,
};
pub use status::{
    AuthorizedDeviceCertificateStatusRead, DeviceCertificateActiveCommand,
    DeviceCertificateActiveCommandState, DeviceCertificateStatusAuthorizationError,
    DeviceCertificateStatusEvidence, DeviceCertificateStatusPortEffect,
    DeviceCertificateStatusProjectionError, DeviceCertificateStatusStore,
    DeviceCertificateStatusStoreError, DeviceCertificateStatusStoreLocal,
    DeviceLatentObservationError, DynDeviceCertificateStatusStore,
};

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use std::time::{Duration, SystemTime};

    use deviceloop::{
        CertificateKeyUsage, CertificatePolicy, CertificatePolicyDurations,
        CertificateRenewBeforeSeconds, CertificateSan, CertificateValiditySeconds, ConditionStatus,
        DegradedReason, DeletingReason, DeviceConditionRestore, DeviceConditionState, FenceEpoch,
        ObservedGeneration, PendingDeviceReason, QuarantinedReason, ReadyReason, ReconcilingReason,
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

    fn desired(generation: u64) -> DesiredStateRestore {
        DesiredStateRestore::new(
            generation,
            PolicyHash::parse(&digest('a')).unwrap(),
            policy(),
            SystemTime::UNIX_EPOCH,
            SystemTime::UNIX_EPOCH,
        )
    }

    fn reported(observed_generation: u64) -> ReportedStateRestore {
        ReportedStateRestore::new(
            observed_generation,
            1,
            ReportedStateHash::parse(&digest('b')).unwrap(),
            ArtifactDigest::parse(&digest('c')).unwrap(),
            ReportEnvelopeId::parse("status-report").unwrap(),
            DeviceSequence::try_new(1).unwrap(),
            None,
            None,
            SystemTime::UNIX_EPOCH,
        )
    }

    fn status_state(
        desired_generation: u64,
        observed_generation: Option<u64>,
        conditions: Vec<DeviceConditionRestore>,
    ) -> DeviceCertificateStateSnapshot {
        DeviceCertificateStateSnapshot::restore(
            scope(),
            desired(desired_generation),
            observed_generation.map(reported),
            conditions,
        )
        .unwrap()
    }

    fn active_command(
        state: DeviceCertificateActiveCommandState,
        queued_at: u64,
        published_at: Option<u64>,
        received_at: Option<u64>,
    ) -> DeviceCertificateActiveCommand {
        DeviceCertificateActiveCommand::restore(
            deviceloop::DesiredGeneration::try_new(7).unwrap(),
            FenceEpoch::try_new(11).unwrap(),
            state,
            SystemTime::UNIX_EPOCH + Duration::from_secs(queued_at),
            published_at.map(|value| SystemTime::UNIX_EPOCH + Duration::from_secs(value)),
            received_at.map(|value| SystemTime::UNIX_EPOCH + Duration::from_secs(value)),
        )
        .unwrap()
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

    #[test]
    fn status_active_command_state_and_temporal_progress_are_closed() {
        for (raw, expected) in [
            ("queued", DeviceCertificateActiveCommandState::Queued),
            ("published", DeviceCertificateActiveCommandState::Published),
            ("received", DeviceCertificateActiveCommandState::Received),
        ] {
            assert_eq!(
                DeviceCertificateActiveCommandState::restore(raw).unwrap(),
                expected
            );
        }
        for terminal in [
            "applied",
            "rejected",
            "timed_out",
            "superseded",
            "cancelled",
            "unknown",
        ] {
            assert!(DeviceCertificateActiveCommandState::restore(terminal).is_err());
        }

        let invalid_progress = [
            (
                DeviceCertificateActiveCommandState::Queued,
                90,
                Some(95),
                None,
            ),
            (
                DeviceCertificateActiveCommandState::Queued,
                90,
                None,
                Some(95),
            ),
            (
                DeviceCertificateActiveCommandState::Published,
                90,
                None,
                None,
            ),
            (
                DeviceCertificateActiveCommandState::Published,
                90,
                Some(89),
                None,
            ),
            (
                DeviceCertificateActiveCommandState::Published,
                90,
                Some(95),
                Some(96),
            ),
            (
                DeviceCertificateActiveCommandState::Received,
                90,
                None,
                Some(96),
            ),
            (
                DeviceCertificateActiveCommandState::Received,
                90,
                Some(95),
                None,
            ),
            (
                DeviceCertificateActiveCommandState::Received,
                90,
                Some(89),
                Some(96),
            ),
            (
                DeviceCertificateActiveCommandState::Received,
                90,
                Some(95),
                Some(94),
            ),
        ];
        for (state, queued_at, published_at, received_at) in invalid_progress {
            assert!(
                DeviceCertificateActiveCommand::restore(
                    deviceloop::DesiredGeneration::try_new(7).unwrap(),
                    FenceEpoch::try_new(11).unwrap(),
                    state,
                    SystemTime::UNIX_EPOCH + Duration::from_secs(queued_at),
                    published_at.map(|value| SystemTime::UNIX_EPOCH + Duration::from_secs(value)),
                    received_at.map(|value| SystemTime::UNIX_EPOCH + Duration::from_secs(value)),
                )
                .is_err(),
                "accepted invalid {state:?} timestamp progression"
            );
        }
    }

    #[test]
    fn status_wire_projection_covers_every_closed_condition_reason() {
        struct Case {
            condition: DeviceConditionRestore,
            kind: &'static str,
            status: &'static str,
            reason: &'static str,
        }

        let observed = ObservedGeneration::try_new(6).unwrap();
        let transition = SystemTime::UNIX_EPOCH + Duration::from_secs(123);
        let mut cases = Vec::new();
        for (index, reason) in ReadyReason::ALL.into_iter().enumerate() {
            let status = if index % 2 == 0 {
                ConditionStatus::False
            } else {
                ConditionStatus::Unknown
            };
            cases.push(Case {
                condition: DeviceConditionRestore::ready(
                    status,
                    reason,
                    Some(observed),
                    transition,
                ),
                kind: "Ready",
                status: status.as_label(),
                reason: reason.as_label(),
            });
        }
        for (index, reason) in ReconcilingReason::ALL.into_iter().enumerate() {
            let status = ConditionStatus::ALL[index % ConditionStatus::ALL.len()];
            cases.push(Case {
                condition: DeviceConditionRestore::reconciling(
                    status,
                    reason,
                    Some(observed),
                    transition,
                ),
                kind: "Reconciling",
                status: status.as_label(),
                reason: reason.as_label(),
            });
        }
        for (index, reason) in PendingDeviceReason::ALL.into_iter().enumerate() {
            let status = ConditionStatus::ALL[index % ConditionStatus::ALL.len()];
            cases.push(Case {
                condition: DeviceConditionRestore::pending_device(
                    status,
                    reason,
                    Some(observed),
                    transition,
                ),
                kind: "PendingDevice",
                status: status.as_label(),
                reason: reason.as_label(),
            });
        }
        for (index, reason) in DegradedReason::ALL.into_iter().enumerate() {
            let status = ConditionStatus::ALL[index % ConditionStatus::ALL.len()];
            cases.push(Case {
                condition: DeviceConditionRestore::degraded(
                    status,
                    reason,
                    Some(observed),
                    transition,
                ),
                kind: "Degraded",
                status: status.as_label(),
                reason: reason.as_label(),
            });
        }
        for (index, reason) in QuarantinedReason::ALL.into_iter().enumerate() {
            let status = ConditionStatus::ALL[index % ConditionStatus::ALL.len()];
            cases.push(Case {
                condition: DeviceConditionRestore::quarantined(
                    status,
                    reason,
                    Some(observed),
                    transition,
                ),
                kind: "Quarantined",
                status: status.as_label(),
                reason: reason.as_label(),
            });
        }
        for (index, reason) in DeletingReason::ALL.into_iter().enumerate() {
            let status = ConditionStatus::ALL[index % ConditionStatus::ALL.len()];
            cases.push(Case {
                condition: DeviceConditionRestore::deleting(
                    status,
                    reason,
                    Some(observed),
                    transition,
                ),
                kind: "Deleting",
                status: status.as_label(),
                reason: reason.as_label(),
            });
        }

        assert_eq!(cases.len(), 25);
        for case in cases {
            let evidence = DeviceCertificateStatusEvidence::restore(
                status_state(7, None, vec![case.condition]),
                None,
                transition,
            )
            .unwrap();
            let json = serde_json::to_value(evidence.to_wire_response().unwrap()).unwrap();
            let condition = &json["data"]["conditions"][0];
            assert_eq!(condition["type"], case.kind);
            assert_eq!(condition["status"], case.status);
            assert_eq!(condition["reason"], case.reason);
            assert_eq!(condition["observedGeneration"], 6);
            assert_eq!(condition["lastTransitionAt"], 123);
        }
    }

    #[test]
    fn status_evidence_rejects_active_command_generation_mismatch() {
        let observed_at = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let mismatched = DeviceCertificateActiveCommand::restore(
            deviceloop::DesiredGeneration::try_new(8).unwrap(),
            FenceEpoch::try_new(11).unwrap(),
            DeviceCertificateActiveCommandState::Queued,
            SystemTime::UNIX_EPOCH + Duration::from_secs(90),
            None,
            None,
        )
        .unwrap();
        assert!(matches!(
            DeviceCertificateStatusEvidence::restore(
                status_state(7, None, vec![]),
                Some(mismatched),
                observed_at,
            ),
            Err(DeviceCertificateError::InvalidPersistedValue)
        ));
    }

    #[test]
    fn status_wire_active_command_is_payload_and_identifier_free() {
        for (command, expected_state) in [
            (
                active_command(DeviceCertificateActiveCommandState::Queued, 90, None, None),
                "queued",
            ),
            (
                active_command(
                    DeviceCertificateActiveCommandState::Published,
                    90,
                    Some(95),
                    None,
                ),
                "published",
            ),
            (
                active_command(
                    DeviceCertificateActiveCommandState::Received,
                    90,
                    Some(95),
                    Some(98),
                ),
                "received",
            ),
        ] {
            let evidence = DeviceCertificateStatusEvidence::restore(
                status_state(7, None, vec![]),
                Some(command),
                SystemTime::UNIX_EPOCH + Duration::from_secs(100),
            )
            .unwrap();
            let json = serde_json::to_value(evidence.to_wire_response().unwrap()).unwrap();
            assert_eq!(
                json["data"]["activeCommand"],
                serde_json::json!({
                    "generation": 7,
                    "fenceEpoch": 11,
                    "state": expected_state,
                })
            );
            let rendered = serde_json::to_string(&json).unwrap();
            for forbidden in [
                "commandId",
                "command_id",
                "<redacted>",
                "CERTIFICATE-BAIT",
                "PRIVATE-KEY-BAIT",
                "CSR-BAIT",
            ] {
                assert!(!rendered.contains(forbidden));
            }
        }
    }

    #[test]
    fn status_observation_derives_exact_closed_numeric_samples() {
        let observed_at = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let drift = DeviceConditionRestore::ready(
            ConditionStatus::False,
            ReadyReason::StateDrift,
            Some(ObservedGeneration::try_new(4).unwrap()),
            SystemTime::UNIX_EPOCH + Duration::from_secs(80),
        );
        let cases = [
            (None, None, None),
            (
                Some(active_command(
                    DeviceCertificateActiveCommandState::Queued,
                    90,
                    None,
                    None,
                )),
                Some(Duration::from_secs(10)),
                None,
            ),
            (
                Some(active_command(
                    DeviceCertificateActiveCommandState::Published,
                    90,
                    Some(95),
                    None,
                )),
                Some(Duration::from_secs(5)),
                Some(Duration::from_secs(5)),
            ),
            (
                Some(active_command(
                    DeviceCertificateActiveCommandState::Received,
                    90,
                    Some(95),
                    Some(98),
                )),
                Some(Duration::from_secs(5)),
                Some(Duration::from_secs(3)),
            ),
        ];
        for (command, queue_age, ack_latency) in cases {
            let evidence = DeviceCertificateStatusEvidence::restore(
                status_state(7, Some(4), vec![drift.clone()]),
                command,
                observed_at,
            )
            .unwrap();
            assert_eq!(
                evidence.observation().unwrap(),
                observ::DeviceLatentObservation::new(
                    3,
                    Some(Duration::from_secs(20)),
                    queue_age,
                    ack_latency,
                )
            );
        }

        let without_report = DeviceCertificateStatusEvidence::restore(
            status_state(7, None, vec![]),
            None,
            observed_at,
        )
        .unwrap();
        assert_eq!(
            without_report.observation().unwrap(),
            observ::DeviceLatentObservation::new(7, None, None, None)
        );
    }

    #[test]
    fn status_evidence_rejects_every_future_timestamp_before_observation() {
        let observed_at = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let future_commands = [
            active_command(DeviceCertificateActiveCommandState::Queued, 101, None, None),
            active_command(
                DeviceCertificateActiveCommandState::Published,
                90,
                Some(101),
                None,
            ),
            active_command(
                DeviceCertificateActiveCommandState::Received,
                90,
                Some(95),
                Some(101),
            ),
        ];
        for command in future_commands {
            assert!(
                DeviceCertificateStatusEvidence::restore(
                    status_state(7, None, vec![]),
                    Some(command),
                    observed_at,
                )
                .is_err()
            );
        }

        let observed = Some(ObservedGeneration::try_new(6).unwrap());
        let future = SystemTime::UNIX_EPOCH + Duration::from_secs(101);
        let future_conditions = [
            DeviceConditionRestore::ready(
                ConditionStatus::False,
                ReadyReason::StateDrift,
                observed,
                future,
            ),
            DeviceConditionRestore::reconciling(
                ConditionStatus::True,
                ReconcilingReason::CommandQueued,
                observed,
                future,
            ),
            DeviceConditionRestore::pending_device(
                ConditionStatus::True,
                PendingDeviceReason::AwaitingDevice,
                observed,
                future,
            ),
            DeviceConditionRestore::degraded(
                ConditionStatus::True,
                DegradedReason::ProtocolViolation,
                observed,
                future,
            ),
            DeviceConditionRestore::quarantined(
                ConditionStatus::True,
                QuarantinedReason::QuarantinedByOperator,
                observed,
                future,
            ),
            DeviceConditionRestore::deleting(
                ConditionStatus::True,
                DeletingReason::DeletionPending,
                observed,
                future,
            ),
        ];
        for condition in future_conditions {
            let observation_formed = std::cell::Cell::new(false);
            let result = DeviceCertificateStatusEvidence::restore(
                status_state(7, None, vec![condition]),
                None,
                observed_at,
            )
            .map(|evidence| {
                observation_formed.set(true);
                evidence.observation()
            });
            assert!(result.is_err());
            assert!(!observation_formed.get());
        }

        let boundary = active_command(
            DeviceCertificateActiveCommandState::Received,
            100,
            Some(100),
            Some(100),
        );
        assert!(
            DeviceCertificateStatusEvidence::restore(
                status_state(7, None, vec![]),
                Some(boundary),
                observed_at,
            )
            .is_ok()
        );
    }

    #[test]
    fn status_read_requires_exact_route_permission_and_path_resource() {
        let scope = scope();
        let resource =
            || httpserve::RouteResource::new(scope.device().as_uuid().hyphenated().to_string());
        let subject = |contract_id, permission, resource| {
            httpserve::AuthorizedSubject::for_test(
                contract_id,
                permission,
                scope.tenant(),
                vocab::PrincipalKind::Admin,
                "status-test-operator",
                resource,
            )
        };
        let exact = subject(
            generated::http::identity_v2::device_certificate_status_get::CONTRACT_ID,
            vocab::RoutePermissionId::IdentityDeviceCertificateStatusRead,
            resource(),
        );
        let query =
            AuthorizedDeviceCertificateStatusRead::from_authorized_subject(&exact, scope.device())
                .unwrap();
        assert_eq!(query.scope(), scope);
        assert_eq!(query.projection(), exact.projection());
        let debug = format!("{query:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&scope.tenant().to_string()));
        assert!(!debug.contains(&scope.device().as_uuid().hyphenated().to_string()));

        let wrong_contract = subject(
            generated::http::identity_v2::device_certificate_policy_put::CONTRACT_ID,
            vocab::RoutePermissionId::IdentityDeviceCertificateStatusRead,
            resource(),
        );
        let wrong_permission = subject(
            generated::http::identity_v2::device_certificate_status_get::CONTRACT_ID,
            vocab::RoutePermissionId::IdentityDeviceCertificatePolicyWrite,
            resource(),
        );
        let missing_resource = subject(
            generated::http::identity_v2::device_certificate_status_get::CONTRACT_ID,
            vocab::RoutePermissionId::IdentityDeviceCertificateStatusRead,
            None,
        );
        let other_device = ids::DeviceId::new(uuid::Uuid::new_v4());
        let mismatched_resource = subject(
            generated::http::identity_v2::device_certificate_status_get::CONTRACT_ID,
            vocab::RoutePermissionId::IdentityDeviceCertificateStatusRead,
            httpserve::RouteResource::new(other_device.as_uuid().hyphenated().to_string()),
        );
        for rejected in [
            wrong_contract,
            wrong_permission,
            missing_resource,
            mismatched_resource,
        ] {
            assert!(
                AuthorizedDeviceCertificateStatusRead::from_authorized_subject(
                    &rejected,
                    scope.device(),
                )
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn status_store_port_is_dyn_compatible_and_read_only() {
        struct MissingStatus;

        impl DeviceCertificateStatusStore for MissingStatus {
            async fn inspect(
                &self,
                _query: AuthorizedDeviceCertificateStatusRead,
            ) -> Result<Option<DeviceCertificateStatusEvidence>, DeviceCertificateStatusStoreError>
            {
                Ok(None)
            }
        }

        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        fn assert_read_effect<T>()
        where
            T: DeviceCertificateStatusPortEffect<
                    Effect = diport::ReadEffect,
                    Privilege = diport::LocalPrivilege,
                > + ?Sized,
        {
        }

        assert_send_sync::<DynDeviceCertificateStatusStore>();
        assert_read_effect::<DynDeviceCertificateStatusStore<'static>>();
        let _store: Box<DynDeviceCertificateStatusStore> =
            DynDeviceCertificateStatusStore::new_box(MissingStatus);
    }
}
