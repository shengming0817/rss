//! Draft device-certificate desired-policy candidate handler.

use std::num::NonZeroU64;
use std::sync::Arc;

use generated::http::identity_v2::device_certificate_policy_put as wire;
use ids::DeviceId;

type ValidationField = wire::IdentityDeviceCertificatePolicyPutValidationDetailField;
type ValidationReason = wire::IdentityDeviceCertificatePolicyPutValidationDetailReason;

use crate::ports::device_certificate::{
    AcceptDesiredPolicy, DesiredPolicyAcceptOutcome, DesiredPolicyAccepted,
    DeviceCertificateRepository, DeviceCertificateRepositoryError, DevicePolicyAcceptInputError,
    DevicePolicyIdempotencyKey, DynDeviceCertificateRepository, ExpectedGeneration,
};

/// Candidate-only handler. It is deliberately not a generated route or production mount.
pub(crate) struct DeviceCertificatePolicyCandidateHandler {
    repository: Arc<DynDeviceCertificateRepository<'static>>,
    binding: httpserve::DevicePolicyCandidateBindingKey,
}

impl DeviceCertificatePolicyCandidateHandler {
    /// Construct from the mandatory desired-policy repository capability.
    #[must_use]
    pub(super) fn new(
        repository: Arc<DynDeviceCertificateRepository<'static>>,
        binding: httpserve::DevicePolicyCandidateBindingKey,
    ) -> Self {
        Self {
            repository,
            binding,
        }
    }

    /// Validate, authorize-bind, and atomically accept one Draft desired policy.
    pub async fn handle(
        &self,
        subject: &httpserve::AuthorizedSubject,
        device: DeviceId,
        request: wire::IdentityDeviceCertificatePolicyPutRequest,
        request_id: httpserve::VerifiedRequestId,
    ) -> wire::IdentityDeviceCertificatePolicyPutHandlerResult {
        let response_id = request_id.clone();
        let request_id_text = request_id.as_str().to_owned();
        let Some(correlation_id) = diagctx::correlation()
            .or_else(|| diagctx::CorrelationId::parse(request_id.as_str()).ok())
        else {
            return Err(
                wire::IdentityDeviceCertificatePolicyPutFrameworkFailure::internal(
                    response_id.into_wire(),
                ),
            );
        };
        let correlation_id_text = correlation_id.as_str().to_owned();
        let input = match candidate_input(
            subject,
            &self.binding,
            device,
            request,
            request_id,
            correlation_id,
        ) {
            Ok(input) => input,
            Err(CandidateInputError::Validation { field, reason }) => {
                return Ok(validation_response(request_id_text, field, reason));
            }
            Err(CandidateInputError::Authorization) => {
                return Err(
                    wire::IdentityDeviceCertificatePolicyPutFrameworkFailure::internal(
                        response_id.into_wire(),
                    ),
                );
            }
        };
        match self.repository.accept_desired_policy(input).await {
            Ok(DesiredPolicyAcceptOutcome::Accepted { result, .. })
            | Ok(DesiredPolicyAcceptOutcome::Replayed { result }) => accepted_response(result)
                .ok_or_else(|| {
                    wire::IdentityDeviceCertificatePolicyPutFrameworkFailure::internal(
                        response_id.into_wire(),
                    )
                }),
            Ok(DesiredPolicyAcceptOutcome::ExpectedGenerationConflict { .. }) => {
                Ok(version_conflict_response(request_id_text))
            }
            Ok(DesiredPolicyAcceptOutcome::IdempotencyConflict)
            | Err(DeviceCertificateRepositoryError::ReconcileTargetQuarantined) => {
                Ok(conflict_response(request_id_text))
            }
            Err(DeviceCertificateRepositoryError::ReconcileEnrollmentMissing) => {
                Ok(not_found_response(request_id_text))
            }
            Err(DeviceCertificateRepositoryError::InvalidMutation) => Ok(validation_response(
                request_id_text,
                ValidationField::Policy,
                ValidationReason::InvalidMutation,
            )),
            Err(DeviceCertificateRepositoryError::StorageUnavailable { .. }) => {
                log_internal_failure(
                    "storage_unavailable",
                    &request_id_text,
                    &correlation_id_text,
                    subject.tenant_id(),
                );
                Ok(
                    wire::IdentityDeviceCertificatePolicyPutResponseEnvelope::Error(
                        wire::IdentityDeviceCertificatePolicyPutResponseError::status_503(
                            response_id.into_wire(),
                        ),
                    ),
                )
            }
            Err(DeviceCertificateRepositoryError::SettlementUnknown { .. }) => {
                log_internal_failure(
                    "settlement_unknown",
                    &request_id_text,
                    &correlation_id_text,
                    subject.tenant_id(),
                );
                Err(
                    wire::IdentityDeviceCertificatePolicyPutFrameworkFailure::internal(
                        response_id.into_wire(),
                    ),
                )
            }
            Err(DeviceCertificateRepositoryError::CorruptState(_)) => {
                log_internal_failure(
                    "corrupt_state",
                    &request_id_text,
                    &correlation_id_text,
                    subject.tenant_id(),
                );
                Err(
                    wire::IdentityDeviceCertificatePolicyPutFrameworkFailure::internal(
                        response_id.into_wire(),
                    ),
                )
            }
        }
    }

    pub(super) fn validation_failure(
        request_id: httpserve::VerifiedRequestId,
        field: ValidationField,
        reason: ValidationReason,
    ) -> wire::IdentityDeviceCertificatePolicyPutHandlerResult {
        Ok(validation_response(
            request_id.as_str().to_owned(),
            field,
            reason,
        ))
    }
}

fn log_internal_failure(
    failure_kind: &'static str,
    request_id: &str,
    correlation_id: &str,
    tenant_id: rss_request_context::TenantId,
) {
    tracing::error!(
        failure_kind,
        request_id,
        correlation_id,
        tenant_id = %tenant_id,
        domain = "identity",
        contract_id = wire::CONTRACT_ID,
        "device-policy candidate request failed"
    );
}

enum CandidateInputError {
    Validation {
        field: ValidationField,
        reason: ValidationReason,
    },
    Authorization,
}

fn candidate_input(
    subject: &httpserve::AuthorizedSubject,
    binding: &httpserve::DevicePolicyCandidateBindingKey,
    device: DeviceId,
    request: wire::IdentityDeviceCertificatePolicyPutRequest,
    request_id: httpserve::VerifiedRequestId,
    correlation_id: diagctx::CorrelationId,
) -> Result<AcceptDesiredPolicy, CandidateInputError> {
    let expected_generation = u64::try_from(request.expected_generation)
        .ok()
        .and_then(|value| ExpectedGeneration::try_new(value).ok())
        .ok_or(CandidateInputError::Validation {
            field: ValidationField::ExpectedGeneration,
            reason: ValidationReason::OutOfRange,
        })?;
    let policy = deviceloop::CertificatePolicy::restore(
        u64::try_from(request.policy.validity_seconds).map_err(|_| {
            CandidateInputError::Validation {
                field: ValidationField::Policy,
                reason: ValidationReason::OutOfRange,
            }
        })?,
        u64::try_from(request.policy.renew_before_seconds).map_err(|_| {
            CandidateInputError::Validation {
                field: ValidationField::Policy,
                reason: ValidationReason::OutOfRange,
            }
        })?,
        request
            .policy
            .key_usages
            .into_iter()
            .map(|usage| usage.to_string())
            .collect(),
        request
            .policy
            .sans
            .unwrap_or_default()
            .into_iter()
            .map(String::from)
            .collect(),
    )
    .map_err(|_| CandidateInputError::Validation {
        field: ValidationField::Policy,
        reason: ValidationReason::InvalidPolicy,
    })?;
    AcceptDesiredPolicy::from_authorized_http_subject(
        subject,
        binding,
        device,
        expected_generation,
        DevicePolicyIdempotencyKey::new(request.idempotency_key),
        policy,
        request_id,
        correlation_id,
    )
    .map_err(|error| match error {
        DevicePolicyAcceptInputError::InvalidInput(_) => CandidateInputError::Validation {
            field: ValidationField::Policy,
            reason: ValidationReason::InvalidPolicy,
        },
        DevicePolicyAcceptInputError::Unauthorized => CandidateInputError::Authorization,
    })
}

fn accepted_response(
    result: DesiredPolicyAccepted,
) -> Option<wire::IdentityDeviceCertificatePolicyPutResponseEnvelope> {
    let accepted_generation = NonZeroU64::new(result.accepted_generation().get())?;
    let authorization_receipt_id = generated::device_certificate::AuthorizationReceiptId::try_from(
        result.authorization_receipt_id().as_uuid(),
    )
    .ok()?;
    Some(
        wire::IdentityDeviceCertificatePolicyPutResponseEnvelope::Success(
            wire::IdentityDeviceCertificatePolicyPutResponse {
                data: wire::IdentityDeviceCertificatePolicyPutData {
                    accepted_generation,
                    authorization_receipt_id,
                    condition: wire::IdentityDeviceCertificatePolicyPutDataCondition::Reconciling,
                },
            },
        ),
    )
}

fn validation_response(
    request_id: String,
    field: ValidationField,
    reason: ValidationReason,
) -> wire::IdentityDeviceCertificatePolicyPutResponseEnvelope {
    wire::IdentityDeviceCertificatePolicyPutResponseEnvelope::Error(
        wire::IdentityDeviceCertificatePolicyPutResponseError::status_400(
            wire::IdentityDeviceCertificatePolicyPutValidationResponse {
                error: wire::IdentityDeviceCertificatePolicyPutValidationError {
                    code: wire::IdentityDeviceCertificatePolicyPutValidationErrorCode::ErrCoreValidation,
                    details: [wire::IdentityDeviceCertificatePolicyPutValidationDetail {
                        field,
                        reason,
                    }],
                    message: wire::IdentityDeviceCertificatePolicyPutValidationErrorMessage::ValidationFailed,
                    request_id,
                    retryable: false,
                },
            },
        ),
    )
}

fn not_found_response(
    request_id: String,
) -> wire::IdentityDeviceCertificatePolicyPutResponseEnvelope {
    wire::IdentityDeviceCertificatePolicyPutResponseEnvelope::Error(
        wire::IdentityDeviceCertificatePolicyPutResponseError::status_404(
            wire::IdentityDeviceCertificatePolicyPutNotFoundResponse {
                error: wire::IdentityDeviceCertificatePolicyPutNotFoundError {
                    code:
                        wire::IdentityDeviceCertificatePolicyPutNotFoundErrorCode::ErrCoreNotFound,
                    details: Vec::new(),
                    message: wire::IdentityDeviceCertificatePolicyPutNotFoundErrorMessage::NotFound,
                    request_id,
                    retryable: false,
                },
            },
        ),
    )
}

fn version_conflict_response(
    request_id: String,
) -> wire::IdentityDeviceCertificatePolicyPutResponseEnvelope {
    conflict_envelope(
        wire::IdentityDeviceCertificatePolicyPutConflictError::ErrCoreVersionConflict {
            details: Vec::new(),
            message:
                wire::IdentityDeviceCertificatePolicyPutVersionConflictMessage::VersionConflict,
            request_id,
            retryable: true,
        },
    )
}

fn conflict_response(
    request_id: String,
) -> wire::IdentityDeviceCertificatePolicyPutResponseEnvelope {
    conflict_envelope(
        wire::IdentityDeviceCertificatePolicyPutConflictError::ErrCoreConflict {
            details: Vec::new(),
            message: wire::IdentityDeviceCertificatePolicyPutGeneralConflictMessage::Conflict,
            request_id,
            retryable: false,
        },
    )
}

fn conflict_envelope(
    error: wire::IdentityDeviceCertificatePolicyPutConflictError,
) -> wire::IdentityDeviceCertificatePolicyPutResponseEnvelope {
    wire::IdentityDeviceCertificatePolicyPutResponseEnvelope::Error(
        wire::IdentityDeviceCertificatePolicyPutResponseError::status_409(
            wire::IdentityDeviceCertificatePolicyPutConflictResponse { error },
        ),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    use axum::response::IntoResponse;
    use deviceloop::{
        CertificatePolicy, CertificatePolicyDurations, CertificateRenewBeforeSeconds,
        CertificateValiditySeconds,
    };
    use uuid::Uuid;

    enum Case {
        Accepted,
        Replayed,
        Missing,
        GenerationConflict,
        IdempotencyConflict,
        Quarantined,
        InvalidMutation,
        Storage,
        SettlementUnknown,
        Corrupt,
    }

    struct TestRepository(Case);

    impl crate::ports::device_certificate::DeviceCertificateRepository for TestRepository {
        async fn accept_desired_policy(
            &self,
            input: AcceptDesiredPolicy,
        ) -> Result<DesiredPolicyAcceptOutcome, DeviceCertificateRepositoryError> {
            assert_eq!(input.request_id(), "0191f7d4-34d7-7b42-9fcb-9e85b92f42a1");
            assert_eq!(input.correlation_id(), input.request_id());
            let accepted = || {
                DesiredPolicyAccepted::fresh(
                    crate::ports::device_certificate::DevicePolicyAuthorizationReceiptId::restore(
                        Uuid::parse_str("0191f7d4-34d7-7b42-9fcb-9e85b92f42a2")
                            .expect("receipt fixture"),
                    )
                    .expect("receipt fixture"),
                    ExpectedGeneration::try_new(0)
                        .expect("generation fixture")
                        .next()
                        .expect("next generation"),
                )
            };
            match self.0 {
                Case::Accepted => Ok(DesiredPolicyAcceptOutcome::Accepted {
                    result: accepted(),
                    wake: eventexec::reconcile::ReconcileWake::new(
                        "target-1",
                        eventexec::reconcile::WakeVersion::try_new(1).expect("wake fixture"),
                    ),
                }),
                Case::Replayed => Ok(DesiredPolicyAcceptOutcome::Replayed { result: accepted() }),
                Case::Missing => Err(DeviceCertificateRepositoryError::ReconcileEnrollmentMissing),
                Case::GenerationConflict => {
                    Ok(DesiredPolicyAcceptOutcome::ExpectedGenerationConflict {
                        actual: ExpectedGeneration::try_new(7).expect("actual generation"),
                    })
                }
                Case::IdempotencyConflict => Ok(DesiredPolicyAcceptOutcome::IdempotencyConflict),
                Case::Quarantined => {
                    Err(DeviceCertificateRepositoryError::ReconcileTargetQuarantined)
                }
                Case::InvalidMutation => Err(DeviceCertificateRepositoryError::InvalidMutation),
                Case::Storage => Err(DeviceCertificateRepositoryError::storage_unavailable(
                    std::io::Error::other("test storage"),
                )),
                Case::SettlementUnknown => {
                    Err(DeviceCertificateRepositoryError::settlement_unknown(
                        std::io::Error::other("test settlement"),
                    ))
                }
                Case::Corrupt => Err(DeviceCertificateRepositoryError::CorruptState(
                    crate::ports::device_certificate::DeviceCertificateError::InvalidDigest,
                )),
            }
        }
    }

    fn subject(
        device: DeviceId,
        binding: httpserve::DevicePolicyCandidateBindingKey,
    ) -> httpserve::AuthorizedSubject {
        httpserve::AuthorizedSubject::for_test_with_device_policy_candidate(
            binding,
            wire::CONTRACT_ID,
            vocab::RoutePermissionId::IdentityDeviceCertificatePolicyWrite,
            rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
                .expect("tenant fixture"),
            rss_request_context::PrincipalKind::User,
            "user-2115",
            httpserve::RouteResource::new(device.as_uuid().hyphenated().to_string()),
            vec![
                httpserve::AuthorizationPolicyReference::new(
                    "policy-2115",
                    std::num::NonZeroU32::MIN,
                )
                .expect("policy fixture"),
            ],
            [7; httpserve::AUTHORIZATION_FINGERPRINT_BYTES],
            std::time::SystemTime::UNIX_EPOCH,
        )
        .expect("durable subject")
    }

    fn request(validity_seconds: i64) -> wire::IdentityDeviceCertificatePolicyPutRequest {
        wire::IdentityDeviceCertificatePolicyPutRequest {
            expected_generation: 0,
            idempotency_key: Uuid::new_v4(),
            policy: wire::IdentityDeviceCertificatePolicyPutPolicy {
                key_usages: vec![
                    wire::IdentityDeviceCertificatePolicyPutPolicyKeyUsagesItem::ClientAuth,
                ],
                renew_before_seconds: 300,
                sans: None,
                validity_seconds,
            },
        }
    }

    fn handler(
        case: Case,
        binding: httpserve::DevicePolicyCandidateBindingKey,
    ) -> DeviceCertificatePolicyCandidateHandler {
        DeviceCertificatePolicyCandidateHandler::new(
            Arc::from(DynDeviceCertificateRepository::new_box(TestRepository(
                case,
            ))),
            binding,
        )
    }

    fn request_id() -> httpserve::VerifiedRequestId {
        httpserve::VerifiedRequestId::for_test("0191f7d4-34d7-7b42-9fcb-9e85b92f42a1")
    }

    #[tokio::test]
    async fn candidate_handler_maps_closed_success_and_failure_surface() {
        let device =
            DeviceId::parse("550e8400-e29b-41d4-a716-446655440000").expect("device fixture");
        for (case, expected) in [
            (Case::Accepted, axum::http::StatusCode::OK),
            (Case::Replayed, axum::http::StatusCode::OK),
            (Case::Missing, axum::http::StatusCode::NOT_FOUND),
            (Case::GenerationConflict, axum::http::StatusCode::CONFLICT),
            (Case::IdempotencyConflict, axum::http::StatusCode::CONFLICT),
            (Case::Quarantined, axum::http::StatusCode::CONFLICT),
            (Case::InvalidMutation, axum::http::StatusCode::BAD_REQUEST),
            (Case::Storage, axum::http::StatusCode::SERVICE_UNAVAILABLE),
            (
                Case::SettlementUnknown,
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (Case::Corrupt, axum::http::StatusCode::INTERNAL_SERVER_ERROR),
        ] {
            let binding = httpserve::DevicePolicyCandidateBindingKey::new();
            let result = handler(case, binding.clone())
                .handle(
                    &subject(device, binding),
                    device,
                    request(3_600),
                    request_id(),
                )
                .await;
            let response = match result {
                Ok(response) => response.into_response(),
                Err(failure) => failure.into_response(),
            };
            assert_eq!(response.status(), expected);
        }
        let binding = httpserve::DevicePolicyCandidateBindingKey::new();
        let invalid_result = handler(Case::Accepted, binding.clone())
            .handle(
                &subject(device, binding),
                device,
                request(300),
                request_id(),
            )
            .await;
        let invalid = match invalid_result {
            Ok(response) => response.into_response(),
            Err(failure) => failure.into_response(),
        };
        assert_eq!(invalid.status(), axum::http::StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(invalid.into_body(), usize::MAX)
            .await
            .expect("validation body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("validation JSON");
        assert_eq!(body["error"]["details"][0]["field"], "policy");
        assert_eq!(body["error"]["details"][0]["reason"], "invalidPolicy");
    }

    #[tokio::test]
    async fn candidate_handler_serializes_each_conflict_code_message_pair() {
        let device =
            DeviceId::parse("550e8400-e29b-41d4-a716-446655440000").expect("device fixture");
        for (case, code, message, retryable) in [
            (
                Case::GenerationConflict,
                "ERR_CORE_VERSION_CONFLICT",
                "version conflict",
                true,
            ),
            (
                Case::IdempotencyConflict,
                "ERR_CORE_CONFLICT",
                "conflict",
                false,
            ),
            (Case::Quarantined, "ERR_CORE_CONFLICT", "conflict", false),
        ] {
            let binding = httpserve::DevicePolicyCandidateBindingKey::new();
            let result = handler(case, binding.clone())
                .handle(
                    &subject(device, binding),
                    device,
                    request(3_600),
                    request_id(),
                )
                .await;
            let response = match result {
                Ok(response) => response.into_response(),
                Err(failure) => failure.into_response(),
            };
            assert_eq!(response.status(), axum::http::StatusCode::CONFLICT);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("conflict body");
            let body: serde_json::Value = serde_json::from_slice(&body).expect("conflict json");
            assert_eq!(body["error"]["code"], code);
            assert_eq!(body["error"]["message"], message);
            assert_eq!(body["error"]["retryable"], retryable);
        }
    }

    #[tokio::test]
    async fn candidate_handler_rejects_authorization_from_another_binding() {
        let device =
            DeviceId::parse("550e8400-e29b-41d4-a716-446655440000").expect("device fixture");
        let authorizer_binding = httpserve::DevicePolicyCandidateBindingKey::new();
        let handler_binding = httpserve::DevicePolicyCandidateBindingKey::new();
        let result = handler(Case::Accepted, handler_binding)
            .handle(
                &subject(device, authorizer_binding),
                device,
                request(3_600),
                request_id(),
            )
            .await;
        let response = match result {
            Ok(response) => response.into_response(),
            Err(failure) => failure.into_response(),
        };
        assert_eq!(
            response.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn candidate_internal_failure_log_carries_tenant_and_domain_context() {
        let tenant = rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .expect("tenant fixture");
        let (_, events) = tracewiretest::with_test_event_capture(|| {
            log_internal_failure("storage_unavailable", "req-2115", "corr-2115", tenant);
        });
        let event = events
            .iter()
            .find(|event| {
                event
                    .fields
                    .get("failure_kind")
                    .is_some_and(|value| value == "storage_unavailable")
            })
            .expect("candidate failure event");
        assert_eq!(event.fields.get("tenant_id"), Some(&tenant.to_string()));
        assert_eq!(
            event.fields.get("domain").map(String::as_str),
            Some("identity")
        );
        assert_eq!(
            event.fields.get("contract_id").map(String::as_str),
            Some(wire::CONTRACT_ID)
        );
    }

    #[test]
    fn canonical_policy_fixture_remains_valid() {
        let durations = CertificatePolicyDurations::new(
            CertificateValiditySeconds::try_new(3_600).expect("validity"),
            CertificateRenewBeforeSeconds::try_new(300).expect("renew"),
        )
        .expect("durations");
        assert!(
            CertificatePolicy::new(
                durations,
                vec![deviceloop::CertificateKeyUsage::ClientAuth],
                Vec::new(),
            )
            .is_ok()
        );
    }
}
