//! Candidate-only mounting of the two governed Draft HTTP contracts.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use httpserve::{
    AuthorizedSubject, ContractMarker, GeneratedPrimaryEndpoint, ListenerRouter, Primary,
};

use super::DevicePolicyCandidateBinding;
use crate::ports::device_certificate::{
    AuthorizedDeviceCertificateStatusRead, DeviceCertificateStatusStore as _,
    DynDeviceCertificateStatusStore,
};

#[derive(Clone)]
pub struct DeviceCandidateStatusState {
    store: Arc<DynDeviceCertificateStatusStore<'static>>,
}

impl DeviceCandidateStatusState {
    #[must_use]
    pub fn new(store: Arc<DynDeviceCertificateStatusStore<'static>>) -> Self {
        Self { store }
    }
}

impl httpserve::ClassifiedRouteState for DeviceCandidateStatusState {
    type Effect = diport::ReadEffect;
    type Privilege = diport::LocalPrivilege;
}

pub fn register_device_candidate_routes(
    router: ListenerRouter<Primary>,
    binding: Arc<DevicePolicyCandidateBinding>,
    status: DeviceCandidateStatusState,
) -> Result<ListenerRouter<Primary>, httpserve::RouteGroupError> {
    let router = router.mount(
        GeneratedPrimaryEndpoint::new_declared(
            generated::http::identity_v2::device_certificate_policy_put::ROUTE,
            policy_handler,
        )?
        .with_state(binding),
    )?;
    router.mount(
        GeneratedPrimaryEndpoint::new_declared(
            generated::http::identity_v2::device_certificate_status_get::ROUTE,
            status_handler,
        )?
        .with_classified_state(status),
    )
}

async fn policy_handler(
    _marker: ContractMarker<
        generated::http::identity_v2::device_certificate_policy_put::RouteMarker,
    >,
    Path(device): Path<String>,
    State(binding): State<Arc<DevicePolicyCandidateBinding>>,
    axum::Extension(subject): axum::Extension<AuthorizedSubject>,
    axum::Extension(request_id): axum::Extension<httpserve::VerifiedRequestId>,
    request: Result<
        Json<generated::http::identity_v2::device_certificate_policy_put::IdentityDeviceCertificatePolicyPutRequest>,
        axum::extract::rejection::JsonRejection,
    >,
) -> generated::http::identity_v2::device_certificate_policy_put::IdentityDeviceCertificatePolicyPutHandlerResult{
    let Ok(device) = ids::DeviceId::parse(&device) else {
        return DevicePolicyCandidateBinding::validation_failure(
            request_id,
            generated::http::identity_v2::device_certificate_policy_put::IdentityDeviceCertificatePolicyPutValidationDetailField::DeviceId,
            generated::http::identity_v2::device_certificate_policy_put::IdentityDeviceCertificatePolicyPutValidationDetailReason::InvalidFormat,
        );
    };
    match request {
        Ok(Json(request)) => binding.handle(&subject, device, request, request_id).await,
        Err(_) => DevicePolicyCandidateBinding::validation_failure(
            request_id,
            generated::http::identity_v2::device_certificate_policy_put::IdentityDeviceCertificatePolicyPutValidationDetailField::Body,
            generated::http::identity_v2::device_certificate_policy_put::IdentityDeviceCertificatePolicyPutValidationDetailReason::InvalidJson,
        ),
    }
}

async fn status_handler(
    _marker: ContractMarker<
        generated::http::identity_v2::device_certificate_status_get::RouteMarker,
    >,
    Path(device): Path<String>,
    State(state): State<DeviceCandidateStatusState>,
    axum::Extension(subject): axum::Extension<AuthorizedSubject>,
    axum::Extension(request_id): axum::Extension<httpserve::VerifiedRequestId>,
) -> generated::http::identity_v2::device_certificate_status_get::IdentityDeviceCertificateStatusGetHandlerResult{
    use generated::http::identity_v2::device_certificate_status_get as wire;
    let Ok(device) = ids::DeviceId::parse(&device) else {
        return Ok(wire::IdentityDeviceCertificateStatusGetResponseEnvelope::Error(
            wire::IdentityDeviceCertificateStatusGetResponseError::status_400(
                wire::IdentityDeviceCertificateStatusGetValidationResponse {
                    error: wire::IdentityDeviceCertificateStatusGetValidationError {
                        code: wire::IdentityDeviceCertificateStatusGetValidationErrorCode::ErrCoreValidation,
                        details: [wire::IdentityDeviceCertificateStatusGetValidationDetail {
                            field: wire::IdentityDeviceCertificateStatusGetValidationDetailField::DeviceId,
                            reason: wire::IdentityDeviceCertificateStatusGetValidationDetailReason::InvalidFormat,
                        }],
                        message: wire::IdentityDeviceCertificateStatusGetValidationErrorMessage::ValidationFailed,
                        request_id: request_id.as_str().to_owned(),
                        retryable: false,
                    },
                },
            ),
        ));
    };
    let Ok(query) =
        AuthorizedDeviceCertificateStatusRead::from_authorized_subject(&subject, device)
    else {
        return Err(
            wire::IdentityDeviceCertificateStatusGetFrameworkFailure::internal(
                request_id.into_wire(),
            ),
        );
    };
    match state.store.inspect(query).await {
        Ok(Some(evidence)) => match evidence.to_wire_response() {
            Ok(response) => Ok(wire::IdentityDeviceCertificateStatusGetResponseEnvelope::Success(
                response,
            )),
            Err(_) => Err(wire::IdentityDeviceCertificateStatusGetFrameworkFailure::internal(
                request_id.into_wire(),
            )),
        },
        Ok(None) => {
            let response =
                crate::ports::device_certificate::DeviceCertificateStatusEvidence::unconfigured(
                    std::time::SystemTime::now(),
                )
                .to_wire_response();
            match response {
                Ok(response) => Ok(wire::IdentityDeviceCertificateStatusGetResponseEnvelope::Success(
                    response,
                )),
                Err(_) => Err(wire::IdentityDeviceCertificateStatusGetFrameworkFailure::internal(
                    request_id.into_wire(),
                )),
            }
        }
        Err(crate::ports::device_certificate::DeviceCertificateStatusStoreError::StorageUnavailable { .. }) => {
            Ok(wire::IdentityDeviceCertificateStatusGetResponseEnvelope::Error(
                wire::IdentityDeviceCertificateStatusGetResponseError::status_503(
                    request_id.into_wire(),
                ),
            ))
        }
        Err(_) => Err(wire::IdentityDeviceCertificateStatusGetFrameworkFailure::internal(
            request_id.into_wire(),
        )),
    }
}
