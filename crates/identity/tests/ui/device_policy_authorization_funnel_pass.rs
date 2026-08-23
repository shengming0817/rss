use identity::ports::device_certificate::{AcceptDesiredPolicy, DevicePolicyAcceptInputError};

fn accepts_only_the_formal_funnel(
    scope: identity::ports::device_certificate::DeviceCertificateScope,
    expected: identity::ports::device_certificate::ExpectedGeneration,
    key: identity::ports::device_certificate::DevicePolicyIdempotencyKey,
    policy: deviceloop::CertificatePolicy,
) -> Result<AcceptDesiredPolicy, DevicePolicyAcceptInputError> {
    AcceptDesiredPolicy::for_test(
        scope,
        expected,
        key,
        policy,
        httpserve::VerifiedRequestId::for_test("0191f7d4-34d7-7b42-9fcb-9e85b92f42a1"),
        diagctx::CorrelationId::parse("corr-2115").map_err(|_| DevicePolicyAcceptInputError::Unauthorized)?,
    )
}

fn main() {}
