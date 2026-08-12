use identity::ports::device_certificate::{AcceptDesiredPolicy, DevicePolicyAcceptInputError};

fn accepts_only_the_formal_funnel(
    subject: &httpserve::AuthorizedSubject,
    device: ids::DeviceId,
    expected: identity::ports::device_certificate::ExpectedGeneration,
    key: identity::ports::device_certificate::DevicePolicyIdempotencyKey,
    policy: deviceloop::CertificatePolicy,
) -> Result<AcceptDesiredPolicy, DevicePolicyAcceptInputError> {
    AcceptDesiredPolicy::from_authorized_subject(subject, device, expected, key, policy)
}

fn main() {}
