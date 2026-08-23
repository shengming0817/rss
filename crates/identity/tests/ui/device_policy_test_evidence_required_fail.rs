use identity::ports::device_certificate::{
    AcceptDesiredPolicy, DeviceCertificateScope, DevicePolicyIdempotencyKey, ExpectedGeneration,
};

fn old_test_constructor(
    scope: DeviceCertificateScope,
    generation: ExpectedGeneration,
    key: DevicePolicyIdempotencyKey,
    policy: deviceloop::CertificatePolicy,
) {
    let _ = AcceptDesiredPolicy::for_test(scope, generation, key, policy);
}

fn main() {}
