use identity::ports::device_certificate::{
    ConditionStateBatch, DeviceCertificateRepository, DeviceCertificateScope,
};

async fn bypass_fence<R: DeviceCertificateRepository>(
    repository: &R,
    scope: DeviceCertificateScope,
    conditions: ConditionStateBatch,
) {
    let _ = repository.upsert_condition_states(scope, conditions).await;
}

fn main() {}
