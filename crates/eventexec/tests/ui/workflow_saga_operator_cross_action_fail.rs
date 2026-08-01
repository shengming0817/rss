fn retry_with_status_proof(
    target: &eventexec::SagaRuntimeOperatorTarget,
    authorization: diport::SagaOperatorAuthorization<diport::saga_operator_action::Status>,
) {
    let _ = target.retry_compensation(authorization);
}

fn main() {}
