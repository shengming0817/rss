use diport::SagaOperatorStore;

fn retry_with_status_authorization<S: SagaOperatorStore>(
    store: &S,
    authorization: diport::SagaOperatorAuthorization<diport::saga_operator_action::Status>,
) {
    let _ = store.retry_compensation(authorization);
}

fn main() {}
