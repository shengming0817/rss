async fn register_without_authorization<S: diport::SagaDurableStore>(
    store: &S,
    registration: diport::SagaInstanceRegistration,
) {
    let _ = store.register(registration).await;
}

fn main() {}
