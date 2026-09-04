use rss_runtime::ManagedTaskRegistration;

fn extract_token(registration: ManagedTaskRegistration) {
    let _token = registration.cancellation_token();
}

fn main() {}
