fn main() {
    use rss_identity_oidc::TransportPolicy;
    use std::time::Duration;
    let timeout = Duration::from_secs(5);
    assert!(TransportPolicy::new(timeout, timeout, 4096, 8).is_ok());
    assert!(TransportPolicy::new(timeout, timeout, 0, 8).is_err());
    println!("passed");
}
