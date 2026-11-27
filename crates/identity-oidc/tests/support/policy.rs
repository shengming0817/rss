use super::ReusePolicy;
/// Small explicit protocol-fixture budgets.
pub fn reuse_policy() -> ReusePolicy {
    use std::time::Duration;
    ReusePolicy {
        max_providers: 16,
        max_resident_bytes: 1024 * 1024,
        max_refreshes: 4,
        max_idle_per_host: 2,
        idle_timeout: Duration::from_secs(30),
        discovery_ttl: Duration::from_secs(300),
        jwks_ttl: Duration::from_secs(60),
        refresh_cooldown: Duration::from_secs(1),
    }
}
