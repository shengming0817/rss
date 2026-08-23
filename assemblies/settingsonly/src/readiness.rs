//! Closed production readiness inventory.

pub(crate) const FEDERATED_JWKS: &str = "federated_access_token_jwks_ready";
pub(crate) const RLS: &str = "rls_ready";
pub(crate) const REDIS: &str = "settingsonly_redis_ready";
pub(crate) const AMQP_PUBLISHER: &str = "settingsonly_amqp_publisher_ready";
pub(crate) const AMQP_SUBSCRIBER: &str = "settingsonly_amqp_subscriber_ready";
pub(crate) const DLX_LIFECYCLE: &str = "settingsonly_dlx_lifecycle";
pub(crate) const DLX_ARCHIVE: &str = "settingsonly_dlx_archive_ready";
pub(crate) const DLX_ARCHIVE_KEY: &str = "settingsonly_dlx_archive_key_ready";
pub(crate) const DLX_HOT_KEY: &str = "settingsonly_dlx_hot_key_ready";
pub(crate) const OUTBOX_RELAY: &str = "outbox_relay_settings";
pub(crate) const EVENT_CONSUMER: &str =
    "event_consumer_settings_config_version_changed_v1_settings";
pub(crate) const INBOX_SWEEPER: &str = "settingsonly_inbox_sweeper";
pub(crate) const OUTBOX_SAMPLER: &str = "settingsonly_outbox_sampler";
pub(crate) const OUTBOX_SWEEPER: &str = "settingsonly_outbox_sweeper";
pub(crate) const DR_ADMISSION: &str = "settingsonly_dr_admission";
pub(crate) const SETTINGS_PROJECTION_WORKER: &str = "projection_worker:settings.config-projection";

/// Exact required-probe closure of the production SettingsOnly assembly.
/// Compiled only for unit tests and the `test-support` façade (artifact acceptance).
#[cfg(any(test, feature = "test-support"))]
pub(crate) const PRODUCTION_REQUIRED_PROBES: &[&str] = &[
    RLS,
    settings_composition::CONFIGS_READY_PROBE_NAME,
    settings_composition::KEYPROVIDER_READY_PROBE_NAME,
    settings_composition::SECRET_RESOLVER_READY_PROBE_NAME,
    FEDERATED_JWKS,
    REDIS,
    AMQP_PUBLISHER,
    AMQP_SUBSCRIBER,
    DLX_LIFECYCLE,
    DLX_ARCHIVE,
    DLX_ARCHIVE_KEY,
    DLX_HOT_KEY,
    OUTBOX_RELAY,
    EVENT_CONSUMER,
    INBOX_SWEEPER,
    OUTBOX_SWEEPER,
    OUTBOX_SAMPLER,
    DR_ADMISSION,
    SETTINGS_PROJECTION_WORKER,
];

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    #[test]
    fn production_required_probe_inventory_is_exact_and_unique() {
        let probes = super::PRODUCTION_REQUIRED_PROBES;
        assert!(!probes.is_empty());
        assert_eq!(
            probes.iter().copied().collect::<HashSet<_>>().len(),
            probes.len()
        );
    }
}
