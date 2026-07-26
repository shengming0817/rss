#![allow(clippy::expect_used)]
// reason: focused configuration tests use expect for direct assertion failures.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use tokio_util::sync::CancellationToken;

use crate::config::{
    AccessPrincipalKind, CapturedConfigValue, RuntimeConfigKey, RuntimeConfigSnapshot,
    RuntimeConfigSource, RuntimeServingConfig, ServiceTokenConfig, ServingConfigMapper,
    TokenProfilesConfig, WorkerRuntimeConfig,
};

#[derive(Clone)]
enum FakeValue {
    NonUnicode,
    Present(String),
}

struct FakeSource {
    values: BTreeMap<String, FakeValue>,
    reads: Arc<Mutex<Vec<String>>>,
    dropped: Arc<AtomicBool>,
}

impl FakeSource {
    fn new(values: impl IntoIterator<Item = (impl Into<String>, FakeValue)>) -> Self {
        Self {
            values: values
                .into_iter()
                .map(|(key, value)| (key.into(), value))
                .collect(),
            reads: Arc::new(Mutex::new(Vec::new())),
            dropped: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl RuntimeConfigSource for FakeSource {
    fn read(&mut self, key: &RuntimeConfigKey) -> CapturedConfigValue {
        self.reads
            .lock()
            .expect("read log mutex")
            .push(key.as_str().to_owned());
        match self.values.get(key.as_str()).cloned() {
            None => CapturedConfigValue::Missing,
            Some(FakeValue::NonUnicode) => CapturedConfigValue::NonUnicode,
            Some(FakeValue::Present(value)) => {
                CapturedConfigValue::Present(secure::SecretText::from_string(value))
            }
        }
    }
}

impl Drop for FakeSource {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Release);
    }
}

fn read_log(source: &FakeSource) -> Arc<Mutex<Vec<String>>> {
    Arc::clone(&source.reads)
}

#[test]
fn runtime_config_snapshot_reads_source_once_and_replays_stable_values() {
    let source = FakeSource::new([
        (
            "RSS_VAULT_TOKEN",
            FakeValue::Present("generation-one".to_owned()),
        ),
        (
            "RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD",
            FakeValue::Present("runtime".to_owned()),
        ),
    ]);
    let reads = read_log(&source);
    let dropped = Arc::clone(&source.dropped);

    let snapshot = RuntimeConfigSnapshot::capture_test(source).expect("capture succeeds");

    assert!(dropped.load(Ordering::Acquire), "source must be dropped");
    assert_eq!(
        snapshot.view().value("RSS_VAULT_TOKEN"),
        Some("generation-one")
    );
    assert_eq!(
        snapshot.view().value("RSS_VAULT_TOKEN"),
        Some("generation-one")
    );
    assert!(
        snapshot
            .view()
            .value("RSS_NOT_IN_SERVING_CATALOG")
            .is_none()
    );

    let reads = reads.lock().expect("read log mutex");
    let counts = reads.iter().fold(BTreeMap::new(), |mut counts, key| {
        *counts.entry(key.as_str()).or_insert(0_usize) += 1;
        counts
    });
    assert!(counts.values().all(|count| *count == 1), "{counts:?}");
}

#[test]
fn worker_runtime_config_uses_one_snapshot_generation_for_every_interval() {
    let values = [
        ("RSS_RELAY_POLL_INTERVAL_MS", "275"),
        ("RSS_RELAY_SAMPLE_INTERVAL_MS", "31000"),
        ("RSS_OUTBOX_SWEEP_INTERVAL_MS", "320000"),
        ("RSS_AUTH_GRANT_SWEEP_INTERVAL_MS", "330000"),
        ("RSS_KEYPROVIDER_READINESS_SAMPLE_INTERVAL_SECS", "7"),
    ];
    let source =
        FakeSource::new(values.map(|(key, value)| (key, FakeValue::Present(value.to_owned()))));
    let reads = read_log(&source);
    let snapshot = RuntimeConfigSnapshot::capture_test(source).expect("capture succeeds");

    let mapper = ServingConfigMapper::for_test(snapshot.view());
    let (event, auth_grant_sweep_interval, keyprovider_readiness_interval) =
        WorkerRuntimeConfig::from_mapper(&mapper)
            .expect("worker config")
            .into_test_parts();

    assert_eq!(
        [
            event.relay_poll_interval(),
            event.relay_sample_interval(),
            event.outbox_sweep_interval(),
            auth_grant_sweep_interval,
            keyprovider_readiness_interval.get(),
        ],
        [
            std::time::Duration::from_millis(275),
            std::time::Duration::from_secs(31),
            std::time::Duration::from_secs(320),
            std::time::Duration::from_secs(330),
            std::time::Duration::from_secs(7),
        ]
    );

    let reads = reads.lock().expect("read log mutex");
    for (key, _) in values {
        assert_eq!(
            reads.iter().filter(|read| read.as_str() == key).count(),
            1,
            "{key} must come from the single captured generation"
        );
    }
}

fn complete_shared_serving_values() -> Vec<(String, String)> {
    let mut values = [
        ("RSS_TOPOLOGY", "durable-shared"),
        ("RSS_AMQP_URL", "amqps://user:pass@broker.test/rss"),
        (
            "RSS_TENANT_AUTHORITY_HMAC_KEY_B64URL",
            "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo",
        ),
        ("RSS_DLX_PAYLOAD_KEY_NAME", "dlx-hot"),
        ("RSS_DLX_ARCHIVE_KEY_NAME", "dlx-archive"),
        ("RSS_VAULT_ADDR", "https://vault.test"),
        ("RSS_VAULT_TOKEN", "general-token"),
        ("RSS_DLX_HOT_VAULT_TOKEN", "hot-token"),
        ("RSS_DLX_ARCHIVE_VAULT_TOKEN", "archive-token"),
        ("RSS_VAULT_TRANSIT_MOUNT", "transit"),
        (
            "RSS_VAULT_TENANT_STORE_ALLOWLIST_JSON",
            r#"{"bindings":[{"tenantId":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","storeId":"vault","mount":"secret","kvPathPrefix":"tenants/a"}]}"#,
        ),
        (
            "RSS_AUDIT_CHAIN_KEY_B64URL",
            "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI",
        ),
        ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
        ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
        ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
        ("RSS_ACCESS_TOKEN_ISSUER", "https://issuer.test"),
        ("RSS_ACCESS_TOKEN_AUDIENCE", "rss"),
        ("RSS_ACCESS_TOKEN_SIGNING_ACTIVE_KEY_ID", "runtime-es256"),
        ("RSS_ACCESS_TOKEN_TTL_SECS", "900"),
        ("RSS_ACCESS_TOKEN_JWKS_REFRESH_INTERVAL_SECS", "60"),
        ("RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD", "runtime"),
        ("RSS_DOMAIN_TRANSPORT_URL", "https://gateway.internal/rpc"),
        (
            "RSS_DOMAIN_TRANSPORT_MTLS_LOCAL_SPIFFE_ID",
            "spiffe://example.org/ns/rss/sa/runtime",
        ),
        (
            "RSS_IDENTITY_DOMAIN_TRANSPORT_MTLS_SPIFFE_ALLOW_SET",
            "spiffe://example.org/ns/rss/sa/identity",
        ),
        ("SPIFFE_ENDPOINT_SOCKET", "unix:///run/spire/agent.sock"),
        ("RSS_RELAY_POLL_INTERVAL_MS", "275"),
        ("RSS_AUTH_GRANT_SWEEP_INTERVAL_MS", "330000"),
        ("RSS_KEYPROVIDER_READINESS_SAMPLE_INTERVAL_SECS", "7"),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value.to_owned()))
    .collect::<Vec<_>>();
    values.push((
        "RSS_ACCESS_TOKEN_JWKS_PATH".to_owned(),
        format!("{}/src/config.rs", env!("CARGO_MANIFEST_DIR")),
    ));
    values
}

fn replace_serving_value(values: &mut [(String, String)], key: &str, value: &str) {
    values
        .iter_mut()
        .find(|(candidate, _)| candidate == key)
        .expect("serving fixture key")
        .1 = value.to_owned();
}

fn select_federated_for_both_external_listeners(values: &mut Vec<(String, String)>) {
    replace_serving_value(values, "RSS_PRIMARY_TOKEN_PROFILE", "federated-access");
    replace_serving_value(values, "RSS_ADMIN_TOKEN_PROFILE", "federated-access");
    values.retain(|(key, _)| !key.starts_with("RSS_ACCESS_TOKEN_"));
    add_federated_access_profile(values);
}

#[test]
fn runtime_config_serving_event_domain_dlx_and_worker_inputs_share_one_captured_generation() {
    let values = complete_shared_serving_values();
    let source = FakeSource::new(
        values
            .iter()
            .cloned()
            .map(|(key, value)| (key, FakeValue::Present(value))),
    );
    let reads = read_log(&source);
    let snapshot = RuntimeConfigSnapshot::capture_test(source).expect("capture succeeds");

    let parts = RuntimeServingConfig::from_snapshot(snapshot.view())
        .expect("complete serving config")
        .into_parts();

    assert_eq!(
        parts.event_transport.topology(),
        bootstrap::Topology::DurableShared
    );
    assert_eq!(
        parts.event_worker.relay_poll_interval(),
        std::time::Duration::from_millis(275)
    );
    assert_eq!(
        parts.auth_grant_sweep_interval,
        std::time::Duration::from_secs(330)
    );
    assert_eq!(parts.audit_consumer_key.as_bytes(), &[0x42; 32]);
    assert_eq!(
        parts
            .domain_modules
            .settings
            .into_readiness_interval()
            .get(),
        std::time::Duration::from_secs(7)
    );
    let _ = (parts.dlx_worker, parts.distributed_worker);

    let reads = reads.lock().expect("read log mutex");
    for (key, _) in values {
        assert_eq!(
            reads.iter().filter(|read| read.as_str() == key).count(),
            1,
            "{key} must be captured once and never reopened by typed mapping"
        );
    }
}

#[test]
fn complete_serving_config_accepts_federated_primary_and_admin_without_local_rss_issuer() {
    let mut values = complete_shared_serving_values();
    select_federated_for_both_external_listeners(&mut values);
    let snapshot = RuntimeConfigSnapshot::capture_test(FakeSource::new(
        values
            .into_iter()
            .map(|(key, value)| (key, FakeValue::Present(value))),
    ))
    .expect("capture complete federated serving generation");

    let parts = RuntimeServingConfig::from_snapshot(snapshot.view())
        .expect("federated-only serving config")
        .into_parts();

    assert!(parts.token_profiles.rss_access().is_none());
    assert!(parts.token_profiles.federated_access().is_some());
    assert!(parts.domain_modules.identity.is_federated_access());
}

#[test]
fn runtime_serving_config_accepts_complete_isolated_event_transport() {
    const SPIFFE_ENDPOINT: &str = "unix:///run/spire/isolated-agent.sock";
    let mut values = complete_shared_serving_values();
    replace_serving_value(&mut values, "RSS_TOPOLOGY", "durable-isolated");
    replace_serving_value(&mut values, "SPIFFE_ENDPOINT_SOCKET", SPIFFE_ENDPOINT);
    values.retain(|(key, _)| key != "RSS_AMQP_URL" && key != "RSS_DOMAIN_TRANSPORT_URL");
    values.push((
        "RSS_IDENTITY_DOMAIN_TRANSPORT_URL".to_owned(),
        "https://identity.internal/rpc".to_owned(),
    ));
    for domain in generated::event::PRODUCER_DOMAINS {
        values.push((
            format!("RSS_{}_AMQP_URL", domain.as_str().to_ascii_uppercase()),
            format!("amqps://user:pass@{}.broker.test/rss", domain.as_str()),
        ));
    }
    let snapshot = RuntimeConfigSnapshot::capture_test(FakeSource::new(
        values
            .into_iter()
            .map(|(key, value)| (key, FakeValue::Present(value))),
    ))
    .expect("snapshot capture");
    let parts = RuntimeServingConfig::from_snapshot(snapshot.view())
        .expect("complete isolated serving config")
        .into_parts();

    assert_eq!(
        parts.event_transport.topology(),
        bootstrap::Topology::DurableIsolated
    );
    assert_eq!(
        snapshot.view().value("SPIFFE_ENDPOINT_SOCKET"),
        Some(SPIFFE_ENDPOINT)
    );
}

#[test]
fn runtime_infra_pg_redis_snapshot_reads_each_key_once_across_repeated_typed_mapping() {
    const PG_REDIS_KEYS: [&str; 26] = [
        "RSS_PG_HOST",
        "RSS_PG_PORT",
        "RSS_PG_DATABASE",
        "RSS_PG_SSL_MODE",
        "RSS_PG_SSL_ROOT_CERT_PATH",
        "RSS_PG_USERNAME",
        "RSS_PG_PASSWORD",
        "RSS_PG_MAX_CONNECTIONS",
        "RSS_PG_READ_USERNAME",
        "RSS_PG_READ_PASSWORD",
        "RSS_PG_READ_MAX_CONNECTIONS",
        "RSS_PG_MIGRATOR_USERNAME",
        "RSS_PG_MIGRATOR_PASSWORD",
        "RSS_PG_AUDIT_ADMIN_USERNAME",
        "RSS_PG_AUDIT_ADMIN_PASSWORD",
        "RSS_PG_DLX_ARCHIVER_USERNAME",
        "RSS_PG_DLX_ARCHIVER_PASSWORD",
        "RSS_PG_DLX_VERIFIER_USERNAME",
        "RSS_PG_DLX_VERIFIER_PASSWORD",
        "RSS_PG_DLX_PURGER_USERNAME",
        "RSS_PG_DLX_PURGER_PASSWORD",
        "RSS_SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES",
        "RSS_PG_READINESS_SAMPLE_INTERVAL_SECS",
        "RSS_REDIS_URL",
        "RSS_REDIS_ALLOW_PLAINTEXT",
        "RSS_REDIS_READINESS_SAMPLE_INTERVAL_SECS",
    ];

    let source = FakeSource::new(PG_REDIS_KEYS.iter().filter_map(|key| {
        let value = match *key {
            "RSS_PG_SSL_ROOT_CERT_PATH"
            | "RSS_PG_AUDIT_ADMIN_USERNAME"
            | "RSS_PG_AUDIT_ADMIN_PASSWORD" => return None,
            "RSS_PG_HOST" => "pg.generation-one",
            "RSS_PG_PORT" => "5432",
            "RSS_PG_DATABASE" => "rss",
            "RSS_PG_SSL_MODE" => "verify-full",
            "RSS_REDIS_URL" => "rediss://cache.generation-one:6380/0",
            "RSS_PG_MAX_CONNECTIONS" | "RSS_PG_READ_MAX_CONNECTIONS" => "5",
            "RSS_PG_READINESS_SAMPLE_INTERVAL_SECS"
            | "RSS_REDIS_READINESS_SAMPLE_INTERVAL_SECS" => "7",
            "RSS_SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES" | "RSS_REDIS_ALLOW_PLAINTEXT" => {
                "false"
            }
            key if key.ends_with("USERNAME") => "role",
            key if key.ends_with("PASSWORD") => "secret",
            _ => return None,
        };
        Some((*key, FakeValue::Present(value.to_owned())))
    }));
    let reads = read_log(&source);
    let snapshot = RuntimeConfigSnapshot::capture_test(source).expect("capture succeeds");

    for _ in 0..2 {
        let pg = crate::infra::pg::PgRuntimeConfig::from_snapshot(snapshot.view())
            .expect("PG typed mapping succeeds");
        let redis = crate::infra::redis::RedisRuntimeConfig::from_snapshot(snapshot.view())
            .expect("Redis typed mapping succeeds");
        drop((pg, redis));
    }

    let reads = reads.lock().expect("read log mutex");
    for key in PG_REDIS_KEYS {
        assert_eq!(
            reads.iter().filter(|read| read.as_str() == key).count(),
            1,
            "{key} must be read once by snapshot capture and never by typed mapping"
        );
    }
}

#[test]
fn runtime_infra_vault_s3_snapshot_reads_each_key_once_across_repeated_typed_mapping() {
    const VAULT_S3_KEYS: [&str; 18] = [
        "RSS_VAULT_ADDR",
        "RSS_VAULT_TOKEN",
        "RSS_VAULT_TRANSIT_MOUNT",
        "RSS_VAULT_CA_CERT_PEM_PATH",
        "RSS_VAULT_TENANT_STORE_ALLOWLIST_JSON",
        "RSS_SETTINGS_CONFIG_VALUE_KEY_NAME",
        "RSS_S3_ENDPOINT_URL",
        "RSS_S3_BUCKET",
        "RSS_S3_ACCESS_KEY_ID",
        "RSS_S3_SECRET_ACCESS_KEY",
        "RSS_S3_SESSION_TOKEN",
        "RSS_S3_REGION",
        "RSS_S3_FORCE_PATH_STYLE",
        "RSS_S3_ALLOW_PLAINTEXT",
        "RSS_DLX_ARCHIVE_S3_BUCKET",
        "RSS_S3_CANARY_KEY_PREFIX",
        "RSS_S3_CANARY_INTERVAL_SECS",
        "RSS_S3_CANARY_TIMEOUT_SECS",
    ];

    let source = FakeSource::new(VAULT_S3_KEYS.iter().filter_map(|key| {
        let value = match *key {
            "RSS_VAULT_ADDR" => "https://vault.generation-one.test",
            "RSS_VAULT_TOKEN" => "vault-generation-one-token",
            "RSS_VAULT_TRANSIT_MOUNT" => "transit",
            "RSS_VAULT_CA_CERT_PEM_PATH" => return None,
            "RSS_VAULT_TENANT_STORE_ALLOWLIST_JSON" => {
                r#"{"bindings":[{"tenantId":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","storeId":"vault","mount":"secret","kvPathPrefix":"tenants/a"}]}"#
            }
            "RSS_SETTINGS_CONFIG_VALUE_KEY_NAME" => "settings-generation-one",
            "RSS_S3_ENDPOINT_URL" => "https://s3.generation-one.test",
            "RSS_S3_BUCKET" => "rss-generation-one",
            "RSS_S3_ACCESS_KEY_ID" => "generation-one-access",
            "RSS_S3_SECRET_ACCESS_KEY" => "generation-one-secret",
            "RSS_S3_SESSION_TOKEN" => "generation-one-session",
            "RSS_S3_REGION" => "us-test-1",
            "RSS_S3_FORCE_PATH_STYLE" | "RSS_S3_ALLOW_PLAINTEXT" => "false",
            "RSS_DLX_ARCHIVE_S3_BUCKET" => "rss-generation-one-archive",
            "RSS_S3_CANARY_KEY_PREFIX" => "rss/generation-one",
            "RSS_S3_CANARY_INTERVAL_SECS" => "30",
            "RSS_S3_CANARY_TIMEOUT_SECS" => "5",
            _ => return None,
        };
        Some((*key, FakeValue::Present(value.to_owned())))
    }));
    let reads = read_log(&source);
    let snapshot = RuntimeConfigSnapshot::capture_test(source).expect("capture succeeds");

    for _ in 0..2 {
        let vault = crate::infra::vault::VaultRuntimeConfig::from_snapshot(snapshot.view())
            .expect("Vault typed mapping succeeds");
        let s3 = crate::infra::s3::S3RuntimeConfig::from_snapshot(snapshot.view())
            .expect("S3 typed mapping succeeds");
        drop((vault, s3));
    }

    let reads = reads.lock().expect("read log mutex");
    for key in VAULT_S3_KEYS {
        assert_eq!(
            reads.iter().filter(|read| read.as_str() == key).count(),
            1,
            "{key} must be read once by snapshot capture and never by typed mapping"
        );
    }
}

#[test]
fn runtime_infra_vault_s3_snapshot_debug_is_opaque() {
    let snapshot = crate::config::test_snapshot(&[
        ("RSS_VAULT_ADDR", "https://vault.snapshot.test"),
        ("RSS_VAULT_TOKEN", "vault-debug-bait"),
        ("RSS_VAULT_TRANSIT_MOUNT", "transit"),
        (
            "RSS_VAULT_TENANT_STORE_ALLOWLIST_JSON",
            r#"{"bindings":[{"tenantId":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","storeId":"vault","mount":"secret","kvPathPrefix":"tenants/a"}]}"#,
        ),
        (
            "RSS_SETTINGS_CONFIG_VALUE_KEY_NAME",
            "settings-key-debug-bait",
        ),
        ("RSS_S3_ENDPOINT_URL", "https://s3.snapshot.test"),
        ("RSS_S3_BUCKET", "rss-snapshot-general"),
        ("RSS_S3_ACCESS_KEY_ID", "access-key-debug-bait"),
        ("RSS_S3_SECRET_ACCESS_KEY", "secret-key-debug-bait"),
        ("RSS_S3_SESSION_TOKEN", "session-token-debug-bait"),
        ("RSS_DLX_ARCHIVE_S3_BUCKET", "rss-snapshot-archive"),
    ])
    .expect("snapshot");

    let vault = crate::infra::vault::VaultRuntimeConfig::from_snapshot(snapshot.view())
        .expect("Vault typed mapping succeeds");
    let s3 = crate::infra::s3::S3RuntimeConfig::from_snapshot(snapshot.view())
        .expect("S3 typed mapping succeeds");
    let debug = format!("{vault:?} {s3:?}");

    assert!(debug.contains("VaultRuntimeConfig"), "{debug}");
    assert!(debug.contains("S3RuntimeConfig"), "{debug}");
    for bait in [
        "vault-debug-bait",
        "settings-key-debug-bait",
        "access-key-debug-bait",
        "secret-key-debug-bait",
        "session-token-debug-bait",
        "vault.snapshot.test",
        "s3.snapshot.test",
    ] {
        assert!(!debug.contains(bait), "Debug leaked {bait}: {debug}");
    }
}

#[test]
fn runtime_config_catalog_deduplicates_static_dynamic_keys_and_excludes_maintenance() {
    let source = FakeSource::new([(
        "RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD",
        FakeValue::Present("runtime".to_owned()),
    )]);
    let reads = read_log(&source);
    let snapshot = RuntimeConfigSnapshot::capture_test(source).expect("capture succeeds");
    drop(snapshot);

    let reads = reads.lock().expect("read log mutex");
    let unique = reads.iter().collect::<BTreeSet<_>>();
    assert_eq!(unique.len(), reads.len(), "catalog keys must be read once");
    for expected in [
        "RSS_KEYPROVIDER_READINESS_SAMPLE_INTERVAL_SECS",
        "RSS_PG_READ_USERNAME",
        "RSS_PG_READ_PASSWORD",
        "RSS_PG_MAX_CONNECTIONS",
        "RSS_PG_READ_MAX_CONNECTIONS",
        "RSS_IDENTITY_DOMAIN_TRANSPORT_URL",
        "RSS_IDENTITY_DOMAIN_TRANSPORT_MTLS_SPIFFE_ALLOW_SET",
        "RSS_AUDIT_DOMAIN_TRANSPORT_URL",
        "RSS_AUDIT_DOMAIN_TRANSPORT_MTLS_SPIFFE_ALLOW_SET",
    ] {
        assert!(
            reads.iter().any(|key| key == expected),
            "missing {expected}"
        );
    }
    for domain in generated::event::PRODUCER_DOMAINS {
        let expected = format!("RSS_{}_AMQP_URL", domain.as_str().to_ascii_uppercase());
        assert!(
            reads.iter().any(|key| key == &expected),
            "missing {expected}"
        );
    }
    for excluded in [
        "RSS_PROJECTION_MAINTENANCE_OPERATOR_GRANTS",
        "RSS_AUDIT_LEDGER_VERIFY_OPERATOR_GRANTS",
        "RSS_DLQ_OPERATOR_GRANTS",
        "RSS_RECONCILE_OPERATOR_GRANTS",
        "RSS_INTERNAL_SERVICE_TOKEN_MIGRATION_EXPIRES_AT_UNIX",
        "RSS_INTERNAL_SERVICE_TOKEN_MIGRATION_TICKET",
        "RSS_CI_CONTAINER_SCOPE",
        "RSS_FORGE_TOKEN",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "RSS_SPIFFE_ROTATION_PRIVATE_KEY",
    ] {
        assert!(
            !reads.iter().any(|key| key == excluded),
            "captured {excluded}"
        );
    }
}

fn runtime_config_decision_transcript(get: &impl Fn(&str) -> Option<String>) -> String {
    let workload = match get("RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD") {
        Some(value) if crate::plan::is_kebab_case_workload(value.trim()) => value.trim().to_owned(),
        Some(value) => format!("error:invalid:{value}"),
        None => "default:runtime".to_owned(),
    };
    format!("identity.workload={workload}")
}

#[test]
fn runtime_config_snapshot_matches_committed_env_decision_transcript() {
    let cases = [
        (
            "configured",
            BTreeMap::from([
                (
                    "RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD".to_owned(),
                    FakeValue::Present("peer-cell".to_owned()),
                ),
                (
                    "RSS_AUTH_GRANT_SWEEP_INTERVAL_MS".to_owned(),
                    FakeValue::Present("1000".to_owned()),
                ),
            ]),
        ),
        ("default", BTreeMap::new()),
        (
            "invalid-fail-soft",
            BTreeMap::from([
                (
                    "RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD".to_owned(),
                    FakeValue::Present("peer-cell".to_owned()),
                ),
                (
                    "RSS_AUTH_GRANT_SWEEP_INTERVAL_MS".to_owned(),
                    FakeValue::Present("999".to_owned()),
                ),
            ]),
        ),
        (
            "non-unicode",
            BTreeMap::from([
                (
                    "RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD".to_owned(),
                    FakeValue::NonUnicode,
                ),
                (
                    "RSS_AUTH_GRANT_SWEEP_INTERVAL_MS".to_owned(),
                    FakeValue::NonUnicode,
                ),
            ]),
        ),
        (
            "empty",
            BTreeMap::from([
                (
                    "RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD".to_owned(),
                    FakeValue::Present(String::new()),
                ),
                (
                    "RSS_AUTH_GRANT_SWEEP_INTERVAL_MS".to_owned(),
                    FakeValue::Present(String::new()),
                ),
            ]),
        ),
        (
            "whitespace",
            BTreeMap::from([
                (
                    "RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD".to_owned(),
                    FakeValue::Present("peer cell".to_owned()),
                ),
                (
                    "RSS_AUTH_GRANT_SWEEP_INTERVAL_MS".to_owned(),
                    FakeValue::Present("   ".to_owned()),
                ),
            ]),
        ),
    ];
    let mut direct = String::new();
    let mut captured = String::new();
    for (name, values) in cases {
        let direct_get = |key: &str| match values.get(key) {
            Some(FakeValue::Present(value)) => Some(value.clone()),
            Some(FakeValue::NonUnicode) | None => None,
        };
        direct.push_str(&format!(
            "[{name}]\n{}\n",
            runtime_config_decision_transcript(&direct_get)
        ));

        let snapshot =
            RuntimeConfigSnapshot::capture_test(FakeSource::new(values)).expect("capture succeeds");
        captured.push_str(&format!(
            "[{name}]\n{}\n",
            runtime_config_decision_transcript(&|key| snapshot
                .view()
                .value(key)
                .map(str::to_owned))
        ));
    }

    const COMMITTED_TRANSCRIPT: &str = "[configured]\n\
identity.workload=peer-cell\n\
[default]\n\
identity.workload=default:runtime\n\
[invalid-fail-soft]\n\
identity.workload=peer-cell\n\
[non-unicode]\n\
identity.workload=default:runtime\n\
[empty]\n\
identity.workload=error:invalid:\n\
[whitespace]\n\
identity.workload=error:invalid:peer cell\n";
    assert_eq!(direct, COMMITTED_TRANSCRIPT);
    assert_eq!(captured, COMMITTED_TRANSCRIPT);
}

#[test]
fn runtime_config_snapshot_preserves_env_var_ok_transcript() {
    let source = FakeSource::new([
        ("RSS_VAULT_TOKEN", FakeValue::NonUnicode),
        ("RSS_VAULT_ADDR", FakeValue::Present(String::new())),
        (
            "RSS_VAULT_TRANSIT_MOUNT",
            FakeValue::Present("  transit  ".to_owned()),
        ),
        (
            "RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD",
            FakeValue::Present("runtime".to_owned()),
        ),
    ]);
    let snapshot = RuntimeConfigSnapshot::capture_test(source).expect("capture succeeds");

    assert!(snapshot.view().value("RSS_MISSING_SERVING_KEY").is_none());
    assert!(snapshot.view().value("RSS_VAULT_TOKEN").is_none());
    assert_eq!(snapshot.view().value("RSS_VAULT_ADDR"), Some(""));
    assert_eq!(
        snapshot.view().value("RSS_VAULT_TRANSIT_MOUNT"),
        Some("  transit  ")
    );
}

#[test]
fn runtime_config_snapshot_debug_is_fully_opaque() {
    let bait = "postgres://user:dsn-password@db/vault-token.jwt-hmac.PEM";
    let source = FakeSource::new([
        ("RSS_VAULT_TOKEN", FakeValue::Present(bait.to_owned())),
        (
            "RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD",
            FakeValue::Present("runtime".to_owned()),
        ),
    ]);
    let snapshot = RuntimeConfigSnapshot::capture_test(source).expect("capture succeeds");
    let debug = format!("{snapshot:?}");

    assert_eq!(debug, "RuntimeConfigSnapshot(<redacted>)");
    for fragment in [
        "RSS_VAULT_TOKEN",
        "dsn-password",
        "vault-token",
        "jwt-hmac",
        "PEM",
    ] {
        assert!(!debug.contains(fragment));
    }
}

#[test]
fn runtime_config_snapshot_is_owned_send_sync_static() {
    fn assert_traits<T: Send + Sync + 'static>() {}
    assert_traits::<RuntimeConfigSnapshot>();
}

#[test]
fn snapshot_capability_reuses_one_generation_for_serving_decisions() {
    let source = FakeSource::new([
        ("RUST_LOG", FakeValue::Present("runtime=debug".to_owned())),
        (
            "RSS_PRIMARY_TOKEN_PROFILE",
            FakeValue::Present("rss-access".to_owned()),
        ),
        (
            "RSS_ADMIN_TOKEN_PROFILE",
            FakeValue::Present("rss-access".to_owned()),
        ),
        (
            "RSS_INTERNAL_AUTH_SCHEME",
            FakeValue::Present("service-token".to_owned()),
        ),
        (
            "RSS_INTERNAL_LISTEN_ADDR",
            FakeValue::Present("127.0.0.1:18080".to_owned()),
        ),
        (
            "RSS_LISTENER_ALLOW_PLAINTEXT",
            FakeValue::Present("true".to_owned()),
        ),
    ]);
    let reads = read_log(&source);
    let snapshot = RuntimeConfigSnapshot::capture_test(source).expect("capture succeeds");
    let config = snapshot.view();

    let scheme = crate::plan::RuntimePlan::bundled(config)
        .expect("generation-one RuntimePlan")
        .listener_execution_plan()
        .listeners()
        .iter()
        .find(|listener| listener.kind() == primitives::ListenerKind::Internal)
        .expect("Internal listener")
        .auth_scheme();
    let addr = crate::listeners::listener_addr_for_scheme_at(
        config,
        primitives::ListenerKind::Internal,
        scheme,
        std::time::SystemTime::UNIX_EPOCH,
    )
    .expect("generation-one listener address");

    assert_eq!(config.value("RUST_LOG"), Some("runtime=debug"));
    assert_eq!(scheme, primitives::AuthScheme::ServiceToken);
    assert_eq!(addr.to_string(), "127.0.0.1:18080");
    let reads = reads.lock().expect("read log mutex");
    for key in [
        "RUST_LOG",
        "RSS_INTERNAL_AUTH_SCHEME",
        "RSS_INTERNAL_LISTEN_ADDR",
        "RSS_LISTENER_ALLOW_PLAINTEXT",
    ] {
        assert_eq!(
            reads.iter().filter(|read| read.as_str() == key).count(),
            1,
            "{key} must come from the single captured generation"
        );
    }
}

#[test]
fn runtime_config_always_captures_assembly_domain_transport_keys() {
    let source = FakeSource::new([(
        "RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD",
        FakeValue::Present("runtime".to_owned()),
    )]);
    let reads = read_log(&source);
    let snapshot =
        RuntimeConfigSnapshot::capture_test(source).expect("capture must not parse-fail");
    drop(snapshot);

    let reads = reads.lock().expect("read log mutex");
    for expected in [
        "RSS_SETTINGS_DOMAIN_TRANSPORT_URL",
        "RSS_SETTINGS_DOMAIN_TRANSPORT_MTLS_SPIFFE_ALLOW_SET",
        "RSS_IDENTITY_DOMAIN_TRANSPORT_URL",
        "RSS_IDENTITY_DOMAIN_TRANSPORT_MTLS_SPIFFE_ALLOW_SET",
        "RSS_AUDIT_DOMAIN_TRANSPORT_URL",
        "RSS_AUDIT_DOMAIN_TRANSPORT_MTLS_SPIFFE_ALLOW_SET",
        "RSS_SETTINGS_DOMAIN_PLACEMENT_WORKLOAD",
        "RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD",
        "RSS_AUDIT_DOMAIN_PLACEMENT_WORKLOAD",
    ] {
        assert!(
            reads.iter().any(|key| key == expected),
            "missing {expected}"
        );
    }
}

fn rss_token_profile_values() -> Vec<(String, String)> {
    vec![
        (
            "RSS_PRIMARY_TOKEN_PROFILE".to_owned(),
            "rss-access".to_owned(),
        ),
        (
            "RSS_ADMIN_TOKEN_PROFILE".to_owned(),
            "rss-access".to_owned(),
        ),
        ("RSS_INTERNAL_AUTH_SCHEME".to_owned(), "mtls".to_owned()),
        (
            "RSS_ACCESS_TOKEN_ISSUER".to_owned(),
            "https://rss.issuer.test".to_owned(),
        ),
        (
            "RSS_ACCESS_TOKEN_AUDIENCE".to_owned(),
            "rss-access-audience".to_owned(),
        ),
        (
            "RSS_ACCESS_TOKEN_SIGNING_ACTIVE_KEY_ID".to_owned(),
            "rss-access-es256".to_owned(),
        ),
        ("RSS_ACCESS_TOKEN_TTL_SECS".to_owned(), "900".to_owned()),
        (
            "RSS_ACCESS_TOKEN_JWKS_PATH".to_owned(),
            format!("{}/src/config.rs", env!("CARGO_MANIFEST_DIR")),
        ),
        (
            "RSS_ACCESS_TOKEN_JWKS_REFRESH_INTERVAL_SECS".to_owned(),
            "60".to_owned(),
        ),
    ]
}

fn add_federated_access_profile(values: &mut Vec<(String, String)>) {
    values.extend([
        (
            "RSS_FEDERATED_ACCESS_TOKEN_ISSUER".to_owned(),
            "https://federated.issuer.test".to_owned(),
        ),
        (
            "RSS_FEDERATED_ACCESS_TOKEN_AUDIENCE".to_owned(),
            "federated-access-audience".to_owned(),
        ),
        (
            "RSS_FEDERATED_ACCESS_TOKEN_TRUSTED_KINDS".to_owned(),
            "user,device,admin".to_owned(),
        ),
        (
            "RSS_FEDERATED_ACCESS_TOKEN_JWKS_PATH".to_owned(),
            format!("{}/src/lib.rs", env!("CARGO_MANIFEST_DIR")),
        ),
        (
            "RSS_FEDERATED_ACCESS_TOKEN_JWKS_REFRESH_INTERVAL_SECS".to_owned(),
            "120".to_owned(),
        ),
    ]);
}

fn add_service_token_profile(values: &mut Vec<(String, String)>) {
    values.extend([
        (
            "RSS_SERVICE_TOKEN_ISSUER".to_owned(),
            "https://service.issuer.test".to_owned(),
        ),
        (
            "RSS_SERVICE_TOKEN_AUDIENCE".to_owned(),
            "service-token-audience".to_owned(),
        ),
        (
            "RSS_SERVICE_TOKEN_HS256_KID".to_owned(),
            "service-hs256".to_owned(),
        ),
        (
            "RSS_SERVICE_TOKEN_HS256_SECRET_B64URL".to_owned(),
            "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo".to_owned(),
        ),
    ]);
}

fn token_profiles_from(
    values: impl IntoIterator<Item = (String, String)>,
) -> anyhow::Result<TokenProfilesConfig> {
    let snapshot = RuntimeConfigSnapshot::capture_test(FakeSource::new(
        values
            .into_iter()
            .map(|(key, value)| (key, FakeValue::Present(value))),
    ))
    .expect("capture token profile config");
    TokenProfilesConfig::from_snapshot(snapshot.view())
}

fn service_token_config_from(
    values: impl IntoIterator<Item = (String, String)>,
) -> anyhow::Result<ServiceTokenConfig> {
    let snapshot = RuntimeConfigSnapshot::capture_test(FakeSource::new(
        values
            .into_iter()
            .map(|(key, value)| (key, FakeValue::Present(value))),
    ))
    .expect("capture service-token config");
    ServiceTokenConfig::from_snapshot(snapshot.view())
}

fn service_token_env_example_values() -> Vec<(String, String)> {
    const PREFIX: &str = "RSS_SERVICE_TOKEN_";
    include_str!("../../../deploy/.env.example")
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            key.starts_with(PREFIX)
                .then(|| (key.to_owned(), value.to_owned()))
        })
        .collect()
}

#[test]
fn auth_grant_and_refresh_ttl_are_paired_in_deploy_and_ops_contracts() {
    let env_example = include_str!("../../../deploy/.env.example");
    let value = |key: &str| {
        env_example.lines().find_map(|line| {
            let (candidate, value) = line.split_once('=')?;
            (candidate == key).then_some(value)
        })
    };
    let auth_grant_ttl = value("RSS_IDENTITY_AUTH_GRANT_TTL_SECS")
        .expect("deploy example must set the AuthGrant TTL")
        .parse::<u64>()
        .expect("AuthGrant TTL example must be seconds");
    let refresh_ttl = value("RSS_REFRESH_TTL_SECS")
        .expect("deploy example must set the refresh TTL")
        .parse::<u64>()
        .expect("refresh TTL example must be seconds");
    assert!(
        auth_grant_ttl >= refresh_ttl,
        "deploy example must satisfy AuthGrant TTL >= refresh TTL"
    );
}

static CONFIG_TEMP_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn unique_config_temp_dir(name: &str) -> std::path::PathBuf {
    let sequence = CONFIG_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "rss-runtime-config-{}-{sequence}-{name}",
        std::process::id()
    ))
}

fn valid_es256_jwks(kid: &str, scalar: [u8; 32]) -> String {
    let signing_key = SigningKey::from_slice(&scalar).expect("valid test scalar");
    let point = signing_key.verifying_key().to_encoded_point(false);
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(point.x().expect("uncompressed point has x"));
    let y = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(point.y().expect("uncompressed point has y"));
    format!(
        r#"{{"keys":[{{"kty":"EC","kid":"{kid}","alg":"ES256","crv":"P-256","x":"{x}","y":"{y}"}}]}}"#
    )
}

fn mint_es256_access_token(
    signing_key: &SigningKey,
    kid: &str,
    issuer: &str,
    audience: &str,
    now: i64,
) -> String {
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(format!(r#"{{"alg":"ES256","typ":"at+jwt","kid":"{kid}"}}"#));
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!(
        r#"{{"sub":"550e8400-e29b-41d4-a716-446655440000","tenant_id":"f47ac10b-58cc-4372-a567-0e02b2c3d479","kind":"user","sid":"6ba7b810-9dad-41d1-80b4-00c04fd430c8","jti":"6ba7b811-9dad-41d1-80b4-00c04fd430c8","auth_time":{},"authn_epoch":7,"iat":{now},"exp":{},"token_use":"access","iss":"{issuer}","aud":"{audience}"}}"#,
        now - 1,
        now + 600
    ));
    let signing_input = format!("{header}.{payload}");
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

struct ConfigTestClock(std::time::SystemTime);

impl diport::Clock for ConfigTestClock {
    fn now(&self) -> std::time::SystemTime {
        self.0
    }
}

#[test]
fn deploy_env_example_service_token_namespace_satisfies_the_production_parser() {
    let values = service_token_env_example_values();
    assert_eq!(values.len(), 4, "fixture must contain the closed namespace");
    service_token_config_from(values)
        .expect("deploy service-token fixture must be production-valid");
}

#[test]
fn deploy_env_example_service_token_secret_contract_rejects_31_bytes() {
    let mut values = service_token_env_example_values();
    replace_serving_value(
        &mut values,
        "RSS_SERVICE_TOKEN_HS256_SECRET_B64URL",
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x5a_u8; 31]),
    );
    let error = service_token_config_from(values)
        .err()
        .expect("31-byte HS256 key must reject");
    assert!(
        error.to_string().contains("32..=128 bytes"),
        "unexpected error: {error}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn access_jwks_watches_the_lexical_operator_path_across_atomic_symlink_swap() {
    use std::os::unix::fs::symlink;

    let directory = unique_config_temp_dir("jwks-swap");
    std::fs::create_dir(&directory).expect("create temp directory");
    let first = directory.join("first.json");
    let second = directory.join("second.json");
    let current = directory.join("current.json");
    let replacement = directory.join("replacement.json");
    std::fs::write(&first, valid_es256_jwks("first", [0x41; 32])).expect("write first JWKS");
    std::fs::write(&second, valid_es256_jwks("second", [0x42; 32])).expect("write second JWKS");
    symlink(&first, &current).expect("create initial JWKS link");

    let mut values = rss_token_profile_values();
    replace_serving_value(
        &mut values,
        "RSS_ACCESS_TOKEN_JWKS_PATH",
        current.to_str().expect("UTF-8 temp path"),
    );
    let config = token_profiles_from(values).expect("parse RSS profile");
    let configured_path = config
        .rss_access()
        .expect("active RSS profile")
        .jwks_path()
        .to_owned();
    let source = oidc::JwksKeySource::load_and_watch(
        "rss-access-test",
        configured_path,
        std::time::Duration::from_secs(3_600),
        CancellationToken::new(),
    )
    .expect("load initial JWKS");

    symlink(&second, &replacement).expect("create replacement JWKS link");
    std::fs::rename(&replacement, &current).expect("atomically replace JWKS link");
    std::fs::remove_file(&first).expect("remove old target");

    assert!(
        source.reload(),
        "reload must follow the stable lexical mount path to the new target"
    );
    assert!(source.is_ready(), "successful swap must remain ready");

    const ISSUER: &str = "https://rss.issuer.test";
    const AUDIENCE: &str = "rss-access-audience";
    let now = 1_700_000_000_i64;
    let verifier = oidc::VerifierConfigBuilder::<diport::RssAccessProfile>::new(ISSUER, AUDIENCE)
        .keys_jwks(source)
        .build()
        .expect("build swapped verifier");
    let provider = oidc::OidcProvider::new(
        verifier,
        Box::new(ConfigTestClock(
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(now as u64),
        )),
    );
    let pdp = diport::DynPdp::new_arc(provider);
    let old_token = mint_es256_access_token(
        &SigningKey::from_slice(&[0x41; 32]).expect("old signing key"),
        "first",
        ISSUER,
        AUDIENCE,
        now,
    );
    let new_token = mint_es256_access_token(
        &SigningKey::from_slice(&[0x42; 32]).expect("new signing key"),
        "second",
        ISSUER,
        AUDIENCE,
        now,
    );
    assert!(
        authn::verify_rss_access(&old_token, &pdp).await.is_err(),
        "the old target key must leave the trusted snapshot"
    );
    assert!(
        authn::verify_rss_access(&new_token, &pdp).await.is_ok(),
        "the replacement target key must enter the trusted snapshot"
    );
    drop(pdp);
    std::fs::remove_dir_all(directory).expect("remove temp directory");
}

#[cfg(unix)]
#[test]
fn access_profiles_reject_two_lexical_paths_with_the_same_startup_identity() {
    use std::os::unix::fs::symlink;

    let directory = unique_config_temp_dir("jwks-alias");
    std::fs::create_dir(&directory).expect("create temp directory");
    let target = directory.join("shared.json");
    let rss_link = directory.join("rss.json");
    let federated_link = directory.join("federated.json");
    std::fs::write(&target, "{}").expect("write shared target");
    symlink(&target, &rss_link).expect("create RSS link");
    symlink(&target, &federated_link).expect("create federated link");

    let mut values = rss_token_profile_values();
    replace_serving_value(&mut values, "RSS_ADMIN_TOKEN_PROFILE", "federated-access");
    replace_serving_value(
        &mut values,
        "RSS_ACCESS_TOKEN_JWKS_PATH",
        rss_link.to_str().expect("UTF-8 RSS path"),
    );
    add_federated_access_profile(&mut values);
    replace_serving_value(
        &mut values,
        "RSS_FEDERATED_ACCESS_TOKEN_JWKS_PATH",
        federated_link.to_str().expect("UTF-8 federated path"),
    );
    let error = token_profiles_from(values).expect_err("same startup identity must reject");
    assert!(
        error
            .to_string()
            .contains("canonical JWKS paths must be distinct"),
        "unexpected error: {error}"
    );
    std::fs::remove_dir_all(directory).expect("remove temp directory");
}

#[test]
fn token_profile_config_builds_only_the_selected_provider_material() {
    let config = token_profiles_from(rss_token_profile_values()).expect("valid RSS profile config");

    let rss = config.rss_access().expect("RSS profile is active");
    assert_eq!(rss.issuer(), "https://rss.issuer.test");
    assert_eq!(rss.audience(), "rss-access-audience");
    assert_eq!(rss.signing_key_ring().active().as_str(), "rss-access-es256");
    assert!(rss.signing_key_ring().next().is_none());
    assert!(
        rss.retirement_schedule()
            .verify_until_for("rss-access-es256")
            .is_none()
    );
    assert_eq!(rss.rotation_mode(), authn::RotationMode::Planned);
    assert_eq!(rss.ttl(), std::time::Duration::from_secs(900));
    assert_eq!(
        rss.jwks_refresh_interval(),
        std::time::Duration::from_secs(60)
    );
    assert!(config.federated_access().is_none());
    assert!(config.service_token().is_none());
}

#[test]
fn token_profile_config_rejects_missing_and_invalid_required_selections() {
    let cases = [
        (
            "missing primary",
            "RSS_PRIMARY_TOKEN_PROFILE",
            None,
            "missing required env var: RSS_PRIMARY_TOKEN_PROFILE",
        ),
        (
            "invalid admin",
            "RSS_ADMIN_TOKEN_PROFILE",
            Some("jwt"),
            "RSS_ADMIN_TOKEN_PROFILE must be exactly rss-access or federated-access",
        ),
        (
            "missing internal",
            "RSS_INTERNAL_AUTH_SCHEME",
            None,
            "missing required env var: RSS_INTERNAL_AUTH_SCHEME",
        ),
        (
            "invalid internal",
            "RSS_INTERNAL_AUTH_SCHEME",
            Some("service"),
            "RSS_INTERNAL_AUTH_SCHEME must be exactly mtls or service-token",
        ),
    ];
    for (case, key, replacement, expected) in cases {
        let mut values = rss_token_profile_values();
        values.retain(|(candidate, _)| candidate != key);
        if let Some(replacement) = replacement {
            values.push((key.to_owned(), replacement.to_owned()));
        }
        let error = token_profiles_from(values).expect_err(case);
        assert_eq!(error.to_string(), expected, "{case}");
    }
}

#[test]
fn token_profile_config_enforces_rss_ttl_and_jwks_refresh_bounds() {
    let cases = [
        ("RSS_ACCESS_TOKEN_TTL_SECS", "0", "1..=900"),
        ("RSS_ACCESS_TOKEN_TTL_SECS", "901", "1..=900"),
        (
            "RSS_ACCESS_TOKEN_JWKS_REFRESH_INTERVAL_SECS",
            "4",
            "5..=3600",
        ),
        (
            "RSS_ACCESS_TOKEN_JWKS_REFRESH_INTERVAL_SECS",
            "3601",
            "5..=3600",
        ),
    ];
    for (key, value, expected) in cases {
        let mut values = rss_token_profile_values();
        replace_serving_value(&mut values, key, value);
        let error = token_profiles_from(values).expect_err(key);
        assert!(error.to_string().contains(expected), "{error}");
    }

    for ttl in ["1", "900"] {
        let mut values = rss_token_profile_values();
        replace_serving_value(&mut values, "RSS_ACCESS_TOKEN_TTL_SECS", ttl);
        token_profiles_from(values).expect("TTL boundary must be accepted");
    }
}

#[test]
fn token_profile_config_rejects_retiring_without_rotated_at() {
    let mut values = rss_token_profile_values();
    values.push((
        "RSS_ACCESS_TOKEN_SIGNING_RETIRING".to_owned(),
        "old-key=1700001320".to_owned(),
    ));
    let error = token_profiles_from(values).expect_err("retiring requires rotated_at");
    let message = error.to_string();
    assert!(
        message.contains("RSS_ACCESS_TOKEN_SIGNING_ROTATED_AT"),
        "{message}"
    );
    assert!(!message.contains("old-key"), "{message}");
}

#[test]
fn token_profile_config_rejects_duplicate_signing_kids() {
    let retiring_kid = "dup-retiring-kid";
    let cases = [
        (
            "active/next",
            vec![(
                "RSS_ACCESS_TOKEN_SIGNING_NEXT_KEY_ID".to_owned(),
                "rss-access-es256".to_owned(),
            )],
            "rss-access-es256",
        ),
        (
            "active/retiring",
            vec![
                (
                    "RSS_ACCESS_TOKEN_SIGNING_RETIRING".to_owned(),
                    format!("{retiring_kid}=1700001320"),
                ),
                (
                    "RSS_ACCESS_TOKEN_SIGNING_ROTATED_AT".to_owned(),
                    "1700000000".to_owned(),
                ),
            ],
            retiring_kid,
        ),
    ];
    for (case, extras, kid) in cases {
        let mut values = rss_token_profile_values();
        if case == "active/retiring" {
            replace_serving_value(
                &mut values,
                "RSS_ACCESS_TOKEN_SIGNING_ACTIVE_KEY_ID",
                retiring_kid,
            );
        }
        values.extend(extras);
        let error = token_profiles_from(values).expect_err(case);
        let message = error.to_string();
        assert!(
            message.contains("signing key ids in the ring must be unique"),
            "{case}: {message}"
        );
        assert!(!message.contains(kid), "{case}: {message}");
    }
}

#[test]
fn token_profile_config_parses_multiple_retiring_kids() {
    const ROTATED_AT: i64 = 1_700_000_000;
    const MIN_OVERLAP: i64 = 1_320;
    let mut values = rss_token_profile_values();
    values.extend([
        (
            "RSS_ACCESS_TOKEN_SIGNING_RETIRING".to_owned(),
            format!(
                "old-a={},old-b={}",
                ROTATED_AT + MIN_OVERLAP,
                ROTATED_AT + MIN_OVERLAP + 60
            ),
        ),
        (
            "RSS_ACCESS_TOKEN_SIGNING_ROTATED_AT".to_owned(),
            ROTATED_AT.to_string(),
        ),
        (
            "RSS_ACCESS_TOKEN_SIGNING_NEXT_KEY_ID".to_owned(),
            "next-kid".to_owned(),
        ),
    ]);
    let config = token_profiles_from(values).expect("multi retiring parse");
    let rss = config.rss_access().expect("rss profile");
    assert_eq!(
        rss.signing_key_ring().next().map(diport::KeyId::as_str),
        Some("next-kid")
    );
    assert_eq!(rss.signing_key_ring().retiring().len(), 2);
    assert_eq!(
        rss.retirement_schedule().verify_until_for("old-a"),
        Some(ROTATED_AT + MIN_OVERLAP)
    );
    assert_eq!(
        rss.retirement_schedule().verify_until_for("old-b"),
        Some(ROTATED_AT + MIN_OVERLAP + 60)
    );
}

#[test]
fn token_profile_config_enforces_planned_rotation_overlap_bounds() {
    // min_overlap = ttl(900) + skew(60) + jwks SLO(300) + margin(60) = 1320
    const ROTATED_AT: i64 = 1_700_000_000;
    const MIN_OVERLAP: i64 = 1_320;
    let retiring_kid = "retiring-overlap-kid";

    let mut short = rss_token_profile_values();
    short.extend([
        (
            "RSS_ACCESS_TOKEN_SIGNING_RETIRING".to_owned(),
            format!("{retiring_kid}={}", ROTATED_AT + MIN_OVERLAP - 1),
        ),
        (
            "RSS_ACCESS_TOKEN_SIGNING_ROTATED_AT".to_owned(),
            ROTATED_AT.to_string(),
        ),
    ]);
    let error = token_profiles_from(short).expect_err("overlap one second short");
    let message = error.to_string();
    assert!(
        message.contains("rotation verify overlap is insufficient"),
        "{message}"
    );
    assert!(
        message.contains("need 1320s") && message.contains("have 1319s"),
        "{message}"
    );
    assert!(
        message.contains("RSS_ACCESS_TOKEN_TTL_SECS")
            && message.contains("RSS_ACCESS_TOKEN_ROTATION_CLOCK_SKEW_SECS")
            && message.contains("RSS_ACCESS_TOKEN_ROTATION_JWKS_PROPAGATION_SLO_SECS")
            && message.contains("RSS_ACCESS_TOKEN_ROTATION_MARGIN_SECS"),
        "{message}"
    );
    assert!(!message.contains(retiring_kid), "{message}");

    let mut exact = rss_token_profile_values();
    exact.extend([
        (
            "RSS_ACCESS_TOKEN_SIGNING_NEXT_KEY_ID".to_owned(),
            "next-staging-kid".to_owned(),
        ),
        (
            "RSS_ACCESS_TOKEN_SIGNING_RETIRING".to_owned(),
            format!("{retiring_kid}={}", ROTATED_AT + MIN_OVERLAP),
        ),
        (
            "RSS_ACCESS_TOKEN_SIGNING_ROTATED_AT".to_owned(),
            ROTATED_AT.to_string(),
        ),
    ]);
    let config = token_profiles_from(exact).expect("exact overlap boundary");
    let rss = config.rss_access().expect("rss active");
    assert_eq!(
        rss.signing_key_ring().next().map(diport::KeyId::as_str),
        Some("next-staging-kid")
    );
    assert_eq!(
        rss.retirement_schedule().verify_until_for(retiring_kid),
        Some(ROTATED_AT + MIN_OVERLAP)
    );
    assert_eq!(rss.rotation_mode(), authn::RotationMode::Planned);
}

#[test]
fn token_profile_config_emergency_rotation_skips_overlap() {
    const ROTATED_AT: i64 = 1_700_000_000;
    let retiring_kid = "emergency-retiring-kid";
    let mut values = rss_token_profile_values();
    values.extend([
        (
            "RSS_ACCESS_TOKEN_SIGNING_RETIRING".to_owned(),
            format!("{retiring_kid}={ROTATED_AT}"),
        ),
        (
            "RSS_ACCESS_TOKEN_SIGNING_ROTATED_AT".to_owned(),
            ROTATED_AT.to_string(),
        ),
        (
            "RSS_ACCESS_TOKEN_ROTATION_MODE".to_owned(),
            "emergency".to_owned(),
        ),
    ]);
    let config = token_profiles_from(values).expect("emergency exempts overlap");
    let rss = config.rss_access().expect("rss active");
    assert_eq!(rss.rotation_mode(), authn::RotationMode::Emergency);
    assert_eq!(
        rss.retirement_schedule().verify_until_for(retiring_kid),
        Some(ROTATED_AT)
    );
}

#[test]
fn token_profile_config_rejects_malformed_retiring_and_rotation_mode() {
    let cases = [
        (
            "empty entry",
            "RSS_ACCESS_TOKEN_SIGNING_RETIRING",
            "old-key=1700001320,",
            "empty entries",
        ),
        (
            "missing equals",
            "RSS_ACCESS_TOKEN_SIGNING_RETIRING",
            "old-key-1700001320",
            "kid=unixSeconds",
        ),
        (
            "non-unix until",
            "RSS_ACCESS_TOKEN_SIGNING_RETIRING",
            "old-key=not-a-unix",
            "unix seconds",
        ),
        (
            "illegal mode",
            "RSS_ACCESS_TOKEN_ROTATION_MODE",
            "gradual",
            "planned or emergency",
        ),
    ];
    for (case, key, value, expected) in cases {
        let mut values = rss_token_profile_values();
        if key == "RSS_ACCESS_TOKEN_SIGNING_RETIRING" {
            values.push((
                "RSS_ACCESS_TOKEN_SIGNING_ROTATED_AT".to_owned(),
                "1700000000".to_owned(),
            ));
        }
        values.push((key.to_owned(), value.to_owned()));
        let error = token_profiles_from(values).expect_err(case);
        assert!(error.to_string().contains(expected), "{case}: {error}");
    }
}

#[test]
fn token_profile_config_custom_overlap_knobs_change_boundary() {
    // Defaults would require 1320s; skew=0 + slo=0 + margin=0 → need ttl only (900).
    const ROTATED_AT: i64 = 1_700_000_000;
    let retiring_kid = "custom-knob-retiring";
    let mut short_default = rss_token_profile_values();
    short_default.extend([
        (
            "RSS_ACCESS_TOKEN_SIGNING_RETIRING".to_owned(),
            format!("{retiring_kid}={}", ROTATED_AT + 900),
        ),
        (
            "RSS_ACCESS_TOKEN_SIGNING_ROTATED_AT".to_owned(),
            ROTATED_AT.to_string(),
        ),
    ]);
    let error = token_profiles_from(short_default).expect_err("default knobs still require 1320");
    assert!(error.to_string().contains("need 1320s"), "{error}");

    let mut custom_ok = rss_token_profile_values();
    custom_ok.extend([
        (
            "RSS_ACCESS_TOKEN_SIGNING_RETIRING".to_owned(),
            format!("{retiring_kid}={}", ROTATED_AT + 900),
        ),
        (
            "RSS_ACCESS_TOKEN_SIGNING_ROTATED_AT".to_owned(),
            ROTATED_AT.to_string(),
        ),
        (
            "RSS_ACCESS_TOKEN_ROTATION_CLOCK_SKEW_SECS".to_owned(),
            "0".to_owned(),
        ),
        (
            "RSS_ACCESS_TOKEN_ROTATION_JWKS_PROPAGATION_SLO_SECS".to_owned(),
            "0".to_owned(),
        ),
        (
            "RSS_ACCESS_TOKEN_ROTATION_MARGIN_SECS".to_owned(),
            "0".to_owned(),
        ),
    ]);
    token_profiles_from(custom_ok).expect("zeroed knobs accept ttl-sized overlap");
}

#[test]
fn token_profile_config_rejects_any_orphan_profile_namespace() {
    let mut inactive_federated = rss_token_profile_values();
    inactive_federated.push((
        "RSS_FEDERATED_ACCESS_TOKEN_ISSUER".to_owned(),
        "https://orphan.test".to_owned(),
    ));
    let error = token_profiles_from(inactive_federated).expect_err("orphan federated config");
    assert!(
        error
            .to_string()
            .contains("orphan token profile configuration: RSS_FEDERATED_ACCESS_TOKEN_*"),
        "{error}"
    );

    let mut inactive_service = rss_token_profile_values();
    inactive_service.push((
        "RSS_SERVICE_TOKEN_HS256_KID".to_owned(),
        "orphan".to_owned(),
    ));
    let error = token_profiles_from(inactive_service).expect_err("orphan service config");
    assert!(
        error
            .to_string()
            .contains("orphan token profile configuration: RSS_SERVICE_TOKEN_*"),
        "{error}"
    );
}

#[test]
fn token_profile_config_accepts_distinct_active_profiles_and_service_token() {
    let mut values = rss_token_profile_values();
    replace_serving_value(&mut values, "RSS_ADMIN_TOKEN_PROFILE", "federated-access");
    replace_serving_value(&mut values, "RSS_INTERNAL_AUTH_SCHEME", "service-token");
    add_federated_access_profile(&mut values);
    add_service_token_profile(&mut values);

    let config = token_profiles_from(values).expect("three distinct profiles");
    let federated = config
        .federated_access()
        .expect("federated profile is active");
    assert_eq!(federated.issuer(), "https://federated.issuer.test");
    assert_eq!(federated.audience(), "federated-access-audience");
    assert_eq!(
        federated.jwks_refresh_interval(),
        std::time::Duration::from_secs(120)
    );
    assert_eq!(
        federated
            .trusted_kinds()
            .iter()
            .copied()
            .map(AccessPrincipalKind::as_str)
            .collect::<Vec<_>>(),
        ["user", "device", "admin"]
    );
    let service = config.service_token().expect("service profile is active");
    assert_eq!(service.issuer(), "https://service.issuer.test");
    assert_eq!(service.audience(), "service-token-audience");
    assert_eq!(service.hs256_kid(), "service-hs256");
    assert_eq!(service.hs256_secret(), &[b'Z'; 32]);
}

#[test]
fn token_profile_config_accepts_every_valid_primary_admin_activation_combination() {
    let mut federated_only = rss_token_profile_values();
    select_federated_for_both_external_listeners(&mut federated_only);

    let mut rss_primary_federated_admin = rss_token_profile_values();
    replace_serving_value(
        &mut rss_primary_federated_admin,
        "RSS_ADMIN_TOKEN_PROFILE",
        "federated-access",
    );
    add_federated_access_profile(&mut rss_primary_federated_admin);

    for (case, values) in [
        ("federated/federated", federated_only),
        ("rss/federated", rss_primary_federated_admin),
        ("rss/rss", rss_token_profile_values()),
    ] {
        let result = token_profiles_from(values);
        let failure = result
            .as_ref()
            .err()
            .map(ToString::to_string)
            .unwrap_or_default();
        assert!(result.is_ok(), "{case} must start: {failure}");
    }
}

#[test]
fn token_profile_config_rejects_federated_primary_with_rss_admin() {
    let mut values = rss_token_profile_values();
    replace_serving_value(&mut values, "RSS_PRIMARY_TOKEN_PROFILE", "federated-access");
    add_federated_access_profile(&mut values);

    let error = token_profiles_from(values).expect_err("split identity authority must reject");
    assert!(
        error
            .to_string()
            .contains("federated Primary requires federated Admin"),
        "unexpected error: {error}"
    );
}

#[test]
fn token_profile_config_rejects_cross_profile_trust_overlap() {
    let cases = [
        (
            "RSS_FEDERATED_ACCESS_TOKEN_ISSUER",
            "https://rss.issuer.test",
            "issuers must be distinct",
        ),
        (
            "RSS_FEDERATED_ACCESS_TOKEN_AUDIENCE",
            "rss-access-audience",
            "audiences must be distinct",
        ),
        (
            "RSS_FEDERATED_ACCESS_TOKEN_JWKS_PATH",
            concat!(env!("CARGO_MANIFEST_DIR"), "/src/config.rs"),
            "canonical JWKS paths must be distinct",
        ),
        (
            "RSS_SERVICE_TOKEN_ISSUER",
            "https://rss.issuer.test",
            "Service Token issuer must be distinct",
        ),
        (
            "RSS_SERVICE_TOKEN_AUDIENCE",
            "federated-access-audience",
            "Service Token audience must be distinct",
        ),
    ];
    for (key, value, expected) in cases {
        let mut values = rss_token_profile_values();
        replace_serving_value(&mut values, "RSS_ADMIN_TOKEN_PROFILE", "federated-access");
        replace_serving_value(&mut values, "RSS_INTERNAL_AUTH_SCHEME", "service-token");
        add_federated_access_profile(&mut values);
        add_service_token_profile(&mut values);
        replace_serving_value(&mut values, key, value);

        let error = token_profiles_from(values).expect_err(key);
        assert!(error.to_string().contains(expected), "{key}: {error}");
    }
}

#[test]
fn token_profile_config_rejects_legacy_env_instead_of_dual_reading_it() {
    let legacy = |family: &str, suffix: &str| format!("RSS_{family}_{suffix}");
    let values = [
        (
            "RSS_PRIMARY_TOKEN_PROFILE".to_owned(),
            "rss-access".to_owned(),
        ),
        (
            "RSS_ADMIN_TOKEN_PROFILE".to_owned(),
            "rss-access".to_owned(),
        ),
        ("RSS_INTERNAL_AUTH_SCHEME".to_owned(), "mtls".to_owned()),
        (
            legacy("JWT", "ISSUER"),
            "https://legacy.issuer.test".to_owned(),
        ),
        (legacy("JWT", "AUDIENCE"), "legacy".to_owned()),
        (legacy("JWT", "ES256_KEY_ID"), "legacy-key".to_owned()),
        (legacy("JWT", "ACCESS_TTL_SECS"), "900".to_owned()),
        (
            legacy("OIDC", "ISSUER"),
            "https://legacy.issuer.test".to_owned(),
        ),
        (legacy("OIDC", "AUDIENCE"), "legacy".to_owned()),
        (legacy("OIDC", "TRUSTED_KINDS"), "user".to_owned()),
        (
            legacy("OIDC", "JWKS_PATH"),
            concat!(env!("CARGO_MANIFEST_DIR"), "/src/config.rs").to_owned(),
        ),
    ];
    let source = FakeSource::new(
        values
            .into_iter()
            .map(|(key, value)| (key, FakeValue::Present(value))),
    );
    let reads = read_log(&source);
    let snapshot = RuntimeConfigSnapshot::capture_test(source).expect("capture");
    let error =
        TokenProfilesConfig::from_snapshot(snapshot.view()).expect_err("no legacy dual-read");
    assert_eq!(
        error.to_string(),
        "missing required env var: RSS_ACCESS_TOKEN_ISSUER"
    );
    let reads = reads.lock().expect("read log");
    let jwt_prefix = legacy("JWT", "");
    let oidc_prefix = legacy("OIDC", "");
    assert!(
        reads
            .iter()
            .all(|key| !key.starts_with(&jwt_prefix) && !key.starts_with(&oidc_prefix))
    );
}

#[test]
fn token_profile_config_rejects_invalid_kind_and_service_secret() {
    let mut values = rss_token_profile_values();
    replace_serving_value(&mut values, "RSS_ADMIN_TOKEN_PROFILE", "federated-access");
    add_federated_access_profile(&mut values);
    replace_serving_value(
        &mut values,
        "RSS_FEDERATED_ACCESS_TOKEN_TRUSTED_KINDS",
        "user,service",
    );
    let error = token_profiles_from(values).expect_err("service kind in federated profile");
    assert!(
        error.to_string().contains(
            "RSS_FEDERATED_ACCESS_TOKEN_TRUSTED_KINDS entries must be exactly user, device, admin, or superAdmin"
        ),
        "{error}"
    );

    let mut values = rss_token_profile_values();
    replace_serving_value(&mut values, "RSS_INTERNAL_AUTH_SCHEME", "service-token");
    add_service_token_profile(&mut values);
    replace_serving_value(
        &mut values,
        "RSS_SERVICE_TOKEN_HS256_SECRET_B64URL",
        "short",
    );
    let error = token_profiles_from(values).expect_err("weak service secret");
    assert!(
        error
            .to_string()
            .contains("RSS_SERVICE_TOKEN_HS256_SECRET_B64URL"),
        "{error}"
    );
}
