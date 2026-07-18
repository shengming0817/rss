#![allow(clippy::expect_used)]
// reason: focused configuration tests use expect for direct assertion failures.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::config::{
    CapturedConfigValue, RuntimeConfigKey, RuntimeConfigSnapshot, RuntimeConfigSource,
    RuntimeServingConfig, ServingConfigMapper, WorkerRuntimeConfig,
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
            "RSS_DOMAIN_TRANSPORT_REQUIRED_DOMAINS",
            FakeValue::Present("identity".to_owned()),
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
        ("RSS_SESSION_SWEEP_INTERVAL_MS", "330000"),
        ("RSS_KEYPROVIDER_READINESS_SAMPLE_INTERVAL_SECS", "7"),
    ];
    let source =
        FakeSource::new(values.map(|(key, value)| (key, FakeValue::Present(value.to_owned()))));
    let reads = read_log(&source);
    let snapshot = RuntimeConfigSnapshot::capture_test(source).expect("capture succeeds");

    let mapper = ServingConfigMapper::for_test(snapshot.view());
    let (event, session_sweep_interval, keyprovider_readiness_interval) =
        WorkerRuntimeConfig::from_mapper(&mapper)
            .expect("worker config")
            .into_test_parts();

    assert_eq!(
        [
            event.relay_poll_interval(),
            event.relay_sample_interval(),
            event.outbox_sweep_interval(),
            session_sweep_interval,
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
    [
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
            "RSS_AUDIT_CHAIN_KEY_B64URL",
            "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI",
        ),
        ("RSS_JWT_ISSUER", "https://issuer.test"),
        ("RSS_JWT_AUDIENCE", "rss"),
        ("RSS_JWT_ES256_KEY_ID", "runtime-es256"),
        ("RSS_JWT_ACCESS_TTL_SECS", "900"),
        ("RSS_DOMAIN_TRANSPORT_REQUIRED_DOMAINS", "identity"),
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
        ("RSS_SESSION_SWEEP_INTERVAL_MS", "330000"),
        ("RSS_KEYPROVIDER_READINESS_SAMPLE_INTERVAL_SECS", "7"),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value.to_owned()))
    .collect()
}

fn replace_serving_value(values: &mut [(String, String)], key: &str, value: &str) {
    values
        .iter_mut()
        .find(|(candidate, _)| candidate == key)
        .expect("serving fixture key")
        .1 = value.to_owned();
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
        parts.session_sweep_interval,
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
    drop((
        parts.domain_transport,
        parts.dlx_worker,
        parts.distributed_worker,
    ));

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
fn runtime_serving_config_accepts_complete_isolated_transport_with_explicit_spiffe_endpoint() {
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
    assert_eq!(parts.domain_transport.spiffe_endpoint, SPIFFE_ENDPOINT);
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
    const VAULT_S3_KEYS: [&str; 17] = [
        "RSS_VAULT_ADDR",
        "RSS_VAULT_TOKEN",
        "RSS_VAULT_TRANSIT_MOUNT",
        "RSS_VAULT_CA_CERT_PEM_PATH",
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
        "RSS_DOMAIN_TRANSPORT_REQUIRED_DOMAINS",
        FakeValue::Present("identity,IDENTITY,audit".to_owned()),
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
    let domains = match crate::domain_transport_required_domains_from(get) {
        Ok(domains) => domains.join(","),
        Err(error) => format!("error:{error}"),
    };
    format!("domains={domains}")
}

#[test]
fn runtime_config_snapshot_matches_committed_env_decision_transcript() {
    let cases = [
        (
            "configured",
            BTreeMap::from([
                (
                    "RSS_DOMAIN_TRANSPORT_REQUIRED_DOMAINS".to_owned(),
                    FakeValue::Present("identity,audit,IDENTITY".to_owned()),
                ),
                (
                    "RSS_SESSION_SWEEP_INTERVAL_MS".to_owned(),
                    FakeValue::Present("1000".to_owned()),
                ),
            ]),
        ),
        (
            "default",
            BTreeMap::from([(
                "RSS_DOMAIN_TRANSPORT_REQUIRED_DOMAINS".to_owned(),
                FakeValue::Present("identity".to_owned()),
            )]),
        ),
        (
            "invalid-fail-soft",
            BTreeMap::from([
                (
                    "RSS_DOMAIN_TRANSPORT_REQUIRED_DOMAINS".to_owned(),
                    FakeValue::Present("identity".to_owned()),
                ),
                (
                    "RSS_SESSION_SWEEP_INTERVAL_MS".to_owned(),
                    FakeValue::Present("999".to_owned()),
                ),
            ]),
        ),
        (
            "non-unicode",
            BTreeMap::from([
                (
                    "RSS_DOMAIN_TRANSPORT_REQUIRED_DOMAINS".to_owned(),
                    FakeValue::NonUnicode,
                ),
                (
                    "RSS_SESSION_SWEEP_INTERVAL_MS".to_owned(),
                    FakeValue::NonUnicode,
                ),
            ]),
        ),
        (
            "empty",
            BTreeMap::from([
                (
                    "RSS_DOMAIN_TRANSPORT_REQUIRED_DOMAINS".to_owned(),
                    FakeValue::Present(String::new()),
                ),
                (
                    "RSS_SESSION_SWEEP_INTERVAL_MS".to_owned(),
                    FakeValue::Present(String::new()),
                ),
            ]),
        ),
        (
            "whitespace",
            BTreeMap::from([
                (
                    "RSS_DOMAIN_TRANSPORT_REQUIRED_DOMAINS".to_owned(),
                    FakeValue::Present("identity audit".to_owned()),
                ),
                (
                    "RSS_SESSION_SWEEP_INTERVAL_MS".to_owned(),
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
domains=AUDIT,IDENTITY\n\
[default]\n\
domains=IDENTITY\n\
[invalid-fail-soft]\n\
domains=IDENTITY\n\
[non-unicode]\n\
domains=error:missing required env var: RSS_DOMAIN_TRANSPORT_REQUIRED_DOMAINS\n\
[empty]\n\
domains=error:RSS_DOMAIN_TRANSPORT_REQUIRED_DOMAINS must not contain empty entries\n\
[whitespace]\n\
domains=error:RSS_DOMAIN_TRANSPORT_REQUIRED_DOMAINS entries must not contain whitespace or control characters\n";
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
            "RSS_DOMAIN_TRANSPORT_REQUIRED_DOMAINS",
            FakeValue::Present("identity".to_owned()),
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
            "RSS_DOMAIN_TRANSPORT_REQUIRED_DOMAINS",
            FakeValue::Present("identity".to_owned()),
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

    let scheme = crate::routes::auth_scheme(config, primitives::ListenerKind::Internal)
        .expect("generation-one auth scheme");
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
fn runtime_config_invalid_required_domains_are_deferred_to_the_existing_builder() {
    let source = FakeSource::new([(
        "RSS_DOMAIN_TRANSPORT_REQUIRED_DOMAINS",
        FakeValue::Present("identity,,audit".to_owned()),
    )]);
    let snapshot =
        RuntimeConfigSnapshot::capture_test(source).expect("capture must not parse-fail");

    let error = crate::domain_transport_required_domains_from(&|name| {
        snapshot.view().value(name).map(str::to_owned)
    })
    .expect_err("existing builder owns the parse error");
    assert_eq!(
        error.to_string(),
        "RSS_DOMAIN_TRANSPORT_REQUIRED_DOMAINS must not contain empty entries"
    );
}
