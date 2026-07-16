#![allow(clippy::expect_used)]
// reason: focused configuration tests use expect for direct assertion failures.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::config::{
    CapturedConfigValue, RuntimeConfigKey, RuntimeConfigSnapshot, RuntimeConfigSource,
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

    let snapshot = RuntimeConfigSnapshot::capture(source).expect("capture succeeds");

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
fn runtime_config_catalog_deduplicates_static_dynamic_keys_and_excludes_maintenance() {
    let source = FakeSource::new([(
        "RSS_DOMAIN_TRANSPORT_REQUIRED_DOMAINS",
        FakeValue::Present("identity,IDENTITY,audit".to_owned()),
    )]);
    let reads = read_log(&source);
    let snapshot = RuntimeConfigSnapshot::capture(source).expect("capture succeeds");
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
    let session_sweep_ms = crate::build_session_sweeper_interval_from(get).as_millis();
    format!("domains={domains}\nsession-sweep-ms={session_sweep_ms}")
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
            RuntimeConfigSnapshot::capture(FakeSource::new(values)).expect("capture succeeds");
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
session-sweep-ms=1000\n\
[default]\n\
domains=IDENTITY\n\
session-sweep-ms=300000\n\
[invalid-fail-soft]\n\
domains=IDENTITY\n\
session-sweep-ms=300000\n\
[non-unicode]\n\
domains=error:missing required env var: RSS_DOMAIN_TRANSPORT_REQUIRED_DOMAINS\n\
session-sweep-ms=300000\n\
[empty]\n\
domains=error:RSS_DOMAIN_TRANSPORT_REQUIRED_DOMAINS must not contain empty entries\n\
session-sweep-ms=300000\n\
[whitespace]\n\
domains=error:RSS_DOMAIN_TRANSPORT_REQUIRED_DOMAINS entries must not contain whitespace or control characters\n\
session-sweep-ms=300000\n";
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
    let snapshot = RuntimeConfigSnapshot::capture(source).expect("capture succeeds");

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
    let snapshot = RuntimeConfigSnapshot::capture(source).expect("capture succeeds");
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
    let snapshot = RuntimeConfigSnapshot::capture(source).expect("capture succeeds");
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
    let snapshot = RuntimeConfigSnapshot::capture(source).expect("capture must not parse-fail");

    let error = crate::domain_transport_required_domains_from(&|name| {
        snapshot.view().value(name).map(str::to_owned)
    })
    .expect_err("existing builder owns the parse error");
    assert_eq!(
        error.to_string(),
        "RSS_DOMAIN_TRANSPORT_REQUIRED_DOMAINS must not contain empty entries"
    );
}
