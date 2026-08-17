#![allow(clippy::expect_used, unused_imports)]
// reason: test setup and assertions use expect/expect_err to retain precise failure context.

use super::minio::*;
use super::mqtt::*;
use super::postgres::*;
use super::rabbitmq::*;
use super::redis::*;
use super::vault::*;
use super::*;

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use testcontainers::core::logs::LogFrame;

fn lookup<'a>(values: &'a [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> + 'a {
    move |key| {
        values
            .iter()
            .find_map(|(candidate, value)| (*candidate == key).then(|| (*value).to_string()))
    }
}

fn unique_test_dir(case: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "rss-testkit-{case}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ))
}

fn create_private_test_dir(path: &Path) {
    std::fs::create_dir_all(path).expect("test log directory must be creatable");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("test log directory must be private");
    }
}

#[test]
fn mqtt_acl_allows_only_the_closed_downlink_contracts() {
    let acl = mqtt_exact_acl("device-primary", "device-cross");
    let downlinks = acl
        .lines()
        .filter(|line| line.contains("/downlink/"))
        .collect::<Vec<_>>();
    assert_eq!(downlinks.len(), 10);
    for line in downlinks {
        assert!(
            MQTT_DOWNLINK_CONTRACTS
                .iter()
                .any(|contract| line.ends_with(contract)),
            "unknown downlink contract entered the exact ACL: {line}"
        );
        assert!(!line.contains('+') && !line.contains('#'));
    }
    assert!(
        !acl.contains("/downlink/identity.device-unknown"),
        "an extra downlink contract must remain rejected"
    );
}

#[test]
fn published_port_resolution_retries_only_bounded_missing_port_metadata() {
    let missing = testcontainers::TestcontainersError::PortNotExposed {
        id: "fixture".to_string(),
        port: REDIS_PORT.tcp(),
    };
    assert!(retry_published_port_resolution(&missing, 1));
    assert!(retry_published_port_resolution(&missing, 2));
    assert!(!retry_published_port_resolution(
        &missing,
        PUBLISHED_PORT_MAX_ATTEMPTS
    ));

    let other = testcontainers::TestcontainersError::Other(Box::new(std::io::Error::other(
        "fixture error",
    )));
    assert!(!retry_published_port_resolution(&other, 1));
}

#[test]
fn network_attachment_rejects_shell_metacharacters_in_dns_name() {
    let err = validate_network_attachment(NetworkAttachment {
        network: "rss-bridge",
        dns_name: "evil;rm -rf /",
    })
    .expect_err("dns_name with shell metacharacters must fail closed");
    assert!(err.to_string().contains("dns_name"));

    validate_network_attachment(NetworkAttachment {
        network: "rss-bridge",
        dns_name: "rss-so-1-vault",
    })
    .expect("safe dns_name must pass");
}

#[test]
fn vault_dev_tls_san_flags_include_dns_name_and_exclude_host_gateway_aliases() {
    let flags = vault_dev_tls_san_flags("rss-fixture-dns");
    assert_eq!(
        flags,
        vec![
            "-dev-tls-san=localhost".to_string(),
            "-dev-tls-san=127.0.0.1".to_string(),
            "-dev-tls-san=rss-fixture-dns".to_string(),
        ]
    );
    let joined = flags.join(" ");
    assert!(!joined.contains("host.docker.internal"));
    assert!(!joined.contains("host.testcontainers.internal"));
}

#[test]
fn tls_dns_names_include_localhost_and_fixture_dns() {
    assert_eq!(
        tls_dns_names("rss-fixture-dns"),
        ["localhost", "rss-fixture-dns"]
    );
    tls_material("rss-fixture-dns").expect("tls material must build with fixture DNS");
}

/// INVARIANT: INTEGRATION-CONTAINER-CONTEXT-01 { level = "Medium", exec = "manual/opt-in", source = "code", synthetic_red = "ci_container_context_rejects_every_partial_environment_shape", anti_vacuity = "ci_container_context_accepts_complete_or_fully_absent_environment" } — CI context is all-or-nothing:
/// a complete context constructs the typed value, while no context is the explicit local mode.
#[test]
fn ci_container_context_accepts_complete_or_fully_absent_environment() {
    let complete = [
        (
            "RSS_CI_CONTAINER_SCOPE",
            "rss-9001-2-event-transport-1-of-2",
        ),
        ("RSS_CI_INTEGRATION_SHARD", "event-transport"),
        ("RSS_CI_INTEGRATION_PARTITION", "1/2"),
        ("RSS_CI_CONTAINER_LOG_DIR", "/tmp/rss-integration-9001-2"),
    ];

    let context = CiContainerContext::from_lookup(lookup(&complete))
        .expect("complete CI context must parse")
        .expect("complete CI context must select managed mode");
    assert_eq!(context.scope, "rss-9001-2-event-transport-1-of-2");
    assert_eq!(context.shard, "event-transport");
    assert_eq!(context.partition, "1/2");
    assert_eq!(
        context.log_dir,
        PathBuf::from("/tmp/rss-integration-9001-2")
    );

    assert!(
        CiContainerContext::from_lookup(lookup(&[]))
            .expect("fully absent context is valid local mode")
            .is_none(),
        "fully absent CI context must retain hermetic local mode"
    );
}

/// Partial context fails closed rather
/// than silently launching an unowned container in CI.
#[test]
fn ci_container_context_rejects_every_partial_environment_shape() {
    let all = [
        (
            "RSS_CI_CONTAINER_SCOPE",
            "rss-9001-2-postgres-domain-unpartitioned",
        ),
        ("RSS_CI_INTEGRATION_SHARD", "postgres-domain"),
        ("RSS_CI_INTEGRATION_PARTITION", "unpartitioned"),
        ("RSS_CI_CONTAINER_LOG_DIR", "/tmp/rss-integration-9001-2"),
    ];

    for missing in all.map(|(key, _)| key) {
        let partial: Vec<_> = all
            .iter()
            .copied()
            .filter(|(key, _)| *key != missing)
            .collect();
        let error = CiContainerContext::from_lookup(lookup(&partial))
            .expect_err("partial CI context must fail closed");
        assert!(
            error.to_string().contains(missing),
            "error must identify missing {missing}: {error}"
        );
    }
}

/// Label and filesystem inputs reject
/// control characters, traversal and malformed canonical partition values.
#[test]
fn ci_container_context_rejects_invalid_scope_shard_partition_and_log_dir() {
    let invalid_cases = [
        (
            "scope control character",
            [
                ("RSS_CI_CONTAINER_SCOPE", "rss-9001\nforged"),
                ("RSS_CI_INTEGRATION_SHARD", "postgres-domain"),
                ("RSS_CI_INTEGRATION_PARTITION", "unpartitioned"),
                ("RSS_CI_CONTAINER_LOG_DIR", "/tmp/rss-integration"),
            ],
        ),
        (
            "shard traversal",
            [
                ("RSS_CI_CONTAINER_SCOPE", "rss-9001-2-postgres-domain"),
                ("RSS_CI_INTEGRATION_SHARD", "../postgres-domain"),
                ("RSS_CI_INTEGRATION_PARTITION", "unpartitioned"),
                ("RSS_CI_CONTAINER_LOG_DIR", "/tmp/rss-integration"),
            ],
        ),
        (
            "non-canonical partition",
            [
                ("RSS_CI_CONTAINER_SCOPE", "rss-9001-2-event-transport"),
                ("RSS_CI_INTEGRATION_SHARD", "event-transport"),
                ("RSS_CI_INTEGRATION_PARTITION", "01/02"),
                ("RSS_CI_CONTAINER_LOG_DIR", "/tmp/rss-integration"),
            ],
        ),
        (
            "relative log directory",
            [
                ("RSS_CI_CONTAINER_SCOPE", "rss-9001-2-postgres-domain"),
                ("RSS_CI_INTEGRATION_SHARD", "postgres-domain"),
                ("RSS_CI_INTEGRATION_PARTITION", "unpartitioned"),
                ("RSS_CI_CONTAINER_LOG_DIR", "target/container-logs"),
            ],
        ),
    ];

    for (case, values) in invalid_cases {
        assert!(
            CiContainerContext::from_lookup(lookup(&values)).is_err(),
            "{case} must fail closed"
        );
    }
}

/// Workflow and Rust share an exact closed partition vocabulary. General-looking
/// fractions are rejected even when numerically well formed.
#[test]
fn canonical_integration_partition_is_an_exact_closed_set() {
    for accepted in ["unpartitioned", "1/2", "2/2"] {
        assert!(
            is_canonical_partition(accepted),
            "workflow partition {accepted} must be accepted"
        );
    }
    for rejected in ["", "1/1", "1/3", "2/3", "01/02", "0/2", "3/2"] {
        assert!(
            !is_canonical_partition(rejected),
            "out-of-contract partition {rejected} must fail closed"
        );
    }
}

#[test]
fn invalid_partition_error_lists_the_exact_closed_vocabulary() {
    let values = [
        ("RSS_CI_CONTAINER_SCOPE", "rss-9001-2-event-transport"),
        ("RSS_CI_INTEGRATION_SHARD", "event-transport"),
        ("RSS_CI_INTEGRATION_PARTITION", "1/3"),
        ("RSS_CI_CONTAINER_LOG_DIR", "/tmp/rss-integration"),
    ];

    let error = CiContainerContext::from_lookup(lookup(&values))
        .expect_err("out-of-contract partition must fail closed");
    assert_eq!(
        error.to_string(),
        "RSS_CI_INTEGRATION_PARTITION 不是 canonical partition（须为 unpartitioned、1/2 或 2/2）"
    );
}

/// `INTEGRATION-CONTAINER-OWNERSHIP-01` 的正向行为证明：闭合 service enum 产出精确
/// ownership labels；正式 Medium/verify 声明与 synthetic-red 位于 xtask。
#[test]
fn container_service_emits_exact_managed_scope_labels() {
    let values = [
        (
            "RSS_CI_CONTAINER_SCOPE",
            "rss-9001-2-event-transport-1-of-2",
        ),
        ("RSS_CI_INTEGRATION_SHARD", "event-transport"),
        ("RSS_CI_INTEGRATION_PARTITION", "1/2"),
        ("RSS_CI_CONTAINER_LOG_DIR", "/tmp/rss-integration-9001-2"),
    ];
    let context = CiContainerContext::from_lookup(lookup(&values))
        .expect("context must parse")
        .expect("context must be managed");

    for (service, expected_name) in [
        (ContainerService::Postgres, "postgres"),
        (ContainerService::Redis, "redis"),
        (ContainerService::RabbitMq, "rabbitmq"),
        (ContainerService::Mosquitto, "mosquitto"),
        (ContainerService::Minio, "minio"),
        (ContainerService::Vault, "vault"),
        (ContainerService::Server, "server"),
    ] {
        let expected = BTreeMap::from([
            ("io.rss.integration.managed".to_string(), "true".to_string()),
            (
                "io.rss.integration.scope".to_string(),
                "rss-9001-2-event-transport-1-of-2".to_string(),
            ),
            (
                "io.rss.integration.shard".to_string(),
                "event-transport".to_string(),
            ),
            (
                "io.rss.integration.partition".to_string(),
                "1/2".to_string(),
            ),
            (
                "io.rss.integration.service".to_string(),
                expected_name.to_string(),
            ),
        ]);
        assert_eq!(service.labels(&context), expected);
    }
}

#[test]
fn vault_fixture_pins_image_and_maps_host_https_endpoint() {
    assert_eq!(
        (vault::VAULT_IMAGE, vault::VAULT_IMAGE_TAG),
        ("hashicorp/vault", "1.17.6")
    );
    assert_eq!(
        vault_host_endpoint("127.0.0.1", 49_152),
        "https://127.0.0.1:49152"
    );
    assert_eq!(ContainerService::Vault.name(), "vault");
}

#[test]
fn mqtt_fixture_keeps_the_exact_acl_available_to_offline_sessions() {
    let config = mqtt_broker_config(None);
    assert_eq!(config.matches("listener 8883").count(), 1);
    assert!(config.contains("per_listener_settings false"));
    assert!(!config.contains("per_listener_settings true"));
    assert!(config.contains("acl_file /mosquitto/config/acl"));
    assert!(!config.contains("plugin_opt_assertion_fault"));

    let faulted = mqtt_broker_config(Some(MqttAssertionFault::CorruptFirstSignature));
    assert_eq!(faulted.matches("plugin_opt_assertion_fault").count(), 1);
    assert!(faulted.contains("corrupt_first_signature"));
}

#[test]
fn exact_provider_tls_inputs_reject_wildcards_and_policy_drift() {
    for queue in ["", "settings.*", "settings/queue", "空"] {
        assert!(
            validate_exact_queue_name(queue).is_err(),
            "accepted non-exact RabbitMQ queue {queue:?}"
        );
    }
    assert!(validate_exact_queue_name("settings.config-version-changed").is_ok());

    let policy: serde_json::Value = serde_json::from_str(&minio_archive_policy())
        .expect("fixed MinIO archive policy must be valid JSON");
    assert_eq!(
        policy,
        serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetBucketVersioning",
                        "s3:GetBucketObjectLockConfiguration",
                        "s3:GetLifecycleConfiguration"
                    ],
                    "Resource": format!("arn:aws:s3:::{MINIO_ARCHIVE_BUCKET}")
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:GetObjectVersion",
                        "s3:GetObjectRetention",
                        "s3:PutObject"
                    ],
                    "Resource": format!("arn:aws:s3:::{MINIO_ARCHIVE_BUCKET}/*")
                }
            ]
        }),
        "MinIO workload policy must remain an exact closed value"
    );
}

#[test]
fn container_command_diagnostics_are_bounded_and_redacted() {
    let oversized = format!(
        "prefix {MINIO_ROOT_PASSWORD} {MINIO_WORKLOAD_PASSWORD} {}",
        "x".repeat(CONTAINER_COMMAND_OUTPUT_LIMIT_BYTES + 128)
    );
    let rendered = runtime::bounded_redacted_command_output(oversized.into_bytes());

    assert!(!rendered.contains(MINIO_ROOT_PASSWORD));
    assert!(!rendered.contains(MINIO_WORKLOAD_PASSWORD));
    assert_eq!(rendered.matches("<redacted>").count(), 2);
    assert!(rendered.ends_with("[rss-testkit: command output truncated]"));
    assert!(
        rendered.len()
            <= CONTAINER_COMMAND_OUTPUT_LIMIT_BYTES
                + "\n[rss-testkit: command output truncated]".len()
    );

    let failure = runtime::ContainerCommandOutput {
        exit_code: Some(7),
        stdout: "safe stdout".to_owned(),
        stderr: "safe stderr".to_owned(),
    }
    .failure("provision archive");
    let diagnostic = failure.to_string();
    assert!(diagnostic.contains("provision archive"));
    assert!(diagnostic.contains("exit=Some(7)"));
    assert!(!diagnostic.contains("mc alias set"));
}

/// INVARIANT: INTEGRATION-CONTAINER-LOG-01 { level = "Medium", exec = "manual/opt-in", source = "code", synthetic_red = "bounded_log_consumer_truncates_at_one_mib_with_marker", anti_vacuity = "bounded_log_consumer_uses_unique_names_and_source_prefixes" } — each container gets a collision-free
/// service-pid-sequence file and every frame retains its Docker stream source.
#[test]
fn bounded_log_consumer_uses_unique_names_and_source_prefixes() {
    let dir = unique_test_dir("log-prefix");
    create_private_test_dir(&dir);
    let first = BoundedFileLogConsumer::new(&dir, ContainerService::Postgres)
        .expect("first consumer must construct");
    let second = BoundedFileLogConsumer::new(&dir, ContainerService::Postgres)
        .expect("second consumer must construct");

    assert_ne!(
        first.path(),
        second.path(),
        "sequence must prevent collisions"
    );
    let expected_prefix = format!("postgres-{}-", std::process::id());
    for path in [first.path(), second.path()] {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("log name must be UTF-8");
        assert!(
            name.starts_with(&expected_prefix),
            "unexpected name: {name}"
        );
        assert!(name.ends_with(".log"), "unexpected name: {name}");
    }

    first
        .write_frame(&LogFrame::StdOut(b"ready\n".to_vec().into()))
        .expect("stdout frame must persist");
    first
        .write_frame(&LogFrame::StdErr(b"warning\n".to_vec().into()))
        .expect("stderr frame must persist");
    let output = std::fs::read_to_string(first.path()).expect("persisted log must be readable");
    assert!(
        output.contains("[stdout] ready\n"),
        "stdout source lost: {output:?}"
    );
    assert!(
        output.contains("[stderr] warning\n"),
        "stderr source lost: {output:?}"
    );

    std::fs::remove_dir_all(dir).expect("test log directory cleanup must succeed");
}

/// Persisted logs, including the explicit
/// truncation marker, never exceed the one MiB per-container budget.
#[test]
fn bounded_log_consumer_truncates_at_one_mib_with_marker() {
    let dir = unique_test_dir("log-limit");
    create_private_test_dir(&dir);
    let consumer = BoundedFileLogConsumer::new(&dir, ContainerService::Redis)
        .expect("consumer must construct");

    let oversized = vec![b'x'; CONTAINER_LOG_LIMIT_BYTES + 4096];
    consumer
        .write_frame(&LogFrame::StdOut(oversized.into()))
        .expect("oversized frame must be bounded, not rejected");
    consumer
        .write_frame(&LogFrame::StdErr(b"must-not-grow-file".to_vec().into()))
        .expect("frames after truncation must be ignored successfully");

    let bytes = std::fs::read(consumer.path()).expect("persisted log must be readable");
    assert!(
        bytes.len() <= 1024 * 1024,
        "log exceeded one MiB: {} bytes",
        bytes.len()
    );
    assert!(
        bytes.ends_with(CONTAINER_LOG_TRUNCATION_MARKER),
        "bounded log must end with the explicit truncation marker"
    );

    let boundary = BoundedFileLogConsumer::new(&dir, ContainerService::RabbitMq)
        .expect("boundary consumer must construct");
    let payload_limit = CONTAINER_LOG_LIMIT_BYTES - CONTAINER_LOG_TRUNCATION_MARKER.len();
    let almost_full = vec![b'y'; payload_limit - b"[stdout] ".len() - 5];
    boundary
        .write_frame(&LogFrame::StdOut(almost_full.into()))
        .expect("first near-limit frame must persist without truncation");
    boundary
        .write_frame(&LogFrame::StdErr(b"overflow".to_vec().into()))
        .expect("second frame crossing the payload budget must append the marker");
    let boundary_bytes = std::fs::read(boundary.path()).expect("boundary log must be readable");
    assert_eq!(
        boundary_bytes.len(),
        CONTAINER_LOG_LIMIT_BYTES,
        "late truncation must still stay within one MiB"
    );
    assert!(boundary_bytes.ends_with(CONTAINER_LOG_TRUNCATION_MARKER));

    std::fs::remove_dir_all(dir).expect("test log directory cleanup must succeed");
}

/// A pre-existing candidate is never overwritten: create_new retries the next sequence.
#[test]
fn bounded_log_consumer_retries_a_preoccupied_filename() {
    let dir = unique_test_dir("log-preoccupied");
    create_private_test_dir(&dir);
    let sequence = AtomicU64::new(7);
    let occupied = dir.join(format!("postgres-{}-7.log", std::process::id()));
    std::fs::write(&occupied, b"pre-existing\n").expect("occupied fixture must be writable");

    let consumer =
        BoundedFileLogConsumer::new_with_sequence(&dir, ContainerService::Postgres, &sequence)
            .expect("consumer must retry after create_new collision");

    assert_eq!(
        consumer.path(),
        dir.join(format!("postgres-{}-8.log", std::process::id()))
    );
    assert_eq!(
        std::fs::read(&occupied).expect("occupied fixture must remain readable"),
        b"pre-existing\n"
    );
    std::fs::remove_dir_all(dir).expect("test log directory cleanup must succeed");
}

#[test]
fn bounded_log_consumer_persists_writer_error_status_on_first_io_failure() {
    let dir = unique_test_dir("log-writer-error");
    create_private_test_dir(&dir);
    let consumer = BoundedFileLogConsumer::new(&dir, ContainerService::Redis)
        .expect("consumer must construct");
    let status_path = consumer.path().with_extension("status");

    // A read-only descriptor deterministically rejects write_all without relying on disk state.
    let read_only = File::open(consumer.path()).expect("log fixture must reopen read-only");
    consumer
        .state
        .lock()
        .expect("writer state mutex must remain healthy")
        .file = read_only;
    assert!(
        consumer
            .write_frame(&LogFrame::StdOut(b"must-fail\n".to_vec().into()))
            .is_err(),
        "read-only descriptor must reproduce the writer failure"
    );
    assert_eq!(
        std::fs::read_to_string(&status_path)
            .expect("writer failure must remain machine-readable after stderr is lost"),
        "writer-error\n"
    );

    std::fs::remove_dir_all(dir).expect("test log directory cleanup must succeed");
}

#[test]
fn bounded_log_consumer_requires_a_prepared_private_real_directory() {
    let missing = unique_test_dir("log-missing");
    assert!(
        BoundedFileLogConsumer::new(&missing, ContainerService::Redis).is_err(),
        "consumer must not create lifecycle directories"
    );

    let public = unique_test_dir("log-public");
    std::fs::create_dir_all(&public).expect("public fixture must be creatable");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o755))
            .expect("public fixture permissions must be settable");
        assert!(
            BoundedFileLogConsumer::new(&public, ContainerService::Redis).is_err(),
            "consumer must reject group/other-accessible directories"
        );
    }
    std::fs::remove_dir_all(public).expect("test log directory cleanup must succeed");

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let real = unique_test_dir("log-real");
        let link = unique_test_dir("log-symlink");
        create_private_test_dir(&real);
        symlink(&real, &link).expect("log directory symlink fixture must be creatable");
        assert!(
            BoundedFileLogConsumer::new(&link, ContainerService::Redis).is_err(),
            "consumer must reject a symlinked log directory"
        );
        std::fs::remove_file(link).expect("symlink fixture cleanup must succeed");
        std::fs::remove_dir_all(real).expect("real directory fixture cleanup must succeed");
    }
}

#[test]
fn redis_external_url_requires_supported_scheme_host_and_explicit_port() {
    for accepted in [
        "redis://localhost:6379",
        "rediss://cache.example.test:6380/0",
        "redis://[::1]:6379",
    ] {
        assert!(
            validate_redis_url(accepted).is_ok(),
            "valid Redis URL rejected: {accepted}"
        );
    }
    for rejected in [
        "",
        "localhost:6379",
        "http://localhost:6379",
        "redis://localhost",
        "redis://:6379",
        "redis://localhost:0",
        "redis://localhost:70000",
    ] {
        assert!(
            validate_redis_url(rejected).is_err(),
            "invalid Redis URL accepted: {rejected}"
        );
    }
}

/// Empty external-service variables are absence, never an opt-in. This pure decision
/// test covers resolvers without starting Docker. MQTT has no external URL resolver.
#[test]
fn empty_external_environment_values_select_self_provision() {
    for key in [
        "RSS_TEST_ALLOW_EXTERNAL_POSTGRES",
        "REDIS_TEST_URL",
        "RSS_AMQP_TEST_URL",
    ] {
        assert_eq!(
            non_empty_external_value(lookup(&[(key, "")]), key)
                .expect("UTF-8 test value must parse"),
            None,
            "empty {key} must select self-provision"
        );
    }
}

/// External PostgreSQL consumes endpoint coordinates only and never owner credentials.
#[test]
fn postgres_external_environment_never_requires_owner_credentials() {
    let endpoint_only = HashMap::from([
        ("RSS_TEST_ALLOW_EXTERNAL_POSTGRES", "1"),
        ("PGHOST", "127.0.0.1"),
        ("PGPORT", "5432"),
        ("PGDATABASE", "rss_test"),
    ]);
    let endpoint = postgres_external_endpoint_from_lookup(|key| {
        endpoint_only.get(key).map(|value| (*value).to_string())
    })
    .expect("endpoint-only external postgres must parse")
    .expect("non-empty opt-in must select external postgres");
    assert_eq!(endpoint.host, "127.0.0.1");
    assert_eq!(endpoint.port, 5432);
    assert_eq!(endpoint.database, "rss_test");
}

#[test]
fn partial_postgres_external_endpoint_fails_closed() {
    let partial = HashMap::from([
        ("RSS_TEST_ALLOW_EXTERNAL_POSTGRES", "1"),
        ("PGHOST", "127.0.0.1"),
    ]);
    let error = postgres_external_endpoint_from_lookup(|key| {
        partial.get(key).map(|value| (*value).to_string())
    })
    .expect_err("partial external postgres endpoint must fail closed");
    let message = error.to_string();
    assert!(
        message.contains("PGPORT"),
        "missing PGPORT not reported: {message}"
    );
    assert!(
        message.contains("PGDATABASE"),
        "missing PGDATABASE not reported: {message}"
    );
}

#[test]
fn external_fixture_cannot_yield_owned_postgres_capability() {
    let fixture = PgFixture::External(ExternalPgFixture {
        endpoint: PgEndpoint {
            host: "127.0.0.1".to_owned(),
            port: 5432,
            database: "rss_test".to_owned(),
        },
    });
    assert!(matches!(fixture.into_owned(), Err(OwnedPostgresRequired)));
}

#[tokio::test]
async fn external_role_resolution_preserves_cluster_global_identity() {
    use sqlx::postgres::PgPoolOptions;

    let owned = owned_postgres()
        .await
        .expect("owned PostgreSQL fixture must start");
    let role = "rss_external_identity_guard";
    let password = "external-identity-guard-password";
    owned
        .resolve_app_roles([PgAppRoleSpec::new(role, password)])
        .await
        .expect("owned fixture must provision the preconfigured role");
    let owner = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(connect_options(
            owned.owner_params(),
            sqlx::postgres::PgSslMode::Prefer,
        ))
        .await
        .expect("fixture owner must connect");
    type RoleSnapshot = (
        Option<String>,
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
        Option<String>,
        i64,
    );
    let snapshot = async |pool: &sqlx::PgPool| -> RoleSnapshot {
        sqlx::query_as(
            "SELECT role.rolpassword, role.rolcanlogin, role.rolsuper, role.rolcreatedb, \
         role.rolcreaterole, role.rolreplication, role.rolbypassrls, role.rolinherit, \
         role.rolvaliduntil::text, \
         (SELECT count(*)::bigint FROM pg_auth_members AS membership \
          WHERE membership.roleid = role.oid OR membership.member = role.oid) \
         FROM pg_authid AS role WHERE role.rolname = $1",
        )
        .bind(role)
        .fetch_one(pool)
        .await
        .expect("owner must snapshot role identity")
    };
    sqlx::query(&format!("ALTER ROLE {role} VALID UNTIL 'infinity'"))
        .execute(&owner)
        .await
        .expect("normalize role validity");
    let before = snapshot(&owner).await;
    let external = PgFixture::External(ExternalPgFixture {
        endpoint: owned.endpoint.clone(),
    });
    external
        .resolve_app_roles([PgAppRoleSpec::new(role, password)])
        .await
        .expect("external fixture must consume the preconfigured role");
    let (first, second) = tokio::join!(
        external.resolve_app_roles([PgAppRoleSpec::new(role, password)]),
        external.resolve_app_roles([PgAppRoleSpec::new(role, password)])
    );
    first.expect("first concurrent external resolution");
    second.expect("second concurrent external resolution");
    assert!(
        external
            .resolve_app_roles([PgAppRoleSpec::new(role, "wrong-password")])
            .await
            .is_err(),
        "wrong external credential must fail closed"
    );
    assert!(
        external
            .resolve_app_roles([PgAppRoleSpec::new("rss_external_missing_role", password,)])
            .await
            .is_err(),
        "missing external role must fail closed"
    );

    sqlx::query(&format!("ALTER ROLE {role} BYPASSRLS"))
        .execute(&owner)
        .await
        .expect("make role bypass RLS");
    assert!(
        external
            .resolve_app_roles([PgAppRoleSpec::new(role, password)])
            .await
            .is_err(),
        "BYPASSRLS external role must fail closed"
    );
    sqlx::query(&format!("ALTER ROLE {role} NOBYPASSRLS"))
        .execute(&owner)
        .await
        .expect("restore RLS posture");

    sqlx::query(&format!("ALTER ROLE {role} SUPERUSER"))
        .execute(&owner)
        .await
        .expect("make role unsafe");
    assert!(
        external
            .resolve_app_roles([PgAppRoleSpec::new(role, password)])
            .await
            .is_err(),
        "SUPERUSER external role must fail closed"
    );
    sqlx::query(&format!("ALTER ROLE {role} NOSUPERUSER"))
        .execute(&owner)
        .await
        .expect("restore role posture");

    sqlx::query(&format!("ALTER ROLE {role} VALID UNTIL '2000-01-01'"))
        .execute(&owner)
        .await
        .expect("expire role");
    assert!(
        external
            .resolve_app_roles([PgAppRoleSpec::new(role, password)])
            .await
            .is_err(),
        "expired external role must fail closed"
    );
    sqlx::query(&format!("ALTER ROLE {role} VALID UNTIL 'infinity'"))
        .execute(&owner)
        .await
        .expect("restore role validity");

    sqlx::query("CREATE ROLE rss_external_parent SUPERUSER")
        .execute(&owner)
        .await
        .expect("create unsafe parent role");
    sqlx::query(&format!("GRANT rss_external_parent TO {role}"))
        .execute(&owner)
        .await
        .expect("grant unsafe membership");
    assert!(
        external
            .resolve_app_roles([PgAppRoleSpec::new(role, password)])
            .await
            .is_err(),
        "external role membership must fail closed"
    );
    sqlx::query(&format!("REVOKE rss_external_parent FROM {role}"))
        .execute(&owner)
        .await
        .expect("revoke unsafe membership");
    sqlx::query("DROP ROLE rss_external_parent")
        .execute(&owner)
        .await
        .expect("drop unsafe parent role");

    let after = snapshot(&owner).await;
    assert_eq!(before, after, "external resolution must be read-only");
    owner.close().await;
}

/// amqp URL 拼 vhost：去重尾 `/` 后追加，env 路径正确性（不依赖容器）。
#[test]
fn amqp_url_with_vhost_appends_after_trimming_slash() {
    assert_eq!(
        amqp_url_with_vhost("amqp://guest:guest@h:5672", "rss_a"),
        "amqp://guest:guest@h:5672/rss_a"
    );
    assert_eq!(
        amqp_url_with_vhost("amqp://guest:guest@h:5672/", "rss_b"),
        "amqp://guest:guest@h:5672/rss_b"
    );
}

/// PgConnParams Debug 脱敏：password 输出 `<redacted>`，不泄露凭证。
#[test]
fn pg_conn_params_debug_redacts_password() {
    let p = PgConnParams {
        host: "localhost".to_string(),
        port: 5432,
        database: "rss_test".to_string(),
        username: "postgres".to_string(),
        password: "s3cr3t".to_string(),
    };
    let s = format!("{p:?}");
    assert!(s.contains("<redacted>"), "Debug 须含 <redacted>: {s}");
    assert!(!s.contains("s3cr3t"), "Debug 不得含明文密码: {s}");
}

/// vhost URL-safe 校验：含不安全字符返回 Err。
#[test]
#[allow(clippy::unwrap_used)]
// reason: 测试体构造 tokio runtime 辅助调 async fn；runtime build 失败属 programmer error，panic 正当。
fn vhost_url_rejects_unsafe_chars() {
    let fixture = RabbitFixture {
        inner: RabbitInner::Env {
            base: "amqp://guest:guest@h:5672".to_string(),
        },
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let result = rt.block_on(fixture.vhost_url("bad/vhost"));
    assert!(result.is_err(), "含 / 须报错");
    let result2 = rt.block_on(fixture.vhost_url("good-vhost_1"));
    // env 路径无容器，直接拼 URL，不报错（URL-safe）。
    assert!(result2.is_ok(), "合法 vhost 须 Ok");
}

#[test]
#[allow(clippy::unwrap_used)]
// reason: 测试体构造 tokio runtime 辅助调 async fn；runtime build 失败属 programmer error。
fn broker_forced_close_rejects_external_fixture_without_management_authority() {
    let fixture = RabbitFixture {
        inner: RabbitInner::Env {
            base: "amqps://guest:guest@example.test:5671".to_string(),
        },
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let error = rt
        .block_on(fixture.broker_force_close_one_connection("rss_test", "review test"))
        .expect_err("external AMQP URL must not imply broker management authority");

    assert!(error.to_string().contains("managed RabbitMQ container"));
}

/// strict_test_db_name：合法测试库名通过，非测试库名拒绝。
/// 表驱动覆盖 ends_with("_test") / "test" 精确匹配 / substring 误命中 / 尾缀不符。
#[test]
fn strict_test_db_name_table() {
    // 通：以 _test 结尾
    assert!(strict_test_db_name("rss_test"), "rss_test 须通");
    assert!(strict_test_db_name("x_test"), "x_test 须通");
    // 通：精确 "test"
    assert!(strict_test_db_name("test"), "test 须通");
    // 拒：prod 中含 test 但不以 _test 结尾
    assert!(!strict_test_db_name("prod_contest"), "prod_contest 须拒");
    // 拒：以 test 开头但不是 "test" 也不以 _test 结尾
    assert!(!strict_test_db_name("testdb"), "testdb 须拒");
    // 拒：test 在前但以 _prod 结尾
    assert!(!strict_test_db_name("test_prod"), "test_prod 须拒");
}

/// validate_amqp_base_url：base URL（无 vhost）通过；含非空 vhost 段报错。
#[test]
fn validate_amqp_base_url_table() {
    // 通：无 path 段
    assert!(
        validate_amqp_base_url("amqp://guest:guest@127.0.0.1:5672").is_ok(),
        "loopback 无 path 须通"
    );
    // 通：尾部空 path（/）
    assert!(
        validate_amqp_base_url("amqp://guest:guest@127.0.0.1:5672/").is_ok(),
        "loopback 尾 / 须通"
    );
    // 拒：外部长存 broker 不允许 non-loopback 明文。
    assert!(
        validate_amqp_base_url("amqp://guest:guest@h:5672").is_err(),
        "non-loopback 明文外部 broker 须拒"
    );
    // 拒：含非空 vhost 段
    assert!(
        validate_amqp_base_url("amqp://guest:guest@h:5672/existing_vhost").is_err(),
        "含 vhost 须拒"
    );
    // 通：loopback 明文保留给本地 fixture。
    assert!(
        validate_amqp_base_url("amqp://guest:guest@127.0.0.1:5672").is_ok(),
        "loopback 明文 fixture 须通"
    );
    // 通：amqps 协议
    assert!(
        validate_amqp_base_url("amqps://user:pass@host:5671").is_ok(),
        "amqps 无 path 须通"
    );
    // 拒：非 amqp 协议
    assert!(
        validate_amqp_base_url("http://h:5672").is_err(),
        "非 amqp 协议须拒"
    );
}

#[cfg(feature = "integration")]
#[tokio::test]
async fn real_redis_lifecycle_preserves_cross_scope_canary() -> anyhow::Result<()> {
    use anyhow::Context as _;
    use std::process::{Command, Output};
    use testcontainers_modules::redis::Redis;

    struct Canary(String);
    impl Drop for Canary {
        fn drop(&mut self) {
            let _ = Command::new("docker")
                .args(["rm", "-fv", self.0.as_str()])
                .output();
        }
    }

    fn run(operation: &str, program: &str, args: &[&str]) -> anyhow::Result<Output> {
        Command::new(program)
            .args(args)
            .output()
            .with_context(|| format!("{operation}: failed to run {program}"))
    }
    fn ensure_success(output: &Output, operation: &str) -> anyhow::Result<()> {
        anyhow::ensure!(
            output.status.success(),
            "{operation} failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let script = root.join(".github/scripts/integration-services.sh");
    let temp = unique_test_dir("real-lifecycle");
    let _ = std::fs::remove_dir_all(&temp);
    std::fs::create_dir_all(&temp).context("create smoke temp directory")?;
    let scope = format!("rss-smoke-{}", std::process::id());
    let other_scope = format!("{scope}-canary");
    let log_dir = temp.join(format!("integration-service-logs-{scope}"));
    let evidence = temp.join("evidence.json");
    let archive = temp.join("logs.tar.gz");
    let script = script.to_string_lossy().into_owned();
    let log_dir_s = log_dir.to_string_lossy().into_owned();
    let evidence_s = evidence.to_string_lossy().into_owned();
    let archive_s = archive.to_string_lossy().into_owned();
    let common = [
        "--scope",
        scope.as_str(),
        "--shard",
        "consistency-fault",
        "--partition",
        "unpartitioned",
        "--log-dir",
        log_dir_s.as_str(),
        "--evidence",
        evidence_s.as_str(),
    ];
    for operation in ["bootstrap", "prepare"] {
        let mut args = vec![operation];
        args.extend(common);
        ensure_success(&run(operation, script.as_str(), &args)?, operation)?;
    }

    let fixture = runtime::start_with_context(
        Redis::default(),
        ContainerService::Redis,
        Some(CiContainerContext {
            scope: scope.clone(),
            shard: "consistency-fault".to_string(),
            partition: "unpartitioned".to_string(),
            log_dir: log_dir.clone(),
        }),
    )
    .await
    .context("real Redis fixture must self-provision")?;

    let owned = run(
        "discover owned Redis",
        "docker",
        &[
            "ps",
            "-aq",
            "--filter",
            "label=io.rss.integration.managed=true",
            "--filter",
            &format!("label=io.rss.integration.scope={scope}"),
        ],
    )?;
    ensure_success(&owned, "discover owned Redis")?;
    let owned_id = String::from_utf8(owned.stdout)
        .context("docker id must be UTF-8")?
        .trim()
        .to_string();
    assert!(!owned_id.is_empty(), "owned Redis id must be discoverable");
    assert!(!owned_id.contains('\n'), "scope must own exactly one Redis");

    let labels = run(
        "inspect owned Redis labels",
        "docker",
        &["inspect", "--format", "{{json .Config.Labels}}", &owned_id],
    )?;
    ensure_success(&labels, "inspect owned Redis labels")?;
    let labels: serde_json::Value =
        serde_json::from_slice(&labels.stdout).context("Docker labels must be JSON")?;
    for (key, value) in [
        ("io.rss.integration.managed", "true"),
        ("io.rss.integration.scope", scope.as_str()),
        ("io.rss.integration.shard", "consistency-fault"),
        ("io.rss.integration.partition", "unpartitioned"),
        ("io.rss.integration.service", "redis"),
    ] {
        assert_eq!(labels[key], value, "label {key} drifted");
    }

    let canary = run(
        "start cross-scope canary",
        "docker",
        &[
            "run",
            "-d",
            "--label",
            "io.rss.integration.managed=true",
            "--label",
            &format!("io.rss.integration.scope={other_scope}"),
            "--label",
            "io.rss.integration.shard=consistency-fault",
            "--label",
            "io.rss.integration.partition=unpartitioned",
            "--label",
            "io.rss.integration.service=redis",
            "redis:5.0",
        ],
    )?;
    ensure_success(&canary, "start cross-scope canary")?;
    let canary = Canary(
        String::from_utf8(canary.stdout)
            .context("canary id must be UTF-8")?
            .trim()
            .to_string(),
    );

    let canonical = std::fs::read_dir(&log_dir)
        .context("prepared log directory must be readable")?
        .map(|entry| entry.map(|value| value.path()))
        .collect::<std::io::Result<Vec<_>>>()
        .context("canonical log entries must be readable")?;
    assert!(
        canonical.iter().any(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("redis-") && name.ends_with(".log"))
        }),
        "real Redis must create one canonical log"
    );
    assert!(
        canonical.iter().any(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("redis-") && name.ends_with(".status"))
                && std::fs::read_to_string(path).is_ok_and(|value| value == "ok\n")
        }),
        "real Redis must create a canonical ok writer status"
    );

    let mut collect = vec!["collect"];
    collect.extend(common);
    collect.extend(["--outcome", "failure", "--archive", archive_s.as_str()]);
    ensure_success(
        &run("collect real Redis logs", script.as_str(), &collect)?,
        "collect real Redis logs",
    )?;

    std::mem::forget(fixture);
    let mut cleanup = vec!["cleanup"];
    cleanup.extend(common);
    ensure_success(
        &run("cleanup owned Redis", script.as_str(), &cleanup)?,
        "cleanup owned Redis",
    )?;
    assert!(
        !run(
            "verify owned Redis cleanup",
            "docker",
            &["inspect", &owned_id]
        )?
        .status
        .success(),
        "exact-scope cleanup must delete owned Redis"
    );
    assert!(
        run(
            "verify cross-scope canary survival",
            "docker",
            &["inspect", &canary.0]
        )?
        .status
        .success(),
        "cross-scope canary must survive cleanup"
    );
    let archive_listing = run(
        "inspect lifecycle archive",
        "tar",
        &["-tzf", archive_s.as_str()],
    )?;
    ensure_success(&archive_listing, "inspect lifecycle archive")?;
    let archive_listing =
        String::from_utf8(archive_listing.stdout).context("archive listing must be UTF-8")?;
    assert!(archive_listing.contains("redis-"));
    assert!(archive_listing.contains(".log"));
    assert!(
        !archive_listing.contains(".status"),
        "writer status is evidence metadata, not archive payload"
    );

    drop(canary);
    std::fs::remove_dir_all(temp).context("smoke temp directory cleanup must succeed")?;
    Ok(())
}
