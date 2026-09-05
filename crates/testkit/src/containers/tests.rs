#![allow(clippy::expect_used, unused_imports)]
// reason: test setup and assertions use expect/expect_err to retain precise failure context.

use super::minio::*;
use super::postgres::*;
use super::rabbitmq::*;
use super::redis::*;
use super::vault::*;
use super::*;

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
}

#[test]
fn exact_provider_tls_inputs_reject_wildcards_and_policy_drift() {
    for queue in ["", "settings.*", "settings/queue", "空"] {
        assert!(
            validate_exact_queue_name(queue).is_err(),
            "accepted non-exact RabbitMQ queue {queue:?}"
        );
    }
    assert!(validate_exact_queue_name("runtime.fact-updated").is_ok());

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

/// Vhost validation is pure; it does not need a fabricated external fixture.
#[test]
fn vhost_names_are_safe_before_management_io() {
    for invalid in ["", "bad/vhost", "bad;vhost", "bad vhost"] {
        assert!(validate_rabbit_vhost(invalid).is_err());
    }
    assert!(validate_rabbit_vhost("good-vhost_1").is_ok());
}
