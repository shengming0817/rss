use super::postgres::PgConnParams;
use super::rabbitmq::{validate_exact_queue_name, validate_rabbit_vhost};
use super::redis::REDIS_PORT;
use super::*;
use testcontainers::core::IntoContainerPort as _;

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
#[allow(clippy::expect_used)] // Fixture setup assertions retain their failure context.
fn network_attachment_rejects_shell_metacharacters_in_dns_name() {
    let err = validate_network_attachment(NetworkAttachment {
        network: "rss-bridge",
        dns_name: "evil;rm -rf /",
    })
    .expect_err("dns_name with shell metacharacters must fail closed");
    assert!(err.to_string().contains("dns_name"));

    validate_network_attachment(NetworkAttachment {
        network: "rss-bridge",
        dns_name: "rss-fixture-pg",
    })
    .expect("safe dns_name must pass");
}

#[test]
#[allow(clippy::expect_used)] // Fixture setup assertions retain their failure context.
fn tls_dns_names_include_localhost_and_fixture_dns() {
    assert_eq!(
        tls_dns_names("rss-fixture-dns"),
        ["localhost", "rss-fixture-dns"]
    );
    tls_material("rss-fixture-dns").expect("tls material must build with fixture DNS");
}

#[test]
fn exact_rabbit_queue_names_reject_wildcards() {
    for queue in ["", "settings.*", "settings/queue", "空"] {
        assert!(
            validate_exact_queue_name(queue).is_err(),
            "accepted non-exact RabbitMQ queue {queue:?}"
        );
    }
    assert!(validate_exact_queue_name("runtime.fact-updated").is_ok());
}

#[test]
fn container_command_diagnostics_are_bounded_and_strip_control_characters() {
    let oversized = format!(
        "prefix\x1b[31m\x00\n\t{}",
        "x".repeat(CONTAINER_COMMAND_OUTPUT_LIMIT_BYTES + 128)
    );
    let rendered = runtime::bounded_command_output(oversized.into_bytes());
    assert!(!rendered.contains('\x1b'));
    assert!(!rendered.contains('\x00'));
    assert!(rendered.contains("\n\t"));
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
    .failure("provision fixture");
    let diagnostic = failure.to_string();
    assert!(diagnostic.contains("provision fixture"));
    assert!(diagnostic.contains("exit=Some(7)"));
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
