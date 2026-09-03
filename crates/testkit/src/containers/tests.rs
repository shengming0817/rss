#![allow(clippy::expect_used, unused_imports)]
// reason: test setup and assertions use expect/expect_err to retain precise failure context.

use super::minio::*;
use super::postgres::*;
use super::rabbitmq::*;
use super::redis::*;
use super::vault::*;
use super::*;

use std::collections::HashMap;

fn lookup<'a>(values: &'a [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> + 'a {
    move |key| {
        values
            .iter()
            .find_map(|(candidate, value)| (*candidate == key).then(|| (*value).to_string()))
    }
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
