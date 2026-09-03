use std::collections::BTreeMap;
use std::time::Duration;

use testcontainers::core::{IntoContainerPort as _, WaitFor};
use testcontainers::{ContainerAsync, CopyTargetOptions, GenericImage, ImageExt as _};
use testcontainers_modules::postgres::Postgres;

use super::{
    NetworkAttachment, Result, attach_network, copied_tls_image, environment_snapshot,
    non_empty_external_value, process_external_value, runtime, tls_material,
};

const PG_PORT: u16 = 5432;
const PG_DB: &str = "rss_test";
const PG_USER: &str = "postgres";
const PG_PASSWORD: &str = "postgres";

/// An external PostgreSQL endpoint cannot satisfy a migration or owner-SQL test.
#[derive(Debug, thiserror::Error)]
#[error("OwnedPostgresRequired: this test performs migration or owner-level SQL")]
pub struct OwnedPostgresRequired;

#[derive(Clone, Debug)]
pub(super) struct PgEndpoint {
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) database: String,
}

pub(super) fn postgres_external_endpoint_from_lookup<F>(lookup: F) -> Result<Option<PgEndpoint>>
where
    F: Fn(&str) -> Option<String>,
{
    if non_empty_external_value(&lookup, "RSS_TEST_ALLOW_EXTERNAL_POSTGRES")?.is_none() {
        return Ok(None);
    }

    const PG_KEYS: &[&str] = &["PGHOST", "PGPORT", "PGDATABASE"];
    let values: BTreeMap<&str, Option<String>> = PG_KEYS
        .iter()
        .copied()
        .map(|key| (key, lookup(key).filter(|value| !value.is_empty())))
        .collect();
    let missing: Vec<&str> = values
        .iter()
        .filter_map(|(key, value)| value.is_none().then_some(*key))
        .collect();
    if !missing.is_empty() {
        return Err(anyhow::anyhow!(
            "RSS_TEST_ALLOW_EXTERNAL_POSTGRES 已设，但缺少或为空的 PG endpoint env：{}",
            missing.join(", ")
        ));
    }
    let required = |key| {
        values
            .get(key)
            .and_then(Option::as_deref)
            .ok_or_else(|| anyhow::anyhow!("external postgres 缺少 {key}"))
    };
    let port_str = required("PGPORT")?;
    let port = port_str
        .parse()
        .map_err(|_| anyhow::anyhow!("PGPORT='{port_str}' 不是合法 u16 端口"))?;
    let database = required("PGDATABASE")?;
    if !strict_test_db_name(database) {
        return Err(anyhow::anyhow!(
            "PGDATABASE='{database}' 须以 '_test' 结尾或精确等于 'test'（严格库名校验，防破坏性 DDL 误打生产库）"
        ));
    }
    Ok(Some(PgEndpoint {
        host: required("PGHOST")?.to_string(),
        port,
        database: database.to_string(),
    }))
}

/// postgres 连接参数（与 adapters/postgres `config_from_env` 同形）。
/// password 字段 Debug 输出脱敏（输出 `<redacted>`），防日志泄露凭证。
#[derive(Clone)]
pub struct PgConnParams {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub password: String,
}

/// Requested PostgreSQL application login for an integration fixture.
#[derive(Clone, Copy)]
pub struct PgAppRoleSpec<'a> {
    role: &'a str,
    password: &'a str,
}

impl<'a> PgAppRoleSpec<'a> {
    /// Binds a pre-provisioned application role to its test credential.
    pub const fn new(role: &'a str, password: &'a str) -> Self {
        Self { role, password }
    }
}

/// Verified application-role connection returned by a fixture.
#[derive(Clone, Debug)]
pub struct PgAppRole {
    pub(super) params: PgConnParams,
}

impl PgAppRole {
    /// Connection parameters carrying only this least-privilege application identity.
    pub fn params(&self) -> &PgConnParams {
        &self.params
    }
}

pub(super) async fn apply_owned_app_roles(
    options: sqlx::postgres::PgConnectOptions,
    logins: &[PgAppRoleSpec<'_>],
) -> Result<()> {
    use sqlx::postgres::PgPoolOptions;

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(options)
        .await?;
    let mut tx = pool.begin().await?;

    let mut ordered = logins.to_vec();
    ordered.sort_unstable_by_key(|login| login.role);
    for login in ordered {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(login.role)
            .execute(&mut *tx)
            .await?;
        let ddl: String = sqlx::query_scalar(
            r#"
            SELECT CASE
                WHEN EXISTS (SELECT FROM pg_roles WHERE rolname = $1)
                    THEN format('ALTER ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT', $1, $2)
                ELSE format('CREATE ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT', $1, $2)
            END
            "#,
        )
        .bind(login.role)
        .bind(login.password)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query(&ddl).execute(&mut *tx).await?;
    }

    tx.commit().await?;
    pool.close().await;
    Ok(())
}

pub(super) fn role_params(endpoint: &PgEndpoint, spec: PgAppRoleSpec<'_>) -> PgConnParams {
    PgConnParams {
        host: endpoint.host.clone(),
        port: endpoint.port,
        database: endpoint.database.clone(),
        username: spec.role.to_owned(),
        password: spec.password.to_owned(),
    }
}

pub(super) fn connect_options(
    params: &PgConnParams,
    ssl_mode: sqlx::postgres::PgSslMode,
) -> sqlx::postgres::PgConnectOptions {
    sqlx::postgres::PgConnectOptions::new()
        .host(&params.host)
        .port(params.port)
        .database(&params.database)
        .username(&params.username)
        .password(&params.password)
        .ssl_mode(ssl_mode)
}

#[derive(sqlx::FromRow)]
struct ExternalRolePosture {
    current_user: String,
    can_login: bool,
    superuser: bool,
    create_db: bool,
    create_role: bool,
    replication: bool,
    bypass_rls: bool,
    inherit: bool,
    credential_valid: bool,
    membership_isolated: bool,
}

impl ExternalRolePosture {
    fn violations(&self, expected_user: &str) -> Vec<&'static str> {
        [
            (self.current_user != expected_user, "CURRENT_USER"),
            (!self.can_login, "LOGIN"),
            (self.superuser, "NOSUPERUSER"),
            (self.create_db, "NOCREATEDB"),
            (self.create_role, "NOCREATEROLE"),
            (self.replication, "NOREPLICATION"),
            (self.bypass_rls, "NOBYPASSRLS"),
            (self.inherit, "NOINHERIT"),
            (!self.credential_valid, "CREDENTIAL_VALID"),
            (!self.membership_isolated, "NO_ROLE_MEMBERSHIPS"),
        ]
        .into_iter()
        .filter_map(|(violated, label)| violated.then_some(label))
        .collect()
    }
}

pub(super) async fn verify_external_app_role(params: &PgConnParams) -> Result<()> {
    use sqlx::postgres::PgPoolOptions;

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(connect_options(params, sqlx::postgres::PgSslMode::Prefer))
        .await?;
    let posture: Option<ExternalRolePosture> = sqlx::query_as(
        "SELECT current_user, role.rolcanlogin AS can_login, role.rolsuper AS superuser, \
         role.rolcreatedb AS create_db, role.rolcreaterole AS create_role, \
         role.rolreplication AS replication, role.rolbypassrls AS bypass_rls, \
         role.rolinherit AS inherit, \
         role.rolvaliduntil IS NULL OR role.rolvaliduntil > clock_timestamp() AS credential_valid, \
         NOT EXISTS (SELECT 1 FROM pg_auth_members AS membership \
                     WHERE membership.roleid = role.oid OR membership.member = role.oid) \
             AS membership_isolated \
         FROM pg_roles AS role WHERE role.rolname = current_user",
    )
    .fetch_optional(&pool)
    .await?;
    pool.close().await;
    let Some(posture) = posture else {
        return Err(anyhow::anyhow!(
            "external postgres app role posture is unavailable"
        ));
    };
    let violations = posture.violations(&params.username);
    if !violations.is_empty() {
        return Err(anyhow::anyhow!(
            "external postgres app role '{}' violates fixed posture: {}",
            params.username,
            violations.join(", ")
        ));
    }

    let alternate_password = if params.password == "rss-testkit-invalid-credential-a" {
        "rss-testkit-invalid-credential-b"
    } else {
        "rss-testkit-invalid-credential-a"
    };
    let mut invalid = params.clone();
    invalid.password = alternate_password.to_owned();
    if let Ok(invalid_pool) = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(connect_options(&invalid, sqlx::postgres::PgSslMode::Prefer))
        .await
    {
        invalid_pool.close().await;
        return Err(anyhow::anyhow!(
            "external postgres app role authentication does not require the supplied credential"
        ));
    }
    Ok(())
}

pub(super) async fn resolve_owned_roles<const N: usize>(
    endpoint: &PgEndpoint,
    specs: [PgAppRoleSpec<'_>; N],
    options: sqlx::postgres::PgConnectOptions,
) -> Result<[PgAppRole; N]> {
    apply_owned_app_roles(options, &specs).await?;
    let roles: Vec<PgAppRole> = specs
        .into_iter()
        .map(|spec| PgAppRole {
            params: role_params(endpoint, spec),
        })
        .collect();
    roles
        .try_into()
        .map_err(|_| anyhow::anyhow!("postgres role resolver cardinality mismatch"))
}

impl std::fmt::Debug for PgConnParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgConnParams")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("database", &self.database)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

// ── postgres ────────────────────────────────────────────────────────────────

/// Fixture-owned PostgreSQL cluster. Only this variant exposes owner coordinates.
pub struct OwnedPgFixture {
    pub(super) _container: Box<ContainerAsync<Postgres>>,
    pub(super) endpoint: PgEndpoint,
    pub(super) owner: PgConnParams,
}

impl OwnedPgFixture {
    /// Owner coordinates for migration and explicitly destructive provider tests.
    pub fn owner_params(&self) -> &PgConnParams {
        &self.owner
    }

    /// Provisions roles inside this fixture-owned cluster.
    pub async fn resolve_app_roles<const N: usize>(
        &self,
        specs: [PgAppRoleSpec<'_>; N],
    ) -> Result<[PgAppRole; N]> {
        let options = connect_options(&self.owner, sqlx::postgres::PgSslMode::Prefer);
        resolve_owned_roles(&self.endpoint, specs, options).await
    }
}

/// Pre-provisioned external PostgreSQL endpoint. It deliberately contains no owner credential.
pub struct ExternalPgFixture {
    pub(super) endpoint: PgEndpoint,
}

/// Closed PostgreSQL fixture ownership proof.
pub enum PgFixture {
    Owned(OwnedPgFixture),
    External(ExternalPgFixture),
}

impl PgFixture {
    /// Consumes the closed fixture and returns the owned proof before any SQL can be opened.
    pub fn into_owned(self) -> std::result::Result<OwnedPgFixture, OwnedPostgresRequired> {
        match self {
            Self::Owned(owned) => Ok(owned),
            Self::External(_) => Err(OwnedPostgresRequired),
        }
    }

    /// Resolves application roles without ever granting external role-mutation authority.
    pub async fn resolve_app_roles<const N: usize>(
        &self,
        specs: [PgAppRoleSpec<'_>; N],
    ) -> Result<[PgAppRole; N]> {
        match self {
            Self::Owned(owned) => {
                let options = connect_options(&owned.owner, sqlx::postgres::PgSslMode::Prefer);
                resolve_owned_roles(&owned.endpoint, specs, options).await
            }
            Self::External(external) => {
                let mut roles = Vec::with_capacity(N);
                for spec in specs {
                    let params = role_params(&external.endpoint, spec);
                    verify_external_app_role(&params).await?;
                    roles.push(PgAppRole { params });
                }
                roles
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("postgres role resolver cardinality mismatch"))
            }
        }
    }
}

/// 严格库名校验：`db` 须以 `_test` 结尾或精确等于 `"test"`。
///
/// 设计意图（fail-closed）：防止 `prod_contest`（substring 命中）之类名称绕过校验；
/// 合法测试库名举例：`rss_test`、`x_test`、`test`。
/// 拒绝举例：`prod_contest`、`testdb`、`test_prod`。
pub(super) fn strict_test_db_name(db: &str) -> bool {
    db == "test" || db.ends_with("_test")
}

/// **默认起容器（fail-closed 安全语义）**。
///
/// 仅当 `RSS_TEST_ALLOW_EXTERNAL_POSTGRES` 存在（非空）时走外部 PG 路径，
/// 防止破坏性 DDL 误打外部库；否则一律 self-provision 容器。
///
/// 外部路径校验：
/// - 只读 endpoint 三元组 `PGHOST`/`PGPORT`/`PGDATABASE`，不读取 external owner 凭据；
/// - `PGPORT` 须为合法 u16；
/// - `PGDATABASE` 须 `ends_with("_test")` 或 `== "test"`（严格库名，单源在 testkit）。
///
/// 容器路径 db 名恒为 `rss_test`（满足严格库名规则）。
///
/// # Example
///
/// ```ignore
/// let pg = testkit::env_or_postgres().await?;
/// let [app] = pg.resolve_app_roles([PgAppRoleSpec::new("rss_app", "secret")]).await?;
/// ```
pub async fn env_or_postgres() -> Result<PgFixture> {
    if process_external_value("RSS_TEST_ALLOW_EXTERNAL_POSTGRES")?.is_some() {
        const PG_KEYS: &[&str] = &["PGHOST", "PGPORT", "PGDATABASE"];
        let values = environment_snapshot(PG_KEYS)?;
        let endpoint = postgres_external_endpoint_from_lookup(|key| {
            if key == "RSS_TEST_ALLOW_EXTERNAL_POSTGRES" {
                Some("true".to_string())
            } else {
                values.get(key).cloned()
            }
        })?
        .ok_or_else(|| anyhow::anyhow!("external postgres opt-in 丢失"))?;
        return Ok(PgFixture::External(ExternalPgFixture { endpoint }));
    }
    Ok(PgFixture::Owned(start_owned_postgres().await?))
}

/// Starts a hermetic PostgreSQL container and returns its non-forgeable owned proof.
pub async fn owned_postgres() -> Result<OwnedPgFixture> {
    if process_external_value("RSS_TEST_ALLOW_EXTERNAL_POSTGRES")?.is_some() {
        return Err(OwnedPostgresRequired.into());
    }
    start_owned_postgres().await
}

async fn start_owned_postgres() -> Result<OwnedPgFixture> {
    // 默认：self-provision 容器（fail-closed）。
    // PG 镜像 tag 固定 16-alpine：迁移刻意要求 PG 13+ core（`0003_create_outbox.sql` 用 `gen_random_uuid()`
    // 无 pgcrypto 扩展）；testcontainers-modules `Postgres::default()` 的默认 tag < 13 缺该内置函数，会令
    // run_migrations 在 0002 处 42883 失败。固定 13+ 让容器与迁移的 PG 版本前提对齐（修 latent 测试 harness
    // 漂移：集成 lane opt-in 不入 CI，此前未暴露）。
    let image = Postgres::default()
        .with_db_name(PG_DB)
        .with_user(PG_USER)
        .with_password(PG_PASSWORD)
        .with_tag("16-alpine");
    let container = runtime::start(image).await?;
    let host = container.get_host().await?.to_string();
    let port = container.get_host_port_ipv4(PG_PORT).await?;
    let endpoint = PgEndpoint {
        host: host.clone(),
        port,
        database: PG_DB.to_string(),
    };
    Ok(OwnedPgFixture {
        _container: Box::new(container),
        owner: PgConnParams {
            host,
            port,
            database: PG_DB.to_string(),
            username: PG_USER.to_string(),
            password: PG_PASSWORD.to_string(),
        },
        endpoint,
    })
}

/// Hermetic PostgreSQL TLS fixture. Only host-side coordinates and trust material are exposed.
pub struct PgTlsFixture {
    pub(super) _container: Box<ContainerAsync<GenericImage>>,
    pub(super) params: PgConnParams,
    pub(super) ca_pem: String,
    pub(super) wrong_ca_pem: String,
}

impl PgTlsFixture {
    pub fn params(&self) -> &PgConnParams {
        &self.params
    }

    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    pub fn wrong_ca_pem(&self) -> &str {
        &self.wrong_ca_pem
    }

    /// Provisions fixture-owned application roles over the private-CA connection.
    pub async fn resolve_app_roles<const N: usize>(
        &self,
        specs: [PgAppRoleSpec<'_>; N],
    ) -> Result<[PgAppRole; N]> {
        let endpoint = PgEndpoint {
            host: self.params.host.clone(),
            port: self.params.port,
            database: self.params.database.clone(),
        };
        let options = connect_options(&self.params, sqlx::postgres::PgSslMode::VerifyFull)
            .ssl_root_cert_from_pem(self.ca_pem.as_bytes().to_vec());
        resolve_owned_roles(&endpoint, specs, options).await
    }
}

/// Starts PostgreSQL 16 with TLS required for every TCP client.
pub async fn postgres_tls(attachment: NetworkAttachment<'_>) -> Result<PgTlsFixture> {
    let material = tls_material(attachment.dns_name)?;
    let startup = b"#!/bin/sh\nset -eu\nchown postgres:postgres /rss-tls/server-key.pem\nchmod 600 /rss-tls/server-key.pem\nexec /usr/local/bin/docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/rss-tls/server.pem -c ssl_key_file=/rss-tls/server-key.pem -c ssl_min_protocol_version=TLSv1.2\n";
    let require_tls = b"#!/bin/sh\nset -eu\nsed -i -E 's/^host([[:space:]])/hostssl\\1/' \"$PGDATA/pg_hba.conf\"\n";
    let image = GenericImage::new("postgres", "16-alpine")
        .with_exposed_port(PG_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ));
    let request = attach_network(
        copied_tls_image(image, &material)
            .with_env_var("POSTGRES_DB", PG_DB)
            .with_env_var("POSTGRES_USER", PG_USER)
            .with_env_var("POSTGRES_PASSWORD", PG_PASSWORD)
            .with_copy_to(
                CopyTargetOptions::new("/rss-tls/start-postgres.sh").with_mode(0o755),
                startup.to_vec(),
            )
            .with_copy_to(
                CopyTargetOptions::new("/docker-entrypoint-initdb.d/00-require-tls.sh")
                    .with_mode(0o755),
                require_tls.to_vec(),
            )
            .with_cmd(["/rss-tls/start-postgres.sh"]),
        attachment,
    )?;
    let container = runtime::start(request).await?;
    let host = container.get_host().await?.to_string();
    let port = container.get_host_port_ipv4(PG_PORT).await?;
    Ok(PgTlsFixture {
        _container: Box::new(container),
        params: PgConnParams {
            host,
            port,
            database: PG_DB.to_owned(),
            username: PG_USER.to_owned(),
            password: PG_PASSWORD.to_owned(),
        },
        ca_pem: material.ca_pem,
        wrong_ca_pem: material.wrong_ca_pem,
    })
}
