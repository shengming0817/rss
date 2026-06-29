//! 真容器 fixtures（testcontainers 0.27 + testcontainers-modules 0.15）。
//!
//! `env_or_*` resolver 回传**不透明 fixture guard**（`PgFixture` / `RedisFixture` / `RabbitFixture`）：
//! **默认起容器**（fail-closed 安全语义）；仅当满足显式 opt-in 条件时走外部路径：
//! - postgres：`RSS_TEST_ALLOW_EXTERNAL_POSTGRES` 存在（非空）+ 5 元组 `PGHOST/PGPORT/PGDATABASE/PGUSER/PGPASSWORD` 全在；
//! - redis：`REDIS_TEST_URL` 存在；
//! - rabbitmq：`RSS_AMQP_TEST_URL` 存在（须为 base broker URL，无非空 vhost 段）。
//!
//! **严格库名（单源在 testkit）**：外部 postgres 路径的 `PGDATABASE` 须 `ends_with("_test")` 或 `== "test"`
//! 才被接受；不满足直接报错（防 `prod_contest` 这类 substring 误命中）。
//! **guard 须绑定到测试作用域结束**——其 `Drop` 停容器（提前 drop 后续连接失败）。
//! 不透明 guard 把 `testcontainers` 类型挡在消费方签名外（消费方只 name `testkit::{*Fixture,FixtureError}`）。
//!
//! 测试 fixture 不引 tracing——进度 / 失败经 testcontainers 自身日志 + fail-loud 错误冒泡可见
//! （reason: 引入 tracing 会拉 tracing subscriber 依赖、增加测试体初始化负担；container 日志由
//! testcontainers log_driver 自管，错误路径经 FixtureError 直接冒泡到测试输出）。
//!
//! ref: testcontainers/testcontainers-rs-modules-community modules/{postgres,redis,rabbitmq}

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::Duration;

use testcontainers::ContainerAsync;
use testcontainers::ImageExt;
use testcontainers::core::{CmdWaitFor, ExecCommand};
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::mosquitto::Mosquitto;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::rabbitmq::RabbitMq;
use testcontainers_modules::redis::{REDIS_PORT, Redis};

/// fixture 错误（容器起停 / 坐标解析 / env 解析）——dev/test 用，anyhow 以与任意测试返回类型组合。
pub type FixtureError = anyhow::Error;
type Result<T> = std::result::Result<T, FixtureError>;

/// 容器内固定端口（modules 镜像默认暴露端口）。
const PG_PORT: u16 = 5432;
const AMQP_PORT: u16 = 5672;
const MQTT_PORT: u16 = 1883;
/// 容器路径 postgres db 名：含 `test` 以满足 adapters/postgres 毁灭性-DDL 守卫。
const PG_DB: &str = "rss_test";
const PG_USER: &str = "postgres";
const PG_PASSWORD: &str = "postgres";

/// rabbitmqctl exec 有界重试（broker 起后 rabbitmqctl/epmd 短暂不可用窗口）。
const RABBITMQCTL_MAX_ATTEMPTS: u32 = 12;
const RABBITMQCTL_BACKOFF_MS: u64 = 500;

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

/// postgres fixture guard：持容器句柄（自起路径）到 `Drop` + 连接参数。**须绑定到测试结束**。
pub struct PgFixture {
    // 自起路径持句柄（Drop 停容器）；env 路径为 None。
    _container: Option<Box<ContainerAsync<Postgres>>>,
    params: PgConnParams,
}

impl PgFixture {
    /// postgres 连接参数。
    pub fn params(&self) -> &PgConnParams {
        &self.params
    }
}

/// 严格库名校验：`db` 须以 `_test` 结尾或精确等于 `"test"`。
///
/// 设计意图（fail-closed）：防止 `prod_contest`（substring 命中）之类名称绕过校验；
/// 合法测试库名举例：`rss_test`、`x_test`、`test`。
/// 拒绝举例：`prod_contest`、`testdb`、`test_prod`。
pub fn strict_test_db_name(db: &str) -> bool {
    db == "test" || db.ends_with("_test")
}

/// **默认起容器（fail-closed 安全语义）**。
///
/// 仅当 `RSS_TEST_ALLOW_EXTERNAL_POSTGRES` 存在（非空）时走外部 PG 路径，
/// 防止破坏性 DDL 误打外部库；否则一律 self-provision 容器。
///
/// 外部路径校验：
/// - 读全 5 元组 `PGHOST`/`PGPORT`/`PGDATABASE`/`PGUSER`/`PGPASSWORD`，缺哪个就在错误里列出缺失 key；
/// - `PGPORT` 须为合法 u16；
/// - `PGDATABASE` 须 `ends_with("_test")` 或 `== "test"`（严格库名，单源在 testkit）。
///
/// 容器路径 db 名恒为 `rss_test`（满足严格库名规则）。
///
/// # Example
///
/// ```ignore
/// let pg = testkit::env_or_postgres().await?;
/// // pg.params() 返回 PgConnParams { host, port, database, username, password }
/// ```
pub async fn env_or_postgres() -> Result<PgFixture> {
    if std::env::var_os("RSS_TEST_ALLOW_EXTERNAL_POSTGRES").is_some() {
        // 外部 PG 路径：读全 5 元组，缺哪个列出缺失 key（非裸 VarError）。
        const PG_KEYS: &[&str] = &["PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD"];
        let missing: Vec<&str> = PG_KEYS
            .iter()
            .copied()
            .filter(|k| std::env::var_os(k).is_none())
            .collect();
        if !missing.is_empty() {
            return Err(anyhow::anyhow!(
                "RSS_TEST_ALLOW_EXTERNAL_POSTGRES 已设，但缺少以下 PG env：{}（须同时设全 5 元组）",
                missing.join(", ")
            ));
        }
        // 所有 key 均已确认存在，env::var 此时仅因 OsString 转 UTF-8 失败才出错（极罕见）。
        let host = std::env::var("PGHOST")?;
        let port_str = std::env::var("PGPORT")?;
        let port: u16 = port_str
            .parse()
            .map_err(|_| anyhow::anyhow!("PGPORT='{}' 不是合法 u16 端口", port_str))?;
        let database = std::env::var("PGDATABASE")?;
        if !strict_test_db_name(&database) {
            return Err(anyhow::anyhow!(
                "PGDATABASE='{}' 须以 '_test' 结尾或精确等于 'test'（严格库名校验，防破坏性 DDL 误打生产库）",
                database
            ));
        }
        let username = std::env::var("PGUSER")?;
        let password = std::env::var("PGPASSWORD")?;
        let params = PgConnParams {
            host,
            port,
            database,
            username,
            password,
        };
        return Ok(PgFixture {
            _container: None,
            params,
        });
    }
    // 默认：self-provision 容器（fail-closed）。
    // PG 镜像 tag 固定 16-alpine：迁移刻意要求 PG 13+ core（`0003_create_outbox.sql` 用 `gen_random_uuid()`
    // 无 pgcrypto 扩展）；testcontainers-modules `Postgres::default()` 的默认 tag < 13 缺该内置函数，会令
    // run_migrations 在 0002 处 42883 失败。固定 13+ 让容器与迁移的 PG 版本前提对齐（修 latent 测试 harness
    // 漂移：集成 lane opt-in 不入 CI，此前未暴露）。
    let container = Postgres::default()
        .with_db_name(PG_DB)
        .with_user(PG_USER)
        .with_password(PG_PASSWORD)
        .with_tag("16-alpine")
        .start()
        .await?;
    let host = container.get_host().await?.to_string();
    let port = container.get_host_port_ipv4(PG_PORT).await?;
    Ok(PgFixture {
        _container: Some(Box::new(container)),
        params: PgConnParams {
            host,
            port,
            database: PG_DB.to_string(),
            username: PG_USER.to_string(),
            password: PG_PASSWORD.to_string(),
        },
    })
}

// ── redis ─────────────────────────────────────────────────────────────────-

/// redis fixture guard：持容器句柄（自起路径）到 `Drop` + `redis://` URL。**须绑定到测试结束**。
pub struct RedisFixture {
    _container: Option<Box<ContainerAsync<Redis>>>,
    url: String,
}

impl RedisFixture {
    /// `redis://host:port` 连接 URL。
    pub fn url(&self) -> &str {
        &self.url
    }
}

/// `REDIS_TEST_URL` 在 → env 路径；否则 self-provision 容器。
///
/// # Example
///
/// ```ignore
/// let redis = testkit::env_or_redis().await?;
/// // redis.url() 返回 "redis://host:port"
/// ```
pub async fn env_or_redis() -> Result<RedisFixture> {
    if let Ok(url) = std::env::var("REDIS_TEST_URL") {
        return Ok(RedisFixture {
            _container: None,
            url,
        });
    }
    let container = Redis::default().start().await?;
    let host = container.get_host().await?;
    let port = container.get_host_port_ipv4(REDIS_PORT).await?;
    let url = format!("redis://{host}:{port}");
    Ok(RedisFixture {
        _container: Some(Box::new(container)),
        url,
    })
}

// ── rabbitmq ─────────────────────────────────────────────────────────────---

/// rabbitmq fixture guard：持容器句柄（自起路径）到 `Drop`。**须绑定到测试结束**。
/// per-domain vhost 经 [`RabbitFixture::vhost_url`] 按需创建（同容器可建多 vhost，供跨 vhost 隔离测试）。
pub struct RabbitFixture {
    inner: RabbitInner,
}

enum RabbitInner {
    /// 自起容器：持句柄；`vhost_url` 经 rabbitmqctl 在该 broker 建 vhost。
    Container {
        container: Box<ContainerAsync<RabbitMq>>,
        host: String,
        port: u16,
        /// 已建 vhost 缓存（幂等：同一 vhost 多次 `vhost_url` 不重复调 rabbitmqctl）。
        created: Mutex<HashSet<String>>,
    },
    /// env 长存 broker：base url（不含 vhost）；`vhost_url` 直接拼（caller 须已建该 vhost）。
    Env { base: String },
}

impl RabbitFixture {
    /// 取 `vhost` 的连接 URL `amqp://guest:guest@host:port/<vhost>`。自起路径会先在 broker 建该 vhost
    /// （+ 给 guest 授权）；env 路径假定长存 broker 已建该 vhost。`vhost` 须 URL-safe（字母数字 / `_` / `-`）。
    /// 同一 guard 多次调用不同 `vhost` → 同容器多 vhost（per-domain 隔离测试用）。
    /// 同一 `vhost` 多次调用幂等——不重复调 rabbitmqctl（已建则直接返回 URL）。
    pub async fn vhost_url(&self, vhost: &str) -> Result<String> {
        // URL-safe 校验：仅字母数字 / _ / -，防注入 rabbitmqctl 参数。
        if !vhost
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '_' | '-'))
        {
            return Err(anyhow::anyhow!(
                "vhost '{vhost}' 含不安全字符，须字母数字/_/-"
            ));
        }
        match &self.inner {
            RabbitInner::Container {
                container,
                host,
                port,
                created,
            } => {
                // 幂等：已建则跳过（reason: rabbitmqctl add_vhost 重入会报 already exists；
                // HashSet 缓存避免重复调用，同时省重试开销）。
                let already = {
                    let guard = created
                        .lock()
                        .map_err(|e| anyhow::anyhow!("vhost cache mutex poisoned: {e}"))?;
                    guard.contains(vhost)
                };
                if !already {
                    create_vhost(container, vhost).await?;
                    created
                        .lock()
                        .map_err(|e| anyhow::anyhow!("vhost cache mutex poisoned: {e}"))?
                        .insert(vhost.to_string());
                }
                Ok(format!("amqp://guest:guest@{host}:{port}/{vhost}"))
            }
            RabbitInner::Env { base } => Ok(amqp_url_with_vhost(base, vhost)),
        }
    }
}

/// 校验 AMQP base broker URL（无非空 vhost 段）。
///
/// 合法：`amqp://user:pass@host:port`、`amqp://user:pass@host:port/`。
/// 拒绝：`amqp://host:5672/existing_vhost`（含非空 path/vhost 段）。
///
/// `RSS_AMQP_TEST_URL` 须为 base broker URL，vhost 由 testkit 拼接/预建。
fn validate_amqp_base_url(url: &str) -> Result<()> {
    // 去协议前缀后找第三个 `/`（host:port 后）；若 path 段非空则拒绝。
    // 简化解析：协议头 `amqp://` 后取第一个 `/` 即为 vhost 起点。
    let after_scheme = url
        .strip_prefix("amqp://")
        .or_else(|| url.strip_prefix("amqps://"))
        .ok_or_else(|| {
            anyhow::anyhow!("RSS_AMQP_TEST_URL 须以 amqp:// 或 amqps:// 开头，实际: {url}")
        })?;
    // `after_scheme` = `user:pass@host:port[/vhost]`；取第一个 `/` 后的内容为 vhost 段。
    if let Some(slash_pos) = after_scheme.find('/') {
        let vhost_part = &after_scheme[slash_pos + 1..];
        if !vhost_part.is_empty() {
            return Err(anyhow::anyhow!(
                "RSS_AMQP_TEST_URL='{}' 含非空 path/vhost 段 '{}'——须为 base broker URL（无 vhost），\
                 vhost 由 testkit 在测试用 fixture 中拼接/预建",
                url,
                vhost_part
            ));
        }
    }
    Ok(())
}

/// **默认起容器（fail-closed 安全语义）**。仅当 `RSS_AMQP_TEST_URL` 存在时走外部 broker 路径。
///
/// 外部路径：`RSS_AMQP_TEST_URL` 须为 **base broker URL（无 path/vhost 段）**，如
/// `amqp://user:pass@host:port` 或 `amqp://user:pass@host:port/`；含非空 vhost 段则报错。
/// vhost 由 testkit 在 `vhost_url()` 中拼接；env 路径假定 broker 已预建该 vhost（caller 负责）。
///
/// # Example
///
/// ```ignore
/// let rabbit = testkit::env_or_rabbitmq().await?;
/// let url = rabbit.vhost_url("rss_identity").await?;
/// // url = "amqp://guest:guest@host:port/rss_identity"
/// ```
pub async fn env_or_rabbitmq() -> Result<RabbitFixture> {
    if let Ok(base) = std::env::var("RSS_AMQP_TEST_URL") {
        validate_amqp_base_url(&base)?;
        return Ok(RabbitFixture {
            inner: RabbitInner::Env { base },
        });
    }
    let container = RabbitMq::default().start().await?;
    let host = container.get_host().await?.to_string();
    let port = container.get_host_port_ipv4(AMQP_PORT).await?;
    Ok(RabbitFixture {
        inner: RabbitInner::Container {
            container: Box::new(container),
            host,
            port,
            created: Mutex::new(HashSet::new()),
        },
    })
}

/// 在运行中的 rabbitmq 容器内建 `vhost` + 给默认 `guest` 用户全权限（per-domain 隔离）。
async fn create_vhost(container: &ContainerAsync<RabbitMq>, vhost: &str) -> Result<()> {
    run_rabbitmqctl(container, &["await_startup"]).await?;
    run_rabbitmqctl(container, &["add_vhost", vhost]).await?;
    run_rabbitmqctl(
        container,
        &["set_permissions", "-p", vhost, "guest", ".*", ".*", ".*"],
    )
    .await?;
    Ok(())
}

/// 给定 base broker URL（`amqp://user:pass@host:port`）+ vhost 拼出完整 URL（env 路径用）。
fn amqp_url_with_vhost(base: &str, vhost: &str) -> String {
    format!("{}/{vhost}", base.trim_end_matches('/'))
}

/// 容器内执行 `rabbitmqctl <args>`，有界重试（broker 起后 rabbitmqctl 短暂不可用）。
/// 末次 attempt 失败后不再 sleep（节省约 6s 空等）。
/// 错误消息含累计约等待时长以便诊断。
async fn run_rabbitmqctl(container: &ContainerAsync<RabbitMq>, args: &[&str]) -> Result<()> {
    let cmd: Vec<String> = std::iter::once("rabbitmqctl")
        .chain(args.iter().copied())
        .map(str::to_string)
        .collect();
    let mut last: Option<i64> = None;
    for attempt in 0..RABBITMQCTL_MAX_ATTEMPTS {
        let res = container
            .exec(ExecCommand::new(cmd.clone()).with_cmd_ready_condition(CmdWaitFor::exit_code(0)))
            .await?;
        let code = res.exit_code().await?;
        if code == Some(0) {
            return Ok(());
        }
        last = code;
        // 末次失败不再 sleep，直接报错（省末次空等约 6s）。
        if attempt + 1 < RABBITMQCTL_MAX_ATTEMPTS {
            tokio::time::sleep(Duration::from_millis(
                RABBITMQCTL_BACKOFF_MS * u64::from(attempt + 1),
            ))
            .await;
        }
    }
    let total_wait_secs: u64 = (0..RABBITMQCTL_MAX_ATTEMPTS - 1)
        .map(|i| RABBITMQCTL_BACKOFF_MS * u64::from(i + 1))
        .sum::<u64>()
        / 1000;
    Err(anyhow::anyhow!(
        "rabbitmqctl {args:?} 未在 {RABBITMQCTL_MAX_ATTEMPTS} 次（累计约 {total_wait_secs}s）内成功（末次 exit={last:?}）"
    ))
}

// ── mqtt（mosquitto）─────────────────────────────────────────────────────────

/// mqtt fixture guard：持容器句柄（自起路径）到 `Drop` + `mqtt://` base URL。**须绑定到测试结束**。
///
/// MQTT **无 vhost**（不同于 rabbitmq）——跨域隔离经 per-domain broker 凭据 + broker 侧 ACL（operator
/// provision），非命名空间段。故 fixture 只回 base broker URL（无 `vhost_url`），比 [`RabbitFixture`] 简单。
pub struct MqttFixture {
    _container: Option<Box<ContainerAsync<Mosquitto>>>,
    url: String,
}

impl MqttFixture {
    /// `mqtt://host:port` 连接 URL（明文；mosquitto fixture 镜像 anonymous，无凭据段）。
    pub fn url(&self) -> &str {
        &self.url
    }
}

/// 校验 MQTT test URL scheme（须 `mqtt://`——明文，adapter v1 仅支持明文；`mqtts://` / 非 mqtt 协议拒绝）。
///
/// 对齐 [`validate_amqp_base_url`] 的对称 scheme 校验：防 `RSS_MQTT_TEST_URL` 误设非 mqtt 协议在集成测试
/// 中产生难诊断的连接错误。
fn validate_mqtt_url(url: &str) -> Result<()> {
    if url.strip_prefix("mqtt://").is_none() {
        return Err(anyhow::anyhow!(
            "RSS_MQTT_TEST_URL 须以 mqtt:// 开头（adapter v1 仅明文 MQTT），实际: {url}"
        ));
    }
    Ok(())
}

/// **默认起容器（fail-closed 安全语义）**。仅当 `RSS_MQTT_TEST_URL` 存在时走外部 broker 路径。
///
/// 自起路径用 `testcontainers_modules::mosquitto::Mosquitto`（`eclipse-mosquitto`，anonymous，1883）。
/// 外部路径：`RSS_MQTT_TEST_URL` 须为 `mqtt://` base URL（caller 负责 broker 可达 / 鉴权）。
///
/// # Example
///
/// ```ignore
/// let mqtt = testkit::env_or_mosquitto().await?;
/// // mqtt.url() 返回 "mqtt://host:port"
/// ```
pub async fn env_or_mosquitto() -> Result<MqttFixture> {
    if let Ok(url) = std::env::var("RSS_MQTT_TEST_URL") {
        validate_mqtt_url(&url)?;
        return Ok(MqttFixture {
            _container: None,
            url,
        });
    }
    let container = Mosquitto::default().start().await?;
    let host = container.get_host().await?.to_string();
    let port = container.get_host_port_ipv4(MQTT_PORT).await?;
    let url = format!("mqtt://{host}:{port}");
    Ok(MqttFixture {
        _container: Some(Box::new(container)),
        url,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// validate_mqtt_url：mqtt:// 通过；非 mqtt 协议（http/mqtts）拒绝。
    #[test]
    fn validate_mqtt_url_table() {
        assert!(validate_mqtt_url("mqtt://h:1883").is_ok(), "mqtt:// 须通");
        assert!(
            validate_mqtt_url("mqtt://user:pass@h:1883").is_ok(),
            "含凭据 mqtt:// 须通"
        );
        assert!(
            validate_mqtt_url("mqtts://h:8883").is_err(),
            "mqtts:// 须拒（adapter v1 仅明文）"
        );
        assert!(
            validate_mqtt_url("http://h:1883").is_err(),
            "非 mqtt 协议须拒"
        );
    }

    /// validate_amqp_base_url：base URL（无 vhost）通过；含非空 vhost 段报错。
    #[test]
    fn validate_amqp_base_url_table() {
        // 通：无 path 段
        assert!(
            validate_amqp_base_url("amqp://guest:guest@h:5672").is_ok(),
            "无 path 须通"
        );
        // 通：尾部空 path（/）
        assert!(
            validate_amqp_base_url("amqp://guest:guest@h:5672/").is_ok(),
            "尾 / 须通"
        );
        // 拒：含非空 vhost 段
        assert!(
            validate_amqp_base_url("amqp://guest:guest@h:5672/existing_vhost").is_err(),
            "含 vhost 须拒"
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
}
