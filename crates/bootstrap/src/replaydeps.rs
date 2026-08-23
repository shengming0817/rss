//! replaydeps —— topology-gated 幂等 claimer 选型（单源策略，零 adapter 依赖）。
//!
//! 组合根（`bins/server` / `journeys` / 未来 `examples`）经 [`resolve`] 按 [`Topology`] 单源选型
//! 幂等去重 claimer：demo 拓扑用进程内 in-mem claimer，durable 拓扑用共享 Redis claimer。
//!
//! # 为什么 resolver 返回**决策**而非**构造好的 adapter**
//!
//! `bootstrap` 是服务层 crate，`deny.toml`（`memory` wrappers=[journeys,xtask]）+
//! `cargo xtask layer-deps` + cargo 依赖图三道门**禁止 bootstrap 依赖 adapters**。故本 resolver 是
//! **纯策略函数**：做拓扑选型 + fail-closed 校验 + 凭据 redaction，返回已校验的 [`ResolvedIdempotency`]
//! 决策；组合根 `match` 该决策再构造具体 adapter，并在**组合根层**持有 in-mem sealing。
//!
//! sealing 的实际归属与强度（主守卫是生产侧）：
//! - 生产 bin（`bins/server` / `bins/rss`）经 cargo-deny **连 `memory` 都依赖不到** ⇒ in-mem claimer
//!   类型层不可命名（**Hard**，比「bootstrap 内 sealing」更强；这是 in-mem 生产不可达的主守卫）。
//! - dev root（`journeys` / `examples`）合法依赖 `memory`，in-mem 仅经 `match
//!   ResolvedIdempotency::Demo` 臂构造——**决策绑定纪律（Medium）**：`match` 把构造收束到已校验决策，
//!   但 dev root 仍能直接绕过（类型层未封闭，dev-only 可接受）；非编译期 Hard。
//!
//! INVARIANT: TOPO-FAILCLOSED-01 { level = "Medium", exec = "manual/opt-in", source = "code" }—— durable 缺 Redis URL ⇒ [`resolve`] 返 `Err`，组合根
//!   fail-fast 拒绝启动，**绝不静默降级回 demo/in-mem**（`Result` + bootstrap fail-fast，Medium；
//!   类型层强化：`Durable` 路径无「降级回 Demo」可表达变体，唯一非 `Err` 输出是带 redis_url 的
//!   `Durable`）。
//! INVARIANT: TOPO-INMEM-SEAL-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }—— in-mem claimer **生产**不可达（生产 bin cargo-deny **Hard**，
//!   主守卫）；dev root 经决策 `match` 收束（Medium 纪律，非编译期封闭）。落地在组合根，非本 crate
//!   （bootstrap 命名不到 in-mem 类型）。
//!
//! 凭据 redaction（Medium）：Redis URL（含 `user:pass`）经 [`RedisUrl`] 收口，其 `Debug`/`Display`
//! 走 URL userinfo 抹除；原文仅 [`RedisUrl::expose`] 受控可达。错误 message 不含凭据 / PII
//! （[`IdempotencyResolveError::MissingRedisUrl`] 仅含 env 提示，安全可诊断）。
//!
//! 注：幂等 claimer 是**单一共享 Redis**（无 per-domain 隔离），故 `DurableShared` 与
//! `DurableIsolated` 两个 durable 变体都收敛为「需 redis url」——隔离语义留给 Redis key namespace
//! 设计，不在 claimer 选型层分叉。
//!
//! ref: `contracts/**/contract.toml`、`generated` 与 `crates/consistency`，topology-gated）

use crate::topology::Topology;

/// Redis URL（含 `user:pass`）——凭据 + scheme policy 收口 newtype。
///
/// `Debug` / `Display` 经 `secure::RedisEndpoint` 脱敏（凭据 non-leak，Medium）；
/// 原始 URL 仅 [`RedisUrl::expose`] 受控可达（命名示警，仅组合根交 Redis 客户端时调用）。
#[derive(Clone, PartialEq, Eq)]
pub struct RedisUrl(secure::RedisEndpoint);

impl RedisUrl {
    /// 由原始 URL 构造（含凭据），并按 transport security policy 校验 scheme。
    pub fn parse(
        url: impl Into<String>,
        policy: secure::PlaintextEndpointPolicy,
    ) -> Result<Self, secure::TransportEndpointError> {
        secure::RedisEndpoint::parse(url, policy).map(Self)
    }

    /// 暴露原始 URL（含凭据）——**仅组合根**交给 Redis 客户端连接时受控调用；命名示警，禁进日志。
    #[allow(clippy::disallowed_methods)]
    pub fn expose(&self) -> &str {
        self.0.expose()
    }
}

impl AsRef<secure::RedisEndpoint> for RedisUrl {
    fn as_ref(&self) -> &secure::RedisEndpoint {
        &self.0
    }
}

impl std::fmt::Debug for RedisUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RedisUrl({})", self.0)
    }
}

impl std::fmt::Display for RedisUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// replaydeps resolver 的 typed 配置。
///
/// 组合根读 env（`RSS_REDIS_URL`）后填入；[`resolve`] 是纯函数、不读 env、不 I/O（保持确定性可测）。
#[derive(Debug, Default)]
pub struct IdempotencyConfig {
    /// Redis URL（含凭据）。durable 拓扑必填，demo 拓扑忽略。
    redis_url: Option<RedisUrl>,
}

impl IdempotencyConfig {
    /// 由可选 Redis URL 构造。
    pub fn new(redis_url: Option<RedisUrl>) -> Self {
        Self { redis_url }
    }
}

/// 已校验的幂等选型决策。组合根 `match` 本枚举映射到具体 adapter
/// （`Demo` → in-mem claimer；`Durable` → Redis claimer）。bootstrap 自身不持 adapter 类型。
///
/// `#[non_exhaustive]`：加新 claimer 变体不破坏下游。
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResolvedIdempotency {
    /// demo 拓扑：组合根用进程内 in-mem claimer。
    Demo,
    /// durable 拓扑：组合根据此连接 Redis claimer（单一共享 Redis，无 per-domain 隔离）。
    Durable {
        /// 已校验的 Redis URL（组合根经 [`RedisUrl::expose`] 受控取原文）。
        redis_url: RedisUrl,
    },
}

/// 幂等选型失败（fail-closed 载体，INVARIANT TOPO-FAILCLOSED-01）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IdempotencyResolveError {
    /// durable 拓扑缺 Redis URL——**绝不**降级回 in-mem。
    #[error("durable idempotency claimer requires a redis url (set RSS_REDIS_URL)")]
    MissingRedisUrl,
}

/// topology-gated 幂等 claimer 选型（单源）。**纯函数**：不读 env、不做 I/O、不连 Redis。
///
/// - [`Topology::Demo`] → `Ok(`[`ResolvedIdempotency::Demo`]`)`。
/// - [`Topology::DurableShared`] | [`Topology::DurableIsolated`] → 需 Redis URL；
///   缺则 `Err(`[`IdempotencyResolveError::MissingRedisUrl`]`)`，**绝不**返回 `Demo`。
///
/// 注：幂等 claimer 是单一共享 Redis（无 per-domain 隔离），故两个 durable 变体都收敛为「需 redis」。
///
/// INVARIANT: TOPO-FAILCLOSED-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（见模块 rustdoc）。
pub fn resolve(
    topo: Topology,
    cfg: IdempotencyConfig,
) -> Result<ResolvedIdempotency, IdempotencyResolveError> {
    match topo {
        // reason: demo 拓扑无外部依赖，恒成立。
        Topology::Demo => Ok(ResolvedIdempotency::Demo),
        // 两个 durable 变体均需 Redis——幂等 claimer 是共享 Redis（无 per-domain 分叉）。
        Topology::DurableShared | Topology::DurableIsolated => cfg
            .redis_url
            .map(|u| ResolvedIdempotency::Durable { redis_url: u })
            .ok_or(IdempotencyResolveError::MissingRedisUrl),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        IdempotencyConfig, IdempotencyResolveError, RedisUrl, ResolvedIdempotency, resolve,
    };
    use crate::topology::Topology;

    const URL_WITH_CREDS: &str = "rediss://user:pass@host:6379/0";
    const URL_NO_CREDS: &str = "rediss://host:6379/0";

    #[allow(clippy::panic)]
    fn redis_url(url: &str) -> RedisUrl {
        match RedisUrl::parse(url, secure::PlaintextEndpointPolicy::Deny) {
            Ok(url) => url,
            Err(err) => panic!("valid rediss url: {err}"),
        }
    }

    // expose() 在 clippy.toml disallowed-methods（凭据出口仅组合根受控调用）；本测试是唯一 sanctioned
    // 验证点（确认 expose 返回原文），item-level carve-out。
    #[allow(clippy::disallowed_methods)]
    fn assert_expose_eq(url: &RedisUrl, expected: &str) {
        assert_eq!(url.expose(), expected);
    }

    // 测试断言取出 Durable 的 redis_url（碰到非 Durable 即失败）。item-level carve-out
    // （workspace lints §「测试模块 item-level #[allow] carve-out」）——confine 到此单一 helper。
    #[allow(clippy::unwrap_used, clippy::panic)]
    fn durable_url(got: Result<ResolvedIdempotency, IdempotencyResolveError>) -> RedisUrl {
        match got.unwrap() {
            ResolvedIdempotency::Durable { redis_url } => redis_url,
            other => panic!("expected Durable, got {other:?}"),
        }
    }

    #[test]
    fn demo_resolves_to_demo() {
        let got = resolve(Topology::Demo, IdempotencyConfig::default());
        assert!(matches!(got, Ok(ResolvedIdempotency::Demo)));
    }

    #[test]
    fn demo_with_redis_url_still_resolves_demo() {
        // demo 拓扑忽略 redis url（reason: demo 无外部依赖）。
        let cfg = IdempotencyConfig::new(Some(redis_url(URL_WITH_CREDS)));
        let got = resolve(Topology::Demo, cfg);
        assert!(matches!(got, Ok(ResolvedIdempotency::Demo)));
    }

    #[test]
    fn durable_shared_missing_redis_fails_closed() {
        // fail-closed：缺 redis url ⇒ 精确 MissingRedisUrl。类型层 `Durable` 路径无 `Ok(Demo)` 可表达
        // 变体，故「绝不静默降级回 demo/in-mem」由类型系统保证（TOPO-FAILCLOSED-01）。
        let got = resolve(Topology::DurableShared, IdempotencyConfig::default());
        assert!(matches!(got, Err(IdempotencyResolveError::MissingRedisUrl)));
    }

    #[test]
    fn durable_isolated_missing_redis_fails_closed() {
        let got = resolve(Topology::DurableIsolated, IdempotencyConfig::default());
        assert!(matches!(got, Err(IdempotencyResolveError::MissingRedisUrl)));
    }

    #[test]
    fn durable_shared_with_redis_url_resolves_durable() {
        // anti-silent-degrade 正例：配置齐备 ⇒ Durable，绝不是 Demo（RedisUrl PartialEq 比对，不经 expose）。
        let cfg = IdempotencyConfig::new(Some(redis_url(URL_WITH_CREDS)));
        let url = durable_url(resolve(Topology::DurableShared, cfg));
        assert_eq!(url, redis_url(URL_WITH_CREDS));
    }

    #[test]
    fn durable_isolated_with_redis_url_resolves_durable() {
        let cfg = IdempotencyConfig::new(Some(redis_url(URL_WITH_CREDS)));
        let url = durable_url(resolve(Topology::DurableIsolated, cfg));
        assert_eq!(url, redis_url(URL_WITH_CREDS));
    }

    #[test]
    fn redis_url_expose_returns_original() {
        // expose() 受控验证点：仍可取原文（组合根交 Redis 客户端用）。
        let url = redis_url(URL_WITH_CREDS);
        assert_expose_eq(&url, URL_WITH_CREDS);
    }

    #[test]
    fn credentials_not_in_redis_url_debug_or_display() {
        // Debug / Display 脱敏验证：含凭据 URL 渲染后不含 user/pass，含脱敏标记。
        let url = redis_url(URL_WITH_CREDS);
        let dbg = format!("{url:?}");
        let disp = format!("{url}");
        for rendered in [&dbg, &disp] {
            assert!(
                rendered.contains("<redacted>"),
                "expected redaction in {rendered}"
            );
            assert!(!rendered.contains("user"), "leaked user in {rendered}");
            assert!(!rendered.contains("pass"), "leaked password in {rendered}");
        }
    }

    #[test]
    fn redis_url_no_creds_debug_and_display_unchanged() {
        // 无凭据 URL：脱敏后原样（不误删 host 段）。
        let url = redis_url(URL_NO_CREDS);
        let dbg = format!("{url:?}");
        let disp = format!("{url}");
        assert!(dbg.contains("host"), "host missing from debug: {dbg}");
        assert!(disp.contains("host"), "host missing from display: {disp}");
    }

    #[test]
    fn missing_redis_url_message() {
        // 错误 message 含可操作提示（env 名）；不含凭据 / PII。
        let err = IdempotencyResolveError::MissingRedisUrl;
        assert_eq!(
            err.to_string(),
            "durable idempotency claimer requires a redis url (set RSS_REDIS_URL)"
        );
    }
}
