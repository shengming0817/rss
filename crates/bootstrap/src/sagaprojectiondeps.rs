//! sagaprojectiondeps —— activation requirements 之后的 topology-gated backend selector（零 adapter 依赖）。
//!
//! 已验证的 assembly workflow plan 先决定 workflow activation 并派生 capability requirements。只有
//! requirements 需要 saga/projection backend 时，组合根才经 [`resolve`] 按 [`Topology`] 选型。
//! Saga 持久化统一经 `SagaDurableStore`：demo 拓扑使用 `memory::MemSagaDurableStore`，durable 拓扑使用
//! `postgres::PgSagaDurableStore`。instance/lease、journal cursor 与 receipt 均由同一边界原子协调；
//! projection 自有 checkpoint 不进入 Saga 的持久化边界。
//!
//! # 与 WorkflowActivation 的边界
//!
//! Assembly manifest v2 的 `workflowActivations`、AssemblyLock v2 与 RuntimePlan v2 `workflowPlans` 构成
//! deployment activation 协议链。本 resolver 不读该 plan，不接受 definition lifecycle/activation，也不提供
//! omitted/disabled 的默认语义；它的成功结果只证明 topology 所需的 backend 配置完整，不证明
//! workflow 已激活，也不证明 typed actions、receipt/dead-letter store、worker 或 probe 已闭合。
//!
//! #1913 只建立上述 v2 协议载体；#1914 负责让 production runtime 在调用本 resolver 前消费
//! activation requirements。因此本模块不声明 omitted/disabled 已在当前 runtime 路径获得零副作用。
//!
//! `Demo` 路径的 in-mem 构造只能在 journeys / xtask 组合根进行（`deny.toml` `memory` wrapper 限定）；
//! 生产 `bins/server` 的 `Demo` 路径须特殊决策（TOPO-INMEM-SEAL-01）。
//!
//! # 为什么 resolver 返回**决策**而非**构造好的 adapter**
//!
//! `bootstrap` 是服务层 crate，`deny.toml` + `cargo xtask layer-deps` + cargo 依赖图三道门**禁止
//! bootstrap 依赖 adapters**（同 [`crate::replaydeps`]）。故本 resolver 是**纯 backend 策略函数**：拓扑选型 +
//! fail-closed 校验 + 凭据 redaction，返回已校验的 [`ResolvedSagaProjection`] 决策；组合根 `match` 该
//! 决策再构造具体 adapter（`Demo` → in-memory providers；`Durable` → PostgreSQL durable providers），
//! 并在组合根层持有 in-mem sealing。Saga 不保留 runtime-lock 或独立 checkpoint provider。
//!
//! INVARIANT: TOPO-FAILCLOSED-01 { level = "Medium", exec = "manual/opt-in", source = "code" }—— durable 缺 postgres URL ⇒ [`resolve`] 返 `Err`，组合根 fail-fast
//!   拒绝启动，**绝不静默降级回 demo/in-mem**（`Result` + bootstrap fail-fast，Medium；类型层强化：
//!   `Durable` 路径无「降级回 Demo」可表达变体，且 `Durable` 正例必须携 postgres URL）。
//! INVARIANT: TOPO-INMEM-SEAL-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }—— in-mem 替身**生产**不可达（生产 bin cargo-deny **Hard**，主守卫）；
//!   dev root 经决策 `match` 收束（Medium 纪律）。落地在组合根，非本 crate。
//!
//! 凭据 redaction（Medium）：postgres URL（含 `user:pass`）经 [`PostgresUrl`] 收口，其 `Debug`/`Display`
//! 走 URL userinfo 抹除；原文仅 [`PostgresUrl::expose`] 受控可达。
//!
//! `DurableShared` 与 `DurableIsolated` 两 durable 变体都收敛为 PostgreSQL durable store；隔离语义由
//! schema / row scope / lease fencing 承载，不在本选型层分叉。
//!
//! ref: docs/rules/eventbus.md §复用层选型（topology-gated）

use crate::topology::Topology;

/// postgres URL（含 `user:pass`）——凭据收口 newtype。
///
/// `Debug` / `Display` 抹去 URL authority 段 userinfo（凭据 non-leak，Medium）；原始 URL 仅
/// [`PostgresUrl::expose`] 受控可达（命名示警，仅组合根交 postgres 客户端时调用）。
#[derive(Clone, PartialEq, Eq)]
pub struct PostgresUrl(String);

impl PostgresUrl {
    /// 由原始 URL 构造（含凭据）。
    pub fn new(url: impl Into<String>) -> Self {
        Self(url.into())
    }

    /// 暴露原始 URL（含凭据）——**仅组合根**交给 postgres 客户端连接时受控调用；命名示警，禁进日志。
    ///
    /// 本方法受 `clippy.toml` `disallowed-methods` 门控——非组合根调用即 CI 红。
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for PostgresUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // reason: 抹去 userinfo 后再打印，禁 Debug 泄凭据（统一经 secure 脱敏 funnel）。
        write!(
            f,
            "PostgresUrl({})",
            secure::redact_url_credentials(&self.0)
        )
    }
}

impl std::fmt::Display for PostgresUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", secure::redact_url_credentials(&self.0))
    }
}

/// sagaprojectiondeps backend selector 的 typed 配置。
///
/// 组合根读 env（`RSS_POSTGRES_URL`）后填入；[`resolve`] 是纯函数、不读 env、不 I/O
/// （确定性可测）。
#[derive(Debug, Default)]
pub struct SagaProjectionConfig {
    /// postgres URL（含凭据）。durable 拓扑必填，demo 拓扑忽略。
    postgres_url: Option<PostgresUrl>,
}

impl SagaProjectionConfig {
    /// 由可选 postgres URL 构造。
    pub fn new(postgres_url: Option<PostgresUrl>) -> Self {
        Self { postgres_url }
    }
}

/// 已校验的 Saga/projection backend 选型决策。组合根 `match` 本枚举映射到具体 adapter；bootstrap
/// 自身不持 adapter 类型。
///
/// `#[non_exhaustive]`：加新后端变体不破坏下游。
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResolvedSagaProjection {
    /// demo 拓扑：组合根使用进程内 providers。
    Demo,
    /// durable 拓扑：组合根据此连接 PostgreSQL durable providers。
    Durable {
        /// 已校验的 postgres URL（组合根经 [`PostgresUrl::expose`] 受控取原文）。
        postgres_url: PostgresUrl,
    },
}

/// Saga/projection durable backend 选型失败（fail-closed 载体，INVARIANT TOPO-FAILCLOSED-01）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SagaProjectionResolveError {
    /// durable 拓扑缺 postgres URL——**绝不**降级回 in-mem。
    #[error("durable saga store requires a postgres url (set RSS_POSTGRES_URL)")]
    MissingPostgresUrl,
}

/// activation requirements 之后的 topology-gated Saga/projection backend 选型。
/// **纯函数**：不读 env、不做 I/O、不连 postgres。
///
/// - [`Topology::Demo`] → `Ok(`[`ResolvedSagaProjection::Demo`]`)`。
/// - [`Topology::DurableShared`] | [`Topology::DurableIsolated`] → 需 postgres URL；缺则返回 fail-closed
///   错误，**绝不**返回 `Demo`。
///
/// 两个 durable 变体都收敛为同一个 PostgreSQL Saga durable-store 边界。
///
/// INVARIANT: TOPO-FAILCLOSED-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（见模块 rustdoc）。
pub fn resolve(
    topo: Topology,
    cfg: SagaProjectionConfig,
) -> Result<ResolvedSagaProjection, SagaProjectionResolveError> {
    match topo {
        // reason: demo 拓扑无外部依赖，恒成立。
        Topology::Demo => Ok(ResolvedSagaProjection::Demo),
        // 两个 durable 变体均需 PostgreSQL；无 runtime-lock 兼容配置面。
        Topology::DurableShared | Topology::DurableIsolated => {
            let postgres_url = cfg
                .postgres_url
                .ok_or(SagaProjectionResolveError::MissingPostgresUrl)?;
            Ok(ResolvedSagaProjection::Durable { postgres_url })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PostgresUrl, ResolvedSagaProjection, SagaProjectionConfig, SagaProjectionResolveError,
        resolve,
    };
    use crate::topology::Topology;

    const URL_WITH_CREDS: &str = "postgres://user:pass@host:5432/rss";
    const URL_NO_CREDS: &str = "postgres://host:5432/rss";
    // expose() 在 clippy.toml disallowed-methods（凭据出口仅组合根受控调用）；本测试是唯一 sanctioned
    // 验证点，item-level carve-out。
    #[allow(clippy::disallowed_methods)]
    fn assert_expose_eq(url: &PostgresUrl, expected: &str) {
        assert_eq!(url.expose(), expected);
    }

    // 取出 Durable 的 postgres_url（碰到非 Durable 即失败）。item-level carve-out。
    #[allow(clippy::unwrap_used, clippy::panic)]
    fn durable_url(got: Result<ResolvedSagaProjection, SagaProjectionResolveError>) -> PostgresUrl {
        match got.unwrap() {
            ResolvedSagaProjection::Durable { postgres_url } => postgres_url,
            other => panic!("expected Durable, got {other:?}"),
        }
    }

    #[test]
    fn demo_resolves_to_demo() {
        let got = resolve(Topology::Demo, SagaProjectionConfig::default());
        assert!(matches!(got, Ok(ResolvedSagaProjection::Demo)));
    }

    #[test]
    fn demo_with_postgres_url_still_resolves_demo() {
        let cfg = SagaProjectionConfig::new(Some(PostgresUrl::new(URL_WITH_CREDS)));
        let got = resolve(Topology::Demo, cfg);
        assert!(matches!(got, Ok(ResolvedSagaProjection::Demo)));
    }

    #[test]
    fn durable_shared_missing_postgres_fails_closed() {
        // fail-closed：类型层 `Durable` 路径无 `Ok(Demo)` 可表达变体（TOPO-FAILCLOSED-01）。
        let got = resolve(Topology::DurableShared, SagaProjectionConfig::default());
        assert!(matches!(
            got,
            Err(SagaProjectionResolveError::MissingPostgresUrl)
        ));
    }

    #[test]
    fn durable_isolated_missing_postgres_fails_closed() {
        let got = resolve(Topology::DurableIsolated, SagaProjectionConfig::default());
        assert!(matches!(
            got,
            Err(SagaProjectionResolveError::MissingPostgresUrl)
        ));
    }

    #[test]
    fn durable_shared_with_postgres_url_resolves_durable() {
        let cfg = SagaProjectionConfig::new(Some(PostgresUrl::new(URL_WITH_CREDS)));
        let pg = durable_url(resolve(Topology::DurableShared, cfg));
        assert_eq!(pg, PostgresUrl::new(URL_WITH_CREDS));
    }

    #[test]
    fn durable_isolated_with_postgres_url_resolves_durable() {
        let cfg = SagaProjectionConfig::new(Some(PostgresUrl::new(URL_WITH_CREDS)));
        let pg = durable_url(resolve(Topology::DurableIsolated, cfg));
        assert_eq!(pg, PostgresUrl::new(URL_WITH_CREDS));
    }

    #[test]
    fn postgres_url_expose_returns_original() {
        let url = PostgresUrl::new(URL_WITH_CREDS);
        assert_expose_eq(&url, URL_WITH_CREDS);
    }

    #[test]
    fn credentials_not_in_postgres_url_debug_or_display() {
        let url = PostgresUrl::new(URL_WITH_CREDS);
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
    fn postgres_url_no_creds_debug_and_display_unchanged() {
        let url = PostgresUrl::new(URL_NO_CREDS);
        let dbg = format!("{url:?}");
        let disp = format!("{url}");
        assert!(dbg.contains("host"), "host missing from debug: {dbg}");
        assert!(disp.contains("host"), "host missing from display: {disp}");
    }

    #[test]
    fn missing_postgres_url_message() {
        let err = SagaProjectionResolveError::MissingPostgresUrl;
        assert_eq!(
            err.to_string(),
            "durable saga store requires a postgres url (set RSS_POSTGRES_URL)"
        );
    }
}
