//! refreshstoredeps —— topology-gated refresh token store 选型（单源策略，零 adapter 依赖）。
//!
//! 组合根经 [`resolve`] 按 [`Topology`] 单源选型 refresh token 持久化后端：demo 拓扑用进程内
//! in-mem 替身，durable 拓扑用 postgres（`postgres::PgRefreshTokenStore`）。
//!
//! # 为什么 resolver 返回**决策**而非**构造好的 adapter**
//!
//! `bootstrap` 是服务层 crate，`deny.toml` + `cargo xtask layer-deps` + cargo 依赖图三道门**禁止
//! bootstrap 依赖 adapters**（同 [`crate::replaydeps`] / [`crate::sagaprojectiondeps`]）。故本
//! resolver 是**纯策略函数**：拓扑选型 + fail-closed 校验 + 凭据 redaction（经复用 [`PostgresUrl`]
//! 自身脱敏），返回已校验的 [`ResolvedRefreshStore`] 决策；组合根 `match` 该决策再构造具体
//! adapter（`Demo` → in-mem refresh store；`Durable` → postgres refresh store），并在组合根层持有
//! in-mem sealing。
//!
//! sealing 的实际归属与强度（主守卫是生产侧）：
//! - 生产 bin（`bins/server` / `bins/rss`）经 cargo-deny **连 `memory` 都依赖不到** ⇒ in-mem refresh
//!   store 类型层不可命名（**Hard**，比「bootstrap 内 sealing」更强；这是 in-mem 生产不可达的主守卫）。
//! - dev root（`journeys` / `examples`）合法依赖 `memory`，in-mem 仅经 `match
//!   ResolvedRefreshStore::Demo` 臂构造——**决策绑定纪律（Medium）**：`match` 把构造收束到已校验
//!   决策，但 dev root 仍能直接绕过（类型层未封闭，dev-only 可接受）；非编译期 Hard。
//!
//! INVARIANT: REFRESHSTORE-FAILCLOSED-01 —— durable 缺 postgres URL ⇒ [`resolve`] 返 `Err`，
//!   组合根 fail-fast 拒绝启动，**绝不静默降级回 demo/in-mem**（`Result` + bootstrap fail-fast，
//!   Medium；类型层强化：`Durable` 路径无「降级回 Demo」可表达变体，唯一非 `Err` 输出是带
//!   `postgres_url` 的 `Durable`）。
//! INVARIANT: TOPO-INMEM-SEAL-01 —— in-mem refresh store **生产**不可达（生产 bin cargo-deny
//!   **Hard**，主守卫）；dev root 经决策 `match` 收束（Medium 纪律，非编译期封闭）。落地在组合
//!   根，非本 crate（bootstrap 命名不到 in-mem 类型）。
//!
//! 凭据 redaction（Medium）：postgres URL（含 `user:pass`）经 [`PostgresUrl`] 收口，其
//! `Debug`/`Display` 走 URL userinfo 抹除（复用 `sagaprojectiondeps::PostgresUrl` 已有脱敏实现，
//! 本模块不重复）；原文仅 [`PostgresUrl::expose`] 受控可达。错误 message 不含凭据 / PII
//! （[`RefreshStoreResolveError::MissingPostgresUrl`] 仅含 env 提示，安全可诊断）。
//!
//! 注：refresh token store 是**单一共享 postgres**（无 per-domain 隔离），故 `DurableShared` 与
//! `DurableIsolated` 两个 durable 变体都收敛为「需 postgres url」——隔离语义留给 schema / row scope，
//! 不在本选型层分叉（同 [`crate::sagaprojectiondeps`] 处理方式）。
//!
//! 本轮无 bin 消费方（live consumer = login 接线 = #1017）；resolver 先行交付，组合根接线后续。
//!
//! ref: docs/rules/eventbus.md §复用层选型（topology-gated）
//! ref: crate::replaydeps（同范式 topology-gated resolver）

use crate::sagaprojectiondeps::PostgresUrl;
use crate::topology::Topology;

/// refreshstoredeps resolver 的 typed 配置。
///
/// 组合根读 env（`RSS_POSTGRES_URL`）后填入；[`resolve`] 是纯函数、不读 env、不 I/O（确定性可测）。
#[derive(Debug, Default)]
pub struct RefreshStoreConfig {
    /// postgres URL（含凭据）。durable 拓扑必填，demo 拓扑忽略。
    postgres_url: Option<PostgresUrl>,
}

impl RefreshStoreConfig {
    /// 由可选 postgres URL 构造。
    pub fn new(postgres_url: Option<PostgresUrl>) -> Self {
        Self { postgres_url }
    }
}

/// 已校验的 refresh token store 选型决策。组合根 `match` 本枚举映射到具体 adapter
/// （`Demo` → in-mem refresh store；`Durable` → postgres refresh store）。bootstrap 自身不持
/// adapter 类型。
///
/// `#[non_exhaustive]`：加新后端变体不破坏下游。
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResolvedRefreshStore {
    /// demo 拓扑：组合根用进程内 in-mem refresh token store。
    Demo,
    /// durable 拓扑：组合根据此连接 postgres refresh token store（单一共享 DB）。
    Durable {
        /// 已校验的 postgres URL（组合根经 [`PostgresUrl::expose`] 受控取原文）。
        postgres_url: PostgresUrl,
    },
}

/// refresh token store 选型失败（fail-closed 载体，INVARIANT REFRESHSTORE-FAILCLOSED-01）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RefreshStoreResolveError {
    /// durable 拓扑缺 postgres URL——**绝不**降级回 in-mem。
    #[error("durable refresh token store requires a postgres url (set RSS_POSTGRES_URL)")]
    MissingPostgresUrl,
}

/// topology-gated refresh token store 选型（单源）。**纯函数**：不读 env、不做 I/O、不连 postgres。
///
/// - [`Topology::Demo`] → `Ok(`[`ResolvedRefreshStore::Demo`]`)`。
/// - [`Topology::DurableShared`] | [`Topology::DurableIsolated`] → 需 postgres URL；缺则
///   `Err(`[`RefreshStoreResolveError::MissingPostgresUrl`]`)`，**绝不**返回 `Demo`。
///
/// 注：refresh token store 是单一共享 postgres（无 per-domain 隔离），故两 durable 变体都收敛为
/// 「需 postgres」。
///
/// INVARIANT: REFRESHSTORE-FAILCLOSED-01（见模块 rustdoc）。
pub fn resolve(
    topo: Topology,
    cfg: RefreshStoreConfig,
) -> Result<ResolvedRefreshStore, RefreshStoreResolveError> {
    match topo {
        // reason: demo 拓扑无外部依赖，恒成立。
        Topology::Demo => Ok(ResolvedRefreshStore::Demo),
        // 两个 durable 变体均需 postgres——refresh store 是共享 DB（无 per-domain 分叉）。
        Topology::DurableShared | Topology::DurableIsolated => cfg
            .postgres_url
            .map(|u| ResolvedRefreshStore::Durable { postgres_url: u })
            .ok_or(RefreshStoreResolveError::MissingPostgresUrl),
    }
}

#[cfg(test)]
mod tests {
    use super::{RefreshStoreConfig, RefreshStoreResolveError, ResolvedRefreshStore, resolve};
    use crate::sagaprojectiondeps::PostgresUrl;
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
    fn durable_url(got: Result<ResolvedRefreshStore, RefreshStoreResolveError>) -> PostgresUrl {
        match got.unwrap() {
            ResolvedRefreshStore::Durable { postgres_url } => postgres_url,
            other => panic!("expected Durable, got {other:?}"),
        }
    }

    #[test]
    fn demo_resolves_to_demo() {
        let got = resolve(Topology::Demo, RefreshStoreConfig::default());
        assert!(matches!(got, Ok(ResolvedRefreshStore::Demo)));
    }

    #[test]
    fn demo_with_postgres_url_still_resolves_demo() {
        // demo 拓扑忽略 postgres url（reason: demo 无外部依赖）。
        let cfg = RefreshStoreConfig::new(Some(PostgresUrl::new(URL_WITH_CREDS)));
        let got = resolve(Topology::Demo, cfg);
        assert!(matches!(got, Ok(ResolvedRefreshStore::Demo)));
    }

    #[test]
    fn durable_shared_missing_postgres_fails_closed() {
        // fail-closed：缺 postgres url ⇒ 精确 MissingPostgresUrl。类型层 `Durable` 路径无
        // `Ok(Demo)` 可表达变体，故「绝不静默降级回 demo/in-mem」由类型系统保证
        // （REFRESHSTORE-FAILCLOSED-01）。
        let got = resolve(Topology::DurableShared, RefreshStoreConfig::default());
        assert!(matches!(
            got,
            Err(RefreshStoreResolveError::MissingPostgresUrl)
        ));
    }

    #[test]
    fn durable_isolated_missing_postgres_fails_closed() {
        let got = resolve(Topology::DurableIsolated, RefreshStoreConfig::default());
        assert!(matches!(
            got,
            Err(RefreshStoreResolveError::MissingPostgresUrl)
        ));
    }

    #[test]
    fn durable_shared_with_postgres_url_resolves_durable() {
        // anti-silent-degrade 正例：配置齐备 ⇒ Durable，绝不是 Demo。
        let cfg = RefreshStoreConfig::new(Some(PostgresUrl::new(URL_WITH_CREDS)));
        let url = durable_url(resolve(Topology::DurableShared, cfg));
        assert_eq!(url, PostgresUrl::new(URL_WITH_CREDS));
    }

    #[test]
    fn durable_isolated_with_postgres_url_resolves_durable() {
        let cfg = RefreshStoreConfig::new(Some(PostgresUrl::new(URL_WITH_CREDS)));
        let url = durable_url(resolve(Topology::DurableIsolated, cfg));
        assert_eq!(url, PostgresUrl::new(URL_WITH_CREDS));
    }

    #[test]
    fn postgres_url_expose_returns_original() {
        // expose() 受控验证点：仍可取原文（组合根交 postgres 客户端用）。
        let url = PostgresUrl::new(URL_WITH_CREDS);
        assert_expose_eq(&url, URL_WITH_CREDS);
    }

    #[test]
    fn credentials_not_in_postgres_url_debug_or_display() {
        // Debug / Display 脱敏验证：含凭据 URL 渲染后不含 user/pass，含脱敏标记。
        // （PostgresUrl 脱敏实现在 sagaprojectiondeps，此处验证 refreshstoredeps 复用路径正确。）
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
        // 无凭据 URL：脱敏后原样（不误删 host 段）。
        let url = PostgresUrl::new(URL_NO_CREDS);
        let dbg = format!("{url:?}");
        let disp = format!("{url}");
        assert!(dbg.contains("host"), "host missing from debug: {dbg}");
        assert!(disp.contains("host"), "host missing from display: {disp}");
    }

    #[test]
    fn missing_postgres_url_message() {
        // 错误 message 含可操作提示（env 名）；不含凭据 / PII。
        let err = RefreshStoreResolveError::MissingPostgresUrl;
        assert_eq!(
            err.to_string(),
            "durable refresh token store requires a postgres url (set RSS_POSTGRES_URL)"
        );
    }
}
