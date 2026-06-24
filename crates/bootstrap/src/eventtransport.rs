//! eventtransport —— topology-gated 事件传输选型（单源策略，零 adapter 依赖）。
//!
//! 组合根（`bins/server` / `journeys` / 未来 `examples`）经 [`resolve`] 按 [`Topology`] 单源选型
//! 事件传输：demo 拓扑用进程内 in-mem bus，durable 拓扑用 per-domain amqp broker。
//!
//! # 为什么 resolver 返回**决策**而非**构造好的 adapter**（ADR / eventbus.md 偏离）
//!
//! `eventbus.md` 早期措辞设想在本模块的 `BrokerKind` match 里直接构造 `MemBus` / `AmqpPublisher`，
//! 并把「in-mem bus 仅 demo 可达」的 sealing 落在 bootstrap（Hard）。但 **bootstrap 是服务层 crate**，
//! `deny.toml`（`amqp` wrappers=[server,rss,xtask,journeys]；`memory` wrappers=[journeys,xtask]）+
//! `cargo xtask layer-deps` + cargo 依赖图三道门**禁止 bootstrap 依赖 adapters**。故本 resolver 是
//! **纯策略函数**：做拓扑选型 + fail-closed 校验 + 凭据 redaction，返回已校验的 [`ResolvedTransport`]
//! 决策；组合根 `match` 该决策再构造具体 adapter，并在**组合根层**持有 in-mem sealing。
//!
//! sealing 的实际归属与强度（主守卫是生产侧）：
//! - 生产 bin（`bins/server` / `bins/rss`）经 cargo-deny **连 `memory` 都依赖不到** ⇒ in-mem bus
//!   类型层不可命名（**Hard**，比「bootstrap 内 sealing」更强；这是 in-mem 生产不可达的主守卫）。
//! - dev root（`journeys` / `examples`）合法依赖 `memory` + `amqp`，in-mem 仅经 `match
//!   ResolvedTransport::Demo` 臂构造——**决策绑定纪律（Medium）**：`match` 把构造收束到已校验决策，
//!   但 dev root 仍能直接 `MemBus::new()` 绕过（类型层未封闭，dev-only 可接受）；非编译期 Hard。
//!
//! INVARIANT: TOPO-FAILCLOSED-01 —— durable 缺 broker URL ⇒ [`resolve`] 返 `Err`，组合根
//!   fail-fast 拒绝启动，**绝不静默降级回 demo/in-mem**（`Result` + bootstrap fail-fast，Medium；
//!   类型层强化：`Durable` 路径无「降级回 Demo」可表达变体，唯一非 `Err` 输出是全域齐备的 `Durable`）。
//! INVARIANT: TOPO-INMEM-SEAL-01 —— in-mem 传输**生产**不可达（生产 bin cargo-deny **Hard**，主守卫）；
//!   dev root 经决策 `match` 收束（Medium 纪律，非编译期封闭）。落地在组合根，非本 crate
//!   （bootstrap 命名不到 in-mem 类型）。
//!
//! 凭据 redaction（FR-020，Medium）：per-domain AMQP URL（含 `user:pass`）经 [`AmqpUrl`] 收口，
//! 其 `Debug`/`Display` 走 `secure::redact_url_credentials` 抹 userinfo；原文仅 [`AmqpUrl::expose`]
//! 受控可达。错误 message 不含凭据 / PII（[`TransportResolveError::MissingBrokerUrl`] 仅含大写 domain 名，
//! 安全可诊断，review F6）。
//!
//! ref: docs/rules/eventbus.md §事件传输选型 / §per-domain AMQP vhost/credential 隔离

use std::collections::BTreeMap;

// 部署拓扑词汇单源 = [`crate::topology::Topology`]（replaydeps / eventtransport / 未来 sagaprojectiondeps
// 共享同一枚举，防同义枚举漂移）。本模块 AMQP 特定语义（DurableShared 回退 `RSS_AMQP_URL`、DurableIsolated
// 禁回退）文档化在 [`resolve`] / [`TransportConfig`] 层，而非枚举本体。
use crate::topology::Topology;

/// per-domain AMQP broker URL（含 `user:pass` + vhost）——凭据收口 newtype。
///
/// `Debug` / `Display` 经 `secure::redact_url_credentials` 抹去 userinfo（凭据 non-leak，Medium）；
/// 原始 URL 仅 [`AmqpUrl::expose`] 受控可达（命名示警，仅组合根交 broker 客户端时调用）。
#[derive(Clone, PartialEq, Eq)]
pub struct AmqpUrl(String);

impl AmqpUrl {
    /// 由原始 URL 构造（含凭据）。
    pub fn new(url: impl Into<String>) -> Self {
        Self(url.into())
    }

    /// 暴露原始 URL（含凭据）——**仅组合根**交给 broker 客户端连接时受控调用；命名示警，禁进日志。
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for AmqpUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // reason: 抹去 userinfo 后再打印，禁 Debug 泄凭据（FR-020）。
        write!(f, "AmqpUrl({})", secure::redact_url_credentials(&self.0))
    }
}

impl std::fmt::Display for AmqpUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", secure::redact_url_credentials(&self.0))
    }
}

/// eventtransport resolver 的 typed 配置。
///
/// 组合根读 env（`RSS_<DOMAIN>_AMQP_URL`，大写 DOMAIN；缺省回退 `RSS_AMQP_URL`）后填入；
/// [`resolve`] 是纯函数、不读 env、不 I/O（保持确定性可测）。
#[derive(Debug, Default)]
pub struct TransportConfig {
    /// per-domain AMQP URL（key = 大写 DOMAIN，如 `"IDENTITY"`）。
    per_domain_urls: BTreeMap<String, AmqpUrl>,
    /// 共享回退 URL（**非隔离**拓扑用；未来隔离拓扑禁回退，见 eventbus.md §per-domain 隔离）。
    shared_url: Option<AmqpUrl>,
}

impl TransportConfig {
    /// 由 per-domain URL 表 + 可选共享回退构造。domain key **自动规范化为大写**——调用方传 `"identity"`
    /// 或 `"IDENTITY"` 均可，免大小写拼错被 shared fallback 静默掩盖（review F6）。
    pub fn new(per_domain_urls: BTreeMap<String, AmqpUrl>, shared_url: Option<AmqpUrl>) -> Self {
        Self {
            per_domain_urls: per_domain_urls
                .into_iter()
                .map(|(domain, url)| (domain.to_uppercase(), url))
                .collect(),
            shared_url,
        }
    }

    /// 增量加一个 per-domain URL（domain 自动规范化为大写）。组合根逐域读 env 时的 typed funnel——
    /// 不必手动 uppercase / 拼对大小写（review F6）。
    #[must_use]
    pub fn with_domain_url(mut self, domain: &str, url: AmqpUrl) -> Self {
        self.per_domain_urls.insert(domain.to_uppercase(), url);
        self
    }
}

/// 已校验的传输选型决策。组合根 `match` 本枚举映射到具体 adapter
/// （`Demo` → in-mem bus；`Durable` → per-domain amqp）。bootstrap 自身不持 adapter 类型。
///
/// `#[non_exhaustive]`：加 broker（mqtt）/隔离拓扑变体不破坏下游。
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResolvedTransport {
    /// demo 拓扑：组合根用进程内 in-mem bus。
    Demo,
    /// durable 拓扑：per-domain（大写 DOMAIN → 已校验 [`AmqpUrl`]）。组合根据此为每个域连 amqp
    /// （per-domain vhost/credential 隔离 seam）。
    Durable {
        /// 已校验的 per-domain AMQP 目标（每个 required 域一条；缺则 [`resolve`] 已 fail-closed）。
        per_domain: BTreeMap<String, AmqpUrl>,
    },
}

/// 传输选型失败（fail-closed 载体，INVARIANT TOPO-FAILCLOSED-01）。
///
/// message 不含凭据 / PII——`domain` 字段是大写域名（如 `IDENTITY`，非敏感），入 message 给出可操作诊断
/// （review F6：错误含 domain + 应设的 env 名）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportResolveError {
    /// durable 拓扑缺某 required 域的 broker URL（shared 拓扑也无共享回退 / isolated 拓扑无 per-domain）
    /// ——**绝不**降级回 in-mem。
    #[error(
        "durable transport requires a broker url for domain {domain} (set RSS_{domain}_AMQP_URL)"
    )]
    MissingBrokerUrl {
        /// 缺 URL 的大写域名。
        domain: String,
    },
    /// **isolated** 拓扑被配了共享 URL（`RSS_AMQP_URL`）——禁回退共享凭据，配置即矛盾，fail-closed。
    #[error("isolated topology must not be configured with a shared broker url (RSS_AMQP_URL)")]
    IsolatedFallbackForbidden,
}

/// topology-gated 事件传输选型（单源）。**纯函数**：不读 env、不做 I/O、不连 broker。
///
/// - [`Topology::Demo`] → `Ok(`[`ResolvedTransport::Demo`]`)`。
/// - [`Topology::DurableShared`] → 逐域校验 AMQP URL（per-domain 优先，缺则回退 `shared_url`）。
/// - [`Topology::DurableIsolated`] → 逐域**必须**有 per-domain URL（**禁**回退）；配置含 `shared_url`
///   → `IsolatedFallbackForbidden`（防误用共享凭据）。
///
/// 任一域缺 URL → `Err(`[`TransportResolveError::MissingBrokerUrl`]`)`，**绝不**返回 `Demo`；全部齐备 →
/// `Ok(`[`ResolvedTransport::Durable`]`)`。`required_domains`（大小写不敏感，内部规范化为大写）由组合根
/// 从 [`crate::Registry`] 的订阅 / 发布声明派生——使 resolver 能 per-domain fail-closed 而自身无需读
/// env / 知道域集。
///
/// INVARIANT: TOPO-FAILCLOSED-01（见模块 rustdoc）。
pub fn resolve(
    topo: Topology,
    cfg: TransportConfig,
    required_domains: &[&str],
) -> Result<ResolvedTransport, TransportResolveError> {
    match topo {
        // reason: demo 拓扑无 broker 依赖，恒成立。
        Topology::Demo => Ok(ResolvedTransport::Demo),
        // 非隔离：per-domain 缺则回退共享 URL（eventbus.md §per-domain：隔离拓扑才禁回退）。
        Topology::DurableShared => resolve_durable(&cfg, required_domains, cfg.shared_url.as_ref()),
        // 隔离：禁回退共享凭据——配置含 shared URL 即矛盾，fail-closed；per-domain 缺即 fail-closed。
        Topology::DurableIsolated => {
            if cfg.shared_url.is_some() {
                return Err(TransportResolveError::IsolatedFallbackForbidden);
            }
            resolve_durable(&cfg, required_domains, None)
        }
    }
}

/// durable 选型公共体：逐 required 域取 per-domain URL（缺则用 `fallback`，isolated 传 `None` 即禁回退）;
/// 任一域缺即 `MissingBrokerUrl { domain }` fail-closed。
fn resolve_durable(
    cfg: &TransportConfig,
    required_domains: &[&str],
    fallback: Option<&AmqpUrl>,
) -> Result<ResolvedTransport, TransportResolveError> {
    let mut per_domain = BTreeMap::new();
    for domain in required_domains {
        let key = domain.to_uppercase();
        let url = cfg.per_domain_urls.get(&key).or(fallback).ok_or(
            TransportResolveError::MissingBrokerUrl {
                domain: key.clone(),
            },
        )?;
        per_domain.insert(key, url.clone());
    }
    Ok(ResolvedTransport::Durable { per_domain })
}

#[cfg(test)]
mod tests {
    use super::{
        AmqpUrl, ResolvedTransport, Topology, TransportConfig, TransportResolveError, resolve,
    };
    use std::collections::BTreeMap;

    const URL_IDENTITY: &str = "amqp://idu:idp@host/identity";
    const URL_SHARED: &str = "amqp://su:sp@host/shared";

    fn cfg_with(domain_key: &str, url: &str) -> TransportConfig {
        let mut m = BTreeMap::new();
        m.insert(domain_key.to_string(), AmqpUrl::new(url));
        TransportConfig::new(m, None)
    }

    // 测试断言取出 Durable 的 per_domain（碰到非 Durable 即失败）。item-level carve-out
    // （workspace lints §「测试模块 item-level #[allow] carve-out」）——confine 到此单一 helper。
    #[allow(clippy::unwrap_used, clippy::panic)]
    fn durable_map(
        got: Result<ResolvedTransport, TransportResolveError>,
    ) -> BTreeMap<String, AmqpUrl> {
        match got.unwrap() {
            ResolvedTransport::Durable { per_domain } => per_domain,
            other => panic!("expected Durable, got {other:?}"),
        }
    }

    #[test]
    fn demo_resolves_to_demo() {
        let got = resolve(Topology::Demo, TransportConfig::default(), &["identity"]);
        assert!(matches!(got, Ok(ResolvedTransport::Demo)));
    }

    #[test]
    fn durable_shared_full_config_resolves_durable_not_demo() {
        // anti-silent-degrade 正例：配置齐备 ⇒ Durable，绝不是 Demo（AmqpUrl PartialEq 比对，不经 expose）。
        let map = durable_map(resolve(
            Topology::DurableShared,
            cfg_with("IDENTITY", URL_IDENTITY),
            &["identity"],
        ));
        assert_eq!(map.len(), 1);
        assert_eq!(map["IDENTITY"], AmqpUrl::new(URL_IDENTITY));
    }

    #[test]
    fn durable_shared_missing_url_fails_closed() {
        // fail-closed：缺配置 ⇒ 精确 MissingBrokerUrl{domain}。类型层 `Durable` 路径无 `Ok(Demo)` 可表达
        // 变体，故「绝不静默降级回 demo/in-mem」由类型系统保证、无需单独 runtime 断言（TOPO-FAILCLOSED-01）。
        let got = resolve(
            Topology::DurableShared,
            TransportConfig::default(),
            &["identity"],
        );
        assert!(matches!(
            got,
            Err(TransportResolveError::MissingBrokerUrl { domain }) if domain == "IDENTITY"
        ));
    }

    #[test]
    fn durable_no_required_domains_is_vacuously_ok() {
        // 无需传输的进程：durable 空 required ⇒ Durable{空}（非 Demo），不 fail。
        let got = resolve(Topology::DurableShared, TransportConfig::default(), &[]);
        assert!(
            matches!(got, Ok(ResolvedTransport::Durable { ref per_domain }) if per_domain.is_empty())
        );
    }

    #[test]
    fn shared_falls_back_to_shared_url() {
        let cfg = TransportConfig::new(BTreeMap::new(), Some(AmqpUrl::new(URL_SHARED)));
        let map = durable_map(resolve(
            Topology::DurableShared,
            cfg,
            &["identity", "audit"],
        ));
        assert_eq!(map["IDENTITY"], AmqpUrl::new(URL_SHARED));
        assert_eq!(map["AUDIT"], AmqpUrl::new(URL_SHARED));
    }

    #[test]
    fn per_domain_url_preferred_over_shared() {
        // shared 回退存在但 per-domain 优先。
        let mut m = BTreeMap::new();
        m.insert("IDENTITY".to_string(), AmqpUrl::new(URL_IDENTITY));
        let cfg = TransportConfig::new(m, Some(AmqpUrl::new(URL_SHARED)));
        let map = durable_map(resolve(Topology::DurableShared, cfg, &["identity"]));
        assert_eq!(map["IDENTITY"], AmqpUrl::new(URL_IDENTITY));
    }

    #[test]
    fn required_domains_case_insensitive() {
        let got = resolve(
            Topology::DurableShared,
            cfg_with("IDENTITY", URL_IDENTITY),
            &["IdEnTiTy"],
        );
        assert!(matches!(got, Ok(ResolvedTransport::Durable { .. })));
    }

    #[test]
    fn with_domain_url_normalizes_case() {
        // F6：with_domain_url 传小写 domain 也能被大写 required 命中（key 规范化）。
        let cfg =
            TransportConfig::default().with_domain_url("identity", AmqpUrl::new(URL_IDENTITY));
        let map = durable_map(resolve(Topology::DurableShared, cfg, &["identity"]));
        assert_eq!(map["IDENTITY"], AmqpUrl::new(URL_IDENTITY));
    }

    #[test]
    fn isolated_full_per_domain_resolves() {
        let cfg = TransportConfig::default()
            .with_domain_url("identity", AmqpUrl::new(URL_IDENTITY))
            .with_domain_url("audit", AmqpUrl::new("amqp://au:ap@host/audit"));
        let map = durable_map(resolve(
            Topology::DurableIsolated,
            cfg,
            &["identity", "audit"],
        ));
        assert_eq!(map["IDENTITY"], AmqpUrl::new(URL_IDENTITY));
    }

    #[test]
    fn isolated_missing_per_domain_fails_closed_no_fallback() {
        // F3：isolated 禁回退——audit 无 per-domain URL（即便后面没 shared）⇒ MissingBrokerUrl{AUDIT}。
        let cfg =
            TransportConfig::default().with_domain_url("identity", AmqpUrl::new(URL_IDENTITY));
        let got = resolve(Topology::DurableIsolated, cfg, &["identity", "audit"]);
        assert!(matches!(
            got,
            Err(TransportResolveError::MissingBrokerUrl { domain }) if domain == "AUDIT"
        ));
    }

    #[test]
    fn isolated_with_shared_url_fails_closed() {
        // F3：isolated 配了共享 URL = 矛盾配置 ⇒ IsolatedFallbackForbidden（绝不用共享凭据）。
        let cfg = TransportConfig::new(BTreeMap::new(), Some(AmqpUrl::new(URL_SHARED)));
        let got = resolve(Topology::DurableIsolated, cfg, &["identity"]);
        assert!(matches!(
            got,
            Err(TransportResolveError::IsolatedFallbackForbidden)
        ));
    }

    #[test]
    // expose() 在 clippy.toml disallowed-methods（凭据出口仅组合根受控调用）；本测试是唯一 sanctioned
    // 验证点（确认 expose 返回原文），item-level carve-out。
    #[allow(clippy::disallowed_methods)]
    fn credentials_not_in_amqp_url_debug_or_display() {
        let url = AmqpUrl::new(URL_IDENTITY);
        let dbg = format!("{url:?}");
        let disp = format!("{url}");
        for rendered in [&dbg, &disp] {
            assert!(
                rendered.contains("<redacted>"),
                "expected redaction in {rendered}"
            );
            assert!(!rendered.contains("idu"), "leaked user in {rendered}");
            assert!(!rendered.contains("idp"), "leaked password in {rendered}");
        }
        // expose() 仍可取原文（受控）。
        assert_eq!(url.expose(), URL_IDENTITY);
    }

    #[test]
    fn missing_broker_url_message_includes_domain_and_env() {
        // F6：错误 message 含 domain + 应设的 env 名（可操作）；domain 名非 PII，无凭据泄漏。
        let err = TransportResolveError::MissingBrokerUrl {
            domain: "IDENTITY".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "durable transport requires a broker url for domain IDENTITY (set RSS_IDENTITY_AMQP_URL)"
        );
    }

    #[test]
    fn isolated_fallback_forbidden_message() {
        let err = TransportResolveError::IsolatedFallbackForbidden;
        assert_eq!(
            err.to_string(),
            "isolated topology must not be configured with a shared broker url (RSS_AMQP_URL)"
        );
    }
}
