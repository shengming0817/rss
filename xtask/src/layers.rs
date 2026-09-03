//! 分层分类单源 —— workspace 成员 crate → `Layer` 映射 + 允许依赖矩阵。
//!
//! 规则单源 = `Cargo.toml`、`xtask/src/layers.rs`、`deny.toml` 与 `cargo xtask layer-deps`。被 `layerdeps`（source-centric 分层依赖 lint）
//! 与 `publicapi`（baseline 目标层）共用，消除分层成员重复（DRY）。
//!
//! 分类策略：`crates/*` 按 crate 名查五层 const 表（basis/engine/diport/service/domain），另将精确路径
//! `crates/runtimeexec` 分类为 RuntimeExec；
//! `adapters/*` / `xtask` / `assemblies/*` / `composition/*` / `journeys*` / `generated` 按成员**路径**判（不靠名，
//! 免疫 crates.io 同名碰撞）。`crates/` 下未登记 → `None`，由 `layerdeps` 覆盖检查
//! （LAYER-DEPS-05）fail——新增 crate 必须在此登记层。
//!
//! INVARIANT: LAYER-DEPS-00 { level = "Medium", exec = "check", source = "code" }—— 五层 const 表、RuntimeExec / Tooling（`crates/workspacefacts`）精确路径与 `Cargo.toml`、`xtask/src/layers.rs`、`deny.toml` 与 `cargo xtask layer-deps`；矩阵 `allows`
//!   编码该节「允许 / 禁止依赖」。漂移由 `layerdeps` 真实工作区绿用例（anti-vacuity）暴露。

/// 基础层（依赖 std + 外部 crate，不依赖上层）。**声明顺序即 intra-base DAG 低→高**
/// （`diagctx（独立根）◁ runtimeinventorymint ◁ vocab ◁ assembly-schema ◁ ids ◁ securederive ◁ secure ◁ support ◁ runctx`，ADR-002 §D3 / §D1-bis）——见
/// [`basis_intra_dag_allows`]。
///
/// `securederive` 是 `secure` 的字段级脱敏 derive proc-macro（#[derive(Redact)]，#1360）：rank 低于
/// `secure` ⇒ sanctioned 前向边 `secure → securederive`（proc-macro 是编译期纯工具，出边全是外部 crate
/// syn/quote/proc-macro2，无内部边可违 [`allows`]）。
///
/// `diagctx`、`authmint`、`sagaauthmint`、`dlqauthmint`、`requestidmint` 与 `pkiauthmint` capability crates 是**独立根**
/// （[`ISOLATED_BASIS_CRATES`]）：任何涉及这些 crate 的 base 内边
/// （双向）均不 sanction，由 `cargo xtask layer-deps`（Medium，BASE-INTRADAG-01）守；Hard 化（dylint 禁 authz
/// crate import diagctx）见 follow-up #1400。
pub(crate) const BASIS_CRATES: &[&str] = &[
    "postgres-migration-inventory",
    "rss-diag-context",
    "authmint",
    "sagaauthmint",
    "dlqauthmint",
    "requestidmint",
    "pkiauthmint",
    "runtimeinventorymint",
    "vocab",
    "assembly-schema",
    "ids",
    "securederive",
    "secure",
    "support",
    "runctx",
];

/// 独立根基础 crate：任何涉及这些 crate 的 intra-base 边（双向）均不 sanction。
/// `diagctx` 是诊断独立根；其余 mint crates 是 production capability 独立根
/// （deny.toml wrappers 另收窄持有方）。
pub(crate) const ISOLATED_BASIS_CRATES: &[&str] = &[
    "rss-diag-context",
    "authmint",
    "sagaauthmint",
    "dlqauthmint",
    "requestidmint",
    "pkiauthmint",
];
/// 引擎 / 原语层（依赖基础）。
///
/// `tracewire` 是 W3C Trace Context capture/remote-parent restore 的唯一生产 OpenTelemetry bridge：
/// domain-neutral 纯 infra、无 workspace 内部边（出边全是外部 opentelemetry/tracing crate），被 service
/// `eventexec` 和 adapters `httpd`/`postgres` 依赖（`allows(Service,Engine)` / `allows(Adapter,Engine)` 均放行；
/// `service→service` 禁故不可置 Service 档）。
pub(crate) const ENGINE_CRATES: &[&str] = &[
    "consistency",
    "primitives",
    "rss-conformance",
    "rss-device-security-contracts",
    "rss-trace-context",
];
/// Provider-neutral eventing authoring/runtime public seam. The package identity is deliberately
/// kept out of the generic engine catalog because its outbound production dependency set is
/// narrower and is checked by `layerdeps` against package identities.
pub(crate) const EVENTING_PUBLIC_CRATES: &[&str] = &["rss-eventing"];
/// DI-infra 层（依赖基础 + 引擎；被服务 / 域 / adapter / 组合根消费）——可替换 provider 的
/// DI port trait 单源 + dynosaur 单一 dyn-dispatch 依赖点（ADR-003）。
pub(crate) const DIPORT_CRATES: &[&str] = &["diport"];
/// 服务层（依赖基础 + 引擎 + DI-infra）。
///
/// `testkit` 是**服务层 test-support 库**（HTTP 契约测试 oneshot harness，#1136）：唯一 workspace
/// 内部 shipped 出边为 `rss-conformance`，其余出边为外部 crate（axum/tower/serde…）；经 `[dev-dependencies]` 被域/组合根消费
/// （dev 边进入 layerdeps 独立 bucket，不进入 `shipped_edges`，见 `layerdeps` 文档头）。归 Service 层 ⇒ 无需 deny.toml 分层
/// ban（仅 Domain/Adapter/Generated 需，LAYER-DEPS-06）、无需改 base intra-DAG。
pub(crate) const SERVICE_CRATES: &[&str] = &[
    "httpserve",
    "authn",
    "bootstrap",
    "eventexec",
    "listenerlifecycle",
    "observ",
    "distributed",
    "deviceloop",
    "testkit",
    "tracewiretest",
];
/// 域层（依赖基础 + 引擎 + 服务 + generated；兄弟域互不依赖）。
pub(crate) const DOMAIN_CRATES: &[&str] = assembly_schema::REGISTERED_DOMAIN_LABELS;

/// dev/test-only adapter（demo / in-mem provider）：**禁生产 bin 依赖**，wrapper consumer 类别只准
/// [`DEV_ADAPTER_ROOTS`]；真实 parent exact-set 由 cargo-deny 证明（`INVARIANT: LAYER-DEPS-07` { level = "Medium", exec = "check", source = "code" }）。
pub(crate) const DEV_ADAPTERS: &[&str] = &["memory"];
/// 允许消费 dev/test adapter 的组合根（验收 journey + tooling，排除 `server`/`rss` 生产 bin）。
pub(crate) const DEV_ADAPTER_ROOTS: &[&str] = &["journeys", "xtask"];

/// 该 adapter 是否 dev/test-only（demo provider）。
pub(crate) fn is_dev_adapter(name: &str) -> bool {
    DEV_ADAPTERS.contains(&name)
}

/// 基础层中的 proc-macro 工具 crate（编译期纯工具，`[lib] proc-macro = true`）。归 [`BASIS_CRATES`] 供
/// 分层分类 + intra-base DAG（`secure → securederive` 前向边），但**不是 SemVer 库 API 面**——其契约
/// （`#[derive(Redact)]` 的 `#[redact]` 属性 grammar + 生成 impl）由 codegen golden（trybuild
/// compile-fail）守，非 `cargo public-api`。故 [`is_proc_macro`] 标记，让 `publicapi` baseline 目标排除。
pub(crate) const PROC_MACRO_CRATES: &[&str] = &["securederive"];

/// 该 crate 是否 proc-macro 工具 crate（不入 `cargo public-api` baseline，见 [`PROC_MACRO_CRATES`]）。
pub(crate) fn is_proc_macro(name: &str) -> bool {
    PROC_MACRO_CRATES.contains(&name)
}

/// test-support 库（HTTP 契约测试 harness）：保持各自既有分层供 classify，但
/// **只准经 `[dev-dependencies]` 消费**——禁进生产 shipped 依赖图（`Cargo.toml`、`xtask/src/layers.rs`、`deny.toml` 与 `cargo xtask layer-deps`）。机器守由 layerdeps
/// [`check_test_support_confinement`](crate::layerdeps::check_test_support_confinement)（INVARIANT:
/// LAYER-DEPS-08）承载：补 `allows` 矩阵盲区。该规则只消费 `shipped_edges`，故任一指向本集成员的
/// shipped 内部边即误用；独立 dev bucket 仅应用 LAYER-DEPS-02/03。
pub(crate) const TEST_SUPPORT_CRATES: &[&str] = &["testkit", "tracewiretest"];

/// 该 crate 是否 test-support 库（只准 dev-dependency 消费，见 [`TEST_SUPPORT_CRATES`]）。
pub(crate) fn is_test_support(name: &str) -> bool {
    TEST_SUPPORT_CRATES.contains(&name)
}

/// workspace 成员所属分层。
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum Layer {
    /// Lowest public value layer; no workspace production dependencies.
    FoundationPublic,
    /// 最低位公开应用内核；自身禁止任何 workspace 生产依赖，所有内部层可反向消费其稳定值面。
    PlatformPublic,
    /// Provider-neutral eventing public seam; exact production out-edges are package-allowlisted.
    EventingPublic,
    Basis,
    Engine,
    /// DI-infra（diport）：基础 / 引擎 之上、服务 / 域 / adapter 之下。
    DiPort,
    Service,
    /// provider-independent runtime 启动内核；只向基础/引擎/DI-infra/服务出边，只允许组合根消费。
    RuntimeExec,
    Domain,
    Adapter,
    Generated,
    /// 非发布 tooling/verification facts；仅组合根可消费，自身无 workspace 内部出边。
    Tooling,
    /// 组合根（xtask / assemblies / composition / journeys）：可依赖所有库 crate。
    Root,
}

/// 按 crate 名 + 成员路径（相对 workspace root，如 `crates/vocab` / `adapters/redis` /
/// `assemblies/runtime` / `xtask` / `generated`）判定分层。`crates/*` 经 const 表查五层；其余按路径前缀。
/// 未识别（含 `crates/` 下未登记）→ `None`。
pub(crate) fn classify(crate_name: &str, member_path: &str) -> Option<Layer> {
    if matches!(
        (crate_name, member_path),
        ("rss-contract", "crates/contract") | ("rss-request-context", "crates/request-context")
    ) {
        return Some(Layer::FoundationPublic);
    }
    if member_path == "crates/platform" {
        return (crate_name == "rss-platform").then_some(Layer::PlatformPublic);
    }
    if member_path == "crates/eventing" {
        return (crate_name == "rss-eventing").then_some(Layer::EventingPublic);
    }
    if member_path == "crates/workspacefacts" {
        return (crate_name == "workspacefacts").then_some(Layer::Tooling);
    }
    if member_path == "crates/runtimeexec" {
        return (crate_name == "runtimeexec").then_some(Layer::RuntimeExec);
    }
    if member_path == "generated" {
        return Some(Layer::Generated);
    }
    if member_path == "xtask"
        || member_path.starts_with("assemblies/")
        || member_path.starts_with("composition/")
        || member_path == "journeys"
        || member_path.starts_with("journeys/")
        || member_path == "journeys-fault-matrix"
    {
        return Some(Layer::Root);
    }
    if member_path.starts_with("adapters/") {
        return Some(Layer::Adapter);
    }
    if member_path.starts_with("crates/") {
        if BASIS_CRATES.contains(&crate_name) {
            return Some(Layer::Basis);
        }
        if ENGINE_CRATES.contains(&crate_name) {
            return Some(Layer::Engine);
        }
        if DIPORT_CRATES.contains(&crate_name) {
            return Some(Layer::DiPort);
        }
        if SERVICE_CRATES.contains(&crate_name) {
            return Some(Layer::Service);
        }
        if DOMAIN_CRATES.contains(&crate_name) {
            return Some(Layer::Domain);
        }
    }
    None
}

/// 分层依赖矩阵：`from` 是否允许直接依赖 `to`（仅工作区内部边；外部 crate 不经此函数）。
/// 规则单源 = `Cargo.toml`、`xtask/src/layers.rs`、`deny.toml` 与 `cargo xtask layer-deps`，不放宽**）：基础仅 std+外部、引擎依赖基础、
/// DI-infra 依赖基础+引擎、服务依赖基础+引擎+DI-infra、域依赖基础+引擎+DI-infra+服务+generated
/// （兄弟域互不依赖）、adapter 实现基础/引擎/DI-infra/服务/**域** trait（adapter→域 = DIP 内向边，impl 域
/// repo/service port，Option 2/ADR-005；反向 域→adapter 仍禁）。**同层横向依赖一律禁**（§分层
/// 未授予任一分组同层依赖；基础"仅 std+外部"直接排除基础互依赖）——fail-closed：只放行 §分层
/// 显式授予的下行边。generated 仅需基础；root 依赖一切。
pub(crate) fn allows(from: Layer, to: Layer) -> bool {
    use Layer::{
        Adapter, Basis, DiPort, Domain, Engine, EventingPublic, FoundationPublic, Generated,
        PlatformPublic, Root, RuntimeExec, Service, Tooling,
    };
    match from {
        // 分层矩阵允许组合根消费所有库 crate；RuntimeExec 再由 deny.toml 精确 target wrapper 收窄。
        Root => true,
        FoundationPublic => false,
        PlatformPublic => to == FoundationPublic,
        // Exact package allowlist is enforced by layerdeps; this row only declares the maximum
        // layer directions needed by the four sanctioned public dependencies.
        EventingPublic => matches!(to, FoundationPublic | Basis | Engine),
        // workspace facts 只消费外部 guppy/thiserror；任何内部出边均属越界。
        Tooling => false,
        // contract 派生 wire 类型只需基础（serde derive 在外部 crate）。
        Generated => matches!(to, FoundationPublic | PlatformPublic | Basis),
        // provider-independent runtime 启动内核：只消费基础/引擎/DI-infra/服务；禁具体域、adapter、
        // generated、组合根及兄弟 RuntimeExec。入边由其它各行保持关闭，仅 Root 行放行。
        RuntimeExec => matches!(
            to,
            FoundationPublic | PlatformPublic | EventingPublic | Basis | Engine | DiPort | Service
        ),
        // adapter：基础 + 引擎 + DI-infra（impl 其 port trait）+ 服务 + 域（impl 域 repo/service port，
        // DIP 内向边，Option 2/ADR-005）；禁兄弟 adapter / generated（反向 域→adapter 由下方 Domain 行禁）。
        Adapter => matches!(
            to,
            FoundationPublic
                | PlatformPublic
                | EventingPublic
                | Basis
                | Engine
                | DiPort
                | Service
                | Domain
        ),
        // 域：基础 + 引擎 + DI-infra + 服务 + generated；禁兄弟域（跨域只经 contract）/ adapter
        //（域不依赖 adapter——依赖反转方向：adapter→域 单向，见上方 Adapter 行）。
        Domain => matches!(
            to,
            FoundationPublic
                | PlatformPublic
                | EventingPublic
                | Basis
                | Engine
                | DiPort
                | Service
                | Generated
        ),
        // 服务：基础 + 引擎 + DI-infra（消费 DI port）；禁兄弟服务（§分层 未授予）/ 域 / adapter / generated。
        Service => matches!(
            to,
            FoundationPublic | PlatformPublic | EventingPublic | Basis | Engine | DiPort
        ),
        // DI-infra：基础 + 引擎（port 签名引用其类型）；禁服务及以上（无 back-path）/ 兄弟 DI-infra。
        DiPort => matches!(
            to,
            FoundationPublic | PlatformPublic | EventingPublic | Basis | Engine
        ),
        // 引擎：仅基础；禁兄弟引擎（§分层 未授予）/ DI-infra 及以上。
        Engine => matches!(to, FoundationPublic | PlatformPublic | Basis),
        // 基础：不依赖上层 / 跨界；同层（兄弟基础）默认禁——唯一例外是 intra-base DAG 前向边，
        // 由 [`basis_intra_dag_allows`] 单独放行（layerdeps 在 Basis→Basis 时叠加判定）。
        Basis => matches!(to, FoundationPublic | PlatformPublic),
    }
}

/// INVARIANT: BASE-INTRADAG-01 { level = "Medium", exec = "check", source = "code" } —— 基础层**内部** DAG 前向边放行。[`BASIS_CRATES`] 的声明顺序即 DAG
/// 低→高（`diagctx（独立根）◁ runtimeinventorymint ◁ vocab ◁ assembly-schema ◁ ids ◁ securederive ◁ secure ◁ support ◁ runctx`，ADR-002 §D3）；高 rank crate 可依赖低 rank crate
/// （前向边，如 sanctioned `runctx → vocab`），反向 / 同 crate / 任一端非基础边一律 `false`。这是
/// [`allows`]「基础同层横向一律禁」的**唯一**例外；`layerdeps::check_layers` 在 `!allows(Basis,Basis)`
/// 时叠加本判定。fail-closed：只放行 DAG 严格前向边。
///
/// [`ISOLATED_BASIS_CRATES`] 中的 crate（如 `diagctx` / `authmint`）是独立根：任何涉及它的 base 内边（双向）均
/// 不 sanction，在 rank 比较之前优先拦截（防止 `X → diagctx` 被高 rank 误放行）。
pub(crate) fn basis_intra_dag_allows(from_crate: &str, to_crate: &str) -> bool {
    // 独立根：双向均不 sanction，优先于 rank 比较。
    if ISOLATED_BASIS_CRATES.contains(&from_crate) || ISOLATED_BASIS_CRATES.contains(&to_crate) {
        return false;
    }
    let rank = |c: &str| BASIS_CRATES.iter().position(|&x| x == c);
    matches!((rank(from_crate), rank(to_crate)), (Some(f), Some(t)) if f > t)
}

/// 受控 `bootstrap → httpserve` **编译期路由类型边**放行（INVARIANT: LAYER-DEPS-ROUTE-FUNNEL-01 { level = "Medium", exec = "check", source = "code" }，ADR-009）。
///
/// typed route funnel（#1113 auth-finalize-before-bind + #1103 typed per-listener route-group）要求 bootstrap
/// 取 httpserve 的路由类型词汇（`ListenerRouter<L>` / `UnfinalizedRoutes`）——三段「produce（bootstrap
/// `finalize_routes`）→ seal → transform（httpserve `finalize_auth`）」须 **co-locate** 才能类型层 Hard，故
/// sanction 这条**唯一**的 `Service → Service` 有向边（对齐 ADR-005 sanctioned `adapter → 域` DIP 内向边范式）。
/// `layerdeps::check_layers` 在 `!allows(Service,Service)` 时叠加本判定。
///
/// **不放宽**一般 `Service → Service`：兄弟服务互不依赖仍守（PR #137 F1 的「不向兄弟服务要 runtime provider」
/// 原则不变——本边仅取**编译期类型**，不取 runtime provider）。fail-closed：只放行这一对有向边，反向
/// （`httpserve → bootstrap`，httpserve 仍禁依赖 bootstrap）/ 其它任意 `Service → Service` 一律交回 [`allows`] 禁。
pub(crate) fn route_funnel_allows(from_crate: &str, to_crate: &str) -> bool {
    (from_crate, to_crate) == ("bootstrap", "httpserve")
}

/// Redis/S3/Vault provider adapter 的 runtime output 边界。
///
/// INVARIANT: LAYER-DEPS-PROVIDER-BOOTSTRAP-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "provider_adapter_bootstrap_forbidden_red_three_edges", anti_vacuity = "provider_adapter_bootstrap_forbidden_green_non_target_edges" }
/// —— 精确拒绝 `redis-adapter|s3|vault → bootstrap` 三条 Cargo package 有向边，防止 adapter 直接取得
/// `DomainModuleResult` 并绕过 runtime-local `ProviderOutput`。这是 [`allows`] 的窄化规则：一般
/// `Adapter → Service` 仍合法（例如 postgres → bootstrap），目标 adapters → `diport` 等下行边也不受影响。
/// `layerdeps::check_layers` 必须在通用 [`allows`] 之前应用该 deny，避免允许矩阵短路。
pub(crate) fn provider_adapter_bootstrap_forbidden(from_crate: &str, to_crate: &str) -> bool {
    matches!(from_crate, "redis-adapter" | "s3" | "vault") && to_crate == "bootstrap"
}

/// Generated authoring/registration seams 的精确 crate edges。
///
/// `generated::command::{CommandEmit, CommandJournal}` 接受字段私有、仅 generated 可构造的
/// `CommandSpec`；`eventexec` 必须实现这些 seam，才能在自身 crate 内构造不可外部伪造的 reviewed DTO。
/// Workflow runtime 同样只在 `eventexec` 内把 generated definition catalog 与 sealed assembly plan
/// exact-join。`bootstrap` 仅实现 sealed event subscription registrar，使 raw transport coordinates
/// 不再出现在 domain callsites。两条边都是类型/可见性 Hard seal 的必要编译边，不是一般
/// `Service → Generated` 放宽；bootstrap 对 generated 的 production item surface 另由 layerdeps 的
/// `LAYER-DEPS-GENERATED-BOOTSTRAP-REGISTRAR-01` exact AST allowlist 收窄。fail-closed：反向或其它
/// service 一律返回 false。
pub(crate) fn generated_seam_allows(from_crate: &str, to_crate: &str) -> bool {
    to_crate == "generated" && matches!(from_crate, "eventexec" | "bootstrap")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("vocab", "crates/vocab", Some(Layer::Basis))]
    #[case("rss-platform", "crates/platform", Some(Layer::PlatformPublic))]
    #[case("runctx", "crates/runctx", Some(Layer::Basis))]
    #[case("rss-diag-context", "crates/diagctx", Some(Layer::Basis))]
    #[case("authmint", "crates/authmint", Some(Layer::Basis))]
    #[case("requestidmint", "crates/requestidmint", Some(Layer::Basis))]
    #[case("pkiauthmint", "crates/pkiauthmint", Some(Layer::Basis))]
    #[case("rss-contract", "crates/contract", Some(Layer::FoundationPublic))]
    #[case(
        "rss-request-context",
        "crates/request-context",
        Some(Layer::FoundationPublic)
    )]
    #[case("consistency", "crates/consistency", Some(Layer::Engine))]
    #[case("diport", "crates/diport", Some(Layer::DiPort))]
    #[case("httpserve", "crates/httpserve", Some(Layer::Service))]
    #[case("bootstrap", "crates/bootstrap", Some(Layer::Service))]
    #[case("runtimeexec", "crates/runtimeexec", Some(Layer::RuntimeExec))]
    #[case("testkit", "crates/testkit", Some(Layer::Service))]
    #[case("identity", "crates/identity", Some(Layer::Domain))]
    #[case("syshealth", "crates/syshealth", Some(Layer::Domain))]
    #[case("redis", "adapters/redis", Some(Layer::Adapter))]
    #[case("postgres", "adapters/postgres", Some(Layer::Adapter))]
    #[case("generated", "generated", Some(Layer::Generated))]
    #[case("xtask", "xtask", Some(Layer::Root))]
    #[case("journeys", "journeys", Some(Layer::Root))]
    #[case("journeys-fault-matrix", "journeys-fault-matrix", Some(Layer::Root))]
    #[case("memory", "adapters/memory", Some(Layer::Adapter))]
    #[case("workspacefacts", "crates/workspacefacts", Some(Layer::Tooling))]
    fn classify_maps_known_members(
        #[case] name: &str,
        #[case] path: &str,
        #[case] want: Option<Layer>,
    ) {
        assert_eq!(classify(name, path), want);
    }

    /// `crates/` 下未登记 crate → `None`（驱动 LAYER-DEPS-05 anti-drift）。
    #[test]
    fn classify_unregistered_crate_is_none() {
        assert_eq!(classify("brandnew", "crates/brandnew"), None);
    }

    #[test]
    fn classify_eventing_public_requires_canonical_identity() {
        assert_eq!(
            classify("rss-eventing", "crates/eventing"),
            Some(Layer::EventingPublic)
        );
        assert_eq!(classify("rss-eventing", "crates/rss-eventing"), None);
        assert_eq!(classify("eventing", "crates/eventing"), None);
    }

    #[test]
    fn classify_runtimeexec_requires_exact_name_and_path() {
        assert_eq!(classify("runtimeexec", "crates/runtimeexec2"), None);
        assert_eq!(classify("runtimeexec2", "crates/runtimeexec"), None);
    }

    #[test]
    fn classify_foundation_rejects_swapped_package_identity() {
        assert_eq!(classify("rss-contract", "crates/request-context"), None);
        assert_eq!(classify("rss-request-context", "crates/contract"), None);
    }

    #[test]
    fn test_support_catalog_is_exact() {
        assert_eq!(TEST_SUPPORT_CRATES, &["testkit", "tracewiretest"]);
        assert!(is_test_support("testkit"));
        assert!(is_test_support("tracewiretest"));
        assert!(!is_test_support("identity"));
        assert_eq!(classify("testkit", "crates/testkit"), Some(Layer::Service));
        assert_eq!(
            classify("tracewiretest", "crates/tracewiretest"),
            Some(Layer::Service)
        );
    }

    /// 四 const 表与 classify 一致：每个登记 crate 名归对应层（防 const 表内漂移 + 覆盖全集非代表性子集）。
    #[test]
    fn classify_covers_all_const_members() {
        let cases: &[(&[&str], Layer)] = &[
            (BASIS_CRATES, Layer::Basis),
            (ENGINE_CRATES, Layer::Engine),
            (DIPORT_CRATES, Layer::DiPort),
            (SERVICE_CRATES, Layer::Service),
            (DOMAIN_CRATES, Layer::Domain),
        ];
        for (names, want) in cases {
            for c in *names {
                assert_eq!(classify(c, &format!("crates/{c}")), Some(*want), "{c}");
            }
        }
    }

    #[test]
    fn domain_crate_registry_is_exact() {
        assert_eq!(
            DOMAIN_CRATES,
            &["identity", "settings", "audit", "contractreg", "syshealth"]
        );
    }

    /// 路径判分类不靠 crate 名——adapter 即使叫 `redis`（与 crates.io 同名）仍按路径归 Adapter。
    #[test]
    fn classify_adapter_immune_to_name() {
        assert_eq!(
            classify("redis-adapter", "adapters/redis"),
            Some(Layer::Adapter)
        );
    }

    /// intra-base DAG 前向边放行 / 反向·同 crate·非基础禁（INVARIANT: BASE-INTRADAG-01 { level = "Medium", exec = "check", source = "code" }anti-vacuity）。
    #[rstest]
    // 前向边（高 rank → 低 rank）：放行。sanctioned `runctx → vocab`。
    #[case("runctx", "vocab", true)]
    #[case("support", "secure", true)]
    #[case("ids", "vocab", true)]
    // sanctioned 前向边 `secure → securederive`（#1360 字段级脱敏 derive proc-macro）。
    #[case("secure", "securederive", true)]
    // 反向 `securederive → secure`：禁（proc-macro 不依赖 secure，只生成 `::secure::…` 路径）。
    #[case("securederive", "secure", false)]
    // 反向边：禁（防成环 / 倒挂）。
    #[case("vocab", "runctx", false)]
    #[case("vocab", "support", false)]
    // 同 crate：禁。
    #[case("vocab", "vocab", false)]
    // 任一端非基础 crate：本例外不适用（false ⇒ 交回 allows 决策）。
    #[case("runctx", "consistency", false)]
    #[case("httpserve", "vocab", false)]
    // diagctx 独立根：双向均不 sanction（anti-vacuity，证明 X→diagctx 不被高 rank 误放行）。
    #[case("runctx", "rss-diag-context", false)]
    #[case("vocab", "rss-diag-context", false)]
    #[case("rss-diag-context", "vocab", false)]
    #[case("rss-diag-context", "runctx", false)]
    // authmint 独立根：与 diagctx 对称的 anti-vacuity（AUTH-EVIDENCE-MINT-01 Hard 半段）。
    #[case("runctx", "authmint", false)]
    #[case("vocab", "authmint", false)]
    #[case("authmint", "vocab", false)]
    #[case("authmint", "runctx", false)]
    // requestidmint 独立根：只能被 deny.toml 指定的上层 wrapper 消费。
    #[case("runctx", "requestidmint", false)]
    #[case("vocab", "requestidmint", false)]
    #[case("requestidmint", "vocab", false)]
    #[case("requestidmint", "runctx", false)]
    // pkiauthmint 独立根：只能被 exact wrapper 集合命名。
    #[case("runctx", "pkiauthmint", false)]
    #[case("vocab", "pkiauthmint", false)]
    #[case("pkiauthmint", "vocab", false)]
    #[case("pkiauthmint", "runctx", false)]
    // runtimeinventorymint is a low-rank capability root consumed only by assembly-schema and
    // runtimeexec; the exact consumer set is additionally closed by deny.toml wrappers.
    #[case("assembly-schema", "runtimeinventorymint", true)]
    #[case("runtimeinventorymint", "assembly-schema", false)]
    fn basis_intra_dag_allows_forward_only(
        #[case] from: &str,
        #[case] to: &str,
        #[case] want: bool,
    ) {
        assert_eq!(basis_intra_dag_allows(from, to), want);
    }

    /// 受控路由类型边只放行 `bootstrap → httpserve`（INVARIANT: LAYER-DEPS-ROUTE-FUNNEL-01 { level = "Medium", exec = "check", source = "code" }anti-vacuity）：
    /// 反向 / 其它 Service→Service / 任一端非该对一律 false（交回 `allows` 禁）。
    #[rstest]
    // sanctioned 唯一边：放行。
    #[case("bootstrap", "httpserve", true)]
    // 反向边：禁（httpserve 仍禁依赖 bootstrap）。
    #[case("httpserve", "bootstrap", false)]
    // 其它 Service→Service：本例外不适用（false ⇒ 交回 allows 禁）。
    #[case("bootstrap", "authn", false)]
    #[case("eventexec", "httpserve", false)]
    // 非 Service 端 / 无关对：false。
    #[case("identity", "httpserve", false)]
    #[case("bootstrap", "bootstrap", false)]
    fn route_funnel_allows_bootstrap_to_httpserve_only(
        #[case] from: &str,
        #[case] to: &str,
        #[case] want: bool,
    ) {
        assert_eq!(route_funnel_allows(from, to), want);
    }

    /// Provider adapter 不得反向取得 runtime 聚合类型：只拒绝 Redis/S3/Vault → bootstrap，
    /// 不扩大成一般 Adapter→Service 禁令（LAYER-DEPS-PROVIDER-BOOTSTRAP-01 anti-vacuity）。
    #[test]
    fn provider_adapter_bootstrap_forbidden_red_three_edges() {
        for adapter in ["redis-adapter", "s3", "vault"] {
            assert!(provider_adapter_bootstrap_forbidden(adapter, "bootstrap"));
        }
    }

    #[test]
    fn provider_adapter_bootstrap_forbidden_green_non_target_edges() {
        for (from, to) in [
            ("postgres", "bootstrap"),
            ("redis-adapter", "diport"),
            ("bootstrap", "redis-adapter"),
        ] {
            assert!(!provider_adapter_bootstrap_forbidden(from, to));
        }
    }

    #[rstest]
    #[case("eventexec", "generated", true)]
    #[case("authn", "generated", false)]
    #[case("bootstrap", "generated", true)]
    #[case("observ", "generated", false)]
    #[case("generated", "eventexec", false)]
    #[case("eventexec", "eventexec", false)]
    fn generated_seam_allows_exact_edges_only(
        #[case] from: &str,
        #[case] to: &str,
        #[case] want: bool,
    ) {
        assert_eq!(generated_seam_allows(from, to), want);
    }

    #[test]
    fn eventing_public_has_only_the_declared_layer_directions() {
        for consumer in [
            Layer::DiPort,
            Layer::Service,
            Layer::Domain,
            Layer::Adapter,
            Layer::RuntimeExec,
            Layer::Root,
        ] {
            assert!(allows(consumer, Layer::EventingPublic), "{consumer:?}");
        }
        for lower in [
            Layer::FoundationPublic,
            Layer::PlatformPublic,
            Layer::Basis,
            Layer::Engine,
            Layer::Generated,
        ] {
            assert!(!allows(lower, Layer::EventingPublic), "{lower:?}");
        }
    }

    #[rstest]
    // 下行（§分层 显式授予的下层边）：允许。
    #[case(Layer::Engine, Layer::Basis, true)]
    #[case(Layer::Service, Layer::Engine, true)]
    #[case(Layer::Service, Layer::Basis, true)]
    #[case(Layer::Domain, Layer::Service, true)]
    #[case(Layer::Domain, Layer::Generated, true)]
    #[case(Layer::Adapter, Layer::Service, true)]
    #[case(Layer::Generated, Layer::Basis, true)]
    // DI-infra 下行授予边：diport 依赖基础+引擎；服务/域/adapter 可依赖 diport。
    #[case(Layer::DiPort, Layer::Basis, true)]
    #[case(Layer::DiPort, Layer::Engine, true)]
    #[case(Layer::Service, Layer::DiPort, true)]
    #[case(Layer::Domain, Layer::DiPort, true)]
    #[case(Layer::Adapter, Layer::DiPort, true)]
    // Root 全开。
    #[case(Layer::Root, Layer::Domain, true)]
    #[case(Layer::Root, Layer::Adapter, true)]
    #[case(Layer::Root, Layer::Generated, true)]
    #[case(Layer::Root, Layer::DiPort, true)]
    #[case(Layer::Root, Layer::Tooling, true)]
    // Tooling facts crate 无内部出边，且除 Root 外任何层不得消费。
    #[case(Layer::Tooling, Layer::Basis, false)]
    #[case(Layer::Tooling, Layer::PlatformPublic, false)]
    #[case(Layer::Tooling, Layer::Tooling, false)]
    #[case(Layer::Service, Layer::Tooling, false)]
    #[case(Layer::Domain, Layer::Tooling, false)]
    #[case(Layer::Adapter, Layer::Tooling, false)]
    // RuntimeExec 只向 provider-independent 下层出边，且只能由 Root 消费。
    #[case(Layer::RuntimeExec, Layer::Basis, true)]
    #[case(Layer::RuntimeExec, Layer::Engine, true)]
    #[case(Layer::RuntimeExec, Layer::DiPort, true)]
    #[case(Layer::RuntimeExec, Layer::Service, true)]
    #[case(Layer::RuntimeExec, Layer::Domain, false)]
    #[case(Layer::RuntimeExec, Layer::Adapter, false)]
    #[case(Layer::RuntimeExec, Layer::Generated, false)]
    #[case(Layer::RuntimeExec, Layer::Root, false)]
    #[case(Layer::RuntimeExec, Layer::RuntimeExec, false)]
    #[case(Layer::Service, Layer::RuntimeExec, false)]
    #[case(Layer::Domain, Layer::RuntimeExec, false)]
    #[case(Layer::Adapter, Layer::RuntimeExec, false)]
    #[case(Layer::Generated, Layer::RuntimeExec, false)]
    #[case(Layer::Root, Layer::RuntimeExec, true)]
    // 同层横向依赖：禁（§分层 未授予任一分组同层依赖）。
    #[case(Layer::Basis, Layer::Basis, false)]
    #[case(Layer::Engine, Layer::Engine, false)]
    #[case(Layer::DiPort, Layer::DiPort, false)]
    #[case(Layer::Service, Layer::Service, false)]
    #[case(Layer::Adapter, Layer::Adapter, false)]
    #[case(Layer::Domain, Layer::Domain, false)]
    // 上行（back-path）/ 跨界：禁。
    #[case(Layer::Basis, Layer::Engine, false)]
    #[case(Layer::Basis, Layer::Service, false)]
    #[case(Layer::Engine, Layer::Service, false)]
    #[case(Layer::Service, Layer::Domain, false)]
    #[case(Layer::Domain, Layer::Adapter, false)]
    #[case(Layer::Service, Layer::Adapter, false)]
    #[case(Layer::Service, Layer::Generated, false)]
    // adapter → 域：放行（DIP 内向边——adapter impl 域定义的 repo/service port，Option 2/ADR-005）。
    // 反向 域 → adapter 仍禁（上面 Domain→Adapter=false），依赖反转方向保持。
    #[case(Layer::Adapter, Layer::Domain, true)]
    #[case(Layer::Adapter, Layer::Generated, false)]
    #[case(Layer::Generated, Layer::Service, false)]
    // DI-infra back-path / 跨界：禁——diport 不依赖服务及以上；引擎/基础/generated 不依赖 diport。
    #[case(Layer::DiPort, Layer::Service, false)]
    #[case(Layer::DiPort, Layer::Domain, false)]
    #[case(Layer::DiPort, Layer::Adapter, false)]
    #[case(Layer::DiPort, Layer::Generated, false)]
    #[case(Layer::Engine, Layer::DiPort, false)]
    #[case(Layer::Basis, Layer::DiPort, false)]
    #[case(Layer::Generated, Layer::DiPort, false)]
    fn allows_matrix(#[case] from: Layer, #[case] to: Layer, #[case] want: bool) {
        assert_eq!(allows(from, to), want);
    }
}
