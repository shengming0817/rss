//! 分层分类单源 —— workspace 成员 crate → `Layer` 映射 + 允许依赖矩阵。
//!
//! 规则单源 = `docs/rules/architecture.md §分层`。被 `layerdeps`（source-centric 分层依赖 lint）
//! 与 `publicapi`（baseline 目标层）共用，消除分层成员重复（DRY）。
//!
//! 分类策略：`crates/*` 按 crate 名查五层 const 表（basis/engine/diport/service/domain）；
//! `adapters/*` / `bins/*` / `xtask` / `assemblies/*` / `journeys` / `generated` 按成员**路径**判（不靠名，
//! 免疫 crates.io 同名碰撞）。`crates/` 下未登记 → `None`，由 `layerdeps` 覆盖检查
//! （LAYER-DEPS-05）fail——新增 crate 必须在此登记层。
//!
//! INVARIANT: LAYER-DEPS-00 —— 五层 const 表与 architecture.md §分层 同源；矩阵 `allows`
//!   编码该节「允许 / 禁止依赖」。漂移由 `layerdeps` 真实工作区绿用例（anti-vacuity）暴露。

/// 基础层（依赖 std + 外部 crate，不依赖上层）。**声明顺序即 intra-base DAG 低→高**
/// （`vocab ◁ ids ◁ secure ◁ support ◁ runctx`，ADR-002 §D3）——见 [`basis_intra_dag_allows`]。
pub(crate) const BASIS_CRATES: &[&str] = &["vocab", "ids", "secure", "support", "runctx"];
/// 引擎 / 原语层（依赖基础）。
pub(crate) const ENGINE_CRATES: &[&str] = &["consistency", "primitives"];
/// DI-infra 层（依赖基础 + 引擎；被服务 / 域 / adapter / 组合根消费）——可替换 provider 的
/// DI port trait 单源 + dynosaur 单一 dyn-dispatch 依赖点（ADR-003）。
pub(crate) const DIPORT_CRATES: &[&str] = &["diport"];
/// 服务层（依赖基础 + 引擎 + DI-infra）。
///
/// `testkit` 是**服务层 test-support 库**（HTTP 契约测试 oneshot harness，#1136）：出边全是外部 crate
/// （axum/tower/serde…，无 workspace 内部边可违 [`allows`]），经 `[dev-dependencies]` 被域/组合根消费
/// （dev-dep 边不入 layerdeps shipped 扫描，见 `layerdeps` 文档头）。归 Service 层 ⇒ 无需 deny.toml 分层
/// ban（仅 Domain/Adapter/Generated 需，LAYER-DEPS-06）、无需改 base intra-DAG。
pub(crate) const SERVICE_CRATES: &[&str] = &[
    "httpserve",
    "authn",
    "bootstrap",
    "eventexec",
    "observ",
    "distributed",
    "deviceloop",
    "testkit",
];
/// 域层（依赖基础 + 引擎 + 服务 + generated；兄弟域互不依赖）。
pub(crate) const DOMAIN_CRATES: &[&str] =
    &["identity", "settings", "audit", "contractreg", "syshealth"];

/// dev/test-only adapter（demo / in-mem provider）：**禁生产 bin 依赖**，只准 test/tooling 组合根
/// （[`DEV_ADAPTER_ROOTS`]）依赖。普通 adapter 须被全部组合根 wrapper 覆盖（LAYER-DEPS-06）；dev adapter
/// 例外——正向只要求 [`DEV_ADAPTER_ROOTS`]、且 wrapper **不得**含生产 bin（`INVARIANT: LAYER-DEPS-07`）。
pub(crate) const DEV_ADAPTERS: &[&str] = &["memory"];
/// 允许消费 dev/test adapter 的组合根（验收 journey + tooling，排除 `server`/`rss` 生产 bin）。
pub(crate) const DEV_ADAPTER_ROOTS: &[&str] = &["journeys", "xtask"];

/// 该 adapter 是否 dev/test-only（demo provider）。
pub(crate) fn is_dev_adapter(name: &str) -> bool {
    DEV_ADAPTERS.contains(&name)
}

/// test-support 库（HTTP 契约测试 harness 等，如 `testkit`）：归 Service 层供 classify，但**只准经
/// `[dev-dependencies]` 消费**——禁进生产 shipped 依赖图（architecture.md §分层）。机器守由 layerdeps
/// [`check_test_support_confinement`](crate::layerdeps::check_test_support_confinement)（INVARIANT:
/// LAYER-DEPS-08）承载：补 `allows` 矩阵盲区——`allows(Domain,Service)=true` 不阻止域 crate 误把 testkit
/// 放进 `[dependencies]`；layerdeps 只扫 shipped 依赖表，故任一指向本集成员的内部边即 shipped 误用。
pub(crate) const TEST_SUPPORT_CRATES: &[&str] = &["testkit"];

/// 该 crate 是否 test-support 库（只准 dev-dependency 消费，见 [`TEST_SUPPORT_CRATES`]）。
pub(crate) fn is_test_support(name: &str) -> bool {
    TEST_SUPPORT_CRATES.contains(&name)
}

/// workspace 成员所属分层。
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum Layer {
    Basis,
    Engine,
    /// DI-infra（diport）：基础 / 引擎 之上、服务 / 域 / adapter 之下。
    DiPort,
    Service,
    Domain,
    Adapter,
    Generated,
    /// 组合根（bins / xtask / assemblies / journeys）：可依赖所有库 crate。
    Root,
}

/// 按 crate 名 + 成员路径（相对 workspace root，如 `crates/vocab` / `adapters/redis` /
/// `bins/server` / `xtask` / `generated`）判定分层。`crates/*` 经 const 表查五层；其余按路径前缀。
/// 未识别（含 `crates/` 下未登记）→ `None`。
pub(crate) fn classify(crate_name: &str, member_path: &str) -> Option<Layer> {
    if member_path == "generated" {
        return Some(Layer::Generated);
    }
    if member_path == "xtask"
        || member_path.starts_with("bins/")
        || member_path.starts_with("assemblies/")
        || member_path == "journeys"
        || member_path.starts_with("journeys/")
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
/// 规则单源 = architecture.md §分层（**逐字编码，不放宽**）：基础仅 std+外部、引擎依赖基础、
/// DI-infra 依赖基础+引擎、服务依赖基础+引擎+DI-infra、域依赖基础+引擎+DI-infra+服务+generated
/// （兄弟域互不依赖）、adapter 实现基础/引擎/DI-infra/服务/**域** trait（adapter→域 = DIP 内向边，impl 域
/// repo/service port，Option 2/ADR-005；反向 域→adapter 仍禁）。**同层横向依赖一律禁**（§分层
/// 未授予任一分组同层依赖；基础"仅 std+外部"直接排除基础互依赖）——fail-closed：只放行 §分层
/// 显式授予的下行边。generated 仅需基础；root 依赖一切。
pub(crate) fn allows(from: Layer, to: Layer) -> bool {
    use Layer::{Adapter, Basis, DiPort, Domain, Engine, Generated, Root, Service};
    match from {
        // 组合根可依赖所有库 crate。
        Root => true,
        // contract 派生 wire 类型只需基础（serde derive 在外部 crate）。
        Generated => to == Basis,
        // adapter：基础 + 引擎 + DI-infra（impl 其 port trait）+ 服务 + 域（impl 域 repo/service port，
        // DIP 内向边，Option 2/ADR-005）；禁兄弟 adapter / generated（反向 域→adapter 由下方 Domain 行禁）。
        Adapter => matches!(to, Basis | Engine | DiPort | Service | Domain),
        // 域：基础 + 引擎 + DI-infra + 服务 + generated；禁兄弟域（跨域只经 contract）/ adapter
        //（域不依赖 adapter——依赖反转方向：adapter→域 单向，见上方 Adapter 行）。
        Domain => matches!(to, Basis | Engine | DiPort | Service | Generated),
        // 服务：基础 + 引擎 + DI-infra（消费 DI port）；禁兄弟服务（§分层 未授予）/ 域 / adapter / generated。
        Service => matches!(to, Basis | Engine | DiPort),
        // DI-infra：基础 + 引擎（port 签名引用其类型）；禁服务及以上（无 back-path）/ 兄弟 DI-infra。
        DiPort => matches!(to, Basis | Engine),
        // 引擎：仅基础；禁兄弟引擎（§分层 未授予）/ DI-infra 及以上。
        Engine => to == Basis,
        // 基础：不依赖上层 / 跨界；同层（兄弟基础）默认禁——唯一例外是 intra-base DAG 前向边，
        // 由 [`basis_intra_dag_allows`] 单独放行（layerdeps 在 Basis→Basis 时叠加判定）。
        Basis => false,
    }
}

/// 基础层**内部** DAG 前向边放行（INVARIANT: BASE-INTRADAG-01）。[`BASIS_CRATES`] 的声明顺序即 DAG
/// 低→高（`vocab ◁ ids ◁ secure ◁ support ◁ runctx`，ADR-002 §D3）；高 rank crate 可依赖低 rank crate
/// （前向边，如 sanctioned `runctx → vocab`），反向 / 同 crate / 任一端非基础边一律 `false`。这是
/// [`allows`]「基础同层横向一律禁」的**唯一**例外；`layerdeps::check_layers` 在 `!allows(Basis,Basis)`
/// 时叠加本判定。fail-closed：只放行 DAG 严格前向边。
pub(crate) fn basis_intra_dag_allows(from_crate: &str, to_crate: &str) -> bool {
    let rank = |c: &str| BASIS_CRATES.iter().position(|&x| x == c);
    matches!((rank(from_crate), rank(to_crate)), (Some(f), Some(t)) if f > t)
}

/// 受控 `bootstrap → httpserve` **编译期路由类型边**放行（INVARIANT: LAYER-DEPS-ROUTE-FUNNEL-01，ADR-009）。
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

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("vocab", "crates/vocab", Some(Layer::Basis))]
    #[case("runctx", "crates/runctx", Some(Layer::Basis))]
    #[case("consistency", "crates/consistency", Some(Layer::Engine))]
    #[case("diport", "crates/diport", Some(Layer::DiPort))]
    #[case("httpserve", "crates/httpserve", Some(Layer::Service))]
    #[case("bootstrap", "crates/bootstrap", Some(Layer::Service))]
    #[case("testkit", "crates/testkit", Some(Layer::Service))]
    #[case("identity", "crates/identity", Some(Layer::Domain))]
    #[case("syshealth", "crates/syshealth", Some(Layer::Domain))]
    #[case("redis", "adapters/redis", Some(Layer::Adapter))]
    #[case("postgres", "adapters/postgres", Some(Layer::Adapter))]
    #[case("generated", "generated", Some(Layer::Generated))]
    #[case("server", "bins/server", Some(Layer::Root))]
    #[case("rss", "bins/rss", Some(Layer::Root))]
    #[case("xtask", "xtask", Some(Layer::Root))]
    #[case("journeys", "journeys", Some(Layer::Root))]
    #[case("memory", "adapters/memory", Some(Layer::Adapter))]
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

    /// 路径判分类不靠 crate 名——adapter 即使叫 `redis`（与 crates.io 同名）仍按路径归 Adapter。
    #[test]
    fn classify_adapter_immune_to_name() {
        assert_eq!(
            classify("redis-adapter", "adapters/redis"),
            Some(Layer::Adapter)
        );
    }

    /// intra-base DAG 前向边放行 / 反向·同 crate·非基础禁（INVARIANT: BASE-INTRADAG-01 anti-vacuity）。
    #[rstest]
    // 前向边（高 rank → 低 rank）：放行。sanctioned `runctx → vocab`。
    #[case("runctx", "vocab", true)]
    #[case("support", "secure", true)]
    #[case("ids", "vocab", true)]
    // 反向边：禁（防成环 / 倒挂）。
    #[case("vocab", "runctx", false)]
    #[case("vocab", "support", false)]
    // 同 crate：禁。
    #[case("vocab", "vocab", false)]
    // 任一端非基础 crate：本例外不适用（false ⇒ 交回 allows 决策）。
    #[case("runctx", "consistency", false)]
    #[case("httpserve", "vocab", false)]
    fn basis_intra_dag_allows_forward_only(
        #[case] from: &str,
        #[case] to: &str,
        #[case] want: bool,
    ) {
        assert_eq!(basis_intra_dag_allows(from, to), want);
    }

    /// 受控路由类型边只放行 `bootstrap → httpserve`（INVARIANT: LAYER-DEPS-ROUTE-FUNNEL-01 anti-vacuity）：
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
