//! 分层分类单源 —— workspace 成员 crate → `Layer` 映射 + 允许依赖矩阵。
//!
//! 规则单源 = `docs/rules/architecture.md §分层`。被 `layerdeps`（source-centric 分层依赖 lint）
//! 与 `publicapi`（baseline 目标层）共用，消除分层成员重复（DRY）。
//!
//! 分类策略：`crates/*` 按 crate 名查四层 const 表（basis/engine/service/domain）；
//! `adapters/*` / `bins/*` / `xtask` / `assemblies/*` / `generated` 按成员**路径**判（不靠名，
//! 免疫 crates.io 同名碰撞）。`crates/` 下未登记 → `None`，由 `layerdeps` 覆盖检查
//! （LAYER-DEPS-05）fail——新增 crate 必须在此登记层。
//!
//! INVARIANT: LAYER-DEPS-00 —— 四层 const 表与 architecture.md §分层 同源；矩阵 `allows`
//!   编码该节「允许 / 禁止依赖」。漂移由 `layerdeps` 真实工作区绿用例（anti-vacuity）暴露。

/// 基础层（仅 std + 外部 crate，不依赖内部其它分组）。
pub(crate) const BASIS_CRATES: &[&str] = &["vocab", "ids", "secure", "support", "runctx"];
/// 引擎 / 原语层（依赖基础）。
pub(crate) const ENGINE_CRATES: &[&str] = &["consistency", "primitives"];
/// 服务层（依赖基础 + 引擎）。
pub(crate) const SERVICE_CRATES: &[&str] = &[
    "httpserve",
    "authn",
    "bootstrap",
    "eventexec",
    "observ",
    "distributed",
    "deviceloop",
];
/// 域层（依赖基础 + 引擎 + 服务 + generated；兄弟域互不依赖）。
pub(crate) const DOMAIN_CRATES: &[&str] =
    &["identity", "settings", "audit", "contractreg", "syshealth"];

/// workspace 成员所属分层。
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum Layer {
    Basis,
    Engine,
    Service,
    Domain,
    Adapter,
    Generated,
    /// 组合根（bins / xtask / assemblies）：可依赖所有库 crate。
    Root,
}

/// 按 crate 名 + 成员路径（相对 workspace root，如 `crates/vocab` / `adapters/redis` /
/// `bins/server` / `xtask` / `generated`）判定分层。`crates/*` 经 const 表查四层；其余按路径前缀。
/// 未识别（含 `crates/` 下未登记）→ `None`。
pub(crate) fn classify(crate_name: &str, member_path: &str) -> Option<Layer> {
    if member_path == "generated" {
        return Some(Layer::Generated);
    }
    if member_path == "xtask"
        || member_path.starts_with("bins/")
        || member_path.starts_with("assemblies/")
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
/// 服务依赖基础+引擎、域依赖基础+引擎+服务+generated（兄弟域互不依赖）、adapter 实现基础/引擎/服务
/// trait。**同层横向依赖一律禁**（§分层 未授予任一分组同层依赖；基础"仅 std+外部"直接排除基础互依赖）——
/// fail-closed：只放行 §分层 显式授予的下行边。generated 仅需基础；root 依赖一切。
pub(crate) fn allows(from: Layer, to: Layer) -> bool {
    use Layer::{Adapter, Basis, Domain, Engine, Generated, Root, Service};
    match from {
        // 组合根可依赖所有库 crate。
        Root => true,
        // contract 派生 wire 类型只需基础（serde derive 在外部 crate）。
        Generated => to == Basis,
        // adapter：基础 + 引擎 + 服务（实现其 trait）；禁兄弟 adapter（§分层 未授予）/ 域 / generated。
        Adapter => matches!(to, Basis | Engine | Service),
        // 域：基础 + 引擎 + 服务 + generated；禁兄弟域（跨域只经 contract）/ adapter。
        Domain => matches!(to, Basis | Engine | Service | Generated),
        // 服务：基础 + 引擎；禁兄弟服务（§分层 未授予）/ 域 / adapter / generated。
        Service => matches!(to, Basis | Engine),
        // 引擎：仅基础；禁兄弟引擎（§分层 未授予）/ 服务及以上。
        Engine => to == Basis,
        // 基础：仅 std + 外部 crate，不依赖任何内部成员（含兄弟基础）。
        Basis => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("vocab", "crates/vocab", Some(Layer::Basis))]
    #[case("runctx", "crates/runctx", Some(Layer::Basis))]
    #[case("consistency", "crates/consistency", Some(Layer::Engine))]
    #[case("httpserve", "crates/httpserve", Some(Layer::Service))]
    #[case("bootstrap", "crates/bootstrap", Some(Layer::Service))]
    #[case("identity", "crates/identity", Some(Layer::Domain))]
    #[case("syshealth", "crates/syshealth", Some(Layer::Domain))]
    #[case("redis", "adapters/redis", Some(Layer::Adapter))]
    #[case("postgres", "adapters/postgres", Some(Layer::Adapter))]
    #[case("generated", "generated", Some(Layer::Generated))]
    #[case("server", "bins/server", Some(Layer::Root))]
    #[case("rss", "bins/rss", Some(Layer::Root))]
    #[case("xtask", "xtask", Some(Layer::Root))]
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
        assert_eq!(classify("redis", "adapters/redis"), Some(Layer::Adapter));
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
    // Root 全开。
    #[case(Layer::Root, Layer::Domain, true)]
    #[case(Layer::Root, Layer::Adapter, true)]
    #[case(Layer::Root, Layer::Generated, true)]
    // 同层横向依赖：禁（§分层 未授予任一分组同层依赖）。
    #[case(Layer::Basis, Layer::Basis, false)]
    #[case(Layer::Engine, Layer::Engine, false)]
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
    #[case(Layer::Adapter, Layer::Domain, false)]
    #[case(Layer::Adapter, Layer::Generated, false)]
    #[case(Layer::Generated, Layer::Service, false)]
    fn allows_matrix(#[case] from: Layer, #[case] to: Layer, #[case] want: bool) {
        assert_eq!(allows(from, to), want);
    }
}
