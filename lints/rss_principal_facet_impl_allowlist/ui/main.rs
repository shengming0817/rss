// rss_principal_facet_impl_allowlist UI fixture（disallowed impl-site：example crate 名
// `rss_principal_facet_impl_allowlist_ui` ∉ allowlist {runctx, authn} ⇒ impl runctx::PrincipalFacet 触发）。
// golden 见 main.stderr：impl runctx::PrincipalFacet 触发；非 runctx trait / inherent / item-level #[allow] 不触发。
// 须用真 runctx（dev-dep）：lint 按被 impl trait 的 crate 名（runctx）+ trait 名匹配，本地 stub trait 无法触发。
// UI 测试只编译查诊断、不运行。
// allow(unknown_lints)：普通 cargo build 本 example 时不认 rss_principal_facet_impl_allowlist（仅 dylint
// driver 认），抑制 G3 逃生门演示处的 unknown_lints 噪声；driver 编译时该 lint 已知，不影响 golden。
#![allow(unused, unknown_lints)]

use runctx::PrincipalFacet;
use vocab::PrincipalKind;

// R：非 allowlist crate impl runctx::PrincipalFacet → 触发。
struct Mine;
impl PrincipalFacet for Mine {
    fn kind(&self) -> PrincipalKind {
        PrincipalKind::Anonymous
    }
    fn matches_subject(&self, _subject: &str) -> bool {
        false
    }
}

// G1（specificity anti-vacuity）：impl 非 runctx trait 不触发——证明 lint 非「任意 trait impl」。
struct Local;
impl std::fmt::Display for Local {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "local")
    }
}

// G2（of_trait 门）：inherent impl（无 trait）不触发。
impl Local {
    fn helper(&self) {}
}

// G3（逃生门）：impl 块上 item-level #[allow] 抑制。
struct Allowed;
#[allow(rss_principal_facet_impl_allowlist)] // reason: UI fixture 验证逃生门
impl PrincipalFacet for Allowed {
    fn kind(&self) -> PrincipalKind {
        PrincipalKind::Anonymous
    }
    fn matches_subject(&self, _subject: &str) -> bool {
        false
    }
}

fn main() {}
