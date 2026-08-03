// rss_pdp_impl_adapter_only UI fixture（impl-site **非** adapters：example crate manifest 父目录是 `lints`、
// 非 `adapters` ⇒ impl diport::Pdp 触发）。golden 见 main.stderr：impl 真 diport::Pdp 触发；non-Pdp diport
// trait（Clock）/ inherent / item-level #[allow] 不触发（specificity + 逃生门 anti-vacuity）。
// 须用真 diport（dev-dep）：lint 按被 impl trait 的 crate 名（diport）+ trait 名（Pdp）匹配，本地 stub 无法触发。
// adapter-path 绿分支（adapters/oidc impl Pdp 不触发）无法在 UI harness 模拟，由真 workspace `cargo dylint --all`
// （oidc 0 诊断）承载——见 src/lib.rs rustdoc「anti-vacuity」。
// UI 测试只编译查诊断、不运行；async verify body 不会执行。
// allow(unknown_lints)：普通 cargo build 本 example 时不认 rss_pdp_impl_adapter_only（仅 dylint driver 认），
// 抑制逃生门演示处的 unknown_lints 噪声；driver 编译时该 lint 已知，不影响 golden。
#![allow(unused, unknown_lints)]

use std::time::SystemTime;

use diport::{Clock, Pdp, PdpError, RawCredential, VerifiedClaims};

// R1：非 adapters crate 内联 impl diport::Pdp（always-allow 伪验签）→ 触发（信任根旁路）。
struct AllowAll;
impl Pdp for AllowAll {
    async fn verify(&self, _raw: &RawCredential) -> Result<VerifiedClaims, PdpError> {
        Ok(VerifiedClaims::service_token(
            vocab::ServiceCallerDomain::MaintenanceOperator,
            vocab::tenant::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap(),
        ))
    }
}

// G1（specificity anti-vacuity）：impl 别的 diport trait（Clock，非 Pdp）不触发——证明 lint 非「任意 diport
// trait impl」（≠ rss_diport_impl_allowlist），只针对验签端口 Pdp / PdpLocal。
struct MyClock;
impl Clock for MyClock {
    fn now(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH
    }
}

// G2（of_trait 门）：inherent impl（无 trait）不触发。
impl AllowAll {
    fn helper(&self) {}
}

// G3（逃生门）：impl 块上 item-level #[allow] 抑制。
struct AllowedByAttr;
#[allow(rss_pdp_impl_adapter_only)] // reason: UI fixture 验证逃生门
impl Pdp for AllowedByAttr {
    async fn verify(&self, _raw: &RawCredential) -> Result<VerifiedClaims, PdpError> {
        Ok(VerifiedClaims::service_token(
            vocab::ServiceCallerDomain::MaintenanceOperator,
            vocab::tenant::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap(),
        ))
    }
}

fn main() {}
