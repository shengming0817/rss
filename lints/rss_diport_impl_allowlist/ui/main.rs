// rss_diport_impl_allowlist UI fixture（impl-site **不在** allowlist：example crate 源路径
// 不含 `adapters` / `bins` / `assemblies` 路径段 ⇒ 非 allowlist ⇒ impl diport port trait 触发）。
// golden 见 main.stderr：impl 真 diport port trait 触发；非 port trait / inherent / item-level #[allow] 不触发。
// 须用真 diport（dev-dep）：lint 按被 impl trait 的 crate 名（diport）匹配，本地 stub trait 无法触发。
// UI 测试只编译查诊断、不运行；async shutdown body 不会执行。
// allow(unknown_lints)：普通 cargo build 本 example 时不认 rss_diport_impl_allowlist（仅 dylint driver 认），
// 抑制 G3 逃生门演示处的 unknown_lints 噪声；driver 编译时该 lint 已知，不影响 golden。
//
// 注：adapter-path 绿分支（adapters/ 下 impl port → 不触发）无法在 UI harness 模拟——harness 控制
// example 源路径，无法置于 `adapters/`；该分支由真 workspace `cargo dylint --all`（12 adapter 0 诊断）承载。
#![allow(unused, unknown_lints)]

use std::time::SystemTime;

use diport::{Clock, ManagedResource, ShutdownError};

// R1：非 allowlist crate impl sync DI port `Clock` → 触发。
struct MyClock;
impl Clock for MyClock {
    fn now(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH
    }
}

// R2：非 allowlist crate impl async DI port（trait_variant Send 变体 `ManagedResource`）→ 触发。
// 证 Send 变体（DefId krate==diport）被捕获，不止 sync port。
struct MyResource;
impl ManagedResource for MyResource {
    fn name(&self) -> &str {
        "mine"
    }
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        Ok(())
    }
}

// G1（specificity anti-vacuity）：非 diport trait impl 不触发——证明 lint 非「任意 trait impl」。
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
#[allow(rss_diport_impl_allowlist)] // reason: UI fixture 验证逃生门
impl Clock for Allowed {
    fn now(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH
    }
}

fn main() {}
