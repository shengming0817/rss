// rss_diport_impl_allowlist UI fixture（impl-site **不在** allowlist：example crate 源路径
// 不含 `adapters` / `bins` / `assemblies` / `composition` 路径段 ⇒ 非 allowlist ⇒ impl provider port 触发）。
// golden 见 main.stderr：provider port 触发；lifecycle/non-port/inherent/item-level #[allow] 不触发。
// 须用真 diport（dev-dep）：lint 按 trait crate identity + 完整 DefPath 匹配，本地 stub trait 无法触发。
// UI 测试只编译查诊断、不运行；async shutdown body 不会执行。
// allow(unknown_lints)：普通 cargo build 本 example 时不认 rss_diport_impl_allowlist（仅 dylint driver 认），
// 抑制 G5 逃生门演示处的 unknown_lints 噪声；driver 编译时该 lint 已知，不影响 golden。
//
// 注：adapter-path 绿分支（adapters/ 下 impl port → 不触发）无法在 UI harness 模拟——harness 控制
// example 源路径，无法置于 `adapters/`；该分支由真 workspace `cargo dylint --all` 的实际 adapter 0 诊断承载。
#![allow(unused, unknown_lints)]

use std::time::SystemTime;

use diport::managed_resource::ManagedResourceLocal;
use diport::{Clock, ManagedResource, ShutdownError};

// R1：非 allowlist crate impl sync provider port `Clock` → 触发。
struct MyClock;
impl Clock for MyClock {
    fn now(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH
    }
}

// G1：生命周期 Send trait 不属于 provider port allowlist 的扫描集。
struct MyResource;
impl ManagedResource for MyResource {
    fn name(&self) -> &str {
        "mine"
    }
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        Ok(())
    }
}

// G2：trait_variant 的 Local 基 trait 与 Send 变体属于同一个生命周期例外。
struct MyLocalResource;
impl ManagedResourceLocal for MyLocalResource {
    fn name(&self) -> &str {
        "mine-local"
    }
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        Ok(())
    }
}

// G3（specificity anti-vacuity）：非 diport trait impl 不触发——证明 lint 非「任意 trait impl」。
struct Local;
impl std::fmt::Display for Local {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "local")
    }
}

// G4（of_trait 门）：inherent impl（无 trait）不触发。
impl Local {
    fn helper(&self) {}
}

// G5（逃生门）：impl 块上 item-level #[allow] 抑制。
struct Allowed;
#[allow(rss_diport_impl_allowlist)] // reason: UI fixture 验证逃生门
impl Clock for Allowed {
    fn now(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH
    }
}

fn main() {}
