// rss_partition_serial_allowlist UI fixture（impl-site **不在** allowlist：example crate 源路径
// 不含 `adapters` / `bins` 路径段 ⇒ 非 allowlist ⇒ impl PartitionSerialDelivery 触发）。
// golden 见 main.stderr：impl 真 consistency::PartitionSerialDelivery 触发；#[allow] 逃生门不触发。
// 须用真 consistency（dev-dep）：lint 按被 impl trait 的 crate 名（consistency）+ 名（PartitionSerialDelivery）匹配，
// 本地 stub trait 无法触发。
// UI 测试只编译查诊断、不运行。
// allow(unknown_lints)：普通 cargo build 本 example 时不认 rss_partition_serial_allowlist（仅 dylint driver 认），
// 抑制逃生门演示处的 unknown_lints 噪声；driver 编译时该 lint 已知，不影响 golden。
//
// 注：adapter-path 绿分支（adapters/ 下 impl → 不触发）无法在 UI harness 模拟——harness 控制 example
// 源路径，无法置于 `adapters/`；该分支由真 workspace `cargo dylint --all` 承载。
#![allow(unused, unknown_lints)]

use consistency::PartitionSerialDelivery;

// R1：非 allowlist crate impl PartitionSerialDelivery → 触发。
// 证明非串行路径被阻拦（INVARIANT PARTITION-SERIAL-IMPL-ALLOWLIST-01 红向 anti-vacuity）。
struct NonSerialStore;
impl PartitionSerialDelivery for NonSerialStore {}

// G1（specificity anti-vacuity）：非 PartitionSerialDelivery trait impl 不触发——证明 lint 非「任意 trait impl」。
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
// 绿向反真空（anti-vacuity）由 golden 单 warning 计数承载：golden 仅含 1 条 warning（NonSerialStore
// 触发），AllowedStore 因下方 #[allow] 抑制，warning 数保持 1。若 #[allow] 失效（lint 名拼错等），
// warning 数变 2，golden 失配 → ui 测试红——这是 G3 的机器锁形式。
struct AllowedStore;
#[allow(rss_partition_serial_allowlist)] // reason: UI fixture 验证逃生门
impl PartitionSerialDelivery for AllowedStore {}

fn main() {}
