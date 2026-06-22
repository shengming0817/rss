//! fail：anti-vacuity 机器锁（DIPORT-UNSAFE-HYGIENE-01）。本文件自带 `#![forbid(unsafe_code)]`
//! （镜像 diport 经 workspace lints 继承的 forbid），证明 **forbid 对手写 unsafe 块仍生效**（编不过）。
//!
//! 与 diport 「即便 forbid 也编译通过」的事实互补：diport 通过证明 dynosaur 0.3 生成的 unsafe 经
//! def-site hygiene **不**触发 consumer forbid（是 dynosaur 的真实效果），而非 forbid 失效——本红用例
//! 锁住「forbid 非恒真」的基线。dynosaur 升级时连同 `cargo test -p diport` 一并复测本不变式。
#![forbid(unsafe_code)]

fn main() {
    let _ = unsafe { core::mem::transmute::<u32, f32>(0u32) };
}
