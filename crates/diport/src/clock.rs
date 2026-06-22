//! `Clock` —— 时间源 DI port（可替换 provider：prod `SystemClock` / test `FakeClock`）。

use std::time::SystemTime;

/// 时间源 DI port。
///
/// **sync trait** → 天然 dyn-compatible，经 `Box<dyn Clock>` 注入即可，**不需** dynosaur
/// （dynosaur 仅为 async fn in trait 的 dyn 派发；sync trait 无此问题）。
///
/// `Clock` 是必填构造器位置参（rust-standards §工程护栏「Clock 是构造器位置参；禁止默认取系统
/// 时钟」）。prod `SystemClock`（内部调 `SystemTime::now`，受 clippy `disallowed_methods` 约束、
/// 仅在 adapter / 组合根 item-level 解禁）只在组合根构造后注入；本 trait 仅声明接缝、不含实现。
///
/// `Send + Sync` supertrait：clock 注入进跨线程持有的 service（多线程 runtime），erased
/// `dyn Clock` 须 `Send + Sync`。
pub trait Clock: Send + Sync {
    /// 当前 wall-clock 时间。
    fn now(&self) -> SystemTime;
}

#[cfg(test)]
mod smoke {
    //! build smoke：证明 sync DI port 可 impl + 经 `Box<dyn Clock>` 动态注入（无 dynosaur）。
    use super::*;

    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> SystemTime {
            // 固定值（非系统时钟）：test 替身确定性，且不触 disallowed_methods。
            SystemTime::UNIX_EPOCH
        }
    }

    #[test]
    fn clock_is_dyn_injectable() {
        let clock: Box<dyn Clock> = Box::new(FixedClock);
        assert_eq!(clock.now(), SystemTime::UNIX_EPOCH);
    }
}
