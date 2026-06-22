// rss_spawn_missing_scope UI fixture（dylint_testing::ui_test_example 消费）。
// golden 见 main.stderr：spawn/spawn_blocking 子任务体内读 runctx::try_*（未经 runctx::scope 重绑）触发；
// 已 scope 重绑 / 不读 ctx / JoinSet::spawn 方法 / item-level #[allow] 逃生门 均不触发。
// 须用真 tokio + 真 runctx（dev-deps）：lint 按 crate 名匹配，本地 stub 模块 crate 名不为 tokio/runctx 无法触发。
#![allow(unused)]

use runctx::{scope, try_current, try_with};

fn unrelated() {}

fn main() {
    // —— 红例（触发）——
    // R1：裸 spawn，子任务读 try_current 未重绑。
    let _ = tokio::spawn(async { try_current() });
    // R2：spawn_blocking 闭包内读 try_with 未重绑。
    let _ = tokio::task::spawn_blocking(|| try_with(|_c| ()));
    // R3：spawn_blocking 直接 fn-path 实参（try_current 作为 FnOnce 传入）。
    let _ = tokio::task::spawn_blocking(try_current);

    // —— 绿例（不触发）——
    // G1：捕获-重绑范式，scope 词法包裹子任务体。
    if let Ok(ctx) = try_current() {
        let _ = tokio::spawn(scope(ctx, async { try_current() }));
    }
    // G2：子任务不读 ctx。
    let _ = tokio::spawn(async { unrelated() });
    // G3：JoinSet::spawn 是方法（非自由函数 tokio::spawn），不在范围。
    let mut set = tokio::task::JoinSet::new();
    set.spawn(async { try_current() });
    // G4：item-level #[allow] 逃生门。
    spawn_with_allow();

    // G5：std::thread::spawn 非 tokio 空间，不覆盖（已知盲区，不触发）。
    let _ = std::thread::spawn(|| {
        let _ = try_current();
    });

    // R4：嵌套 spawn。外层 async 体不直接读 ctx（不报）；内层裸 spawn 读 ctx 未重绑——
    // 由内层自身 check_expr 报「一次」（验证外层扫描不下钻内层 spawn 子树、不重复报）。
    let _ = tokio::spawn(async {
        let _ = tokio::spawn(async { try_current() });
    });

    // R5：同一子任务体内两处未重绑读——try_with 自身 + 其闭包内的 try_current，
    // 各属独立的未重绑 ctx 读，按设计**各报一次**（共 2 条）。
    let _ = tokio::spawn(async {
        let _ = try_with(|_| try_current());
    });
}

#[allow(rss_spawn_missing_scope)] // reason: UI fixture 验证逃生门
fn spawn_with_allow() {
    let _ = tokio::spawn(async { try_current() });
}
