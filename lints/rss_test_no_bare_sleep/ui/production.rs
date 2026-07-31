// rss_test_no_bare_sleep 生产绿例：非 test 上下文的 backoff sleep 不触发。
// golden 见 production.stderr（空 = 零诊断）。
// G-not：`#[cfg(not(test))]` 不得因 token/cfg 含字面 `test` 被误判为测试上下文。
#![allow(unused, unknown_lints, dead_code)]

use std::time::Duration;

fn production_backoff() {
    std::thread::sleep(Duration::from_millis(1));
}

async fn production_async_backoff() {
    tokio::time::sleep(Duration::from_millis(1)).await;
}

#[cfg(not(test))]
mod not_test_gated {
    use std::time::Duration;

    pub fn backoff() {
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn main() {
    production_backoff();
    let _ = production_async_backoff;
    #[cfg(not(test))]
    not_test_gated::backoff();
}
