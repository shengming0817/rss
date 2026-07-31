// ambient `--cfg test` 下的生产 backoff：不得因 lib test 构建的 ambient cfg 误杀。
// golden 见 production_cfg_test.stderr（空 = 零诊断）。
#![allow(unused, unknown_lints, dead_code)]

use std::time::Duration;

fn production_backoff() {
    std::thread::sleep(Duration::from_millis(1));
}

async fn production_async_backoff() {
    tokio::time::sleep(Duration::from_millis(1)).await;
}

fn main() {
    production_backoff();
    let _ = production_async_backoff;
}
