// rss_test_no_bare_sleep UI fixture（dylint_testing::ui::Test + rustc_flags --test）。
// golden 见 main.stderr：
//   RED：#[test] / #[tokio::test] 内裸 std::thread::sleep / tokio::time::sleep（含 use 导入）
//   RED：#[cfg(test)] mod helper 内裸 sleep（非 #[test] 函数，靠显式 cfg(test) mod）
//   GREEN：item-level #[allow(rss_test_no_bare_sleep)] 逃生
// 生产/not(test) 绿例见 production*.rs；/tests/ 路径由 path_contains_tests_segment 单测锁。
#![allow(unused, unknown_lints, dead_code)]

use std::time::Duration;
use tokio::time::sleep as imported_sleep;

// R1：#[test] + std::thread::sleep → 触发。
#[test]
fn bare_thread_sleep() {
    std::thread::sleep(Duration::from_millis(1));
}

// R2：#[tokio::test] + tokio::time::sleep → 触发。
#[tokio::test]
async fn bare_tokio_sleep() {
    tokio::time::sleep(Duration::from_millis(1)).await;
}

// R3：use 导入的 sleep（time::sleep 形态）→ 触发。
#[tokio::test]
async fn bare_imported_sleep() {
    imported_sleep(Duration::from_millis(1)).await;
}

// R4：显式 #[cfg(test)] mod 内 helper（非 #[test]）裸 sleep → 触发。
#[cfg(test)]
mod helpers {
    use std::time::Duration;

    pub fn helper_bare_sleep() {
        std::thread::sleep(Duration::from_millis(1));
    }
}

// G1：item-level #[allow] 逃生门 → 不触发。
#[allow(rss_test_no_bare_sleep)] // reason: UI fixture 验证逃生门
#[test]
fn allowed_bare_sleep() {
    std::thread::sleep(Duration::from_millis(1));
}

fn main() {
    #[cfg(test)]
    helpers::helper_bare_sleep();
}
