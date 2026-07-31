//! 跨模块测试工具（仅 `#[cfg(test)]` 编译）。
//!
//! `unique_tmp`：基于 process id + 原子递增计数器生成唯一临时目录路径，
//! 避免并发测试在同一进程内路径碰撞。
#![cfg(test)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// 生成唯一临时目录路径（不自动创建，调用方负责 `fs::create_dir_all` 与清理）。
///
/// Base temp dir is canonicalized so macOS `/var` → `/private/var` aliases do not break
/// assembly-lock repository-root identity checks.
pub(crate) fn unique_tmp(prefix: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp = std::env::temp_dir();
    let temp = std::fs::canonicalize(&temp).unwrap_or(temp);
    temp.join(format!("rss-xtask-{prefix}-{}-{n}", std::process::id()))
}
