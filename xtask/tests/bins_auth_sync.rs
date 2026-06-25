//! `bins-auth-sync` 机器门（评审 F6，INVARIANT BINS-AUTH-SYNC-01）：`bins/server` 与 `bins/rss` 的认证接线
//! 文件须保持同步——把「字节级同步只靠注释」（AI-robust Soft）升为 nextest-gated 机器门（Medium）。
//!
//! 信任根逻辑（`auth_bridge.rs`）须**字节级相同**；`lib.rs` / `tests/auth_e2e.rs` 仅允许 crate 名/use 路径不同
//! （归一化后须相同）。任一其它行漂移（如只在一个 bin 改了验签桥）即此门红——杜绝信任根静默漂移。
//!
//! 逻辑增长时按 `tasks.md:57` 提取 `assemblies/authwire` 共享模块、删两份副本，本门随之删/改。

use std::path::PathBuf;

#[allow(clippy::expect_used)]
fn read(rel: &str) -> String {
    // CARGO_MANIFEST_DIR = .../xtask；父目录 = workspace 根。
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask 父目录 = workspace 根")
        .to_path_buf();
    std::fs::read_to_string(root.join(rel)).expect("读 bins 认证文件失败")
}

#[test]
fn auth_bridge_byte_identical() {
    assert_eq!(
        read("bins/server/src/auth_bridge.rs"),
        read("bins/rss/src/auth_bridge.rs"),
        "两 bin 的 auth_bridge.rs（验签桥 = 信任根逻辑）须字节级同步；漂移即此门红"
    );
}

#[test]
fn lib_identical_modulo_crate_doc() {
    let server = read("bins/server/src/lib.rs");
    let rss = read("bins/rss/src/lib.rs").replace("//! rss —", "//! server —");
    assert_eq!(
        server, rss,
        "两 bin 的 lib.rs 须仅 crate doc 首行不同；其它行漂移即此门红"
    );
}

#[test]
fn e2e_identical_modulo_crate_use() {
    let server = read("bins/server/tests/auth_e2e.rs");
    let rss = read("bins/rss/tests/auth_e2e.rs").replace("use rss::", "use server::");
    assert_eq!(
        server, rss,
        "两 bin 的 auth_e2e.rs 须仅 use 路径不同；其它行漂移即此门红"
    );
}
