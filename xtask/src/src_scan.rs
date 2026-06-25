//! 生产源文件系统扫描工具（`pdpallow` 与 `command_symmetry` 共用文件遍历层）。
//!
//! 抽出纯文件系统辅助（`member_dirs` / `rs_files` / `is_excluded` + `SCAN_EXCLUDED_SEGMENTS`），
//! 消除两模块间重复。**扫描根集不在此共享**——二者根集不同（`pdpallow` 限 `crates/bins`，排
//! `adapters/*` legit Pdp impl 站点；`command_symmetry` 须覆盖 `adapters` / `journeys` 等组合根），
//! 各模块自带根集（曾共享 `PROD_ROOTS` 是缺陷，#1124 review F5 修）。
//!
//! `strip_comments` 仅 `pdpallow` 的 attribute text-scan 使用；`command_symmetry` 已改 `syn` AST 扫描
//! （#1124 review F4），AST 天然忽略字符串 / 注释内同名文本，无 text-scan 盲区。
//!
//! 盲区（AI-robust 写明，仅 `strip_comments` text-scan 适用）：对字符串字面量仅保留引号分隔符、
//! 内容被丢弃，故字面量内的禁用模式**不会**被扫到——已知、已测盲区（详见 `pdpallow` 的
//! `#[cfg(test)]`）。raw string（`r"..."`）不特判（罕见）。

use std::path::{Path, PathBuf};

use anyhow::Result;

/// 扫描中显式排除的路径段（按 member 目录名末端段匹配）。
///
/// - `eventexec`：sanctioned runtime 宿主（`command::emit_async` 声明处，合法）。
/// - `generated`：codegen 派生，非生产业务代码。
/// - `xtask`：治理工具自身，含演示串，不扫。
/// - `lints`：dylint crate 独立 workspace，不扫。
///
/// INVARIANT: COMMAND-SYMMETRY-01 + PDP-ALLOW-CONFINE-01 的路径排除约定。
pub(crate) const SCAN_EXCLUDED_SEGMENTS: &[&str] = &["eventexec", "generated", "xtask", "lints"];

/// 判断路径的末端目录段（`file_name()`）是否在显式排除列表中。
pub(crate) fn is_excluded(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|name| SCAN_EXCLUDED_SEGMENTS.contains(&name))
}

/// `top_dir` 下的直接子目录（workspace 成员目录；`top_dir` 不存在 → 空）。
pub(crate) fn member_dirs(top_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !top_dir.is_dir() {
        return Ok(out);
    }
    let entries = std::fs::read_dir(top_dir)
        .map_err(|e| anyhow::anyhow!("src_scan: 读目录 {} 失败: {e}", top_dir.display()))?;
    for entry in entries {
        let path = entry
            .map_err(|e| anyhow::anyhow!("src_scan: 遍历 {} 失败: {e}", top_dir.display()))?
            .path();
        if path.is_dir() {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// 递归收集 `dir` 下全部 `.rs` 文件（目录不存在 → 空，由 canary 兜底）。
pub(crate) fn rs_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !dir.is_dir() {
        return Ok(out);
    }
    let entries = std::fs::read_dir(dir)
        .map_err(|e| anyhow::anyhow!("src_scan: 读目录 {} 失败: {e}", dir.display()))?;
    for entry in entries {
        let path = entry
            .map_err(|e| anyhow::anyhow!("src_scan: 遍历 {} 失败: {e}", dir.display()))?
            .path();
        if path.is_dir() {
            out.extend(rs_files(&path)?);
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// string-aware 去 `//` 行注释 + `/* */` 块注释（保留 `\n` 供行号计算；保留字符串字面量引号，
/// 丢弃字面量内容）。
///
/// # 盲区
///
/// - **字符串字面量内容**：字面量内的禁用模式（如 `"command::emit_async"`）在 strip 后不存在，
///   故**不会**被下游扫描命中——属于已知盲区。调用方须避免把字面量内的演示串错误期望为 finding。
///   各使用模块的 `#[cfg(test)]` 含针对此盲区的测试（`string_literal_blind_spot_pinned`）。
/// - **raw string**（`r"..."`）：不特判（罕见）。
pub(crate) fn strip_comments(src: &str) -> String {
    #[derive(PartialEq)]
    enum St {
        Code,
        Line,
        Block,
        Str,
    }
    let mut out = String::with_capacity(src.len());
    let mut chars = src.chars().peekable();
    let mut st = St::Code;
    while let Some(c) = chars.next() {
        match st {
            St::Code => match c {
                '/' if chars.peek() == Some(&'/') => {
                    chars.next();
                    st = St::Line;
                }
                '/' if chars.peek() == Some(&'*') => {
                    chars.next();
                    st = St::Block;
                }
                '"' => {
                    st = St::Str;
                    out.push('"');
                }
                _ => out.push(c),
            },
            St::Line => {
                if c == '\n' {
                    st = St::Code;
                    out.push('\n');
                }
            }
            St::Block => {
                if c == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    st = St::Code;
                } else if c == '\n' {
                    out.push('\n');
                }
            }
            St::Str => match c {
                '\\' => {
                    chars.next();
                }
                '"' => {
                    st = St::Code;
                    out.push('"');
                }
                '\n' => out.push('\n'),
                _ => {} // 字符串内容丢弃（盲区：详见函数 doc）
            },
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// strip_comments 基础行为：行注释被剥，块注释被剥，保留换行。
    #[test]
    fn strip_comments_removes_line_and_block_comments() {
        assert_eq!(strip_comments("// foo\nbar\n"), "\nbar\n");
        assert_eq!(strip_comments("/* foo */bar\n"), "bar\n");
        assert_eq!(strip_comments("a/* x\ny */b\n"), "a\nb\n");
    }

    /// string-literal 盲区：字面量内容（引号之间）被丢弃，故内部的禁用模式不被命中。
    /// 此为**已知设计盲区**，本测试钉住当前行为（防静默改变）。
    /// 调用方（command_symmetry / pdpallow）扫描范围不含工具自身源，从而避开误报。
    #[test]
    fn string_literal_blind_spot_pinned() {
        // 字符串字面量内的 "command::emit_async" 在 strip 后消失（内容被丢弃）。
        let src = r#"let x = "command::emit_async";"#;
        let stripped = strip_comments(src);
        // 引号保留，内容消失：只剩 `let x = "";`
        assert!(
            !stripped.contains("command::emit_async"),
            "字面量内容在 strip 后不应可见（盲区确认）：{stripped:?}"
        );
        assert!(
            stripped.contains("\"\""),
            "引号分隔符应保留（代码结构不被破坏）：{stripped:?}"
        );
    }

    /// is_excluded：列表内的段返回 true，其他返回 false。
    #[test]
    fn is_excluded_matches_known_segments() {
        for seg in SCAN_EXCLUDED_SEGMENTS {
            let p = std::path::PathBuf::from(format!("/some/path/{seg}"));
            assert!(is_excluded(&p), "应排除 {seg}");
        }
        let included = std::path::PathBuf::from("/some/path/identity");
        assert!(!is_excluded(&included), "identity 不在排除列表");
    }

    /// is_excluded 测试：显式排除路径（作为 BareEmitExit 排除约定的文档测试）。
    #[test]
    fn excluded_paths_are_skipped() {
        // 以下路径段须在排除列表中——此为 COMMAND-SYMMETRY-01 + PDP-ALLOW-CONFINE-01 约定。
        assert!(is_excluded(&std::path::PathBuf::from(
            "/workspace/crates/eventexec"
        )));
        assert!(is_excluded(&std::path::PathBuf::from(
            "/workspace/generated"
        )));
        assert!(is_excluded(&std::path::PathBuf::from("/workspace/xtask")));
        // lints/ 在 workspace 根（非 crates/bins/ 下），不会被 member_dirs 枚举到；
        // 但 "lints" 在排除列表中，若 member_dirs 结果含此段则会被跳过。
        assert!(is_excluded(&std::path::PathBuf::from("/workspace/lints")));
        // 非排除路径不在列表中。
        assert!(!is_excluded(&std::path::PathBuf::from(
            "/workspace/crates/identity"
        )));
        assert!(!is_excluded(&std::path::PathBuf::from(
            "/workspace/bins/rss-server"
        )));
    }
}
