//! 路径分量安全（防 `../` 逃逸）——codegen 写盘与 validate R6/R7 共用单源。
//!
//! INVARIANT: CONTRACT-FREEZE-01 { level = "Medium", exec = "verify", source = "code" }（运行期部分）— 声明 / 派生的文件名与路径段须为纯安全段，
//! 不含父目录 / 绝对 / 分隔符分量，杜绝 authoring 字段拼进生成路径时的逃逸。
//! 此前同一逻辑散落 codegen `validate_schema_filename` 与 validate `rule_unsafe_schema_path` 两处，
//! 加 codegen module 名守卫后成第三处——收口于此单源（DRY），双侧引用。

use std::path::{Component, Path};

/// 文件名 / 路径段是否含路径分量（`..`、绝对路径、`/`、`\`）。`true` = 不安全（须拒绝）。
///
/// 纯文件名（如 `request.schema.json`、`_seed_v1`）返回 `false`；
/// `../x`、`/etc`、`a/b`、`a\b` 返回 `true`。
pub(crate) fn is_unsafe_segment(s: &str) -> bool {
    let has_path_component = Path::new(s).components().any(|c| {
        matches!(
            c,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    });
    has_path_component || s.contains('/') || s.contains('\\')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pure_filenames_are_safe() {
        for ok in ["request.schema.json", "_seed_v1", "identity_v1", "a.rs"] {
            assert!(!is_unsafe_segment(ok), "{ok} 应安全");
        }
    }

    #[test]
    fn path_components_are_unsafe() {
        // anti-vacuity（负向）：父目录 / 绝对 / 分隔符任一即不安全。
        for bad in ["../x", "..", "/etc/passwd", "a/b", "a\\b", "sub/dir/x.rs"] {
            assert!(is_unsafe_segment(bad), "{bad} 应不安全");
        }
    }
}
