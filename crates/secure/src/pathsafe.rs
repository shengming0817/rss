//! 路径分量安全判定（防逃逸）。

/// 判定单个路径分量是否安全（无 `..` / 分隔符 / 控制字符等）。
pub fn is_safe_segment(_segment: &str) -> bool {
    todo!()
}
