//! 路径分量安全判定（防逃逸）。

/// 判定单个路径分量是否安全（无 `..` / 分隔符 / 控制字符等）。
///
/// 仅校验单个**已解码**路径分量；调用方须先 URL-decode；
/// 不做 Windows 设备名 / Unicode 规范化过滤。
pub fn is_safe_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != ".."
        && segment != "."
        && !segment.contains(['/', '\\'])
        && !segment.chars().any(|c| c.is_control())
}

#[cfg(test)]
mod tests {
    use super::is_safe_segment;

    #[test]
    fn accepts_normal_segment() {
        assert!(is_safe_segment("foo"));
        assert!(is_safe_segment("foo.txt"));
        assert!(is_safe_segment("foo-bar_baz"));
        assert!(is_safe_segment("日本語"));
    }

    #[test]
    fn rejects_empty() {
        assert!(!is_safe_segment(""));
    }

    #[test]
    fn rejects_dot_dot() {
        assert!(!is_safe_segment(".."));
    }

    #[test]
    fn rejects_single_dot() {
        assert!(!is_safe_segment("."));
    }

    #[test]
    fn rejects_forward_slash() {
        assert!(!is_safe_segment("foo/bar"));
    }

    #[test]
    fn rejects_backslash() {
        assert!(!is_safe_segment("foo\\bar"));
    }

    #[test]
    fn rejects_control_characters() {
        assert!(!is_safe_segment("foo\x00bar"));
        assert!(!is_safe_segment("foo\nbar"));
        assert!(!is_safe_segment("foo\x1fbar"));
    }
}
