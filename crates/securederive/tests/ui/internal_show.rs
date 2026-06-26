#![allow(dead_code)]
//! 防误标：`sensitivity = internal` 与 `mode = show` 同用 ⇒ 编译错误（Internal 不进 Debug，明文输出矛盾）。
use securederive::Redactable;

#[derive(Redactable)]
struct Bad {
    #[redact(sensitivity = internal, mode = show)]
    note: String,
}

fn main() {}
