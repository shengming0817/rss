#![allow(dead_code)]
//! fail-closed：字段缺 `#[redact(...)]` ⇒ 编译错误（忘标脱敏的 secret 字段不可表达）。
use securederive::Redactable;

#[derive(Redactable)]
struct Bad {
    plain: String,
}

fn main() {}
