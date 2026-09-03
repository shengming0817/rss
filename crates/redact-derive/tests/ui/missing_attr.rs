#![allow(dead_code)]
//! fail-closed：字段缺 `#[redact(...)]` ⇒ 编译错误（忘标脱敏的 secret 字段不可表达）。
use rss_redact_derive::Redact;

#[derive(Redact)]
struct Bad {
    plain: String,
}

fn main() {}
