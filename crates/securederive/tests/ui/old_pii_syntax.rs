#![allow(dead_code)]
//! 旧 `pii = "..."` 语法已移除，不保留兼容别名。
use securederive::Redact;

#[derive(Redact)]
struct Bad {
    #[redact(pii = "generic")]
    subject: String,
}

fn main() {}
