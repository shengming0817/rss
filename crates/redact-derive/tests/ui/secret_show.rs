#![allow(dead_code)]
//! 防误标：`secret` 与 `mode = "show"` 同用 ⇒ 编译错误（敏感字段不可声明明文输出）。
use rss_redact_derive::Redact;

#[derive(Redact)]
struct Bad {
    #[redact(sensitivity = secret, mode = "show")]
    leaky: String,
}

fn main() {}
