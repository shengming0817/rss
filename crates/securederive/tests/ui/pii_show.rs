#![allow(dead_code)]
//! 防误标：`pii` 与 `mode = "show"` 同用 ⇒ 编译错误（PII 字段不可声明明文输出）。
use securederive::Redact;

#[derive(Redact)]
struct Bad {
    #[redact(sensitivity = pii_email, mode = "show")]
    email: String,
}

fn main() {}
