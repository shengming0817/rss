#![allow(dead_code)]
//! 未知 PII kind ⇒ 编译错误（PII 子类闭值集）。
use securederive::Redact;

#[derive(Redact)]
struct Bad {
    #[redact(pii = "vip")]
    x: String,
}

fn main() {}
