#![allow(dead_code)]
//! 未知 sensitivity ⇒ 编译错误（sensitivity 闭值集）。
use securederive::Redact;

#[derive(Redact)]
struct Bad {
    #[redact(sensitivity = pii_vip)]
    x: String,
}

fn main() {}
