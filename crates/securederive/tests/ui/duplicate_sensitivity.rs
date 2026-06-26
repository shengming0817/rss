#![allow(dead_code)]
//! 重复 sensitivity ⇒ 编译错误（public/internal/secret/pii 必须四选一）。
use securederive::Redact;

#[derive(Redact)]
struct Bad {
    #[redact(public, secret)]
    x: String,
}

fn main() {}
