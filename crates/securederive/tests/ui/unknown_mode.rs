#![allow(dead_code)]
//! 未知 mode ⇒ 编译错误（mode 闭值集，拼写错不静默）。
use securederive::Redact;

#[derive(Redact)]
struct Bad {
    #[redact(public, mode = "bogus")]
    x: String,
}

fn main() {}
