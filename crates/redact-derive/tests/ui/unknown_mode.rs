#![allow(dead_code)]
//! 未知 mode ⇒ 编译错误（mode 闭值集，拼写错不静默）。
use rss_redact_derive::Redact;

#[derive(Redact)]
struct Bad {
    #[redact(sensitivity = public, mode = "bogus")]
    x: String,
}

fn main() {}
