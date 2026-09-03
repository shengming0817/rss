#![allow(dead_code)]
//! 重复 sensitivity ⇒ 编译错误。
use rss_redact_derive::Redact;

#[derive(Redact)]
struct Bad {
    #[redact(sensitivity = public, sensitivity = secret)]
    x: String,
}

fn main() {}
