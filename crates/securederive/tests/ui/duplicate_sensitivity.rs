#![allow(dead_code)]
//! 重复 sensitivity ⇒ 编译错误。
use securederive::Redact;

#[derive(Redact)]
struct Bad {
    #[redact(sensitivity = public, sensitivity = secret)]
    x: String,
}

fn main() {}
