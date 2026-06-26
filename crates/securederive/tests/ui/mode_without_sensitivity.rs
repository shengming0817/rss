#![allow(dead_code)]
//! mode 不能单独声明：字段必须先显式选择 sensitivity。
use securederive::Redact;

#[derive(Redact)]
struct Bad {
    #[redact(mode = "fixed")]
    x: String,
}

fn main() {}
