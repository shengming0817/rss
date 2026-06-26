//! 防误标：`pii` 与 `mode = "hash"` 同用 ⇒ 编译错误（低熵 PII 不可用无盐 hash 脱敏）。

use securederive::Redact;

#[derive(Redact)]
struct BadPiiHash {
    #[redact(pii = "email", mode = "hash")]
    email: String,
}

fn main() {}
