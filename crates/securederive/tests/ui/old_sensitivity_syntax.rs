//! 旧 `public/internal/secret` 裸 key 语法已移除，不保留兼容别名。

#[derive(securederive::Redact)]
struct BadPublic {
    #[redact(public)]
    x: String,
}

#[derive(securederive::Redact)]
struct BadInternal {
    #[redact(internal)]
    x: String,
}

#[derive(securederive::Redact)]
struct BadSecret {
    #[redact(secret)]
    x: String,
}

fn main() {}
