#[derive(privacy::Redact)]
struct Masked<T>(#[redact(sensitivity = pii_email)] T);

#[derive(Debug)]
struct DebugOnly;

fn main() {
    let value = Masked(DebugOnly);
    let _ = privacy::safe(&value, privacy::RedactScope::Wire);
}
