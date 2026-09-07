#[derive(privacy::Redact)]
struct Visible<T>(#[redact(sensitivity = public)] T);

struct Opaque;

fn main() {
    let value = Visible(Opaque);
    let _ = format!("{value:?}");
}
