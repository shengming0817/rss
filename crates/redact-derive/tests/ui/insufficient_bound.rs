use privacy::Redact;
#[derive(Redact)]
#[redact(bound = "")]
struct Visible<T> {
    #[redact(sensitivity = public)]
    value: T,
}
fn main() {}
