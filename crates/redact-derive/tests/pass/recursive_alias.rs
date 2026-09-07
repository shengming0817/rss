use privacy::Redact;
type Link<T> = Option<Box<Node<T>>>;
#[derive(Redact)]
#[redact(bound = "T: std::fmt::Debug")]
struct Node<T> {
    #[redact(sensitivity = public)]
    value: T,
    #[redact(sensitivity = public)]
    next: Link<T>,
}
struct Opaque;
type HiddenLink<T> = Option<Box<HiddenNode<T>>>;
#[derive(Redact)]
#[redact(bound = "")]
struct HiddenNode<T> {
    #[redact(sensitivity = secret)]
    hidden: T,
    #[redact(sensitivity = public)]
    next: HiddenLink<T>,
}
fn main() {
    assert!(format!("{:?}", HiddenNode { hidden: Opaque, next: None }).contains("<redacted>"));
    assert!(format!("{:?}", Node { value: 1u8, next: None }).contains("value: 1"));
}
