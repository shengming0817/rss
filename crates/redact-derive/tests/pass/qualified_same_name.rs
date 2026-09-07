use privacy::Redact;
mod other {
    pub trait Printable {}
    pub struct Opaque;
    impl Printable for Opaque {}
    pub struct Node<T>(pub T);
    impl<T: Printable> std::fmt::Debug for Node<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("opaque wrapper")
        }
    }
}
#[derive(Redact)]
struct Node<T> {
    #[redact(sensitivity = public)]
    value: other::Node<T>,
}
fn main() {
    assert!(format!("{:?}", Node { value: other::Node(other::Opaque) }).contains("opaque wrapper"));
}
