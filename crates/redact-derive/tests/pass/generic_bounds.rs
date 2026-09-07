use privacy::{Redact, RedactScope};
use std::marker::PhantomData;

#[derive(Debug)]
struct DebugOnly;
struct Opaque;

#[derive(Redact)]
struct Visible<T> {
    #[redact(sensitivity = public)]
    value: T,
}

#[derive(Redact)]
struct Masked<T>(#[redact(sensitivity = pii_email)] T);

#[derive(Redact)]
struct Hidden<T, U> {
    #[redact(sensitivity = secret, mode = "fixed")]
    fixed: T,
    #[redact(sensitivity = secret, mode = "drop")]
    dropped: U,
}

trait Item { type Value; }
impl Item for Opaque { type Value = String; }

#[derive(Redact)]
struct Associated<'a, T: Item, const N: usize>
where T::Value: 'a,
{
    #[redact(sensitivity = pii_phone)]
    value: T::Value,
    #[redact(sensitivity = public)]
    marker: PhantomData<&'a T>,
    #[redact(sensitivity = public)]
    bytes: [u8; N],
}

fn main() {
    let result = ResultNode { hidden: Opaque, both: Err(DebugOnly) };
    assert!(format!("{result:?}").contains("DebugOnly"));
    let mixed = MixedNode { hidden: Opaque, both: (None, DebugOnly) };
    assert!(format!("{mixed:?}").contains("DebugOnly"));
    assert_eq!(format!("{:?}", Node { next: None }), "Node { next: None }");
    let recursive = GenericNode { value: DebugOnly, next: None };
    assert!(format!("{recursive:?}").contains("DebugOnly"));
    assert_eq!(format!("{:?}", Visible { value: DebugOnly }), "Visible { value: DebugOnly }");
    let masked = Masked("alice@example.com".to_owned());
    assert_eq!(masked.redact_scoped(RedactScope::Wire), "Masked(<redacted>)");
    assert_eq!(format!("{:?}", Hidden { fixed: Opaque, dropped: Opaque }), "Hidden { fixed: <redacted> }");
    let associated = Associated::<'_, Opaque, 2> { value: "123456".into(), marker: PhantomData, bytes: [1, 2] };
    assert!(format!("{associated:?}").contains("****3456"));
}

#[derive(Redact)]
struct Node {
    #[redact(sensitivity = public)]
    next: Option<Box<Node>>,
}

#[derive(Redact)]
#[redact(bound = "T: std::fmt::Debug")]
struct GenericNode<T> {
    #[redact(sensitivity = public)]
    value: T,
    #[redact(sensitivity = public)]
    next: Option<Box<GenericNode<T>>>,
}


#[derive(Redact)]
#[redact(bound = "U: std::fmt::Debug")]
struct MixedNode<T, U> {
    #[redact(sensitivity = secret)]
    hidden: T,
    #[redact(sensitivity = public)]
    both: (Option<Box<MixedNode<T, U>>>, U),
}


#[derive(Redact)]
#[redact(bound = "U: std::fmt::Debug")]
struct ResultNode<T, U> {
    #[redact(sensitivity = secret)]
    hidden: T,
    #[redact(sensitivity = public)]
    both: Result<Box<ResultNode<T, U>>, U>,
}
