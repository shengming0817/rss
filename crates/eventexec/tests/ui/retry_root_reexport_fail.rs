use eventexec::{BackoffError, BackoffPolicy};

fn main() {
    let _ = BackoffPolicy::default();
    let _: Option<BackoffError> = None;
}
