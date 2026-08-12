fn assert_clone<T: Clone>() {}

fn main() {
    assert_clone::<httpserve::AuthorizationProvenance>();
}
