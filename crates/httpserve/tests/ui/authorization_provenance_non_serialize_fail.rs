use httpserve::AuthorizationProvenance;

fn assert_serialize<T: serde::Serialize>() {}

fn main() {
    assert_serialize::<AuthorizationProvenance>();
}
