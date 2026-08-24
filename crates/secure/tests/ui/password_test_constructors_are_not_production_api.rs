use secure::{PasswordHash, RawPassword};

fn main() {
    let _ = PasswordHash::for_test(RawPassword::new("fixture".to_string()));
    let _ = PasswordHash::for_test_with_params(
        RawPassword::new("fixture".to_string()),
        8 * 1024,
        1,
        1,
    );
}
