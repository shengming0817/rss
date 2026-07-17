use secure::{PasswordHash, RawPassword};

fn main() {
    let _ = PasswordHash::for_test_with_params(
        RawPassword::new("legacy".to_string()),
        8 * 1024,
        1,
        1,
    );
}
