use secure::{PasswordHash, RawPassword};

fn main() {
    let _ = PasswordHash::for_test(RawPassword::new("legacy".to_string()));
}
