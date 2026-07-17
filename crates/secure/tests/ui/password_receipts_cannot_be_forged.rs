use secure::{RawPassword, ValidatedPassword};

fn main() {
    let raw = RawPassword::new("not-policy-approved".to_string());
    let _ = ValidatedPassword(raw);
}
