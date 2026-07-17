struct AdHocBlocklist;

impl secure::PasswordBlocklist for AdHocBlocklist {
    fn contains(&self, _digest: &secure::PasswordDigest) -> bool {
        false
    }
}

fn main() {}
