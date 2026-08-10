use rss_platform::VerifiedAccess;

fn require_clone<T: Clone>() {}
fn require_debug<T: std::fmt::Debug>() {}

fn main() {
    require_clone::<VerifiedAccess>();
    require_debug::<VerifiedAccess>();
}
