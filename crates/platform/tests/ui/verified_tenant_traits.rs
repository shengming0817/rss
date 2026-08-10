use rss_platform::VerifiedTenant;

fn require_clone<T: Clone>() {}
fn require_debug<T: std::fmt::Debug>() {}

fn main() {
    require_clone::<VerifiedTenant<'static>>();
    require_debug::<VerifiedTenant<'static>>();
}
