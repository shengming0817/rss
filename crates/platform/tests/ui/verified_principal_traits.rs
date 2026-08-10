use rss_platform::VerifiedPrincipal;

fn require_clone<T: Clone>() {}
fn require_debug<T: std::fmt::Debug>() {}

fn main() {
    require_clone::<VerifiedPrincipal<'static>>();
    require_debug::<VerifiedPrincipal<'static>>();
}
