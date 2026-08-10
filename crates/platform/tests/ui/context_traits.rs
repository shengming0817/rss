use rss_platform::RequestContext;

fn require_clone<T: Clone>() {}
fn require_debug<T: std::fmt::Debug>() {}

fn main() {
    require_clone::<RequestContext<'static>>();
    require_debug::<RequestContext<'static>>();
}
