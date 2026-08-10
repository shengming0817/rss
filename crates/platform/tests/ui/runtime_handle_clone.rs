fn require_clone<T: Clone>() {}

fn main() { require_clone::<rss_platform::RuntimeHandle>(); }
