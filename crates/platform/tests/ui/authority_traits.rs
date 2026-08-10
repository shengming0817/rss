use rss_platform::AccessToken;

fn require_clone<T: Clone>(_: &T) {}
fn require_debug<T: std::fmt::Debug>(_: &T) {}

fn main() {
    let token = AccessToken::parse("header.payload.signature").unwrap();
    require_clone(&token);
    require_debug(&token);
}
