//! fail：`VerifiedMtlsPeer::seal` 是 `pub(crate)`，外部 crate 不能绕过 TLS/SPIFFE
//! allow-set verifier 直接 mint peer evidence。
fn main() {
    let id = authn::SpiffeId::parse("spiffe://example.org/ns/rss/sa/internal").unwrap();
    let _ = authn::VerifiedMtlsPeer::seal(id); // E0624: associated function `seal` is private
}
