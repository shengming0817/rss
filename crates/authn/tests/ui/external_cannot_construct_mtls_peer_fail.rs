//! fail：`VerifiedMtlsPeer` 字段私有，外部 crate 不能用 struct 字面量伪造
//! 已经通过 TLS/SPIFFE allow-set 的 peer evidence。
fn main() {
    let id = authn::SpiffeId::parse("spiffe://example.org/ns/rss/sa/internal").unwrap();

    let _ = authn::VerifiedMtlsPeer {
        spiffe_id: id,
    }; // E0451: 私有字段不可达
}
