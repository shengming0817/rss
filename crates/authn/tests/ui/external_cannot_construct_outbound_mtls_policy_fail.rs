//! fail：`OutboundMtlsPolicy` 字段私有，外部 crate 不能绕过 trust-domain / allow-set 构造器。

fn main() {
    let local_identity = authn::SpiffeId::parse("spiffe://example.org/ns/rss/sa/runtime").unwrap();
    let server_allow_set =
        authn::MtlsAllowSet::new(["spiffe://example.org/ns/rss/sa/identity"]).unwrap();
    let trust_domains = authn::MtlsTrustDomainAllowSet::new(["example.org"]).unwrap();

    let _policy = authn::OutboundMtlsPolicy {
        local_identity,
        server_allow_set,
        trust_domains,
    };
}
