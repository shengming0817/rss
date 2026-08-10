use std::net::{IpAddr, SocketAddr};

use axum::extract::ConnectInfo;
use axum::http::{HeaderValue, Request};
use httpserve::{ResolvedClientIp, TrustedProxyConfig};

#[allow(clippy::expect_used)]
// reason: fixed socket/header fixtures are valid by construction; failure is a test defect.
fn request(peer: &str, xff: Option<HeaderValue>, x_real_ip: Option<HeaderValue>) -> Request<()> {
    let mut request = Request::new(());
    request.extensions_mut().insert(ConnectInfo(
        peer.parse::<SocketAddr>().expect("valid peer socket"),
    ));
    if let Some(value) = xff {
        request.headers_mut().insert("x-forwarded-for", value);
    }
    if let Some(value) = x_real_ip {
        request.headers_mut().insert("x-real-ip", value);
    }
    request
}

#[test]
#[allow(clippy::expect_used)]
// reason: fixed IP/CIDR literals are valid test fixtures.
fn disabled_and_untrusted_peer_ignore_forwarding_headers() {
    let spoofed = HeaderValue::from_static("198.51.100.7");
    let disabled = TrustedProxyConfig::disabled();
    let disabled_request = request("10.0.0.4:443", Some(spoofed.clone()), None);
    assert_eq!(
        disabled
            .resolve(&disabled_request)
            .map(ResolvedClientIp::get),
        Some("10.0.0.4".parse::<IpAddr>().expect("valid IP"))
    );

    let trusted =
        TrustedProxyConfig::try_from_json(Some(r#"["192.0.2.0/24"]"#)).expect("valid CIDR");
    let untrusted_request = request("10.0.0.4:443", Some(spoofed), None);
    assert_eq!(
        trusted
            .resolve(&untrusted_request)
            .map(ResolvedClientIp::get),
        Some("10.0.0.4".parse::<IpAddr>().expect("valid IP"))
    );
}

#[test]
#[allow(clippy::expect_used)]
// reason: fixed IP/CIDR literals are valid test fixtures.
fn trusted_peer_strips_proxy_chain_from_the_right() {
    let trusted = TrustedProxyConfig::try_from_json(Some(r#"["10.0.0.0/8","2001:db8:ffff::/48"]"#))
        .expect("valid CIDRs");
    let request = request(
        "10.0.0.4:443",
        Some(HeaderValue::from_static(
            "2001:db8::7, 2001:db8:ffff::2, 10.0.0.9",
        )),
        None,
    );
    assert_eq!(
        trusted.resolve(&request).map(ResolvedClientIp::get),
        Some("2001:db8::7".parse::<IpAddr>().expect("valid IP"))
    );
}

#[test]
#[allow(clippy::expect_used)]
// reason: fixed IP/CIDR literals are valid test fixtures.
fn malformed_or_ambiguous_xff_falls_back_to_peer_without_x_real_ip() {
    let trusted = TrustedProxyConfig::try_from_json(Some(r#"["10.0.0.0/8"]"#)).expect("valid CIDR");
    let request = request(
        "10.0.0.4:443",
        Some(HeaderValue::from_static("198.51.100.7,,10.0.0.9")),
        Some(HeaderValue::from_static("203.0.113.9")),
    );
    assert_eq!(
        trusted.resolve(&request).map(ResolvedClientIp::get),
        Some("10.0.0.4".parse::<IpAddr>().expect("valid IP"))
    );
}

#[test]
#[allow(clippy::expect_used)]
// reason: fixed IP/CIDR literals are valid test fixtures.
fn x_real_ip_is_used_only_when_xff_is_absent() {
    let trusted = TrustedProxyConfig::try_from_json(Some(r#"["10.0.0.0/8"]"#)).expect("valid CIDR");
    let request = request(
        "10.0.0.4:443",
        None,
        Some(HeaderValue::from_static("203.0.113.9")),
    );
    assert_eq!(
        trusted.resolve(&request).map(ResolvedClientIp::get),
        Some("203.0.113.9".parse::<IpAddr>().expect("valid IP"))
    );
}

#[test]
#[allow(clippy::expect_used)]
// reason: fixed IP/CIDR/header fixtures are valid by construction.
fn duplicate_non_utf8_oversized_and_too_many_hops_fall_back_to_peer() {
    let trusted = TrustedProxyConfig::try_from_json(Some(r#"["10.0.0.0/8"]"#)).expect("valid CIDR");
    let peer = "10.0.0.4".parse::<IpAddr>().expect("valid IP");

    let mut duplicate = request(
        "10.0.0.4:443",
        Some(HeaderValue::from_static("198.51.100.7")),
        None,
    );
    duplicate
        .headers_mut()
        .append("x-forwarded-for", HeaderValue::from_static("203.0.113.9"));

    let non_utf8 = request(
        "10.0.0.4:443",
        Some(HeaderValue::from_bytes(&[0xff]).expect("opaque header bytes")),
        None,
    );
    let oversized = request(
        "10.0.0.4:443",
        Some(HeaderValue::from_str(&"1".repeat(4 * 1024 + 1)).expect("large header")),
        None,
    );
    let too_many = request(
        "10.0.0.4:443",
        Some(
            HeaderValue::from_str(
                &std::iter::repeat_n("10.0.0.9", 33)
                    .collect::<Vec<_>>()
                    .join(","),
            )
            .expect("many hops"),
        ),
        None,
    );

    for ambiguous in [&duplicate, &non_utf8, &oversized, &too_many] {
        assert_eq!(
            trusted.resolve(ambiguous).map(ResolvedClientIp::get),
            Some(peer)
        );
    }
}

#[test]
#[allow(clippy::expect_used)]
// reason: fixed IP/CIDR literals are valid test fixtures.
fn all_trusted_chain_and_missing_transport_peer_fail_closed() {
    let trusted = TrustedProxyConfig::try_from_json(Some(r#"["10.0.0.0/8"]"#)).expect("valid CIDR");
    let all_trusted = request(
        "10.0.0.4:443",
        Some(HeaderValue::from_static("10.0.0.8,10.0.0.9")),
        None,
    );
    assert_eq!(
        trusted.resolve(&all_trusted).map(ResolvedClientIp::get),
        Some("10.0.0.4".parse::<IpAddr>().expect("valid IP"))
    );
    assert_eq!(trusted.resolve(&Request::new(())), None);
}

#[test]
#[allow(clippy::expect_used)]
// reason: fixed IP/CIDR/header fixtures are valid by construction.
fn x_real_ip_ambiguity_and_trusted_address_fall_back_to_peer() {
    let trusted = TrustedProxyConfig::try_from_json(Some(r#"["10.0.0.0/8"]"#)).expect("valid CIDR");
    let peer = "10.0.0.4".parse::<IpAddr>().expect("valid IP");
    let mut duplicate = request(
        "10.0.0.4:443",
        None,
        Some(HeaderValue::from_static("198.51.100.7")),
    );
    duplicate
        .headers_mut()
        .append("x-real-ip", HeaderValue::from_static("203.0.113.9"));
    let invalid = request(
        "10.0.0.4:443",
        None,
        Some(HeaderValue::from_static("not-an-ip")),
    );
    let non_utf8 = request(
        "10.0.0.4:443",
        None,
        Some(HeaderValue::from_bytes(&[0xff]).expect("opaque header bytes")),
    );
    let oversized = request(
        "10.0.0.4:443",
        None,
        Some(HeaderValue::from_str(&"1".repeat(4 * 1024 + 1)).expect("large header")),
    );
    let trusted_address = request(
        "10.0.0.4:443",
        None,
        Some(HeaderValue::from_static("10.0.0.9")),
    );

    for ambiguous in [
        &duplicate,
        &invalid,
        &non_utf8,
        &oversized,
        &trusted_address,
    ] {
        assert_eq!(
            trusted.resolve(ambiguous).map(ResolvedClientIp::get),
            Some(peer)
        );
    }
}

#[test]
fn universal_networks_are_not_valid_trusted_proxy_boundaries() {
    assert!(TrustedProxyConfig::try_from_json(Some(r#"["0.0.0.0/0"]"#)).is_err());
    assert!(TrustedProxyConfig::try_from_json(Some(r#"["::/0"]"#)).is_err());
    assert!(
        TrustedProxyConfig::try_from_json(Some(r#"["10.0.0.0/8","0.0.0.0/0"]"#)).is_err(),
        "one universal member must reject the whole policy"
    );
}
