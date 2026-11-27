fn main() {
    use rss_identity_web_credentials::{BrowserBinding, bearer_presentation, cookie_presentation};
    let mut h = http::HeaderMap::new();
    let binding = BrowserBinding::start(&h).unwrap();
    assert!(binding.set_cookie.unwrap().is_sensitive());
    h.insert("cookie", format!("__Host-identity-oidc-browser={}", binding.value).parse().unwrap());
    assert_eq!(BrowserBinding::require(&h).unwrap(), binding.value);
    h.insert("cookie", "__Host-identity-session=fixture".parse().unwrap());
    h.insert("authorization", "Bearer fixture".parse().unwrap());
    assert!(bearer_presentation(&h).is_err());
    assert!(cookie_presentation(&h).is_err());
    println!("passed");
}
