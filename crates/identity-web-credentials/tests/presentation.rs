use http::HeaderMap;
use rss_identity_web_credentials::*;

#[test]
fn rejects_ambiguous_presentation_and_preserves_cookie_attributes() -> anyhow::Result<()> {
    let mut headers=HeaderMap::new();
    headers.insert("cookie","__Host-identity-session=fixture".parse()?);
    headers.insert("authorization","Bearer fixture".parse()?);
    assert!(cookie_presentation(&headers).is_err());
    assert!(bearer_presentation(&headers).is_err());
    headers.clear();
    headers.append("origin","https://host.test".parse()?);
    headers.append("origin","https://host.test".parse()?);
    let config=HttpConfig::new("https://host.test",std::time::Duration::from_secs(5))?;
    assert!(same_origin(&headers,&config).is_err());
    assert_eq!(clear_session_cookie().to_str()?,"__Host-identity-session=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0");
    Ok(())
}
