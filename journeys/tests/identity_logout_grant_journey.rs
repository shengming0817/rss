//! Current/all logout contract journey.

#![cfg(feature = "integration")]

use generated::http::identity_v1::{logout, logout_all};

#[test]
fn identity_logout_grant_journey() -> anyhow::Result<()> {
    let current: logout::IdentityLogoutRequest = serde_json::from_str("{}")?;
    let all: logout_all::IdentityLogoutAllRequest = serde_json::from_str("{}")?;
    assert_eq!(serde_json::to_value(current)?, serde_json::json!({}));
    assert_eq!(serde_json::to_value(all)?, serde_json::json!({}));

    for forbidden in [
        r#"{"sessionId":"550e8400-e29b-41d4-a716-446655440000"}"#,
        r#"{"subject":"11111111-2222-4333-8444-555555555555"}"#,
    ] {
        assert!(serde_json::from_str::<logout::IdentityLogoutRequest>(forbidden).is_err());
        assert!(serde_json::from_str::<logout_all::IdentityLogoutAllRequest>(forbidden).is_err());
    }

    assert_eq!(
        logout::SPEC.route.auth(),
        vocab::HttpRouteAuth::Permission(vocab::RoutePermissionId::IdentitySessionLogoutCurrent)
    );
    assert_eq!(
        logout_all::SPEC.route.auth(),
        vocab::HttpRouteAuth::Permission(vocab::RoutePermissionId::IdentitySessionLogoutAll)
    );
    Ok(())
}
