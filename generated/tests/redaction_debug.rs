//! generated DTO Debug redaction 回归（#1358）。
//!
//! contract schema 的字段级 `x-pii` / `x-redaction` 必须派生成安全 `Debug`；
//! public 字段仍可见，敏感字段不泄漏原值。

use generated::event::identity_v1::session_created::IdentitySessionCreatedPayload;
use generated::http::identity_v1::IdentityLoginRequest;
use generated::http::settings_v1::SettingsConfigPublishRequest;
use generated::http::settings_v2::SettingsSecretPublishRequest;

#[test]
fn login_request_debug_redacts_password_and_shows_public_username() {
    let req = IdentityLoginRequest {
        username: "alice".to_string(),
        password: "correct-horse-battery-staple".to_string(),
    };

    let rendered = format!("{req:?}");
    assert!(rendered.contains("username: \"alice\""), "{rendered}");
    assert!(rendered.contains("password: <redacted>"), "{rendered}");
    assert!(
        !rendered.contains("correct-horse-battery-staple"),
        "password leaked: {rendered}"
    );
}

#[test]
fn settings_secret_request_debug_redacts_store_coordinates() {
    let req = SettingsSecretPublishRequest {
        key: "vault.db".to_string(),
        store_id: "prod-vault".to_string(),
        ref_key: "apps/rss/db-password".to_string(),
        ref_version: Some("v42".to_string()),
    };

    let rendered = format!("{req:?}");
    for leaked in ["vault.db", "prod-vault", "apps/rss/db-password", "v42"] {
        assert!(!rendered.contains(leaked), "coordinate leaked: {rendered}");
    }
    assert!(rendered.contains("<redacted>"), "{rendered}");
}

#[test]
fn settings_config_publish_debug_redacts_value() {
    let req = SettingsConfigPublishRequest {
        key: "auth.jwtSigningKey".to_string(),
        value: "super-secret-config-value".to_string(),
    };

    let rendered = format!("{req:?}");
    assert!(
        !rendered.contains("auth.jwtSigningKey"),
        "key leaked: {rendered}"
    );
    assert!(
        !rendered.contains("super-secret-config-value"),
        "value leaked: {rendered}"
    );
    assert!(rendered.contains("<redacted>"), "{rendered}");
}

#[test]
#[allow(clippy::expect_used)]
fn identity_event_debug_redacts_subject_and_session() {
    let subject = "550e8400-e29b-41d4-a716-446655440000"
        .parse()
        .expect("uuid literal");
    let payload = IdentitySessionCreatedPayload {
        session_id: "sid-secret".to_string(),
        subject,
        tenant_id: "tenant-a".to_string(),
        occurred_at: 42,
    };

    let rendered = format!("{payload:?}");
    assert!(rendered.contains("tenant_id: \"tenant-a\""), "{rendered}");
    assert!(rendered.contains("occurred_at: 42"), "{rendered}");
    assert!(
        !rendered.contains("sid-secret"),
        "session leaked: {rendered}"
    );
    assert!(
        !rendered.contains("550e8400-e29b-41d4-a716-446655440000"),
        "subject leaked: {rendered}"
    );
}
