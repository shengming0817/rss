//! generated DTO Debug redaction 回归（#1358）。
//!
//! contract schema 的字段级 `x-pii` / `x-redaction` 必须派生成安全 `Debug`；
//! public 字段仍可见，敏感字段不泄漏原值。

use generated::event::identity_v1::session_created::IdentitySessionCreatedPayload;
use generated::http::identity_v1::login::IdentityLoginRequest;
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
        session_id: "7d65e5f2-e716-4c4e-8e4c-6f7ab1754ef8"
            .parse()
            .expect("session UUID"),
        subject,
        tenant_id: "f47ac10b-58cc-4372-a567-0e02b2c3d479"
            .parse()
            .expect("tenant UUID"),
        occurred_at: 42,
    };

    let rendered = format!("{payload:?}");
    assert!(
        rendered.contains("f47ac10b-58cc-4372-a567-0e02b2c3d479"),
        "{rendered}"
    );
    assert!(rendered.contains("occurred_at: 42"), "{rendered}");
    assert!(
        !rendered.contains("7d65e5f2-e716-4c4e-8e4c-6f7ab1754ef8"),
        "session leaked: {rendered}"
    );
    assert!(
        !rendered.contains("550e8400-e29b-41d4-a716-446655440000"),
        "subject leaked: {rendered}"
    );
}
