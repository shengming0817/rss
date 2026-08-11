use generated::event::identity_v1::session_created::IdentitySessionCreatedPayload;

const SUBJECT: &str = "550e8400-e29b-41d4-a716-446655440000";
const SESSION: &str = "7d65e5f2-e716-4c4e-8e4c-6f7ab1754ef8";
const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

fn payload(subject: &str, session_id: &str, tenant_id: &str) -> serde_json::Value {
    serde_json::json!({
        "sessionId": session_id,
        "subject": subject,
        "tenantId": tenant_id,
        "occurredAt": 1_700_000_000_i64,
    })
}

#[test]
fn session_created_accepts_uuid_identity_coordinates() -> Result<(), Box<dyn std::error::Error>> {
    let decoded =
        serde_json::from_value::<IdentitySessionCreatedPayload>(payload(SUBJECT, SESSION, TENANT))?;

    assert_eq!(decoded.subject, SUBJECT.parse::<uuid::Uuid>()?);
    assert_eq!(decoded.session_id, SESSION.parse::<uuid::Uuid>()?);
    assert_eq!(decoded.tenant_id, TENANT.parse::<uuid::Uuid>()?);
    Ok(())
}

#[test]
fn session_created_rejects_non_uuid_identity_coordinates() {
    for value in [
        payload("not-a-subject", SESSION, TENANT),
        payload(SUBJECT, "not-a-session", TENANT),
        payload(SUBJECT, SESSION, "not-a-tenant"),
    ] {
        assert!(
            serde_json::from_value::<IdentitySessionCreatedPayload>(value).is_err(),
            "every identity coordinate must be UUID-typed at decode"
        );
    }
}
