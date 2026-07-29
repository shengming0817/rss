//! `identity.security-event@v1` active wire 回归。
//!
//! 契约冻结安全事件分类、pseudonymous actor/target、租户和发生时间；不得把 raw
//! subject/grant/token 等关联标识或凭据材料扩进 durable fact。

use generated::event::{
    EVENTS,
    identity_v1::security_event::{
        IdentitySecurityEventPayload, IdentitySecurityEventPayloadTarget,
        IdentitySecurityEventPayloadTargetKind, SPEC,
    },
};
use serde_json::{Value, json};

const CASES: [(&str, &str); 10] = [
    ("passwordChanged", "subject"),
    ("passwordReset", "subject"),
    ("accountLocked", "subject"),
    ("accountSuspended", "subject"),
    ("accountDeactivated", "subject"),
    ("accountReactivated", "subject"),
    ("logoutCurrent", "grant"),
    ("logoutAll", "subject"),
    ("refreshReuseDetected", "grant"),
    ("credentialDeleted", "subject"),
];

#[test]
#[allow(clippy::expect_used)]
fn all_ten_kinds_have_their_canonical_opaque_target_and_roundtrip() {
    for (kind_wire, target_kind) in CASES {
        let wire = json!({
            "kind": kind_wire,
            "actor": {
                "kind": "service",
                "keyId": 1,
                "ref": "507a4927-18d6-4e28-8964-ea4d21ce9e79",
            },
            "target": {
                "kind": target_kind,
                "keyId": 1,
                "ref": "4c2ca32f-2f92-41ba-a305-8b2bf6f9617a",
            },
            "tenantId": "tenant-a",
            "occurredAt": 42,
        });
        let payload: IdentitySecurityEventPayload =
            serde_json::from_value(wire.clone()).expect("canonical security event must decode");

        assert_eq!(payload.tenant_id, "tenant-a");
        assert_eq!(payload.occurred_at, 42);
        assert_eq!(
            serde_json::to_value(payload).expect("security event must encode"),
            wire
        );
    }
}

#[test]
fn unknown_fields_kinds_and_targets_are_rejected() {
    for invalid in [
        json!({
            "kind": "logoutCurrent",
            "actor": {"kind": "service", "keyId": 1, "ref": "507a4927-18d6-4e28-8964-ea4d21ce9e79"},
            "target": {"kind": "grant", "keyId": 1, "ref": "4c2ca32f-2f92-41ba-a305-8b2bf6f9617a"},
            "tenantId": "tenant-a",
            "occurredAt": 42,
            "subject": "forbidden",
        }),
        json!({
            "kind": "unknown",
            "actor": {"kind": "service", "keyId": 1, "ref": "507a4927-18d6-4e28-8964-ea4d21ce9e79"},
            "target": {"kind": "grant", "keyId": 1, "ref": "4c2ca32f-2f92-41ba-a305-8b2bf6f9617a"},
            "tenantId": "tenant-a",
            "occurredAt": 42,
        }),
        json!({
            "kind": "logoutCurrent",
            "actor": {"kind": "service", "keyId": 1, "ref": "507a4927-18d6-4e28-8964-ea4d21ce9e79"},
            "target": {"kind": "unknown", "keyId": 1, "ref": "4c2ca32f-2f92-41ba-a305-8b2bf6f9617a"},
            "tenantId": "tenant-a",
            "occurredAt": 42,
        }),
    ] {
        assert!(
            serde_json::from_value::<IdentitySecurityEventPayload>(invalid).is_err(),
            "closed draft wire must reject unknown input"
        );
    }
}

#[test]
#[allow(clippy::expect_used)]
fn schema_surface_is_exact_and_contains_no_sensitive_identifier_fields() {
    let schema: Value = serde_json::from_str(include_str!(
        "../../contracts/event/identity/v1/security-event/payload.schema.json"
    ))
    .expect("committed security-event schema must be JSON");
    let object = schema.as_object().expect("schema root must be an object");
    assert_eq!(
        object.get("additionalProperties"),
        Some(&Value::Bool(false))
    );

    let properties = object
        .get("properties")
        .and_then(Value::as_object)
        .expect("schema properties must be an object");
    let mut names = properties.keys().map(String::as_str).collect::<Vec<_>>();
    names.sort_unstable();
    assert_eq!(names, ["actor", "kind", "occurredAt", "target", "tenantId"]);
    assert_eq!(
        properties.get("kind").and_then(|kind| kind.get("enum")),
        Some(&json!([
            "passwordChanged",
            "passwordReset",
            "accountLocked",
            "accountSuspended",
            "accountDeactivated",
            "accountReactivated",
            "logoutCurrent",
            "logoutAll",
            "refreshReuseDetected",
            "credentialDeleted",
        ])),
        "schema kind enum must be the exact closed ten-value wire set"
    );
    let target = properties
        .get("target")
        .expect("schema must carry one tagged opaque target");
    assert_eq!(
        target.get("additionalProperties"),
        Some(&Value::Bool(false))
    );
    assert_eq!(
        target
            .get("properties")
            .and_then(|value| value.get("kind"))
            .and_then(|value| value.get("enum")),
        Some(&json!(["subject", "grant"]))
    );
    assert_eq!(
        target
            .get("properties")
            .and_then(|value| value.get("ref"))
            .and_then(|value| value.get("format")),
        Some(&json!("uuid"))
    );

    for forbidden in [
        "subject",
        "grant",
        "session",
        "sid",
        "jti",
        "token",
        "password",
        "credential",
        "email",
        "username",
    ] {
        assert!(
            !properties
                .keys()
                .any(|name| name.to_ascii_lowercase().contains(forbidden)),
            "sensitive or correlating field `{forbidden}` must not enter the fact"
        );
    }
}

#[test]
#[allow(clippy::expect_used)]
fn opaque_target_debug_redacts_the_correlating_reference() {
    let reference = "4c2ca32f-2f92-41ba-a305-8b2bf6f9617a"
        .parse()
        .expect("uuid literal");
    let target = IdentitySecurityEventPayloadTarget {
        key_id: std::num::NonZeroU64::new(1).expect("non-zero key id"),
        kind: IdentitySecurityEventPayloadTargetKind::Grant,
        ref_: reference,
    };

    let rendered = format!("{target:?}");
    assert!(rendered.contains("kind: Grant"), "{rendered}");
    assert!(rendered.contains("ref_: <redacted>"), "{rendered}");
    assert!(
        !rendered.contains("4c2ca32f-2f92-41ba-a305-8b2bf6f9617a"),
        "opaque reference leaked: {rendered}"
    );
}

#[test]
fn active_fact_has_the_required_audit_subscription_and_registry_entry() {
    assert_eq!(SPEC.subscriptions().len(), 1);
    assert_eq!(SPEC.subscriptions()[0].consumer(), "audit");
    assert!(EVENTS.contains(&SPEC));
}
