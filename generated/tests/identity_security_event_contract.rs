//! `identity.security-event@v1` draft wire 回归。
//!
//! 契约只冻结安全事件分类、opaque target、租户和发生时间；不得把 raw subject/grant/token
//! 等关联标识或凭据材料扩进 durable fact。生产接线与订阅不属于 draft。

use generated::event::{
    EVENTS,
    identity_v1::security_event::{
        IdentitySecurityEventPayload, IdentitySecurityEventPayloadTarget,
        IdentitySecurityEventPayloadTargetKind, SPEC,
    },
};
use serde_json::{Value, json};

const CASES: [(&str, &str); 9] = [
    ("passwordChanged", "subject"),
    ("passwordReset", "subject"),
    ("accountLocked", "subject"),
    ("accountSuspended", "subject"),
    ("accountDeactivated", "subject"),
    ("logoutCurrent", "grant"),
    ("logoutAll", "subject"),
    ("refreshReuseDetected", "grant"),
    ("credentialDeleted", "subject"),
];

#[test]
#[allow(clippy::expect_used)]
fn all_nine_kinds_have_their_canonical_opaque_target_and_roundtrip() {
    for (kind_wire, target_kind) in CASES {
        let wire = json!({
            "kind": kind_wire,
            "target": {
                "kind": target_kind,
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
            "target": {"kind": "grant", "ref": "4c2ca32f-2f92-41ba-a305-8b2bf6f9617a"},
            "tenantId": "tenant-a",
            "occurredAt": 42,
            "subject": "forbidden",
        }),
        json!({
            "kind": "unknown",
            "target": {"kind": "grant", "ref": "4c2ca32f-2f92-41ba-a305-8b2bf6f9617a"},
            "tenantId": "tenant-a",
            "occurredAt": 42,
        }),
        json!({
            "kind": "logoutCurrent",
            "target": {"kind": "unknown", "ref": "4c2ca32f-2f92-41ba-a305-8b2bf6f9617a"},
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
    assert_eq!(names, ["kind", "occurredAt", "target", "tenantId"]);
    assert_eq!(
        properties.get("kind").and_then(|kind| kind.get("enum")),
        Some(&json!([
            "passwordChanged",
            "passwordReset",
            "accountLocked",
            "accountSuspended",
            "accountDeactivated",
            "logoutCurrent",
            "logoutAll",
            "refreshReuseDetected",
            "credentialDeleted",
        ])),
        "schema kind enum must be the exact closed nine-value wire set"
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
fn draft_fact_has_no_subscription_and_is_not_in_the_active_registry() {
    assert!(SPEC.subscriptions().is_empty());
    assert!(!EVENTS.contains(&SPEC));
}
