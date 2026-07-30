//! Device-certificate desired-state and status draft wire regression.

#![allow(clippy::expect_used)]

use generated::http::identity_v2::{
    device_certificate_policy_put::{
        IdentityDeviceCertificatePolicyPutConflictResponse,
        IdentityDeviceCertificatePolicyPutNotFoundResponse,
        IdentityDeviceCertificatePolicyPutRequest, IdentityDeviceCertificatePolicyPutResponse,
    },
    device_certificate_status_get::IdentityDeviceCertificateStatusGetResponse,
};
use serde_json::{Value, json};

fn schema(source: &str) -> Value {
    serde_json::from_str(source).expect("committed contract schema must be valid JSON")
}

#[test]
fn policy_schema_accepts_the_frozen_shape_and_rejects_boundary_violations() {
    let schema = schema(include_str!(
        "../../contracts/http/identity/v2/device-certificate-policy-put/request.schema.json"
    ));
    let validator = jsonschema::validator_for(&schema).expect("policy schema must compile");
    let valid = json!({
        "idempotencyKey": "b497a9ce-6ac5-4d44-a0a3-869af114db5f",
        "expectedGeneration": 0,
        "policy": {
            "validitySeconds": 300,
            "renewBeforeSeconds": 60,
            "keyUsages": ["clientAuth", "serverAuth"],
            "sans": ["device.example.test"]
        }
    });
    let maximum_bounds = json!({
        "idempotencyKey": "b497a9ce-6ac5-4d44-a0a3-869af114db5f",
        "expectedGeneration": 0,
        "policy": {
            "validitySeconds": 31536000,
            "renewBeforeSeconds": 31535999,
            "keyUsages": ["clientAuth"]
        }
    });
    for valid in [valid, maximum_bounds] {
        assert!(validator.is_valid(&valid), "unexpectedly invalid: {valid}");
        assert!(serde_json::from_value::<IdentityDeviceCertificatePolicyPutRequest>(valid).is_ok());
    }

    let thirty_three_sans = (0..33)
        .map(|index| Value::String(format!("device-{index}.example.test")))
        .collect::<Vec<_>>();
    for invalid in [
        json!({
            "idempotencyKey": "b497a9ce-6ac5-4d44-a0a3-869af114db5f", "expectedGeneration": -1,
            "policy": {"validitySeconds": 300, "renewBeforeSeconds": 60, "keyUsages": ["clientAuth"]}
        }),
        json!({
            "idempotencyKey": "b497a9ce-6ac5-4d44-a0a3-869af114db5f", "expectedGeneration": 0,
            "policy": {"validitySeconds": 299, "renewBeforeSeconds": 60, "keyUsages": ["clientAuth"]}
        }),
        json!({
            "idempotencyKey": "b497a9ce-6ac5-4d44-a0a3-869af114db5f", "expectedGeneration": 0,
            "policy": {"validitySeconds": 300, "renewBeforeSeconds": 59, "keyUsages": ["clientAuth"]}
        }),
        json!({
            "idempotencyKey": "b497a9ce-6ac5-4d44-a0a3-869af114db5f", "expectedGeneration": 0,
            "policy": {"validitySeconds": 31536001, "renewBeforeSeconds": 60, "keyUsages": ["clientAuth"]}
        }),
        json!({
            "idempotencyKey": "b497a9ce-6ac5-4d44-a0a3-869af114db5f", "expectedGeneration": 0,
            "policy": {"validitySeconds": 31536000, "renewBeforeSeconds": 31536000, "keyUsages": ["clientAuth"]}
        }),
        json!({
            "idempotencyKey": "b497a9ce-6ac5-4d44-a0a3-869af114db5f", "expectedGeneration": 0,
            "policy": {"validitySeconds": 300, "renewBeforeSeconds": 60, "keyUsages": []}
        }),
        json!({
            "idempotencyKey": "b497a9ce-6ac5-4d44-a0a3-869af114db5f", "expectedGeneration": 0,
            "policy": {"validitySeconds": 300, "renewBeforeSeconds": 60, "keyUsages": ["clientAuth", "clientAuth"]}
        }),
        json!({
            "idempotencyKey": "b497a9ce-6ac5-4d44-a0a3-869af114db5f", "expectedGeneration": 0,
            "policy": {"validitySeconds": 300, "renewBeforeSeconds": 60, "keyUsages": ["clientAuth"], "sans": thirty_three_sans}
        }),
        json!({
            "idempotencyKey": "b497a9ce-6ac5-4d44-a0a3-869af114db5f", "expectedGeneration": 0,
            "tenantId": "forbidden", "deviceId": "forbidden",
            "policy": {"validitySeconds": 300, "renewBeforeSeconds": 60, "keyUsages": ["clientAuth"]}
        }),
    ] {
        assert!(
            !validator.is_valid(&invalid),
            "unexpectedly valid: {invalid}"
        );
    }
    assert!(
        serde_json::from_value::<IdentityDeviceCertificatePolicyPutRequest>(json!({
            "idempotencyKey": "not-a-uuid", "expectedGeneration": 0,
            "policy": {"validitySeconds": 300, "renewBeforeSeconds": 60, "keyUsages": ["clientAuth"]}
        }))
        .is_err(),
        "generated UUID type must reject malformed idempotency keys"
    );
}

#[test]
fn policy_response_only_represents_acceptance_not_convergence() {
    let schema = schema(include_str!(
        "../../contracts/http/identity/v2/device-certificate-policy-put/response.schema.json"
    ));
    let validator =
        jsonschema::validator_for(&schema).expect("policy response schema must compile");
    assert!(validator.is_valid(&json!({
        "data": {"acceptedGeneration": 1, "condition": "Reconciling"}
    })));
    for invalid in [
        json!({"data": {"acceptedGeneration": 0, "condition": "Reconciling"}}),
        json!({"data": {"acceptedGeneration": 1, "condition": "Ready"}}),
        json!({"data": {"acceptedGeneration": 1, "condition": "PendingDevice", "completed": true}}),
    ] {
        assert!(
            !validator.is_valid(&invalid),
            "unexpectedly valid: {invalid}"
        );
    }
}

#[test]
fn policy_known_responses_are_typed_and_status_bound() {
    assert!(
        serde_json::from_value::<IdentityDeviceCertificatePolicyPutNotFoundResponse>(json!({
            "error": {"code": "NotFound"}
        }))
        .is_ok()
    );
    for code in ["ExpectedGenerationConflict", "IdempotencyKeyConflict"] {
        assert!(
            serde_json::from_value::<IdentityDeviceCertificatePolicyPutConflictResponse>(json!({
                "error": {"code": code}
            }))
            .is_ok()
        );
    }

    assert_eq!(
        <IdentityDeviceCertificatePolicyPutResponse as generated::http::HttpResponseBinding>::STATUS,
        200
    );
    assert_eq!(
        <IdentityDeviceCertificatePolicyPutNotFoundResponse as generated::http::HttpResponseBinding>::STATUS,
        404
    );
    assert_eq!(
        <IdentityDeviceCertificatePolicyPutConflictResponse as generated::http::HttpResponseBinding>::STATUS,
        409
    );
}

#[test]
fn status_command_is_optional_nullable_and_payload_free() {
    let schema = schema(include_str!(
        "../../contracts/http/identity/v2/device-certificate-status-get/response.schema.json"
    ));
    let validator = jsonschema::validator_for(&schema).expect("status schema must compile");
    let without_command = json!({
        "data": {"desiredGeneration": 0, "observedGeneration": 0, "conditions": []}
    });
    let null_command = json!({
        "data": {"desiredGeneration": 0, "observedGeneration": 0, "conditions": [], "activeCommand": null}
    });
    let command = json!({
        "data": {
            "desiredGeneration": 2,
            "observedGeneration": 1,
            "conditions": [{
                "type": "Reconciling", "status": "True", "reason": "AwaitingDevice",
                "observedGeneration": 1, "lastTransitionAt": 42
            }],
            "activeCommand": {"commandId": "command-1", "generation": 2, "fenceEpoch": 1, "state": "published"}
        }
    });
    for valid in [without_command, null_command, command] {
        assert!(validator.is_valid(&valid));
        assert!(
            serde_json::from_value::<IdentityDeviceCertificateStatusGetResponse>(valid).is_ok()
        );
    }

    for invalid in [
        json!({
            "data": {"desiredGeneration": -1, "observedGeneration": 0, "conditions": []}
        }),
        json!({
            "data": {"desiredGeneration": 0, "observedGeneration": -1, "conditions": []}
        }),
        json!({
            "data": {"desiredGeneration": 1, "observedGeneration": 0, "conditions": [],
                "activeCommand": {"commandId": "command-1", "generation": 0, "fenceEpoch": 1,
                    "state": "published"}}
        }),
        json!({
            "data": {"desiredGeneration": 1, "observedGeneration": 0, "conditions": [],
                "activeCommand": {"commandId": "command-1", "generation": 1, "fenceEpoch": 0,
                    "state": "published"}}
        }),
        json!({
            "data": {"desiredGeneration": 1, "observedGeneration": 0, "conditions": [],
                "activeCommand": {"commandId": "command-1", "generation": 1, "fenceEpoch": 1,
                    "state": "published", "payload": {"certificate": "forbidden"}}}
        }),
        json!({
            "data": {"desiredGeneration": 1, "observedGeneration": 0,
                "conditions": [{"type": "UnknownType", "status": "True", "reason": "AwaitingDevice",
                    "observedGeneration": 0, "lastTransitionAt": 42}]}
        }),
    ] {
        assert!(
            !validator.is_valid(&invalid),
            "unexpectedly valid: {invalid}"
        );
    }
    assert!(
        serde_json::from_value::<IdentityDeviceCertificateStatusGetResponse>(json!({
            "data": {"desiredGeneration": 1, "observedGeneration": 0, "conditions": [],
                "activeCommand": {"commandId": "command-1", "generation": 1, "fenceEpoch": 1,
                    "state": "published", "payload": {"certificate": "forbidden"}}}
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<IdentityDeviceCertificateStatusGetResponse>(json!({
            "data": {"desiredGeneration": 1, "observedGeneration": 0,
                "conditions": [{"type": "UnknownType", "status": "True", "reason": "AwaitingDevice",
                    "observedGeneration": 0, "lastTransitionAt": 42}]}
        }))
        .is_err()
    );
}
