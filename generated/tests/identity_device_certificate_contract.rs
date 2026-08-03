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
use generated::{
    command::{CommandJournalPolicy, FencedCommandSpec, identity_v1 as certificate_command},
    event::identity_v1::{
        device_certificate_reported, device_command_acked, device_ingress_receipted,
    },
};
use serde_json::{Value, json};

fn schema(source: &str) -> Value {
    serde_json::from_str(source).expect("committed contract schema must be valid JSON")
}

fn manifest_string_field<'a>(source: &'a str, field: &str) -> Option<&'a str> {
    for line in source.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() == field {
            return value
                .trim()
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'));
        }
    }
    None
}

fn assert_fenced_command(command: &Value) {
    let request = serde_json::from_value::<
        certificate_command::IdentityApplyDeviceCertificateRequest,
    >(command.clone())
    .expect("canonical fenced command must deserialize");
    let intent_digest = command["intentDigest"]
        .as_str()
        .expect("fixture digest is a string");
    let request_debug = format!("{request:?}");
    assert!(!request_debug.contains(intent_digest));
    let fenced = certificate_command::fenced_reconcile_command(request);
    let fenced_debug = format!("{fenced:?}");
    assert!(!fenced_debug.contains(intent_digest));
    assert_eq!(
        serde_json::to_value(fenced.request()).expect("typed request must serialize"),
        *command
    );
    assert_eq!(
        fenced.device_id().to_string(),
        "b497a9ce-6ac5-4d44-a0a3-869af114db5f"
    );
    assert_eq!(fenced.desired_generation().get(), 2);
    assert_eq!(fenced.fence_epoch().get(), 3);
    assert_eq!(fenced.intent_digest(), format!("sha256:{}", "4".repeat(64)));
    assert_eq!(fenced.deadline_epoch_seconds().get(), 42);
}

fn assert_fenced_contract_has_no_ordinary_producer() {
    let generated_source = include_str!("../src/command/identity_v1.rs");
    for forbidden in [
        "impl super::JournaledCommandContract for Contract",
        "impl super::DirectCommandContract for Contract",
        "pub async fn journal_async",
        "pub async fn emit_async",
    ] {
        assert!(
            !generated_source.contains(forbidden),
            "fenced contract must not expose ordinary producer entry `{forbidden}`"
        );
    }
    assert!(generated_source.contains("pub fn register_handler<Reg, H, Fut>"));
}

#[test]
fn device_command_and_fact_contracts_remain_draft_until_activation() {
    let manifests = [
        (
            include_str!("../../contracts/command/identity/v1/contract.toml"),
            "identity.apply-device-certificate",
        ),
        (
            include_str!("../../contracts/event/identity/v1/device-command-acked/contract.toml"),
            "identity.device-command-acked",
        ),
        (
            include_str!(
                "../../contracts/event/identity/v1/device-certificate-reported/contract.toml"
            ),
            "identity.device-certificate-reported",
        ),
        (
            include_str!(
                "../../contracts/event/identity/v1/device-ingress-receipted/contract.toml"
            ),
            "identity.device-ingress-receipted",
        ),
    ];

    assert_eq!(manifests.len(), 4);
    for (manifest, contract_id) in manifests {
        assert_eq!(manifest_string_field(manifest, "id"), Some(contract_id));
        assert_eq!(manifest_string_field(manifest, "lifecycle"), Some("draft"));
    }
}

#[test]
fn device_command_and_fact_schemas_match_the_frozen_contract_set() {
    for (live, frozen, dto_title) in [
        (
            include_str!("../../contracts/command/identity/v1/request.schema.json"),
            include_str!(
                "../../docs/spec/007-l4-device-latent-production-loop/contracts/apply-device-certificate.command.schema.json"
            ),
            "IdentityApplyDeviceCertificateRequest",
        ),
        (
            include_str!(
                "../../contracts/event/identity/v1/device-command-acked/payload.schema.json"
            ),
            include_str!(
                "../../docs/spec/007-l4-device-latent-production-loop/contracts/device-command-acked.event.schema.json"
            ),
            "IdentityDeviceCommandAckedPayload",
        ),
        (
            include_str!(
                "../../contracts/event/identity/v1/device-certificate-reported/payload.schema.json"
            ),
            include_str!(
                "../../docs/spec/007-l4-device-latent-production-loop/contracts/device-certificate-reported.event.schema.json"
            ),
            "IdentityDeviceCertificateReportedPayload",
        ),
        (
            include_str!(
                "../../contracts/event/identity/v1/device-ingress-receipted/payload.schema.json"
            ),
            include_str!(
                "../../docs/spec/007-l4-device-latent-production-loop/contracts/application-receipt.schema.json"
            ),
            "IdentityDeviceIngressReceiptedPayload",
        ),
    ] {
        let mut frozen = schema(frozen);
        frozen["title"] = json!(dto_title);
        assert_eq!(schema(live), frozen);
    }
}

#[test]
fn generated_device_command_and_facts_bind_the_frozen_wire_shapes() {
    assert_fenced_contract_has_no_ordinary_producer();

    let command = json!({
        "deviceId": "b497a9ce-6ac5-4d44-a0a3-869af114db5f",
        "desiredGeneration": 2,
        "fenceEpoch": 3,
        "intentDigest": format!("sha256:{}", "4".repeat(64)),
        "policyHash": format!("sha256:{}", "1".repeat(64)),
        "artifactId": "certificate-artifact-1",
        "artifactDigest": format!("sha256:{}", "2".repeat(64)),
        "deadlineEpochSeconds": 42
    });
    assert_fenced_command(&command);
    for invalid in [
        {
            let mut invalid = command.clone();
            invalid["desiredGeneration"] = json!(0);
            invalid
        },
        {
            let mut invalid = command.clone();
            invalid["privateKey"] = json!("forbidden");
            invalid
        },
    ] {
        assert!(
            serde_json::from_value::<certificate_command::IdentityApplyDeviceCertificateRequest>(
                invalid
            )
            .is_err()
        );
    }

    let ack = json!({
        "deviceId": "b497a9ce-6ac5-4d44-a0a3-869af114db5f",
        "commandId": "command-1",
        "desiredGeneration": 2,
        "fenceEpoch": 3,
        "deviceSequence": 0,
        "result": "received",
        "reason": "None",
        "observedAt": 42
    });
    assert!(
        serde_json::from_value::<device_command_acked::IdentityDeviceCommandAckedPayload>(
            ack.clone()
        )
        .is_ok()
    );
    let mut generation_zero_ack = ack.clone();
    generation_zero_ack["desiredGeneration"] = json!(0);
    assert!(
        serde_json::from_value::<device_command_acked::IdentityDeviceCommandAckedPayload>(
            generation_zero_ack
        )
        .is_err()
    );
    for (result, reason) in [("received", "DeviceFailure"), ("rejected", "None")] {
        let mut invalid = ack.clone();
        invalid["result"] = json!(result);
        invalid["reason"] = json!(reason);
        assert!(
            serde_json::from_value::<device_command_acked::IdentityDeviceCommandAckedPayload>(
                invalid
            )
            .is_err(),
            "ACK must reject the illegal {result}/{reason} combination"
        );
    }

    let reported = json!({
        "deviceId": "b497a9ce-6ac5-4d44-a0a3-869af114db5f",
        "observedGeneration": 2,
        "fenceEpoch": 3,
        "deviceSequence": 1,
        "stateHash": format!("sha256:{}", "3".repeat(64)),
        "artifactDigest": format!("sha256:{}", "2".repeat(64)),
        "expiresAt": null,
        "observedAt": 43
    });
    assert!(
        serde_json::from_value::<
            device_certificate_reported::IdentityDeviceCertificateReportedPayload,
        >(reported.clone())
        .is_ok()
    );
    let mut generation_zero_report = reported.clone();
    generation_zero_report["observedGeneration"] = json!(0);
    assert!(
        serde_json::from_value::<
            device_certificate_reported::IdentityDeviceCertificateReportedPayload,
        >(generation_zero_report)
        .is_err()
    );

    let receipt = json!({
        "ingressEnvelopeId": "ingress-envelope-1",
        "deviceId": "b497a9ce-6ac5-4d44-a0a3-869af114db5f",
        "outcome": "committed",
        "reason": "None",
        "committedAt": 44
    });
    assert!(
        serde_json::from_value::<device_ingress_receipted::IdentityDeviceIngressReceiptedPayload>(
            receipt.clone()
        )
        .is_ok()
    );
    for (outcome, reason) in [
        ("committed", "ProtocolViolation"),
        ("duplicate", "None"),
        ("stale", "AlreadyCommitted"),
        ("rejected", "GenerationStale"),
    ] {
        let mut invalid = receipt.clone();
        invalid["outcome"] = json!(outcome);
        invalid["reason"] = json!(reason);
        assert!(
            serde_json::from_value::<
                device_ingress_receipted::IdentityDeviceIngressReceiptedPayload,
            >(invalid)
            .is_err(),
            "receipt must reject the illegal {outcome}/{reason} combination"
        );
    }

    for mut forbidden in [command, ack, reported, receipt] {
        forbidden
            .as_object_mut()
            .expect("wire payload must be an object")
            .insert("tenantId".to_string(), json!("forbidden"));
        let serialized = serde_json::to_string(&forbidden).expect("JSON value must serialize");
        assert!(
            serde_json::from_str::<certificate_command::IdentityApplyDeviceCertificateRequest>(
                &serialized
            )
            .is_err()
                && serde_json::from_str::<device_command_acked::IdentityDeviceCommandAckedPayload>(
                    &serialized
                )
                .is_err()
                && serde_json::from_str::<
                    device_certificate_reported::IdentityDeviceCertificateReportedPayload,
                >(&serialized)
                .is_err()
                && serde_json::from_str::<
                    device_ingress_receipted::IdentityDeviceIngressReceiptedPayload,
                >(&serialized)
                .is_err()
        );
    }
}

#[test]
fn device_ack_and_receipt_schemas_reject_cross_variant_reason_pairs() {
    let ack_schema = schema(include_str!(
        "../../contracts/event/identity/v1/device-command-acked/payload.schema.json"
    ));
    let ack_validator = jsonschema::draft7::options()
        .build(&ack_schema)
        .expect("ACK schema must compile");
    for (result, reason) in [("received", "DeviceFailure"), ("rejected", "None")] {
        let invalid = json!({
            "deviceId": "b497a9ce-6ac5-4d44-a0a3-869af114db5f",
            "commandId": "command-1",
            "desiredGeneration": 2,
            "fenceEpoch": 3,
            "deviceSequence": 0,
            "result": result,
            "reason": reason,
            "observedAt": 42
        });
        assert!(
            !ack_validator.is_valid(&invalid),
            "ACK schema must reject {result}/{reason}"
        );
    }

    let receipt_schema = schema(include_str!(
        "../../contracts/event/identity/v1/device-ingress-receipted/payload.schema.json"
    ));
    let receipt_validator = jsonschema::draft7::options()
        .build(&receipt_schema)
        .expect("receipt schema must compile");
    for (outcome, reason) in [
        ("committed", "ProtocolViolation"),
        ("duplicate", "None"),
        ("stale", "AlreadyCommitted"),
        ("rejected", "GenerationStale"),
    ] {
        let invalid = json!({
            "ingressEnvelopeId": "ingress-envelope-1",
            "deviceId": "b497a9ce-6ac5-4d44-a0a3-869af114db5f",
            "outcome": outcome,
            "reason": reason,
            "committedAt": 44
        });
        assert!(
            !receipt_validator.is_valid(&invalid),
            "receipt schema must reject {outcome}/{reason}"
        );
    }
}

#[test]
fn generated_device_command_and_facts_bake_contract_and_transport_coordinates() {
    assert_eq!(
        certificate_command::CONTRACT_ID,
        "identity.apply-device-certificate"
    );
    assert_eq!(
        certificate_command::TOPIC,
        "identity.commands.apply-device-certificate"
    );
    assert_eq!(
        certificate_command::SPEC.journal(),
        CommandJournalPolicy::Required
    );

    for (spec, contract_id, topic) in [
        (
            device_command_acked::SPEC,
            "identity.device-command-acked",
            "identity.device-command-acked",
        ),
        (
            device_certificate_reported::SPEC,
            "identity.device-certificate-reported",
            "identity.device-certificate-reported",
        ),
        (
            device_ingress_receipted::SPEC,
            "identity.device-ingress-receipted",
            "identity.device-ingress-receipted",
        ),
    ] {
        assert_eq!(spec.contract_id(), contract_id);
        assert_eq!(spec.topic(), topic);
        assert!(spec.subscriptions().is_empty());
    }
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
            "activeCommand": {"generation": 2, "fenceEpoch": 1, "state": "published"}
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
                "activeCommand": {"generation": 0, "fenceEpoch": 1,
                    "state": "published"}}
        }),
        json!({
            "data": {"desiredGeneration": 1, "observedGeneration": 0, "conditions": [],
                "activeCommand": {"generation": 1, "fenceEpoch": 0,
                    "state": "published"}}
        }),
        json!({
            "data": {"desiredGeneration": 1, "observedGeneration": 0, "conditions": [],
                "activeCommand": {"generation": 1, "fenceEpoch": 1,
                    "state": "published", "payload": {"certificate": "forbidden"}}}
        }),
        json!({
            "data": {"desiredGeneration": 1, "observedGeneration": 0, "conditions": [],
                "activeCommand": {"commandId": "command-1", "generation": 1, "fenceEpoch": 1,
                    "state": "published"}}
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
                "activeCommand": {"generation": 1, "fenceEpoch": 1,
                    "state": "published", "payload": {"certificate": "forbidden"}}}
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<IdentityDeviceCertificateStatusGetResponse>(json!({
            "data": {"desiredGeneration": 1, "observedGeneration": 0, "conditions": [],
                "activeCommand": {"commandId": "command-1", "generation": 1, "fenceEpoch": 1,
                    "state": "published"}}
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
