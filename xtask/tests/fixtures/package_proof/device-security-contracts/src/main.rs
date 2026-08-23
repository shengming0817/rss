use release_package::{
    AuthorizationReceiptId, apply_device_certificate, device_certificate_reported,
    device_command_acked, device_ingress_receipted, policy_put, status_get,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const RECEIPT: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const DEVICE: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn accepts<T: serde::de::DeserializeOwned>(value: Value) -> bool {
    serde_json::from_value::<T>(value).is_ok()
}

fn rejects<T: serde::de::DeserializeOwned>(value: Value) -> bool {
    !accepts::<T>(value)
}

fn main() {
    let parsed_receipt: AuthorizationReceiptId = RECEIPT.parse().expect("valid receipt id");
    let restored_receipt = AuthorizationReceiptId::try_from(parsed_receipt.as_uuid())
        .expect("non-nil UUID");
    let modules = [
        (&policy_put::DESCRIPTOR, policy_put::LIFECYCLE, policy_put::SCHEMAS),
        (&status_get::DESCRIPTOR, status_get::LIFECYCLE, status_get::SCHEMAS),
        (&apply_device_certificate::DESCRIPTOR, apply_device_certificate::LIFECYCLE, apply_device_certificate::SCHEMAS),
        (&device_command_acked::DESCRIPTOR, device_command_acked::LIFECYCLE, device_command_acked::SCHEMAS),
        (&device_certificate_reported::DESCRIPTOR, device_certificate_reported::LIFECYCLE, device_certificate_reported::SCHEMAS),
        (&device_ingress_receipted::DESCRIPTOR, device_ingress_receipted::LIFECYCLE, device_ingress_receipted::SCHEMAS),
    ];
    let expected_ids = [
        "identity.device-certificate-policy-put",
        "identity.device-certificate-status-get",
        "identity.apply-device-certificate",
        "identity.device-command-acked",
        "identity.device-certificate-reported",
        "identity.device-ingress-receipted",
    ];
    let descriptors_verified = modules.iter().zip(expected_ids).all(|((descriptor, _, _), id)| {
        descriptor.id() == id
            && descriptor.version().major() > 0
            && descriptor.schema_digest().starts_with("sha256:")
    });
    let schema_bytes_and_digests_verified = modules.iter().all(|(_, _, schemas)| {
        !schemas.is_empty() && schemas.iter().all(|schema| {
            !schema.role().is_empty()
                && schema.digest().starts_with("sha256:")
                && schema.digest().len() == 71
                && schema.digest() == format!("sha256:{:x}", Sha256::digest(schema.json()))
                && serde_json::from_slice::<Value>(schema.json()).is_ok()
        })
    });

    let policy_lineage_required = accepts::<policy_put::IdentityDeviceCertificatePolicyPutResponse>(json!({
        "data": {"authorizationReceiptId": RECEIPT, "acceptedGeneration": 7, "condition": "Reconciling"}
    })) && rejects::<policy_put::IdentityDeviceCertificatePolicyPutResponse>(json!({
        "data": {"acceptedGeneration": 7, "condition": "Reconciling"}
    }));

    let policy_request = |expected_generation, validity, renew, usages: Value, sans: Value| json!({
        "idempotencyKey": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        "expectedGeneration": expected_generation,
        "policy": {
            "validitySeconds": validity,
            "renewBeforeSeconds": renew,
            "keyUsages": usages,
            "sans": sans
        }
    });
    let policy_schema_constraints_enforced =
        accepts::<policy_put::IdentityDeviceCertificatePolicyPutRequest>(policy_request(
            0, 3600, 600, json!(["clientAuth"]), json!(["device.example"]),
        ))
        && rejects::<policy_put::IdentityDeviceCertificatePolicyPutRequest>(policy_request(
            -1, 3600, 600, json!(["clientAuth"]), json!([]),
        ))
        && rejects::<policy_put::IdentityDeviceCertificatePolicyPutRequest>(policy_request(
            0, 299, 60, json!(["clientAuth"]), json!([]),
        ))
        && rejects::<policy_put::IdentityDeviceCertificatePolicyPutRequest>(policy_request(
            0, 3600, 3600, json!(["clientAuth"]), json!([]),
        ))
        && rejects::<policy_put::IdentityDeviceCertificatePolicyPutRequest>(policy_request(
            0, 3600, 600, json!([]), json!([]),
        ))
        && rejects::<policy_put::IdentityDeviceCertificatePolicyPutRequest>(policy_request(
            0, 3600, 600, json!(["clientAuth", "clientAuth"]), json!([]),
        ))
        && rejects::<policy_put::IdentityDeviceCertificatePolicyPutRequest>(policy_request(
            0, 3600, 600, json!(["clientAuth"]), json!(["device.example", "device.example"]),
        ));
    let policy_error_envelope_uniform =
        accepts::<policy_put::IdentityDeviceCertificatePolicyPutNotFoundResponse>(json!({
            "error": {"code": "ERR_CORE_NOT_FOUND", "message": "not found", "retryable": false, "details": [], "requestId": "req-1"}
        }))
        && accepts::<policy_put::IdentityDeviceCertificatePolicyPutConflictResponse>(json!({
            "error": {"code": "ERR_CORE_VERSION_CONFLICT", "message": "version conflict", "retryable": false, "details": [], "requestId": "req-2"}
        }))
        && rejects::<policy_put::IdentityDeviceCertificatePolicyPutConflictResponse>(json!({
            "error": {"code": "ExpectedGenerationConflict"}
        }));

    let status_closed_variants = accepts::<status_get::IdentityDeviceCertificateStatusGetResponse>(json!({
        "data": {"desired": null, "observedGeneration": 0, "conditions": []}
    })) && accepts::<status_get::IdentityDeviceCertificateStatusGetResponse>(json!({
        "data": {"desired": {"generation": 7, "authorizationReceiptId": RECEIPT, "activeCommand": null}, "observedGeneration": 0, "conditions": []}
    })) && rejects::<status_get::IdentityDeviceCertificateStatusGetResponse>(json!({
        "data": {"desiredGeneration": 7, "activeCommand": null, "observedGeneration": 0, "conditions": []}
    }));

    let command = json!({
        "deviceId": DEVICE, "authorizationReceiptId": RECEIPT, "desiredGeneration": 7,
        "fenceEpoch": 3, "intentDigest": DIGEST, "policyHash": DIGEST,
        "artifactId": "artifact-identity-0001", "artifactDigest": DIGEST,
        "deadlineEpochSeconds": 1900000000
    });
    let mut command_without_lineage = command.clone();
    command_without_lineage.as_object_mut().unwrap().remove("authorizationReceiptId");
    let command_lineage_required = accepts::<apply_device_certificate::IdentityApplyDeviceCertificateRequest>(command)
        && rejects::<apply_device_certificate::IdentityApplyDeviceCertificateRequest>(command_without_lineage);

    let ack = json!({
        "deviceId": DEVICE, "commandId": "command-1", "desiredGeneration": 7,
        "fenceEpoch": 3, "deviceSequence": 1, "result": "received", "reason": "None", "observedAt": 1
    });
    let mut ack_injected = ack.clone();
    ack_injected.as_object_mut().unwrap().insert("authorizationReceiptId".into(), json!(RECEIPT));
    let ack_lineage_injection_rejected = accepts::<device_command_acked::IdentityDeviceCommandAckedPayload>(ack)
        && rejects::<device_command_acked::IdentityDeviceCommandAckedPayload>(ack_injected);

    let report = json!({
        "deviceId": DEVICE, "observedGeneration": 7, "fenceEpoch": 3, "deviceSequence": 2,
        "stateHash": DIGEST, "artifactDigest": DIGEST, "observedAt": 2
    });
    let mut report_injected = report.clone();
    report_injected.as_object_mut().unwrap().insert("authorizationReceiptId".into(), json!(RECEIPT));
    let report_lineage_injection_rejected = accepts::<device_certificate_reported::IdentityDeviceCertificateReportedPayload>(report)
        && rejects::<device_certificate_reported::IdentityDeviceCertificateReportedPayload>(report_injected);

    let committed = json!({
        "ingressEnvelopeId": "ingress-1", "deviceId": DEVICE, "authorizationReceiptId": RECEIPT,
        "desiredGeneration": 7, "outcome": "committed", "reason": "None", "committedAt": 3
    });
    let mut committed_without_lineage = committed.clone();
    committed_without_lineage.as_object_mut().unwrap().remove("authorizationReceiptId");
    let committed_lineage_required = accepts::<device_ingress_receipted::IdentityDeviceIngressReceiptedPayload>(committed)
        && rejects::<device_ingress_receipted::IdentityDeviceIngressReceiptedPayload>(committed_without_lineage);

    let rejected = json!({
        "ingressEnvelopeId": "ingress-2", "deviceId": DEVICE,
        "outcome": "rejected", "reason": "NotAccepted", "committedAt": 4
    });
    let mut rejected_injected = rejected.clone();
    rejected_injected.as_object_mut().unwrap().insert("authorizationReceiptId".into(), json!(RECEIPT));
    rejected_injected.as_object_mut().unwrap().insert("desiredGeneration".into(), json!(7));
    let rejected_lineage_injection_rejected = accepts::<device_ingress_receipted::IdentityDeviceIngressReceiptedPayload>(rejected)
        && rejects::<device_ingress_receipted::IdentityDeviceIngressReceiptedPayload>(rejected_injected);

    println!("{}", json!({
        "package": "rss-device-security-contracts",
        "sixModulesConsumed": modules.len() == 6,
        "descriptorsVerified": descriptors_verified,
        "schemaBytesAndDigestsVerified": schema_bytes_and_digests_verified,
        "draftLifecycleVerified": modules.iter().all(|(_, lifecycle, _)| *lifecycle == "draft"),
        "policyLineageRequired": policy_lineage_required,
        "policySchemaConstraintsEnforced": policy_schema_constraints_enforced,
        "policyErrorEnvelopeUniform": policy_error_envelope_uniform,
        "statusClosedVariants": status_closed_variants,
        "commandLineageRequired": command_lineage_required,
        "ackLineageInjectionRejected": ack_lineage_injection_rejected,
        "reportLineageInjectionRejected": report_lineage_injection_rejected,
        "committedLineageRequired": committed_lineage_required,
        "rejectedLineageInjectionRejected": rejected_lineage_injection_rejected,
        "receiptConversionsConverge": parsed_receipt == restored_receipt,
        "receiptDebugRedacted": format!("{parsed_receipt:?}") == "AuthorizationReceiptId(<redacted>)",
        "nilReceiptRejected": "00000000-0000-0000-0000-000000000000".parse::<AuthorizationReceiptId>().is_err()
    }));
}
