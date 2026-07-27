use generated::http::runtime_v1::inventory::{
    ROUTE, RuntimeInventoryRequest, RuntimeInventoryResponse,
};

fn response_schema() -> Result<serde_json::Value, serde_json::Error> {
    serde_json::from_slice(include_bytes!(
        "../../contracts/http/runtime/v1/inventory/response.schema.json"
    ))
}

fn valid_response() -> serde_json::Value {
    let fingerprint = format!("sha256:{}", "a".repeat(64));
    serde_json::json!({
        "data": {
            "assemblyFingerprint": fingerprint,
            "runtimePlanFingerprint": format!("sha256:{}", "b".repeat(64)),
            "deploymentFingerprint": format!("sha256:{}", "c".repeat(64)),
            "buildIdentity": {
                "sourceSha": "d".repeat(40),
                "imageDigest": format!("sha256:{}", "e".repeat(64))
            },
            "schemaVersion": 1,
            "domains": ["identity"],
            "listeners": [],
            "providerPosture": [],
            "placements": [{
                "domain": "identity",
                "workload": "runtime",
                "mode": "local",
                "readiness": "ready"
            }]
        }
    })
}

#[test]
fn runtime_inventory_wire_is_closed_and_camel_case() -> Result<(), Box<dyn std::error::Error>> {
    let value = valid_response();
    let response: RuntimeInventoryResponse = serde_json::from_value(value)?;
    let encoded = serde_json::to_value(response)?;
    assert!(encoded["data"].get("providerPosture").is_some());
    assert!(encoded["data"].get("provider_posture").is_none());

    let mut unknown = encoded;
    unknown["data"]["secretSentinel"] = serde_json::json!("must-not-pass");
    assert!(serde_json::from_value::<RuntimeInventoryResponse>(unknown).is_err());
    assert!(
        serde_json::from_value::<RuntimeInventoryRequest>(serde_json::json!({"extra": true}))
            .is_err()
    );
    Ok(())
}

#[test]
fn runtime_inventory_instances_obey_response_schema() -> Result<(), Box<dyn std::error::Error>> {
    let schema = response_schema()?;
    let validator = jsonschema::draft7::options().build(&schema)?;
    let valid = valid_response();
    assert!(
        validator.validate(&valid).is_ok(),
        "canonical response must satisfy the published schema"
    );

    let mut empty_domains = valid.clone();
    empty_domains["data"]["domains"] = serde_json::json!([]);
    assert!(
        validator.validate(&empty_domains).is_err(),
        "domains minItems must be enforced against instances"
    );

    let mut missing_readiness = valid;
    missing_readiness["data"]["placements"][0]
        .as_object_mut()
        .ok_or_else(|| std::io::Error::other("placement fixture must be an object"))?
        .remove("readiness");
    assert!(
        validator.validate(&missing_readiness).is_err(),
        "placement readiness must be required by the wire contract"
    );
    Ok(())
}

#[test]
fn runtime_inventory_route_identity_is_exact() {
    let evidence = ROUTE.evidence();
    assert_eq!(evidence.contract_id(), "runtime.inventory");
    assert_eq!(evidence.method(), "GET");
    assert_eq!(evidence.path(), "/api/v1/runtime/inventory");
    assert_eq!(evidence.resource(), Some("runtimeInventory"));
    assert_eq!(
        evidence.resource_sharing(),
        vocab::http::HttpResourceSharing::Global
    );
    assert_eq!(
        evidence.auth(),
        vocab::HttpRouteAuth::Permission(vocab::RoutePermissionId::RuntimeInventoryRead)
    );
}
