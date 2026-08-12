use generated::http::runtime_v1::inventory::{
    ROUTE, RuntimeInventoryRequest, RuntimeInventoryResponse, project_read_result,
};

fn observation() -> Result<
    assembly_schema::runtime_inventory::RuntimeInventoryObservation,
    Box<dyn std::error::Error>,
> {
    use assembly_schema::runtime_inventory as model;
    let digest = |byte: char| {
        model::CanonicalSha256Digest::parse(format!("sha256:{}", byte.to_string().repeat(64)))
    };
    let parts = model::RuntimeInventoryParts::new(
        model::RuntimeInventoryIdentity::for_test(digest('a')?, digest('b')?),
        Some(model::RuntimeInventoryBuildMetadata::new(
            "d".repeat(40),
            digest('e')?,
        )),
        vec![assembly_schema::AssemblyDomain::Identity],
        vec![
            model::RuntimeInventoryActivatedWorkflow::executing_projection(
                "settings.config-projection".to_owned(),
                "v1".to_owned(),
                digest('c')?,
                model::RuntimeInventoryExecutingProjectionActivation::Shadow,
                model::RuntimeInventoryProjectionExecution::new(
                    "v3".to_owned(),
                    model::RuntimeInventoryProjectionWorkerStatus::Healthy {
                        selected_generation: model::RuntimeInventorySelectedGeneration::Uniform(
                            "v3".to_owned(),
                        ),
                        max_lag: 7,
                    },
                ),
            ),
            model::RuntimeInventoryActivatedWorkflow::active_saga(
                "identity.rotate-credential".to_owned(),
                "v2".to_owned(),
                digest('f')?,
            ),
        ],
        vec![model::RuntimeInventoryListener::new(
            "admin".to_owned(),
            assembly_schema::AssemblyListenerKind::Admin,
            assembly_schema::ListenerAuth::Mtls,
            model::RuntimeInventoryEndpoint::new(
                model::RuntimeInventoryEndpointScheme::Http,
                "127.0.0.1".to_owned(),
                8080,
            ),
        )],
        vec![model::RuntimeInventoryProviderPosture::new(
            "construction-only".to_owned(),
            model::RuntimeInventoryProviderState::Unobserved,
        )],
        vec![model::RuntimeInventoryPlacement::new(
            assembly_schema::AssemblyDomain::Identity,
            "runtime".to_owned(),
            model::RuntimeInventoryPlacementMode::Local,
            None,
            None,
            model::RuntimeInventoryPlacementReadiness::Ready,
        )],
    );
    Ok(model::RuntimeInventoryObservation::for_test(parts)?)
}

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
            "buildMetadata": {
                "sourceRevision": "d".repeat(40),
                "imageDigest": format!("sha256:{}", "e".repeat(64))
            },
            "runtimePlanFingerprint": format!("sha256:{}", "b".repeat(64)),
            "schemaVersion": 2,
            "activatedWorkflows": [{
                "mode": "projection",
                "id": "settings.config-projection",
                "definitionVersion": "v1",
                "definitionSchemaDigest": format!("sha256:{}", "c".repeat(64)),
                "activation": "shadow",
                "targetGeneration": "v3",
                "workerStatus": {
                    "state": "healthy",
                    "selectedGeneration": { "state": "uniform", "generation": "v3" },
                    "maxLag": 7
                }
            }, {
                "mode": "saga",
                "id": "identity.rotate-credential",
                "definitionVersion": "v2",
                "definitionSchemaDigest": format!("sha256:{}", "f".repeat(64)),
                "activation": "active"
            }],
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
    assert!(encoded["data"].get("activatedWorkflows").is_some());
    assert!(encoded["data"].get("provider_posture").is_none());
    assert!(encoded["data"].get("deploymentFingerprint").is_none());
    assert_eq!(
        encoded["data"]["buildMetadata"]["sourceRevision"],
        "d".repeat(40)
    );
    assert_eq!(
        encoded["data"]["buildMetadata"]["imageDigest"],
        format!("sha256:{}", "e".repeat(64))
    );

    let mut unknown = encoded;
    unknown["data"]["secretSentinel"] = serde_json::json!("must-not-pass");
    assert!(serde_json::from_value::<RuntimeInventoryResponse>(unknown).is_err());
    assert!(
        serde_json::from_value::<RuntimeInventoryRequest>(serde_json::json!({"extra": true}))
            .is_err()
    );

    let mut legacy = valid_response();
    legacy["data"]["deploymentFingerprint"] =
        serde_json::json!(format!("sha256:{}", "c".repeat(64)));
    assert!(serde_json::from_value::<RuntimeInventoryResponse>(legacy).is_err());

    let mut missing_activated_workflows = valid_response();
    missing_activated_workflows["data"]
        .as_object_mut()
        .ok_or_else(|| std::io::Error::other("inventory data fixture must be an object"))?
        .remove("activatedWorkflows");
    assert!(
        serde_json::from_value::<RuntimeInventoryResponse>(missing_activated_workflows).is_err()
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

    let mut invalid_build_metadata = valid.clone();
    invalid_build_metadata["data"]["buildMetadata"]["sourceRevision"] =
        serde_json::json!("A".repeat(40));
    assert!(
        validator.validate(&invalid_build_metadata).is_err(),
        "build metadata source revision must be a lowercase Git object id"
    );

    let mut disabled_workflow = valid.clone();
    disabled_workflow["data"]["activatedWorkflows"][0]["activation"] =
        serde_json::json!("disabled");
    assert!(
        validator.validate(&disabled_workflow).is_err(),
        "activated workflows must exclude disabled entries"
    );
    assert!(serde_json::from_value::<RuntimeInventoryResponse>(disabled_workflow).is_err());

    let mut mismatched_tag = valid.clone();
    mismatched_tag["data"]["activatedWorkflows"][0]["mode"] = serde_json::json!("saga");
    assert!(
        validator.validate(&mismatched_tag).is_err(),
        "the workflow mode tag must select exactly one strict variant"
    );
    assert!(serde_json::from_value::<RuntimeInventoryResponse>(mismatched_tag).is_err());

    let mut legacy_version = valid.clone();
    legacy_version["data"]["schemaVersion"] = serde_json::json!(1);
    assert!(validator.validate(&legacy_version).is_err());
    assert!(serde_json::from_value::<RuntimeInventoryResponse>(legacy_version).is_err());

    for missing in ["targetGeneration", "workerStatus"] {
        let mut executing_missing_required = valid.clone();
        executing_missing_required["data"]["activatedWorkflows"][0]
            .as_object_mut()
            .ok_or_else(|| std::io::Error::other("projection fixture must be an object"))?
            .remove(missing);
        assert!(
            validator.validate(&executing_missing_required).is_err(),
            "executing projection must require {missing}"
        );
        assert!(
            serde_json::from_value::<RuntimeInventoryResponse>(executing_missing_required).is_err(),
            "generated DTO must require {missing}"
        );
    }

    let mut valid_capture_only = valid.clone();
    valid_capture_only["data"]["activatedWorkflows"][0]["activation"] =
        serde_json::json!("capture-only");
    let capture = valid_capture_only["data"]["activatedWorkflows"][0]
        .as_object_mut()
        .ok_or_else(|| std::io::Error::other("projection fixture must be an object"))?;
    let target_generation = capture
        .remove("targetGeneration")
        .ok_or_else(|| std::io::Error::other("executing fixture must have targetGeneration"))?;
    let worker_status = capture
        .remove("workerStatus")
        .ok_or_else(|| std::io::Error::other("executing fixture must have workerStatus"))?;
    assert!(validator.validate(&valid_capture_only).is_ok());
    assert!(serde_json::from_value::<RuntimeInventoryResponse>(valid_capture_only.clone()).is_ok());

    for (forbidden, value) in [
        ("targetGeneration", target_generation),
        ("workerStatus", worker_status),
    ] {
        let mut capture_with_execution_field = valid_capture_only.clone();
        capture_with_execution_field["data"]["activatedWorkflows"][0][forbidden] = value;
        assert!(
            validator.validate(&capture_with_execution_field).is_err(),
            "capture-only projection must reject {forbidden}"
        );
        assert!(
            serde_json::from_value::<RuntimeInventoryResponse>(capture_with_execution_field)
                .is_err(),
            "generated DTO must reject capture-only {forbidden}"
        );
    }

    for invalid_status in [
        serde_json::json!({"state": "starting", "maxLag": 0}),
        serde_json::json!({
            "state": "unavailable",
            "reason": "sweep-incomplete",
            "selectedGeneration": {"state": "none"}
        }),
        serde_json::json!({
            "state": "stopped",
            "stopClass": "fatal",
            "reason": "other"
        }),
        serde_json::json!({
            "state": "healthy",
            "selectedGeneration": {"state": "uniform"},
            "maxLag": 0
        }),
    ] {
        let mut instance = valid.clone();
        instance["data"]["activatedWorkflows"][0]["workerStatus"] = invalid_status;
        assert!(validator.validate(&instance).is_err());
        assert!(serde_json::from_value::<RuntimeInventoryResponse>(instance).is_err());
    }

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
fn runtime_inventory_accepts_unobserved_and_rejects_unknown_provider_state()
-> Result<(), Box<dyn std::error::Error>> {
    let mut unobserved = valid_response();
    unobserved["data"]["providerPosture"] = serde_json::json!([
        {"id": "construction-only", "state": "unobserved"}
    ]);
    serde_json::from_value::<RuntimeInventoryResponse>(unobserved.clone())?;
    let schema = response_schema()?;
    let validator = jsonschema::draft7::options().build(&schema)?;
    assert!(validator.validate(&unobserved).is_ok());

    unobserved["data"]["providerPosture"][0]["state"] = serde_json::json!("unknown");
    assert!(serde_json::from_value::<RuntimeInventoryResponse>(unobserved.clone()).is_err());
    assert!(validator.validate(&unobserved).is_err());
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

#[test]
fn runtime_inventory_projection_is_complete_and_owns_schema_version()
-> Result<(), Box<dyn std::error::Error>> {
    let response = RuntimeInventoryResponse::try_from(observation()?)?;
    let value = serde_json::to_value(response)?;
    let schema = response_schema()?;
    let validator = jsonschema::draft7::options().build(&schema)?;
    assert!(validator.validate(&value).is_ok());
    assert_eq!(value["data"]["schemaVersion"], 2);
    assert_eq!(value["data"]["providerPosture"][0]["state"], "unobserved");
    assert_eq!(
        value["data"]["activatedWorkflows"].as_array().map(Vec::len),
        Some(2)
    );
    assert_eq!(value["data"]["listeners"][0]["endpoint"]["port"], 8080);
    assert_eq!(value["data"]["placements"][0]["readiness"], "ready");
    assert_eq!(
        value["data"]["buildMetadata"]["sourceRevision"],
        "d".repeat(40)
    );
    Ok(())
}

#[test]
fn runtime_inventory_read_failures_have_one_closed_core_policy()
-> Result<(), Box<dyn std::error::Error>> {
    use assembly_schema::runtime_inventory::{
        RuntimeInventoryInvariantKind, RuntimeInventoryReadFailure,
    };
    use generated::http::runtime_v1::inventory::{
        RuntimeInventoryProjectionFailure, RuntimeInventoryProjectionStage,
    };
    let unavailable = project_read_result(Err(RuntimeInventoryReadFailure::Unavailable))
        .err()
        .ok_or_else(|| std::io::Error::other("unpublished inventory must fail"))?
        .core_error();
    assert_eq!(
        unavailable.kind(),
        vocab::CoreErrorKind::ProviderUnavailable
    );
    let invariant_failure = project_read_result(Err(RuntimeInventoryReadFailure::Invariant(
        RuntimeInventoryInvariantKind::Listeners,
    )))
    .err()
    .ok_or_else(|| std::io::Error::other("invariant failure must fail"))?;
    assert_eq!(
        invariant_failure.diagnostic_stage(),
        Some("observation.listeners")
    );
    let invariant = invariant_failure.core_error();
    assert_eq!(invariant.kind(), vocab::CoreErrorKind::Internal);
    let projection =
        RuntimeInventoryProjectionFailure::Projection(RuntimeInventoryProjectionStage::ListenerId);
    assert_eq!(
        projection.diagnostic_stage(),
        Some("projection.listener.id")
    );
    assert_eq!(
        projection.core_error().kind(),
        vocab::CoreErrorKind::Internal
    );
    Ok(())
}
