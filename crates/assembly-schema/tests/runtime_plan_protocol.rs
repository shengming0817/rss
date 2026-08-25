#![allow(clippy::expect_used, clippy::unwrap_used)]
// reason: protocol fixtures should fail at the exact local assertion when their frozen bytes drift.

use assembly_schema::{
    AssemblyManifest, CanonicalAssemblyManifestV2, ParsedAssemblyLock, ParsedRuntimePlan,
    RepositoryVerifiedAssemblyLock, RuntimePlan, RuntimePlanErrorStage, RuntimePlanJsonCategory,
    validate_runtime_plan_json_slice,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const RUNTIME_PLAN_TAG: &str = "rss-runtime-plan-v4";
const ASSEMBLY_PLAN_TAG: &str = "rss-assembly-lock-v3";
const SECRET_SENTINEL: &str = "ZZ_RUNTIME_PLAN_SECRET_1788_DO_NOT_SERIALIZE";

fn vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/fingerprint-v2-vectors.json"))
        .expect("shared fingerprint vectors")
}

fn runtime_vector() -> Value {
    vectors()["vectors"]
        .as_array()
        .expect("vector array")
        .iter()
        .find(|vector| vector["name"] == "runtime-plan-closed")
        .expect("runtime plan vector")
        .clone()
}

fn assembly_lock_vector() -> Value {
    vectors()["vectors"]
        .as_array()
        .expect("vector array")
        .iter()
        .find(|vector| vector["name"] == "assembly-lock-production")
        .expect("assembly lock vector")
        .clone()
}

fn canonical_bytes(value: &impl Serialize) -> Vec<u8> {
    serde_json_canonicalizer::to_vec(value).expect("RFC 8785 canonical JSON")
}

fn tagged_fingerprint(tag: &str, value: &impl Serialize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(tag.as_bytes());
    hasher.update([0]);
    hasher.update(canonical_bytes(value));
    format!("sha256:{:x}", hasher.finalize())
}

fn wire_from_vector() -> Value {
    let vector = runtime_vector();
    seal_unsigned(vector["unsigned"].clone())
}

fn assembly_lock_wire_from_vector() -> Value {
    let vector = assembly_lock_vector();
    let mut unsigned = vector["unsigned"].clone();
    let fingerprint = tagged_fingerprint(ASSEMBLY_PLAN_TAG, &unsigned);
    unsigned
        .as_object_mut()
        .expect("unsigned AssemblyLock object")
        .insert("fingerprint".to_owned(), Value::String(fingerprint));
    unsigned
}

fn manifest_bound_workflow_fixture() -> (
    CanonicalAssemblyManifestV2,
    RepositoryVerifiedAssemblyLock,
    Value,
) {
    let manifest =
        AssemblyManifest::from_toml_str(include_str!("../../../assemblies/runtime/assembly.toml"))
            .expect("bound fixture manifest")
            .canonicalize_v2()
            .expect("canonical bound fixture manifest");
    let lock = repository_verified_lock(
        "runtime",
        include_bytes!("../../../assemblies/runtime/assembly.lock.json"),
    );
    let plan_wire = serde_json::from_slice(include_bytes!(
        "../../../assemblies/runtime/runtime-plan.json"
    ))
    .expect("committed runtime plan");
    ParsedRuntimePlan::from_json_slice_bound(
        &serde_json::to_vec(&plan_wire).expect("bound fixture RuntimePlan JSON"),
        &manifest,
        &lock,
    )
    .expect("valid manifest-bound workflow fixture");
    (manifest, lock, plan_wire)
}

fn repository_verified_lock(name: &str, bytes: &[u8]) -> RepositoryVerifiedAssemblyLock {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("repository root");
    let source = assembly_schema::RepositoryAssemblyManifestV2::discover_v2(
        root,
        &root.join("assemblies").join(name),
    )
    .expect("repository assembly manifest");
    ParsedAssemblyLock::from_json_slice(bytes)
        .expect("parsed AssemblyLock")
        .verify_repository_v2(&source)
        .expect("repository-verified AssemblyLock")
}

fn seal_unsigned(mut unsigned: Value) -> Value {
    let fingerprint = tagged_fingerprint(RUNTIME_PLAN_TAG, &unsigned);
    let mut wire = unsigned
        .as_object_mut()
        .expect("unsigned RuntimePlan object")
        .clone();
    wire.insert(
        "runtimePlanFingerprint".to_owned(),
        Value::String(fingerprint),
    );
    Value::Object(wire)
}

fn parse_result(value: &Value) -> Result<(), assembly_schema::RuntimePlanError> {
    validate_runtime_plan_json_slice(&serde_json::to_vec(value).expect("wire JSON"))
}

fn assert_reader_rejects(value: Value, expected_diagnostic: &str) {
    let error = parse_result(&value).expect_err("invalid RuntimePlan must fail closed");
    assert!(
        error.to_string().contains(expected_diagnostic),
        "expected diagnostic `{expected_diagnostic}`, got `{error}` for {value}"
    );
}

fn expanded_unsigned() -> Value {
    let mut unsigned = runtime_vector()["unsigned"].clone();
    unsigned["providerPlans"] = json!([
        {"id":"a-provider","constructor":"amqp::AmqpPublisher","activation":{"kind":"localEventExecution"},"outputs":["probes"]},
        {"id":"z-provider","constructor":"oidc::OidcProvider","activation":{"kind":"process"},"outputs":["workers"]}
    ]);
    unsigned["listenerPlans"] = json!([
        {"id":"admin-main","kind":"admin","auth":"rssAccessToken","domains":["identity"]},
        {"id":"primary-main","kind":"primary","auth":"rssAccessToken","domains":["settings"]}
    ]);
    unsigned["domainPlans"] = json!([
        {"id":"identity","lifecycle":["construct","ready","shutdown"]},
        {"id":"settings","lifecycle":["construct","ready","shutdown"]}
    ]);
    unsigned["placementPlans"] = json!([
        {"domain":"identity","workload":"runtime"},
        {"domain":"settings","workload":"runtime"}
    ]);
    unsigned
}

fn wire_with_fingerprint(unsigned: Value, fingerprint: Value) -> Value {
    let mut wire = unsigned;
    wire.as_object_mut()
        .expect("unsigned object")
        .insert("runtimePlanFingerprint".to_owned(), fingerprint);
    wire
}

fn parse(value: &Value) -> Option<()> {
    parse_result(value).ok()
}

#[test]
fn runtime_plan_shared_vector_freezes_rfc8785_bytes_and_tagged_fingerprint() {
    let vector = runtime_vector();
    let unsigned = &vector["unsigned"];
    let canonical_hex = canonical_bytes(unsigned)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    assert_eq!(vector["stageTag"], RUNTIME_PLAN_TAG);
    assert_eq!(canonical_hex, vector["canonicalHex"]);
    assert_eq!(
        tagged_fingerprint(RUNTIME_PLAN_TAG, unsigned),
        vector["expected"]
    );
    assert_ne!(
        tagged_fingerprint(ASSEMBLY_PLAN_TAG, unsigned),
        vector["expected"],
        "a fingerprint from another protocol stage must not validate"
    );
}

#[test]
fn assembly_lock_shared_vector_is_v3_and_the_reader_rejects_v2() {
    let vector = assembly_lock_vector();
    let unsigned = &vector["unsigned"];
    let canonical_hex = canonical_bytes(unsigned)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    assert_eq!(vector["stageTag"], ASSEMBLY_PLAN_TAG);
    assert_eq!(canonical_hex, vector["canonicalHex"]);
    assert_eq!(
        tagged_fingerprint(ASSEMBLY_PLAN_TAG, unsigned),
        vector["expected"]
    );

    let valid = assembly_lock_wire_from_vector();
    ParsedAssemblyLock::from_json_slice(&serde_json::to_vec(&valid).expect("lock JSON"))
        .expect("valid v3 AssemblyLock vector");
    let committed: Value =
        serde_json::from_str(include_str!("../schemas/assembly-lock.schema.json"))
            .expect("committed AssemblyLock schema");
    assert_eq!(committed["properties"]["schemaVersion"]["const"], 3);
    let validator = jsonschema::draft7::options()
        .should_validate_formats(true)
        .build(&committed)
        .expect("Draft-07 AssemblyLock schema");
    assert!(validator.validate(&valid).is_ok());

    let mut v2 = valid;
    v2["schemaVersion"] = json!(2);
    assert!(validator.validate(&v2).is_err());
    let result = ParsedAssemblyLock::from_json_slice(&serde_json::to_vec(&v2).expect("lock JSON"));
    assert!(result.is_err(), "AssemblyLock v2 must be rejected");
    let Some(error) = result.err() else {
        return;
    };
    assert!(
        error
            .to_string()
            .contains("unsupported AssemblyLock schemaVersion 2")
    );
}

#[test]
fn runtime_plan_reader_accepts_the_shared_closed_vector() {
    let vector = runtime_vector();
    let wire = wire_from_vector();
    parse(&wire).expect("valid shared RuntimePlan vector");

    assert_eq!(wire["schemaVersion"], 4);
    assert_eq!(wire["planKind"], json!({"kind": "generic"}));
    assert_eq!(
        wire["assemblyFingerprint"],
        vector["unsigned"]["assemblyFingerprint"].clone()
    );
    assert_eq!(wire["runtimePlanFingerprint"], vector["expected"].clone());
    assert_eq!(wire["providerPlans"][0]["id"], "pdp");
    assert_eq!(
        wire["providerPlans"][0]["constructor"],
        "oidc::OidcProvider"
    );
    assert_eq!(wire["listenerPlans"][0]["id"], "health-main");
    assert_eq!(wire["listenerPlans"][1]["id"], "primary-main");
    assert_eq!(wire["domainPlans"][0]["id"], "identity");
    assert_eq!(wire["placementPlans"][0]["workload"], "runtime");
    assert_eq!(wire["workflowPlans"].as_array().map(Vec::len), Some(2));
    assert_eq!(wire["workflowPlans"][0]["id"], "identity.account-view");
    assert_eq!(wire["workflowPlans"][1]["id"], "settings.bootstrap");
}

#[test]
fn runtime_plan_reader_is_closed_and_fails_on_bad_version_enum_or_digest() {
    let valid = wire_from_vector();

    let mut unknown_root = valid.clone();
    unknown_root
        .as_object_mut()
        .unwrap()
        .insert("legacy".to_owned(), json!(true));

    let mut unknown_provider = valid.clone();
    unknown_provider["providerPlans"][0]
        .as_object_mut()
        .unwrap()
        .insert("port".to_owned(), json!("diport::Pdp"));

    let mut unknown_activation = valid.clone();
    unknown_activation["providerPlans"][0]["activation"]
        .as_object_mut()
        .unwrap()
        .insert("unexpected".to_owned(), json!("smuggled"));

    let mut unknown_auth = valid.clone();
    unknown_auth["listenerPlans"][0]["auth"] = json!("bearer");

    let mut unknown_constructor = valid.clone();
    unknown_constructor["providerPlans"][0]["constructor"] = json!("https://secret.example/token");

    let mut unknown_lifecycle = valid.clone();
    unknown_lifecycle["domainPlans"][0]["lifecycle"][1] = json!("started");

    let mut unsupported_version = valid.clone();
    unsupported_version["schemaVersion"] = json!(1);
    let unsupported_error = parse_result(&unsupported_version)
        .expect_err("RuntimePlan v1 must be rejected with a typed version error");
    assert_eq!(
        unsupported_error.stage(),
        RuntimePlanErrorStage::SchemaVersion
    );
    assert_eq!(
        unsupported_error.to_string(),
        "unsupported RuntimePlan schemaVersion 1; supported schemaVersion is 4; regenerate the RuntimePlan"
    );

    let mut uppercase_digest = valid.clone();
    uppercase_digest["assemblyFingerprint"] =
        json!("sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    let mut wrong_fingerprint = valid.clone();
    wrong_fingerprint["runtimePlanFingerprint"] =
        json!("sha256:0000000000000000000000000000000000000000000000000000000000000000");
    assert_reader_rejects(wrong_fingerprint, "fingerprint mismatch");

    for invalid in [
        unknown_root,
        unknown_provider,
        unknown_activation,
        unknown_auth,
        unknown_constructor,
        unknown_lifecycle,
        unsupported_version,
        uppercase_digest,
    ] {
        assert!(
            parse(&invalid).is_none(),
            "strict RuntimePlan reader accepted invalid wire: {invalid}"
        );
    }
}

#[test]
fn repository_bound_workflows_round_trip_without_capability_requirements() {
    let (manifest, lock, wire) = manifest_bound_workflow_fixture();
    let wire_text = serde_json::to_string(&wire).expect("serialize RuntimePlan text");
    assert!(!wire_text.contains("capabilityRequirement"));

    let bytes = serde_json::to_vec(&wire).expect("serialize omission RuntimePlan bytes");
    validate_runtime_plan_json_slice(&bytes).expect("strict RuntimePlan reader");
    let parsed = ParsedRuntimePlan::from_json_slice_bound(&bytes, &manifest, &lock)
        .expect("repository-bound RuntimePlan reader");
    assert_eq!(
        parsed.workflow_plans().len(),
        manifest.workflow_activations().len()
    );
}

#[test]
fn runtime_plan_reader_rejects_complete_negative_matrix() {
    for field in ["providerPlans", "domainPlans", "placementPlans"] {
        let mut missing = runtime_vector()["unsigned"].clone();
        missing[field] = json!([]);
        assert_reader_rejects(seal_unsigned(missing), "must not be empty");
    }

    let mut listenerless = runtime_vector()["unsigned"].clone();
    listenerless["listenerPlans"] = json!([]);
    parse_result(&seal_unsigned(listenerless))
        .expect("library-only RuntimePlan may intentionally own no listener");

    for field in [
        "providerPlans",
        "listenerPlans",
        "domainPlans",
        "placementPlans",
    ] {
        let mut duplicate = runtime_vector()["unsigned"].clone();
        let fact = duplicate[field]
            .as_array()
            .and_then(|facts| facts.last())
            .expect("non-empty plan array")
            .clone();
        duplicate[field]
            .as_array_mut()
            .expect("plan array")
            .push(fact);
        assert_reader_rejects(seal_unsigned(duplicate), "duplicate keyed facts");
    }

    let mut dangling_listener = runtime_vector()["unsigned"].clone();
    dangling_listener["listenerPlans"][0]["domains"] = json!(["settings"]);
    assert_reader_rejects(seal_unsigned(dangling_listener), "dangling reference");

    let mut dangling_placement = runtime_vector()["unsigned"].clone();
    dangling_placement["placementPlans"][0]["domain"] = json!("settings");
    assert_reader_rejects(seal_unsigned(dangling_placement), "dangling reference");

    let mut reverse_listeners = expanded_unsigned();
    reverse_listeners["listenerPlans"]
        .as_array_mut()
        .expect("listener plans")
        .reverse();
    assert_reader_rejects(seal_unsigned(reverse_listeners), "not in canonical order");

    let mut reverse_placements = expanded_unsigned();
    reverse_placements["placementPlans"]
        .as_array_mut()
        .expect("placement plans")
        .reverse();
    assert_reader_rejects(seal_unsigned(reverse_placements), "not in canonical order");

    let mut reverse_workflows = runtime_vector()["unsigned"].clone();
    reverse_workflows["workflowPlans"]
        .as_array_mut()
        .expect("workflow plans")
        .reverse();
    assert_reader_rejects(seal_unsigned(reverse_workflows), "not in canonical order");

    let mut duplicate_workflow = runtime_vector()["unsigned"].clone();
    let duplicate = duplicate_workflow["workflowPlans"][0].clone();
    duplicate_workflow["workflowPlans"]
        .as_array_mut()
        .expect("workflow plans")
        .insert(1, duplicate);
    assert_reader_rejects(seal_unsigned(duplicate_workflow), "duplicate keyed facts");

    let mut missing_workflows = runtime_vector()["unsigned"].clone();
    missing_workflows
        .as_object_mut()
        .expect("unsigned RuntimePlan")
        .remove("workflowPlans");
    assert!(
        parse(&seal_unsigned(missing_workflows)).is_none(),
        "required workflowPlans field was accepted when missing"
    );

    let mut leaked_requirements = runtime_vector()["unsigned"].clone();
    leaked_requirements["workflowPlans"][0]
        .as_object_mut()
        .expect("workflow plan")
        .insert("capabilityRequirements".to_owned(), json!(["source"]));
    assert!(
        parse(&seal_unsigned(leaked_requirements)).is_none(),
        "derived capability requirements entered the RuntimePlan wire"
    );

    let mut unsorted_outputs = runtime_vector()["unsigned"].clone();
    unsorted_outputs["providerPlans"][0]["outputs"] = json!(["workers", "probes"]);
    assert_reader_rejects(seal_unsigned(unsorted_outputs), "not in canonical order");
}

#[test]
fn manifest_bound_reader_rejects_missing_and_extra_workflow_plans() {
    let (manifest, lock, valid) = manifest_bound_workflow_fixture();

    let mut missing = valid.clone();
    missing
        .as_object_mut()
        .expect("RuntimePlan wire")
        .remove("runtimePlanFingerprint");
    missing["workflowPlans"]
        .as_array_mut()
        .expect("workflow plans")
        .pop();
    let missing = seal_unsigned(missing);
    let missing_result = ParsedRuntimePlan::from_json_slice_bound(
        &serde_json::to_vec(&missing).expect("missing workflow JSON"),
        &manifest,
        &lock,
    );
    assert!(missing_result.is_err());
    let Some(missing_error) = missing_result.err() else {
        return;
    };
    assert!(missing_error.to_string().contains("workflowPlans"));

    let mut extra = valid;
    extra
        .as_object_mut()
        .expect("RuntimePlan wire")
        .remove("runtimePlanFingerprint");
    extra["workflowPlans"]
        .as_array_mut()
        .expect("workflow plans")
        .push(json!({
            "mode": "projection",
            "id": "syshealth.extra-view",
            "definitionVersion": "v1",
            "definitionSchemaDigest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "targetGeneration": "extra-v1",
            "activation": "disabled"
        }));
    let extra = seal_unsigned(extra);
    let extra_result = ParsedRuntimePlan::from_json_slice_bound(
        &serde_json::to_vec(&extra).expect("extra workflow JSON"),
        &manifest,
        &lock,
    );
    assert!(extra_result.is_err());
    let Some(extra_error) = extra_result.err() else {
        return;
    };
    assert!(extra_error.to_string().contains("workflowPlans"));
}

#[test]
fn runtime_plan_reader_rejects_unstable_workload_ids_without_rewriting() {
    for workload in [
        "",
        "runtime service",
        "runtime/service",
        "https://runtime.example",
        "Runtime",
        "runtime_1",
    ] {
        let mut unsigned = runtime_vector()["unsigned"].clone();
        unsigned["placementPlans"][0]["workload"] = json!(workload);
        assert_reader_rejects(seal_unsigned(unsigned), "placementPlans.workload");
    }
}

#[test]
fn runtime_plan_fingerprint_covers_every_unsigned_fact_but_not_itself() {
    let vector = runtime_vector();
    let unsigned = vector["unsigned"].clone();
    let expected = vector["expected"].as_str().expect("expected fingerprint");

    let mutations: Vec<(&str, Value)> = vec![
        ("schema version", {
            let mut value = unsigned.clone();
            value["schemaVersion"] = json!(1);
            value
        }),
        ("assembly fingerprint", {
            let mut value = unsigned.clone();
            value["assemblyFingerprint"] =
                json!("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            value
        }),
        ("provider id", {
            let mut value = unsigned.clone();
            value["providerPlans"][0]["id"] = json!("other-pdp");
            value
        }),
        ("provider constructor", {
            let mut value = unsigned.clone();
            value["providerPlans"][0]["constructor"] = json!("amqp::AmqpPublisher");
            value
        }),
        ("provider outputs", {
            let mut value = unsigned.clone();
            value["providerPlans"][0]["outputs"] = json!(["workers"]);
            value
        }),
        ("listener id", {
            let mut value = unsigned.clone();
            value["listenerPlans"][0]["id"] = json!("primary-alt");
            value
        }),
        ("listener kind", {
            let mut value = unsigned.clone();
            value["listenerPlans"][0]["kind"] = json!("admin");
            value
        }),
        ("listener auth", {
            let mut value = unsigned.clone();
            value["listenerPlans"][0]["auth"] = json!("mtls");
            value
        }),
        ("listener domains", {
            let mut value = unsigned.clone();
            value["listenerPlans"][0]["domains"] = json!(["settings"]);
            value
        }),
        ("domain id", {
            let mut value = unsigned.clone();
            value["domainPlans"][0]["id"] = json!("settings");
            value
        }),
        ("domain lifecycle", {
            let mut value = unsigned.clone();
            value["domainPlans"][0]["lifecycle"] =
                json!(["construct", "ready", "shutdown", "retired"]);
            value
        }),
        ("placement workload", {
            let mut value = unsigned.clone();
            value["placementPlans"][0]["workload"] = json!("runtime-canary");
            value
        }),
        ("placement domain", {
            let mut value = unsigned.clone();
            value["placementPlans"][0]["domain"] = json!("settings");
            value
        }),
        ("workflow mode", {
            let mut value = unsigned.clone();
            value["workflowPlans"][0]["mode"] = json!("saga");
            value
        }),
        ("workflow id", {
            let mut value = unsigned.clone();
            value["workflowPlans"][0]["id"] = json!("identity.account-view-canary");
            value
        }),
        ("workflow definition version", {
            let mut value = unsigned.clone();
            value["workflowPlans"][0]["definitionVersion"] = json!("v2");
            value
        }),
        ("workflow definition schema digest", {
            let mut value = unsigned.clone();
            value["workflowPlans"][0]["definitionSchemaDigest"] =
                json!("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
            value
        }),
        ("workflow activation", {
            let mut value = unsigned.clone();
            value["workflowPlans"][0]["activation"] = json!("active");
            value
        }),
    ];

    for (field, changed) in mutations {
        assert_ne!(
            tagged_fingerprint(RUNTIME_PLAN_TAG, &changed),
            expected,
            "{field} was omitted from the RuntimePlan preimage"
        );
    }

    let wire = wire_with_fingerprint(unsigned, json!(expected));
    let changed_self = {
        let mut changed = wire.clone();
        changed["runtimePlanFingerprint"] =
            json!("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        changed
    };
    let unsigned_again = |mut value: Value| {
        value
            .as_object_mut()
            .unwrap()
            .remove("runtimePlanFingerprint");
        value
    };
    assert_eq!(
        tagged_fingerprint(RUNTIME_PLAN_TAG, &unsigned_again(wire)),
        tagged_fingerprint(RUNTIME_PLAN_TAG, &unsigned_again(changed_self)),
        "the RuntimePlan fingerprint field must never enter its own preimage"
    );
}

#[test]
fn runtime_plan_reader_detects_semantics_preserving_fingerprint_mutations() {
    let expanded = seal_unsigned(expanded_unsigned());
    let mutations = [
        ("assembly fingerprint", {
            let mut value = expanded.clone();
            value["assemblyFingerprint"] =
                json!("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            value
        }),
        ("provider id", {
            let mut value = expanded.clone();
            value["providerPlans"][0]["id"] = json!("b-provider");
            value
        }),
        ("provider constructor", {
            let mut value = expanded.clone();
            value["providerPlans"][0]["constructor"] = json!("amqp::AmqpSubscriber");
            value
        }),
        ("provider outputs", {
            let mut value = expanded.clone();
            value["providerPlans"][0]["outputs"] = json!(["resources"]);
            value
        }),
        ("listener domains", {
            let mut value = expanded.clone();
            value["listenerPlans"][0]["domains"] = json!(["identity", "settings"]);
            value
        }),
        ("domain order", {
            let mut value = expanded.clone();
            value["domainPlans"]
                .as_array_mut()
                .expect("domain plans")
                .reverse();
            value
        }),
        ("placement workload", {
            let mut value = expanded.clone();
            value["placementPlans"][0]["workload"] = json!("runtime-canary");
            value
        }),
        ("workflow activation", {
            let mut value = expanded.clone();
            value["workflowPlans"][0]["activation"] = json!("active");
            value
        }),
    ];
    for (field, changed) in mutations {
        let error = parse_result(&changed).expect_err("stale fingerprint must fail");
        assert!(
            error.to_string().contains("fingerprint mismatch"),
            "{field} mutation bypassed the production fingerprint check: {error}"
        );
    }

    let mut internal = runtime_vector()["unsigned"].clone();
    internal["listenerPlans"][0] = json!({
        "id": "internal-main",
        "kind": "internal",
        "auth": "mtls",
        "domains": ["identity"]
    });
    let mut changed_auth = seal_unsigned(internal);
    changed_auth["listenerPlans"][0]["auth"] = json!("serviceToken");
    assert_reader_rejects(changed_auth, "fingerprint mismatch");
}

#[test]
fn runtime_plan_reader_rejects_duplicate_json_keys_and_does_not_echo_secret_values() {
    let wire = serde_json::to_string(&wire_from_vector()).expect("wire string");
    let duplicate = wire.replacen(
        "\"schemaVersion\":4",
        "\"schemaVersion\":4,\"schemaVersion\":4",
        1,
    );
    assert!(validate_runtime_plan_json_slice(duplicate.as_bytes()).is_err());

    let bait = wire.replacen(
        "\"schemaVersion\":4",
        &format!("\"secret\":\"{SECRET_SENTINEL}\",\"schemaVersion\":4"),
        1,
    );
    let result = validate_runtime_plan_json_slice(bait.as_bytes());
    assert!(
        result.is_err(),
        "secret-bearing unknown field must fail closed"
    );
    let error = result.expect_err("secret-bearing unknown field must fail closed");
    assert!(
        !error.to_string().contains(SECRET_SENTINEL),
        "strict reader error leaked an unknown secret value"
    );

    let auth_bait = wire.replace(
        "\"auth\":\"rssAccessToken\"",
        &format!("\"auth\":\"{SECRET_SENTINEL}\""),
    );
    let auth_error = validate_runtime_plan_json_slice(auth_bait.as_bytes())
        .expect_err("unknown auth must fail closed");
    assert!(!auth_error.to_string().contains(SECRET_SENTINEL));
    assert!(!format!("{auth_error:?}").contains(SECRET_SENTINEL));
}

#[test]
fn runtime_plan_reader_reports_sealed_redacted_json_stage_category_and_path() {
    let eof = validate_runtime_plan_json_slice(b"{").expect_err("truncated JSON must fail");
    assert_eq!(eof.stage(), RuntimePlanErrorStage::WireDecode);
    assert_eq!(eof.json_category(), Some(RuntimePlanJsonCategory::Eof));
    assert_eq!(eof.json_path().expect("JSON path").as_str(), "$");

    let mut wrong_type = wire_from_vector();
    wrong_type["providerPlans"][0]["outputs"] = json!("resources");
    let wrong_type = parse_result(&wrong_type).expect_err("wrong type must fail");
    assert_eq!(
        wrong_type.json_category(),
        Some(RuntimePlanJsonCategory::Data)
    );
    assert_eq!(
        wrong_type.json_path().expect("wrong-type path").as_str(),
        "$.providerPlans[0].outputs"
    );

    let mut missing = wire_from_vector();
    missing["providerPlans"][0]
        .as_object_mut()
        .expect("provider object")
        .remove("constructor");
    let missing = parse_result(&missing).expect_err("missing field must fail");
    assert_eq!(missing.json_category(), Some(RuntimePlanJsonCategory::Data));
    assert!(
        missing
            .json_path()
            .expect("missing-field path")
            .as_str()
            .starts_with("$.providerPlans[0]")
    );

    let mut unknown_constructor = wire_from_vector();
    unknown_constructor["providerPlans"][0]["constructor"] = json!(SECRET_SENTINEL);
    let unknown_constructor =
        parse_result(&unknown_constructor).expect_err("unknown constructor must fail");
    assert_eq!(
        unknown_constructor
            .json_path()
            .expect("unknown-constructor path")
            .as_str(),
        "$.providerPlans[0].constructor"
    );

    let mut secret_key = serde_json::to_string(&wire_from_vector()).expect("wire string");
    secret_key = secret_key.replacen(
        "\"schemaVersion\":4",
        &format!("\"{SECRET_SENTINEL}\":true,\"schemaVersion\":4"),
        1,
    );
    let unknown_field = validate_runtime_plan_json_slice(secret_key.as_bytes())
        .expect_err("unknown secret-bearing key must fail");

    for error in [
        &eof,
        &wrong_type,
        &missing,
        &unknown_constructor,
        &unknown_field,
    ] {
        assert_eq!(error.stage(), RuntimePlanErrorStage::WireDecode);
        assert!(
            error
                .json_path()
                .expect("strict JSON error path")
                .as_str()
                .starts_with('$')
        );
        assert!(!error.to_string().contains(SECRET_SENTINEL));
        assert!(!format!("{error:?}").contains(SECRET_SENTINEL));
    }
}

#[test]
fn runtime_plan_writer_validates_against_draft7_and_round_trips_through_the_reader() {
    let writer = wire_from_vector();
    parse(&writer).expect("shared vector");
    let committed: Value =
        serde_json::from_str(include_str!("../schemas/runtime-plan.schema.json"))
            .expect("committed schema");
    assert_eq!(
        committed["$id"],
        "https://rss.local/assembly-schema/runtime-plan.schema.json"
    );
    let validator = jsonschema::draft7::options()
        .should_validate_formats(true)
        .build(&committed)
        .expect("Draft-07 RuntimePlan schema");
    assert!(
        validator.validate(&writer).is_ok(),
        "the real RuntimePlan writer drifted from the committed Draft-07 schema"
    );

    let encoded = serde_json::to_vec(&writer).expect("writer bytes");
    validate_runtime_plan_json_slice(&encoded).expect("writer round-trip");
}

#[test]
fn runtime_plan_v4_freezes_closed_workflow_activation_states_without_capability_facts() {
    let committed: Value =
        serde_json::from_str(include_str!("../schemas/runtime-plan.schema.json"))
            .expect("committed schema");
    let validator = jsonschema::draft7::options()
        .should_validate_formats(true)
        .build(&committed)
        .expect("Draft-07 RuntimePlan schema");

    for activation in ["disabled", "capture-only", "shadow", "active"] {
        let mut unsigned = runtime_vector()["unsigned"].clone();
        unsigned["workflowPlans"] = json!([{
            "mode": "projection",
            "id": "identity.account-view",
            "definitionVersion": "v1",
            "definitionSchemaDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "targetGeneration": "materialized-v7",
            "activation": activation
        }]);
        let wire = seal_unsigned(unsigned);
        assert!(
            validator.validate(&wire).is_ok(),
            "projection state {activation}"
        );
        let result = parse_result(&wire);
        assert!(
            result.is_ok(),
            "projection state {activation} failed strict reader: {:?}",
            result.err()
        );
    }

    for activation in ["disabled", "active"] {
        let mut unsigned = runtime_vector()["unsigned"].clone();
        unsigned["workflowPlans"] = json!([{
            "mode": "saga",
            "id": "identity.recovery",
            "definitionVersion": "v1",
            "definitionSchemaDigest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "activation": activation
        }]);
        let wire = seal_unsigned(unsigned);
        assert!(validator.validate(&wire).is_ok(), "saga state {activation}");
        let result = parse_result(&wire);
        assert!(
            result.is_ok(),
            "saga state {activation} failed strict reader: {:?}",
            result.err()
        );
    }

    for (mode, activation) in [("projection", "paused"), ("saga", "shadow")] {
        let mut unsigned = runtime_vector()["unsigned"].clone();
        let mut workflow = json!({
            "mode": mode,
            "id": "identity.invalid-state",
            "definitionVersion": "v1",
            "definitionSchemaDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "activation": activation
        });
        if mode == "projection" {
            workflow["targetGeneration"] = json!("materialized-v7");
        }
        unsigned["workflowPlans"] = json!([workflow]);
        let wire = seal_unsigned(unsigned);
        assert!(
            validator.validate(&wire).is_err(),
            "{mode} accepted {activation}"
        );
        assert!(
            parse(&wire).is_none(),
            "strict reader accepted {mode}/{activation}"
        );
    }

    for plan in wire_from_vector()["workflowPlans"]
        .as_array()
        .expect("workflow plans")
    {
        let object = plan.as_object().expect("workflow plan object");
        let projection = object.get("mode").and_then(Value::as_str) == Some("projection");
        assert_eq!(object.len(), if projection { 6 } else { 5 });
        assert_eq!(object.contains_key("targetGeneration"), projection);
        assert!(!object.contains_key("capabilityRequirements"));
        assert!(!object.contains_key("requirements"));
    }
}

#[test]
fn runtime_plan_rust_schema_matches_the_committed_v4_boundary() {
    let rust = serde_json::to_value(schemars::schema_for!(RuntimePlan)).expect("Rust schema");
    let committed: Value =
        serde_json::from_str(include_str!("../schemas/runtime-plan.schema.json"))
            .expect("committed schema");

    assert_eq!(rust, committed);
}
