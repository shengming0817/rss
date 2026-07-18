#![allow(clippy::expect_used, clippy::unwrap_used)]
// reason: protocol fixtures should fail at the exact local assertion when their frozen bytes drift.

use assembly_schema::{
    ParsedRuntimePlan, ProviderConstructor, RuntimePlan, RuntimePlanErrorStage,
    RuntimePlanJsonCategory,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const RUNTIME_PLAN_TAG: &str = "rss-runtime-plan-v1";
const ASSEMBLY_PLAN_TAG: &str = "rss-assembly-lock-v1";
const SECRET_SENTINEL: &str = "ZZ_RUNTIME_PLAN_SECRET_1788_DO_NOT_SERIALIZE";

fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../docs/spec/007-runtime-deployment-executable-plan/fixtures/fingerprint-v1-vectors.json"
    ))
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

fn parse_result(value: &Value) -> Result<ParsedRuntimePlan, assembly_schema::RuntimePlanError> {
    ParsedRuntimePlan::from_json_slice(&serde_json::to_vec(value).expect("wire JSON"))
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
        {"id":"a-provider","constructor":"amqp::AmqpPublisher","outputs":["probes"]},
        {"id":"z-provider","constructor":"oidc::OidcProvider","outputs":["workers"]}
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

fn parse(value: &Value) -> Option<ParsedRuntimePlan> {
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
fn runtime_plan_reader_accepts_the_shared_closed_vector() {
    let vector = runtime_vector();
    let parsed = parse(&wire_from_vector()).expect("valid shared RuntimePlan vector");

    assert_eq!(parsed.schema_version(), 1);
    assert_eq!(
        parsed.assembly_fingerprint().as_str(),
        vector["unsigned"]["assemblyFingerprint"]
            .as_str()
            .expect("assembly fingerprint")
    );
    assert_eq!(
        parsed.runtime_plan_fingerprint().as_str(),
        vector["expected"].as_str().expect("runtime fingerprint")
    );
    assert_eq!(parsed.provider_plans().len(), 1);
    assert_eq!(parsed.provider_plans()[0].id(), "pdp");
    assert_eq!(
        parsed.provider_plans()[0].constructor(),
        ProviderConstructor::OidcProvider
    );
    assert_eq!(parsed.listener_plans()[0].id(), "primary-main");
    assert_eq!(parsed.domain_plans()[0].id().as_str(), "identity");
    assert_eq!(parsed.placement_plans()[0].workload(), "runtime");
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

    let mut unknown_auth = valid.clone();
    unknown_auth["listenerPlans"][0]["auth"] = json!("bearer");

    let mut unknown_constructor = valid.clone();
    unknown_constructor["providerPlans"][0]["constructor"] = json!("https://secret.example/token");

    let mut unknown_lifecycle = valid.clone();
    unknown_lifecycle["domainPlans"][0]["lifecycle"][1] = json!("started");

    let mut unsupported_version = valid.clone();
    unsupported_version["schemaVersion"] = json!(2);

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
fn runtime_plan_reader_rejects_complete_negative_matrix() {
    for field in [
        "providerPlans",
        "listenerPlans",
        "domainPlans",
        "placementPlans",
    ] {
        let mut missing = runtime_vector()["unsigned"].clone();
        missing[field] = json!([]);
        assert_reader_rejects(seal_unsigned(missing), "must not be empty");

        let mut duplicate = runtime_vector()["unsigned"].clone();
        let fact = duplicate[field][0].clone();
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

    let mut unsorted_outputs = runtime_vector()["unsigned"].clone();
    unsorted_outputs["providerPlans"][0]["outputs"] = json!(["workers", "probes"]);
    assert_reader_rejects(seal_unsigned(unsorted_outputs), "not in canonical order");
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
            value["schemaVersion"] = json!(2);
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
        "\"schemaVersion\":1",
        "\"schemaVersion\":1,\"schemaVersion\":1",
        1,
    );
    assert!(ParsedRuntimePlan::from_json_slice(duplicate.as_bytes()).is_err());

    let bait = wire.replacen(
        "\"schemaVersion\":1",
        &format!("\"secret\":\"{SECRET_SENTINEL}\",\"schemaVersion\":1"),
        1,
    );
    let result = ParsedRuntimePlan::from_json_slice(bait.as_bytes());
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
    let auth_error = ParsedRuntimePlan::from_json_slice(auth_bait.as_bytes())
        .expect_err("unknown auth must fail closed");
    assert!(!auth_error.to_string().contains(SECRET_SENTINEL));
    assert!(!format!("{auth_error:?}").contains(SECRET_SENTINEL));
}

#[test]
fn runtime_plan_reader_reports_sealed_redacted_json_stage_category_and_path() {
    let eof = ParsedRuntimePlan::from_json_slice(b"{").expect_err("truncated JSON must fail");
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
        "\"schemaVersion\":1",
        &format!("\"{SECRET_SENTINEL}\":true,\"schemaVersion\":1"),
        1,
    );
    let unknown_field = ParsedRuntimePlan::from_json_slice(secret_key.as_bytes())
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
    let parsed = parse(&wire_from_vector()).expect("shared vector");
    let writer = serde_json::to_value(parsed.as_plan()).expect("RuntimePlan writer");
    let committed: Value = serde_json::from_str(include_str!(
        "../../../docs/spec/007-runtime-deployment-executable-plan/contracts/runtime-plan.schema.json"
    ))
    .expect("committed schema");
    let validator = jsonschema::draft7::options()
        .should_validate_formats(true)
        .build(&committed)
        .expect("Draft-07 RuntimePlan schema");
    assert!(
        validator.validate(&writer).is_ok(),
        "the real RuntimePlan writer drifted from the committed Draft-07 schema"
    );

    let encoded = serde_json::to_vec(&writer).expect("writer bytes");
    let reparsed = ParsedRuntimePlan::from_json_slice(&encoded).expect("writer round-trip");
    assert_eq!(
        reparsed.runtime_plan_fingerprint().as_str(),
        parsed.runtime_plan_fingerprint().as_str()
    );
}

#[test]
fn runtime_plan_rust_schema_matches_the_committed_v1_boundary() {
    let rust = serde_json::to_value(schemars::schema_for!(RuntimePlan)).expect("Rust schema");
    let committed: Value = serde_json::from_str(include_str!(
        "../../../docs/spec/007-runtime-deployment-executable-plan/contracts/runtime-plan.schema.json"
    ))
    .expect("committed schema");

    assert_eq!(rust, committed);
}
