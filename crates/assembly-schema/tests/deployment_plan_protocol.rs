#![allow(clippy::expect_used, clippy::unwrap_used)]

use assembly_schema::{
    DeploymentIdentityV1Input, DeploymentPlan, DeploymentPlanErrorStage, DeploymentPlanV1Input,
    DeploymentServiceV1Input, DeploymentWorkloadV1Input, ParsedDeploymentPlan, ParsedRuntimePlan,
    PortExposure, PortV1Input, ProbeKind, ProbeV1Input, ResourceListV1Input,
    ResourceRequirementsV1Input, SecretRefV1Input,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const TAG: &str = "rss-deployment-plan-v1";
const SECRET: &str = "ZZ_DEPLOYMENT_SECRET_1802_DO_NOT_LEAK";
type WireMutation = (&'static str, fn(Value) -> Value);

fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../docs/spec/007-runtime-deployment-executable-plan/fixtures/fingerprint-v1-vectors.json"
    ))
    .expect("vectors")
}

fn vector(name: &str) -> Value {
    vectors()["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["name"] == name)
        .expect("named vector")
        .clone()
}

fn fingerprint(tag: &str, value: &impl Serialize) -> String {
    let canonical = serde_json_canonicalizer::to_vec(value).expect("canonical JSON");
    let mut hasher = Sha256::new();
    hasher.update(tag.as_bytes());
    hasher.update([0]);
    hasher.update(canonical);
    format!("sha256:{:x}", hasher.finalize())
}

fn runtime() -> ParsedRuntimePlan {
    let vector = vector("runtime-plan-closed");
    let mut wire = vector["unsigned"].clone();
    wire.as_object_mut().unwrap().insert(
        "runtimePlanFingerprint".to_owned(),
        vector["expected"].clone(),
    );
    ParsedRuntimePlan::from_json_slice(&serde_json::to_vec(&wire).unwrap()).expect("runtime")
}

fn runtime_from_unsigned(unsigned: Value) -> ParsedRuntimePlan {
    let mut wire = unsigned.clone();
    wire.as_object_mut().unwrap().insert(
        "runtimePlanFingerprint".to_owned(),
        json!(fingerprint("rss-runtime-plan-v1", &unsigned)),
    );
    ParsedRuntimePlan::from_json_slice(&serde_json::to_vec(&wire).unwrap())
        .expect("mutated runtime")
}

fn assert_production_fingerprint_rejects(runtime: &ParsedRuntimePlan, wire: Value, label: &str) {
    let error = ParsedDeploymentPlan::from_json_slice(
        runtime.as_plan(),
        &serde_json::to_vec(&wire).unwrap(),
    )
    .unwrap_err();
    assert_eq!(
        error.stage(),
        DeploymentPlanErrorStage::Fingerprint,
        "mutation did not reach production fingerprint check: {label}: {error}"
    );
}

fn deployment_wire() -> Value {
    let vector = vector("deployment-plan-kubernetes-secret");
    let mut wire = vector["unsigned"].clone();
    wire.as_object_mut().unwrap().insert(
        "deploymentFingerprint".to_owned(),
        vector["expected"].clone(),
    );
    wire
}

fn resign(mut wire: Value) -> Value {
    wire.as_object_mut()
        .unwrap()
        .remove("deploymentFingerprint");
    let fingerprint = fingerprint(TAG, &wire);
    wire.as_object_mut()
        .unwrap()
        .insert("deploymentFingerprint".to_owned(), json!(fingerprint));
    wire
}

fn strict_reader_rejects(wire: Value) -> bool {
    let runtime = runtime();
    ParsedDeploymentPlan::from_json_slice(
        runtime.as_plan(),
        &serde_json::to_vec(&resign(wire)).unwrap(),
    )
    .is_err()
}

#[test]
fn deployment_plan_shared_vector_and_runtime_bound_reader_are_exact() {
    let vector = vector("deployment-plan-kubernetes-secret");
    assert_eq!(fingerprint(TAG, &vector["unsigned"]), vector["expected"]);
    let runtime = runtime();
    let parsed = ParsedDeploymentPlan::from_json_slice(
        runtime.as_plan(),
        &serde_json::to_vec(&deployment_wire()).unwrap(),
    )
    .expect("deployment vector");
    assert_eq!(parsed.schema_version(), 1);
    assert_eq!(parsed.workloads()[0].name(), "runtime");
    assert_eq!(parsed.services()[0].ports()[0].port(), 8081);

    let mut wrong_stage = deployment_wire();
    let mut unsigned = wrong_stage.clone();
    unsigned
        .as_object_mut()
        .unwrap()
        .remove("deploymentFingerprint");
    wrong_stage["deploymentFingerprint"] = json!(fingerprint("rss-runtime-plan-v1", &unsigned));
    let error = ParsedDeploymentPlan::from_json_slice(
        runtime.as_plan(),
        &serde_json::to_vec(&wrong_stage).unwrap(),
    )
    .expect_err("cross-stage fingerprint must fail");
    assert_eq!(error.stage(), DeploymentPlanErrorStage::Fingerprint);
}

#[test]
fn deployment_plan_reader_rejects_changed_runtime_even_with_recomputed_deployment_identity() {
    let runtime = runtime();
    let mut unsigned = vector("deployment-plan-kubernetes-secret")["unsigned"].clone();
    unsigned["runtimePlanFingerprint"] =
        json!("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let mut wire = unsigned.clone();
    wire.as_object_mut().unwrap().insert(
        "deploymentFingerprint".to_owned(),
        json!(fingerprint(TAG, &unsigned)),
    );
    let error = ParsedDeploymentPlan::from_json_slice(
        runtime.as_plan(),
        &serde_json::to_vec(&wire).unwrap(),
    )
    .expect_err("foreign runtime must fail");
    assert_eq!(error.stage(), DeploymentPlanErrorStage::UpstreamIdentity);
}

#[test]
fn deployment_plan_reader_rejects_unknown_duplicate_trailing_and_secret_bait_without_leak() {
    let runtime = runtime();
    let valid = serde_json::to_string(&deployment_wire()).unwrap();
    for invalid in [
        valid.replacen(
            "\"schemaVersion\":1",
            &format!("\"{SECRET}\":true,\"schemaVersion\":1"),
            1,
        ),
        valid.replacen(
            "\"schemaVersion\":1",
            "\"schemaVersion\":1,\"schemaVersion\":1",
            1,
        ),
        format!("{valid} true"),
    ] {
        let error = ParsedDeploymentPlan::from_json_slice(runtime.as_plan(), invalid.as_bytes())
            .expect_err("strict wire must fail");
        assert!(!error.to_string().contains(SECRET));
        assert!(!format!("{error:?}").contains(SECRET));
    }
}

#[test]
fn deployment_plan_reader_rejects_quantity_ordering_image_probe_and_graph_failures() {
    let runtime = runtime();
    let cases: [WireMutation; 4] = [
        ("mutable image", |mut value: Value| {
            value["workloads"][0]["image"] = json!("registry/rss:latest");
            value
        }),
        ("request over limit", |mut value: Value| {
            value["workloads"][0]["resources"]["requests"]["cpu"] = json!("2");
            value
        }),
        ("empty probes", |mut value: Value| {
            value["workloads"][0]["probes"] = json!([]);
            value
        }),
        ("dangling service", |mut value: Value| {
            value["services"][0]["workload"] = json!("missing");
            value
        }),
    ];
    for (name, mutate) in cases {
        let mut wire = mutate(deployment_wire());
        let mut unsigned = wire.clone();
        unsigned
            .as_object_mut()
            .unwrap()
            .remove("deploymentFingerprint");
        wire["deploymentFingerprint"] = json!(fingerprint(TAG, &unsigned));
        assert!(
            ParsedDeploymentPlan::from_json_slice(
                runtime.as_plan(),
                &serde_json::to_vec(&wire).unwrap()
            )
            .is_err(),
            "accepted {name}"
        );
    }
}

#[test]
fn deployment_plan_reader_rejects_noncanonical_probe_identity_and_global_port_aliases() {
    let mut short_probe = deployment_wire();
    short_probe["workloads"][0]["probes"][0]["path"] = json!("/readyz");
    assert!(
        strict_reader_rejects(short_probe),
        "accepted noncanonical probe route"
    );

    let mut mismatched_identity = deployment_wire();
    mismatched_identity["workloads"][0]["identity"]["name"] = json!("other");
    assert!(
        strict_reader_rejects(mismatched_identity),
        "accepted identity not bound to its workload"
    );

    let mut duplicate_listener_port = deployment_wire();
    duplicate_listener_port["services"] = json!([
        {
            "name": "runtime",
            "workload": "runtime",
            "ports": [{"name": "http", "port": 8080, "exposure":"serviceExposed"}]
        },
        {
            "name": "runtime-shadow",
            "workload": "runtime",
            "ports": [{"name": "http", "port": 18080, "exposure":"serviceExposed"}]
        }
    ]);
    assert!(
        strict_reader_rejects(duplicate_listener_port),
        "accepted one RuntimePlan listener through two service ports"
    );
}

#[test]
fn deployment_plan_schema_and_reader_share_closed_name_and_image_grammar() {
    let committed: Value = serde_json::from_str(include_str!(
        "../../../docs/spec/007-runtime-deployment-executable-plan/contracts/deployment-plan.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::draft7::options()
        .should_validate_formats(true)
        .build(&committed)
        .unwrap();

    let mut dns_63 = deployment_wire();
    dns_63["workloads"][0]["secretRefs"][0]["name"] = json!("a".repeat(63));
    let dns_63 = resign(dns_63);
    assert!(validator.validate(&dns_63).is_ok());
    assert!(!strict_reader_rejects(dns_63));

    let mut dotted_service_account = deployment_wire();
    dotted_service_account["workloads"][0]["identity"]["serviceAccount"] = json!("runtime.team");
    let dotted_service_account = resign(dotted_service_account);
    assert!(validator.validate(&dotted_service_account).is_ok());
    assert!(!strict_reader_rejects(dotted_service_account));

    for (label, pointer, invalid) in [
        (
            "64-byte DNS label",
            "/workloads/0/secretRefs/0/name",
            "a".repeat(64),
        ),
        (
            "uppercase repository",
            "/workloads/0/image",
            format!("UPPER/repo@sha256:{}", "4".repeat(64)),
        ),
        (
            "empty repository component",
            "/workloads/0/image",
            format!("registry.example//rss@sha256:{}", "4".repeat(64)),
        ),
        (
            "tagged repository",
            "/workloads/0/image",
            format!("registry.example/rss:latest@sha256:{}", "4".repeat(64)),
        ),
        (
            "NUL in repository",
            "/workloads/0/image",
            format!("registry.example/rs\0s@sha256:{}", "4".repeat(64)),
        ),
        (
            "ASCII control in repository",
            "/workloads/0/image",
            format!("registry.example/rs\u{001f}s@sha256:{}", "4".repeat(64)),
        ),
        (
            "64-byte workload DNS label",
            "/workloads/0/name",
            "a".repeat(64),
        ),
        (
            "64-byte service DNS label",
            "/services/0/name",
            "a".repeat(64),
        ),
        (
            "64-byte service-account label",
            "/workloads/0/identity/serviceAccount",
            "a".repeat(64),
        ),
        (
            "16-byte service port name",
            "/services/0/ports/0/name",
            "abcdefghijklmnop".to_owned(),
        ),
        (
            "numeric-only service port name",
            "/services/0/ports/0/name",
            "123".to_owned(),
        ),
        (
            "consecutive-hyphen service port name",
            "/services/0/ports/0/name",
            "http--main".to_owned(),
        ),
    ] {
        let mut wire = deployment_wire();
        *wire.pointer_mut(pointer).unwrap() = json!(invalid);
        let wire = resign(wire);
        assert!(
            validator.validate(&wire).is_err(),
            "schema accepted {label}"
        );
        assert!(strict_reader_rejects(wire), "reader accepted {label}");
    }

    let mut schema_too_broad = deployment_wire();
    schema_too_broad["workloads"][0]["identity"]["serviceAccount"] = json!("UPPER");
    let schema_too_broad = resign(schema_too_broad);
    assert!(validator.validate(&schema_too_broad).is_err());
    assert!(strict_reader_rejects(schema_too_broad));
}

#[test]
fn deployment_plan_keyed_sets_reject_swapped_and_duplicate_facts() {
    let mut duplicate_workload = deployment_wire();
    let workload = duplicate_workload["workloads"][0].clone();
    duplicate_workload["workloads"] = json!([workload.clone(), workload]);
    assert!(strict_reader_rejects(duplicate_workload));

    let mut swapped_workloads = deployment_wire();
    let first_workload = swapped_workloads["workloads"][0].clone();
    let mut second_workload = first_workload.clone();
    second_workload["name"] = json!("zz-runtime");
    second_workload["identity"]["name"] = json!("zz-runtime");
    swapped_workloads["workloads"] = json!([second_workload, first_workload]);
    assert!(strict_reader_rejects(swapped_workloads));

    let mut duplicate_secret = deployment_wire();
    let secret = duplicate_secret["workloads"][0]["secretRefs"][0].clone();
    duplicate_secret["workloads"][0]["secretRefs"] = json!([secret.clone(), secret]);
    assert!(strict_reader_rejects(duplicate_secret));

    let mut duplicate_service = deployment_wire();
    let service = duplicate_service["services"][0].clone();
    duplicate_service["services"] = json!([service.clone(), service]);
    assert!(strict_reader_rejects(duplicate_service));

    let mut duplicate_port = deployment_wire();
    let port = duplicate_port["services"][0]["ports"][0].clone();
    duplicate_port["services"][0]["ports"] = json!([port.clone(), port]);
    assert!(strict_reader_rejects(duplicate_port));

    let mut swapped_secrets = deployment_wire();
    let first_secret = swapped_secrets["workloads"][0]["secretRefs"][0].clone();
    let second_secret = json!({
        "kind":"kubernetesSecret", "name":"runtime-secrets", "key":"zz-last"
    });
    swapped_secrets["workloads"][0]["secretRefs"] = json!([second_secret, first_secret]);
    assert!(strict_reader_rejects(swapped_secrets));

    let mut swapped_ports = deployment_wire();
    swapped_ports["services"][0]["ports"]
        .as_array_mut()
        .unwrap()
        .reverse();
    assert!(strict_reader_rejects(swapped_ports));

    let mut swapped_services = deployment_wire();
    let first_service = swapped_services["services"][0].clone();
    let second_service = json!({
        "name":"zz-shadow", "workload":"runtime",
        "ports":[{"name":"http","port":18080,"exposure":"serviceExposed"}]
    });
    swapped_services["services"] = json!([second_service, first_service]);
    assert!(strict_reader_rejects(swapped_services));
}

#[test]
fn deployment_plan_two_element_sorted_sets_are_non_vacuous_where_v1_is_expressible() {
    let mut secrets = deployment_wire();
    secrets["workloads"][0]["secretRefs"] = json!([
        {"kind":"kubernetesSecret", "name":"runtime-secrets", "key":"database.url"},
        {"kind":"vaultRef", "storeId":"vault", "refKey":"runtime/keyring"}
    ]);
    assert!(!strict_reader_rejects(secrets));

    let mut services = deployment_wire();
    services["services"] = json!([
        {"name":"runtime", "workload":"runtime", "ports":[{"name":"health", "port":8081,"exposure":"serviceExposed"}]},
        {"name":"zz-runtime", "workload":"runtime", "ports":[{"name":"http", "port":8080,"exposure":"serviceExposed"}]}
    ]);
    assert!(!strict_reader_rejects(services));

    let ports = deployment_wire();
    assert_eq!(ports["services"][0]["ports"].as_array().unwrap().len(), 2);
    assert!(!strict_reader_rejects(ports));
}

fn add_service_exposure(wire: &mut Value) {
    for service in wire["services"].as_array_mut().unwrap() {
        for port in service["ports"].as_array_mut().unwrap() {
            port["exposure"] = json!("serviceExposed");
        }
    }
}

#[test]
fn deployment_plan_internal_listener_requires_explicit_workload_only_exposure() {
    let mut runtime_unsigned = vector("runtime-plan-closed")["unsigned"].clone();
    runtime_unsigned["listenerPlans"] = json!([
        {"id":"health-main","kind":"health","auth":"noAuth","domains":[]},
        {"id":"internal-main","kind":"internal","auth":"mtls","domains":[]},
        {"id":"primary-main","kind":"primary","auth":"rssAccessToken","domains":["identity"]}
    ]);
    let changed_runtime = runtime_from_unsigned(runtime_unsigned);
    let mut deployment = deployment_wire();
    deployment["runtimePlanFingerprint"] =
        json!(changed_runtime.runtime_plan_fingerprint().as_str());
    add_service_exposure(&mut deployment);
    assert!(
        ParsedDeploymentPlan::from_json_slice(
            changed_runtime.as_plan(),
            &serde_json::to_vec(&resign(deployment.clone())).unwrap(),
        )
        .is_err(),
        "Internal listener escaped without an explicit workload-only port"
    );
    deployment["services"].as_array_mut().unwrap().push(json!({
        "name":"runtime-internal",
        "workload":"runtime",
        "ports":[{"name":"internal","port":8082,"exposure":"workloadOnly"}]
    }));
    ParsedDeploymentPlan::from_json_slice(
        changed_runtime.as_plan(),
        &serde_json::to_vec(&resign(deployment)).unwrap(),
    )
    .expect("explicit workload-only Internal exposure");
}

#[test]
fn deployment_plan_two_workload_ordering_reaches_the_target_branch() {
    let mut runtime_unsigned = vector("runtime-plan-closed")["unsigned"].clone();
    runtime_unsigned["domainPlans"] = json!([
        {"id":"identity","lifecycle":["construct","ready","shutdown"]},
        {"id":"settings","lifecycle":["construct","ready","shutdown"]}
    ]);
    runtime_unsigned["placementPlans"] = json!([
        {"domain":"identity","workload":"runtime"},
        {"domain":"settings","workload":"worker"}
    ]);
    let changed_runtime = runtime_from_unsigned(runtime_unsigned);
    let mut deployment = deployment_wire();
    deployment["runtimePlanFingerprint"] =
        json!(changed_runtime.runtime_plan_fingerprint().as_str());
    add_service_exposure(&mut deployment);
    let mut worker = deployment["workloads"][0].clone();
    worker["name"] = json!("worker");
    worker["identity"]["name"] = json!("worker");
    worker["secretRefs"] = json!([]);
    for probe in worker["probes"].as_array_mut().unwrap() {
        probe["port"] = json!(9081);
    }
    deployment["workloads"].as_array_mut().unwrap().push(worker);
    deployment["services"].as_array_mut().unwrap().push(json!({
        "name":"worker",
        "workload":"worker",
        "ports":[{"name":"health","port":9081,"exposure":"serviceExposed"}]
    }));
    let sorted = resign(deployment.clone());
    ParsedDeploymentPlan::from_json_slice(
        changed_runtime.as_plan(),
        &serde_json::to_vec(&sorted).unwrap(),
    )
    .expect("two-workload sorted green");

    let mut swapped = deployment.clone();
    swapped["workloads"].as_array_mut().unwrap().reverse();
    let error = ParsedDeploymentPlan::from_json_slice(
        changed_runtime.as_plan(),
        &serde_json::to_vec(&resign(swapped)).unwrap(),
    )
    .unwrap_err();
    assert_eq!(error.stage(), DeploymentPlanErrorStage::PlanFacts);

    let mut duplicate = deployment;
    let worker = duplicate["workloads"][1].clone();
    duplicate["workloads"].as_array_mut().unwrap().push(worker);
    let error = ParsedDeploymentPlan::from_json_slice(
        changed_runtime.as_plan(),
        &serde_json::to_vec(&resign(duplicate)).unwrap(),
    )
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "DeploymentPlan field `workloads` contains duplicate keyed facts"
    );
}

#[test]
fn deployment_plan_writer_and_rust_schema_match_committed_draft7() {
    let runtime = runtime();
    let parsed = ParsedDeploymentPlan::from_json_slice(
        runtime.as_plan(),
        &serde_json::to_vec(&deployment_wire()).unwrap(),
    )
    .unwrap();
    let writer = serde_json::to_value(parsed.as_plan()).unwrap();
    let committed: Value = serde_json::from_str(include_str!(
        "../../../docs/spec/007-runtime-deployment-executable-plan/contracts/deployment-plan.schema.json"
    )).unwrap();
    let validator = jsonschema::draft7::options()
        .should_validate_formats(true)
        .build(&committed)
        .unwrap();
    assert!(validator.validate(&writer).is_ok());
    assert_eq!(
        serde_json::to_value(schemars::schema_for!(DeploymentPlan)).unwrap(),
        committed
    );
}

#[test]
fn deployment_plan_compile_v1_copies_runtime_identity_and_emits_no_secret_values() {
    let runtime = runtime();
    let mut input = DeploymentPlanV1Input::new();
    input.workload(DeploymentWorkloadV1Input::new(
        "runtime",
        "registry.example/rss@sha256:4444444444444444444444444444444444444444444444444444444444444444",
        DeploymentIdentityV1Input::new("runtime", "runtime"),
        vec![SecretRefV1Input::kubernetes("runtime-secrets", "database.url")],
        ResourceRequirementsV1Input::new(
            ResourceListV1Input::new("500m", "256Mi"),
            ResourceListV1Input::new("1", "512Mi"),
        ),
        vec![ProbeV1Input::new(ProbeKind::Readiness, 8081)],
    ));
    input.service(DeploymentServiceV1Input::new(
        "runtime",
        "runtime",
        vec![
            PortV1Input::new("health", 8081, PortExposure::ServiceExposed),
            PortV1Input::new("http", 8080, PortExposure::ServiceExposed),
        ],
    ));
    let plan = DeploymentPlan::compile_v1(runtime.as_plan(), input).expect("compiled plan");
    assert_eq!(
        plan.assembly_fingerprint().as_str(),
        runtime.assembly_fingerprint().as_str()
    );
    assert_eq!(
        plan.runtime_plan_fingerprint().as_str(),
        runtime.runtime_plan_fingerprint().as_str()
    );
    assert_eq!(
        plan.deployment_fingerprint().as_str(),
        vector("deployment-plan-kubernetes-secret")["expected"]
    );
    assert!(!format!("{:?}", plan.workloads()[0].secret_refs()[0]).contains("runtime-secrets"));
}

#[test]
fn deployment_plan_fingerprint_covers_every_unsigned_leaf_and_excludes_itself() {
    let dep_vector = vector("deployment-plan-kubernetes-secret");
    let unsigned = dep_vector["unsigned"].clone();
    let expected = dep_vector["expected"].as_str().unwrap();
    for pointer in [
        "/schemaVersion",
        "/assemblyFingerprint",
        "/runtimePlanFingerprint",
    ] {
        let mut changed = unsigned.clone();
        *changed.pointer_mut(pointer).unwrap() = json!(2);
        assert_ne!(fingerprint(TAG, &changed), expected, "omitted {pointer}");
    }
    let paths = [
        ("workloads", 0, "name"),
        ("workloads", 0, "image"),
        ("services", 0, "name"),
        ("services", 0, "workload"),
    ];
    for (collection, index, field) in paths {
        let mut changed = unsigned.clone();
        changed[collection][index][field] = json!("changed");
        assert_ne!(
            fingerprint(TAG, &changed),
            expected,
            "omitted {collection}.{field}"
        );
    }
    for pointer in [
        "/workloads/0/identity/name",
        "/workloads/0/identity/serviceAccount",
        "/workloads/0/secretRefs/0/name",
        "/workloads/0/secretRefs/0/key",
        "/workloads/0/resources/requests/cpu",
        "/workloads/0/resources/requests/memory",
        "/workloads/0/resources/limits/cpu",
        "/workloads/0/resources/limits/memory",
        "/workloads/0/probes/0/kind",
        "/workloads/0/probes/0/path",
        "/workloads/0/probes/0/port",
        "/services/0/ports/0/name",
        "/services/0/ports/0/port",
    ] {
        let mut changed = unsigned.clone();
        *changed.pointer_mut(pointer).unwrap() = json!("changed");
        assert_ne!(fingerprint(TAG, &changed), expected, "omitted {pointer}");
    }
    let mut wire = deployment_wire();
    wire["deploymentFingerprint"] =
        json!("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    wire.as_object_mut()
        .unwrap()
        .remove("deploymentFingerprint");
    assert_eq!(fingerprint(TAG, &wire), expected);

    let runtime = runtime();
    let valid_mutations: [WireMutation; 9] = [
        ("image", |mut value| {
            value["workloads"][0]["image"] = json!(
                "registry.example/rss@sha256:5555555555555555555555555555555555555555555555555555555555555555"
            );
            value
        }),
        ("identity.serviceAccount", |mut value| {
            value["workloads"][0]["identity"]["serviceAccount"] = json!("runtime-service");
            value
        }),
        ("secret.name", |mut value| {
            value["workloads"][0]["secretRefs"][0]["name"] = json!("runtime-secrets-v2");
            value
        }),
        ("secret.key", |mut value| {
            value["workloads"][0]["secretRefs"][0]["key"] = json!("database.v2");
            value
        }),
        ("requests", |mut value| {
            value["workloads"][0]["resources"]["requests"] = json!({"cpu":"400m","memory":"128Mi"});
            value
        }),
        ("limits", |mut value| {
            value["workloads"][0]["resources"]["limits"] = json!({"cpu":"2","memory":"1Gi"});
            value
        }),
        ("probe.kind/path", |mut value| {
            value["workloads"][0]["probes"][0]["kind"] = json!("startup");
            value["workloads"][0]["probes"][0]["path"] = json!("/health/v1/healthz");
            value
        }),
        ("probe.port/service.port", |mut value| {
            value["workloads"][0]["probes"][0]["port"] = json!(9090);
            value["services"][0]["ports"][0]["port"] = json!(9090);
            value
        }),
        ("service.name", |mut value| {
            value["services"][0]["name"] = json!("runtime-service");
            value
        }),
    ];
    for (label, mutate) in valid_mutations {
        assert_production_fingerprint_rejects(&runtime, mutate(deployment_wire()), label);
    }

    let mut vault = deployment_wire();
    vault["workloads"][0]["secretRefs"] = json!([{
        "kind":"vaultRef", "storeId":"rss-vault", "refKey":"runtime/keyring", "refVersion":"v1"
    }]);
    let mut vault_unsigned = vault.clone();
    vault_unsigned
        .as_object_mut()
        .unwrap()
        .remove("deploymentFingerprint");
    vault["deploymentFingerprint"] = json!(fingerprint(TAG, &vault_unsigned));
    ParsedDeploymentPlan::from_json_slice(runtime.as_plan(), &serde_json::to_vec(&vault).unwrap())
        .expect("valid vault baseline");
    for (field, value) in [
        ("storeId", json!("rss-vault-v2")),
        ("refKey", json!("runtime/keyring-v2")),
        ("refVersion", json!("v2")),
    ] {
        let mut changed = vault.clone();
        changed["workloads"][0]["secretRefs"][0][field] = value;
        assert_production_fingerprint_rejects(&runtime, changed, field);
    }

    let mut runtime_unsigned = vector("runtime-plan-closed")["unsigned"].clone();
    runtime_unsigned["placementPlans"][0]["workload"] = json!("runtime-v2");
    let changed_runtime = runtime_from_unsigned(runtime_unsigned);
    let mut changed_graph = deployment_wire();
    changed_graph["runtimePlanFingerprint"] =
        json!(changed_runtime.runtime_plan_fingerprint().as_str());
    changed_graph["workloads"][0]["name"] = json!("runtime-v2");
    changed_graph["workloads"][0]["identity"]["name"] = json!("runtime-v2");
    changed_graph["services"][0]["workload"] = json!("runtime-v2");
    assert_production_fingerprint_rejects(
        &changed_runtime,
        changed_graph,
        "runtime/workload graph",
    );

    let mut assembly_runtime_unsigned = vector("runtime-plan-closed")["unsigned"].clone();
    assembly_runtime_unsigned["assemblyFingerprint"] =
        json!("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let changed_assembly_runtime = runtime_from_unsigned(assembly_runtime_unsigned);
    let mut changed_upstream = deployment_wire();
    changed_upstream["assemblyFingerprint"] =
        json!(changed_assembly_runtime.assembly_fingerprint().as_str());
    changed_upstream["runtimePlanFingerprint"] =
        json!(changed_assembly_runtime.runtime_plan_fingerprint().as_str());
    assert_production_fingerprint_rejects(
        &changed_assembly_runtime,
        changed_upstream,
        "assembly/runtime upstream identity",
    );
}
