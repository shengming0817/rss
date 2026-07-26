//! Runtime deployment schemas, semantic fixtures, and fingerprint protocol validator.

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const FEATURE_REL: &str = "docs/spec/007-runtime-deployment-executable-plan";
const SCHEMA_NAMES: [&str; 4] = [
    "assembly-lock.schema.json",
    "deployment-plan.schema.json",
    "runtime-inventory.schema.json",
    "runtime-plan.schema.json",
];
const FIXTURE_NAMES: [&str; 2] = ["schema-cases.json", "fingerprint-v1-vectors.json"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Options {
    pub(crate) selftest: bool,
}

pub(crate) fn parse_options(args: &[&str]) -> Result<Options> {
    let mut selftest = false;
    for arg in args {
        match *arg {
            "--selftest" if !selftest => selftest = true,
            other => bail!("runtime-deployment-spec 未知或重复参数: {other}"),
        }
    }
    Ok(Options { selftest })
}

pub(crate) fn run(options: &Options) -> Result<()> {
    let root = crate::workspace_root()?;
    let loaded = validate_repository(&root)?;
    if options.selftest {
        run_selftest(&loaded)?;
        println!("runtime-deployment-spec selftest: all synthetic reds rejected");
    }
    println!(
        "runtime-deployment-spec: {} schemas, {} fingerprint vectors",
        loaded.schemas.len(),
        loaded.fingerprints.vectors.len()
    );
    Ok(())
}

/// Aggregate-gate entrypoint: validate committed machine artifacts and exercise every synthetic red.
pub(crate) fn run_selftest_gate() -> Result<()> {
    run(&Options { selftest: true })
}

struct Loaded {
    schemas: BTreeMap<String, Value>,
    schema_cases: SchemaCases,
    fingerprints: FingerprintFixtures,
}

fn validate_repository(root: &Path) -> Result<Loaded> {
    let feature = root.join(FEATURE_REL);
    validate_machine_inputs(root, &feature)?;
    let schemas = load_schemas(&feature)?;
    let fingerprints: FingerprintFixtures =
        read_json(&feature.join("fixtures/fingerprint-v1-vectors.json"))?;
    validate_fingerprints(&fingerprints)?;
    let schema_cases: SchemaCases = read_json(&feature.join("fixtures/schema-cases.json"))?;
    validate_schema_set(&schemas, &schema_cases, &fingerprints)?;
    Ok(Loaded {
        schemas,
        schema_cases,
        fingerprints,
    })
}

fn validate_machine_inputs(root: &Path, feature: &Path) -> Result<()> {
    let pointer: Value = read_json(&root.join(".specify/feature.json"))?;
    ensure!(
        pointer == serde_json::json!({"feature_directory": FEATURE_REL}),
        "active feature pointer drift"
    );
    let mut required = Vec::new();
    required.extend(SCHEMA_NAMES.map(|name| feature.join("contracts").join(name)));
    required.extend(FIXTURE_NAMES.map(|name| feature.join("fixtures").join(name)));
    for path in &required {
        ensure!(
            path.is_file() && path.metadata()?.len() > 0,
            "required artifact missing or empty: {}",
            path.display()
        );
    }
    ensure!(
        !feature.join("validate.py").exists(),
        "legacy Python validator remains"
    );
    Ok(())
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))
}

fn load_schemas(feature: &Path) -> Result<BTreeMap<String, Value>> {
    let directory = feature.join("contracts");
    let mut found = BTreeMap::new();
    for entry in fs::read_dir(&directory)? {
        let path = entry?.path();
        if path.extension().and_then(|part| part.to_str()) != Some("json") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|part| part.to_str())
            .context("contract filename is not UTF-8")?
            .to_string();
        ensure!(
            found.insert(name.clone(), read_json(&path)?).is_none(),
            "duplicate schema {name}"
        );
    }
    ensure!(
        found.keys().map(String::as_str).eq(SCHEMA_NAMES),
        "schema set is not exact: {:?}",
        found.keys().collect::<Vec<_>>()
    );
    Ok(found)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SchemaCases {
    schema_version: u64,
    schemas: BTreeMap<String, CaseSet>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseSet {
    valid: Vec<NamedCase>,
    invalid: Vec<NamedCase>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct NamedCase {
    name: String,
    instance: Value,
}

fn validate_schema_set(
    schemas: &BTreeMap<String, Value>,
    cases: &SchemaCases,
    fingerprints: &FingerprintFixtures,
) -> Result<()> {
    ensure!(schemas.len() == 4, "schema anti-vacuity count is not four");
    ensure!(cases.schema_version == 1, "schema cases version drift");
    ensure!(
        cases.schemas.keys().eq(schemas.keys()),
        "schema case set differs from schema set"
    );
    for (name, schema) in schemas {
        ensure!(
            schema.get("$schema").and_then(Value::as_str)
                == Some("http://json-schema.org/draft-07/schema#"),
            "{name}: not Draft-07"
        );
        reject_external_refs(schema, name)?;
        walk_schema(schema, name)?;
        let validator = jsonschema::draft7::options()
            .should_validate_formats(true)
            .build(schema)
            .map_err(|error| anyhow::anyhow!("{name}: cannot compile Draft-07 schema: {error}"))?;
        let fixture = &cases.schemas[name];
        ensure!(!fixture.valid.is_empty(), "{name}: no valid cases");
        ensure!(!fixture.invalid.is_empty(), "{name}: no invalid cases");
        for case in &fixture.valid {
            validator.validate(&case.instance).map_err(|errors| {
                let detail = errors
                    .map(|error| error.to_string())
                    .collect::<Vec<_>>()
                    .join("; ");
                anyhow::anyhow!("{name}/{} valid case rejected: {detail}", case.name)
            })?;
            validate_semantics(name, &case.instance, fingerprints)
                .with_context(|| format!("{name}/{} valid semantics", case.name))?;
        }
        for case in &fixture.invalid {
            let schema_rejects = validator.validate(&case.instance).is_err();
            let semantics_reject = validate_semantics(name, &case.instance, fingerprints).is_err();
            if name == "runtime-plan.schema.json"
                && matches!(
                    case.name.as_str(),
                    "empty-provider-plans"
                        | "empty-listener-plans"
                        | "empty-domain-plans"
                        | "empty-placement-plans"
                        | "internal-no-auth"
                        | "unknown-auth-scheme"
                        | "unknown-provider-constructor"
                        | "unknown-lifecycle-channel"
                        | "invalid-lifecycle-sequence"
                        | "non-kebab-provider-id"
                        | "primary-mtls-auth"
                        | "non-kebab-workload-id"
                )
            {
                ensure!(
                    schema_rejects,
                    "{name}/{} must be rejected by Draft-07 itself, independently of its stale fingerprint",
                    case.name
                );
            }
            ensure!(
                schema_rejects || semantics_reject,
                "{name}/{} invalid case was accepted",
                case.name
            );
        }
    }
    Ok(())
}

fn reject_external_refs(value: &Value, where_: &str) -> Result<()> {
    match value {
        Value::Object(object) => {
            if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                ensure!(
                    reference.starts_with("#/"),
                    "{where_}: external $ref is forbidden: {reference}"
                );
            }
            for (key, child) in object {
                reject_external_refs(child, &format!("{where_}/{key}"))?;
            }
        }
        Value::Array(array) => {
            for (index, child) in array.iter().enumerate() {
                reject_external_refs(child, &format!("{where_}/{index}"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn walk_schema(value: &Value, where_: &str) -> Result<()> {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("object") {
                ensure!(
                    object.get("additionalProperties") == Some(&Value::Bool(false)),
                    "{where_}: object schema is open"
                );
            }
            if object.get("type").and_then(Value::as_str) == Some("array")
                && object
                    .get("description")
                    .and_then(Value::as_str)
                    .is_some_and(|text| text.starts_with("Set-like"))
            {
                ensure!(
                    object.get("uniqueItems") == Some(&Value::Bool(true)),
                    "{where_}: set-like array lacks uniqueItems"
                );
            }
            for (key, child) in object {
                walk_schema(child, &format!("{where_}/{key}"))?;
            }
        }
        Value::Array(array) => {
            for (index, child) in array.iter().enumerate() {
                walk_schema(child, &format!("{where_}/{index}"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_semantics(
    schema: &str,
    instance: &Value,
    fingerprints: &FingerprintFixtures,
) -> Result<()> {
    match schema {
        "assembly-lock.schema.json" => {
            validate_instance_fingerprint(instance, "fingerprint", "rss-assembly-lock-v1")
        }
        "runtime-plan.schema.json" => validate_runtime_plan_wire(
            &serde_json::to_vec(instance).context("serialize RuntimePlan semantics input")?,
        ),
        "deployment-plan.schema.json" => {
            validate_deployment_plan(instance)?;
            validate_instance_fingerprint(
                instance,
                "deploymentFingerprint",
                "rss-deployment-plan-v1",
            )
        }
        "runtime-inventory.schema.json" => {
            validate_inventory(instance)?;
            validate_inventory_fingerprint_chain(instance, fingerprints)
        }
        _ => bail!("unknown schema semantics {schema}"),
    }
}

fn object(value: &Value) -> Result<&Map<String, Value>> {
    value.as_object().context("expected object")
}

fn array_field<'a>(value: &'a Value, field: &str) -> Result<&'a [Value]> {
    object(value)?
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .with_context(|| format!("missing array {field}"))
}

fn string_field<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    object(value)?
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("missing string {field}"))
}

type Identity = Vec<String>;

fn object_identity(value: &Value, keys: &[&str]) -> Result<Identity> {
    keys.iter()
        .map(|key| string_field(value, key).map(str::to_owned))
        .collect()
}

fn unique_objects(values: &[Value], label: &str, keys: &[&str]) -> Result<BTreeSet<Identity>> {
    let mut identities = BTreeSet::new();
    for value in values {
        let identity = object_identity(value, keys)?;
        ensure!(
            identities.insert(identity.clone()),
            "{label}: duplicate identity {identity:?}"
        );
    }
    Ok(identities)
}

fn sorted_unique_objects(
    values: &[Value],
    label: &str,
    keys: &[&str],
) -> Result<BTreeSet<Identity>> {
    let identities = unique_objects(values, label, keys)?;
    let ordered = values
        .iter()
        .map(|value| object_identity(value, keys))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        ordered.windows(2).all(|pair| pair[0] < pair[1]),
        "{label}: set-like identities are not strictly sorted"
    );
    Ok(identities)
}

fn sorted_unique_secret_refs(values: &[Value]) -> Result<()> {
    let identities = values
        .iter()
        .map(|value| {
            let kind = string_field(value, "kind")?;
            match kind {
                "kubernetesSecret" => Ok(vec![
                    kind.to_owned(),
                    string_field(value, "name")?.to_owned(),
                    string_field(value, "key")?.to_owned(),
                ]),
                "vaultRef" => {
                    let reference = object(value)?;
                    let ref_version = match reference.get("refVersion") {
                        None => "",
                        Some(version) => version
                            .as_str()
                            .context("vaultRef.refVersion must be a string")?,
                    };
                    Ok(vec![
                        kind.to_owned(),
                        string_field(value, "storeId")?.to_owned(),
                        string_field(value, "refKey")?.to_owned(),
                        ref_version.to_owned(),
                    ])
                }
                other => bail!("unknown secret reference kind {other}"),
            }
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        identities.windows(2).all(|pair| pair[0] < pair[1]),
        "workload.secretRefs are not unique and strictly sorted"
    );
    Ok(())
}

fn validate_runtime_plan_wire(bytes: &[u8]) -> Result<()> {
    assembly_schema::validate_runtime_plan_json_slice(bytes)
        .context("typed RuntimePlan semantics rejected wire")
}

fn validate_deployment_plan(instance: &Value) -> Result<()> {
    let workloads = array_field(instance, "workloads")?;
    let workload_names = sorted_unique_objects(workloads, "workloads", &["name"])?;
    let services = array_field(instance, "services")?;
    sorted_unique_objects(services, "services", &["name"])?;
    for workload in workloads {
        unique_objects(
            array_field(workload, "probes")?,
            "workload.probes",
            &["kind"],
        )?;
        sorted_unique_secret_refs(array_field(workload, "secretRefs")?)?;
        validate_resources(
            object(workload)?
                .get("resources")
                .context("workload resources missing")?,
        )?;
    }
    for service in services {
        let workload = string_field(service, "workload")?;
        ensure!(
            workload_names.contains(&vec![workload.to_owned()]),
            "service references unknown workload {workload}"
        );
        sorted_unique_objects(array_field(service, "ports")?, "service.ports", &["name"])?;
    }
    Ok(())
}

fn validate_inventory(instance: &Value) -> Result<()> {
    let domains = array_field(instance, "domains")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .context("inventory domain must be string")
                .map(str::to_string)
        })
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        domains.len() == array_field(instance, "domains")?.len(),
        "duplicate inventory domain"
    );
    sorted_unique_objects(array_field(instance, "listeners")?, "listeners", &["id"])?;
    sorted_unique_objects(
        array_field(instance, "providerPosture")?,
        "providerPosture",
        &["id"],
    )?;
    let placements = array_field(instance, "placements")?;
    sorted_unique_objects(placements, "placements", &["domain", "workload"])?;
    for placement in placements {
        let domain = string_field(placement, "domain")?;
        ensure!(
            domains.contains(domain),
            "inventory placement references unknown domain {domain}"
        );
    }
    Ok(())
}

fn validate_resources(value: &Value) -> Result<()> {
    let resources = object(value)?;
    let requests = object(
        resources
            .get("requests")
            .context("resources.requests missing")?,
    )?;
    let limits = object(
        resources
            .get("limits")
            .context("resources.limits missing")?,
    )?;
    for field in ["cpu", "memory"] {
        let request = requests
            .get(field)
            .and_then(Value::as_str)
            .with_context(|| format!("requests.{field} missing"))?;
        let limit = limits
            .get(field)
            .and_then(Value::as_str)
            .with_context(|| format!("limits.{field} missing"))?;
        let request = parse_quantity(request, field)?;
        let limit = parse_quantity(limit, field)?;
        ensure!(request <= limit, "resources {field} request exceeds limit");
    }
    Ok(())
}

fn parse_quantity(raw: &str, kind: &str) -> Result<u128> {
    let suffixes: &[(&str, u128)] = match kind {
        "cpu" => &[("m", 1), ("", 1_000)],
        "memory" => &[
            ("Ki", 1 << 10),
            ("Mi", 1 << 20),
            ("Gi", 1 << 30),
            ("Ti", 1 << 40),
            ("K", 1_000),
            ("M", 1_000_000),
            ("G", 1_000_000_000),
            ("T", 1_000_000_000_000),
            ("", 1),
        ],
        _ => bail!("unknown resource quantity kind {kind}"),
    };
    for (suffix, multiplier) in suffixes {
        if let Some(number) = raw.strip_suffix(suffix) {
            if number.is_empty() {
                continue;
            }
            let parsed: u128 = number
                .parse()
                .with_context(|| format!("invalid {kind} quantity {raw}"))?;
            return parsed
                .checked_mul(*multiplier)
                .with_context(|| format!("{kind} quantity overflows u128: {raw}"));
        }
    }
    bail!("invalid {kind} quantity {raw}")
}

fn validate_instance_fingerprint(
    instance: &Value,
    result_field: &str,
    stage_tag: &str,
) -> Result<()> {
    let declared = object(instance)?
        .get(result_field)
        .and_then(Value::as_str)
        .with_context(|| format!("missing {result_field}"))?;
    let mut unsigned = instance.clone();
    object_mut(&mut unsigned)?.remove(result_field);
    let expected = fingerprint(stage_tag, &unsigned)?;
    ensure!(
        declared == expected,
        "{result_field} does not match {stage_tag} canonical preimage"
    );
    Ok(())
}

fn validate_inventory_fingerprint_chain(
    inventory: &Value,
    fixtures: &FingerprintFixtures,
) -> Result<()> {
    for (field, stage_tag) in [
        ("assemblyFingerprint", "rss-assembly-lock-v1"),
        ("runtimePlanFingerprint", "rss-runtime-plan-v1"),
        ("deploymentFingerprint", "rss-deployment-plan-v1"),
    ] {
        let declared = object(inventory)?
            .get(field)
            .and_then(Value::as_str)
            .with_context(|| format!("inventory missing {field}"))?;
        let expected = fixtures
            .vectors
            .iter()
            .find(|vector| vector.stage_tag == stage_tag)
            .with_context(|| format!("missing fingerprint vector {stage_tag}"))?
            .expected
            .as_str();
        ensure!(
            declared == expected,
            "inventory {field} differs from fixture chain"
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FingerprintFixtures {
    schema_version: u64,
    vectors: Vec<FingerprintVector>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FingerprintVector {
    name: String,
    stage_tag: String,
    unsigned: Value,
    canonical_hex: String,
    expected: String,
}

fn validate_fingerprints(fixtures: &FingerprintFixtures) -> Result<()> {
    ensure!(
        fixtures.schema_version == 1,
        "fingerprint fixture version drift"
    );
    ensure!(
        fixtures.vectors.len() == 3,
        "fingerprint vector count is not three"
    );
    let mut names = BTreeSet::new();
    let mut tags = BTreeSet::new();
    for vector in &fixtures.vectors {
        ensure!(
            names.insert(&vector.name),
            "duplicate fingerprint vector name"
        );
        ensure!(
            !vector.stage_tag.is_empty()
                && vector.stage_tag.is_ascii()
                && !vector.stage_tag.as_bytes().contains(&0),
            "{}: stageTag must be nonempty ASCII without NUL",
            vector.name
        );
        ensure!(
            tags.insert(&vector.stage_tag),
            "duplicate fingerprint stageTag"
        );
        ensure!(
            vector.unsigned.is_object(),
            "{}: unsigned must be an object",
            vector.name
        );
        let canonical = serde_json_canonicalizer::to_vec(&vector.unsigned)
            .with_context(|| format!("{}: canonicalize", vector.name))?;
        ensure!(
            hex(&canonical) == vector.canonical_hex,
            "{}: canonicalHex drift",
            vector.name
        );
        let expected = fingerprint_bytes(&vector.stage_tag, &canonical);
        ensure!(
            expected == vector.expected,
            "{}: fingerprint drift",
            vector.name
        );
    }
    Ok(())
}

fn fingerprint(stage_tag: &str, unsigned: &Value) -> Result<String> {
    let canonical =
        serde_json_canonicalizer::to_vec(unsigned).context("canonicalize fingerprint preimage")?;
    Ok(fingerprint_bytes(stage_tag, &canonical))
}

fn fingerprint_bytes(stage_tag: &str, canonical: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(stage_tag.as_bytes());
    hasher.update([0]);
    hasher.update(canonical);
    format!("sha256:{}", hex(&hasher.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn run_selftest(loaded: &Loaded) -> Result<()> {
    for mutation in [
        SchemaMutation::InvalidType,
        SchemaMutation::InvalidRequired,
        SchemaMutation::DanglingRef,
    ] {
        let mut schemas = loaded.schemas.clone();
        mutate_schema(&mut schemas, mutation)?;
        ensure!(
            validate_schema_set(&schemas, &loaded.schema_cases, &loaded.fingerprints).is_err(),
            "schema mutation {mutation:?} was accepted"
        );
    }
    let deployment = loaded.schema_cases.schemas["deployment-plan.schema.json"]
        .valid
        .first()
        .context("deployment valid case missing")?
        .instance
        .clone();
    let mut duplicate = deployment.clone();
    let workloads = duplicate
        .get_mut("workloads")
        .and_then(Value::as_array_mut)
        .context("deployment workloads missing")?;
    let mut second = workloads
        .first()
        .context("deployment workload missing")?
        .clone();
    object_mut(&mut second)?.insert(
        "image".to_string(),
        Value::String(format!("example.invalid/changed@sha256:{}", "f".repeat(64))),
    );
    workloads.push(second);
    ensure!(
        validate_deployment_plan(&duplicate).is_err(),
        "keyed duplicate mutation was accepted"
    );

    let mut out_of_order = deployment.clone();
    let workloads = out_of_order
        .get_mut("workloads")
        .and_then(Value::as_array_mut)
        .context("deployment workloads missing")?;
    let mut earlier = workloads
        .first()
        .context("deployment workload missing")?
        .clone();
    object_mut(&mut earlier)?.insert("name".to_string(), Value::String("aaa".to_string()));
    workloads.push(earlier);
    ensure!(
        validate_deployment_plan(&out_of_order).is_err(),
        "set-like order mutation was accepted"
    );

    let mut dangling = deployment.clone();
    let service = dangling
        .get_mut("services")
        .and_then(Value::as_array_mut)
        .and_then(|values| values.first_mut())
        .context("deployment service missing")?;
    object_mut(service)?.insert(
        "workload".to_string(),
        Value::String("__missing__".to_string()),
    );
    ensure!(
        validate_deployment_plan(&dangling).is_err(),
        "dangling reference mutation was accepted"
    );

    let mut bad_resource = deployment;
    let resources = bad_resource
        .get_mut("workloads")
        .and_then(Value::as_array_mut)
        .and_then(|values| values.first_mut())
        .and_then(|workload| workload.get_mut("resources"))
        .context("deployment resources missing")?;
    let requests = object_mut(resources)?
        .get_mut("requests")
        .context("resource requests missing")?;
    object_mut(requests)?.insert("cpu".to_string(), Value::String("999".to_string()));
    ensure!(
        validate_deployment_plan(&bad_resource).is_err(),
        "resource order mutation was accepted"
    );

    let mut fingerprints = loaded.fingerprints.clone();
    fingerprints.vectors[0].expected = format!("sha256:{}", "0".repeat(64));
    ensure!(
        validate_fingerprints(&fingerprints).is_err(),
        "fingerprint mutation was accepted"
    );
    Ok(())
}

fn object_mut(value: &mut Value) -> Result<&mut Map<String, Value>> {
    value.as_object_mut().context("expected mutable object")
}

#[derive(Debug, Clone, Copy)]
enum SchemaMutation {
    InvalidType,
    InvalidRequired,
    DanglingRef,
}

fn mutate_schema(schemas: &mut BTreeMap<String, Value>, mutation: SchemaMutation) -> Result<()> {
    let schema = schemas
        .get_mut("runtime-plan.schema.json")
        .context("runtime-plan schema missing")?;
    match mutation {
        SchemaMutation::InvalidType => {
            object_mut(schema)?.insert(
                "type".to_string(),
                Value::String("invalid-type".to_string()),
            );
        }
        SchemaMutation::InvalidRequired => {
            object_mut(schema)?.insert(
                "required".to_string(),
                Value::String("schemaVersion".to_string()),
            );
        }
        SchemaMutation::DanglingRef => {
            let fingerprint = schema
                .get_mut("properties")
                .and_then(Value::as_object_mut)
                .and_then(|properties| properties.get_mut("assemblyFingerprint"))
                .context("assemblyFingerprint schema missing")?;
            object_mut(fingerprint)?.insert(
                "$ref".to_string(),
                Value::String("#/definitions/missing".to_string()),
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_are_closed() -> Result<()> {
        assert_eq!(parse_options(&["--selftest"])?, Options { selftest: true });
        assert_eq!(parse_options(&[])?, Options { selftest: false });
        assert!(parse_options(&["--selftest", "--selftest"]).is_err());
        assert!(parse_options(&["--bogus"]).is_err());
        Ok(())
    }

    #[test]
    fn committed_fixtures_and_synthetic_reds_are_live() -> Result<()> {
        let root = crate::workspace_root()?;
        let loaded = validate_repository(&root)?;
        run_selftest(&loaded)
    }

    #[test]
    fn quantity_order_is_semantic() -> Result<()> {
        ensure!(parse_quantity("500m", "cpu")? < parse_quantity("1", "cpu")?);
        ensure!(parse_quantity("512Mi", "memory")? < parse_quantity("1Gi", "memory")?);
        ensure!(
            parse_quantity("9007199254740993m", "cpu")? < parse_quantity("9007199254741", "cpu")?
        );
        assert_eq!(
            parse_quantity("99999999999999999999Ti", "memory")?,
            99_999_999_999_999_999_999_u128 * (1_u128 << 40)
        );
        assert!(parse_quantity("banana", "cpu").is_err());
        assert!(parse_quantity(&format!("{}T", u128::MAX), "memory").is_err());
        Ok(())
    }

    #[test]
    fn structured_identities_do_not_collide_on_nul() -> Result<()> {
        let values = serde_json::json!([
            {"left": "x\u{0000}y", "right": "z"},
            {"left": "x", "right": "y\u{0000}z"}
        ]);
        let identities = unique_objects(
            values.as_array().context("test values must be an array")?,
            "test",
            &["left", "right"],
        )?;
        assert_eq!(identities.len(), 2);
        Ok(())
    }

    #[test]
    fn runtime_plan_semantics_are_owned_by_the_typed_reader() -> Result<()> {
        let root = crate::workspace_root()?;
        let loaded = validate_repository(&root)?;
        let valid = loaded.schema_cases.schemas["runtime-plan.schema.json"]
            .valid
            .first()
            .context("runtime plan valid case missing")?
            .instance
            .clone();

        validate_semantics("runtime-plan.schema.json", &valid, &loaded.fingerprints)?;

        let raw = serde_json::to_string(&valid)?;
        let duplicate_key = raw.replacen(
            "\"schemaVersion\":1",
            "\"schemaVersion\":1,\"schemaVersion\":1",
            1,
        );
        assert!(validate_runtime_plan_wire(duplicate_key.as_bytes()).is_err());

        let mut dangling = valid.clone();
        dangling["listenerPlans"][0]["domains"] =
            Value::Array(vec![Value::String("settings".to_owned())]);
        let Err(error) =
            validate_semantics("runtime-plan.schema.json", &dangling, &loaded.fingerprints)
        else {
            bail!("typed reader accepted dangling domains");
        };
        assert!(format!("{error:#}").contains("dangling reference"));

        let mut unsorted = valid;
        let mut earlier = unsorted["providerPlans"][0].clone();
        object_mut(&mut earlier)?.insert("id".to_owned(), Value::String("a-provider".to_owned()));
        unsorted["providerPlans"]
            .as_array_mut()
            .context("provider plans missing")?
            .push(earlier);
        let Err(error) =
            validate_semantics("runtime-plan.schema.json", &unsorted, &loaded.fingerprints)
        else {
            bail!("typed reader accepted noncanonical plan order");
        };
        assert!(format!("{error:#}").contains("canonical order"));
        Ok(())
    }

    #[test]
    fn vault_ref_version_is_optional_in_semantic_carrier() -> Result<()> {
        let values = serde_json::json!([
            {"kind": "vaultRef", "storeId": "primary", "refKey": "db/password"}
        ]);
        sorted_unique_secret_refs(values.as_array().context("test values must be an array")?)
    }
}
