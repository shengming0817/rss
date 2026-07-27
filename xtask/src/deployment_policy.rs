//! Static deployment manifest policy and strict schema validation.
//!
//! INVARIANT: DEPLOYMENT-RENDER-POLICY-CLOSURE-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "deployment_policy::tests::semantic_mutation_suite_is_nonempty_exact_and_every_case_fails_closed + deployment_policy::tests::rendered_tree_rejects_missing_extra_and_symlink + deployment_policy::tests::schema_digest_rejects_mutation", anti_vacuity = "deployment_policy::tests::semantic_mutation_suite_is_nonempty_exact_and_every_case_fails_closed + deployment_policy::tests::committed_schema_digests_are_exact + deployment_policy::tests::rendered_inventory_is_six_core_and_six_extensions" } — committed two-phase manifests and pinned local Kubernetes/CRD schemas form an exact, non-empty closure before kubeconform runs.
//!
//! Gate budget: `deployment-policy-check` replaces the deleted
//! `deploy/helm/rss/tests/render-policy.sh` policy carrier. It remains separate from
//! `deployment-plan-check` because strict kubeconform execution is an external-tool capability;
//! the plan gate owns Helm generation/drift while both call this module's single semantic validator.

use crate::cmd::{ExternalProgram, external_cmd};
use anyhow::{Context, Result, ensure};
use assembly_schema::{
    ApplicationConfig, AvailabilityClass, DeploymentPlan, MigrationMode, PortExposure, ProbeKind,
    SecretConsumer, SecretPurpose,
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::Path;

pub(crate) const KUBECONFORM_VERSION: &str = env!("RSS_TOOL_VERSION_KUBECONFORM");
const KUBERNETES_VERSION: &str = "1.30.0";
const RENDERED_DIR: &str = "deploy/rendered";
const EXTENSIONS_DIR: &str = "deploy/rendered/extensions";
const CORE_SCHEMA_LOCATION_TEMPLATE: &str =
    "deploy/schemas/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json";
const SCHEMA_LOCATION_TEMPLATE: &str =
    "deploy/schemas/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json";
const SCHEMAS: &[(&str, &str)] = &[
    (
        "deploy/schemas/apps/deployment_v1.json",
        "eec9281764590b81aae81f0571790a1733e886585093e389f6bc03e233809763",
    ),
    (
        "deploy/schemas/autoscaling/horizontalpodautoscaler_v2.json",
        "75e74b614d909e1d0140f6a286d6d58876c9591917ebd3f8456f7c7646cb921f",
    ),
    (
        "deploy/schemas/batch/job_v1.json",
        "10a36c2ac43f955296a8f311bc950eab81f9285ae99a12c79e059f1bb91c10c9",
    ),
    (
        "deploy/schemas/configmap_v1.json",
        "e0eaddebd677c08aa092b2da2264d86ac4fc34eed112b9fac2945b3f00c1e9b1",
    ),
    (
        "deploy/schemas/monitoring.coreos.com/servicemonitor_v1.json",
        "e27d2c90afaf0950fe99f822072d9db7882a7fb134c2781583b0ea0cfcdf0bbd",
    ),
    (
        "deploy/schemas/networking.k8s.io/networkpolicy_v1.json",
        "68f66caa6cb28841e7ab6b2b1cf5ac56085d50730a3813e538dd9204529b5b04",
    ),
    (
        "deploy/schemas/policy/poddisruptionbudget_v1.json",
        "9f72ca6ac7baa59ce19de22e9817b0ec91ae3f061343acd212c70c511a40e10b",
    ),
    (
        "deploy/schemas/secrets-store.csi.x-k8s.io/secretproviderclass_v1.json",
        "fdba4a9fd8cf4073d7bf1f67d8ffac86073486431cc529f3be407b35d58d001f",
    ),
    (
        "deploy/schemas/service_v1.json",
        "4de9eaf03191038e5b82edaed358d91abc474dd375c582d216b951c12934fbed",
    ),
    (
        "deploy/schemas/serviceaccount_v1.json",
        "30f37eecc08c8793b1b96f954986e48320a7d5c265bf3a00cefd8595c2c63b44",
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RenderPhase {
    Migration,
    Serving,
}

impl RenderPhase {
    const fn consumer(self) -> SecretConsumer {
        match self {
            Self::Migration => SecretConsumer::Migration,
            Self::Serving => SecretConsumer::Serving,
        }
    }
}

pub(crate) fn validate_rendered_phase(
    rendered: &[u8],
    plan: &DeploymentPlan,
    profile: &str,
    phase: RenderPhase,
) -> Result<()> {
    let documents = serde_yaml_ng::Deserializer::from_slice(rendered)
        .map(|document| {
            Value::deserialize(document)
                .with_context(|| format!("profile={profile}: rendered manifest is invalid YAML"))
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        !documents.is_empty(),
        "profile={profile}: rendered manifest set is empty"
    );
    validate_resource_identities(&documents, profile)?;
    validate_gvk_closure(&documents, profile, phase)?;
    validate_forbidden_surfaces(&documents, profile)?;
    validate_resource_counts(&documents, plan, profile, phase)?;
    match phase {
        RenderPhase::Migration => validate_migration(&documents, plan, profile),
        RenderPhase::Serving => validate_serving(&documents, plan, profile),
    }
}

fn validate_gvk_closure(documents: &[Value], profile: &str, phase: RenderPhase) -> Result<()> {
    const MIGRATION_GVKS: &[(&str, &str)] = &[
        ("v1", "ServiceAccount"),
        ("batch/v1", "Job"),
        ("networking.k8s.io/v1", "NetworkPolicy"),
        ("secrets-store.csi.x-k8s.io/v1", "SecretProviderClass"),
    ];
    const SERVING_GVKS: &[(&str, &str)] = &[
        ("v1", "ConfigMap"),
        ("v1", "Service"),
        ("v1", "ServiceAccount"),
        ("apps/v1", "Deployment"),
        ("autoscaling/v2", "HorizontalPodAutoscaler"),
        ("monitoring.coreos.com/v1", "ServiceMonitor"),
        ("networking.k8s.io/v1", "NetworkPolicy"),
        ("policy/v1", "PodDisruptionBudget"),
        ("secrets-store.csi.x-k8s.io/v1", "SecretProviderClass"),
    ];
    let allowed = match phase {
        RenderPhase::Migration => MIGRATION_GVKS,
        RenderPhase::Serving => SERVING_GVKS,
    };
    for document in documents {
        let api_version = document
            .pointer("/apiVersion")
            .and_then(Value::as_str)
            .context("rendered resource apiVersion missing")?;
        let kind = document
            .pointer("/kind")
            .and_then(Value::as_str)
            .context("rendered resource kind missing")?;
        ensure!(
            allowed.contains(&(api_version, kind)),
            "profile={profile} apiVersion={api_version} resource={kind}: resource is outside the phase GVK closure"
        );
    }
    Ok(())
}

fn validate_forbidden_surfaces(documents: &[Value], profile: &str) -> Result<()> {
    for forbidden in ["Secret", "Role", "RoleBinding"] {
        ensure!(
            resources(documents, forbidden).is_empty(),
            "profile={profile} resource={forbidden}: forbidden resource kind"
        );
    }
    for document in documents {
        ensure!(
            document.pointer("/data").is_none()
                || document.pointer("/kind").and_then(Value::as_str) == Some("ConfigMap"),
            "profile={profile}: secret-like data surface is forbidden"
        );
        ensure!(
            !contains_key(document, "secretKeyRef")
                && !contains_key(document, "envFrom")
                && !contains_key(document, "stringData"),
            "profile={profile}: secret environment surface is forbidden"
        );
        reject_plain_secret_environment(document, profile)?;
    }
    Ok(())
}

fn reject_plain_secret_environment(value: &Value, profile: &str) -> Result<()> {
    if let Some(environment) = value.get("env").and_then(Value::as_array) {
        for entry in environment {
            let Some(name) = entry.get("name").and_then(Value::as_str) else {
                continue;
            };
            let upper = name.to_ascii_uppercase();
            let secret_bearing = ["PASSWORD", "SECRET", "TOKEN", "SIGNING_KEY", "HMAC_KEY"]
                .iter()
                .any(|marker| upper.contains(marker));
            ensure!(
                !secret_bearing || upper.ends_with("_FILE"),
                "profile={profile}: secret-bearing environment entry must be a file reference: {name}"
            );
        }
    }
    match value {
        Value::Object(map) => {
            for child in map.values() {
                reject_plain_secret_environment(child, profile)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                reject_plain_secret_environment(child, profile)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn contains_key(value: &Value, needle: &str) -> bool {
    match value {
        Value::Object(map) => {
            map.contains_key(needle) || map.values().any(|value| contains_key(value, needle))
        }
        Value::Array(values) => values.iter().any(|value| contains_key(value, needle)),
        _ => false,
    }
}

fn validate_resource_counts(
    documents: &[Value],
    plan: &DeploymentPlan,
    profile: &str,
    phase: RenderPhase,
) -> Result<()> {
    let workloads = plan.workloads().len();
    let service_accounts = plan
        .workloads()
        .iter()
        .map(|workload| workload.identity().service_account())
        .collect::<BTreeSet<_>>()
        .len();
    let exposed_services = plan
        .services()
        .iter()
        .filter(|service| {
            service
                .ports()
                .iter()
                .any(|port| port.exposure() == PortExposure::ServiceExposed)
        })
        .count();
    let monitored_services = plan
        .services()
        .iter()
        .filter(|service| {
            service.ports().iter().any(|port| {
                port.name() == "health" && port.exposure() == PortExposure::ServiceExposed
            })
        })
        .count();
    let expected = match phase {
        RenderPhase::Migration => [
            ("ServiceAccount", service_accounts),
            ("Job", workloads),
            ("SecretProviderClass", workloads),
            ("NetworkPolicy", workloads * 2),
            ("Deployment", 0),
            ("Service", 0),
            ("ConfigMap", 0),
            ("HorizontalPodAutoscaler", 0),
            ("PodDisruptionBudget", 0),
            ("ServiceMonitor", 0),
        ],
        RenderPhase::Serving => [
            ("ServiceAccount", service_accounts),
            ("Job", 0),
            ("SecretProviderClass", workloads),
            ("NetworkPolicy", workloads * 3),
            ("Deployment", workloads),
            ("Service", exposed_services),
            ("ConfigMap", 1),
            ("HorizontalPodAutoscaler", workloads),
            ("PodDisruptionBudget", workloads),
            ("ServiceMonitor", monitored_services),
        ],
    };
    for (kind, count) in expected {
        ensure!(
            resources(documents, kind).len() == count,
            "profile={profile} resource={kind}: cardinality drift"
        );
    }
    Ok(())
}

fn resources<'a>(documents: &'a [Value], kind: &str) -> Vec<&'a Value> {
    documents
        .iter()
        .filter(|document| document.pointer("/kind").and_then(Value::as_str) == Some(kind))
        .collect()
}

fn validate_resource_identities(documents: &[Value], profile: &str) -> Result<()> {
    let mut identities = BTreeSet::new();
    for document in documents {
        let api_version = document
            .pointer("/apiVersion")
            .and_then(Value::as_str)
            .context("rendered resource apiVersion missing")?;
        let kind = document
            .pointer("/kind")
            .and_then(Value::as_str)
            .context("rendered resource kind missing")?;
        let name = document
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .context("rendered resource metadata.name missing")?;
        let namespace = document
            .pointer("/metadata/namespace")
            .and_then(Value::as_str)
            .unwrap_or("default");
        ensure!(
            identities.insert((api_version, kind, namespace, name)),
            "profile={profile} resource={kind}: duplicate Kubernetes identity {namespace}/{name}"
        );
    }
    Ok(())
}

fn validate_migration(documents: &[Value], plan: &DeploymentPlan, profile: &str) -> Result<()> {
    ensure!(
        plan.migration_mode() == MigrationMode::ForwardOnlyTwoPhase,
        "profile={profile}: migration phase requires forward-only fence"
    );
    let migration_head = plan
        .migration_head_fingerprint()
        .context("forward-only plan migration head fingerprint missing")?;
    let artifact = plan
        .migration_artifact()
        .context("forward-only plan migration artifact missing")?;
    let budget = plan
        .migration_execution_budget()
        .context("forward-only plan migration execution budget missing")?;
    ensure!(
        plan.availability_class() == AvailabilityClass::MaintenanceWindow,
        "profile={profile}: forward-only migration requires maintenance window availability"
    );
    let head_suffix = &migration_head.as_str()["sha256:".len()..][..12];
    for job in resources(documents, "Job") {
        let component = job
            .pointer("/metadata/labels/app.kubernetes.io~1component")
            .and_then(Value::as_str)
            .context("Job component label missing")?;
        let workload_name = component
            .strip_suffix("-migration")
            .context("Job migration component suffix missing")?;
        let workload = plan
            .workloads()
            .iter()
            .find(|workload| workload.name() == workload_name)
            .with_context(|| {
                format!("profile={profile} resource=Job: unknown workload {workload_name}")
            })?;
        let semantic_suffix = format!("{}-migration-r1-{head_suffix}", workload.name());
        let expected_name = if semantic_suffix.len() >= 62 {
            semantic_suffix
        } else {
            format!("rss-{semantic_suffix}")
        };
        ensure!(
            job.pointer("/metadata/name").and_then(Value::as_str) == Some(&expected_name),
            "profile={profile} resource=Job: migration head identity drift"
        );
        ensure_eq(
            job.pointer("/spec/activeDeadlineSeconds"),
            &Value::from(budget.active_deadline_seconds()),
            profile,
            "Job",
            "/spec/activeDeadlineSeconds",
        )?;
        ensure_eq(
            job.pointer("/spec/backoffLimit"),
            &Value::from(budget.backoff_limit()),
            profile,
            "Job",
            "/spec/backoffLimit",
        )?;
        ensure_eq(
            job.pointer("/spec/template/spec/automountServiceAccountToken"),
            &Value::Bool(false),
            profile,
            "Job",
            "/spec/template/spec/automountServiceAccountToken",
        )?;
        ensure_eq(
            job.pointer("/spec/template/spec/containers/0/image"),
            &Value::String(artifact.image().to_owned()),
            profile,
            "Job",
            "/spec/template/spec/containers/0/image",
        )?;
        ensure_eq(
            job.pointer("/spec/template/spec/containers/0/command"),
            &serde_json::json!(["rss", "postgres", "migrate-all"]),
            profile,
            "Job",
            "/spec/template/spec/containers/0/command",
        )?;
        ensure_eq(
            job.pointer("/spec/template/spec/containers/0/env"),
            &serde_json::json!([
                {
                    "name": "RSS_PG_DATABASE_URL_FILE",
                    "value": "/var/run/rss/secrets/database-url"
                },
                {
                    "name": "RSS_BUILD_SOURCE_SHA",
                    "value": artifact.source_revision()
                },
                {
                    "name": "RSS_BUILD_IMAGE_DIGEST",
                    "value": artifact.image().rsplit_once('@').map(|(_, digest)| digest)
                        .context("migration artifact image digest missing")?
                }
            ]),
            profile,
            "Job",
            "/spec/template/spec/containers/0/env",
        )?;
        ensure_eq(
            job.pointer("/spec/template/spec/containers/0/resources/requests/cpu"),
            &Value::String(workload.resources().requests().cpu().to_owned()),
            profile,
            "Job",
            "/spec/template/spec/containers/0/resources/requests/cpu",
        )?;
        ensure_eq(
            job.pointer("/spec/template/spec/containers/0/resources/requests/memory"),
            &Value::String(workload.resources().requests().memory().to_owned()),
            profile,
            "Job",
            "/spec/template/spec/containers/0/resources/requests/memory",
        )?;
        ensure_eq(
            job.pointer("/spec/template/spec/containers/0/resources/limits/cpu"),
            &Value::String(workload.resources().limits().cpu().to_owned()),
            profile,
            "Job",
            "/spec/template/spec/containers/0/resources/limits/cpu",
        )?;
        ensure_eq(
            job.pointer("/spec/template/spec/containers/0/resources/limits/memory"),
            &Value::String(workload.resources().limits().memory().to_owned()),
            profile,
            "Job",
            "/spec/template/spec/containers/0/resources/limits/memory",
        )?;
        validate_read_only_vault_mount(job, profile, "Job")?;
    }
    validate_secret_provider_classes(documents, plan, profile, RenderPhase::Migration)?;
    validate_network_policies(documents, plan, profile, RenderPhase::Migration)
}

fn validate_serving(documents: &[Value], plan: &DeploymentPlan, profile: &str) -> Result<()> {
    let expected_availability = match plan.migration_mode() {
        MigrationMode::ForwardOnlyTwoPhase => AvailabilityClass::MaintenanceWindow,
        MigrationMode::None => AvailabilityClass::HighlyAvailable,
    };
    ensure!(
        plan.availability_class() == expected_availability,
        "profile={profile}: migration and availability policy drift"
    );
    for deployment in resources(documents, "Deployment") {
        let component = deployment
            .pointer("/metadata/labels/app.kubernetes.io~1component")
            .and_then(Value::as_str)
            .context("Deployment component label missing")?;
        let workload = plan
            .workloads()
            .iter()
            .find(|workload| workload.name() == component)
            .with_context(|| {
                format!("profile={profile} resource=Deployment: unknown workload {component}")
            })?;
        ensure_eq(
            deployment.pointer("/spec/template/spec/containers/0/image"),
            &Value::String(workload.image().to_owned()),
            profile,
            "Deployment",
            "/spec/template/spec/containers/0/image",
        )?;
        ensure_eq(
            deployment.pointer("/spec/template/spec/containers/0/resources"),
            &serde_json::json!({
                "limits": {
                    "cpu": workload.resources().limits().cpu(),
                    "memory": workload.resources().limits().memory(),
                },
                "requests": {
                    "cpu": workload.resources().requests().cpu(),
                    "memory": workload.resources().requests().memory(),
                },
            }),
            profile,
            "Deployment",
            "/spec/template/spec/containers/0/resources",
        )?;
        validate_probes(deployment, workload.probes(), profile)?;
        let expected_strategy = match plan.migration_mode() {
            MigrationMode::ForwardOnlyTwoPhase => "Recreate",
            MigrationMode::None => "RollingUpdate",
        };
        ensure_eq(
            deployment.pointer("/spec/strategy/type"),
            &Value::String(expected_strategy.to_owned()),
            profile,
            "Deployment",
            "/spec/strategy/type",
        )?;
        ensure!(
            deployment.pointer("/spec/replicas").is_none(),
            "profile={profile} resource=Deployment field=/spec/replicas: HPA owner conflict"
        );
        let grace = u64::from(plan.drain_seconds()) + 15;
        ensure_eq(
            deployment.pointer("/spec/template/spec/terminationGracePeriodSeconds"),
            &Value::from(grace),
            profile,
            "Deployment",
            "/spec/template/spec/terminationGracePeriodSeconds",
        )?;
        ensure_eq(
            deployment.pointer("/spec/template/spec/automountServiceAccountToken"),
            &Value::Bool(false),
            profile,
            "Deployment",
            "/spec/template/spec/automountServiceAccountToken",
        )?;
        ensure_eq(
            deployment.pointer("/spec/template/spec/containers/0/lifecycle/preStop/sleep/seconds"),
            &Value::from(5),
            profile,
            "Deployment",
            "/spec/template/spec/containers/0/lifecycle/preStop/sleep/seconds",
        )?;
        validate_spreads(deployment, profile)?;
        validate_read_only_vault_mount(deployment, profile, "Deployment")?;
        validate_spiffe_mount(deployment, plan, profile)?;
        validate_application_config(documents, deployment, plan, profile)?;
    }
    validate_workload_linkage(documents, profile)?;
    validate_availability(documents, plan, profile)?;
    validate_service_monitors(documents, profile)?;
    validate_secret_provider_classes(documents, plan, profile, RenderPhase::Serving)?;
    validate_network_policies(documents, plan, profile, RenderPhase::Serving)
}

fn validate_probes(
    deployment: &Value,
    probes: &[assembly_schema::ProbePlan],
    profile: &str,
) -> Result<()> {
    for (kind, field) in [
        (ProbeKind::Startup, "startupProbe"),
        (ProbeKind::Readiness, "readinessProbe"),
        (ProbeKind::Liveness, "livenessProbe"),
    ] {
        let pointer = format!("/spec/template/spec/containers/0/{field}");
        let expected = probes
            .iter()
            .find(|probe| probe.kind() == kind)
            .map(|probe| {
                serde_json::json!({
                    "httpGet": {
                        "path": probe.path(),
                        "port": probe.port(),
                        "scheme": "HTTP",
                    }
                })
            });
        ensure!(
            deployment.pointer(&pointer) == expected.as_ref(),
            "profile={profile} resource=Deployment field={pointer}: probe projection drift"
        );
    }
    Ok(())
}

fn ensure_eq(
    actual: Option<&Value>,
    expected: &Value,
    profile: &str,
    resource: &str,
    pointer: &str,
) -> Result<()> {
    ensure!(
        actual == Some(expected),
        "profile={profile} resource={resource} field={pointer}: policy drift"
    );
    Ok(())
}

fn validate_read_only_vault_mount(document: &Value, profile: &str, kind: &str) -> Result<()> {
    let pod = "/spec/template/spec";
    let mounts = document
        .pointer(&format!("{pod}/containers/0/volumeMounts"))
        .and_then(Value::as_array)
        .context("Vault volume mounts missing")?;
    ensure!(
        mounts.iter().any(|mount| {
            mount.pointer("/name").and_then(Value::as_str) == Some("vault-secrets")
                && mount.pointer("/readOnly").and_then(Value::as_bool) == Some(true)
        }),
        "profile={profile} resource={kind}: read-only Vault mount missing"
    );
    let volumes = document
        .pointer(&format!("{pod}/volumes"))
        .and_then(Value::as_array)
        .context("Vault volumes missing")?;
    ensure!(
        volumes.iter().any(|volume| {
            volume.pointer("/name").and_then(Value::as_str) == Some("vault-secrets")
                && volume.pointer("/csi/driver").and_then(Value::as_str)
                    == Some("secrets-store.csi.k8s.io")
                && volume.pointer("/csi/readOnly").and_then(Value::as_bool) == Some(true)
        }),
        "profile={profile} resource={kind}: Vault CSI volume missing"
    );
    Ok(())
}

fn validate_spreads(deployment: &Value, profile: &str) -> Result<()> {
    let spreads = deployment
        .pointer("/spec/template/spec/topologySpreadConstraints")
        .and_then(Value::as_array)
        .context("topologySpreadConstraints missing")?;
    ensure!(
        spreads.iter().any(|spread| {
            spread.pointer("/topologyKey").and_then(Value::as_str) == Some("kubernetes.io/hostname")
                && spread.pointer("/whenUnsatisfiable").and_then(Value::as_str)
                    == Some("DoNotSchedule")
        }),
        "profile={profile} resource=Deployment: hostname spread missing"
    );
    ensure!(
        spreads.iter().any(|spread| {
            spread.pointer("/topologyKey").and_then(Value::as_str)
                == Some("topology.kubernetes.io/zone")
                && spread.pointer("/whenUnsatisfiable").and_then(Value::as_str)
                    == Some("ScheduleAnyway")
        }),
        "profile={profile} resource=Deployment: zone spread missing"
    );
    Ok(())
}

fn named_entry<'a>(document: &'a Value, pointer: &str, name: &str) -> Option<&'a Value> {
    document
        .pointer(pointer)
        .and_then(Value::as_array)?
        .iter()
        .find(|entry| entry.pointer("/name").and_then(Value::as_str) == Some(name))
}

#[cfg(test)]
fn named_entry_mut<'a>(
    document: &'a mut Value,
    pointer: &str,
    name: &str,
) -> Option<&'a mut Value> {
    document
        .pointer_mut(pointer)?
        .as_array_mut()?
        .iter_mut()
        .find(|entry| entry.pointer("/name").and_then(Value::as_str) == Some(name))
}

fn workload_port(plan: &DeploymentPlan, workload: &str, name: &str) -> Option<u16> {
    plan.services()
        .iter()
        .filter(|service| service.workload() == workload)
        .flat_map(|service| service.ports())
        .find(|port| port.name() == name)
        .map(|port| port.port())
}

fn environment_value<'a>(deployment: &'a Value, name: &str) -> Option<&'a str> {
    named_entry(deployment, "/spec/template/spec/containers/0/env", name)?
        .pointer("/value")
        .and_then(Value::as_str)
}

fn validate_application_config(
    documents: &[Value],
    deployment: &Value,
    plan: &DeploymentPlan,
    profile: &str,
) -> Result<()> {
    let component = deployment
        .pointer("/metadata/labels/app.kubernetes.io~1component")
        .and_then(Value::as_str)
        .context("Deployment component label missing")?;
    let workload = plan
        .workloads()
        .iter()
        .find(|workload| workload.name() == component)
        .context("Deployment application config workload missing")?;
    let args = deployment.pointer("/spec/template/spec/containers/0/args");
    let public_trust = named_entry(deployment, "/spec/template/spec/volumes", "public-trust");
    let config_map = resources(documents, "ConfigMap")
        .into_iter()
        .next()
        .context("serving ConfigMap missing")?;
    match workload.application_config() {
        ApplicationConfig::None => {
            ensure!(
                args.is_none() && public_trust.is_none(),
                "profile={profile} resource=Deployment: unexpected application config carrier"
            );
            for (port_name, environment) in [
                ("http", "RSS_PRIMARY_LISTEN_ADDR"),
                ("internal", "RSS_INTERNAL_LISTEN_ADDR"),
                ("admin", "RSS_ADMIN_LISTEN_ADDR"),
                ("health", "RSS_HEALTH_LISTEN_ADDR"),
            ] {
                let expected =
                    workload_port(plan, component, port_name).map(|port| format!("0.0.0.0:{port}"));
                ensure!(
                    environment_value(deployment, environment) == expected.as_deref(),
                    "profile={profile} resource=Deployment: runtime listener input drift"
                );
            }
            let ceilings = plan.replica_database_budget().pool_ceilings();
            for (environment, expected) in [
                ("RSS_PG_MAX_CONNECTIONS", Some(ceilings.writer())),
                ("RSS_PG_READ_MAX_CONNECTIONS", Some(ceilings.reader())),
                (
                    "RSS_PG_DLX_ARCHIVER_MAX_CONNECTIONS",
                    ceilings.dlx_archiver(),
                ),
                (
                    "RSS_PG_DLX_VERIFIER_MAX_CONNECTIONS",
                    ceilings.dlx_verifier(),
                ),
                ("RSS_PG_DLX_PURGER_MAX_CONNECTIONS", ceilings.dlx_purger()),
            ] {
                let expected = expected.map(|value| value.to_string());
                ensure!(
                    environment_value(deployment, environment) == expected.as_deref(),
                    "profile={profile} resource=Deployment: PostgreSQL pool ceiling drift"
                );
            }
        }
        ApplicationConfig::SettingsOnlyV1 | ApplicationConfig::IdentityAuditV1 => {
            ensure_eq(
                args,
                &serde_json::json!(["--config", "/var/run/rss/deployment/application.toml"]),
                profile,
                "Deployment",
                "/spec/template/spec/containers/0/args",
            )?;
            ensure!(
                config_map
                    .pointer("/data")
                    .and_then(Value::as_object)
                    .is_some_and(|data| data.contains_key(&format!("{component}.toml"))),
                "profile={profile} resource=ConfigMap: workload application config missing"
            );
            let application = config_map
                .pointer("/data")
                .and_then(Value::as_object)
                .and_then(|data| data.get(&format!("{component}.toml")))
                .and_then(Value::as_str)
                .context("workload application config document missing")?;
            let application: toml::Value =
                toml::from_str(application).context("workload application config is invalid")?;
            let ceilings = plan.replica_database_budget().pool_ceilings();
            for (role, expected) in [
                ("writer", Some(ceilings.writer())),
                ("reader", Some(ceilings.reader())),
                ("auditAdmin", ceilings.audit_admin()),
            ] {
                let configured = application
                    .get("postgres")
                    .and_then(|value| value.get(role))
                    .and_then(|value| value.get("maxConnections"))
                    .and_then(toml::Value::as_integer)
                    .and_then(|value| u16::try_from(value).ok());
                ensure!(
                    configured == expected,
                    "profile={profile} resource=ConfigMap: PostgreSQL pool ceiling drift"
                );
            }
            for (listener, port_name, environment) in [
                ("primary", "http", "RSS_DEPLOYMENT_PRIMARY_PORT"),
                ("admin", "admin", "RSS_DEPLOYMENT_ADMIN_PORT"),
                ("health", "health", "RSS_DEPLOYMENT_HEALTH_PORT"),
            ] {
                let expected = workload_port(plan, component, port_name)
                    .context("typed workload listener port missing")?;
                let configured = application
                    .get("listeners")
                    .and_then(|value| value.get(listener))
                    .and_then(|value| value.get("bind"))
                    .and_then(toml::Value::as_str)
                    .and_then(|bind| bind.rsplit_once(':'))
                    .and_then(|(_, port)| port.parse::<u16>().ok());
                let expected_text = expected.to_string();
                ensure!(
                    configured == Some(expected)
                        && environment_value(deployment, environment)
                            == Some(expected_text.as_str()),
                    "profile={profile} resource=Deployment: sealed listener carrier drift"
                );
            }
            let deployment_plan =
                named_entry(deployment, "/spec/template/spec/volumes", "deployment-plan")
                    .context("deployment plan projection missing")?;
            let config_key = format!("{component}.toml");
            ensure!(
                deployment_plan
                    .pointer("/projected/sources/0/configMap/items")
                    .and_then(Value::as_array)
                    .is_some_and(|items| items.iter().any(|item| {
                        item.pointer("/key").and_then(Value::as_str) == Some(config_key.as_str())
                            && item.pointer("/path").and_then(Value::as_str)
                                == Some("application.toml")
                    })),
                "profile={profile} resource=Deployment: workload application projection drift"
            );
            let trust = public_trust.context("public trust ConfigMap projection missing")?;
            ensure_eq(
                trust.pointer("/configMap/name"),
                &Value::String("rss-public-trust-v1".to_owned()),
                profile,
                "Deployment",
                "/spec/template/spec/volumes/public-trust/configMap/name",
            )?;
            let actual = trust
                .pointer("/configMap/items")
                .and_then(Value::as_array)
                .context("public trust key projection missing")?
                .iter()
                .filter_map(|item| item.pointer("/key").and_then(Value::as_str))
                .collect::<BTreeSet<_>>();
            let expected = match workload.application_config() {
                ApplicationConfig::SettingsOnlyV1 => {
                    BTreeSet::from(["postgres-ca.pem", "vault-ca.pem", "federated.jwks.json"])
                }
                ApplicationConfig::IdentityAuditV1 => BTreeSet::from([
                    "postgres-ca.pem",
                    "vault-ca.pem",
                    "oidc.jwks.json",
                    "password-blocklist.sha256",
                ]),
                ApplicationConfig::None => BTreeSet::new(),
            };
            ensure!(
                actual == expected,
                "profile={profile} resource=Deployment: public trust projection drift"
            );
        }
    }
    Ok(())
}

fn validate_spiffe_mount(deployment: &Value, plan: &DeploymentPlan, profile: &str) -> Result<()> {
    let component = deployment
        .pointer("/metadata/labels/app.kubernetes.io~1component")
        .and_then(Value::as_str)
        .context("Deployment component label missing")?;
    let ingress_peers = plan
        .workloads()
        .iter()
        .find(|workload| workload.name() == component)
        .context("Deployment workload missing from typed plan")?
        .ingress_peer_identities()
        .next()
        .is_some();
    let expected = ingress_peers
        || plan.services().iter().any(|service| {
            service.workload() == component
                && service
                    .ports()
                    .iter()
                    .any(|port| port.exposure() == PortExposure::WorkloadOnly)
        });
    let volumes = deployment
        .pointer("/spec/template/spec/volumes")
        .and_then(Value::as_array)
        .context("Deployment volumes missing")?;
    let actual = volumes.iter().any(|volume| {
        volume.pointer("/csi/driver").and_then(Value::as_str) == Some("csi.spiffe.io")
    });
    ensure!(
        actual == expected,
        "profile={profile} resource=Deployment: SPIFFE listener closure drift"
    );
    let endpoint = deployment
        .pointer("/spec/template/spec/containers/0/env")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|entry| {
            entry.pointer("/name").and_then(Value::as_str) == Some("SPIFFE_ENDPOINT_SOCKET")
                && entry.pointer("/value").and_then(Value::as_str)
                    == Some("unix:///run/spire/sockets/agent.sock")
        });
    ensure!(
        endpoint == expected,
        "profile={profile} resource=Deployment: SPIFFE endpoint closure drift"
    );
    Ok(())
}

fn string_map(value: Option<&Value>) -> Option<BTreeMap<&str, &str>> {
    value?.as_object().map(|map| {
        map.iter()
            .filter_map(|(key, value)| value.as_str().map(|value| (key.as_str(), value)))
            .collect()
    })
}

fn validate_workload_linkage(documents: &[Value], profile: &str) -> Result<()> {
    let deployments = resources(documents, "Deployment");
    for deployment in deployments {
        let name = deployment
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .context("Deployment metadata.name missing")?;
        let component = deployment
            .pointer("/metadata/labels/app.kubernetes.io~1component")
            .and_then(Value::as_str)
            .context("Deployment component label missing")?;
        let pod_labels = string_map(deployment.pointer("/spec/template/metadata/labels"))
            .context("Deployment pod labels missing")?;

        let hpa = resources(documents, "HorizontalPodAutoscaler")
            .into_iter()
            .filter(|resource| {
                resource
                    .pointer("/metadata/labels/app.kubernetes.io~1component")
                    .and_then(Value::as_str)
                    == Some(component)
            })
            .collect::<Vec<_>>();
        ensure!(
            hpa.len() == 1
                && hpa[0]
                    .pointer("/spec/scaleTargetRef/name")
                    .and_then(Value::as_str)
                    == Some(name),
            "profile={profile} resource=HorizontalPodAutoscaler: workload target drift"
        );

        for kind in ["PodDisruptionBudget", "Service", "NetworkPolicy"] {
            for resource in resources(documents, kind).into_iter().filter(|resource| {
                resource
                    .pointer("/metadata/labels/app.kubernetes.io~1component")
                    .and_then(Value::as_str)
                    == Some(component)
            }) {
                let pointer = if kind == "Service" {
                    "/spec/selector"
                } else if kind == "NetworkPolicy" {
                    "/spec/podSelector/matchLabels"
                } else {
                    "/spec/selector/matchLabels"
                };
                ensure!(
                    string_map(resource.pointer(pointer)).as_ref() == Some(&pod_labels),
                    "profile={profile} resource={kind}: workload selector drift"
                );
            }
        }

        let port_names = deployment
            .pointer("/spec/template/spec/containers/0/ports")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|port| port.pointer("/name").and_then(Value::as_str))
            .collect::<BTreeSet<_>>();
        for service in resources(documents, "Service")
            .into_iter()
            .filter(|resource| {
                resource
                    .pointer("/metadata/labels/app.kubernetes.io~1component")
                    .and_then(Value::as_str)
                    == Some(component)
            })
        {
            for port in service
                .pointer("/spec/ports")
                .and_then(Value::as_array)
                .context("Service ports missing")?
            {
                let target = port
                    .pointer("/targetPort")
                    .and_then(Value::as_str)
                    .context("Service targetPort must use a closed listener name")?;
                ensure!(
                    port_names.contains(target),
                    "profile={profile} resource=Service: targetPort listener drift"
                );
            }
        }
    }

    for monitor in resources(documents, "ServiceMonitor") {
        let selector = string_map(monitor.pointer("/spec/selector/matchLabels"))
            .context("ServiceMonitor selector missing")?;
        ensure!(
            resources(documents, "Service")
                .into_iter()
                .any(
                    |service| string_map(service.pointer("/spec/selector")).as_ref()
                        == Some(&selector)
                ),
            "profile={profile} resource=ServiceMonitor: service selector drift"
        );
    }
    Ok(())
}

fn validate_availability(documents: &[Value], plan: &DeploymentPlan, profile: &str) -> Result<()> {
    let budget = plan.replica_database_budget();
    ensure!(
        u32::from(budget.max_replicas()) * budget.connections_per_replica()
            <= u32::from(budget.database_connection_limit() - budget.reserved_connections()),
        "profile={profile}: replica database capacity equation drift"
    );
    for hpa in resources(documents, "HorizontalPodAutoscaler") {
        ensure_eq(
            hpa.pointer("/spec/minReplicas"),
            &Value::from(budget.min_replicas()),
            profile,
            "HorizontalPodAutoscaler",
            "/spec/minReplicas",
        )?;
        ensure_eq(
            hpa.pointer("/spec/maxReplicas"),
            &Value::from(budget.max_replicas()),
            profile,
            "HorizontalPodAutoscaler",
            "/spec/maxReplicas",
        )?;
        ensure_eq(
            hpa.pointer("/spec/metrics/0/resource/target/averageUtilization"),
            &Value::from(70),
            profile,
            "HorizontalPodAutoscaler",
            "/spec/metrics/0/resource/target/averageUtilization",
        )?;
    }
    for pdb in resources(documents, "PodDisruptionBudget") {
        ensure_eq(
            pdb.pointer("/spec/maxUnavailable"),
            &Value::from(1),
            profile,
            "PodDisruptionBudget",
            "/spec/maxUnavailable",
        )?;
    }
    Ok(())
}

fn validate_service_monitors(documents: &[Value], profile: &str) -> Result<()> {
    for monitor in resources(documents, "ServiceMonitor") {
        ensure_eq(
            monitor.pointer("/spec/endpoints/0/port"),
            &Value::String("health".to_owned()),
            profile,
            "ServiceMonitor",
            "/spec/endpoints/0/port",
        )?;
        ensure_eq(
            monitor.pointer("/spec/endpoints/0/path"),
            &Value::String("/health/v1/metrics".to_owned()),
            profile,
            "ServiceMonitor",
            "/spec/endpoints/0/path",
        )?;
    }
    Ok(())
}

fn validate_secret_provider_classes(
    documents: &[Value],
    plan: &DeploymentPlan,
    profile: &str,
    phase: RenderPhase,
) -> Result<()> {
    for spc in resources(documents, "SecretProviderClass") {
        let component = spc
            .pointer("/metadata/labels/app.kubernetes.io~1component")
            .and_then(Value::as_str)
            .context("SecretProviderClass component label missing")?;
        let workload = plan
            .workloads()
            .iter()
            .find(|workload| workload.name() == component)
            .with_context(|| {
                format!(
                    "profile={profile} resource=SecretProviderClass: unknown workload {component}"
                )
            })?;
        let bindings = workload
            .secret_bindings()
            .iter()
            .filter(|binding| binding.consumers().contains(&phase.consumer()))
            .collect::<Vec<_>>();
        for binding in &bindings {
            let expected_consumer = [phase.consumer()];
            ensure!(
                binding.consumers() == expected_consumer,
                "profile={profile} resource=SecretProviderClass: secret consumer closure drift"
            );
            let purpose_allowed = matches!(
                (phase, binding.purpose()),
                (RenderPhase::Migration, SecretPurpose::MigrationDatabaseUrl)
                    | (RenderPhase::Serving, SecretPurpose::ServingDatabaseUrl)
                    | (RenderPhase::Serving, SecretPurpose::ServingSecretBundle)
            );
            ensure!(
                purpose_allowed,
                "profile={profile} resource=SecretProviderClass: phase secret purpose drift"
            );
        }
        let store_ids = bindings
            .iter()
            .map(|binding| binding.vault().store_id())
            .collect::<BTreeSet<_>>();
        ensure!(
            store_ids.len() == 1,
            "profile={profile} resource=SecretProviderClass: workload Vault store closure drift"
        );
        let store_id = store_ids
            .first()
            .context("SecretProviderClass has no phase secret binding")?;
        ensure_eq(
            spc.pointer("/spec/parameters/vaultAddress"),
            &Value::String(format!("https://{store_id}.vault.svc:8200")),
            profile,
            "SecretProviderClass",
            "/spec/parameters/vaultAddress",
        )?;
        let phase_name = match phase {
            RenderPhase::Migration => "migration",
            RenderPhase::Serving => "serving",
        };
        ensure_eq(
            spc.pointer("/spec/parameters/roleName"),
            &Value::String(format!("rss-{profile}-{phase_name}")),
            profile,
            "SecretProviderClass",
            "/spec/parameters/roleName",
        )?;
        let spc_name = spc
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .context("SecretProviderClass metadata.name missing")?;
        let pod_kind = match phase {
            RenderPhase::Migration => "Job",
            RenderPhase::Serving => "Deployment",
        };
        let pod_component = match phase {
            RenderPhase::Migration => format!("{component}-migration"),
            RenderPhase::Serving => component.to_owned(),
        };
        let pod = resources(documents, pod_kind)
            .into_iter()
            .find(|resource| {
                resource
                    .pointer("/metadata/labels/app.kubernetes.io~1component")
                    .and_then(Value::as_str)
                    == Some(pod_component.as_str())
            })
            .with_context(|| format!("{pod_kind} for SecretProviderClass workload missing"))?;
        let mounted_spc = named_entry(pod, "/spec/template/spec/volumes", "vault-secrets")
            .and_then(|volume| {
                volume
                    .pointer("/csi/volumeAttributes/secretProviderClass")
                    .and_then(Value::as_str)
            });
        ensure!(
            mounted_spc == Some(spc_name),
            "profile={profile} resource={pod_kind}: workload SecretProviderClass reference drift"
        );
        ensure_eq(
            spc.pointer("/spec/provider"),
            &Value::String("vault".to_owned()),
            profile,
            "SecretProviderClass",
            "/spec/provider",
        )?;
        let objects = spc
            .pointer("/spec/parameters/objects")
            .and_then(Value::as_str)
            .context("SecretProviderClass objects missing")?;
        let parsed = serde_yaml_ng::from_str::<Vec<Value>>(objects)
            .context("SecretProviderClass objects invalid")?;
        let mut expected = bindings
            .iter()
            .map(|binding| {
                let mut object = serde_json::Map::from_iter([
                    (
                        "objectName".to_owned(),
                        Value::String(binding.target_file_name().to_owned()),
                    ),
                    (
                        "secretPath".to_owned(),
                        Value::String(binding.vault().ref_key().to_owned()),
                    ),
                    ("secretKey".to_owned(), Value::String("value".to_owned())),
                ]);
                if let Some(version) = binding.vault().ref_version() {
                    object.insert(
                        "objectVersion".to_owned(),
                        Value::String(version.to_owned()),
                    );
                }
                Value::Object(object)
            })
            .collect::<Vec<_>>();
        let sort_key = |object: &Value| {
            object
                .pointer("/objectName")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let mut actual = parsed;
        actual.sort_by_key(&sort_key);
        expected.sort_by_key(sort_key);
        ensure!(
            actual == expected,
            "profile={profile} resource=SecretProviderClass: workload Vault object projection drift"
        );
    }
    Ok(())
}

fn validate_network_policies(
    documents: &[Value],
    plan: &DeploymentPlan,
    profile: &str,
    phase: RenderPhase,
) -> Result<()> {
    let policies = resources(documents, "NetworkPolicy");
    ensure!(
        policies.iter().any(|policy| {
            policy
                .pointer("/spec/ingress")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
                && policy
                    .pointer("/spec/egress")
                    .and_then(Value::as_array)
                    .is_some_and(Vec::is_empty)
        }),
        "profile={profile} resource=NetworkPolicy: bidirectional default-deny missing"
    );
    let expected_egress = match phase {
        RenderPhase::Migration => 3,
        RenderPhase::Serving => plan.dependency_peer_roles().len(),
    };
    for policy in policies.iter().filter(|policy| {
        policy
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .is_some_and(|name| name.ends_with("-egress"))
    }) {
        ensure!(
            policy
                .pointer("/spec/egress")
                .and_then(Value::as_array)
                .is_some_and(|rules| rules.len() == expected_egress),
            "profile={profile} resource=NetworkPolicy: dependency egress closure drift"
        );
    }
    Ok(())
}

pub(crate) fn run() -> Result<()> {
    crate::deployment_plan::run(crate::deployment_plan::Action::Check)
        .context("deployment policy typed Helm preflight failed")?;
    run_after_plan_preflight()
}

pub(crate) fn run_after_plan_preflight() -> Result<()> {
    let root = crate::workspace_root()?;
    validate_repository(&root)
}

pub(crate) fn validate_repository(root: &Path) -> Result<()> {
    validate_schema_tree(root)?;
    validate_schema_digests(root)?;
    let (core, extensions) = repository_rendered_paths(root)?;
    validate_rendered_tree(root, &core, &extensions)?;
    probe_kubeconform(root)?;
    for relative in core {
        validate_with_kubeconform(root, &relative, false)?;
    }
    for relative in extensions {
        validate_with_kubeconform(root, &relative, true)?;
    }
    Ok(())
}

fn validate_schema_tree(root: &Path) -> Result<()> {
    let schema_root = root.join("deploy/schemas");
    let mut pending = vec![schema_root.clone()];
    let mut actual = BTreeSet::new();
    while let Some(directory) = pending.pop() {
        let metadata = fs::symlink_metadata(&directory)
            .context("deployment policy schema directory missing")?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "deployment policy schema directory is unsafe"
        );
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            ensure!(
                !metadata.file_type().is_symlink(),
                "deployment policy schema entry is a symlink"
            );
            if metadata.is_dir() {
                pending.push(path);
            } else {
                ensure!(
                    metadata.is_file(),
                    "deployment policy schema entry is unsafe"
                );
                actual.insert(
                    path.strip_prefix(root)?
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
            }
        }
    }
    let expected = SCHEMAS
        .iter()
        .map(|(relative, _)| (*relative).to_owned())
        .chain(["deploy/schemas/README.md".to_owned()])
        .collect::<BTreeSet<_>>();
    ensure!(
        actual == expected,
        "deployment policy schema exact-set drift"
    );
    Ok(())
}

fn validate_schema_digests(root: &Path) -> Result<()> {
    for (relative, expected) in SCHEMAS {
        let bytes = fs::read(root.join(relative))
            .with_context(|| format!("deployment policy schema missing: {relative}"))?;
        validate_digest(&bytes, expected)
            .with_context(|| format!("deployment policy schema drift: {relative}"))?;
    }
    Ok(())
}

fn validate_digest(bytes: &[u8], expected: &str) -> Result<()> {
    let actual = format!("{:x}", Sha256::digest(bytes));
    ensure!(actual == expected, "SHA-256 mismatch");
    Ok(())
}

fn rendered_paths(profiles: &[(String, MigrationMode)], extensions: bool) -> Vec<String> {
    let directory = if extensions {
        EXTENSIONS_DIR
    } else {
        RENDERED_DIR
    };
    profiles
        .iter()
        .flat_map(|(profile, mode)| {
            let mut paths = Vec::with_capacity(2);
            if *mode == MigrationMode::ForwardOnlyTwoPhase {
                paths.push(format!("{directory}/{profile}-migration.yaml"));
            }
            paths.push(format!("{directory}/{profile}-serving.yaml"));
            paths
        })
        .collect()
}

fn repository_rendered_paths(root: &Path) -> Result<(Vec<String>, Vec<String>)> {
    let matrix = crate::assembly_artifacts::load_verified(root)?;
    let mut profiles = Vec::new();
    for row in matrix.supported_rows() {
        let deployment = row.deployment();
        let plan = DeploymentPlan::compile_v1(deployment.runtime_plan(), deployment.plan_input())?;
        profiles.push((row.name().to_owned(), plan.migration_mode()));
    }
    ensure!(
        !profiles.is_empty(),
        "deployment policy profile set is empty"
    );
    Ok((
        rendered_paths(&profiles, false),
        rendered_paths(&profiles, true),
    ))
}

fn validate_rendered_tree(root: &Path, core: &[String], extensions: &[String]) -> Result<()> {
    validate_exact_directory(root, RENDERED_DIR, true, core)?;
    validate_exact_directory(root, EXTENSIONS_DIR, false, extensions)
}

fn validate_exact_directory(
    root: &Path,
    relative: &str,
    allow_extensions_directory: bool,
    expected: &[String],
) -> Result<()> {
    let directory = root.join(relative);
    let metadata = fs::symlink_metadata(&directory)
        .with_context(|| format!("deployment policy rendered directory missing: {relative}"))?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "deployment policy rendered directory is unsafe: {relative}"
    );
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(&directory)
        .with_context(|| format!("deployment policy cannot inspect: {relative}"))?
    {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if allow_extensions_directory && entry.file_name() == "extensions" {
            ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "deployment policy extensions directory is unsafe"
            );
            continue;
        }
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "deployment policy rendered entry is unsafe: {}",
            path.display()
        );
        let relative_path = path
            .strip_prefix(root)?
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = fs::read(&path)?;
        ensure!(
            !bytes.is_empty() && bytes.ends_with(b"\n") && !bytes.contains(&b'\r'),
            "deployment policy rendered bytes are not non-empty LF: {relative_path}"
        );
        actual.insert(relative_path);
    }
    let expected = expected.iter().cloned().collect::<BTreeSet<_>>();
    ensure!(
        actual == expected,
        "deployment policy rendered exact-set drift: {relative}"
    );
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KubeconformProbeError {
    Missing,
    Failed(String),
    InvalidUtf8,
    VersionMismatch { expected: String, actual: String },
}

impl std::fmt::Display for KubeconformProbeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => formatter.write_str("kubeconform executable is missing"),
            Self::Failed(stderr) => write!(formatter, "kubeconform probe failed: {stderr}"),
            Self::InvalidUtf8 => formatter.write_str("kubeconform version is not UTF-8"),
            Self::VersionMismatch { expected, actual } => {
                write!(
                    formatter,
                    "kubeconform version mismatch: expected={expected} actual={actual}"
                )
            }
        }
    }
}

impl std::error::Error for KubeconformProbeError {}

pub(crate) fn probe_kubeconform(root: &Path) -> std::result::Result<(), KubeconformProbeError> {
    let output = external_cmd(ExternalProgram::Kubeconform, &["-v"], &[], Some(root))
        .output()
        .map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                KubeconformProbeError::Missing
            } else {
                KubeconformProbeError::Failed(error.to_string())
            }
        })?;
    if !output.status.success() {
        return Err(KubeconformProbeError::Failed(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ));
    }
    let actual = std::str::from_utf8(&output.stdout)
        .map_err(|_| KubeconformProbeError::InvalidUtf8)?
        .trim();
    let expected = format!("v{KUBECONFORM_VERSION}");
    if actual != expected {
        return Err(KubeconformProbeError::VersionMismatch {
            expected,
            actual: actual.to_owned(),
        });
    }
    Ok(())
}

fn kubeconform_args(path: &str, _extensions: bool) -> Vec<&str> {
    vec![
        "-strict",
        "-summary",
        "-kubernetes-version",
        KUBERNETES_VERSION,
        "-schema-location",
        CORE_SCHEMA_LOCATION_TEMPLATE,
        "-schema-location",
        SCHEMA_LOCATION_TEMPLATE,
        path,
    ]
}

fn validate_with_kubeconform(root: &Path, relative: &str, extensions: bool) -> Result<()> {
    let args = kubeconform_args(relative, extensions);
    let output = external_cmd(ExternalProgram::Kubeconform, &args, &[], Some(root))
        .output()
        .with_context(|| format!("deployment policy kubeconform failed: {relative}"))?;
    let diagnostic = if output.stderr.is_empty() {
        &output.stdout
    } else {
        &output.stderr
    };
    ensure!(
        output.status.success(),
        "deployment policy kubeconform rejected {relative}: {}",
        String::from_utf8_lossy(diagnostic).trim()
    );
    let summary = String::from_utf8_lossy(&output.stdout);
    ensure!(
        (summary.contains(" resource found") || summary.contains(" resources found"))
            && !summary.contains("0 resource found")
            && !summary.contains("0 resources found"),
        "deployment policy kubeconform anti-vacuity failed: {relative}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEMANTIC_MUTATIONS: [&str; 21] = [
        "service-account",
        "secret-provider-class",
        "network-policy",
        "job",
        "pdb",
        "hpa",
        "service-monitor",
        "listener",
        "grace",
        "selector",
        "target-port",
        "spiffe",
        "resource-identity",
        "migration-env",
        "migration-resources",
        "migration-head",
        "application-config",
        "public-trust",
        "listener-carrier",
        "spc-reference",
        "postgres-pool-ceiling",
    ];

    fn repository_case(profile: &str, phase: RenderPhase) -> Result<(DeploymentPlan, Vec<Value>)> {
        let root = crate::workspace_root()?;
        let matrix = crate::assembly_artifacts::load_verified(&root)?;
        let row = matrix
            .supported_rows()
            .iter()
            .find(|row| row.name() == profile)
            .context("test profile missing")?;
        let deployment = row.deployment();
        let plan = DeploymentPlan::compile_v1(deployment.runtime_plan(), deployment.plan_input())?;
        let phase_name = match phase {
            RenderPhase::Migration => "migration",
            RenderPhase::Serving => "serving",
        };
        let mut rendered = fs::read(
            root.join(RENDERED_DIR)
                .join(format!("{profile}-{phase_name}.yaml")),
        )?;
        rendered.extend_from_slice(b"---\n");
        rendered.extend_from_slice(&fs::read(
            root.join(EXTENSIONS_DIR)
                .join(format!("{profile}-{phase_name}.yaml")),
        )?);
        let documents = serde_yaml_ng::Deserializer::from_slice(&rendered)
            .map(Value::deserialize)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok((plan, documents))
    }

    fn validate_values(
        documents: &[Value],
        plan: &DeploymentPlan,
        phase: RenderPhase,
    ) -> Result<()> {
        let mut rendered = Vec::new();
        for document in documents {
            rendered.extend_from_slice(b"---\n");
            rendered.extend_from_slice(serde_yaml_ng::to_string(document)?.as_bytes());
        }
        let profile = plan
            .workloads()
            .first()
            .context("test plan workload missing")?
            .name();
        validate_rendered_phase(&rendered, plan, profile, phase)
    }

    fn remove_first_kind(documents: &mut Vec<Value>, kind: &str) {
        let index = documents
            .iter()
            .position(|document| document.pointer("/kind").and_then(Value::as_str) == Some(kind))
            .unwrap_or_else(|| panic!("mutation kind must exist: {kind}"));
        documents.remove(index);
    }

    fn first_kind_mut<'a>(documents: &'a mut [Value], kind: &str) -> &'a mut Value {
        documents
            .iter_mut()
            .find(|document| document.pointer("/kind").and_then(Value::as_str) == Some(kind))
            .unwrap_or_else(|| panic!("mutation kind must exist: {kind}"))
    }

    fn remove_field(document: &mut Value, parent: &str, field: &str) {
        document
            .pointer_mut(parent)
            .and_then(Value::as_object_mut)
            .unwrap_or_else(|| panic!("mutation parent must exist: {parent}"))
            .remove(field)
            .unwrap_or_else(|| panic!("mutation field must exist: {field}"));
    }

    fn current_profile_modes() -> Vec<(String, MigrationMode)> {
        ["identityaudit", "runtime", "settingsonly"]
            .into_iter()
            .map(|profile| (profile.to_owned(), MigrationMode::ForwardOnlyTwoPhase))
            .collect()
    }

    #[test]
    fn committed_schema_digests_are_exact() -> Result<()> {
        validate_schema_digests(&crate::workspace_root()?)
    }

    #[test]
    fn committed_schema_inventory_is_exact() -> Result<()> {
        validate_schema_tree(&crate::workspace_root()?)
    }

    #[test]
    fn schema_digest_rejects_mutation() {
        assert!(validate_digest(b"mutated", SCHEMAS[0].1).is_err());
    }

    #[test]
    fn secret_environment_boundary_rejects_values_and_accepts_only_file_references() -> Result<()> {
        let raw = serde_json::json!({"env": [{"name": "RSS_DATABASE_PASSWORD", "value": "bait"}]});
        assert!(reject_plain_secret_environment(&raw, "synthetic").is_err());
        let file = serde_json::json!({
            "env": [{
                "name": "RSS_DATABASE_PASSWORD_FILE",
                "value": "/var/run/rss/secrets/database-password"
            }]
        });
        reject_plain_secret_environment(&file, "synthetic")
    }

    #[test]
    fn semantic_mutation_suite_is_nonempty_exact_and_every_case_fails_closed() -> Result<()> {
        ensure!(
            SEMANTIC_MUTATIONS.len() == 21
                && SEMANTIC_MUTATIONS.iter().collect::<BTreeSet<_>>().len() == 21,
            "semantic mutation inventory must be exact and non-empty"
        );

        let (serving_plan, serving) = repository_case("runtime", RenderPhase::Serving)?;
        validate_values(&serving, &serving_plan, RenderPhase::Serving)?;
        for kind in [
            "ServiceAccount",
            "SecretProviderClass",
            "NetworkPolicy",
            "PodDisruptionBudget",
            "HorizontalPodAutoscaler",
            "ServiceMonitor",
        ] {
            let mut mutated = serving.clone();
            remove_first_kind(&mut mutated, kind);
            assert!(
                validate_values(&mutated, &serving_plan, RenderPhase::Serving).is_err(),
                "removing {kind} must fail closed"
            );
        }

        let mut mutated = serving.clone();
        remove_field(
            first_kind_mut(&mut mutated, "Deployment"),
            "/spec/template/spec",
            "terminationGracePeriodSeconds",
        );
        assert!(validate_values(&mutated, &serving_plan, RenderPhase::Serving).is_err());

        let mut mutated = serving.clone();
        first_kind_mut(&mut mutated, "Service")["spec"]["selector"]["app.kubernetes.io/component"] =
            Value::String("wrong-workload".to_owned());
        assert!(validate_values(&mutated, &serving_plan, RenderPhase::Serving).is_err());

        let mut mutated = serving.clone();
        first_kind_mut(&mut mutated, "Service")["spec"]["ports"][0]["targetPort"] =
            Value::String("missing-listener".to_owned());
        assert!(validate_values(&mutated, &serving_plan, RenderPhase::Serving).is_err());

        let mut mutated = serving.clone();
        remove_field(
            first_kind_mut(&mut mutated, "Deployment"),
            "/spec/template/spec/containers/0",
            "ports",
        );
        assert!(validate_values(&mutated, &serving_plan, RenderPhase::Serving).is_err());

        let mut mutated = serving.clone();
        remove_field(
            first_kind_mut(&mut mutated, "Deployment"),
            "/spec/template/spec/containers/0",
            "env",
        );
        assert!(validate_values(&mutated, &serving_plan, RenderPhase::Serving).is_err());

        let mut mutated = serving.clone();
        let pool = named_entry_mut(
            first_kind_mut(&mut mutated, "Deployment"),
            "/spec/template/spec/containers/0/env",
            "RSS_PG_DLX_ARCHIVER_MAX_CONNECTIONS",
        )
        .context("runtime pool ceiling environment missing")?;
        pool["value"] = Value::String("9".to_owned());
        assert!(validate_values(&mutated, &serving_plan, RenderPhase::Serving).is_err());

        let mut mutated = serving.clone();
        let names = mutated
            .iter()
            .filter(|document| {
                document.pointer("/kind").and_then(Value::as_str) == Some("NetworkPolicy")
            })
            .filter_map(|document| {
                document
                    .pointer("/metadata/name")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .collect::<Vec<_>>();
        ensure!(names.len() >= 2, "resource identity mutation is vacuous");
        let second = mutated
            .iter_mut()
            .filter(|document| {
                document.pointer("/kind").and_then(Value::as_str) == Some("NetworkPolicy")
            })
            .nth(1)
            .context("second NetworkPolicy missing")?;
        second["metadata"]["name"] = Value::String(names[0].clone());
        assert!(validate_values(&mutated, &serving_plan, RenderPhase::Serving).is_err());

        let (migration_plan, migration) = repository_case("runtime", RenderPhase::Migration)?;
        validate_values(&migration, &migration_plan, RenderPhase::Migration)?;
        let mut mutated = migration.clone();
        remove_first_kind(&mut mutated, "Job");
        assert!(validate_values(&mutated, &migration_plan, RenderPhase::Migration).is_err());

        let mut mutated = migration.clone();
        remove_field(
            first_kind_mut(&mut mutated, "Job"),
            "/spec/template/spec/containers/0",
            "env",
        );
        assert!(validate_values(&mutated, &migration_plan, RenderPhase::Migration).is_err());

        let mut mutated = migration.clone();
        remove_field(
            first_kind_mut(&mut mutated, "Job"),
            "/spec/template/spec/containers/0",
            "resources",
        );
        assert!(validate_values(&mutated, &migration_plan, RenderPhase::Migration).is_err());

        let mut mutated = migration;
        first_kind_mut(&mut mutated, "Job")["metadata"]["name"] =
            Value::String("rss-runtime-migration-wrong-head".to_owned());
        assert!(validate_values(&mutated, &migration_plan, RenderPhase::Migration).is_err());

        let (settings_plan, settings) = repository_case("settingsonly", RenderPhase::Serving)?;
        validate_values(&settings, &settings_plan, RenderPhase::Serving)?;
        let mut mutated = settings.clone();
        remove_field(
            first_kind_mut(&mut mutated, "Deployment"),
            "/spec/template/spec/containers/0",
            "args",
        );
        assert!(validate_values(&mutated, &settings_plan, RenderPhase::Serving).is_err());

        let mut mutated = settings;
        let deployment = first_kind_mut(&mut mutated, "Deployment");
        let volumes = deployment
            .pointer_mut("/spec/template/spec/volumes")
            .and_then(Value::as_array_mut)
            .context("Deployment volumes missing")?;
        volumes.retain(|volume| {
            volume.pointer("/name").and_then(Value::as_str) != Some("public-trust")
        });
        assert!(validate_values(&mutated, &settings_plan, RenderPhase::Serving).is_err());

        let mut mutated = repository_case("settingsonly", RenderPhase::Serving)?.1;
        let environment = first_kind_mut(&mut mutated, "Deployment")
            .pointer_mut("/spec/template/spec/containers/0/env")
            .and_then(Value::as_array_mut)
            .context("Deployment environment missing")?;
        let primary_port = environment
            .iter_mut()
            .find(|entry| {
                entry.pointer("/name").and_then(Value::as_str)
                    == Some("RSS_DEPLOYMENT_PRIMARY_PORT")
            })
            .context("primary port environment missing")?;
        primary_port["value"] = Value::String("9999".to_owned());
        assert!(validate_values(&mutated, &settings_plan, RenderPhase::Serving).is_err());

        let mut mutated = repository_case("settingsonly", RenderPhase::Serving)?.1;
        let deployment = first_kind_mut(&mut mutated, "Deployment");
        let vault = deployment
            .pointer_mut("/spec/template/spec/volumes")
            .and_then(Value::as_array_mut)
            .and_then(|volumes| {
                volumes.iter_mut().find(|volume| {
                    volume.pointer("/name").and_then(Value::as_str) == Some("vault-secrets")
                })
            })
            .context("Vault volume missing")?;
        vault["csi"]["volumeAttributes"]["secretProviderClass"] =
            Value::String("wrong-workload-secrets".to_owned());
        assert!(validate_values(&mutated, &settings_plan, RenderPhase::Serving).is_err());
        Ok(())
    }

    #[test]
    fn phase_gvk_closure_rejects_an_extra_legal_resource() -> Result<()> {
        let (plan, mut documents) = repository_case("runtime", RenderPhase::Serving)?;
        documents.push(serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {"name": "unexpected"},
            "rules": []
        }));
        assert!(validate_values(&documents, &plan, RenderPhase::Serving).is_err());
        Ok(())
    }

    #[test]
    fn serving_projection_rejects_image_and_resource_drift() -> Result<()> {
        let (plan, documents) = repository_case("runtime", RenderPhase::Serving)?;
        let mut image = documents.clone();
        first_kind_mut(&mut image, "Deployment")["spec"]["template"]["spec"]["containers"][0]
            ["image"] = Value::String(
            "ghcr.io/gocell/rss-runtime@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
        );
        assert!(validate_values(&image, &plan, RenderPhase::Serving).is_err());

        let mut resources = documents;
        first_kind_mut(&mut resources, "Deployment")["spec"]["template"]["spec"]["containers"][0]
            ["resources"]["limits"]["cpu"] = Value::String("99".to_owned());
        assert!(validate_values(&resources, &plan, RenderPhase::Serving).is_err());
        Ok(())
    }

    #[test]
    fn serving_projection_rejects_probe_drift() -> Result<()> {
        let (plan, mut documents) = repository_case("runtime", RenderPhase::Serving)?;
        first_kind_mut(&mut documents, "Deployment")["spec"]["template"]["spec"]["containers"][0]
            ["readinessProbe"]["httpGet"]["path"] = Value::String("/wrong-ready-path".to_owned());
        assert!(validate_values(&documents, &plan, RenderPhase::Serving).is_err());
        Ok(())
    }

    #[test]
    fn migration_projection_rejects_artifact_budget_and_attempt_drift() -> Result<()> {
        let (plan, documents) = repository_case("runtime", RenderPhase::Migration)?;

        let mut artifact = documents.clone();
        first_kind_mut(&mut artifact, "Job")["spec"]["template"]["spec"]["containers"][0]
            ["image"] = Value::String(
            "ghcr.io/gocell/rss-operator@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
        );
        assert!(validate_values(&artifact, &plan, RenderPhase::Migration).is_err());

        let mut deadline = documents.clone();
        first_kind_mut(&mut deadline, "Job")["spec"]["activeDeadlineSeconds"] = Value::from(1);
        assert!(validate_values(&deadline, &plan, RenderPhase::Migration).is_err());

        let mut backoff = documents.clone();
        first_kind_mut(&mut backoff, "Job")["spec"]["backoffLimit"] = Value::from(1);
        assert!(validate_values(&backoff, &plan, RenderPhase::Migration).is_err());

        let mut attempt = documents;
        first_kind_mut(&mut attempt, "Job")["metadata"]["name"] =
            Value::String("rss-runtime-migration-r2-wrong".to_owned());
        assert!(validate_values(&attempt, &plan, RenderPhase::Migration).is_err());
        Ok(())
    }

    #[test]
    fn hpa_projection_rejects_replica_budget_drift() -> Result<()> {
        let (plan, mut documents) = repository_case("runtime", RenderPhase::Serving)?;
        first_kind_mut(&mut documents, "HorizontalPodAutoscaler")["spec"]["minReplicas"] =
            Value::from(1);
        assert!(validate_values(&documents, &plan, RenderPhase::Serving).is_err());
        Ok(())
    }

    #[test]
    fn secret_projection_rejects_vault_coordinate_drift() -> Result<()> {
        let (plan, documents) = repository_case("runtime", RenderPhase::Serving)?;
        let mut address = documents.clone();
        first_kind_mut(&mut address, "SecretProviderClass")["spec"]["parameters"]["vaultAddress"] =
            Value::String("https://wrong.vault.svc:8200".to_owned());
        assert!(validate_values(&address, &plan, RenderPhase::Serving).is_err());

        let mut path = documents;
        let spc = first_kind_mut(&mut path, "SecretProviderClass");
        let objects = spc["spec"]["parameters"]["objects"]
            .as_str()
            .context("SecretProviderClass objects missing")?
            .replacen("runtime/database-url", "wrong/database-url", 1);
        spc["spec"]["parameters"]["objects"] = Value::String(objects);
        assert!(validate_values(&path, &plan, RenderPhase::Serving).is_err());
        Ok(())
    }

    #[test]
    fn rendered_inventory_is_six_core_and_six_extensions() {
        let profiles = current_profile_modes();
        let core = rendered_paths(&profiles, false);
        let extensions = rendered_paths(&profiles, true);
        assert_eq!(core.len(), 6);
        assert_eq!(extensions.len(), 6);
        assert_eq!(core.iter().collect::<BTreeSet<_>>().len(), 6);
        assert_eq!(extensions.iter().collect::<BTreeSet<_>>().len(), 6);
    }

    #[test]
    fn none_mode_has_a_serving_only_exact_rendered_closure() {
        let profiles = vec![
            ("no-fence".to_owned(), MigrationMode::None),
            ("fenced".to_owned(), MigrationMode::ForwardOnlyTwoPhase),
        ];
        assert_eq!(
            rendered_paths(&profiles, false),
            vec![
                "deploy/rendered/no-fence-serving.yaml",
                "deploy/rendered/fenced-migration.yaml",
                "deploy/rendered/fenced-serving.yaml",
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn rendered_tree_rejects_missing_extra_and_symlink() -> Result<()> {
        use std::os::unix::fs::symlink;

        let root = crate::testutil::unique_tmp("deployment-policy-tree");
        fs::create_dir_all(root.join(EXTENSIONS_DIR))?;
        let profiles = current_profile_modes();
        let core = rendered_paths(&profiles, false);
        let extensions = rendered_paths(&profiles, true);
        for relative in core.iter().cloned().chain(extensions.iter().cloned()) {
            fs::write(root.join(relative), b"apiVersion: v1\n")?;
        }
        validate_rendered_tree(&root, &core, &extensions)?;

        let missing = root.join(core[0].as_str());
        fs::remove_file(&missing)?;
        assert!(validate_rendered_tree(&root, &core, &extensions).is_err());
        fs::write(&missing, b"apiVersion: v1\n")?;

        fs::write(root.join(RENDERED_DIR).join("extra.yaml"), b"x\n")?;
        assert!(validate_rendered_tree(&root, &core, &extensions).is_err());
        fs::remove_file(root.join(RENDERED_DIR).join("extra.yaml"))?;

        let target = root.join("target.yaml");
        fs::write(&target, b"x\n")?;
        fs::remove_file(&missing)?;
        symlink(&target, &missing)?;
        assert!(validate_rendered_tree(&root, &core, &extensions).is_err());
        Ok(())
    }

    #[test]
    fn kubeconform_arguments_are_strict_pinned_and_never_ignore_missing() {
        let core = kubeconform_args("deploy/rendered/runtime-serving.yaml", false);
        let extension = kubeconform_args("deploy/rendered/extensions/runtime-serving.yaml", true);
        assert!(core.contains(&"-strict"));
        assert!(
            core.windows(2)
                .any(|pair| pair == ["-kubernetes-version", "1.30.0"])
        );
        assert!(!core.iter().any(|arg| arg.contains("ignore-missing")));
        assert!(!core.iter().any(|arg| arg.contains("://")));
        assert!(!core.contains(&"default"));
        assert!(core.contains(&CORE_SCHEMA_LOCATION_TEMPLATE));
        assert!(core.contains(&SCHEMA_LOCATION_TEMPLATE));
        assert!(extension.contains(&CORE_SCHEMA_LOCATION_TEMPLATE));
        assert!(extension.contains(&SCHEMA_LOCATION_TEMPLATE));
        assert!(!extension.contains(&"default"));
        assert!(!extension.iter().any(|arg| arg.contains("ignore-missing")));
        assert!(!extension.iter().any(|arg| arg.contains("://")));
    }
}
