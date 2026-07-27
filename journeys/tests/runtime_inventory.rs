use anyhow::Context as _;
use generated::http::runtime_v1::inventory as wire;
use serde_json::Value;

#[test]
fn runtime_inventory_artifacts_bind_all_three_assemblies() {
    for (name, runtime_bytes, deployment_bytes, manifest) in [
        (
            "runtime",
            include_bytes!("../../assemblies/runtime/runtime-plan.json").as_slice(),
            include_bytes!("../../deploy/generated/runtime.deployment-plan.json").as_slice(),
            include_str!("../../assemblies/runtime/assembly.toml"),
        ),
        (
            "settingsonly",
            include_bytes!("../../assemblies/settingsonly/runtime-plan.json").as_slice(),
            include_bytes!("../../deploy/generated/settingsonly.deployment-plan.json").as_slice(),
            include_str!("../../assemblies/settingsonly/assembly.toml"),
        ),
        (
            "identityaudit",
            include_bytes!("../../assemblies/identityaudit/runtime-plan.json").as_slice(),
            include_bytes!("../../deploy/generated/identityaudit.deployment-plan.json").as_slice(),
            include_str!("../../assemblies/identityaudit/assembly.toml"),
        ),
    ] {
        let runtime: Value = serde_json::from_slice(runtime_bytes).expect("RuntimePlan JSON");
        let deployment: Value =
            serde_json::from_slice(deployment_bytes).expect("DeploymentPlan JSON");
        assert_eq!(
            runtime["assemblyFingerprint"], deployment["assemblyFingerprint"],
            "{name} assembly fingerprint"
        );
        assert_eq!(
            runtime["runtimePlanFingerprint"], deployment["runtimePlanFingerprint"],
            "{name} runtime fingerprint"
        );
        assert!(
            runtime["listenerPlans"]
                .as_array()
                .expect("listeners")
                .iter()
                .any(|listener| listener["kind"] == "admin"),
            "{name} must bind Admin"
        );
        assert!(
            runtime["placementPlans"]
                .as_array()
                .expect("placements")
                .iter()
                .all(|placement| placement["workload"].as_str().is_some()),
            "{name} placements must name workloads"
        );
        let manifest: toml::Value = toml::from_str(manifest).expect("assembly manifest");
        assert_eq!(
            manifest["frameworkContracts"][0]["id"].as_str(),
            Some("runtime.inventory")
        );
        assert_eq!(
            manifest["frameworkContracts"][0]["listener"].as_str(),
            Some("admin")
        );
    }
}

fn assert_allow(
    name: &str,
    status: reqwest::StatusCode,
    body: &[u8],
    serving_address: std::net::SocketAddr,
    audit_calls: usize,
    runtime_plan: &[u8],
    deployment_plan: &[u8],
) -> anyhow::Result<()> {
    let expected_runtime: Value = serde_json::from_slice(runtime_plan)?;
    let expected_deployment: Value = serde_json::from_slice(deployment_plan)?;
    let expected_assembly = expected_runtime["assemblyFingerprint"]
        .as_str()
        .context("RuntimePlan assembly fingerprint")?;
    let expected_runtime_fingerprint = expected_runtime["runtimePlanFingerprint"]
        .as_str()
        .context("RuntimePlan fingerprint")?;
    let expected_deployment_fingerprint = expected_deployment["deploymentFingerprint"]
        .as_str()
        .context("DeploymentPlan fingerprint")?;
    assert_eq!(status, reqwest::StatusCode::OK, "{name} inventory route");
    assert!(audit_calls > 0, "{name} allow must record audit evidence");
    let response: wire::RuntimeInventoryResponse = serde_json::from_slice(body)?;
    let data = response.data;
    assert_eq!(data.schema_version, 1, "{name} schema version");
    assert_eq!(data.assembly_fingerprint.as_str(), expected_assembly);
    assert_eq!(
        data.runtime_plan_fingerprint.as_str(),
        expected_runtime_fingerprint
    );
    assert_eq!(
        data.deployment_fingerprint.as_str(),
        expected_deployment_fingerprint
    );
    assert_eq!(
        data.domains.len(),
        expected_runtime["domainPlans"]
            .as_array()
            .context("domain plans")?
            .len()
    );
    assert_eq!(
        data.provider_posture.len(),
        expected_runtime["providerPlans"]
            .as_array()
            .context("provider plans")?
            .len()
    );
    assert!(
        data.provider_posture
            .iter()
            .all(|provider| provider.state == wire::RuntimeProviderPostureState::Ready)
    );
    assert_eq!(
        data.placements.len(),
        expected_runtime["placementPlans"]
            .as_array()
            .context("placement plans")?
            .len()
    );
    assert!(
        data.placements
            .iter()
            .all(|placement| !placement.workload.as_str().is_empty())
    );
    let admin = data
        .listeners
        .iter()
        .find(|listener| listener.kind == wire::RuntimeListenerKind::Admin)
        .context("Admin listener inventory")?;
    assert_eq!(
        admin.endpoint.host.as_str(),
        serving_address.ip().to_string()
    );
    assert_eq!(admin.endpoint.port.get(), u64::from(serving_address.port()));
    Ok(())
}

macro_rules! inventory_journey {
    ($test:ident, $module:path, $runtime:literal, $deployment:literal) => {
        async fn $test() -> anyhow::Result<()> {
            use $module as fixture;

            let allow = fixture::run_journey(fixture::JourneyCase::Allow).await?;
            assert_allow(
                stringify!($test),
                allow.status,
                &allow.body,
                allow.serving_address,
                allow.audit_calls,
                include_bytes!($runtime),
                include_bytes!($deployment),
            )?;

            let degraded = fixture::run_journey(fixture::JourneyCase::ProbeDegraded).await?;
            assert_provider_posture(
                stringify!($test),
                degraded.status,
                &degraded.body,
                wire::RuntimeProviderPostureState::Degraded,
            )?;

            let unavailable = fixture::run_journey(fixture::JourneyCase::ProbeUnavailable).await?;
            assert_provider_posture(
                stringify!($test),
                unavailable.status,
                &unavailable.body,
                wire::RuntimeProviderPostureState::Unavailable,
            )?;

            let deny = fixture::run_journey(fixture::JourneyCase::Deny).await?;
            assert_eq!(deny.status, reqwest::StatusCode::FORBIDDEN);
            assert!(deny.audit_calls > 0, "deny must record audit evidence");

            let audit_fail = fixture::run_journey(fixture::JourneyCase::AuditFail).await?;
            assert_eq!(
                audit_fail.status,
                reqwest::StatusCode::INTERNAL_SERVER_ERROR
            );
            assert!(
                audit_fail.audit_calls > 0,
                "audit failure must reach audit sink"
            );
            Ok(())
        }
    };
}

fn assert_provider_posture(
    name: &str,
    status: reqwest::StatusCode,
    body: &[u8],
    expected: wire::RuntimeProviderPostureState,
) -> anyhow::Result<()> {
    assert_eq!(status, reqwest::StatusCode::OK, "{name} probe journey");
    let response: wire::RuntimeInventoryResponse = serde_json::from_slice(body)?;
    assert!(
        response
            .data
            .provider_posture
            .iter()
            .any(|provider| provider.state == expected),
        "{name} did not expose {expected:?} through the production probe chain"
    );
    Ok(())
}

inventory_journey!(
    runtime_inventory_live_journey,
    runtime::test_support::runtime_inventory,
    "../../assemblies/runtime/runtime-plan.json",
    "../../deploy/generated/runtime.deployment-plan.json"
);

#[tokio::test]
async fn runtime_inventory_live_journeys_are_port_exact_and_serial() -> anyhow::Result<()> {
    runtime_inventory_live_journey().await?;
    settingsonly_inventory_live_journey().await?;
    identityaudit_inventory_live_journey().await?;
    Ok(())
}
inventory_journey!(
    settingsonly_inventory_live_journey,
    settingsonly::runtime_inventory_test_support,
    "../../assemblies/settingsonly/runtime-plan.json",
    "../../deploy/generated/settingsonly.deployment-plan.json"
);
inventory_journey!(
    identityaudit_inventory_live_journey,
    identityaudit::runtime_inventory_test_support,
    "../../assemblies/identityaudit/runtime-plan.json",
    "../../deploy/generated/identityaudit.deployment-plan.json"
);
