#![allow(clippy::expect_used)]
// reason: inventory artifact fixture tests assert exact assembly source/plan shape via expect.

use anyhow::Context as _;
use generated::http::runtime_v1::inventory as wire;
use serde_json::Value;

#[test]
fn runtime_inventory_journey_constructs_the_production_launch_adapter() {
    let source = include_str!("../../assemblies/runtime/src/launch.rs");
    let journey = source
        .split_once("pub(crate) async fn serve_inventory_journey")
        .expect("runtime inventory journey entrypoint")
        .1
        .split_once("trait ListenerRegistrar")
        .expect("runtime inventory journey boundary")
        .0;

    assert!(
        journey.contains("let adapter = RuntimeLaunchAdapter::new("),
        "runtime inventory journey must construct the production RuntimeLaunchAdapter"
    );
    assert!(
        !source.contains("struct InventoryJourneyAdapter"),
        "runtime inventory journey must not define a parallel launch adapter"
    );
}

#[test]
fn runtime_inventory_artifacts_bind_all_three_assemblies() {
    for (name, runtime_bytes, lock_bytes, manifest) in [
        (
            "runtime",
            include_bytes!("../../assemblies/runtime/runtime-plan.json").as_slice(),
            include_bytes!("../../assemblies/runtime/assembly.lock.json").as_slice(),
            include_str!("../../assemblies/runtime/assembly.toml"),
        ),
        (
            "settingsonly",
            include_bytes!("../../assemblies/settingsonly/runtime-plan.json").as_slice(),
            include_bytes!("../../assemblies/settingsonly/assembly.lock.json").as_slice(),
            include_str!("../../assemblies/settingsonly/assembly.toml"),
        ),
        (
            "identityaudit",
            include_bytes!("../../assemblies/identityaudit/runtime-plan.json").as_slice(),
            include_bytes!("../../assemblies/identityaudit/assembly.lock.json").as_slice(),
            include_str!("../../assemblies/identityaudit/assembly.toml"),
        ),
    ] {
        let runtime: Value = serde_json::from_slice(runtime_bytes).expect("RuntimePlan JSON");
        let lock: Value = serde_json::from_slice(lock_bytes).expect("assembly.lock.json");
        assert_eq!(
            lock["fingerprint"].as_str(),
            runtime["assemblyFingerprint"].as_str(),
            "{name} lock fingerprint must match runtime-plan assemblyFingerprint"
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
        let listener_pdp_plans: Vec<&Value> = runtime["providerPlans"]
            .as_array()
            .expect("provider plans")
            .iter()
            .filter(|provider| provider["id"] == "listener-pdp")
            .collect();
        assert_eq!(
            listener_pdp_plans.len(),
            1,
            "{name} must bind exactly one listener-pdp providerPlan"
        );
        let outputs = listener_pdp_plans[0]["outputs"]
            .as_array()
            .expect("listener-pdp outputs")
            .iter()
            .map(|output| output.as_str().expect("listener-pdp output worker name"))
            .collect::<Vec<_>>();
        assert_eq!(
            outputs,
            vec!["probes", "resources"],
            "{name} listener-pdp outputs must be exactly probes then resources"
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
) -> anyhow::Result<()> {
    let expected_runtime: Value = serde_json::from_slice(runtime_plan)?;
    let expected_assembly = expected_runtime["assemblyFingerprint"]
        .as_str()
        .context("RuntimePlan assembly fingerprint")?;
    let expected_runtime_fingerprint = expected_runtime["runtimePlanFingerprint"]
        .as_str()
        .context("RuntimePlan fingerprint")?;
    assert_eq!(status, reqwest::StatusCode::OK, "{name} inventory route");
    assert!(audit_calls > 0, "{name} allow must record audit evidence");
    let response: wire::RuntimeInventoryResponse = serde_json::from_slice(body)?;
    let data = response.data;
    assert_eq!(data.schema_version, 1, "{name} schema version");
    assert_eq!(data.assembly_fingerprint.as_str(), expected_assembly);
    let build_metadata = data
        .build_metadata
        .as_ref()
        .context("runtime inventory build metadata")?;
    assert_eq!(build_metadata.source_revision.as_str(), "a".repeat(40));
    assert_eq!(
        build_metadata.image_digest.as_str(),
        format!("sha256:{}", "b".repeat(64))
    );
    assert_eq!(
        data.runtime_plan_fingerprint.as_str(),
        expected_runtime_fingerprint
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
    let listener_pdp = data
        .provider_posture
        .iter()
        .find(|provider| provider.id.as_str() == "listener-pdp")
        .context("listener-pdp provider posture")?;
    assert_eq!(
        listener_pdp.state,
        wire::RuntimeProviderPostureState::Ready,
        "{name} healthy listener-pdp receipt must be ready"
    );
    assert!(data.provider_posture.iter().all(|provider| {
        provider.id.as_str() == "listener-pdp"
            || provider.state == wire::RuntimeProviderPostureState::Unobserved
    }));
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
    ($test:ident, $module:path, $runtime:literal) => {
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
    let listener_pdp = response
        .data
        .provider_posture
        .iter()
        .find(|provider| provider.id.as_str() == "listener-pdp")
        .context("listener-pdp provider posture")?;
    assert_eq!(
        listener_pdp.state, expected,
        "{name} did not expose {expected:?} through the listener-pdp receipt"
    );
    assert!(
        response.data.provider_posture.iter().all(|provider| {
            provider.id.as_str() == "listener-pdp"
                || provider.state == wire::RuntimeProviderPostureState::Unobserved
        }),
        "{name} leaked listener-pdp readiness into another provider posture"
    );
    Ok(())
}

inventory_journey!(
    runtime_inventory_live_journey,
    runtime::test_support::runtime_inventory,
    "../../assemblies/runtime/runtime-plan.json"
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
    "../../assemblies/settingsonly/runtime-plan.json"
);
inventory_journey!(
    identityaudit_inventory_live_journey,
    identityaudit::runtime_inventory_test_support,
    "../../assemblies/identityaudit/runtime-plan.json"
);
