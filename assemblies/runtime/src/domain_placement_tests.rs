//! RTD-014 domain placement execution matrix.

#![allow(clippy::expect_used, clippy::panic)]
// reason: placement matrix assertions use expect/panic for exact local fail-closed diagnostics.

use crate::config::test_snapshot;
use crate::plan::RuntimePlan;
use assembly_schema::AssemblyDomain;
use std::collections::BTreeMap;

fn profile_snapshot(entries: &[(&str, &str)]) -> crate::config::RuntimeConfigSnapshot {
    let mut merged = BTreeMap::from([
        ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
        ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
        ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
    ]);
    merged.extend(entries.iter().copied());
    let merged = merged.into_iter().collect::<Vec<_>>();
    test_snapshot(&merged).expect("test snapshot")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedPlacement {
    Local,
    Remote,
}

fn modes(
    plan: &crate::plan::PlacementExecutionPlan,
) -> Vec<(AssemblyDomain, ExpectedPlacement, String)> {
    plan.placements()
        .iter()
        .map(|spec| {
            (
                spec.domain(),
                if spec.is_local() {
                    ExpectedPlacement::Local
                } else {
                    ExpectedPlacement::Remote
                },
                spec.workload().to_owned(),
            )
        })
        .collect()
}

fn domain_spec(
    plan: &crate::plan::PlacementExecutionPlan,
    domain: AssemblyDomain,
) -> &crate::plan::PlacementExecutionSpec {
    plan.placements()
        .iter()
        .find(|spec| spec.domain() == domain)
        .unwrap_or_else(|| panic!("{domain:?} placement"))
}

#[test]
fn domain_placement_all_local_default_uses_runtime_workload() {
    let snapshot = profile_snapshot(&[]);
    let runtime_plan = RuntimePlan::bundled(snapshot.view()).expect("bundled plan");
    let placement = runtime_plan
        .placement_execution_plan(bootstrap::Topology::Demo, snapshot.view())
        .expect("local placement plan");
    assert_eq!(runtime_plan.assembly_identity(), "runtime");
    assert_eq!(
        modes(&placement),
        vec![
            (
                AssemblyDomain::Audit,
                ExpectedPlacement::Local,
                "runtime".into()
            ),
            (
                AssemblyDomain::Identity,
                ExpectedPlacement::Local,
                "runtime".into()
            ),
            (
                AssemblyDomain::Settings,
                ExpectedPlacement::Local,
                "runtime".into()
            ),
        ]
    );
    assert!(placement.remote_domains().next().is_none());
}

#[test]
fn domain_placement_remote_matrix_via_peer_cell_workload() {
    let cases = [
        (
            "RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD",
            AssemblyDomain::Identity,
            vec![AssemblyDomain::Identity],
            vec![
                (
                    AssemblyDomain::Audit,
                    ExpectedPlacement::Local,
                    "runtime".into(),
                ),
                (
                    AssemblyDomain::Identity,
                    ExpectedPlacement::Remote,
                    "peer-cell".into(),
                ),
                (
                    AssemblyDomain::Settings,
                    ExpectedPlacement::Local,
                    "runtime".into(),
                ),
            ],
        ),
        (
            "RSS_SETTINGS_DOMAIN_PLACEMENT_WORKLOAD",
            AssemblyDomain::Settings,
            vec![AssemblyDomain::Settings],
            vec![
                (
                    AssemblyDomain::Audit,
                    ExpectedPlacement::Local,
                    "runtime".into(),
                ),
                (
                    AssemblyDomain::Identity,
                    ExpectedPlacement::Local,
                    "runtime".into(),
                ),
                (
                    AssemblyDomain::Settings,
                    ExpectedPlacement::Remote,
                    "peer-cell".into(),
                ),
            ],
        ),
        (
            "RSS_AUDIT_DOMAIN_PLACEMENT_WORKLOAD",
            AssemblyDomain::Audit,
            vec![AssemblyDomain::Audit],
            vec![
                (
                    AssemblyDomain::Audit,
                    ExpectedPlacement::Remote,
                    "peer-cell".into(),
                ),
                (
                    AssemblyDomain::Identity,
                    ExpectedPlacement::Local,
                    "runtime".into(),
                ),
                (
                    AssemblyDomain::Settings,
                    ExpectedPlacement::Local,
                    "runtime".into(),
                ),
            ],
        ),
    ];
    let default = RuntimePlan::bundled(profile_snapshot(&[]).view()).expect("default plan");
    for (env, remote_domain, expected_remotes, expected_modes) in cases {
        let snapshot = profile_snapshot(&[
            (env, "peer-cell"),
            ("RSS_TOPOLOGY", "durable-shared"),
            ("RSS_DOMAIN_TRANSPORT_URL", "https://gateway.internal/rpc"),
        ]);
        let runtime_plan = RuntimePlan::bundled(snapshot.view()).expect("bundled plan");
        assert_ne!(
            runtime_plan.as_typed().runtime_plan_fingerprint().as_str(),
            default.as_typed().runtime_plan_fingerprint().as_str(),
            "placement workload is a non-secret fingerprint fact for {env}"
        );
        let placement = runtime_plan
            .placement_execution_plan(bootstrap::Topology::DurableShared, snapshot.view())
            .expect("remote placement plan");
        assert_eq!(modes(&placement), expected_modes, "modes for {env}");
        assert_eq!(
            placement.remote_domains().collect::<Vec<_>>(),
            expected_remotes,
            "remotes for {env}"
        );
        assert!(domain_spec(&placement, remote_domain).is_remote());
    }
}

#[test]
fn domain_placement_multi_remote_settings_and_audit() {
    let snapshot = profile_snapshot(&[
        ("RSS_SETTINGS_DOMAIN_PLACEMENT_WORKLOAD", "peer-cell"),
        ("RSS_AUDIT_DOMAIN_PLACEMENT_WORKLOAD", "peer-cell"),
        ("RSS_TOPOLOGY", "durable-shared"),
        ("RSS_DOMAIN_TRANSPORT_URL", "https://gateway.internal/rpc"),
    ]);
    let runtime_plan = RuntimePlan::bundled(snapshot.view()).expect("bundled plan");
    let placement = runtime_plan
        .placement_execution_plan(bootstrap::Topology::DurableShared, snapshot.view())
        .expect("remote placement plan");
    assert_eq!(
        modes(&placement),
        vec![
            (
                AssemblyDomain::Audit,
                ExpectedPlacement::Remote,
                "peer-cell".into()
            ),
            (
                AssemblyDomain::Identity,
                ExpectedPlacement::Local,
                "runtime".into()
            ),
            (
                AssemblyDomain::Settings,
                ExpectedPlacement::Remote,
                "peer-cell".into()
            ),
        ]
    );
    assert_eq!(
        placement.remote_domains().collect::<Vec<_>>(),
        vec![AssemblyDomain::Audit, AssemblyDomain::Settings]
    );
}

#[test]
fn domain_placement_rejects_non_kebab_workload() {
    let snapshot = profile_snapshot(&[("RSS_AUDIT_DOMAIN_PLACEMENT_WORKLOAD", "Peer_Cell")]);
    let error = RuntimePlan::bundled(snapshot.view()).expect_err("invalid workload must fail");
    assert!(
        error
            .to_string()
            .contains("RSS_AUDIT_DOMAIN_PLACEMENT_WORKLOAD")
    );
}

#[test]
fn domain_placement_rejects_empty_blank_and_spaced_workload() {
    let cases = [
        ("RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD", ""),
        ("RSS_SETTINGS_DOMAIN_PLACEMENT_WORKLOAD", "   "),
        ("RSS_AUDIT_DOMAIN_PLACEMENT_WORKLOAD", "peer cell"),
    ];
    for (env, raw) in cases {
        let snapshot = profile_snapshot(&[(env, raw)]);
        let error =
            RuntimePlan::bundled(snapshot.view()).expect_err(&format!("{env}={raw:?} must fail"));
        let rendered = error.to_string();
        assert!(
            rendered.contains(env),
            "error for {env}={raw:?} must name env; got {rendered}"
        );
    }
}

#[test]
fn domain_placement_remote_on_local_listener_fails_closed() {
    let snapshot = profile_snapshot(&[
        ("RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD", "peer-cell"),
        ("RSS_TOPOLOGY", "durable-shared"),
        ("RSS_DOMAIN_TRANSPORT_URL", "https://gateway.internal/rpc"),
    ]);
    let runtime_plan = RuntimePlan::bundled(snapshot.view()).expect("bundled plan");
    let listeners = runtime_plan.listener_execution_plan();
    let placement = runtime_plan
        .placement_execution_plan(bootstrap::Topology::DurableShared, snapshot.view())
        .expect("remote placement plan");
    let error = placement
        .reject_remote_on_local_listeners(&listeners)
        .expect_err("remote identity mounts on primary");
    let rendered = error.to_string();
    assert!(rendered.contains("identity"));
    assert!(rendered.contains("primary-main"));
    assert!(rendered.contains("RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD"));
}

#[test]
fn domain_placement_remote_endpoint_from_per_domain_url() {
    let snapshot = profile_snapshot(&[
        ("RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD", "peer-cell"),
        ("RSS_TOPOLOGY", "durable-isolated"),
        (
            "RSS_IDENTITY_DOMAIN_TRANSPORT_URL",
            "https://identity.internal:8443/rpc",
        ),
        (
            "RSS_DOMAIN_TRANSPORT_MTLS_LOCAL_SPIFFE_ID",
            "spiffe://example.org/ns/rss/sa/runtime",
        ),
    ]);
    let runtime_plan = RuntimePlan::bundled(snapshot.view()).expect("bundled plan");
    let placement = runtime_plan
        .placement_execution_plan(bootstrap::Topology::DurableIsolated, snapshot.view())
        .expect("remote placement plan");
    let identity = domain_spec(&placement, AssemblyDomain::Identity);
    assert!(identity.is_remote());
    let endpoint = identity.endpoint().expect("per-domain endpoint");
    assert_eq!(endpoint.as_url().scheme(), "https");
    assert_eq!(endpoint.host(), "identity.internal");
    assert_eq!(endpoint.port().get(), 8443);
    assert_eq!(endpoint.as_url().path(), "/rpc");
    assert_eq!(identity.spiffe_identity(), None);
    assert_eq!(
        identity.readiness(),
        Some(runtimeexec::inventory::InventoryPlacementReadiness::MtlsSourceUnavailable)
    );
}

#[test]
fn domain_placement_remote_endpoint_from_shared_url_on_durable_shared() {
    let snapshot = profile_snapshot(&[
        ("RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD", "peer-cell"),
        ("RSS_TOPOLOGY", "durable-shared"),
        ("RSS_DOMAIN_TRANSPORT_URL", "https://gateway.internal/rpc"),
    ]);
    let runtime_plan = RuntimePlan::bundled(snapshot.view()).expect("bundled plan");
    let placement = runtime_plan
        .placement_execution_plan(bootstrap::Topology::DurableShared, snapshot.view())
        .expect("remote placement plan");
    let identity = domain_spec(&placement, AssemblyDomain::Identity);
    let endpoint = identity.endpoint().expect("shared fallback endpoint");
    assert_eq!(endpoint.as_url().scheme(), "https");
    assert_eq!(endpoint.host(), "gateway.internal");
    assert_eq!(endpoint.port().get(), 443);
    assert_eq!(identity.spiffe_identity(), None);
    assert_eq!(
        identity.readiness(),
        Some(runtimeexec::inventory::InventoryPlacementReadiness::MtlsSourceUnavailable)
    );
}

#[test]
fn domain_placement_isolated_rejects_shared_endpoint() {
    let snapshot = profile_snapshot(&[
        ("RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD", "peer-cell"),
        ("RSS_TOPOLOGY", "durable-isolated"),
        ("RSS_DOMAIN_TRANSPORT_URL", "https://gateway.internal/rpc"),
    ]);
    let runtime_plan = RuntimePlan::bundled(snapshot.view()).expect("bundled plan");
    let error = runtime_plan
        .placement_execution_plan(bootstrap::Topology::DurableIsolated, snapshot.view())
        .err()
        .expect("isolated topology must reject shared endpoint");
    assert!(format!("{error:#}").contains("RSS_DOMAIN_TRANSPORT_URL"));
}

#[test]
fn domain_placement_fails_closed_on_invalid_endpoint_urls() {
    let cases = [
        "http://identity.internal/rpc",
        "https://user:pass@identity.internal/rpc",
        "https://identity.internal/rpc?token=secret",
        "https://identity.internal/rpc#frag",
    ];
    for raw in cases {
        let snapshot = profile_snapshot(&[
            ("RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD", "peer-cell"),
            ("RSS_TOPOLOGY", "durable-isolated"),
            ("RSS_IDENTITY_DOMAIN_TRANSPORT_URL", raw),
        ]);
        let runtime_plan = RuntimePlan::bundled(snapshot.view()).expect("bundled plan");
        let error = runtime_plan
            .placement_execution_plan(bootstrap::Topology::DurableIsolated, snapshot.view())
            .err()
            .expect("invalid remote endpoint must fail placement mint");
        assert!(
            error
                .to_string()
                .contains("RSS_IDENTITY_DOMAIN_TRANSPORT_URL"),
            "error must identify endpoint env for {raw:?}"
        );
        assert!(
            !error.to_string().contains(raw),
            "error must not expose endpoint value for {raw:?}"
        );
    }
}

#[test]
fn domain_placement_missing_endpoint_process_error_is_actionable() {
    let snapshot = profile_snapshot(&[
        ("RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD", "peer-cell"),
        ("RSS_TOPOLOGY", "durable-isolated"),
    ]);
    let runtime_plan = RuntimePlan::bundled(snapshot.view()).expect("bundled plan");
    let error = runtime_plan
        .placement_execution_plan(bootstrap::Topology::DurableIsolated, snapshot.view())
        .err()
        .expect("missing remote endpoint must fail placement mint");
    let process_line = crate::safe_process_error_line(&error);

    assert!(process_line.contains("RSS_IDENTITY_DOMAIN_TRANSPORT_URL"));
    assert!(process_line.contains("IDENTITY"));
    assert!(!process_line.contains("peer-cell"));
}

#[test]
fn domain_placement_demo_with_remote_fails_closed() {
    let snapshot = profile_snapshot(&[("RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD", "peer-cell")]);
    let runtime_plan = RuntimePlan::bundled(snapshot.view()).expect("bundled plan");
    let error = runtime_plan
        .placement_execution_plan(bootstrap::Topology::Demo, snapshot.view())
        .err()
        .expect("demo + remote must fail placement mint");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("demo topology does not support remote-placed domains"),
        "got {rendered}"
    );
    assert!(rendered.contains("IDENTITY"));
    assert!(
        !rendered.contains("require outbound transport targets"),
        "demo must not mislead toward URL remediation; got {rendered}"
    );
}

#[test]
fn domain_placement_all_local_demo_yields_inproc() {
    let snapshot = profile_snapshot(&[]);
    let runtime_plan = RuntimePlan::bundled(snapshot.view()).expect("bundled plan");
    let placement = runtime_plan
        .placement_execution_plan(bootstrap::Topology::Demo, snapshot.view())
        .expect("local placement plan");
    let config = crate::phase::test_support::DomainTransportConfig::from_placement(
        &placement,
        &crate::config::ServingConfigMapper::for_test(snapshot.view()),
    )
    .expect("all-local demo must be InProc");
    assert!(
        matches!(
            config,
            crate::phase::test_support::DomainTransportConfig::InProc
        ),
        "expected InProc for all-local demo"
    );
}

#[test]
fn domain_placement_transport_targets_bijection_with_remote_set() {
    let snapshot = profile_snapshot(&[
        ("RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD", "peer-cell"),
        ("RSS_TOPOLOGY", "durable-shared"),
        ("RSS_DOMAIN_TRANSPORT_URL", "https://gateway.internal/rpc"),
    ]);
    let runtime_plan = RuntimePlan::bundled(snapshot.view()).expect("bundled plan");
    let placement = runtime_plan
        .placement_execution_plan(bootstrap::Topology::DurableShared, snapshot.view())
        .expect("remote placement plan");
    let remotes = placement
        .remote_domains()
        .map(|domain| domain.as_str().to_ascii_uppercase())
        .collect::<Vec<_>>();
    assert_eq!(remotes, vec!["IDENTITY".to_owned()]);
    let targets =
        crate::phase::test_support::build_domain_transport_targets_from(&placement, |name| {
            match name {
                "RSS_DOMAIN_TRANSPORT_MTLS_LOCAL_SPIFFE_ID" => {
                    Some("spiffe://example.org/ns/rss/sa/runtime".to_owned())
                }
                "RSS_IDENTITY_DOMAIN_TRANSPORT_MTLS_SPIFFE_ALLOW_SET" => {
                    Some("spiffe://example.org/ns/rss/sa/identity".to_owned())
                }
                _ => None,
            }
        })
        .expect("remote targets");
    assert_eq!(targets.len(), 1);
}

#[test]
fn domain_placement_wire_domains_skips_remote_modules() {
    let placement = crate::plan::PlacementExecutionPlan::from_specs_for_test(vec![
        crate::plan::PlacementExecutionSpec::local_for_test(AssemblyDomain::Settings, "runtime"),
        crate::plan::PlacementExecutionSpec::remote_for_test(
            AssemblyDomain::Identity,
            "peer-cell",
            secure::DomainHttpEndpoint::parse("https://identity.internal/rpc")
                .expect("valid endpoint"),
        ),
        crate::plan::PlacementExecutionSpec::local_for_test(AssemblyDomain::Audit, "runtime"),
    ]);
    assert!(placement.is_local(AssemblyDomain::Settings));
    assert!(!placement.is_local(AssemblyDomain::Identity));
    assert!(placement.is_local(AssemblyDomain::Audit));
    let source = include_str!("generated/modules_gen.rs");
    assert!(source.contains("if placement.is_local(assembly_schema::AssemblyDomain::Identity)"));
    assert!(source.contains("let _ = identity;"));
}
