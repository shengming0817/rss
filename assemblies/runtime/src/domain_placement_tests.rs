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
fn remote_domains_are_removed_from_local_listener_projection() {
    let snapshot = profile_snapshot(&[
        ("RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD", "peer-cell"),
        ("RSS_TOPOLOGY", "durable-shared"),
        ("RSS_DOMAIN_TRANSPORT_URL", "https://gateway.internal/rpc"),
    ]);
    let placed = RuntimePlan::bundled(snapshot.view())
        .expect("bundled plan")
        .place(bootstrap::Topology::DurableShared, snapshot.view())
        .expect("remote placement projection")
        .into_parts();
    assert!(
        placed
            .listeners
            .declared_listeners()
            .iter()
            .any(|listener| listener.domains().contains(&AssemblyDomain::Identity))
    );
    assert!(
        placed
            .listeners
            .listeners()
            .iter()
            .all(|listener| !listener.domains().contains(&AssemblyDomain::Identity))
    );
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

#[tokio::test]
#[allow(clippy::expect_used)]
async fn generated_domain_factories_execute_exact_local_projection_for_all_subsets() {
    let domains = crate::modules_gen::ASSEMBLY_DOMAINS;
    for remote_mask in 0_u8..(1_u8 << domains.len()) {
        let mut entries = vec![
            ("RSS_TOPOLOGY", "durable-shared"),
            ("RSS_DOMAIN_TRANSPORT_URL", "https://gateway.internal/rpc"),
        ];
        for (index, domain) in domains.iter().enumerate() {
            if remote_mask & (1 << index) != 0 {
                entries.push((
                    match domain {
                        AssemblyDomain::Settings => "RSS_SETTINGS_DOMAIN_PLACEMENT_WORKLOAD",
                        AssemblyDomain::Identity => "RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD",
                        AssemblyDomain::Audit => "RSS_AUDIT_DOMAIN_PLACEMENT_WORKLOAD",
                        other => panic!("unexpected bundled domain {other:?}"),
                    },
                    "peer-cell",
                ));
            }
        }
        let snapshot = profile_snapshot(&entries);
        let parts = RuntimePlan::bundled(snapshot.view())
            .expect("bundled plan")
            .place(bootstrap::Topology::DurableShared, snapshot.view())
            .expect("placed runtime")
            .into_parts();
        let expected = parts
            .domain
            .local_domains()
            .iter()
            .map(AssemblyDomain::as_str)
            .collect::<Vec<_>>();
        let bindings = crate::modules_gen::wire_test_domains(&parts.domain)
            .await
            .expect("generated local factories");
        assert_eq!(
            bindings
                .iter()
                .map(bootstrap::DomainBinding::name)
                .collect::<Vec<_>>(),
            expected,
            "mask={remote_mask}"
        );
    }
}

#[test]
fn placement_projection_closes_domains_listeners_providers_and_events_for_all_subsets() {
    let domains = crate::modules_gen::ASSEMBLY_DOMAINS;
    for remote_mask in 0_u8..(1_u8 << domains.len()) {
        let mut entries = vec![
            ("RSS_TOPOLOGY", "durable-shared"),
            ("RSS_DOMAIN_TRANSPORT_URL", "https://gateway.internal/rpc"),
        ];
        for (index, domain) in domains.iter().enumerate() {
            if remote_mask & (1 << index) != 0 {
                let key = match domain {
                    AssemblyDomain::Settings => "RSS_SETTINGS_DOMAIN_PLACEMENT_WORKLOAD",
                    AssemblyDomain::Identity => "RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD",
                    AssemblyDomain::Audit => "RSS_AUDIT_DOMAIN_PLACEMENT_WORKLOAD",
                    other => panic!("unexpected bundled domain {other:?}"),
                };
                entries.push((key, "peer-cell"));
            }
        }
        let snapshot = profile_snapshot(&entries);
        let parts = RuntimePlan::bundled(snapshot.view())
            .expect("bundled plan")
            .place(bootstrap::Topology::DurableShared, snapshot.view())
            .expect("placed runtime")
            .into_parts();
        let local = domains
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(index, domain)| (remote_mask & (1 << index) == 0).then_some(domain))
            .collect::<Vec<_>>();
        assert_eq!(
            parts.domain.local_domains(),
            local.as_slice(),
            "mask={remote_mask}"
        );
        assert!(parts.listeners.listeners().iter().all(|listener| {
            listener
                .domains()
                .iter()
                .all(|domain| local.contains(domain))
        }));

        let event_active = local.iter().any(|domain| {
            matches!(
                domain,
                AssemblyDomain::Settings | AssemblyDomain::Identity | AssemblyDomain::Audit
            )
        });
        assert_eq!(parts.events.is_active(), event_active, "mask={remote_mask}");
        let (_, provider_specs, _) = parts.providers.into_parts();
        let actual_ids = provider_specs
            .iter()
            .map(|spec| spec.id())
            .collect::<Vec<_>>();
        let expected_ids = crate::providers_gen::PROVIDER_CATALOG
            .iter()
            .filter(|entry| match entry.activation() {
                assembly_schema::ProviderActivation::Process => true,
                assembly_schema::ProviderActivation::DomainLocal(domain) => local.contains(&domain),
                assembly_schema::ProviderActivation::LocalEventExecution => event_active,
            })
            .map(|entry| entry.role().as_str())
            .collect::<Vec<_>>();
        assert_eq!(actual_ids, expected_ids, "mask={remote_mask}");
        for spec in provider_specs {
            match spec.activation() {
                assembly_schema::ProviderActivation::Process => {}
                assembly_schema::ProviderActivation::DomainLocal(domain) => {
                    assert!(
                        local.contains(&domain),
                        "mask={remote_mask} role={}",
                        spec.id()
                    );
                }
                assembly_schema::ProviderActivation::LocalEventExecution => {
                    assert!(event_active, "mask={remote_mask} role={}", spec.id());
                }
            }
        }
    }
}
