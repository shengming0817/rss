use std::future::ready;

use testkit::device_command_conformance::{
    DeviceCommandCasCase, DeviceCommandCasObservation, DeviceCommandConformanceError,
    DeviceCommandCreateCase, DeviceCommandCreateObservation, DeviceIngressConformanceCase,
    DeviceIngressConformanceObservation, assert_device_command_cas, assert_device_command_create,
    assert_device_command_restart_equivalence, assert_device_ingress_conformance,
};

#[tokio::test]
async fn provider_neutral_device_command_contract_is_composable()
-> Result<(), DeviceCommandConformanceError> {
    let create = DeviceCommandCreateCase {
        first_input: "first",
        replay_input: "replay",
        identity_conflict_input: "identity-conflict",
        active_conflict_input: "active-conflict",
        expected_snapshot: "queued-v1",
        expected_active_command_id: "command-1",
        create: |input| {
            ready(Ok::<_, &'static str>(match input {
                "first" => DeviceCommandCreateObservation::Created("queued-v1"),
                "replay" => DeviceCommandCreateObservation::Replay("queued-v1"),
                "identity-conflict" => DeviceCommandCreateObservation::IdentityConflict,
                "active-conflict" => DeviceCommandCreateObservation::ActiveConflict {
                    command_id: "command-1",
                },
                _ => unreachable!("closed synthetic fixture"),
            }))
        },
    };
    assert_device_command_create(create).await?;

    let reloaded = assert_device_command_restart_equivalence("command-1", "queued-v1", |_| {
        ready(Ok::<_, &'static str>(Some("queued-v1")))
    })
    .await?;
    assert_eq!(reloaded, "queued-v1");

    let cas = DeviceCommandCasCase {
        contender_a_input: "winner",
        contender_b_input: "loser",
        stale_input: "stale",
        no_change_input: "no-change",
        missing_input: "missing",
        expected_actual_version: 2_u64,
        transition: |input| {
            ready(Ok::<_, &'static str>(match input {
                "winner" => DeviceCommandCasObservation::Advanced("published-v2"),
                "loser" | "stale" => DeviceCommandCasObservation::VersionConflict { actual: 2 },
                "no-change" => DeviceCommandCasObservation::NoChange,
                "missing" => DeviceCommandCasObservation::Missing,
                _ => unreachable!("closed synthetic fixture"),
            }))
        },
        load: || ready(Ok::<_, &'static str>(Some("published-v2"))),
        load_missing: || ready(Ok::<_, &'static str>(None)),
    };
    assert_eq!(assert_device_command_cas(cas).await?, "published-v2");
    Ok(())
}

#[tokio::test]
async fn provider_neutral_ingress_contract_proves_replay_conflict_and_tenant_isolation()
-> Result<(), DeviceCommandConformanceError> {
    let case = DeviceIngressConformanceCase {
        tenant_a: "tenant-a",
        tenant_b: "tenant-b",
        event_id: "event-1",
        first_input: "first",
        replay_input: "replay",
        conflict_input: "conflict",
        tenant_b_input: "tenant-b-first",
        append: |tenant, input| {
            ready(Ok::<_, &'static str>(match (tenant, input) {
                ("tenant-a", "first") => DeviceIngressConformanceObservation::Appended(10),
                ("tenant-a", "replay") => DeviceIngressConformanceObservation::Replay(10),
                ("tenant-a", "conflict") => DeviceIngressConformanceObservation::Conflict,
                ("tenant-b", "tenant-b-first") => DeviceIngressConformanceObservation::Appended(20),
                _ => unreachable!("closed synthetic fixture"),
            }))
        },
        load: |tenant, _event_id| {
            ready(Ok::<_, &'static str>(match tenant {
                "tenant-a" => Some(10),
                "tenant-b" => Some(20),
                _ => None,
            }))
        },
    };

    assert_device_ingress_conformance(case).await
}

#[tokio::test]
async fn create_contract_rejects_a_provider_that_reinserts_an_exact_replay() {
    let case = DeviceCommandCreateCase {
        first_input: true,
        replay_input: false,
        identity_conflict_input: false,
        active_conflict_input: false,
        expected_snapshot: 1_u8,
        expected_active_command_id: 7_u8,
        create: |first| {
            ready(Ok::<_, &'static str>(DeviceCommandCreateObservation::<
                u8,
                u8,
            >::Created(u8::from(
                first,
            ))))
        },
    };

    assert!(matches!(
        assert_device_command_create(case).await,
        Err(DeviceCommandConformanceError::UnexpectedOutcome {
            stage: "exact create replay",
            ..
        })
    ));
}

#[tokio::test]
async fn cas_contract_rejects_a_stale_attempt_that_changes_durable_state() {
    let mut load_count = 0_u8;
    let case = DeviceCommandCasCase {
        contender_a_input: "winner",
        contender_b_input: "loser",
        stale_input: "stale",
        no_change_input: "no-change",
        missing_input: "missing",
        expected_actual_version: 2_u64,
        transition: |input| {
            ready(Ok::<_, &'static str>(match input {
                "winner" => DeviceCommandCasObservation::Advanced("published-v2"),
                "loser" | "stale" => DeviceCommandCasObservation::VersionConflict { actual: 2 },
                "no-change" => DeviceCommandCasObservation::NoChange,
                "missing" => DeviceCommandCasObservation::Missing,
                _ => unreachable!("closed synthetic fixture"),
            }))
        },
        load: move || {
            load_count += 1;
            ready(Ok::<_, &'static str>(Some(if load_count == 1 {
                "published-v2"
            } else {
                "corrupt-v3"
            })))
        },
        load_missing: || ready(Ok::<_, &'static str>(None)),
    };

    assert!(matches!(
        assert_device_command_cas(case).await,
        Err(DeviceCommandConformanceError::ValueMismatch {
            stage: "stale CAS zero-write",
            ..
        })
    ));
}

#[tokio::test]
async fn cas_contract_rejects_missing_substituted_for_no_change() {
    let case = DeviceCommandCasCase {
        contender_a_input: "winner",
        contender_b_input: "loser",
        stale_input: "stale",
        no_change_input: "no-change",
        missing_input: "missing",
        expected_actual_version: 2_u64,
        transition: |input| {
            ready(Ok::<_, &'static str>(match input {
                "winner" => DeviceCommandCasObservation::Advanced("published-v2"),
                "loser" | "stale" => DeviceCommandCasObservation::VersionConflict { actual: 2 },
                "no-change" => DeviceCommandCasObservation::Missing,
                "missing" => DeviceCommandCasObservation::NoChange,
                _ => unreachable!("closed synthetic fixture"),
            }))
        },
        load: || ready(Ok::<_, &'static str>(Some("published-v2"))),
        load_missing: || ready(Ok::<_, &'static str>(None)),
    };

    assert!(matches!(
        assert_device_command_cas(case).await,
        Err(DeviceCommandConformanceError::UnexpectedOutcome {
            stage: "semantic no-change",
            ..
        })
    ));
}

#[tokio::test]
async fn cas_contract_rejects_no_change_substituted_for_missing() {
    let case = DeviceCommandCasCase {
        contender_a_input: "winner",
        contender_b_input: "loser",
        stale_input: "stale",
        no_change_input: "no-change",
        missing_input: "missing",
        expected_actual_version: 2_u64,
        transition: |input| {
            ready(Ok::<_, &'static str>(match input {
                "winner" => DeviceCommandCasObservation::Advanced("published-v2"),
                "loser" | "stale" => DeviceCommandCasObservation::VersionConflict { actual: 2 },
                "no-change" | "missing" => DeviceCommandCasObservation::NoChange,
                _ => unreachable!("closed synthetic fixture"),
            }))
        },
        load: || ready(Ok::<_, &'static str>(Some("published-v2"))),
        load_missing: || ready(Ok::<_, &'static str>(None)),
    };

    assert!(matches!(
        assert_device_command_cas(case).await,
        Err(DeviceCommandConformanceError::UnexpectedOutcome {
            stage: "missing CAS",
            ..
        })
    ));
}

#[tokio::test]
async fn cas_contract_rejects_a_no_change_that_changes_durable_state() {
    let mut load_count = 0_u8;
    let case = DeviceCommandCasCase {
        contender_a_input: "winner",
        contender_b_input: "loser",
        stale_input: "stale",
        no_change_input: "no-change",
        missing_input: "missing",
        expected_actual_version: 2_u64,
        transition: |input| {
            ready(Ok::<_, &'static str>(match input {
                "winner" => DeviceCommandCasObservation::Advanced("published-v2"),
                "loser" | "stale" => DeviceCommandCasObservation::VersionConflict { actual: 2 },
                "no-change" => DeviceCommandCasObservation::NoChange,
                "missing" => DeviceCommandCasObservation::Missing,
                _ => unreachable!("closed synthetic fixture"),
            }))
        },
        load: move || {
            load_count += 1;
            ready(Ok::<_, &'static str>(Some(if load_count < 3 {
                "published-v2"
            } else {
                "corrupt-v3"
            })))
        },
        load_missing: || ready(Ok::<_, &'static str>(None)),
    };

    assert!(matches!(
        assert_device_command_cas(case).await,
        Err(DeviceCommandConformanceError::ValueMismatch {
            stage: "semantic no-change zero-write",
            ..
        })
    ));
}

#[tokio::test]
async fn cas_contract_rejects_a_missing_result_that_changes_durable_state() {
    let case = DeviceCommandCasCase {
        contender_a_input: "winner",
        contender_b_input: "loser",
        stale_input: "stale",
        no_change_input: "no-change",
        missing_input: "missing",
        expected_actual_version: 2_u64,
        transition: |input| {
            ready(Ok::<_, &'static str>(match input {
                "winner" => DeviceCommandCasObservation::Advanced("published-v2"),
                "loser" | "stale" => DeviceCommandCasObservation::VersionConflict { actual: 2 },
                "no-change" => DeviceCommandCasObservation::NoChange,
                "missing" => DeviceCommandCasObservation::Missing,
                _ => unreachable!("closed synthetic fixture"),
            }))
        },
        load: || ready(Ok::<_, &'static str>(Some("published-v2"))),
        load_missing: || ready(Ok::<_, &'static str>(Some("illegally-created-v1"))),
    };

    assert!(matches!(
        assert_device_command_cas(case).await,
        Err(DeviceCommandConformanceError::ValueMismatch {
            stage: "missing CAS zero-write",
            ..
        })
    ));
}

#[tokio::test]
async fn ingress_contract_rejects_cross_tenant_receipt_aliasing() {
    let case = DeviceIngressConformanceCase {
        tenant_a: "tenant-a",
        tenant_b: "tenant-b",
        event_id: "event-1",
        first_input: "first",
        replay_input: "replay",
        conflict_input: "conflict",
        tenant_b_input: "tenant-b-first",
        append: |tenant, input| {
            ready(Ok::<_, &'static str>(match (tenant, input) {
                ("tenant-a", "first") | ("tenant-b", "tenant-b-first") => {
                    DeviceIngressConformanceObservation::Appended(10)
                }
                ("tenant-a", "replay") => DeviceIngressConformanceObservation::Replay(10),
                _ => DeviceIngressConformanceObservation::Conflict,
            }))
        },
        load: |_tenant, _event_id| ready(Ok::<_, &'static str>(Some(10))),
    };

    assert!(matches!(
        assert_device_ingress_conformance(case).await,
        Err(DeviceCommandConformanceError::TenantIsolationViolation)
    ));
}
