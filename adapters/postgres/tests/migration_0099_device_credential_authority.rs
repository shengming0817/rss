const MIGRATION: &str = include_str!("../migrations/0099_separate_device_credential_authority.sql");
const HISTORICAL_MIGRATION: &str = include_str!("../migrations/0094_close_device_ingress_uow.sql");

#[path = "support/migration_contract.rs"]
mod migration_contract;

use migration_contract::{RoutineContract, RoutineHeaderContract, RoutineIdentity, normalize_sql};

fn ack_identity() -> RoutineIdentity<'static> {
    RoutineIdentity::public(
        "rss_commit_device_command_ack_ingress",
        &[
            "uuid", "uuid", "text", "text", "bigint", "bigint", "bigint", "bytea", "text",
            "bigint", "boolean",
        ],
    )
}

fn report_identity() -> RoutineIdentity<'static> {
    RoutineIdentity::public(
        "rss_commit_device_certificate_report_ingress",
        &[
            "uuid", "uuid", "text", "bigint", "bigint", "bigint", "bytea", "bytea", "bytea",
            "bigint", "bigint", "bigint", "boolean",
        ],
    )
}

fn assert_exact_received_report_authority(sql: &str) -> Result<(), String> {
    for identity in [
        RoutineIdentity::public("rss_device_command_guard", &[]),
        RoutineIdentity::public("rss_device_certificate_reported_guard", &[]),
    ] {
        RoutineHeaderContract {
            identity,
            required: &["LANGUAGE plpgsql", "SET search_path = pg_catalog, pg_temp"],
            forbidden: &["SECURITY DEFINER"],
        }
        .check(sql)?;
    }
    RoutineContract {
        identity: RoutineIdentity::public("rss_device_command_guard", &[]),
        required: &[
            "retains_received_report_authority := OLD.state = 'received' AND NEW.state = 'applied'",
            "(NEW.tenant_id, NEW.command_id, NEW.device_id, NEW.generation, NEW.fence_epoch, NEW.intent_digest, NEW.deadline, NEW.queued_at) IS NOT DISTINCT FROM (OLD.tenant_id, OLD.command_id, OLD.device_id, OLD.generation, OLD.fence_epoch, OLD.intent_digest, OLD.deadline, OLD.queued_at)",
            "NEW.generation <> authority_generation",
            "NEW.fence_epoch <> authority_epoch AND NOT retains_received_report_authority",
        ],
        forbidden: &[
            "NEW.generation <> authority_generation OR NEW.fence_epoch <> authority_epoch",
        ],
        ordered: &[],
    }
    .check(sql)?;

    RoutineContract {
        identity: RoutineIdentity::public("rss_device_certificate_reported_guard", &[]),
        required: &[
            "NEW.observed_generation <> authority_generation",
            "command.tenant_id = NEW.tenant_id",
            "command.device_id = NEW.device_id",
            "command.generation = NEW.observed_generation",
            "command.fence_epoch = NEW.fence_epoch",
            "command.state = 'received'",
        ],
        forbidden: &[
            "NEW.observed_generation <> authority_generation OR NEW.fence_epoch <> authority_epoch",
        ],
        ordered: &[],
    }
    .check(sql)?;

    Ok(())
}

fn remove_fragment_after(sql: &str, marker: &str, fragment: &str) -> Result<String, String> {
    let routine_start = sql
        .find(marker)
        .ok_or_else(|| format!("missing synthetic routine marker `{marker}`"))?;
    let relative = sql[routine_start..]
        .find(fragment)
        .ok_or_else(|| format!("missing synthetic fragment `{fragment}` after `{marker}`"))?;
    let start = routine_start + relative;
    let mut mutated = sql.to_owned();
    mutated.replace_range(start..start + fragment.len(), "TRUE");
    Ok(mutated)
}

#[test]
fn migration_preserves_only_exact_received_report_authority() -> Result<(), String> {
    assert_exact_received_report_authority(MIGRATION)?;

    let sql = normalize_sql(MIGRATION);
    for signature in [
        "public.rss_device_command_guard()",
        "public.rss_device_certificate_reported_guard()",
    ] {
        assert!(
            sql.contains(&format!(
                "REVOKE ALL ON FUNCTION {signature} FROM PUBLIC,rss_app,rss_app_read"
            )),
            "0099 must retain the fail-closed trigger ACL for `{signature}`"
        );
        assert!(
            !sql.contains(&format!("GRANT EXECUTE ON FUNCTION {signature}")),
            "0099 trigger `{signature}` must not gain an EXECUTE grant"
        );
    }
    Ok(())
}

#[test]
fn authority_contract_rejects_each_missing_identity_binding() -> Result<(), String> {
    for (marker, fragment) in [
        (
            "CREATE OR REPLACE FUNCTION public.rss_device_command_guard()",
            "NEW.generation <> authority_generation",
        ),
        (
            "CREATE OR REPLACE FUNCTION public.rss_device_certificate_reported_guard()",
            "command.tenant_id = NEW.tenant_id",
        ),
        (
            "CREATE OR REPLACE FUNCTION public.rss_device_certificate_reported_guard()",
            "command.device_id = NEW.device_id",
        ),
    ] {
        let mutated = remove_fragment_after(MIGRATION, marker, fragment)?;
        let Err(error) = assert_exact_received_report_authority(&mutated) else {
            return Err(format!(
                "authority contract accepted removal of `{fragment}`"
            ));
        };
        assert!(
            error.contains("public.rss_device_command_guard()")
                || error.contains("public.rss_device_certificate_reported_guard()"),
            "failure must name the exact guard: {error}"
        );
    }

    let tuple = "(\n                NEW.tenant_id, NEW.command_id, NEW.device_id, NEW.generation,\n                NEW.fence_epoch, NEW.intent_digest, NEW.deadline, NEW.queued_at\n            ) IS NOT DISTINCT FROM (\n                OLD.tenant_id, OLD.command_id, OLD.device_id, OLD.generation,\n                OLD.fence_epoch, OLD.intent_digest, OLD.deadline, OLD.queued_at\n            )";
    let mutated = MIGRATION.replacen(tuple, "TRUE", 1);
    let Err(error) = assert_exact_received_report_authority(&mutated) else {
        return Err("authority contract accepted removal of the command identity tuple".to_owned());
    };
    assert!(error.contains("public.rss_device_command_guard()"));
    Ok(())
}

#[test]
fn migration_separates_transport_credential_from_certificate_authority() -> Result<(), String> {
    let common_required = [
        "p_credential_generation IS NULL OR p_credential_generation<=0",
        "p_scope_matches IS NOT TRUE",
    ];
    for identity in [ack_identity(), report_identity()] {
        RoutineHeaderContract {
            identity,
            required: &[
                "LANGUAGE plpgsql",
                "SECURITY DEFINER",
                "SET search_path=pg_catalog,pg_temp",
            ],
            forbidden: &[],
        }
        .check(MIGRATION)?;
    }
    RoutineContract {
        identity: ack_identity(),
        required: &[
            common_required[0],
            common_required[1],
            "p_fence_epoch<authority_epoch THEN 'stale_fence'",
        ],
        forbidden: &[
            "p_credential_generation IS DISTINCT FROM authority_generation",
            "command_state IS DISTINCT FROM 'received'",
        ],
        ordered: &[],
    }
    .check(MIGRATION)?;
    RoutineContract {
        identity: report_identity(),
        required: &[
            common_required[0],
            common_required[1],
            "p_fence_epoch<authority_epoch AND command_state IS DISTINCT FROM 'received' THEN 'stale_fence'",
        ],
        forbidden: &[
            "p_credential_generation IS DISTINCT FROM authority_generation",
            "p_fence_epoch<authority_epoch THEN 'stale_fence'",
        ],
        ordered: &[],
    }
    .check(MIGRATION)?;

    let sql = normalize_sql(MIGRATION);
    let ack_signature = "public.rss_commit_device_command_ack_ingress(uuid,uuid,text,text,bigint,bigint,bigint,bytea,text,bigint,boolean)";
    let report_signature = "public.rss_commit_device_certificate_report_ingress(uuid,uuid,text,bigint,bigint,bigint,bytea,bytea,bytea,bigint,bigint,bigint,boolean)";
    for signature in [ack_signature, report_signature] {
        assert!(
            sql.contains(&format!(
                "ALTER FUNCTION {signature} OWNER TO rss_device_command_funnel_owner"
            )),
            "0099 must retain the reviewed owner for `{signature}`"
        );
    }
    assert!(
        sql.contains(&format!(
            "REVOKE ALL ON FUNCTION {ack_signature}, {report_signature} FROM PUBLIC,rss_app_read"
        )),
        "0099 must close both ingress funnels before granting the writer capability"
    );
    assert!(
        sql.contains(&format!(
            "GRANT EXECUTE ON FUNCTION {ack_signature}, {report_signature} TO rss_app"
        )),
        "0099 must grant both ingress funnels only to rss_app"
    );
    for signature in [ack_signature, report_signature] {
        let grants = sql
            .split(';')
            .filter(|statement| {
                statement.contains("GRANT EXECUTE ON FUNCTION") && statement.contains(signature)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            grants.len(),
            1,
            "0099 must have one identity-scoped EXECUTE grant for `{signature}`"
        );
        assert!(grants[0].trim_end().ends_with("TO rss_app"));
    }
    Ok(())
}

#[test]
fn correction_is_forward_only_and_preserves_historical_checksum_input() -> Result<(), String> {
    for identity in [ack_identity(), report_identity()] {
        RoutineContract {
            identity,
            required: &["p_credential_generation IS DISTINCT FROM authority_generation"],
            forbidden: &[],
            ordered: &[],
        }
        .check(HISTORICAL_MIGRATION)?;
    }

    assert!(!MIGRATION.contains("DROP FUNCTION"));
    assert!(!MIGRATION.contains("CREATE FUNCTION public.rss_commit_"));
    Ok(())
}
