const MIGRATION: &str = include_str!("../migrations/0094_close_device_ingress_uow.sql");
const COMMAND_ADAPTER: &str = include_str!("../src/device_command.rs");
const CERTIFICATE_PORT: &str =
    include_str!("../../../crates/identity/src/device_certificate/port.rs");

#[path = "support/migration_contract.rs"]
mod migration_contract;

use migration_contract::{RoutineContract, RoutineHeaderContract, RoutineIdentity, normalize_sql};

const ACK_SIGNATURE: &str = "public.rss_commit_device_command_ack_ingress(uuid,uuid,text,text,bigint,bigint,bigint,bytea,text,bigint,boolean)";
const REPORT_SIGNATURE: &str = "public.rss_commit_device_certificate_report_ingress(uuid,uuid,text,bigint,bigint,bigint,bytea,bytea,bytea,bigint,bigint,bigint,boolean)";

fn assert_funnel_posture(
    sql: &str,
    identity: RoutineIdentity<'_>,
    signature: &str,
) -> Result<(), String> {
    RoutineHeaderContract {
        identity,
        required: &[
            "LANGUAGE plpgsql",
            "SECURITY DEFINER",
            "SET search_path=pg_catalog,pg_temp",
        ],
        forbidden: &[],
    }
    .check(sql)?;

    let normalized = normalize_sql(sql);
    assert!(
        normalized.contains(&format!(
            "ALTER FUNCTION {signature} OWNER TO rss_device_command_funnel_owner"
        )),
        "missing exact owner for `{signature}`"
    );
    for (verb, closure) in [
        ("REVOKE ALL ON FUNCTION", "FROM PUBLIC,rss_app_read"),
        ("GRANT EXECUTE ON FUNCTION", "TO rss_app"),
    ] {
        let statements = normalized
            .split(';')
            .filter(|statement| statement.contains(verb) && statement.contains(signature))
            .collect::<Vec<_>>();
        assert_eq!(
            statements.len(),
            1,
            "`{signature}` must have one identity-scoped `{verb}` statement"
        );
        assert!(
            statements[0].contains(closure),
            "`{signature}` has capability closure drift in `{verb}`"
        );
    }
    Ok(())
}

#[test]
fn migration_closes_legacy_ingress_writers_and_installs_only_two_funnels() -> Result<(), String> {
    let normalized = MIGRATION.split_whitespace().collect::<Vec<_>>().join(" ");
    for required in [
        "DROP FUNCTION public.rss_apply_device_command_ack(uuid,uuid,text,bigint,bigint,text)",
        "DROP FUNCTION public.rss_upsert_device_certificate_report( uuid,uuid,bigint,bigint,bytea,bytea,text,bigint,bigint,bigint )",
        "CREATE FUNCTION public.rss_commit_device_command_ack_ingress",
        "CREATE FUNCTION public.rss_commit_device_certificate_report_ingress",
        "SECURITY DEFINER",
        "OWNER TO rss_device_command_funnel_owner",
        "REVOKE INSERT,UPDATE,DELETE ON public.device_ingress_receipts",
        "public.device_certificate_reported_states,public.device_commands,public.device_certificate_conditions FROM rss_app",
        "pg_advisory_xact_lock",
        "device ingress fact conflict",
        "p_credential_generation bigint",
        "p_scope_matches IS NOT TRUE",
        "p_scope_matches IS NULL",
        "p_credential_generation IS DISTINCT FROM authority_generation",
        "CREATE INDEX device_ingress_receipts_high_water_idx ON public.device_ingress_receipts (tenant_id,device_id,generation,fence_epoch,device_sequence DESC) WHERE disposition IN ('advanced','device_rejected')",
    ] {
        assert!(
            normalized.contains(required),
            "missing hard-cut carrier: {required}"
        );
    }
    for identity in [
        RoutineIdentity::public(
            "rss_commit_device_command_ack_ingress",
            &[
                "uuid", "uuid", "text", "text", "bigint", "bigint", "bigint", "bytea", "text",
                "bigint", "boolean",
            ],
        ),
        RoutineIdentity::public(
            "rss_commit_device_certificate_report_ingress",
            &[
                "uuid", "uuid", "text", "bigint", "bigint", "bigint", "bytea", "bytea", "bytea",
                "bigint", "bigint", "bigint", "boolean",
            ],
        ),
    ] {
        RoutineContract {
            identity,
            required: &[
                "p_credential_generation bigint",
                "p_scope_matches IS NOT TRUE",
                "p_scope_matches IS NULL",
                "p_credential_generation IS DISTINCT FROM authority_generation",
            ],
            forbidden: &[],
            ordered: &[],
        }
        .check(MIGRATION)?;
    }
    assert_funnel_posture(
        MIGRATION,
        RoutineIdentity::public(
            "rss_commit_device_command_ack_ingress",
            &[
                "uuid", "uuid", "text", "text", "bigint", "bigint", "bigint", "bytea", "text",
                "bigint", "boolean",
            ],
        ),
        ACK_SIGNATURE,
    )?;
    assert_funnel_posture(
        MIGRATION,
        RoutineIdentity::public(
            "rss_commit_device_certificate_report_ingress",
            &[
                "uuid", "uuid", "text", "bigint", "bigint", "bigint", "bytea", "bytea", "bytea",
                "bigint", "bigint", "bigint", "boolean",
            ],
        ),
        REPORT_SIGNATURE,
    )?;
    Ok(())
}

#[test]
fn each_ingress_funnel_owns_its_security_posture() -> Result<(), String> {
    let mutated = MIGRATION.replacen("LANGUAGE plpgsql SECURITY DEFINER", "LANGUAGE plpgsql", 1);
    let result = assert_funnel_posture(
        &mutated,
        RoutineIdentity::public(
            "rss_commit_device_command_ack_ingress",
            &[
                "uuid", "uuid", "text", "text", "bigint", "bigint", "bigint", "bytea", "text",
                "bigint", "boolean",
            ],
        ),
        ACK_SIGNATURE,
    );
    let Err(error) = result else {
        return Err("the report funnel masked ACK SECURITY DEFINER drift".to_owned());
    };
    assert!(error.contains("public.rss_commit_device_command_ack_ingress"));
    Ok(())
}

#[test]
fn ingress_outbox_lowering_has_one_canonical_owner() {
    const IDENTITY_TX: &str = include_str!("../src/cotx/identity.rs");

    assert!(IDENTITY_TX.contains("struct CanonicalDeviceIngressFact"));
    assert!(IDENTITY_TX.contains("fn from_reviewed_event"));
    assert!(IDENTITY_TX.contains("CanonicalOutboxFact::from_entry_env"));
    assert!(!COMMAND_ADAPTER.contains("CanonicalOutboxFact::from_entry_env"));
}

#[test]
fn rust_surface_has_no_independent_reported_writer_or_legacy_sql_call() {
    assert!(!CERTIFICATE_PORT.contains("advance_reported"));
    assert!(!COMMAND_ADAPTER.contains("FROM public.rss_apply_device_command_ack("));
    assert!(!COMMAND_ADAPTER.contains("FROM public.rss_upsert_device_certificate_report("));
    assert!(COMMAND_ADAPTER.contains("rss_commit_device_command_ack_ingress"));
    assert!(COMMAND_ADAPTER.contains("rss_commit_device_certificate_report_ingress"));
}
