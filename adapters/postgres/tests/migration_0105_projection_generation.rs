const MIGRATION: &str =
    include_str!("../migrations/0105_advance_settings_projection_input_generation.sql");

#[path = "support/migration_contract.rs"]
mod migration_contract;

use migration_contract::{RoutineContract, RoutineHeaderContract, RoutineIdentity};

const OLD_GENERATION: &str =
    "sha256:ff7c69626735495640031695caf9c053830aa6efdcb8c3efa038d68d0cd25801";

#[test]
fn routine_contract_rejects_cross_function_and_comment_bait() -> Result<(), String> {
    let current = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let sql = format!(
        "CREATE FUNCTION public.target() RETURNS text AS $$ SELECT '{OLD_GENERATION}'; -- {current}\n $$ LANGUAGE sql;\n\
         CREATE FUNCTION public.neighbor() RETURNS text AS $$ SELECT '{current}' $$ LANGUAGE sql;\n\
         -- CREATE FUNCTION public.target() RETURNS text AS $$ SELECT '{current}' $$ LANGUAGE sql;"
    );
    let result = RoutineContract {
        identity: RoutineIdentity::public("target", &[]),
        required: &[current],
        forbidden: &[OLD_GENERATION],
        ordered: &[],
    }
    .check(&sql);
    let Err(error) = result else {
        return Err(
            "neighboring routine and comment bait satisfied the target contract".to_owned(),
        );
    };
    assert!(error.contains("public.target"));
    Ok(())
}

#[test]
fn routine_contract_accepts_reformatting_dollar_tags_and_reordering() -> Result<(), String> {
    let first = "CREATE OR REPLACE FUNCTION public.same (p_id uuid) RETURNS text AS $body$ SELECT 'uuid' $body$ LANGUAGE sql;";
    let second =
        "CREATE FUNCTION\npublic.same(p_id text) RETURNS text AS $$ SELECT 'text' $$ LANGUAGE sql;";
    let sql = format!("{first}\n{second}");
    RoutineContract {
        identity: RoutineIdentity::public("same", &["text"]),
        required: &["SELECT 'text'"],
        forbidden: &["SELECT 'uuid'"],
        ordered: &[],
    }
    .check(&sql)?;
    RoutineContract {
        identity: RoutineIdentity::public("same", &["uuid"]),
        required: &["SELECT 'uuid'"],
        forbidden: &["SELECT 'text'"],
        ordered: &[],
    }
    .check(&sql)
}

#[test]
fn routine_contract_distinguishes_schema_collision() -> Result<(), String> {
    let sql = "CREATE FUNCTION public.same(p_id uuid) RETURNS text AS $$ SELECT 'public' $$ LANGUAGE sql;\n\
               CREATE FUNCTION other.same(p_id uuid) RETURNS text AS $$ SELECT 'other' $$ LANGUAGE sql;";
    RoutineContract {
        identity: RoutineIdentity::public("same", &["uuid"]),
        required: &["SELECT 'public'"],
        forbidden: &["SELECT 'other'"],
        ordered: &[],
    }
    .check(sql)?;
    RoutineContract {
        identity: RoutineIdentity::named("other", "same", &["uuid"]),
        required: &["SELECT 'other'"],
        forbidden: &["SELECT 'public'"],
        ordered: &[],
    }
    .check(sql)
}

#[test]
fn routine_contract_fails_closed_on_missing_exact_identity() -> Result<(), String> {
    let sql =
        "CREATE FUNCTION public.target_extra() RETURNS text AS $$ SELECT 'pin' $$ LANGUAGE sql;";
    let result = RoutineContract {
        identity: RoutineIdentity::public("target", &[]),
        required: &["pin"],
        forbidden: &[],
        ordered: &[],
    }
    .check(sql);
    let Err(error) = result else {
        return Err("a prefix-related routine satisfied the exact target identity".to_owned());
    };
    assert!(error.contains("public.target"));
    Ok(())
}

#[test]
fn routine_contract_ignores_complete_commented_definition() -> Result<(), String> {
    let sql = "-- CREATE FUNCTION public.target() RETURNS text AS $$ SELECT 'pin' $$ LANGUAGE sql;";
    let result = RoutineContract {
        identity: RoutineIdentity::public("target", &[]),
        required: &["pin"],
        forbidden: &[],
        ordered: &[],
    }
    .check(sql);
    let Err(error) = result else {
        return Err("a complete commented definition satisfied the target identity".to_owned());
    };
    assert!(error.contains("public.target()"));
    Ok(())
}

#[test]
fn routine_contract_ignores_required_fragment_in_target_body_comment() -> Result<(), String> {
    let sql = "CREATE FUNCTION public.target() RETURNS text AS $$ SELECT 'neutral'; -- required-pin\n $$ LANGUAGE sql;";
    let result = RoutineContract {
        identity: RoutineIdentity::public("target", &[]),
        required: &["required-pin"],
        forbidden: &[],
        ordered: &[],
    }
    .check(sql);
    let Err(error) = result else {
        return Err("a target-body comment satisfied a required semantic fragment".to_owned());
    };
    assert!(error.contains("public.target()"));
    Ok(())
}

#[test]
fn routine_contract_does_not_borrow_a_neighbor_body_delimiter() -> Result<(), String> {
    let sql = "CREATE FUNCTION public.target() RETURNS text AS 'SELECT neutral' LANGUAGE sql;\n\
               CREATE FUNCTION public.neighbor() RETURNS text AS $$ SELECT required_pin $$ LANGUAGE sql;";
    let result = RoutineContract {
        identity: RoutineIdentity::public("target", &[]),
        required: &["required_pin"],
        forbidden: &[],
        ordered: &[],
    }
    .check(sql);
    let Err(error) = result else {
        return Err("a neighboring dollar body was borrowed by the target routine".to_owned());
    };
    assert!(error.contains("public.target()"));
    Ok(())
}

#[test]
fn routine_header_posture_ignores_quoted_body_bait() -> Result<(), String> {
    let sql = "CREATE FUNCTION public.target() RETURNS text AS $$ SELECT 'SECURITY DEFINER' $$ LANGUAGE sql;";
    let result = RoutineHeaderContract {
        identity: RoutineIdentity::public("target", &[]),
        required: &["SECURITY DEFINER"],
        forbidden: &[],
    }
    .check(sql);
    let Err(error) = result else {
        return Err("a quoted body literal satisfied header security posture".to_owned());
    };
    assert!(error.contains("public.target()"));
    Ok(())
}

#[test]
fn routine_contract_canonicalizes_equivalent_token_spacing() -> Result<(), String> {
    let sql = "CREATE FUNCTION public.target() RETURNS integer AS $$ BEGIN value:=1; IF value<>2 THEN RETURN value; END IF; END $$ LANGUAGE plpgsql;";
    RoutineContract {
        identity: RoutineIdentity::public("target", &[]),
        required: &["value := 1", "value <> 2"],
        forbidden: &[],
        ordered: &["value := 1", "value <> 2"],
    }
    .check(sql)
}

#[test]
fn routine_contract_uses_the_final_exact_replacement() -> Result<(), String> {
    let old =
        "CREATE FUNCTION public.target(p_id uuid) RETURNS text AS $$ SELECT 'old' $$ LANGUAGE sql;";
    let new = "CREATE OR REPLACE FUNCTION public.target(p_id uuid) RETURNS text AS $body$ SELECT 'new' $body$ LANGUAGE sql;";
    RoutineContract {
        identity: RoutineIdentity::public("target", &["uuid"]),
        required: &["SELECT 'new'"],
        forbidden: &["SELECT 'old'"],
        ordered: &[],
    }
    .check(&format!("{old}\n{new}"))?;

    let result = RoutineContract {
        identity: RoutineIdentity::public("target", &["uuid"]),
        required: &["SELECT 'new'"],
        forbidden: &["SELECT 'old'"],
        ordered: &[],
    }
    .check(&format!("{new}\n{old}"));
    let Err(error) = result else {
        return Err("an earlier replacement overrode the final exact definition".to_owned());
    };
    assert!(error.contains("public.target(uuid)"));
    Ok(())
}

#[test]
fn migration_hard_cuts_derived_state_and_reinstalls_every_pinned_function() -> Result<(), String> {
    let current = postgres_migration_inventory::projection_input_generation();
    assert_ne!(current, OLD_GENERATION);
    assert!(!MIGRATION.contains(OLD_GENERATION));

    for identity in [
        RoutineIdentity::public(
            "rss_settings_projection_apply_current",
            &[
                "text", "text", "uuid", "text", "text", "text", "text", "text", "text", "bigint",
                "text", "text", "bigint", "bigint", "bytea",
            ],
        ),
        RoutineIdentity::public(
            "rss_settings_projection_worker_plan_is_current",
            &["text", "text", "text", "text"],
        ),
        RoutineIdentity::public(
            "rss_settings_projection_apply_operator",
            &[
                "uuid", "text", "text", "text", "text", "text", "text", "bigint", "text", "text",
                "bigint", "bigint", "bytea",
            ],
        ),
        RoutineIdentity::public("rss_settings_projection_resolve_active", &[]),
        RoutineIdentity::public("rss_projection_operator_status_active", &["uuid"]),
        RoutineIdentity::public(
            "rss_projection_operator_swap_active",
            &["uuid", "text", "text", "bigint", "text", "text", "text"],
        ),
    ] {
        RoutineContract {
            identity,
            required: &[current],
            forbidden: &[OLD_GENERATION],
            ordered: &[],
        }
        .check(MIGRATION)?;
    }

    for table in [
        "settings_projection_dedupe_receipts",
        "settings_config_projection_rows",
        "projection_worker_tenant_quarantine",
        "checkpoint",
        "settings_projection_active_pointer",
        "settings_projection_generations",
    ] {
        assert!(MIGRATION.contains(&format!("DELETE FROM public.{table}")));
    }
    assert!(!MIGRATION.contains("DELETE FROM public.projection_events"));
    assert!(!MIGRATION.contains("DELETE FROM public.projection_input_bindings"));
    assert!(!MIGRATION.contains("EXECUTE"));
    Ok(())
}
