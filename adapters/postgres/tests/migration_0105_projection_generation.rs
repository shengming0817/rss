const MIGRATION: &str =
    include_str!("../migrations/0105_advance_settings_projection_input_generation.sql");
const GENERATED_INPUTS: &str =
    include_str!("../../../crates/postgres-migration-inventory/src/projection_inputs.rs");

const OLD_GENERATION: &str =
    "sha256:ff7c69626735495640031695caf9c053830aa6efdcb8c3efa038d68d0cd25801";

fn current_generation() -> Result<&'static str, &'static str> {
    let (_, tail) = GENERATED_INPUTS
        .split_once("PROJECTION_INPUT_GENERATION")
        .ok_or("generated inventory must expose its generation")?;
    let start = tail
        .find("sha256:")
        .ok_or("generated inventory must contain a sha256 generation")?;
    tail.get(start..start + "sha256:".len() + 64)
        .ok_or("generated inventory contains a truncated sha256 generation")
}

#[test]
fn migration_hard_cuts_derived_state_and_reinstalls_every_pinned_function()
-> Result<(), &'static str> {
    let current = current_generation()?;
    assert_ne!(current, OLD_GENERATION);
    assert!(!MIGRATION.contains(OLD_GENERATION));
    assert!(MIGRATION.contains(current));

    for function in [
        "rss_settings_projection_apply_current",
        "rss_settings_projection_worker_plan_is_current",
        "rss_settings_projection_apply_operator",
        "rss_settings_projection_resolve_active",
        "rss_projection_operator_status_active",
        "rss_projection_operator_swap_active",
    ] {
        assert!(MIGRATION.contains(&format!("CREATE OR REPLACE FUNCTION public.{function}")));
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
    assert_eq!(MIGRATION.matches(current).count(), 6);
    Ok(())
}
