const SECRET_REFS_HARDENING: &str =
    include_str!("../migrations/0058_harden_secret_refs_append_only.sql");
const MIGRATION_README: &str = include_str!("../migrations/README.md");

#[test]
fn secret_refs_repair_must_finish_before_sqlx_reaches_0058() {
    for token in [
        "reviewed out-of-band preflight/repair",
        "before deploying the binary that contains 0058",
    ] {
        assert!(
            SECRET_REFS_HARDENING.contains(token),
            "0058 recovery hint omits the deployment-order contract: {token}"
        );
    }
    for token in [
        "SQLx applies pending migrations",
        "version order",
        "0058 remains the first pending migration",
        "no later forward migration can run first",
        "reviewed out-of-band repair",
    ] {
        assert!(
            MIGRATION_README.contains(token),
            "migration runbook omits the SQLx ordering/recovery contract: {token}"
        );
    }
    for misleading in ["explicit forward data migration", "forward data migration"] {
        assert!(
            !SECRET_REFS_HARDENING.contains(misleading) && !MIGRATION_README.contains(misleading),
            "failed 0058 must not claim that a later forward migration can repair it: {misleading}"
        );
    }
}
