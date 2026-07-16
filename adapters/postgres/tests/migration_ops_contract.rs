const SECRET_REFS_HARDENING: &str =
    include_str!("../migrations/0058_harden_secret_refs_append_only.sql");
const MIGRATION_README: &str = include_str!("../migrations/README.md");
const DLX_CUTOVER: &str = include_str!("../migrations/0062_prepare_dead_letter_cutover.sql");
const DLX_LIFECYCLE: &str = include_str!("../migrations/0063_dead_letter_lifecycle.sql");
const LOCALONLY_READ_ROLE: &str = include_str!("../migrations/0067_localonly_read_role.sql");
const READER_PROVISIONING: &str =
    include_str!("../../../deploy/postgres-upgrade/provision-reader-role.sh");
const READER_UPGRADE_SMOKE: &str =
    include_str!("../../../deploy/postgres-upgrade/smoke-retained-volume.sh");

#[test]
fn reader_provisioning_disables_inherited_xtrace_before_secret_expansion() {
    assert!(
        matches!(
            (
                READER_PROVISIONING.find("set +x"),
                READER_PROVISIONING.find("${RSS_PG_")
            ),
            (Some(disable_xtrace), Some(first_secret_expansion))
                if disable_xtrace < first_secret_expansion
        ),
        "set +x must exist and execute before any credential-bearing shell expansion"
    );
    assert!(!READER_PROVISIONING.contains("set -x"));
    for required in [
        "ALTER ROLE rss_app_read SET default_transaction_read_only = 'on'",
        "ALTER ROLE rss_app_read SET search_path = pg_catalog, public",
        "current_setting('lo_compat_privileges')",
        "rss_app_read:on:pg_catalog, public:off",
    ] {
        assert!(
            READER_PROVISIONING.contains(required),
            "reader credential provisioning must preserve the startup-gate role settings: {required}"
        );
    }
}

#[test]
fn localonly_reader_migration_is_exact_and_has_no_future_grant_fallback() {
    for required in [
        "CREATE ROLE rss_app_read",
        "LOGIN",
        "NOSUPERUSER",
        "NOBYPASSRLS",
        "NOCREATEDB",
        "NOCREATEROLE",
        "NOREPLICATION",
        "NOINHERIT",
        "default_transaction_read_only = 'on'",
        "search_path = pg_catalog, public",
        "refuse implicit normalization",
        "REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC",
        "GRANT TEMPORARY ON DATABASE %I TO rss_app",
        "GRANT CONNECT ON DATABASE %I TO rss_app_read",
        "FOR application_schema IN",
        "n.nspname <> 'information_schema'",
        "n.nspname !~ '^pg_'",
        "REVOKE ALL PRIVILEGES ON SCHEMA %I FROM rss_app_read",
        "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA %I FROM rss_app_read",
        "REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA %I FROM rss_app_read",
        "REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA %I FROM rss_app_read",
        "a.attacl IS NOT NULL",
        "REVOKE ALL PRIVILEGES (%I) ON TABLE %I.%I FROM rss_app_read",
        "pg_largeobject_metadata",
        "REVOKE ALL PRIVILEGES ON LARGE OBJECT %s FROM %s",
        "pg_parameter_acl",
        "REVOKE ALL PRIVILEGES ON PARAMETER %I FROM %s",
        "acl.grantee IN (0::oid, reader.oid)",
        "pg_catalog.lo_from_bytea(oid, bytea)",
        "pg_catalog.lo_put(oid, bigint, bytea)",
        "pg_catalog.lo_unlink(oid)",
        "FROM PUBLIC, rss_app_read",
        "TO rss_app",
        "CREATE POLICY saga_worker_tenant_index_tenant_isolation",
        "AS RESTRICTIVE",
        "USING (false)",
        "GRANT SELECT ON TABLE %I.%I TO rss_app_read",
        "a.attname = 'tenant_id'",
        "c.relkind IN ('r', 'p')",
    ] {
        assert!(
            LOCALONLY_READ_ROLE.contains(required),
            "0067 omits the exact tenant-reader contract: {required}"
        );
    }
    for forbidden in [
        "ALTER DEFAULT PRIVILEGES",
        "GRANT INSERT",
        "GRANT UPDATE",
        "GRANT DELETE",
        "GRANT TRUNCATE",
        "GRANT USAGE ON ALL SEQUENCES",
        "GRANT TEMPORARY ON DATABASE %I TO rss_app_read",
        "PASSWORD",
    ] {
        assert!(
            !LOCALONLY_READ_ROLE.contains(forbidden),
            "0067 exposes a forbidden reader capability or fallback: {forbidden}"
        );
    }
}

#[test]
fn reader_upgrade_smoke_uses_real_sqlx_ledger_and_release_cli_with_bounded_startup() {
    for required in [
        "RSS_TEST_ALLOW_EXTERNAL_POSTGRES=1",
        "integration_tests::bootstrap_reader_upgrade_smoke_predecessor",
        "postgres migrate-reader-lane",
        "FROM _sqlx_migrations WHERE version = 67",
        "docker inspect",
        "deadline=",
    ] {
        assert!(
            READER_UPGRADE_SMOKE.contains(required),
            "retained-volume smoke omits release-path evidence: {required}"
        );
    }
    for forbidden in [
        "sed -n",
        "0067_localonly_read_role.sql",
        "for migration in",
        "until owner_psql",
    ] {
        assert!(
            !READER_UPGRADE_SMOKE.contains(forbidden),
            "retained-volume smoke must not replay migration SQL or wait forever: {forbidden}"
        );
    }
}

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

#[test]
fn dlx_lifecycle_migration_is_fixed_shape_and_archive_before_purge() {
    let dlx_only = DLX_LIFECYCLE
        .split_once("-- Keep published outbox retention")
        .map_or(DLX_LIFECYCLE, |(dlx, _)| dlx);
    for required in [
        "dead_letter must be empty before enabling DLX lifecycle v3",
        "ALTER COLUMN tenant_id SET NOT NULL",
        "dead_letter_archive_receipts",
        "object_version_id text NOT NULL",
        "reconcile_after timestamptz NOT NULL",
        "ENABLE ROW LEVEL SECURITY",
        "FORCE ROW LEVEL SECURITY",
        "CREATE ROLE rss_dlx_archiver NOLOGIN NOBYPASSRLS NOSUPERUSER",
        "rss_dlx_claim_archive_candidates()",
        "rss_dlx_archive_backlog()",
        "LIMIT 100",
        "rss_dlx_record_archive_receipt",
        "rss_dlx_purge_verified()",
        "LIMIT 1000",
        "rss_dlx_reconcile_expired_receipts()",
        "rss_dlx_delete_missing_archive_receipt",
        "object_lock_mode = 'COMPLIANCE'",
        "object_lock_retain_until > now()",
        "p_object_lock_retain_until <= verified_at + interval '30 days'",
        "object_lock_retain_until > verified_at + interval '30 days'",
        "last_attempt_at <= now() - interval '30 days'",
        "SET search_path = pg_catalog, pg_temp",
        "DLX workload roles must have no role memberships",
        "rss_dlx_lifecycle_owner must have no role memberships",
        "SET reconcile_after = now() + interval '1 day'",
        "DROP FUNCTION IF EXISTS public.rss_sweep_dead_letter(bigint)",
        "replay_capsule_encoding = 'key-provider-v3'",
    ] {
        assert!(
            DLX_LIFECYCLE.contains(required),
            "0063 omits the fixed DLX lifecycle contract: {required}"
        );
    }

    for forbidden in [
        "GRANT EXECUTE ON FUNCTION rss_dlx_claim_archive_candidates() TO rss_app",
        "TO rss_app; -- rss_dlx_record_archive_receipt",
        "GRANT EXECUTE ON FUNCTION rss_dlx_purge_verified() TO rss_app",
        "GRANT DELETE ON dead_letter",
        "p_retain_seconds",
        "p_limit",
        "SET search_path = public, pg_temp",
        "FROM dead_letter AS",
        "FROM dead_letter_archive_receipts AS",
        "DELETE FROM dead_letter AS",
        "DELETE FROM dead_letter_archive_receipts AS",
    ] {
        assert!(
            !dlx_only.contains(forbidden),
            "0063 exposes a forbidden compatibility or variable policy surface: {forbidden}"
        );
    }
}

#[test]
fn dlx_lifecycle_roles_and_claims_are_separated_and_durable() {
    let migration = include_str!("../migrations/0063_dead_letter_lifecycle.sql");
    for required in [
        "CREATE ROLE rss_dlx_verifier NOLOGIN NOBYPASSRLS NOSUPERUSER",
        "CREATE ROLE rss_dlx_purger NOLOGIN NOBYPASSRLS NOSUPERUSER",
        "archive_claim_token uuid",
        "archive_lease_until timestamptz",
        "archive_next_attempt_at timestamptz NOT NULL",
        "archive_failure_count int NOT NULL",
        "archive_quarantined_at timestamptz",
        "UPDATE public.dead_letter AS d",
        "archive_claim_token = gen_random_uuid()",
        "FOR UPDATE OF d SKIP LOCKED",
        "rss_dlx_settle_archive_retry",
        "rss_dlx_quarantine_archive_candidate",
        "TO rss_dlx_verifier",
        "TO rss_dlx_purger",
    ] {
        assert!(
            migration.contains(required),
            "0063 must carry durable separated DLX lifecycle token `{required}`"
        );
    }
    for forbidden in [
        "rss_dlx_record_archive_receipt(uuid, uuid, text, text, bytea, text, text, timestamptz, timestamptz)\n    TO rss_dlx_archiver",
        "GRANT EXECUTE ON FUNCTION public.rss_dlx_purge_verified() TO rss_dlx_archiver",
    ] {
        assert!(
            !migration.contains(forbidden),
            "archiver must not mint or consume purge proof: {forbidden}"
        );
    }
}

#[test]
fn legacy_cutover_has_no_digest_authorized_delete_escape() {
    let cutover = include_str!("../migrations/0062_prepare_dead_letter_cutover.sql");
    assert!(
        !cutover.contains("DELETE FROM public.dead_letter"),
        "an inventory digest is not a recoverable export proof"
    );
    assert!(
        !cutover.contains("CREATE FUNCTION public.rss_cutover_legacy_dead_letter"),
        "0062 must not install an owner-only destructive escape hatch"
    );
}

#[test]
fn dlx_cutover_is_fail_closed_and_never_disposes_legacy_rows() {
    for required in [
        "LOCK TABLE public.dead_letter IN ACCESS EXCLUSIVE MODE",
        "legacy dead_letter must be empty before DLX v3",
        "automatic disposal is forbidden",
        "separately reviewed export/restore migration is required",
        "complete encrypted row bytes",
        "restore drill",
    ] {
        assert!(
            DLX_CUTOVER.contains(required),
            "0062 omits audited cutover contract: {required}"
        );
    }
    for forbidden in [
        "CREATE FUNCTION",
        "DELETE FROM public.dead_letter",
        "dead_letter_legacy_cutover_audit",
        "rss_cutover_legacy_dead_letter",
        "source_inventory_sha256",
        "RSS_DEAD_LETTER_RETAIN_SECONDS",
        "p_retain_seconds",
    ] {
        assert!(
            !DLX_CUTOVER.contains(forbidden),
            "0062 exposes a reusable or policy-bearing cutover surface: {forbidden}"
        );
    }
    assert!(
        !DLX_LIFECYCLE.contains("rss_cutover_legacy_dead_letter"),
        "0063 must not retain or remove a reusable destructive cutover function"
    );
}
