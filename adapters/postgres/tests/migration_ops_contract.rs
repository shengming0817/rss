const SECRET_REFS_HARDENING: &str =
    include_str!("../migrations/0058_harden_secret_refs_append_only.sql");
const MIGRATION_README: &str = include_str!("../migrations/README.md");
const DLX_CUTOVER: &str = include_str!("../migrations/0062_prepare_dead_letter_cutover.sql");
const DLX_LIFECYCLE: &str = include_str!("../migrations/0063_dead_letter_lifecycle.sql");
const LOCALONLY_READ_ROLE: &str = include_str!("../migrations/0067_localonly_read_role.sql");
const SERVICE_TOKEN_REPLAY_MIGRATION: &str =
    include_str!("../migrations/0068_replace_service_token_replay_store.sql");
const ACCOUNT_SECURITY_MIGRATION: &str =
    include_str!("../migrations/0069_create_account_security_states.sql");
const ACCOUNT_SECURITY_CAPACITY_GATE: &str =
    include_str!("../../../docs/ops/0069-account-security-capacity-gate.sh");
const ACCOUNT_SECURITY_CAPACITY_SELFTEST: &str =
    include_str!("../../../docs/ops/0069-account-security-capacity-gate.selftest.sh");
const SERVICE_TOKEN_REPLAY_ADAPTER: &str = include_str!("../src/service_token_replay.rs");
const READER_PROVISIONING: &str =
    include_str!("../../../deploy/postgres-upgrade/provision-reader-role.sh");
const READER_UPGRADE_SMOKE: &str =
    include_str!("../../../deploy/postgres-upgrade/smoke-retained-volume.sh");

#[test]
fn account_security_migration_is_strict_closed_and_least_privilege() {
    let normalized = ACCOUNT_SECURITY_MIGRATION
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for required in [
        "CREATE TABLE public.account_security_states",
        "PRIMARY KEY (tenant_id, user_id)",
        "REFERENCES public.credentials (tenant_id, user_id) ON DELETE CASCADE",
        "CHECK (status IN ('active', 'suspended', 'locked', 'deactivated'))",
        "CHECK (authn_epoch >= 0)",
        "CHECK (version >= 1)",
        "CHECK (status_changed_at <= updated_at)",
        "INSERT INTO public.account_security_states",
        "'active', 0, 1",
        "ALTER TABLE public.credentials",
        "DEFERRABLE INITIALLY DEFERRED",
        "ENABLE ROW LEVEL SECURITY",
        "FORCE ROW LEVEL SECURITY",
        "NULLIF(current_setting('rss.tenant_id', true), '')::uuid",
        "WHERE status = 'active'",
        "DELETE FROM public.refresh_tokens",
        "ADD COLUMN authn_epoch_at_issue bigint NOT NULL",
        "CHECK (authn_epoch_at_issue >= 0)",
        "GRANT SELECT, INSERT, UPDATE ON TABLE public.account_security_states TO rss_app",
        "GRANT SELECT ON TABLE public.account_security_states TO rss_app_read",
    ] {
        assert!(
            normalized.contains(required),
            "0069 omits account-security hard constraint: {required}"
        );
    }

    for forbidden in [
        "GRANT DELETE ON TABLE public.account_security_states",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.account_security_states",
        "CREATE POLICY account_security_tenant_isolation ON public.account_security_states USING ( tenant_id = current_setting",
        "ON CONFLICT",
    ] {
        assert!(
            !normalized.contains(forbidden),
            "0069 contains compatibility or excess-privilege path: {forbidden}"
        );
    }
}

#[test]
fn account_security_cutover_has_bounded_locking_and_executable_runbook() {
    for required in [
        "SET LOCAL lock_timeout = '5s'",
        "SET LOCAL statement_timeout = '5min'",
    ] {
        assert!(
            ACCOUNT_SECURITY_MIGRATION.contains(required),
            "0069 omits bounded migration timeout: {required}"
        );
    }

    let runbook = MIGRATION_README
        .split_once("### 0069 account security state 原子切换")
        .map_or(MIGRATION_README, |(_, runbook)| runbook);
    for required in [
        "零参数 `rss` bootstrap",
        "pg_catalog.pg_stat_activity",
        "pg_catalog.pg_locks",
        "docs/ops/0069-account-security-capacity-gate.sh",
        "EXPECTED_REPLICAS",
        "MAINTENANCE_WINDOW_SECONDS",
        "0069 account-security capacity gate: PASS",
        "rss-postgres-migrator",
        "_sqlx_migrations=69",
        "missing_state",
        "pg_catalog.pg_constraint",
        "relforcerowsecurity",
        "pg_catalog.pg_policies",
        "information_schema.role_table_grants",
        "active_legacy_refresh_families",
        "WHERE status = 'active'",
        "不得手工 DELETE",
        "若 ledger 已为 `69`，禁止启动旧 binary",
    ] {
        assert!(
            runbook.contains(required),
            "0069 cutover runbook omits executable evidence token: {required}"
        );
    }

    let blocker_list = runbook
        .split_once("mode IN (")
        .and_then(|(_, tail)| tail.split_once(");").map(|(list, _)| list))
        .expect("0069 runbook must contain a closed lock blocker list");
    let actual = blocker_list
        .split('\'')
        .skip(1)
        .step_by(2)
        .collect::<std::collections::BTreeSet<_>>();
    let expected = [
        "RowExclusiveLock",
        "ShareUpdateExclusiveLock",
        "ShareLock",
        "ShareRowExclusiveLock",
        "ExclusiveLock",
        "AccessExclusiveLock",
    ]
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        actual, expected,
        "0069 preflight blockers must exactly match SHARE ROW EXCLUSIVE conflicts"
    );

    for required in [
        "set -eu",
        "SELECT count(*) FROM public.credentials",
        "pg_total_relation_size('public.credentials'::regclass)",
        "DATA_BUDGET",
        "WAL_BUDGET",
        "ARCHIVE_BUDGET",
        "SELECT count(*) FROM pg_stat_replication",
        "sample.byte_lag = 0",
        "sample.reply_time >= sample.checked_at - interval '60 seconds'",
        "pg_switch_wal()",
        "archive_target_present",
        "MINIMUM_WINDOW_SECONDS=480",
    ] {
        assert!(
            ACCOUNT_SECURITY_CAPACITY_GATE.contains(required),
            "0069 capacity gate omits fail-closed carrier: {required}"
        );
    }
    for required in [
        "short maintenance window must fail closed",
        "credential row overflow must fail closed",
        "credential byte overflow must fail closed",
        "replica inventory mismatch must fail closed",
        "unhealthy replica must fail closed",
        "archive failure-count change must fail closed",
    ] {
        assert!(
            ACCOUNT_SECURITY_CAPACITY_SELFTEST.contains(required),
            "0069 capacity selftest omits red case: {required}"
        );
    }
}

#[test]
fn service_token_replay_store_is_async_fixed_shape_and_least_privilege() {
    for forbidden in [
        "block_in_place",
        "Handle::block_on",
        "service_token_replay_nonces",
        "DELETE FROM service_token_replay",
    ] {
        assert!(
            !SERVICE_TOKEN_REPLAY_ADAPTER.contains(forbidden),
            "replay adapter contains blocking, legacy, or hot-path cleanup token: {forbidden}"
        );
    }

    let consume_function = SERVICE_TOKEN_REPLAY_MIGRATION
        .split_once("CREATE FUNCTION public.rss_service_token_replay_sweep_expired()")
        .map_or(SERVICE_TOKEN_REPLAY_MIGRATION, |(consume, _)| consume);
    for required in [
        "active legacy service-token replay entries prevent scoped-store cutover",
        "DROP TABLE public.service_token_replay_nonces",
        "key_digest bytea PRIMARY KEY",
        "pg_catalog.octet_length(key_digest) = 32",
        "INSERT INTO public.service_token_replay_keys",
        "ON CONFLICT (key_digest) DO NOTHING",
        "SECURITY DEFINER",
        "SET search_path = pg_catalog, pg_temp",
        "REVOKE ALL ON TABLE public.service_token_replay_keys FROM PUBLIC, rss_app",
        "GRANT EXECUTE ON FUNCTION public.rss_service_token_replay_check_and_record",
    ] {
        assert!(
            SERVICE_TOKEN_REPLAY_MIGRATION.contains(required),
            "0068 omits replay-store contract token: {required}"
        );
    }
    assert!(
        !consume_function.contains("DELETE FROM public.service_token_replay_keys"),
        "authentication consume function must never perform retention cleanup"
    );
    for required in [
        ".run(async",
        ".server_timeout_millis()",
        "pool.begin()",
        "set_config('statement_timeout'",
        "set_config('lock_timeout'",
        ".commit()",
    ] {
        assert!(
            SERVICE_TOKEN_REPLAY_ADAPTER.contains(required),
            "replay adapter omits the single absolute deadline transaction funnel: {required}"
        );
    }
    assert!(
        !SERVICE_TOKEN_REPLAY_ADAPTER.contains(".fetch_one(&self.pool)"),
        "replay SQL must not bypass the deadline-owned transaction"
    );
    for required in [
        "LIMIT 1000",
        "FOR UPDATE SKIP LOCKED",
        "interval '5 minutes'",
    ] {
        assert!(
            SERVICE_TOKEN_REPLAY_MIGRATION.contains(required),
            "bounded replay retention function omits: {required}"
        );
    }
}

#[test]
fn service_token_replay_cutover_runbook_is_non_rolling_and_executable() {
    let runbook = MIGRATION_README
        .split_once("### 0068 service-token replay store 破坏性切换")
        .map_or(MIGRATION_README, |(_, runbook)| runbook);

    for required in [
        "零参数 `rss` bootstrap",
        "rss-postgres-writer",
        "rss-postgres-maintenance",
        "rss-postgres-migrator",
        "pg_catalog.pg_stat_activity",
        "pg_catalog.pg_locks",
        "service_token_replay_nonces",
        "expires_at > pg_catalog.clock_timestamp()",
        "SELECT max(version) FROM public._sqlx_migrations",
        "to_regclass('public.service_token_replay_nonces') IS NULL",
        "to_regclass('public.service_token_replay_keys') IS NOT NULL",
        "pg_catalog.pg_get_userbyid",
        "proc.proconfig",
        "has_function_privilege",
        "SET LOCAL ROLE rss_app",
        "rss_service_token_replay_check_and_record",
        "rss_service_token_replay_sweep_expired",
        "service_token_replay_sweeper",
        "readyz",
    ] {
        assert!(
            runbook.contains(required),
            "0068 cutover runbook omits executable evidence token: {required}"
        );
    }

    let ordered_steps = [
        "1. **停止旧世界**",
        "2. **迁移前探针**",
        "3. **唯一 migration runner**",
        "4. **迁移后 catalog / ACL 探针**",
        "5. **以 `rss_app` 实测固定函数**",
        "6. **只启动新世界**",
        "7. **失败恢复**",
    ];
    let positions: Vec<Option<usize>> = ordered_steps
        .iter()
        .map(|step| runbook.find(step))
        .collect();
    assert!(
        positions.iter().all(Option::is_some),
        "0068 cutover runbook must contain every ordered non-rolling step: {positions:?}"
    );
    assert!(
        positions
            .windows(2)
            .all(|pair| matches!(pair, [Some(left), Some(right)] if left < right)),
        "0068 cutover steps are not in executable order: {positions:?}"
    );
    assert!(
        !runbook.contains("执行 migration job"),
        "0068 must name the supported singleton bootstrap instead of a fictitious generic migration job"
    );
}

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
