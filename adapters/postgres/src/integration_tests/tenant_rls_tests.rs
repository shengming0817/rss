//! Postgres integration tests — tenant_rls seam.

use super::support::*;

/// RLS 能力门反例：superuser/owner 连接不能作为 durable serving pool。该路径同时不是固定 `rss_app`
/// serving role 且会绕过 RLS，能力门须 fail-fast；当前以 role mismatch 先命中。
#[tokio::test(flavor = "multi_thread")]
async fn verify_rls_capability_rejects_owner_serving_role() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let verdict = store.verify_rls_capability().await; // owner/superuser 不能作为 serving pool
    assert!(
        matches!(verdict, Err(crate::PgError::RlsUnexpectedServingRole)),
        "owner/superuser 连接应使 serving role gate fail-fast，实得: {verdict:?}"
    );
    store.shutdown().await?;
    Ok(())
}

/// RLS 能力门反例：即使某个测试角色是 NOBYPASSRLS，也不能替代生产固定 serving role `rss_app`。
#[tokio::test(flavor = "multi_thread")]
async fn verify_rls_capability_rejects_non_rss_app_nobypass_role() -> TestResult {
    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let app = connect_pg_nobypass_role(&pg, &store).await?;
    let verdict = app.verify_rls_capability().await;
    assert!(
        matches!(verdict, Err(crate::PgError::RlsUnexpectedServingRole)),
        "non-rss_app NOBYPASSRLS 角色不得作为 serving pool，实得: {verdict:?}"
    );
    app.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

/// RLS 能力门反例：owner/superuser session 即使 `SET ROLE rss_app` 也不是长期 serving 直连。
#[tokio::test(flavor = "multi_thread")]
async fn verify_rls_capability_rejects_owner_session_set_role_rss_app() -> TestResult {
    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let p = pg.owner_params();
    let switched_config = PgConfig::new(
        p.host.clone(),
        p.port,
        p.database.clone(),
        p.username.clone(),
        PgPassword::new(p.password.clone()),
    )
    .with_ssl_mode(PgSslMode::Prefer)
    .with_max_connections(1)
    .with_acquire_timeout(std::time::Duration::from_secs(5));
    let switched = PgStore::connect(&switched_config).await?;

    sqlx::query("SET ROLE rss_app")
        .execute(&switched.pool)
        .await?;
    let (session_user, current_user): (String, String) =
        sqlx::query_as("SELECT session_user, current_user")
            .fetch_one(&switched.pool)
            .await?;
    assert_ne!(
        session_user, current_user,
        "test must prove SET ROLE made current_user differ from login session"
    );
    assert_eq!(current_user, "rss_app");

    let verdict = switched.verify_rls_capability().await;
    assert!(
        matches!(verdict, Err(crate::PgError::RlsUnexpectedServingRole)),
        "SET ROLE rss_app must not satisfy direct serving login gate, got: {verdict:?}"
    );
    switched.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

/// RLS 能力门正例：迁移后所有 tenant 表均 FORCE RLS + 规范 policy + GUC roundtrip，且以真实 `rss_app`
/// writer 与 `rss_app_read` reader 直连分别跑 capability gate → 放行。
///
/// INVARIANT: TENANCY-PG-CATALOG-PROOF-01 { level = "Medium", exec = "integration-critical", source = "code", synthetic_red = "integration_tests::tenant_rls_tests::serving_gates_reject_default_acl_drift", anti_vacuity = "integration_tests::tenant_rls_tests::verify_rls_capability_ok_after_migrations" }
#[tokio::test(flavor = "multi_thread")]
async fn verify_rls_capability_ok_after_migrations() -> TestResult {
    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?; // 迁移经 owner/superuser
    let app = connect_pg_rss_app_role(&pg, &store).await?;
    let reader = connect_pg_rss_app_read_role(&pg, &store).await?;
    let (writer_session, writer_current): (String, String) =
        sqlx::query_as("SELECT session_user, current_user")
            .fetch_one(&app.pool)
            .await?;
    assert_eq!(writer_session, "rss_app", "writer pool 必须直连 rss_app");
    assert_eq!(writer_current, "rss_app", "writer pool 必须直连 rss_app");
    let (reader_session, reader_current): (String, String) =
        sqlx::query_as("SELECT session_user, current_user")
            .fetch_one(&reader.pool)
            .await?;
    assert_eq!(
        reader_session, "rss_app_read",
        "reader pool 必须直连 rss_app_read"
    );
    assert_eq!(
        reader_current, "rss_app_read",
        "reader pool 必须直连 rss_app_read"
    );
    app.verify_rls_capability().await?; // rss_app writer catalog gate
    reader.verify_tenant_read_capability().await?; // rss_app_read reader catalog gate
    app.shutdown().await?;
    reader.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn writer_gate_rejects_attribute_membership_ownership_and_effective_privilege_drift()
-> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;

    sqlx::query("ALTER ROLE rss_app INHERIT")
        .execute(&owner.pool)
        .await?;
    assert!(matches!(
        app.verify_rls_capability().await,
        Err(PgError::WriterRoleAttributes)
    ));
    sqlx::query("ALTER ROLE rss_app NOINHERIT")
        .execute(&owner.pool)
        .await?;

    sqlx::query("CREATE ROLE synthetic_writer_parent NOLOGIN")
        .execute(&owner.pool)
        .await?;
    sqlx::query("GRANT synthetic_writer_parent TO rss_app")
        .execute(&owner.pool)
        .await?;
    assert!(matches!(
        app.verify_rls_capability().await,
        Err(PgError::WriterMembership)
    ));
    sqlx::query("REVOKE synthetic_writer_parent FROM rss_app")
        .execute(&owner.pool)
        .await?;
    sqlx::query("DROP ROLE synthetic_writer_parent")
        .execute(&owner.pool)
        .await?;

    sqlx::query("CREATE TABLE public.synthetic_writer_owned(id bigint)")
        .execute(&owner.pool)
        .await?;
    sqlx::query("ALTER TABLE public.synthetic_writer_owned OWNER TO rss_app")
        .execute(&owner.pool)
        .await?;
    assert!(matches!(
        app.verify_rls_capability().await,
        Err(PgError::WriterOwnership)
    ));
    sqlx::query("DROP TABLE public.synthetic_writer_owned")
        .execute(&owner.pool)
        .await?;

    let database = pg.owner_params().database.replace('"', "\"\"");
    sqlx::query(&format!(
        "GRANT CREATE ON DATABASE \"{database}\" TO rss_app"
    ))
    .execute(&owner.pool)
    .await?;
    assert!(matches!(
        app.verify_rls_capability().await,
        Err(PgError::WriterPrivileges { .. })
    ));
    sqlx::query(&format!(
        "REVOKE CREATE ON DATABASE \"{database}\" FROM rss_app"
    ))
    .execute(&owner.pool)
    .await?;

    sqlx::query("GRANT SELECT ON TABLE public._sqlx_migrations TO rss_app WITH GRANT OPTION")
        .execute(&owner.pool)
        .await?;
    assert!(matches!(
        app.verify_rls_capability().await,
        Err(PgError::WriterPrivileges { .. })
    ));
    sqlx::query("REVOKE GRANT OPTION FOR SELECT ON TABLE public._sqlx_migrations FROM rss_app")
        .execute(&owner.pool)
        .await?;

    app.verify_rls_capability().await?;
    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

/// Catalog 负例：`ALTER DEFAULT PRIVILEGES` 给 serving writer/reader 或 PUBLIC 的未来 object ACL
/// （TABLE/SEQUENCE/FUNCTION/TYPE/SCHEMA）不得逃过 exact capability gate。isolated DB + finally
/// drop，避免污染 external PG opt-in 库。
#[tokio::test(flavor = "multi_thread")]
async fn serving_gates_reject_default_acl_drift() -> TestResult {
    let (fixture, admin) = connect_pg().await?;
    let database = create_isolated_database(&admin, "serving_default_acl").await?;
    let verdict = assert_default_acl_drift_rejected(&fixture, &database).await;
    let cleanup = drop_isolated_database(&admin, &database).await;
    admin.shutdown().await?;
    cleanup?;
    verdict
}

async fn assert_default_acl_drift_rejected(
    fixture: &testkit::OwnedPgFixture,
    database: &str,
) -> TestResult {
    let (owner, app, reader) = connect_isolated_serving_roles(fixture, database).await?;
    assert_reader_table_default_acl_classified(&owner, &app, &reader).await?;
    assert_writer_sequence_default_acl_classified(&owner, &app, &reader).await?;
    assert_reader_function_default_acl_classified(&owner, &app, &reader).await?;
    assert_public_sequence_default_acl_rejected(&owner, &app, &reader).await?;
    assert_public_type_default_acl_rejected(&owner, &app, &reader).await?;
    assert_reader_schema_default_acl_classified(&owner, &app, &reader).await?;
    app.verify_rls_capability().await?;
    reader.verify_tenant_read_capability().await?;
    app.shutdown().await?;
    reader.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

async fn connect_isolated_serving_roles(
    fixture: &testkit::OwnedPgFixture,
    database: &str,
) -> Result<(PgStore, PgStore, PgStore), Box<dyn std::error::Error + Send + Sync>> {
    let owner =
        PgStore::connect(&isolated_database_config(fixture.owner_params(), database)).await?;
    owner.run_migrations().await?;
    sqlx::query(&format!(
        "ALTER ROLE {TEST_APP_ROLE} LOGIN PASSWORD '{TEST_APP_PASSWORD}' \
         NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT"
    ))
    .execute(&owner.pool)
    .await?;
    sqlx::query(&format!(
        "ALTER ROLE {TEST_READ_ROLE} PASSWORD '{TEST_READ_PASSWORD}'"
    ))
    .execute(&owner.pool)
    .await?;
    let app = PgStore::connect(&isolated_database_role_config(
        fixture.owner_params(),
        database,
        TEST_APP_ROLE,
        TEST_APP_PASSWORD,
    ))
    .await?;
    let reader = PgStore::connect(&isolated_database_role_config(
        fixture.owner_params(),
        database,
        TEST_READ_ROLE,
        TEST_READ_PASSWORD,
    ))
    .await?;
    Ok((owner, app, reader))
}

async fn assert_reader_table_default_acl_classified(
    owner: &PgStore,
    app: &PgStore,
    reader: &PgStore,
) -> TestResult {
    sqlx::query("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO rss_app_read")
        .execute(&owner.pool)
        .await?;
    let reader_verdict = reader.verify_tenant_read_capability().await;
    let writer_verdict = app.verify_rls_capability().await;
    sqlx::query(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE SELECT ON TABLES FROM rss_app_read",
    )
    .execute(&owner.pool)
    .await?;
    assert!(
        matches!(
            reader_verdict,
            Err(PgError::TenantReadDefaultPrivileges { .. })
        ),
        "reader TABLE default ACL must fail the tenant-read gate, got: {reader_verdict:?}"
    );
    assert!(
        writer_verdict.is_ok(),
        "reader-targeted TABLE default ACL must not fail the writer gate, got: {writer_verdict:?}"
    );
    Ok(())
}

async fn assert_writer_sequence_default_acl_classified(
    owner: &PgStore,
    app: &PgStore,
    reader: &PgStore,
) -> TestResult {
    sqlx::query("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE ON SEQUENCES TO rss_app")
        .execute(&owner.pool)
        .await?;
    let writer_verdict = app.verify_rls_capability().await;
    let reader_verdict = reader.verify_tenant_read_capability().await;
    sqlx::query("ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE USAGE ON SEQUENCES FROM rss_app")
        .execute(&owner.pool)
        .await?;
    assert!(
        matches!(writer_verdict, Err(PgError::WriterDefaultPrivileges { .. })),
        "writer SEQUENCE default ACL must fail the serving gate, got: {writer_verdict:?}"
    );
    assert!(
        reader_verdict.is_ok(),
        "writer-targeted SEQUENCE default ACL must not fail the reader gate, got: {reader_verdict:?}"
    );
    Ok(())
}

async fn assert_reader_function_default_acl_classified(
    owner: &PgStore,
    app: &PgStore,
    reader: &PgStore,
) -> TestResult {
    // Direct role grant — not PUBLIC EXECUTE (PostgreSQL built-in default would no-op / fold).
    sqlx::query(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO rss_app_read",
    )
    .execute(&owner.pool)
    .await?;
    let reader_verdict = reader.verify_tenant_read_capability().await;
    let writer_verdict = app.verify_rls_capability().await;
    sqlx::query(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM rss_app_read",
    )
    .execute(&owner.pool)
    .await?;
    assert!(
        matches!(
            reader_verdict,
            Err(PgError::TenantReadDefaultPrivileges { .. })
        ),
        "reader FUNCTION default ACL must fail the tenant-read gate, got: {reader_verdict:?}"
    );
    assert!(
        writer_verdict.is_ok(),
        "reader-targeted FUNCTION default ACL must not fail the writer gate, got: {writer_verdict:?}"
    );
    Ok(())
}

async fn assert_public_sequence_default_acl_rejected(
    owner: &PgStore,
    app: &PgStore,
    reader: &PgStore,
) -> TestResult {
    sqlx::query("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE ON SEQUENCES TO PUBLIC")
        .execute(&owner.pool)
        .await?;
    let writer_verdict = app.verify_rls_capability().await;
    let reader_verdict = reader.verify_tenant_read_capability().await;
    sqlx::query("ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE USAGE ON SEQUENCES FROM PUBLIC")
        .execute(&owner.pool)
        .await?;
    assert!(
        matches!(writer_verdict, Err(PgError::WriterDefaultPrivileges { .. })),
        "PUBLIC SEQUENCE default ACL must fail the serving gate, got: {writer_verdict:?}"
    );
    assert!(
        matches!(
            reader_verdict,
            Err(PgError::TenantReadDefaultPrivileges { .. })
        ),
        "PUBLIC SEQUENCE default ACL must fail the tenant-read gate, got: {reader_verdict:?}"
    );
    Ok(())
}

async fn assert_public_type_default_acl_rejected(
    owner: &PgStore,
    app: &PgStore,
    reader: &PgStore,
) -> TestResult {
    sqlx::query("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE ON TYPES TO PUBLIC")
        .execute(&owner.pool)
        .await?;
    let writer_verdict = app.verify_rls_capability().await;
    let reader_verdict = reader.verify_tenant_read_capability().await;
    sqlx::query("ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE USAGE ON TYPES FROM PUBLIC")
        .execute(&owner.pool)
        .await?;
    assert!(
        matches!(writer_verdict, Err(PgError::WriterDefaultPrivileges { .. })),
        "PUBLIC TYPE default ACL must fail the serving gate, got: {writer_verdict:?}"
    );
    assert!(
        matches!(
            reader_verdict,
            Err(PgError::TenantReadDefaultPrivileges { .. })
        ),
        "PUBLIC TYPE default ACL must fail the tenant-read gate, got: {reader_verdict:?}"
    );
    Ok(())
}

async fn assert_reader_schema_default_acl_classified(
    owner: &PgStore,
    app: &PgStore,
    reader: &PgStore,
) -> TestResult {
    // SCHEMA default ACL uses defaclobjtype='n'; exercises the n branch of SERVING_DEFAULT_ACL_SQL.
    sqlx::query("ALTER DEFAULT PRIVILEGES GRANT USAGE ON SCHEMAS TO rss_app_read")
        .execute(&owner.pool)
        .await?;
    let reader_verdict = reader.verify_tenant_read_capability().await;
    let writer_verdict = app.verify_rls_capability().await;
    sqlx::query("ALTER DEFAULT PRIVILEGES REVOKE USAGE ON SCHEMAS FROM rss_app_read")
        .execute(&owner.pool)
        .await?;
    assert!(
        matches!(
            reader_verdict,
            Err(PgError::TenantReadDefaultPrivileges { .. })
        ),
        "reader SCHEMA default ACL must fail the tenant-read gate, got: {reader_verdict:?}"
    );
    assert!(
        writer_verdict.is_ok(),
        "reader-targeted SCHEMA default ACL must not fail the writer gate, got: {writer_verdict:?}"
    );
    Ok(())
}

/// audit admin pool 角色必须是可直连 LOGIN role；部署只需注入密码，不应再把权限组 NOLOGIN 当连接身份。
#[tokio::test(flavor = "multi_thread")]
async fn audit_admin_role_is_login_after_migrations() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let (can_login, bypass_rls): (bool, bool) = sqlx::query_as(
        "SELECT rolcanlogin, rolbypassrls FROM pg_roles WHERE rolname = 'rss_audit_admin'",
    )
    .fetch_one(&store.pool)
    .await?;
    assert!(can_login, "rss_audit_admin must be a LOGIN role");
    assert!(!bypass_rls, "rss_audit_admin must remain NOBYPASSRLS");
    store.shutdown().await?;
    Ok(())
}

/// audit admin 正例：迁移后注入密码即可直连，并通过 exact read-only capability gate。
#[tokio::test(flavor = "multi_thread")]
async fn verify_audit_admin_capability_ok_after_migrations() -> TestResult {
    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let audit_admin = connect_pg_audit_admin_role(&pg, &store).await?;
    audit_admin.verify_audit_admin_capability().await?;
    audit_admin.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

/// audit admin 负例：除 `audit_entries:SELECT` 外，任一 public table privilege 都必须启动期 fail-fast。
#[tokio::test(flavor = "multi_thread")]
async fn verify_audit_admin_capability_rejects_extra_table_privilege() -> TestResult {
    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS _audit_admin_extra_privilege (id int)")
        .execute(&store.pool)
        .await?;
    sqlx::query("GRANT SELECT ON _audit_admin_extra_privilege TO rss_audit_admin")
        .execute(&store.pool)
        .await?;
    let audit_admin = connect_pg_audit_admin_role(&pg, &store).await?;

    let verdict = audit_admin.verify_audit_admin_capability().await;

    sqlx::query("DROP TABLE IF EXISTS _audit_admin_extra_privilege")
        .execute(&store.pool)
        .await?;
    assert!(
        matches!(verdict, Err(crate::PgError::AuditAdminPrivileges)),
        "rss_audit_admin extra table privilege must fail startup gate, got: {verdict:?}"
    );
    audit_admin.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

/// 真实 serving pool 覆盖：不用 `SET ROLE` 模拟，直接以 `rss_app` 登录连接验证 tenant A/B 隔离。
///
/// INVARIANT: TENANCY-PG-BEHAVIOR-PROOF-01 { level = "Medium", exec = "integration-critical", source = "code", synthetic_red = "integration_tests::tenant_rls_tests::rss_app_permissive_policy_breaks_tenant_ab_isolation", anti_vacuity = "integration_tests::tenant_rls_tests::rss_app_serving_pool_enforces_tenant_ab_isolation" }
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: uuid v4 与固定 SQL happy-path；集成测试构造值均合法。
async fn rss_app_serving_pool_enforces_tenant_ab_isolation() -> TestResult {
    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &store).await?;

    let (session_user, current_user): (String, String) =
        sqlx::query_as("SELECT session_user, current_user")
            .fetch_one(&app.pool)
            .await?;
    assert_eq!(session_user, "rss_app", "serving pool 必须直连 rss_app");
    assert_eq!(current_user, "rss_app", "serving pool 必须直连 rss_app");

    let observed = observe_rss_app_tenant_ab_isolation(&store, &app).await?;
    assert_eq!(
        observed.tenant_a_visible, 1,
        "tenant A scope 应能看到 tenant A role"
    );
    assert_eq!(
        observed.tenant_b_visible, 0,
        "tenant B scope 不得看到 tenant A role"
    );
    assert_eq!(
        observed.unset_guc_visible, 0,
        "未设 rss.tenant_id 时读必须 fail-closed"
    );

    app.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

/// Behavior synthetic-red：isolated DB 上追加 allow-all permissive policy 后，同一 A/B 观察 helper
/// 必须实证跨租与无 GUC 可见——证明 green 读取隔离不是 vacuous。角色 mutation 的唯一入口与
/// fail-closed 由独立 function/ACL 测试覆盖，不能通过放宽 RLS 获得直接 DML 能力。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: uuid v4 与固定 SQL happy-path；集成测试构造值均合法。
async fn rss_app_permissive_policy_breaks_tenant_ab_isolation() -> TestResult {
    let (fixture, admin) = connect_pg().await?;
    let database = create_isolated_database(&admin, "serving_permissive_ab").await?;
    let verdict = assert_permissive_policy_breaks_ab_isolation(&fixture, &database).await;
    let cleanup = drop_isolated_database(&admin, &database).await;
    admin.shutdown().await?;
    cleanup?;
    verdict
}

async fn assert_permissive_policy_breaks_ab_isolation(
    fixture: &testkit::OwnedPgFixture,
    database: &str,
) -> TestResult {
    let owner =
        PgStore::connect(&isolated_database_config(fixture.owner_params(), database)).await?;
    owner.run_migrations().await?;
    sqlx::query(&format!(
        "ALTER ROLE {TEST_APP_ROLE} LOGIN PASSWORD '{TEST_APP_PASSWORD}' \
         NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT"
    ))
    .execute(&owner.pool)
    .await?;
    sqlx::raw_sql("CREATE POLICY allow_all ON public.roles USING (true) WITH CHECK (true)")
        .execute(&owner.pool)
        .await?;

    let app = PgStore::connect(&isolated_database_role_config(
        fixture.owner_params(),
        database,
        TEST_APP_ROLE,
        TEST_APP_PASSWORD,
    ))
    .await?;
    let observed = observe_rss_app_tenant_ab_isolation(&owner, &app).await?;
    assert_eq!(
        observed.tenant_a_visible, 1,
        "seed under A must remain visible to A"
    );
    assert!(
        observed.tenant_b_visible > 0,
        "permissive policy must let tenant B see tenant A rows, got {}",
        observed.tenant_b_visible
    );
    assert!(
        observed.unset_guc_visible > 0,
        "permissive policy must make rows visible without GUC, got {}",
        observed.unset_guc_visible
    );

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

/// Direct `rss_app` A/B behavior observation shared by green isolation and permissive-policy red.
struct RssAppTenantAbObservation {
    tenant_a_visible: i64,
    tenant_b_visible: i64,
    unset_guc_visible: i64,
}

#[allow(clippy::unwrap_used)]
// reason: uuid v4 fixtures are valid; observation is test-only.
async fn observe_rss_app_tenant_ab_isolation(
    owner: &PgStore,
    app: &PgStore,
) -> Result<RssAppTenantAbObservation, Box<dyn std::error::Error + Send + Sync>> {
    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let role_a = uuid::Uuid::new_v4().to_string();
    owner_record_role_revision(owner, &tenant_a, &role_a, "rss-app-serving-test").await?;

    let tenant_a_visible = count_roles_under_tenant(app, &tenant_a, &role_a).await?;
    let tenant_b_visible = count_roles_under_tenant(app, &tenant_b, &role_a).await?;
    let unset_guc_visible = count_roles_without_tenant_guc(app, &role_a).await?;

    Ok(RssAppTenantAbObservation {
        tenant_a_visible,
        tenant_b_visible,
        unset_guc_visible,
    })
}

async fn count_roles_under_tenant(
    app: &PgStore,
    tenant: &str,
    role_id: &str,
) -> Result<i64, Box<dyn std::error::Error + Send + Sync>> {
    let mut tx = app.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(tenant)
        .execute(&mut *tx)
        .await?;
    let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM roles WHERE id = $1")
        .bind(role_id)
        .fetch_one(&mut *tx)
        .await?;
    tx.rollback().await?;
    Ok(cnt.0)
}

async fn count_roles_without_tenant_guc(
    app: &PgStore,
    role_id: &str,
) -> Result<i64, Box<dyn std::error::Error + Send + Sync>> {
    let mut tx = app.pool.begin().await?;
    let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM roles WHERE id = $1")
        .bind(role_id)
        .fetch_one(&mut *tx)
        .await?;
    tx.rollback().await?;
    Ok(cnt.0)
}

async fn owner_record_role_revision(
    store: &PgStore,
    tenant: &str,
    role_id: &str,
    name: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut tx = store.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(tenant)
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT * FROM rss_record_role_revision($1, $2, '{}'::text[], $3::uuid, 'admin')")
        .bind(role_id)
        .bind(name)
        .bind(uuid::Uuid::new_v4().to_string())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Tenant-scoped read transactions must be physically read-only, even when the underlying
/// fixture connection is an owner that could otherwise mutate the tenant relation.
#[tokio::test(flavor = "multi_thread")]
async fn tenant_db_binds_identity_and_read_lifecycle() -> TestResult {
    const ORIGINAL_NAME: &str = "tenant-read-original";
    const ATTEMPTED_NAME: &str = "tenant-read-mutated";

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant = test_tenant();
    let tenant_id = tenant.to_string();
    let role_id = unique_event_id("tenant-read-only");
    owner_record_role_revision(&store, &tenant_id, &role_id, ORIGINAL_NAME).await?;

    let tenant_pool =
        crate::cotx::TenantDb::<crate::cotx::ServingReadLane>::from_unverified_for_test(&store);
    let scope = integration_tenant_scope(tenant);
    let transaction_read_only: String = tenant_pool
        .test_read(scope, |mut connection| {
            Box::pin(async move {
                assert_eq!(connection.tenant(), tenant);
                connection.test_transaction_read_only().await
            })
        })
        .await?;

    let update_role_id = role_id.clone();
    let update_result = tenant_pool
        .test_read(scope, move |mut connection| {
            Box::pin(async move {
                connection
                    .test_attempt_role_update(&update_role_id, ATTEMPTED_NAME)
                    .await
            })
        })
        .await;
    let update_sqlstate = match &update_result {
        Err(sqlx::Error::Database(error)) => error.code().map(|code| code.into_owned()),
        _ => None,
    };

    let mapped_transaction_read_only: String = tenant_pool
        .test_read_map(
            scope,
            |mut connection| {
                Box::pin(async move {
                    assert_eq!(connection.tenant(), tenant);
                    connection.test_transaction_read_only().await
                })
            },
            |error| error,
        )
        .await?;
    let mapped_role_id = role_id.clone();
    let mapped_update_result = tenant_pool
        .test_read_map(
            scope,
            move |mut connection| {
                Box::pin(async move {
                    connection
                        .test_attempt_role_update(&mapped_role_id, ATTEMPTED_NAME)
                        .await
                })
            },
            |error| error,
        )
        .await;
    let mapped_update_sqlstate = match &mapped_update_result {
        Err(sqlx::Error::Database(error)) => error.code().map(|code| code.into_owned()),
        _ => None,
    };

    let persisted_name: String =
        sqlx::query_scalar("SELECT name FROM role_revisions WHERE role_id = $1")
            .bind(&role_id)
            .fetch_one(&store.pool)
            .await?;

    assert_eq!(
        (
            transaction_read_only.as_str(),
            update_sqlstate.as_deref(),
            mapped_transaction_read_only.as_str(),
            mapped_update_sqlstate.as_deref(),
            persisted_name.as_str(),
        ),
        ("on", Some("25006"), "on", Some("25006"), ORIGINAL_NAME,),
        "tenant read/read_map must report read-only, reject valid UPDATEs, and leave owner-visible data unchanged"
    );

    store.shutdown().await?;
    Ok(())
}

/// The dedicated reader must pass the exact startup gate, retain tenant RLS isolation, and still
/// reject DML by ACL when a caller explicitly overrides the role's default with `BEGIN READ WRITE`.
#[tokio::test(flavor = "multi_thread")]
async fn tenant_reader_role_is_exact_and_forced_read_write_is_denied() -> TestResult {
    const ORIGINAL_NAME: &str = "reader-role-original";
    const ATTEMPTED_NAME: &str = "reader-role-mutated";

    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let tenant_a = test_tenant();
    let tenant_b = rss_request_context::TenantId::parse("00000000-0000-4000-8000-000000000abc")?;
    let tenant_a_id = tenant_a.to_string();
    let role_id = unique_event_id("tenant-reader-role");
    owner_record_role_revision(&owner, &tenant_a_id, &role_id, ORIGINAL_NAME).await?;

    let reader_config = rss_app_read_config(&pg, &owner).await?;
    let verified_reader = PgStore::connect_verified_read(&reader_config).await?;
    let reader_store = verified_reader.store_arc();
    let read_pool = crate::cotx::TenantDb::<crate::cotx::ServingReadLane>::new(&verified_reader);
    let writer_keeps_temporary: bool = sqlx::query_scalar(
        "SELECT has_database_privilege('rss_app', current_database(), 'TEMPORARY')",
    )
    .fetch_one(&owner.pool)
    .await?;
    assert!(
        writer_keeps_temporary,
        "removing PUBLIC TEMPORARY must not remove the existing writer capability"
    );

    let reader_role = role_id.clone();
    let tenant_a_count: i64 = read_pool
        .test_read(integration_tenant_scope(tenant_a), move |mut connection| {
            Box::pin(async move { connection.test_role_count(&reader_role).await })
        })
        .await?;
    let reader_role = role_id.clone();
    let tenant_b_count: i64 = read_pool
        .test_read(integration_tenant_scope(tenant_b), move |mut connection| {
            Box::pin(async move { connection.test_role_count(&reader_role).await })
        })
        .await?;
    assert_eq!(tenant_a_count, 1, "reader must see its own tenant row");
    assert_eq!(tenant_b_count, 0, "reader RLS must hide another tenant row");

    let leaked_tenant: Option<String> =
        sqlx::query_scalar("SELECT current_setting('rss.tenant_id', true)")
            .fetch_one(&reader_store.pool)
            .await?;
    assert!(
        leaked_tenant.is_none_or(|value| value.is_empty()),
        "committed reader transactions must not leak tenant GUC into a reused connection"
    );

    let mut forced_read_write = reader_store.pool.begin_with("BEGIN READ WRITE").await?;
    crate::cotx::set_local_tenant(&mut forced_read_write, tenant_a).await?;
    let denied = sqlx::query(
        "UPDATE role_revisions SET name = $1 WHERE role_id = $2 AND tenant_id = $3::uuid",
    )
    .bind(ATTEMPTED_NAME)
    .bind(&role_id)
    .bind(&tenant_a_id)
    .execute(&mut *forced_read_write)
    .await;
    assert!(
        matches!(
            denied,
            Err(sqlx::Error::Database(ref error)) if error.code().as_deref() == Some("42501")
        ),
        "forced READ WRITE must still be denied by reader ACL: {denied:?}"
    );
    forced_read_write.rollback().await?;

    let persisted_name: String =
        sqlx::query_scalar("SELECT name FROM role_revisions WHERE role_id = $1")
            .bind(&role_id)
            .fetch_one(&owner.pool)
            .await?;
    assert_eq!(persisted_name, ORIGINAL_NAME);

    reader_store.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

/// `default_transaction_read_only` is only a default: a caller can explicitly start READ WRITE.
/// The reader role must therefore lack EXECUTE on pg_catalog large-object mutators, otherwise it
/// can create persistent database state without touching any application relation ACL.
#[tokio::test(flavor = "multi_thread")]
async fn tenant_reader_forced_read_write_cannot_persist_large_objects() -> TestResult {
    let (fixture, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let reader_config = rss_app_read_config(&fixture, &owner).await?;
    let reader = PgStore::connect_verified_read(&reader_config).await?;
    let reader_store = reader.store_arc();
    let protected_oid: i64 = sqlx::query_scalar(
        "SELECT lo_from_bytea(0, decode('6f776e65722d6279746573', 'hex'))::bigint",
    )
    .fetch_one(&owner.pool)
    .await?;
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_largeobject_metadata")
        .fetch_one(&owner.pool)
        .await?;

    let mut tx = reader_store.pool.begin_with("BEGIN READ WRITE").await?;
    let create: Result<i64, sqlx::Error> = sqlx::query_scalar(
        "SELECT lo_from_bytea(0, decode('7265616465722d7772697465', 'hex'))::bigint",
    )
    .fetch_one(&mut *tx)
    .await;
    let created_oid = create.as_ref().ok().copied();
    if created_oid.is_some() {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }

    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_largeobject_metadata")
        .fetch_one(&owner.pool)
        .await?;
    if let Some(oid) = created_oid {
        sqlx::query(&format!("SELECT lo_unlink({oid}::oid)"))
            .execute(&owner.pool)
            .await?;
    }

    let mut write_tx = reader_store.pool.begin_with("BEGIN READ WRITE").await?;
    let write = sqlx::query(&format!(
        "SELECT lo_put({protected_oid}::oid, 0, decode('7265616465722d6f7665727772697465', 'hex'))"
    ))
    .execute(&mut *write_tx)
    .await;
    if write.is_ok() {
        write_tx.commit().await?;
    } else {
        write_tx.rollback().await?;
    }

    let mut unlink_tx = reader_store.pool.begin_with("BEGIN READ WRITE").await?;
    let unlink = sqlx::query(&format!("SELECT lo_unlink({protected_oid}::oid)"))
        .execute(&mut *unlink_tx)
        .await;
    if unlink.is_ok() {
        unlink_tx.commit().await?;
    } else {
        unlink_tx.rollback().await?;
    }

    let protected_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_largeobject_metadata WHERE oid = $1::oid)",
    )
    .bind(protected_oid)
    .fetch_one(&owner.pool)
    .await?;
    let protected_bytes = if protected_exists {
        Some(
            sqlx::query_scalar::<_, Vec<u8>>(&format!("SELECT lo_get({protected_oid}::oid)"))
                .fetch_one(&owner.pool)
                .await?,
        )
    } else {
        None
    };
    if protected_exists {
        sqlx::query(&format!("SELECT lo_unlink({protected_oid}::oid)"))
            .execute(&owner.pool)
            .await?;
    }

    assert!(
        matches!(
            create,
            Err(sqlx::Error::Database(ref error)) if error.code().as_deref() == Some("42501")
        ),
        "forced READ WRITE reader must not execute lo_from_bytea: {create:?}"
    );
    assert_eq!(
        after, before,
        "denied reader LO creation must leave pg_largeobject_metadata unchanged"
    );
    for (operation, result) in [("lo_put", write), ("lo_unlink", unlink)] {
        assert!(
            matches!(
                result,
                Err(sqlx::Error::Database(ref error)) if error.code().as_deref() == Some("42501")
            ),
            "forced READ WRITE reader must not execute {operation}: {result:?}"
        );
    }
    assert!(
        protected_exists,
        "reader must not unlink the owner large object"
    );
    assert_eq!(
        protected_bytes.as_deref(),
        Some(b"owner-bytes".as_slice()),
        "reader must not overwrite owner large-object bytes"
    );

    reader_store.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

/// Effective relation ACL drift is rejected even when the role itself and all tenant grants are
/// otherwise valid.
#[tokio::test(flavor = "multi_thread")]
async fn tenant_reader_gate_rejects_non_tenant_relation_select() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    sqlx::query("CREATE TABLE _tenant_reader_acl_drift (id integer PRIMARY KEY)")
        .execute(&owner.pool)
        .await?;
    sqlx::query("GRANT SELECT ON _tenant_reader_acl_drift TO rss_app_read")
        .execute(&owner.pool)
        .await?;
    let reader = connect_pg_rss_app_read_role(&pg, &owner).await?;

    let verdict = reader.verify_tenant_read_capability().await;

    assert!(
        matches!(verdict, Err(crate::PgError::TenantReadRelationPrivileges)),
        "non-tenant relation SELECT must fail the exact ACL gate: {verdict:?}"
    );
    reader.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

/// Partitioned tenant relations are part of both the ACL inventory and the FORCE-RLS/policy gate;
/// granting the required reader SELECT must not hide a missing RLS policy on relkind `p`.
#[tokio::test(flavor = "multi_thread")]
async fn tenant_reader_gate_rejects_partitioned_tenant_relation_without_rls() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    sqlx::query(
        "CREATE TABLE tenant_reader_partitioned_without_rls \
         (tenant_id uuid NOT NULL, bucket integer NOT NULL) PARTITION BY LIST (bucket)",
    )
    .execute(&owner.pool)
    .await?;
    sqlx::query("GRANT SELECT ON tenant_reader_partitioned_without_rls TO rss_app_read")
        .execute(&owner.pool)
        .await?;
    let reader = connect_pg_rss_app_read_role(&pg, &owner).await?;

    let verdict = reader.verify_tenant_read_capability().await;

    assert!(
        matches!(verdict, Err(crate::PgError::RlsNotEnforced { .. })),
        "partitioned tenant relation without FORCE RLS/policy must fail closed: {verdict:?}"
    );
    reader.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

/// The reader gate is a direct-login gate, not merely a check that the connected role happens to
/// have a safe-looking effective privilege set.
#[tokio::test(flavor = "multi_thread")]
async fn tenant_reader_gate_rejects_wrong_direct_role() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let writer = connect_pg_rss_app_role(&pg, &owner).await?;

    let verdict = writer.verify_tenant_read_capability().await;

    assert!(
        matches!(verdict, Err(crate::PgError::TenantReadUnexpectedRole)),
        "rss_app must not pass the dedicated reader direct-role gate: {verdict:?}"
    );
    writer.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

/// Relation and column ACL drift are independent escalation surfaces. Restore each mutation before
/// asserting its verdict so a failed assertion cannot contaminate later integration tests that
/// reuse an externally supplied PostgreSQL database.
#[tokio::test(flavor = "multi_thread")]
async fn tenant_reader_gate_rejects_tenant_dml_and_column_acl_drift() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let reader_config = rss_app_read_config(&pg, &owner).await?;
    let tenant = test_tenant();
    let tenant_id = tenant.to_string();
    let role_id = unique_event_id("tenant-reader-column-acl-drift");
    owner_record_role_revision(&owner, &tenant_id, &role_id, "before").await?;

    sqlx::query("GRANT UPDATE ON roles TO rss_app_read")
        .execute(&owner.pool)
        .await?;
    let table_dml_verdict = tenant_reader_gate_verdict(&reader_config).await?;
    sqlx::query("REVOKE UPDATE ON roles FROM rss_app_read")
        .execute(&owner.pool)
        .await?;
    assert!(
        matches!(
            table_dml_verdict,
            Err(crate::PgError::TenantReadRelationPrivileges)
        ),
        "tenant table-level UPDATE must fail the exact reader ACL gate: {table_dml_verdict:?}"
    );

    sqlx::query("GRANT UPDATE (name) ON role_revisions TO rss_app_read")
        .execute(&owner.pool)
        .await?;
    let reader = PgStore::connect(reader_config.as_pg_config()).await?;
    let mut forced_read_write = reader.pool.begin_with("BEGIN READ WRITE").await?;
    crate::cotx::set_local_tenant(&mut forced_read_write, tenant).await?;
    let escalated = sqlx::query(
        "UPDATE role_revisions SET name = 'column-acl-bypass' \
         WHERE role_id = $1 AND tenant_id = $2::uuid",
    )
    .bind(&role_id)
    .bind(&tenant_id)
    .execute(&mut *forced_read_write)
    .await?;
    assert_eq!(
        escalated.rows_affected(),
        1,
        "synthetic drift must be a real write escalation, not a vacuous catalog case"
    );
    forced_read_write.rollback().await?;
    reader.shutdown().await?;
    let column_update_verdict = tenant_reader_gate_verdict(&reader_config).await?;
    sqlx::query("REVOKE UPDATE (name) ON role_revisions FROM rss_app_read")
        .execute(&owner.pool)
        .await?;
    assert!(
        matches!(
            column_update_verdict,
            Err(crate::PgError::TenantReadRelationPrivileges)
        ),
        "column-level UPDATE must fail the exact reader ACL gate: {column_update_verdict:?}"
    );

    sqlx::query("GRANT SELECT (name) ON role_revisions TO rss_app_read WITH GRANT OPTION")
        .execute(&owner.pool)
        .await?;
    let column_grant_option_verdict = tenant_reader_gate_verdict(&reader_config).await?;
    sqlx::query("REVOKE SELECT (name) ON role_revisions FROM rss_app_read")
        .execute(&owner.pool)
        .await?;
    assert!(
        matches!(
            column_grant_option_verdict,
            Err(crate::PgError::TenantReadRelationPrivileges)
        ),
        "column SELECT WITH GRANT OPTION must fail the exact reader ACL gate: \
         {column_grant_option_verdict:?}"
    );

    sqlx::query("GRANT SELECT ON roles TO rss_app_read WITH GRANT OPTION")
        .execute(&owner.pool)
        .await?;
    let relation_grant_option_verdict = tenant_reader_gate_verdict(&reader_config).await?;
    sqlx::query("REVOKE GRANT OPTION FOR SELECT ON roles FROM rss_app_read")
        .execute(&owner.pool)
        .await?;
    assert!(
        matches!(
            relation_grant_option_verdict,
            Err(crate::PgError::TenantReadRelationPrivileges)
        ),
        "table SELECT WITH GRANT OPTION must fail the exact reader ACL gate: \
         {relation_grant_option_verdict:?}"
    );

    owner.shutdown().await?;
    Ok(())
}

/// Every non-relation reader capability is checked as an independent fail-fast stage. Each drift
/// is restored before the next probe so no earlier failure can mask a later gate.
#[tokio::test(flavor = "multi_thread")]
async fn tenant_reader_gate_rejects_role_and_non_relation_privilege_drift() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let reader_config = rss_app_read_config(&pg, &owner).await?;

    sqlx::query("ALTER ROLE rss_app_read SET default_transaction_read_only = 'off'")
        .execute(&owner.pool)
        .await?;
    assert!(matches!(
        tenant_reader_gate_verdict(&reader_config).await?,
        Err(crate::PgError::TenantReadDefaultTransaction)
    ));
    sqlx::query("ALTER ROLE rss_app_read SET default_transaction_read_only = 'on'")
        .execute(&owner.pool)
        .await?;

    sqlx::query("ALTER ROLE rss_app_read SET search_path = public")
        .execute(&owner.pool)
        .await?;
    assert!(matches!(
        tenant_reader_gate_verdict(&reader_config).await?,
        Err(crate::PgError::TenantReadSearchPath)
    ));
    sqlx::query("ALTER ROLE rss_app_read SET search_path = pg_catalog, public")
        .execute(&owner.pool)
        .await?;

    sqlx::query("ALTER ROLE rss_app_read INHERIT")
        .execute(&owner.pool)
        .await?;
    let inherit_before_probe: bool = sqlx::query_scalar(
        "SELECT rolinherit FROM pg_catalog.pg_roles WHERE rolname = 'rss_app_read'",
    )
    .fetch_one(&owner.pool)
    .await?;
    assert!(inherit_before_probe, "synthetic INHERIT drift must be real");
    let inherit_verdict = tenant_reader_gate_verdict(&reader_config).await?;
    let inherit_after_probe: bool = sqlx::query_scalar(
        "SELECT rolinherit FROM pg_catalog.pg_roles WHERE rolname = 'rss_app_read'",
    )
    .fetch_one(&owner.pool)
    .await?;
    assert!(
        inherit_after_probe,
        "reader probe must observe role drift without healing it"
    );
    assert!(matches!(
        inherit_verdict,
        Err(crate::PgError::TenantReadRoleAttributes)
    ));
    sqlx::query("ALTER ROLE rss_app_read NOINHERIT")
        .execute(&owner.pool)
        .await?;

    sqlx::query("CREATE ROLE tenant_reader_forbidden_parent NOLOGIN")
        .execute(&owner.pool)
        .await?;
    sqlx::query("GRANT tenant_reader_forbidden_parent TO rss_app_read")
        .execute(&owner.pool)
        .await?;
    assert!(matches!(
        tenant_reader_gate_verdict(&reader_config).await?,
        Err(crate::PgError::TenantReadMembership)
    ));
    sqlx::query("REVOKE tenant_reader_forbidden_parent FROM rss_app_read")
        .execute(&owner.pool)
        .await?;
    sqlx::query("DROP ROLE tenant_reader_forbidden_parent")
        .execute(&owner.pool)
        .await?;

    sqlx::query("CREATE TABLE tenant_reader_forbidden_owned (id integer PRIMARY KEY)")
        .execute(&owner.pool)
        .await?;
    sqlx::query("ALTER TABLE tenant_reader_forbidden_owned OWNER TO rss_app_read")
        .execute(&owner.pool)
        .await?;
    assert!(matches!(
        tenant_reader_gate_verdict(&reader_config).await?,
        Err(crate::PgError::TenantReadOwnership)
    ));
    sqlx::query("DROP TABLE tenant_reader_forbidden_owned")
        .execute(&owner.pool)
        .await?;

    let grant_temporary = format!(
        "GRANT TEMPORARY ON DATABASE \"{}\" TO rss_app_read",
        pg.owner_params().database.replace('"', "\"\"")
    );
    sqlx::query(&grant_temporary).execute(&owner.pool).await?;
    assert!(matches!(
        tenant_reader_gate_verdict(&reader_config).await?,
        Err(crate::PgError::TenantReadDatabasePrivileges)
    ));
    let revoke_temporary = format!(
        "REVOKE TEMPORARY ON DATABASE \"{}\" FROM rss_app_read",
        pg.owner_params().database.replace('"', "\"\"")
    );
    sqlx::query(&revoke_temporary).execute(&owner.pool).await?;

    let grant_connect_option = format!(
        "GRANT CONNECT ON DATABASE \"{}\" TO rss_app_read WITH GRANT OPTION",
        pg.owner_params().database.replace('"', "\"\"")
    );
    sqlx::query(&grant_connect_option)
        .execute(&owner.pool)
        .await?;
    assert!(matches!(
        tenant_reader_gate_verdict(&reader_config).await?,
        Err(crate::PgError::TenantReadDatabasePrivileges)
    ));
    let revoke_connect_option = format!(
        "REVOKE GRANT OPTION FOR CONNECT ON DATABASE \"{}\" FROM rss_app_read",
        pg.owner_params().database.replace('"', "\"\"")
    );
    sqlx::query(&revoke_connect_option)
        .execute(&owner.pool)
        .await?;

    sqlx::query("GRANT USAGE ON SEQUENCE auth_audit_events_id_seq TO rss_app_read")
        .execute(&owner.pool)
        .await?;
    assert!(matches!(
        tenant_reader_gate_verdict(&reader_config).await?,
        Err(crate::PgError::TenantReadSequencePrivileges)
    ));
    sqlx::query("REVOKE ALL ON SEQUENCE auth_audit_events_id_seq FROM rss_app_read")
        .execute(&owner.pool)
        .await?;

    sqlx::query("CREATE SCHEMA tenant_reader_forbidden_schema")
        .execute(&owner.pool)
        .await?;
    sqlx::query("GRANT USAGE ON SCHEMA tenant_reader_forbidden_schema TO rss_app_read")
        .execute(&owner.pool)
        .await?;
    assert!(matches!(
        tenant_reader_gate_verdict(&reader_config).await?,
        Err(crate::PgError::TenantReadSchemaPrivileges)
    ));
    sqlx::query("DROP SCHEMA tenant_reader_forbidden_schema")
        .execute(&owner.pool)
        .await?;

    sqlx::query("GRANT USAGE ON SCHEMA public TO rss_app_read WITH GRANT OPTION")
        .execute(&owner.pool)
        .await?;
    assert!(matches!(
        tenant_reader_gate_verdict(&reader_config).await?,
        Err(crate::PgError::TenantReadSchemaPrivileges)
    ));
    sqlx::query("REVOKE GRANT OPTION FOR USAGE ON SCHEMA public FROM rss_app_read")
        .execute(&owner.pool)
        .await?;

    sqlx::query(
        "CREATE FUNCTION tenant_reader_forbidden_function() RETURNS integer \
         LANGUAGE sql IMMUTABLE AS 'SELECT 1'",
    )
    .execute(&owner.pool)
    .await?;
    let public_function_verdict = tenant_reader_gate_verdict(&reader_config).await?;
    assert!(matches!(
        public_function_verdict,
        Err(crate::PgError::TenantReadFunctionPrivileges { .. })
    ));
    sqlx::query("REVOKE ALL ON FUNCTION tenant_reader_forbidden_function() FROM PUBLIC")
        .execute(&owner.pool)
        .await?;
    sqlx::query("GRANT EXECUTE ON FUNCTION tenant_reader_forbidden_function() TO rss_app_read")
        .execute(&owner.pool)
        .await?;
    assert!(matches!(
        tenant_reader_gate_verdict(&reader_config).await?,
        Err(crate::PgError::TenantReadFunctionPrivileges { .. })
    ));
    sqlx::query("DROP FUNCTION tenant_reader_forbidden_function()")
        .execute(&owner.pool)
        .await?;

    sqlx::query("GRANT EXECUTE ON FUNCTION pg_catalog.lo_create(oid) TO rss_app_read")
        .execute(&owner.pool)
        .await?;
    let lo_mutator_verdict = tenant_reader_gate_verdict(&reader_config).await?;
    sqlx::query("REVOKE EXECUTE ON FUNCTION pg_catalog.lo_create(oid) FROM rss_app_read")
        .execute(&owner.pool)
        .await?;
    assert!(matches!(
        lo_mutator_verdict,
        Err(crate::PgError::TenantReadLargeObjectMutatorPrivileges)
    ));

    let large_object_oid: i64 =
        sqlx::query_scalar("SELECT lo_from_bytea(0, decode('726561646572', 'hex'))::bigint")
            .fetch_one(&owner.pool)
            .await?;
    sqlx::query(&format!(
        "GRANT SELECT ON LARGE OBJECT {large_object_oid} TO rss_app_read"
    ))
    .execute(&owner.pool)
    .await?;
    let reader = PgStore::connect(reader_config.as_pg_config()).await?;
    let large_object_bytes: Vec<u8> =
        sqlx::query_scalar(&format!("SELECT lo_get({large_object_oid}::oid)"))
            .fetch_one(&reader.pool)
            .await?;
    assert_eq!(large_object_bytes, b"reader");
    reader.shutdown().await?;
    let large_object_verdict = tenant_reader_gate_verdict(&reader_config).await?;
    sqlx::query(&format!(
        "REVOKE ALL PRIVILEGES ON LARGE OBJECT {large_object_oid} FROM rss_app_read"
    ))
    .execute(&owner.pool)
    .await?;
    assert!(matches!(
        large_object_verdict,
        Err(crate::PgError::TenantReadLargeObjectPrivileges)
    ));

    sqlx::query(&format!(
        "GRANT SELECT ON LARGE OBJECT {large_object_oid} TO PUBLIC"
    ))
    .execute(&owner.pool)
    .await?;
    let reader = PgStore::connect(reader_config.as_pg_config()).await?;
    let public_large_object_bytes: Vec<u8> =
        sqlx::query_scalar(&format!("SELECT lo_get({large_object_oid}::oid)"))
            .fetch_one(&reader.pool)
            .await?;
    assert_eq!(public_large_object_bytes, b"reader");
    reader.shutdown().await?;
    let public_large_object_verdict = tenant_reader_gate_verdict(&reader_config).await?;
    sqlx::query(&format!(
        "REVOKE ALL PRIVILEGES ON LARGE OBJECT {large_object_oid} FROM PUBLIC"
    ))
    .execute(&owner.pool)
    .await?;
    assert!(matches!(
        public_large_object_verdict,
        Err(crate::PgError::TenantReadLargeObjectPrivileges)
    ));

    sqlx::query(&format!(
        "GRANT SELECT ON LARGE OBJECT {large_object_oid} TO rss_app_read WITH GRANT OPTION"
    ))
    .execute(&owner.pool)
    .await?;
    let large_object_grantable: bool = sqlx::query_scalar(&format!(
        "SELECT bool_or(acl.is_grantable) FROM pg_largeobject_metadata object \
         CROSS JOIN LATERAL aclexplode(object.lomacl) acl \
         WHERE object.oid = {large_object_oid}::oid \
           AND acl.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'rss_app_read')"
    ))
    .fetch_one(&owner.pool)
    .await?;
    assert!(large_object_grantable);
    let large_object_grant_option_verdict = tenant_reader_gate_verdict(&reader_config).await?;
    sqlx::query(&format!(
        "REVOKE ALL PRIVILEGES ON LARGE OBJECT {large_object_oid} FROM rss_app_read"
    ))
    .execute(&owner.pool)
    .await?;
    assert!(matches!(
        large_object_grant_option_verdict,
        Err(crate::PgError::TenantReadLargeObjectPrivileges)
    ));
    sqlx::query(&format!("SELECT lo_unlink({large_object_oid}::oid)"))
        .execute(&owner.pool)
        .await?;

    sqlx::query("GRANT ALTER SYSTEM ON PARAMETER work_mem TO rss_app_read")
        .execute(&owner.pool)
        .await?;
    let reader = PgStore::connect(reader_config.as_pg_config()).await?;
    let can_alter_system: bool = sqlx::query_scalar(
        "SELECT has_parameter_privilege(current_user, 'work_mem', 'ALTER SYSTEM')",
    )
    .fetch_one(&reader.pool)
    .await?;
    assert!(
        can_alter_system,
        "synthetic parameter ACL drift must be effective"
    );
    reader.shutdown().await?;
    let parameter_verdict = tenant_reader_gate_verdict(&reader_config).await?;
    sqlx::query("REVOKE ALL PRIVILEGES ON PARAMETER work_mem FROM rss_app_read")
        .execute(&owner.pool)
        .await?;
    assert!(matches!(
        parameter_verdict,
        Err(crate::PgError::TenantReadParameterPrivileges)
    ));

    sqlx::query("GRANT SET ON PARAMETER work_mem TO PUBLIC")
        .execute(&owner.pool)
        .await?;
    let reader = PgStore::connect(reader_config.as_pg_config()).await?;
    let public_can_set: bool =
        sqlx::query_scalar("SELECT has_parameter_privilege(current_user, 'work_mem', 'SET')")
            .fetch_one(&reader.pool)
            .await?;
    assert!(public_can_set, "PUBLIC parameter drift must be effective");
    reader.shutdown().await?;
    let public_parameter_verdict = tenant_reader_gate_verdict(&reader_config).await?;
    sqlx::query("REVOKE ALL PRIVILEGES ON PARAMETER work_mem FROM PUBLIC")
        .execute(&owner.pool)
        .await?;
    assert!(matches!(
        public_parameter_verdict,
        Err(crate::PgError::TenantReadParameterPrivileges)
    ));

    sqlx::query("GRANT ALTER SYSTEM ON PARAMETER work_mem TO rss_app_read WITH GRANT OPTION")
        .execute(&owner.pool)
        .await?;
    let parameter_grantable: bool = sqlx::query_scalar(
        "SELECT bool_or(acl.is_grantable) FROM pg_parameter_acl parameter \
         CROSS JOIN LATERAL aclexplode(parameter.paracl) acl \
         WHERE parameter.parname = 'work_mem' \
           AND acl.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'rss_app_read')",
    )
    .fetch_one(&owner.pool)
    .await?;
    assert!(parameter_grantable);
    let parameter_grant_option_verdict = tenant_reader_gate_verdict(&reader_config).await?;
    sqlx::query("REVOKE ALL PRIVILEGES ON PARAMETER work_mem FROM rss_app_read")
        .execute(&owner.pool)
        .await?;
    assert!(matches!(
        parameter_grant_option_verdict,
        Err(crate::PgError::TenantReadParameterPrivileges)
    ));

    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn tenant_reader_gate_rejects_active_resolver_body_drift() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let reader_config = rss_app_read_config(&pg, &owner).await?;
    let original_definition: String = sqlx::query_scalar(
        "SELECT pg_catalog.pg_get_functiondef(\
             'public.rss_settings_projection_resolve_active()'::regprocedure\
         )",
    )
    .fetch_one(&owner.pool)
    .await?;

    sqlx::query(
        r#"
        CREATE OR REPLACE FUNCTION public.rss_settings_projection_resolve_active()
        RETURNS TABLE (
            generation text,
            definition_version text,
            definition_schema_digest text,
            input_generation text,
            promoted_high_water_lsn bigint,
            token bigint
        )
        LANGUAGE plpgsql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$ BEGIN RETURN; END; $function$
        "#,
    )
    .execute(&owner.pool)
    .await?;
    let verdict = tenant_reader_gate_verdict(&reader_config).await?;
    sqlx::query(&original_definition)
        .execute(&owner.pool)
        .await?;

    assert!(matches!(
        verdict,
        Err(crate::PgError::TenantReadFunctionDefinition { .. })
    ));
    owner.shutdown().await?;
    Ok(())
}

async fn assert_inbox_function_posture_drift(
    reader_config: &crate::pool::PgTenantReadConfig,
    owner: &PgStore,
    drift: &str,
    restore: &str,
) -> TestResult {
    sqlx::query(drift).execute(&owner.pool).await?;
    let verdict = tenant_reader_gate_verdict(reader_config).await?;
    sqlx::query(restore).execute(&owner.pool).await?;
    assert!(
        matches!(
            verdict,
            Err(crate::PgError::TenantReadFunctionPrivileges { .. })
        ),
        "inbox SECURITY DEFINER posture drift must fail closed: {verdict:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn tenant_reader_gate_rejects_inbox_function_posture_and_body_drift() -> TestResult {
    const FUNCTION: &str = "public.rss_inbox_sample_backlog(text[])";
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let reader_config = rss_app_read_config(&pg, &owner).await?;

    for (drift, restore) in [
        (
            format!("ALTER FUNCTION {FUNCTION} SECURITY INVOKER"),
            format!("ALTER FUNCTION {FUNCTION} SECURITY DEFINER"),
        ),
        (
            format!("ALTER FUNCTION {FUNCTION} RESET search_path"),
            format!("ALTER FUNCTION {FUNCTION} SET search_path TO pg_catalog, pg_temp"),
        ),
        (
            "ALTER ROLE rss_inbox_receipt_maintenance LOGIN".to_owned(),
            "ALTER ROLE rss_inbox_receipt_maintenance NOLOGIN".to_owned(),
        ),
        (
            "GRANT rss_app_read TO rss_inbox_receipt_maintenance".to_owned(),
            "REVOKE rss_app_read FROM rss_inbox_receipt_maintenance".to_owned(),
        ),
        (
            format!("GRANT EXECUTE ON FUNCTION {FUNCTION} TO PUBLIC"),
            format!("REVOKE EXECUTE ON FUNCTION {FUNCTION} FROM PUBLIC"),
        ),
    ] {
        assert_inbox_function_posture_drift(&reader_config, &owner, &drift, &restore).await?;
    }

    let original_definition: String = sqlx::query_scalar(&format!(
        "SELECT pg_catalog.pg_get_functiondef('{FUNCTION}'::regprocedure)"
    ))
    .fetch_one(&owner.pool)
    .await?;
    sqlx::raw_sql(
        r#"
        CREATE OR REPLACE FUNCTION public.rss_inbox_sample_backlog(p_consumer_groups text[])
        RETURNS TABLE (
            tenant_id uuid,
            consumer_group text,
            depth bigint,
            oldest_age_seconds bigint
        )
        LANGUAGE plpgsql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$ BEGIN RETURN; END; $function$
        "#,
    )
    .execute(&owner.pool)
    .await?;
    let body_verdict = tenant_reader_gate_verdict(&reader_config).await?;
    sqlx::raw_sql(&original_definition)
        .execute(&owner.pool)
        .await?;
    assert!(
        matches!(
            body_verdict,
            Err(crate::PgError::TenantReadFunctionDefinition { .. })
        ),
        "inbox function body drift must fail closed: {body_verdict:?}"
    );

    owner.shutdown().await?;
    Ok(())
}

/// RLS 能力门反例（fail-closed）：存在含 `tenant_id` 列却**无** RLS 的表 → `Err(RlsNotEnforced)`。
/// throwaway 表经 owner 建，能力门经**非绕过角色**判定（pg_catalog 不受权限过滤、仍可见该表）；DROP 还原。
#[tokio::test(flavor = "multi_thread")]
async fn verify_rls_capability_rejects_tenant_table_without_rls() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS _rls_probe_bad (tenant_id uuid NOT NULL, x int)")
        .execute(&store.pool)
        .await?;
    let app = connect_pg_rss_app_role(&_pg, &store).await?;
    let verdict = app.verify_rls_capability().await;
    sqlx::query("DROP TABLE IF EXISTS _rls_probe_bad")
        .execute(&store.pool)
        .await?;
    assert!(
        matches!(verdict, Err(crate::PgError::RlsNotEnforced { .. })),
        "含 tenant_id 列却无 FORCE RLS 的表应使能力门 fail-closed，实得: {verdict:?}"
    );
    app.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

/// RLS 能力门反例：仅 ENABLE、无 FORCE → 仍 `Err(RlsNotEnforced)`（owner 可绕过 policy）。
#[tokio::test(flavor = "multi_thread")]
async fn verify_rls_capability_rejects_enable_without_force() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    for stmt in [
        "CREATE TABLE IF NOT EXISTS _rls_probe_enable_only (tenant_id uuid NOT NULL, x int)",
        "ALTER TABLE _rls_probe_enable_only ENABLE ROW LEVEL SECURITY",
        "CREATE POLICY tenant_isolation ON _rls_probe_enable_only \
         USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid) \
         WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)",
    ] {
        sqlx::query(stmt).execute(&store.pool).await?;
    }
    let app = connect_pg_rss_app_role(&_pg, &store).await?;
    let verdict = app.verify_rls_capability().await;
    sqlx::query("DROP TABLE IF EXISTS _rls_probe_enable_only")
        .execute(&store.pool)
        .await?;
    assert!(
        matches!(verdict, Err(crate::PgError::RlsNotEnforced { .. })),
        "ENABLE without FORCE must fail closed, got: {verdict:?}"
    );
    app.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

/// RLS 能力门反例（policy 内容校验 + OR-widening）：tenant 表有 canonical policy，但第二条 permissive
/// policy 为 `USING/WITH CHECK (true)` → 仍 `Err(RlsNotEnforced)`。守「至少一条正确但另一条放宽」
/// 的运行时隔离静默失效路径（能力门校验 policy 内容、非仅存在性；live catalog 为权威证明）。
/// 经**非绕过角色**判定；throwaway 表隔离 + DROP 还原。
#[tokio::test(flavor = "multi_thread")]
async fn verify_rls_capability_rejects_permissive_policy() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    for stmt in [
        "CREATE TABLE IF NOT EXISTS _rls_probe_permissive (tenant_id uuid NOT NULL, x int)",
        "ALTER TABLE _rls_probe_permissive ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE _rls_probe_permissive FORCE ROW LEVEL SECURITY",
        "CREATE POLICY tenant_isolation ON _rls_probe_permissive USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)",
        "CREATE POLICY allow_all ON _rls_probe_permissive USING (true) WITH CHECK (true)",
    ] {
        sqlx::query(stmt).execute(&store.pool).await?;
    }
    let app = connect_pg_rss_app_role(&_pg, &store).await?;
    let verdict = app.verify_rls_capability().await;
    sqlx::query("DROP TABLE IF EXISTS _rls_probe_permissive")
        .execute(&store.pool)
        .await?;
    assert!(
        matches!(verdict, Err(crate::PgError::RlsNotEnforced { .. })),
        "canonical policy 加第二条 allow-all permissive policy 应 fail-closed，实得: {verdict:?}"
    );
    app.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn tenant_reader_gate_rejects_semantically_inverted_canonical_policies() -> TestResult {
    let (fixture, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let reader_config = rss_app_read_config(&fixture, &owner).await?;
    for (table, predicate) in [
        (
            "_rls_probe_not_canonical",
            "NOT (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)",
        ),
        (
            "_rls_probe_false_canonical",
            "(tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid) = false",
        ),
    ] {
        sqlx::query(&format!(
            "CREATE TABLE {table} (tenant_id uuid NOT NULL, x integer)"
        ))
        .execute(&owner.pool)
        .await?;
        sqlx::raw_sql(&format!(
            "ALTER TABLE {table} ENABLE ROW LEVEL SECURITY; \
             ALTER TABLE {table} FORCE ROW LEVEL SECURITY; \
             CREATE POLICY tenant_isolation ON {table} USING ({predicate}) WITH CHECK ({predicate}); \
             GRANT SELECT ON {table} TO rss_app_read"
        ))
        .execute(&owner.pool)
        .await?;

        let verdict = tenant_reader_gate_verdict(&reader_config).await?;
        sqlx::query(&format!("DROP TABLE {table}"))
            .execute(&owner.pool)
            .await?;
        assert!(
            matches!(verdict, Err(crate::PgError::RlsNotEnforced { .. })),
            "semantically inverted canonical predicate must fail closed: {predicate}; {verdict:?}"
        );
    }
    owner.shutdown().await?;
    Ok(())
}

/// A policy created under a hostile search_path can deparse to the canonical text while retaining
/// a user-defined `=` operator OID. Prove the exploit reads both tenants, then prove the catalog
/// dependency gate rejects it even after the function EXECUTE ACL is removed from the reader.
#[tokio::test(flavor = "multi_thread")]
async fn tenant_reader_gate_rejects_same_text_custom_operator_policy() -> TestResult {
    let (fixture, admin) = connect_pg().await?;
    let database = create_isolated_database(&admin, "tenant_reader_operator_shadow").await?;
    let owner_config = isolated_database_config(fixture.owner_params(), &database);
    let reader_config = isolated_tenant_read_config(fixture.owner_params(), &database);

    let verdict: TestResult = async {
        let owner = PgStore::connect(&owner_config).await?;
        owner.run_migrations().await?;
        sqlx::query(&format!(
            "ALTER ROLE {TEST_READ_ROLE} PASSWORD '{TEST_READ_PASSWORD}'"
        ))
        .execute(&owner.pool)
        .await?;
        sqlx::raw_sql(
            r#"
            CREATE FUNCTION public.tenant_reader_always_true(uuid, uuid)
                RETURNS boolean LANGUAGE sql IMMUTABLE AS 'SELECT true';
            CREATE OPERATOR public.= (
                LEFTARG = uuid,
                RIGHTARG = uuid,
                FUNCTION = public.tenant_reader_always_true
            );
            SET search_path = public, pg_catalog;
            CREATE TABLE public._tenant_reader_operator_shadow (
                tenant_id uuid NOT NULL,
                value text NOT NULL
            );
            ALTER TABLE public._tenant_reader_operator_shadow ENABLE ROW LEVEL SECURITY;
            ALTER TABLE public._tenant_reader_operator_shadow FORCE ROW LEVEL SECURITY;
            CREATE POLICY tenant_isolation ON public._tenant_reader_operator_shadow
                USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
                WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
            RESET search_path;
            GRANT SELECT ON public._tenant_reader_operator_shadow TO rss_app_read;
            INSERT INTO public._tenant_reader_operator_shadow (tenant_id, value) VALUES
                ('00000000-0000-4000-8000-000000000001', 'tenant-a'),
                ('00000000-0000-4000-8000-000000000002', 'tenant-b');
            "#,
        )
        .execute(&owner.pool)
        .await?;

        let reader = PgStore::connect(reader_config.as_pg_config()).await?;
        let mut read_tx = reader.pool.begin_with("BEGIN READ ONLY").await?;
        crate::cotx::set_local_tenant(
            &mut read_tx,
            rss_request_context::TenantId::parse("00000000-0000-4000-8000-000000000001")?,
        )
        .await?;
        let visible: i64 =
            sqlx::query_scalar("SELECT count(*) FROM public._tenant_reader_operator_shadow")
                .fetch_one(&mut *read_tx)
                .await?;
        read_tx.rollback().await?;
        assert_eq!(
            visible, 2,
            "the custom operator must be a real cross-tenant bypass, not catalog-only drift"
        );

        sqlx::query(
            "REVOKE EXECUTE ON FUNCTION public.tenant_reader_always_true(uuid, uuid) FROM PUBLIC",
        )
        .execute(&owner.pool)
        .await?;
        let gate = reader.verify_tenant_read_capability().await;
        assert!(
            matches!(gate, Err(crate::PgError::RlsNotEnforced { .. })),
            "non-pinned policy dependencies must fail the RLS gate: {gate:?}"
        );
        reader.shutdown().await?;

        sqlx::raw_sql(
            "DROP TABLE public._tenant_reader_operator_shadow; \
             DROP OPERATOR public.= (uuid, uuid); \
             DROP FUNCTION public.tenant_reader_always_true(uuid, uuid)",
        )
        .execute(&owner.pool)
        .await?;
        owner.shutdown().await?;
        Ok(())
    }
    .await;

    let cleanup = drop_isolated_database(&admin, &database).await;
    admin.shutdown().await?;
    cleanup?;
    verdict
}

/// PostgreSQL's compatibility mode intentionally bypasses LO ACL checks for reads. The reader
/// startup gate must therefore reject the setting itself, even when no reader/PUBLIC LO ACL exists.
#[tokio::test(flavor = "multi_thread")]
async fn tenant_reader_gate_rejects_large_object_compatibility_mode() -> TestResult {
    let (fixture, admin) = connect_pg().await?;
    let database = create_isolated_database(&admin, "tenant_reader_lo_compat").await?;
    let owner_config = isolated_database_config(fixture.owner_params(), &database);
    let reader_config = isolated_tenant_read_config(fixture.owner_params(), &database);

    let verdict: TestResult = async {
        let owner = PgStore::connect(&owner_config).await?;
        owner.run_migrations().await?;
        sqlx::query(&format!(
            "ALTER ROLE {TEST_READ_ROLE} PASSWORD '{TEST_READ_PASSWORD}'"
        ))
        .execute(&owner.pool)
        .await?;
        let large_object_oid: i64 =
            sqlx::query_scalar("SELECT lo_from_bytea(0, decode('636f6d706174', 'hex'))::bigint")
                .fetch_one(&owner.pool)
                .await?;
        sqlx::raw_sql(&format!(
            "REVOKE ALL PRIVILEGES ON LARGE OBJECT {large_object_oid} FROM PUBLIC; \
             REVOKE ALL PRIVILEGES ON LARGE OBJECT {large_object_oid} FROM rss_app_read; \
             ALTER DATABASE \"{database}\" SET lo_compat_privileges = 'on'"
        ))
        .execute(&owner.pool)
        .await?;

        let reader = PgStore::connect(reader_config.as_pg_config()).await?;
        let bytes: Vec<u8> = sqlx::query_scalar(&format!("SELECT lo_get({large_object_oid}::oid)"))
            .fetch_one(&reader.pool)
            .await?;
        assert_eq!(
            bytes, b"compat",
            "lo_compat_privileges=on must demonstrably bypass an empty reader ACL"
        );
        let gate = reader.verify_tenant_read_capability().await;
        assert!(matches!(
            gate,
            Err(crate::PgError::TenantReadLargeObjectCompatibility)
        ));
        reader.shutdown().await?;

        sqlx::query(&format!(
            "ALTER DATABASE \"{database}\" RESET lo_compat_privileges"
        ))
        .execute(&owner.pool)
        .await?;
        sqlx::query(&format!("SELECT lo_unlink({large_object_oid}::oid)"))
            .execute(&owner.pool)
            .await?;
        owner.shutdown().await?;
        Ok(())
    }
    .await;

    let cleanup = drop_isolated_database(&admin, &database).await;
    admin.shutdown().await?;
    cleanup?;
    verdict
}

/// 写侧缺 WITH CHECK 必须被运行时 capability gate 拒绝。
#[tokio::test(flavor = "multi_thread")]
async fn verify_rls_capability_rejects_missing_with_check() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    for stmt in [
        "CREATE TABLE IF NOT EXISTS _rls_probe_missing_check (tenant_id uuid NOT NULL, x int)",
        "ALTER TABLE _rls_probe_missing_check ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE _rls_probe_missing_check FORCE ROW LEVEL SECURITY",
        "CREATE POLICY tenant_isolation ON _rls_probe_missing_check USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)",
    ] {
        sqlx::query(stmt).execute(&store.pool).await?;
    }
    let app = connect_pg_rss_app_role(&_pg, &store).await?;
    let verdict = app.verify_rls_capability().await;
    sqlx::query("DROP TABLE IF EXISTS _rls_probe_missing_check")
        .execute(&store.pool)
        .await?;
    assert!(
        matches!(verdict, Err(crate::PgError::RlsNotEnforced { .. })),
        "缺 WITH CHECK 应 fail-closed，实得: {verdict:?}"
    );
    app.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

/// 仅含 tenant/GUC token、但没有等值绑定的 policy 必须被 runtime gate 拒绝。
#[tokio::test(flavor = "multi_thread")]
async fn verify_rls_capability_rejects_token_stuffing_without_tenant_equality() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    for stmt in [
        "CREATE TABLE IF NOT EXISTS _rls_probe_token_stuffing (tenant_id uuid NOT NULL, x int)",
        "ALTER TABLE _rls_probe_token_stuffing ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE _rls_probe_token_stuffing FORCE ROW LEVEL SECURITY",
        "CREATE POLICY tenant_isolation ON _rls_probe_token_stuffing USING (tenant_id IS NOT NULL AND current_setting('rss.tenant_id', true) IS NOT NULL) WITH CHECK (tenant_id IS NOT NULL AND current_setting('rss.tenant_id', true) IS NOT NULL)",
    ] {
        sqlx::query(stmt).execute(&store.pool).await?;
    }
    let app = connect_pg_rss_app_role(&_pg, &store).await?;
    let verdict = app.verify_rls_capability().await;
    sqlx::query("DROP TABLE IF EXISTS _rls_probe_token_stuffing")
        .execute(&store.pool)
        .await?;
    assert!(
        matches!(verdict, Err(crate::PgError::RlsNotEnforced { .. })),
        "token stuffing without tenant equality must fail closed, got: {verdict:?}"
    );
    app.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

/// inbox_receipts RLS/grant lock (#1626).
///
/// The table is mutable claim state, so rss_app needs DML privileges, but every
/// row must still be scoped by FORCE RLS and the standard tenant isolation policy.
#[tokio::test(flavor = "multi_thread")]
async fn inbox_receipts_rls_grants_and_tenant_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let (rls_enabled, rls_forced, can_select, can_insert, can_update, can_delete): (
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
    ) = sqlx::query_as(
        "SELECT c.relrowsecurity, c.relforcerowsecurity, \
                has_table_privilege('rss_app', 'inbox_receipts', 'SELECT'), \
                has_table_privilege('rss_app', 'inbox_receipts', 'INSERT'), \
                has_table_privilege('rss_app', 'inbox_receipts', 'UPDATE'), \
                has_table_privilege('rss_app', 'inbox_receipts', 'DELETE') \
         FROM pg_class c \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relname = 'inbox_receipts'",
    )
    .fetch_one(&store.pool)
    .await?;
    assert!(rls_enabled, "inbox_receipts must ENABLE RLS");
    assert!(rls_forced, "inbox_receipts must FORCE RLS");
    assert!(can_select, "rss_app must SELECT inbox_receipts");
    assert!(can_insert, "rss_app must INSERT inbox_receipts");
    assert!(can_update, "rss_app must UPDATE inbox_receipts");
    assert!(
        can_delete,
        "rss_app must DELETE inbox_receipts for release/sweep mutable state paths"
    );

    let (qual, with_check): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT qual, with_check \
         FROM pg_policies \
         WHERE schemaname = 'public' \
           AND tablename = 'inbox_receipts' \
           AND policyname = 'tenant_isolation'",
    )
    .fetch_one(&store.pool)
    .await?;
    for body in [qual.as_deref(), with_check.as_deref()] {
        let body = body.ok_or_else(|| {
            std::io::Error::other("tenant_isolation policy must define both USING and WITH CHECK")
        })?;
        assert!(
            body.to_lowercase().contains("nullif(current_setting"),
            "tenant_isolation policy must use NULLIF(current_setting(...)): {body}"
        );
        assert!(
            body.contains("rss.tenant_id"),
            "tenant_isolation policy must reference rss.tenant_id: {body}"
        );
    }

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let event_id = format!("receipt-{}", uuid::Uuid::new_v4());
    let group = format!("receipt-group-{}", uuid::Uuid::new_v4());

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO inbox_receipts \
             (tenant_id, event_id, consumer_group, domain, topic, contract_id, \
              contract_version, schema_hash, trace, correlation_id, status, lease_token, receive_count) \
             VALUES \
             ($1::uuid, $2, $3, 'identity', 'identity.session-created', \
              'identity.session-created', 'v1', $4, '00-00000000000000000000000000000000-0000000000000000-00', \
              'corr-receipt', 'claimed', gen_random_uuid(), 1)",
        )
        .bind(&tenant_a)
        .bind(&event_id)
        .bind(&group)
        .bind(TEST_SCHEMA_HASH)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM inbox_receipts WHERE event_id = $1 AND consumer_group = $2",
        )
        .bind(&event_id)
        .bind(&group)
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(cnt.0, 1, "tenant A scope must see tenant A receipt");
        tx.rollback().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_b)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM inbox_receipts WHERE event_id = $1 AND consumer_group = $2",
        )
        .bind(&event_id)
        .bind(&group)
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(cnt.0, 0, "tenant B scope must not see tenant A receipt");

        let denied = sqlx::query(
            "INSERT INTO inbox_receipts \
             (tenant_id, event_id, consumer_group, domain, topic, contract_id, \
              contract_version, schema_hash, status, lease_token, receive_count) \
             VALUES \
             ($1::uuid, 'receipt-denied', 'receipt-denied-group', 'identity', \
              'identity.session-created', 'identity.session-created', 'v1', $2, \
              'claimed', gen_random_uuid(), 1)",
        )
        .bind(&tenant_a)
        .bind(TEST_SCHEMA_HASH)
        .execute(&mut *tx)
        .await;
        assert!(
            denied.is_err(),
            "tenant B scope must not insert a tenant A receipt"
        );
        tx.rollback().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM inbox_receipts WHERE event_id = $1 AND consumer_group = $2",
        )
        .bind(&event_id)
        .bind(&group)
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(
            cnt.0, 0,
            "missing rss.tenant_id must fail closed for inbox_receipts"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn command_journal_schema_rls_grants_after_migrations() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let (rls_enabled, rls_forced, can_select, can_insert, can_update, can_delete): (
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
    ) = sqlx::query_as(
        "SELECT c.relrowsecurity, c.relforcerowsecurity, \
                has_table_privilege('rss_app', 'command_journal', 'SELECT'), \
                has_table_privilege('rss_app', 'command_journal', 'INSERT'), \
                has_table_privilege('rss_app', 'command_journal', 'UPDATE'), \
                has_table_privilege('rss_app', 'command_journal', 'DELETE') \
         FROM pg_class c \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relname = 'command_journal'",
    )
    .fetch_one(&store.pool)
    .await?;
    assert!(rls_enabled, "command_journal must ENABLE RLS");
    assert!(rls_forced, "command_journal must FORCE RLS");
    assert!(can_select, "rss_app must SELECT command_journal");
    assert!(can_insert, "rss_app must INSERT command_journal");
    assert!(can_update, "rss_app must UPDATE command_journal");
    assert!(!can_delete, "rss_app must not DELETE command_journal");

    let pk_columns: (String,) = sqlx::query_as(
        "SELECT string_agg(a.attname, ',' ORDER BY k.ord) \
         FROM pg_constraint c \
         JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord) ON true \
         JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum \
         WHERE c.conrelid = 'command_journal'::regclass AND c.contype = 'p'",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        pk_columns.0, "tenant_id,command_id",
        "command_journal primary key must be tenant-first"
    );

    let constraint_text: Vec<(String, String)> = sqlx::query_as(
        "SELECT conname, pg_get_constraintdef(oid) \
         FROM pg_constraint \
         WHERE conrelid = 'command_journal'::regclass \
         ORDER BY conname",
    )
    .fetch_all(&store.pool)
    .await?;
    let constraint_text = constraint_text
        .iter()
        .map(|(name, def)| format!("{name}: {def}"))
        .collect::<Vec<_>>()
        .join("\n");
    for name in [
        "command_journal_command_id_valid",
        "command_journal_fingerprint_valid",
        "command_journal_outbox_event_id_valid",
        "command_journal_status_valid",
        "command_journal_attempt_positive",
        "command_journal_terminal_summary_matches_status",
    ] {
        assert!(
            constraint_text.contains(name),
            "missing command_journal constraint `{name}` in:\n{constraint_text}"
        );
    }
    let legacy_key_column: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'command_journal' \
           AND column_name = 'idempotency_key'",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        legacy_key_column.0, 0,
        "raw idempotency keys must not be persisted"
    );

    let alias_constraints: Vec<(String,)> = sqlx::query_as(
        "SELECT conname FROM pg_constraint \
         WHERE conrelid = 'command_idempotency_aliases'::regclass ORDER BY conname",
    )
    .fetch_all(&store.pool)
    .await?;
    let alias_constraints = alias_constraints
        .into_iter()
        .map(|(name,)| name)
        .collect::<Vec<_>>();
    for name in [
        "command_idempotency_aliases_pkey",
        "command_alias_topic_nonempty",
        "command_alias_key_id_valid",
        "command_alias_digest_256bit",
        "command_alias_command_id_valid",
    ] {
        assert!(
            alias_constraints.iter().any(|actual| actual == name),
            "missing command alias constraint `{name}` in {alias_constraints:?}"
        );
    }
    let alias_pk: (String,) = sqlx::query_as(
        "SELECT string_agg(a.attname, ',' ORDER BY k.ord) \
         FROM pg_constraint c \
         JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord) ON true \
         JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum \
         WHERE c.conrelid = 'command_idempotency_aliases'::regclass AND c.contype = 'p'",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(alias_pk.0, "tenant_id,topic,key_id,alias_digest");

    let (qual, with_check): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT qual, with_check \
         FROM pg_policies \
         WHERE schemaname = 'public' \
           AND tablename = 'command_journal' \
           AND policyname = 'tenant_isolation'",
    )
    .fetch_one(&store.pool)
    .await?;
    for body in [qual.as_deref(), with_check.as_deref()] {
        let body = body.ok_or_else(|| {
            std::io::Error::other("command_journal tenant policy missing USING/WITH CHECK")
        })?;
        assert!(
            body.to_lowercase().contains("nullif(current_setting"),
            "command_journal policy must use NULLIF(current_setting(...)): {body}"
        );
        assert!(
            body.contains("rss.tenant_id"),
            "command_journal policy must reference rss.tenant_id: {body}"
        );
    }

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;
    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let command_id = command_journal_command_id('a');
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO command_journal \
             (tenant_id, command_id, topic, contract_id, contract_version, \
              schema_hash, request_fingerprint, outbox_event_id) \
             VALUES ($1::uuid, $2, $3, 'test.contract', 'v1', $4, $5, $2)",
        )
        .bind(&tenant_a)
        .bind(&command_id)
        .bind(generated::command::_seed_v1::TOPIC)
        .bind(TEST_SCHEMA_HASH)
        .bind(command_journal_fingerprint('1'))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
    }

    for (tenant, expected, label) in [(&tenant_a, 1_i64, "tenant A"), (&tenant_b, 0, "tenant B")] {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(tenant)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) =
            sqlx::query_as("SELECT count(*) FROM command_journal WHERE command_id = $1")
                .bind(&command_id)
                .fetch_one(&mut *tx)
                .await?;
        assert_eq!(
            cnt.0, expected,
            "{label} command_journal visibility mismatch"
        );
        tx.rollback().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_b)
            .execute(&mut *tx)
            .await?;
        let denied = sqlx::query(
            "INSERT INTO command_journal \
             (tenant_id, command_id, topic, contract_id, contract_version, \
              schema_hash, request_fingerprint, outbox_event_id) \
             VALUES ($1::uuid, $2, $3, 'test.contract', 'v1', $4, $5, $2)",
        )
        .bind(&tenant_a)
        .bind(command_journal_command_id('c'))
        .bind(generated::command::_seed_v1::TOPIC)
        .bind(TEST_SCHEMA_HASH)
        .bind(command_journal_fingerprint('3'))
        .execute(&mut *tx)
        .await;
        assert!(
            denied.is_err(),
            "tenant B scope must not insert tenant A command_journal rows"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_rls_grants_and_tenant_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let grants: Vec<(String, bool, bool, bool, bool, bool, bool)> = sqlx::query_as(
        "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity, \
                has_table_privilege('rss_app', c.oid, 'SELECT'), \
                has_table_privilege('rss_app', c.oid, 'INSERT'), \
                has_table_privilege('rss_app', c.oid, 'UPDATE'), \
                has_table_privilege('rss_app', c.oid, 'DELETE') \
         FROM pg_class c \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' \
           AND c.relname IN ( \
             'reconcile_targets', 'reconcile_leases', \
             'reconcile_attempts', 'reconcile_actions', 'reconcile_attempt_results' \
           ) \
         ORDER BY c.relname",
    )
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(grants.len(), 5, "all reconcile tables must be inspected");
    for (table, rls_enabled, rls_forced, can_select, can_insert, can_update, can_delete) in grants {
        assert!(rls_enabled, "{table} must ENABLE RLS");
        assert!(rls_forced, "{table} must FORCE RLS");
        assert!(can_select, "rss_app must SELECT {table}");
        assert!(can_insert, "rss_app must INSERT {table}");
        match table.as_str() {
            "reconcile_targets" | "reconcile_leases" => {
                assert!(can_update, "rss_app must UPDATE mutable {table}");
                assert!(!can_delete, "rss_app must not DELETE mutable {table}");
            }
            "reconcile_attempts" | "reconcile_actions" | "reconcile_attempt_results" => {
                assert!(!can_update, "rss_app must not UPDATE append-only {table}");
                assert!(!can_delete, "rss_app must not DELETE append-only {table}");
            }
            _ => unreachable!("query filters table list"),
        }
    }

    let policies: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT tablename, qual, with_check \
         FROM pg_policies \
         WHERE schemaname = 'public' \
           AND tablename IN ( \
             'reconcile_targets', 'reconcile_leases', \
             'reconcile_attempts', 'reconcile_actions', 'reconcile_attempt_results' \
           ) \
           AND policyname = 'tenant_isolation' \
         ORDER BY tablename",
    )
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(policies.len(), 5, "all reconcile tables need tenant policy");
    for (table, qual, with_check) in policies {
        for body in [qual.as_deref(), with_check.as_deref()] {
            let body = body.ok_or_else(|| {
                std::io::Error::other(format!("{table} tenant policy missing USING/WITH CHECK"))
            })?;
            assert!(
                body.to_lowercase().contains("nullif(current_setting"),
                "{table} tenant policy must use NULLIF(current_setting(...)): {body}"
            );
            assert!(
                body.contains("rss.tenant_id"),
                "{table} tenant policy must reference rss.tenant_id: {body}"
            );
        }
    }

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let resource = format!("rls-device-{}", uuid::Uuid::new_v4());

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO reconcile_targets \
             (tenant_id, reconciler_id, resource_kind, resource_id) \
             VALUES ($1::uuid, 'rls-reconciler', 'device', $2)",
        )
        .bind(&tenant_a)
        .bind(&resource)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
    }

    for (tenant, expected, label) in [(&tenant_a, 1_i64, "tenant A"), (&tenant_b, 0, "tenant B")] {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(tenant)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM reconcile_targets \
             WHERE reconciler_id = 'rls-reconciler' AND resource_id = $1",
        )
        .bind(&resource)
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(cnt.0, expected, "{label} visibility mismatch");
        tx.rollback().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM reconcile_targets \
             WHERE reconciler_id = 'rls-reconciler' AND resource_id = $1",
        )
        .bind(&resource)
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(
            cnt.0, 0,
            "missing rss.tenant_id must fail closed for reconcile_targets"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

/// migration 0107：ledger is tenant-scoped and every non-owner consumer is read-only.
#[tokio::test(flavor = "multi_thread")]
async fn resource_security_fact_ledger_rls_grants_and_tenant_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let (
        rls_enabled,
        rls_forced,
        can_select,
        can_insert,
        can_update,
        can_delete,
        audit_can_select,
    ): (bool, bool, bool, bool, bool, bool, bool) = sqlx::query_as(
        "SELECT c.relrowsecurity, c.relforcerowsecurity, \
                has_table_privilege('rss_app', 'resource_security_fact_revisions', 'SELECT'), \
                has_table_privilege('rss_app', 'resource_security_fact_revisions', 'INSERT'), \
                has_table_privilege('rss_app', 'resource_security_fact_revisions', 'UPDATE'), \
                has_table_privilege('rss_app', 'resource_security_fact_revisions', 'DELETE'), \
                has_table_privilege('rss_audit_admin', 'resource_security_fact_revisions', 'SELECT') \
         FROM pg_class c \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relname = 'resource_security_fact_revisions'",
    )
    .fetch_one(&store.pool)
    .await?;
    assert!(rls_enabled && rls_forced);
    assert_eq!(
        (can_select, can_insert, can_update, can_delete),
        (true, false, false, false)
    );
    assert!(
        !audit_can_select,
        "audit-admin exact capability excludes fact ledger"
    );

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let resource_id = uuid::Uuid::new_v4().to_string();

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_resource_fact_bootstrap")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "SELECT public.rss_apply_resource_security_fact_revision(
                $1::uuid, $2::uuid, 'resource.owner', 1, 'test-control-plane', 'owner-a', NULL,
                clock_timestamp() - interval '1 second', clock_timestamp() + interval '5 minutes')",
        )
        .bind(&tenant_a)
        .bind(&resource_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM resource_security_fact_revisions WHERE fact_key = 'resource.owner'",
        )
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(cnt.0, 1, "tenant A scope must see tenant A attribute");
        tx.rollback().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_b)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM resource_security_fact_revisions WHERE fact_key = 'resource.owner'",
        )
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(cnt.0, 0, "tenant B scope must not see tenant A attribute");
        tx.rollback().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_resource_fact_bootstrap")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query(
            "SELECT public.rss_apply_resource_security_fact_revision(
                $1::uuid, $2::uuid, 'resource.owner', 1, 'test-control-plane', 'owner-b', NULL,
                clock_timestamp() - interval '1 second', clock_timestamp() + interval '5 minutes')",
        )
        .bind(&tenant_b)
        .bind(uuid::Uuid::new_v4().to_string())
        .execute(&mut *tx)
        .await;
        let error = result.expect_err("bootstrap tenant mismatch must be rejected in the funnel");
        assert_eq!(
            error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("42501")
        );
        tx.rollback().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM resource_security_fact_revisions")
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 0,
            "missing rss.tenant_id must make fact ledger invisible"
        );
        tx.rollback().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_resource_fact_bootstrap")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind("00000000-0000-0000-0000-000000000000")
            .execute(&mut *tx)
            .await?;
        let error = sqlx::query(
            "SELECT public.rss_apply_resource_security_fact_revision(
                '00000000-0000-0000-0000-000000000000'::uuid, $1::uuid,
                'resource.owner', 1, 'test-control-plane', 'owner-nil', NULL,
                clock_timestamp() - interval '1 second', clock_timestamp() + interval '5 minutes')",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .execute(&mut *tx)
        .await
        .expect_err("nil tenant must be rejected by the bootstrap funnel");
        assert_eq!(
            error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("42501")
        );
        tx.rollback().await?;
    }

    for statement in [
        "UPDATE resource_security_fact_revisions SET source_id = 'tampered'",
        "DELETE FROM resource_security_fact_revisions",
        "TRUNCATE resource_security_fact_revisions",
    ] {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        assert!(
            sqlx::query(statement).execute(&mut *tx).await.is_err(),
            "serving role must not mutate append-only fact ledger: {statement}"
        );
        tx.rollback().await?;
    }

    {
        let result = sqlx::query(
            "INSERT INTO resource_security_fact_revisions
             (tenant_id, device_id, fact_key, revision, source_id, owner_principal_id, observed_at, expires_at)
             VALUES ($1::uuid, $2::uuid, 'resource.id', 1, 'source', 'reserved', now(), now() + interval '1 minute')",
        )
        .bind(&tenant_a)
        .bind(uuid::Uuid::new_v4().to_string())
        .execute(&store.pool)
        .await;
        assert!(result.is_err(), "resource.id is synthetic and reserved");
    }

    store.shutdown().await?;
    Ok(())
}

/// migration 0034：abac_policies 必须授予 rss_app 窄 DML 权限，并由 FORCE RLS 执行 tenant isolation。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: uuid::Uuid::new_v4().to_string() 与固定测试 JSON 均为合法构造；item-level carve-out。
async fn policy_repo_rls_grants_and_tenant_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let (rls_enabled, rls_forced, can_select, can_insert, can_update, can_delete): (
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
    ) = sqlx::query_as(
        "SELECT c.relrowsecurity, c.relforcerowsecurity, \
                has_table_privilege('rss_app', 'abac_policies', 'SELECT'), \
                has_table_privilege('rss_app', 'abac_policies', 'INSERT'), \
                has_table_privilege('rss_app', 'abac_policies', 'UPDATE'), \
                has_table_privilege('rss_app', 'abac_policies', 'DELETE') \
         FROM pg_class c \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relname = 'abac_policies'",
    )
    .fetch_one(&store.pool)
    .await?;
    assert!(rls_enabled, "abac_policies must ENABLE RLS");
    assert!(rls_forced, "abac_policies must FORCE RLS");
    assert!(can_select, "rss_app must SELECT abac_policies");
    assert!(can_insert, "rss_app must INSERT abac_policies");
    assert!(can_update, "rss_app must UPDATE abac_policies");
    assert!(
        !can_delete,
        "rss_app must not DELETE abac_policies; policy delete is versioned tombstone UPDATE"
    );

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let rules_json = principal_kind_rule_json(
        r#"{"family":"equality","predicate":"eq","operand":{"kind":"literal","valueType":"string","value":"admin"}}"#,
    );

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO abac_policies \
             (tenant_id, id, version, contract_id, permission, effective_from, effective_until, rules) \
             VALUES ($1::uuid, 'rls-policy-a', 1, $2, $3, now(), NULL, $4::jsonb)",
        )
        .bind(&tenant_a)
        .bind(POLICY_CONTRACT_ID)
        .bind(POLICY_PERMISSION)
        .bind(&rules_json)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) =
            sqlx::query_as("SELECT count(*) FROM abac_policies WHERE id = 'rls-policy-a'")
                .fetch_one(&mut *tx)
                .await?;
        assert_eq!(cnt.0, 1, "tenant A scope must see tenant A policy");
        tx.rollback().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_b)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) =
            sqlx::query_as("SELECT count(*) FROM abac_policies WHERE id = 'rls-policy-a'")
                .fetch_one(&mut *tx)
                .await?;
        assert_eq!(cnt.0, 0, "tenant B scope must not see tenant A policy");
        tx.rollback().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query(
            "INSERT INTO abac_policies \
             (tenant_id, id, version, contract_id, permission, effective_from, effective_until, rules) \
             VALUES ($1::uuid, 'rls-policy-b', 1, $2, $3, now(), NULL, $4::jsonb)",
        )
        .bind(&tenant_b)
        .bind(POLICY_CONTRACT_ID)
        .bind(POLICY_PERMISSION)
        .bind(&rules_json)
        .execute(&mut *tx)
        .await;
        assert!(
            result.is_err(),
            "WITH CHECK must reject tenant B row while rss.tenant_id is tenant A"
        );
        tx.rollback().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM abac_policies")
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 0,
            "missing rss.tenant_id must make abac_policies invisible"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

/// T20：RLS 强制力证明 — auth_grants 表。
///
/// 验证：rss_app 角色 + tenant_a scope 下经唯一 function 追加成功 / SELECT 可见；切换 tenant_b
/// scope → 不可见；直接伪造 identity row 即使 tenant scope 正确也被 ACL 拒绝。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: uuid::Uuid::new_v4().to_string() 和固定 UUID 格式化不会失败；函数级 item-level carve-out。
async fn t20_rls_auth_grants_enforces_tenant_isolation_and_acl() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_a_id = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let tenant_b_id = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let tenant_a = tenant_a_id.to_string();
    let tenant_b = tenant_b_id.to_string();
    let user_a = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())?;
    let user_b = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())?;
    seed_auth_grant_account(&store, tenant_a_id, user_a).await?;
    seed_auth_grant_account(&store, tenant_b_id, user_b).await?;
    let grant_a = uuid::Uuid::new_v4().to_string();

    // Tx1：同租户 Active root 可以写入。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO auth_grants \
             (tenant_id, grant_id, user_id, auth_time, authn_epoch_at_issue, status, \
              expires_at, created_at, closed_at, close_reason) \
             VALUES ($1::uuid, $2, $3::uuid, now(), 0, 'active', \
                     now() + interval '1 hour', now(), NULL, NULL)",
        )
        .bind(&tenant_a)
        .bind(&grant_a)
        .bind(user_a.as_uuid().to_string())
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Tx1 INSERT tenant_a AuthGrant failed: {e}"))?;
        tx.commit().await?;
    }

    // Tx2：同租户可见。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM auth_grants WHERE grant_id = $1")
            .bind(&grant_a)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(cnt.0, 1, "t20: rss_app + tenant_a scope — AuthGrant 应可见");
        tx.rollback().await?;
    }

    // Tx3：跨租户不可见。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_b)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM auth_grants WHERE grant_id = $1")
            .bind(&grant_a)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 0,
            "t20: rss_app + tenant_b scope — AuthGrant 应被 RLS 过滤"
        );
        tx.rollback().await?;
    }

    // Tx4：tenant_a scope 不能写 tenant_b root，即使 tenant_b 账户真实存在。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query(
            "INSERT INTO auth_grants \
             (tenant_id, grant_id, user_id, auth_time, authn_epoch_at_issue, status, \
              expires_at, created_at, closed_at, close_reason) \
             VALUES ($1::uuid, $2, $3::uuid, now(), 0, 'active', \
                     now() + interval '1 hour', now(), NULL, NULL)",
        )
        .bind(&tenant_b)
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(user_b.as_uuid().to_string())
        .execute(&mut *tx)
        .await;
        assert!(result.is_err(), "t20: WITH CHECK 应拒绝跨租 AuthGrant 写入");
        tx.rollback().await?;
    }

    // Tx5：缺少 tenant scope 时 fail closed。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM auth_grants")
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 0,
            "t20: rss_app + 未设 tenant scope — RLS fail closed"
        );
        tx.rollback().await?;
    }

    // Serving/read roles cannot directly delete the root.
    let delete_privileges: (bool, bool) = sqlx::query_as(
        "SELECT has_table_privilege('rss_app', 'auth_grants', 'DELETE'), \
                has_table_privilege('rss_app_read', 'auth_grants', 'DELETE')",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(delete_privileges, (false, false));

    store.shutdown().await?;
    Ok(())
}

/// T21：RLS 强制力证明 — config_entries 表（#1298）。
///
/// 验证：rss_app 角色 + tenant_a scope 下 INSERT 成功 / SELECT 可见；切换 tenant_b scope → 不可见；
/// tenant_a scope 内尝试写 tenant_b 行 → WITH CHECK 拒绝。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: uuid::Uuid::new_v4().to_string() 不会失败；函数级 item-level carve-out。
async fn t21_rls_config_entries_enforces_tenant_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let cfg_key = format!("rls.test.key.{}", uuid::Uuid::new_v4());

    // Tx1：rss_app + tenant_a scope → INSERT config_entry → 成功。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO config_entries (
                 tenant_id, config_key, version, value, protection_scheme, value_enc, key_id
             ) VALUES ($1::uuid, $2, 1, NULL, 1, $3, $4)",
        )
        .bind(&tenant_a)
        .bind(&cfg_key)
        .bind(&b"ciphertext"[..])
        .bind("settings-config:1")
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Tx1 INSERT tenant_a config failed (should succeed): {e}"))?;
        tx.commit().await?;
    }

    // Tx2：rss_app + tenant_a scope → SELECT → 可见（USING pass）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM config_entries WHERE tenant_id = $1::uuid AND config_key = $2",
        )
        .bind(&tenant_a)
        .bind(&cfg_key)
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(
            cnt.0, 1,
            "t21: rss_app + tenant_a scope — config_entry 应可见（USING policy pass）"
        );
        tx.rollback().await?;
    }

    // Tx3：rss_app + tenant_b scope → SELECT 同 key → 不可见（跨租 USING 过滤）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_b)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) =
            sqlx::query_as("SELECT count(*) FROM config_entries WHERE config_key = $1")
                .bind(&cfg_key)
                .fetch_one(&mut *tx)
                .await?;
        assert_eq!(
            cnt.0, 0,
            "t21: rss_app + tenant_b scope — tenant_a config_entry 应不可见（跨租 RLS 过滤）"
        );
        tx.rollback().await?;
    }

    // Tx4：rss_app + tenant_a scope，尝试写 tenant_b config → WITH CHECK 拒绝。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query(
            "INSERT INTO config_entries (
                 tenant_id, config_key, version, value, protection_scheme, value_enc, key_id
             ) VALUES ($1::uuid, $2, 1, NULL, 1, $3, $4)",
        )
        .bind(&tenant_b) // tenant_b ≠ rss.tenant_id(=tenant_a) → WITH CHECK fail
        .bind(format!("{cfg_key}.cross"))
        .bind(&b"ciphertext"[..])
        .bind("settings-config:1")
        .execute(&mut *tx)
        .await;
        assert!(
            result.is_err(),
            "t21: WITH CHECK 应拒绝 tenant_b config 写入（rss.tenant_id=tenant_a）"
        );
        tx.rollback().await?;
    }

    // Tx5（NULL fail-closed）：rss_app + 未设 rss.tenant_id → SELECT config_entries → 0 行。
    // current_setting('rss.tenant_id', true) 返 NULL → RLS USING 谓词 NULL → 所有行过滤，fail-closed。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        // 不调用 set_config('rss.tenant_id', ...) → current_setting 返 NULL → 行不可见。
        let cnt: (i64,) =
            sqlx::query_as("SELECT count(*) FROM config_entries WHERE config_key = $1")
                .bind(&cfg_key)
                .fetch_one(&mut *tx)
                .await?;
        assert_eq!(
            cnt.0, 0,
            "t21: rss_app + 未设 rss.tenant_id — current_setting NULL → RLS fail-closed（0 行）"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

/// T22：RLS 强制力证明 — roles 表（#1298）。
///
/// 验证：owner fixture 先追加 role revision；rss_app 在 tenant_a scope 下 SELECT 可见，切换 tenant_b
/// scope 后不可见；任何 direct/function mutation 都因 ACL 拒绝。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: uuid::Uuid::new_v4().to_string() 不会失败；函数级 item-level carve-out。
async fn t22_rls_roles_enforces_tenant_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let role_id = format!("rls-role-{}", uuid::Uuid::new_v4());

    // Tx1：test owner 追加 revision，避免给通用 serving role 暴露自报 actor 的 mutation 路径。
    owner_record_role_revision(&store, &tenant_a, &role_id, "RlsTestRole").await?;

    // Tx2：rss_app + tenant_a scope → SELECT → 可见（USING pass）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) =
            sqlx::query_as("SELECT count(*) FROM roles WHERE tenant_id = $1::uuid AND id = $2")
                .bind(&tenant_a)
                .bind(&role_id)
                .fetch_one(&mut *tx)
                .await?;
        assert_eq!(
            cnt.0, 1,
            "t22: rss_app + tenant_a scope — role 应可见（USING policy pass）"
        );
        tx.rollback().await?;
    }

    // Tx3：rss_app + tenant_b scope → SELECT 同 role_id → 不可见（跨租 USING 过滤）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_b)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM roles WHERE id = $1")
            .bind(&role_id)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 0,
            "t22: rss_app + tenant_b scope — tenant_a role 应不可见（跨租 RLS 过滤）"
        );
        tx.rollback().await?;
    }

    // Tx4：rss_app + tenant_a scope，尝试直接伪造 role identity → ACL 拒绝。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query("INSERT INTO roles (tenant_id, id) VALUES ($1::uuid, $2)")
            .bind(&tenant_b)
            .bind(format!("{role_id}-cross"))
            .execute(&mut *tx)
            .await;
        assert!(
            matches!(result, Err(sqlx::Error::Database(ref error)) if error.code().as_deref() == Some("42501")),
            "t22: rss_app 必须没有直接 role INSERT 能力: {result:?}"
        );
        tx.rollback().await?;
    }

    // Tx5（NULL fail-closed）：rss_app + 未设 rss.tenant_id → SELECT roles → 0 行。
    // current_setting('rss.tenant_id', true) 返 NULL → RLS USING 谓词 NULL → 所有行过滤，fail-closed。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        // 不调用 set_config('rss.tenant_id', ...) → current_setting 返 NULL → 行不可见。
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM roles WHERE id = $1")
            .bind(&role_id)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 0,
            "t22: rss_app + 未设 rss.tenant_id — current_setting NULL → RLS fail-closed（0 行）"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

/// T22b：RLS 强制力证明 — role_bindings 表（#1190 PR5b）。
///
/// 验证：rss_app 角色 + tenant_a scope 下 INSERT/SELECT binding 成功；切换 tenant_b scope → 不可见；
/// tenant_a scope 内尝试写 tenant_b binding → WITH CHECK 拒绝；未设 rss.tenant_id → fail-closed（0 行）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: uuid::Uuid::new_v4().to_string() 不会失败；函数级 item-level carve-out。
async fn t22b_rls_role_bindings_enforces_tenant_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let role_id = format!("rls-binding-role-{}", uuid::Uuid::new_v4());
    let subject = format!("rls-binding-subject-{}", uuid::Uuid::new_v4());

    // FK 前置：两个租户各有同 id role，避免 Tx4 被 FK 失败遮蔽 RLS WITH CHECK。
    sqlx::query("INSERT INTO roles (tenant_id, id) VALUES ($1::uuid, $2), ($3::uuid, $2)")
        .bind(&tenant_a)
        .bind(&role_id)
        .bind(&tenant_b)
        .execute(&store.pool)
        .await?;

    // Tx1：rss_app + tenant_a scope → INSERT tenant_a binding → 成功。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO role_bindings (tenant_id, role_id, subject) \
             VALUES ($1::uuid, $2, $3)",
        )
        .bind(&tenant_a)
        .bind(&role_id)
        .bind(&subject)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Tx1 INSERT tenant_a role_binding failed (should succeed): {e}"))?;
        tx.commit().await?;
    }

    // Tx2：rss_app + tenant_a scope → SELECT → 可见（USING pass）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM role_bindings WHERE tenant_id = $1::uuid AND role_id = $2 AND subject = $3",
        )
        .bind(&tenant_a)
        .bind(&role_id)
        .bind(&subject)
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(
            cnt.0, 1,
            "t22b: rss_app + tenant_a scope — role_binding 应可见（USING policy pass）"
        );
        tx.rollback().await?;
    }

    // Tx3：rss_app + tenant_b scope → SELECT 同 binding → 不可见（跨租 USING 过滤）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_b)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM role_bindings WHERE role_id = $1 AND subject = $2",
        )
        .bind(&role_id)
        .bind(&subject)
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(
            cnt.0, 0,
            "t22b: rss_app + tenant_b scope — tenant_a role_binding 应不可见（跨租 RLS 过滤）"
        );
        tx.rollback().await?;
    }

    // Tx4：rss_app + tenant_a scope，尝试写 tenant_b binding → WITH CHECK 拒绝。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query(
            "INSERT INTO role_bindings (tenant_id, role_id, subject) \
             VALUES ($1::uuid, $2, $3)",
        )
        .bind(&tenant_b)
        .bind(&role_id)
        .bind(format!("{subject}-cross"))
        .execute(&mut *tx)
        .await;
        assert!(
            result.is_err(),
            "t22b: WITH CHECK 应拒绝 tenant_b role_binding 写入（rss.tenant_id=tenant_a）"
        );
        tx.rollback().await?;
    }

    // Tx5（NULL fail-closed）：rss_app + 未设 rss.tenant_id → SELECT role_bindings → 0 行。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM role_bindings WHERE role_id = $1 AND subject = $2",
        )
        .bind(&role_id)
        .bind(&subject)
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(
            cnt.0, 0,
            "t22b: rss_app + 未设 rss.tenant_id — current_setting NULL → RLS fail-closed（0 行）"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

/// T24：RLS 强制力证明 — credentials 表（#1316，与 T20–T23 同范式补 credentials 表 DB 层隔离）。
///
/// 以 `SET LOCAL ROLE rss_app`（非 owner，superuser 永远绕过 RLS 不适合验证）+ tenant scope 切换，验证
/// `0012` 的 RLS policy 真实生效：tenant_a scope INSERT/SELECT 成功可见；切 tenant_b → 不可见（USING 过滤）；
/// tenant_a scope 写 tenant_b 行 → WITH CHECK 拒绝。
///
/// 注：不含「未设 rss.tenant_id → 0 行」子用例——`set_config(..,is_local=true)` 在 pool 复用连接上 tx 末 revert
/// 为 placeholder GUC 默认值 `''`（非 NULL），`''::uuid` 在 USING 谓词 raise（仍 fail-closed=不泄数据，但非「0 行」），
/// 该 unset-scope 行为依赖连接是否曾被 set（pool 不可控）⇒ 不在本测试断言（T20–T23 的同款 null-scope 子用例有相同
/// 连接态依赖，见 OOS issue）。核心 RLS 强制力由下列 4 步 USING/WITH CHECK 证明已足。
#[tokio::test(flavor = "multi_thread")]
async fn t24_rls_credentials_enforces_tenant_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    // 提权：superuser 需成为 rss_app member 才能 SET LOCAL ROLE；幂等。
    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let user_a = uuid::Uuid::new_v4().to_string();

    // Tx1：rss_app + tenant_a scope → INSERT tenant_a 凭据 → 成功（WITH CHECK pass）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO credentials (tenant_id, user_id, login, password_hash, version) \
             VALUES ($1::uuid, $2::uuid, 'rls-alice', 'phc-placeholder', 1)",
        )
        .bind(&tenant_a)
        .bind(&user_a)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Tx1 INSERT tenant_a credential failed (should succeed): {e}"))?;
        sqlx::query(
            "INSERT INTO account_security_states \
             (tenant_id, user_id, status, authn_epoch, version, status_changed_at, updated_at) \
             VALUES ($1::uuid, $2::uuid, 'active', 0, 1, now(), now())",
        )
        .bind(&tenant_a)
        .bind(&user_a)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Tx1 INSERT tenant_a security state failed: {e}"))?;
        tx.commit().await?;
    }

    // Tx2：rss_app + tenant_a scope → SELECT → 可见（USING pass）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) =
            sqlx::query_as("SELECT count(*) FROM credentials WHERE login = 'rls-alice'")
                .fetch_one(&mut *tx)
                .await?;
        assert_eq!(cnt.0, 1, "t24: tenant_a scope — 凭据应可见（USING pass）");
        tx.rollback().await?;
    }

    // Tx3：rss_app + tenant_b scope → SELECT 同行 → 不可见（跨租 USING 过滤）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_b)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) =
            sqlx::query_as("SELECT count(*) FROM credentials WHERE login = 'rls-alice'")
                .fetch_one(&mut *tx)
                .await?;
        assert_eq!(
            cnt.0, 0,
            "t24: tenant_b scope — 凭据应不可见（跨租 RLS 过滤）"
        );
        tx.rollback().await?;
    }

    // Tx4：rss_app + tenant_a scope，尝试写 tenant_b 凭据 → WITH CHECK 拒绝。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query(
            "INSERT INTO credentials (tenant_id, user_id, login, password_hash, version) \
             VALUES ($1::uuid, $2::uuid, 'rls-bob', 'phc-placeholder', 1)",
        )
        .bind(&tenant_b) // tenant_b ≠ rss.tenant_id(=tenant_a) → WITH CHECK fail
        .bind(uuid::Uuid::new_v4().to_string())
        .execute(&mut *tx)
        .await;
        assert!(
            result.is_err(),
            "t24: WITH CHECK 应拒绝 tenant_b 写入（rss.tenant_id=tenant_a）"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

/// TA5: RLS 跨租读隔离——rss_app + tenant_b scope 下看不到 tenant_a 的审计行。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta5_audit_rls_cross_tenant_read_denied() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant_a_str = uuid::Uuid::new_v4().to_string();
    let tenant_a = rss_request_context::TenantId::parse(&tenant_a_str).unwrap();
    let tenant_b_str = uuid::Uuid::new_v4().to_string();

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let repo = make_audit_repo(&store);
    repo.append(audit_scope(tenant_a), make_audit_record(tenant_a, 0))
        .await?;

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_b_str)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) =
            sqlx::query_as("SELECT count(*) FROM audit_entries WHERE tenant_id = $1::uuid")
                .bind(&tenant_a_str)
                .fetch_one(&mut *tx)
                .await?;
        assert_eq!(
            cnt.0, 0,
            "TA5: rss_app + tenant_b scope — tenant_a 行须不可见（跨租 RLS 过滤）"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

/// TA11: RLS NULL tenant fail-closed——rss_app 未设 rss.tenant_id → current_setting NULL → 0 行。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta11_audit_rls_null_tenant_fail_closed() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_str = uuid::Uuid::new_v4().to_string();
    let tenant = rss_request_context::TenantId::parse(&tenant_str).unwrap();
    let repo = make_audit_repo(&store);
    repo.append(audit_scope(tenant), make_audit_record(tenant, 0))
        .await?;

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        // 故意不设 rss.tenant_id → current_setting 返 NULL → RLS USING 全过滤。
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM audit_entries")
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 0,
            "TA11: rss_app + 未设 rss.tenant_id → NULL → RLS fail-closed（0 行）"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

// ── command_journal foundation (#1441) ───────────────────────────────────────

fn command_journal_fingerprint(nibble: char) -> String {
    format!("sha256:{}", nibble.to_string().repeat(64))
}

fn command_journal_command_id(nibble: char) -> String {
    format!(
        "command:v2:{}-{}-4{}-8{}-{}",
        nibble.to_string().repeat(8),
        nibble.to_string().repeat(4),
        nibble.to_string().repeat(3),
        nibble.to_string().repeat(3),
        nibble.to_string().repeat(12),
    )
}
