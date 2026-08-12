use std::sync::Arc;

use super::{
    PgConfig, PgError, current_role_owns_database_objects,
    has_projection_external_persistence_capabilities, load_effective_capability_fingerprint,
    load_function_definition_fingerprint,
};
use crate::projection_worker::VerifiedPgProjectionWorkerStore;

const PROJECTION_WORKER_APPLICATION_NAME: &str = "rss-postgres-projection-worker";
const EXPECTED_PROJECTION_WORKER_CAPABILITY_FINGERPRINT: &str =
    "sha256:223134df6e06666cf1bce94580e0b6325c4aa164e9263d38b73a28548cf7abf2";
const EXPECTED_PROJECTION_WORKER_FUNCTION_FINGERPRINT: &str =
    "sha256:fb4027ec88269151a0ed0dcc203bd7596e9bde8253c96a1bdd65a21feb818bff";
const PROJECTION_WORKER_FUNCTION_DEFINITIONS_SQL: &str = r#"
SELECT procedure.proname,
       language.lanname,
       procedure.prosrc,
       procedure.provolatile::text,
       procedure.proparallel::text,
       procedure.proleakproof,
       procedure.proisstrict
FROM pg_catalog.pg_proc AS procedure
JOIN pg_catalog.pg_language AS language ON language.oid = procedure.prolang
WHERE procedure.oid IN (
    'public.rss_projection_worker_list_tenants(text,text,text,text,uuid,integer)'::regprocedure,
    'public.rss_projection_worker_quarantine_tenant(uuid,text,text,text,text,text,text,bigint)'::regprocedure,
    'public.rss_projection_worker_tenant_is_quarantined(uuid,text,text,text,text,text)'::regprocedure,
    'public.rss_projection_worker_read_events(uuid,text,text,text,text,text,bigint,integer)'::regprocedure,
    'public.rss_projection_worker_source_high_water(uuid,text,text,text,text,text)'::regprocedure,
    'public.rss_projection_worker_observe_tenant(uuid,text,text,text,text,text)'::regprocedure,
    'public.rss_projection_worker_get_checkpoint(uuid,text,text,text,text,text)'::regprocedure,
    'public.rss_projection_worker_save_checkpoint(uuid,text,text,text,text,text,bigint,bigint)'::regprocedure,
    'public.rss_projection_worker_insert_dead_letter(uuid,text,text,text,text,text,text,text,text,text,text,text,jsonb,text,bigint,text,bytea,text,integer,text)'::regprocedure,
    'public.rss_settings_projection_apply_worker(uuid,text,text,text,text,text,text,bigint,text,text,bigint,bigint,bytea)'::regprocedure,
    'public.rss_settings_projection_resolve_active()'::regprocedure
)
ORDER BY procedure.proname
"#;

/// Opaque configuration for the dedicated function-only Projection worker credential.
#[derive(Clone)]
pub struct PgProjectionWorkerConfig(PgConfig);

impl PgProjectionWorkerConfig {
    #[must_use]
    pub fn new(config: PgConfig) -> Self {
        Self(config)
    }

    pub(super) fn as_pg_config(&self) -> &PgConfig {
        &self.0
    }
}

impl std::fmt::Debug for PgProjectionWorkerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PgProjectionWorkerConfig")
            .field(&self.0)
            .finish()
    }
}

/// Startup failure for the feature-owned Projection worker credential.
#[derive(Debug, thiserror::Error)]
pub enum PgProjectionWorkerError {
    /// Connection or shared PostgreSQL provider setup failed before the worker capability gate.
    #[error(transparent)]
    Provider(#[from] PgError),
    /// Projection worker role/function/catalog probing failed.
    #[error("postgres projection worker capability probe failed")]
    Capability(#[source] sqlx::Error),
    /// Projection worker is not the exact function-only workload role and direct grant set.
    #[error("postgres projection worker role or grants are not exact")]
    RoleOrGrantMismatch,
    /// Projection worker owns one or more database objects.
    #[error("postgres projection worker must not own database objects")]
    Ownership,
    /// One or more fixed Projection worker function definitions drifted.
    #[error("postgres projection worker function definitions are not exact")]
    FunctionDefinitions { actual_fingerprint: String },
    /// Projection worker can persist through a capability outside its exact function allowlist.
    #[error("postgres projection worker effective privileges are not exact")]
    Privileges { actual_fingerprint: String },
}

/// Unforgeable proof that the pool module completed the exact worker verification gate.
pub(crate) struct ProjectionWorkerMint(pub(super) ());

impl super::PgStore {
    /// Exact capability gate for the dedicated background Projection worker role.
    pub(crate) async fn verify_projection_worker_capability(
        &self,
    ) -> Result<(), PgProjectionWorkerError> {
        let exact: (bool,) = sqlx::query_as(
            r#"
            WITH role_grants AS (
                SELECT grant_row.table_name, grant_row.privilege_type
                FROM information_schema.role_table_grants AS grant_row
                WHERE grant_row.grantee = current_user
                  AND grant_row.table_schema = 'public'
            )
            SELECT session_user = 'rss_projection_worker'
               AND current_user = 'rss_projection_worker'
               AND role.rolcanlogin
               AND NOT role.rolsuper
               AND NOT role.rolbypassrls
               AND NOT role.rolcreatedb
               AND NOT role.rolcreaterole
               AND NOT role.rolreplication
               AND NOT role.rolinherit
               AND COALESCE(cardinality(role.rolconfig), 0) = 1
               AND role.rolconfig @> ARRAY['search_path=pg_catalog, public']::text[]
               AND NOT EXISTS (SELECT 1 FROM role_grants)
               AND has_function_privilege(current_user, 'public.rss_projection_worker_list_tenants(text,text,text,text,uuid,integer)', 'EXECUTE')
               AND has_function_privilege(current_user, 'public.rss_projection_worker_quarantine_tenant(uuid,text,text,text,text,text,text,bigint)', 'EXECUTE')
               AND has_function_privilege(current_user, 'public.rss_projection_worker_tenant_is_quarantined(uuid,text,text,text,text,text)', 'EXECUTE')
               AND has_function_privilege(current_user, 'public.rss_projection_worker_read_events(uuid,text,text,text,text,text,bigint,integer)', 'EXECUTE')
               AND has_function_privilege(current_user, 'public.rss_projection_worker_source_high_water(uuid,text,text,text,text,text)', 'EXECUTE')
               AND has_function_privilege(current_user, 'public.rss_projection_worker_observe_tenant(uuid,text,text,text,text,text)', 'EXECUTE')
               AND has_function_privilege(current_user, 'public.rss_projection_worker_get_checkpoint(uuid,text,text,text,text,text)', 'EXECUTE')
               AND has_function_privilege(current_user, 'public.rss_projection_worker_save_checkpoint(uuid,text,text,text,text,text,bigint,bigint)', 'EXECUTE')
               AND has_function_privilege(current_user, 'public.rss_projection_worker_insert_dead_letter(uuid,text,text,text,text,text,text,text,text,text,text,text,jsonb,text,bigint,text,bytea,text,integer,text)', 'EXECUTE')
               AND has_function_privilege(current_user, 'public.rss_settings_projection_apply_worker(uuid,text,text,text,text,text,text,bigint,text,text,bigint,bigint,bytea)', 'EXECUTE')
               AND has_function_privilege(current_user, 'public.rss_settings_projection_resolve_active()', 'EXECUTE')
               AND (
                    SELECT count(*) = 11
                       AND pg_catalog.bool_and(
                           procedure.prosecdef
                           AND procedure.proconfig =
                               ARRAY['search_path=pg_catalog, pg_temp']::text[]
                           AND function_owner.rolname = CASE
                               WHEN procedure.proname = 'rss_settings_projection_resolve_active'
                               THEN 'rss_projection_serving_owner'
                               ELSE 'rss_projection_worker_owner'
                           END
                           AND NOT function_owner.rolcanlogin
                           AND NOT function_owner.rolsuper
                           AND NOT function_owner.rolbypassrls
                           AND NOT function_owner.rolcreatedb
                           AND NOT function_owner.rolcreaterole
                           AND NOT function_owner.rolreplication
                           AND NOT function_owner.rolinherit
                           AND NOT EXISTS (
                               SELECT 1
                               FROM pg_catalog.pg_auth_members AS membership
                               WHERE membership.member = function_owner.oid
                                  OR membership.roleid = function_owner.oid
                           )
                           AND (
                               SELECT count(*) = CASE
                                          WHEN procedure.proname =
                                              'rss_settings_projection_resolve_active'
                                          THEN 3 ELSE 2 END
                                  AND count(*) FILTER (
                                      WHERE acl.grantor = procedure.proowner
                                        AND acl.grantee = procedure.proowner
                                        AND acl.privilege_type = 'EXECUTE'
                                        AND NOT acl.is_grantable
                                  ) = 1
                                  AND count(*) FILTER (
                                      WHERE procedure.proname =
                                                'rss_settings_projection_resolve_active'
                                        AND acl.grantee =
                                            'rss_app_read'::regrole::oid
                                        AND acl.privilege_type = 'EXECUTE'
                                        AND NOT acl.is_grantable
                                  ) = CASE
                                          WHEN procedure.proname =
                                              'rss_settings_projection_resolve_active'
                                          THEN 1 ELSE 0 END
                                  AND count(*) FILTER (
                                      WHERE acl.grantor = procedure.proowner
                                        AND acl.grantee = role.oid
                                        AND acl.privilege_type = 'EXECUTE'
                                        AND NOT acl.is_grantable
                                  ) = 1
                               FROM pg_catalog.aclexplode(
                                   COALESCE(
                                       procedure.proacl,
                                       pg_catalog.acldefault('f', procedure.proowner)
                                   )
                               ) AS acl
                           )
                       )
                    FROM pg_catalog.pg_proc AS procedure
                    JOIN pg_catalog.pg_roles AS function_owner
                      ON function_owner.oid = procedure.proowner
                    WHERE procedure.oid IN (
                        'public.rss_projection_worker_list_tenants(text,text,text,text,uuid,integer)'::regprocedure,
                        'public.rss_projection_worker_quarantine_tenant(uuid,text,text,text,text,text,text,bigint)'::regprocedure,
                        'public.rss_projection_worker_tenant_is_quarantined(uuid,text,text,text,text,text)'::regprocedure,
                        'public.rss_projection_worker_read_events(uuid,text,text,text,text,text,bigint,integer)'::regprocedure,
                        'public.rss_projection_worker_source_high_water(uuid,text,text,text,text,text)'::regprocedure,
                        'public.rss_projection_worker_observe_tenant(uuid,text,text,text,text,text)'::regprocedure,
                        'public.rss_projection_worker_get_checkpoint(uuid,text,text,text,text,text)'::regprocedure,
                        'public.rss_projection_worker_save_checkpoint(uuid,text,text,text,text,text,bigint,bigint)'::regprocedure,
                        'public.rss_projection_worker_insert_dead_letter(uuid,text,text,text,text,text,text,text,text,text,text,text,jsonb,text,bigint,text,bytea,text,integer,text)'::regprocedure,
                        'public.rss_settings_projection_apply_worker(uuid,text,text,text,text,text,text,bigint,text,text,bigint,bigint,bytea)'::regprocedure,
                        'public.rss_settings_projection_resolve_active()'::regprocedure
                    )
               )
               AND NOT EXISTS (
                    SELECT 1
                    FROM information_schema.role_routine_grants AS grant_row
                    WHERE grant_row.grantee = current_user
                      AND grant_row.specific_schema = 'public'
                      AND grant_row.routine_name NOT IN (
                          'rss_projection_worker_list_tenants',
                          'rss_projection_worker_quarantine_tenant',
                          'rss_projection_worker_tenant_is_quarantined',
                          'rss_projection_worker_read_events',
                          'rss_projection_worker_source_high_water',
                          'rss_projection_worker_observe_tenant',
                          'rss_projection_worker_get_checkpoint',
                          'rss_projection_worker_save_checkpoint',
                          'rss_projection_worker_insert_dead_letter',
                          'rss_settings_projection_apply_worker',
                          'rss_settings_projection_resolve_active'
                      )
               )
               AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_auth_members AS membership
                    WHERE membership.member = role.oid OR membership.roleid = role.oid
               )
            FROM pg_catalog.pg_roles AS role
            WHERE role.rolname = current_user
            "#,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(PgProjectionWorkerError::Capability)?;
        if !exact.0 {
            return Err(PgProjectionWorkerError::RoleOrGrantMismatch);
        }
        if current_role_owns_database_objects(&self.pool)
            .await
            .map_err(PgProjectionWorkerError::Capability)?
        {
            return Err(PgProjectionWorkerError::Ownership);
        }
        if has_projection_external_persistence_capabilities(&self.pool)
            .await
            .map_err(PgProjectionWorkerError::Capability)?
        {
            return Err(PgProjectionWorkerError::Privileges {
                actual_fingerprint: "external-persistence".to_owned(),
            });
        }
        let function_fingerprint = load_function_definition_fingerprint(
            &self.pool,
            PROJECTION_WORKER_FUNCTION_DEFINITIONS_SQL,
        )
        .await
        .map_err(PgProjectionWorkerError::Capability)?;
        if function_fingerprint != EXPECTED_PROJECTION_WORKER_FUNCTION_FINGERPRINT {
            return Err(PgProjectionWorkerError::FunctionDefinitions {
                actual_fingerprint: function_fingerprint,
            });
        }
        let actual_fingerprint = load_effective_capability_fingerprint(&self.pool)
            .await
            .map_err(PgProjectionWorkerError::Capability)?;
        if actual_fingerprint != EXPECTED_PROJECTION_WORKER_CAPABILITY_FINGERPRINT {
            return Err(PgProjectionWorkerError::Privileges { actual_fingerprint });
        }
        Ok(())
    }

    /// Connect and mint the function-only Projection worker capability after its exact gate.
    pub(crate) async fn connect_verified_projection_worker(
        config: &PgProjectionWorkerConfig,
    ) -> Result<VerifiedPgProjectionWorkerStore, PgProjectionWorkerError> {
        let store = Arc::new(
            Self::connect_for(
                config.as_pg_config(),
                "projection-worker",
                PROJECTION_WORKER_APPLICATION_NAME,
            )
            .await
            .map_err(PgProjectionWorkerError::Provider)?,
        );
        if let Err(error) = store.verify_projection_worker_capability().await {
            store.pool.close().await;
            return Err(error);
        }
        Ok(
            crate::projection_worker::VerifiedPgProjectionWorkerStore::mint(
                store,
                ProjectionWorkerMint(()),
            ),
        )
    }
}
