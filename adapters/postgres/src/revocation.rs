//! Persistent certificate-revocation store and its startup capability gate.

use diport::{CertNotAfter, CertScope, CertSerial, RevocationStore, RevocationStoreError};
use sqlx::PgConnection;

use crate::cotx::{PgTenantWritePool, infra_tenant_scope};
use crate::pool::{PgError, VerifiedPgWriteStore};

const REVOCATION_CAPABILITY_PROBE_TENANT: &str = "00000000-0000-0000-0000-000000000001";

/// Proof that the serving writer observed the exact revocation schema, RLS and ACL capability.
///
/// The type and field are crate-private. Production construction is confined to
/// [`VerifiedPgWriteStore::verify_revocation_capability`].
#[derive(Clone)]
pub(crate) struct RevocationCapabilityReceipt {
    _seal: (),
}

impl RevocationCapabilityReceipt {
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn for_test() -> Self {
        Self { _seal: () }
    }
}

/// PostgreSQL-backed certificate revocation provider.
///
/// The private typed writer pool makes an unscoped query or mutation unrepresentable. The receipt
/// proves that this value was constructed only after the exact startup capability gate succeeded.
#[derive(Clone)]
pub struct PgRevocationStore {
    pool: PgTenantWritePool,
    receipt: RevocationCapabilityReceipt,
}

impl PgRevocationStore {
    pub(crate) fn new(writer: &VerifiedPgWriteStore, receipt: RevocationCapabilityReceipt) -> Self {
        Self {
            pool: PgTenantWritePool::new(writer),
            receipt,
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum RevocationOperationError {
    #[error("certificate is not active")]
    CertificateExpired,
    #[error("certificate revocation expiry conflicts with persisted evidence")]
    ExpiryConflict,
    #[error("certificate revocation write did not produce authoritative evidence")]
    EvidenceMissing,
}

fn operation_error(error: RevocationOperationError) -> RevocationStoreError {
    RevocationStoreError::new(error)
}

fn storage_error(error: sqlx::Error) -> RevocationStoreError {
    tracing::warn!(
        target: "postgres",
        error = %secure::redact_error(&error),
        "certificate revocation store operation failed"
    );
    RevocationStoreError::new(error)
}

impl RevocationStore for PgRevocationStore {
    #[tracing::instrument(
        name = "postgres.revocation.revoke",
        skip_all,
        fields(tenant = %scope.tenant(), device = %scope.device().as_uuid())
    )]
    async fn revoke(
        &self,
        serial: CertSerial,
        scope: CertScope,
        not_after: CertNotAfter,
    ) -> Result<(), RevocationStoreError> {
        let tenant = scope.tenant().as_uuid().to_string();
        let device = scope.device().as_uuid().to_string();
        let serial = serial.as_bytes().to_vec();
        let not_after = not_after.unix_seconds();
        self.pool
            .write(
                scope,
                move |tx| {
                    Box::pin(async move {
                        let active: bool = sqlx::query_scalar(
                            "SELECT pg_catalog.to_timestamp($1) > pg_catalog.clock_timestamp()",
                        )
                        .bind(not_after)
                        .fetch_one(tx.conn())
                        .await
                        .map_err(storage_error)?;
                        if !active {
                            return Err(operation_error(
                                RevocationOperationError::CertificateExpired,
                            ));
                        }

                        sqlx::query(
                            r#"
                            INSERT INTO public.certificate_revocations
                                (tenant_id, device_id, serial, not_after)
                            VALUES ($1::uuid, $2::uuid, $3, pg_catalog.to_timestamp($4))
                            ON CONFLICT (tenant_id, device_id, serial) DO NOTHING
                            "#,
                        )
                        .bind(&tenant)
                        .bind(&device)
                        .bind(&serial)
                        .bind(not_after)
                        .execute(tx.conn())
                        .await
                        .map_err(storage_error)?;

                        let same_expiry: Option<bool> = sqlx::query_scalar(
                            r#"
                            SELECT not_after = pg_catalog.to_timestamp($4)
                            FROM public.certificate_revocations
                            WHERE tenant_id = $1::uuid
                              AND device_id = $2::uuid
                              AND serial = $3
                            "#,
                        )
                        .bind(tenant)
                        .bind(device)
                        .bind(serial)
                        .bind(not_after)
                        .fetch_optional(tx.conn())
                        .await
                        .map_err(storage_error)?;
                        match same_expiry {
                            Some(true) => Ok(()),
                            Some(false) => {
                                Err(operation_error(RevocationOperationError::ExpiryConflict))
                            }
                            None => Err(operation_error(RevocationOperationError::EvidenceMissing)),
                        }
                    })
                },
                storage_error,
            )
            .await
    }

    #[tracing::instrument(
        name = "postgres.revocation.is_revoked",
        skip_all,
        level = "debug",
        fields(tenant = %scope.tenant(), device = %scope.device().as_uuid())
    )]
    async fn is_revoked(
        &self,
        serial: CertSerial,
        scope: CertScope,
    ) -> Result<bool, RevocationStoreError> {
        let tenant = scope.tenant().as_uuid().to_string();
        let device = scope.device().as_uuid().to_string();
        let serial = serial.as_bytes().to_vec();
        self.pool
            .revocation_read(
                &self.receipt,
                scope,
                move |tx| {
                    Box::pin(async move {
                        let revoked: Option<bool> = sqlx::query_scalar(
                            r#"
                            SELECT true
                            FROM public.certificate_revocations
                            WHERE tenant_id = $1::uuid
                              AND device_id = $2::uuid
                              AND serial = $3
                              AND not_after > pg_catalog.clock_timestamp()
                            "#,
                        )
                        .bind(tenant)
                        .bind(device)
                        .bind(serial)
                        .fetch_optional(tx.conn())
                        .await
                        .map_err(storage_error)?;
                        Ok(revoked.unwrap_or(false))
                    })
                },
                storage_error,
            )
            .await
    }

    async fn shutdown(&self) -> Result<(), RevocationStoreError> {
        // The pool is shared and owned by PgRuntimeDeps; this provider has no independent resource.
        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct RevocationSchemaProbe {
    rls_enabled: bool,
    rls_forced: bool,
    columns_exact: bool,
    primary_key_exact: bool,
    serial_check_exact: bool,
    time_check_exact: bool,
    default_exact: bool,
    retention_index_exact: bool,
    tenant_policy_exact: bool,
}

impl RevocationSchemaProbe {
    fn is_exact(&self) -> bool {
        self.rls_enabled
            && self.rls_forced
            && self.columns_exact
            && self.primary_key_exact
            && self.serial_check_exact
            && self.time_check_exact
            && self.default_exact
            && self.retention_index_exact
            && self.tenant_policy_exact
    }
}

async fn load_schema_probe(
    connection: &mut PgConnection,
) -> Result<Option<RevocationSchemaProbe>, PgError> {
    sqlx::query_as(
        r#"
        SELECT relation.relrowsecurity AS rls_enabled,
               relation.relforcerowsecurity AS rls_forced,
               (
                   SELECT pg_catalog.string_agg(
                       attribute.attname || ':'
                           || pg_catalog.format_type(attribute.atttypid, attribute.atttypmod)
                           || ':' || attribute.attnotnull::text,
                       ',' ORDER BY attribute.attnum
                   )
                   FROM pg_catalog.pg_attribute AS attribute
                   WHERE attribute.attrelid = relation.oid
                     AND attribute.attnum > 0
                     AND NOT attribute.attisdropped
               ) = 'tenant_id:uuid:true,device_id:uuid:true,serial:bytea:true,revoked_at:timestamp with time zone:true,not_after:timestamp with time zone:true'
                   AS columns_exact,
               COALESCE((
                   SELECT pg_catalog.string_agg(attribute.attname, ',' ORDER BY key.ordinality)
                   FROM pg_catalog.pg_constraint AS constraint_row
                   CROSS JOIN LATERAL pg_catalog.unnest(constraint_row.conkey)
                       WITH ORDINALITY AS key(attnum, ordinality)
                   JOIN pg_catalog.pg_attribute AS attribute
                     ON attribute.attrelid = constraint_row.conrelid
                    AND attribute.attnum = key.attnum
                   WHERE constraint_row.conrelid = relation.oid
                     AND constraint_row.contype = 'p'
               ) = 'tenant_id,device_id,serial', false) AS primary_key_exact,
               EXISTS (
                   SELECT 1 FROM pg_catalog.pg_constraint AS constraint_row
                   WHERE constraint_row.conrelid = relation.oid
                     AND constraint_row.contype = 'c'
                     AND constraint_row.conname = 'certificate_revocations_serial_length'
                     AND pg_catalog.regexp_replace(
                         pg_catalog.pg_get_constraintdef(constraint_row.oid, true),
                         '[[:space:]()]', '', 'g'
                     ) = 'CHECKoctet_lengthserial>=1ANDoctet_lengthserial<=20'
               ) AS serial_check_exact,
               EXISTS (
                   SELECT 1 FROM pg_catalog.pg_constraint AS constraint_row
                   WHERE constraint_row.conrelid = relation.oid
                     AND constraint_row.contype = 'c'
                     AND constraint_row.conname = 'certificate_revocations_time_order'
                     AND pg_catalog.regexp_replace(
                         pg_catalog.pg_get_constraintdef(constraint_row.oid, true),
                         '[[:space:]()]', '', 'g'
                     ) = 'CHECKrevoked_at<not_after'
               ) AS time_check_exact,
               COALESCE((
                   SELECT pg_catalog.pg_get_expr(default_value.adbin, default_value.adrelid)
                   FROM pg_catalog.pg_attribute AS attribute
                   JOIN pg_catalog.pg_attrdef AS default_value
                     ON default_value.adrelid = attribute.attrelid
                    AND default_value.adnum = attribute.attnum
                   WHERE attribute.attrelid = relation.oid
                     AND attribute.attname = 'revoked_at'
               ) = 'clock_timestamp()', false) AS default_exact,
               EXISTS (
                   SELECT 1
                   FROM pg_catalog.pg_index AS index
                   JOIN pg_catalog.pg_class AS index_relation ON index_relation.oid = index.indexrelid
                   JOIN pg_catalog.pg_am AS access_method
                     ON access_method.oid = index_relation.relam
                   WHERE index.indrelid = relation.oid
                     AND index.indisvalid
                     AND index.indisready
                     AND index.indislive
                     AND NOT index.indisunique
                     AND NOT index.indisexclusion
                     AND index.indpred IS NULL
                     AND index.indexprs IS NULL
                     AND index.indnkeyatts = 4
                     AND index.indnatts = 4
                     AND index_relation.relkind = 'i'
                     AND index_relation.reloptions IS NULL
                     AND index_relation.relname = 'certificate_revocations_retention_idx'
                     AND access_method.amname = 'btree'
                     AND (
                         SELECT pg_catalog.string_agg(
                             attribute.attname,
                             ',' ORDER BY key.ordinality
                         )
                         FROM pg_catalog.unnest(index.indkey)
                             WITH ORDINALITY AS key(attnum, ordinality)
                         JOIN pg_catalog.pg_attribute AS attribute
                           ON attribute.attrelid = index.indrelid
                          AND attribute.attnum = key.attnum
                     ) = 'not_after,tenant_id,device_id,serial'
                     AND NOT EXISTS (
                         SELECT 1
                         FROM pg_catalog.unnest(index.indoption)
                             WITH ORDINALITY AS key_option(bits, ordinality)
                         WHERE key_option.bits <> 0
                     )
                     AND NOT EXISTS (
                         SELECT 1
                         FROM pg_catalog.unnest(index.indcollation)
                             WITH ORDINALITY AS key_collation(collation_oid, ordinality)
                         WHERE key_collation.collation_oid <> 0
                     )
                     AND NOT EXISTS (
                         SELECT 1
                         FROM pg_catalog.unnest(index.indclass)
                             WITH ORDINALITY AS key_opclass(opclass_oid, ordinality)
                         JOIN pg_catalog.unnest(index.indkey)
                             WITH ORDINALITY AS key_column(attnum, ordinality)
                           ON key_column.ordinality = key_opclass.ordinality
                         JOIN pg_catalog.pg_attribute AS attribute
                           ON attribute.attrelid = index.indrelid
                          AND attribute.attnum = key_column.attnum
                         JOIN pg_catalog.pg_opclass AS opclass
                           ON opclass.oid = key_opclass.opclass_oid
                         WHERE opclass.opcmethod <> access_method.oid
                            OR NOT opclass.opcdefault
                            OR opclass.opcintype <> attribute.atttypid
                     )
               ) AS retention_index_exact,
               EXISTS (
                   SELECT 1
                   FROM pg_catalog.pg_policy AS policy
                   WHERE policy.polrelid = relation.oid
                     AND policy.polname = 'tenant_isolation'
                     AND policy.polpermissive
                     AND policy.polcmd = '*'
                     AND policy.polroles = ARRAY[0::oid]
                     AND pg_catalog.pg_get_expr(policy.polqual, policy.polrelid)
                         = '(tenant_id = (NULLIF(current_setting(''rss.tenant_id''::text, true), ''''::text))::uuid)'
                     AND pg_catalog.pg_get_expr(policy.polwithcheck, policy.polrelid)
                         = '(tenant_id = (NULLIF(current_setting(''rss.tenant_id''::text, true), ''''::text))::uuid)'
               ) AS tenant_policy_exact
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'public'
          AND relation.relname = 'certificate_revocations'
          AND relation.relkind = 'r'
        "#,
    )
    .fetch_optional(connection)
    .await
    .map_err(PgError::RevocationCapability)
}

#[derive(sqlx::FromRow)]
struct RelationAclProbe {
    no_unexpected_grants: bool,
    no_missing_grants: bool,
}

impl RelationAclProbe {
    fn is_exact(&self) -> bool {
        self.no_unexpected_grants && self.no_missing_grants
    }
}

async fn load_relation_acl_probe(
    connection: &mut PgConnection,
) -> Result<RelationAclProbe, PgError> {
    sqlx::query_as(
        r#"
        WITH relation AS (
            SELECT relation.oid, relation.relowner, relation.relacl
            FROM pg_catalog.pg_class AS relation
            JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = 'public'
              AND relation.relname = 'certificate_revocations'
        ), actual AS (
            SELECT CASE WHEN acl.grantee = 0 THEN 'PUBLIC'
                        ELSE pg_catalog.pg_get_userbyid(acl.grantee) END AS grantee,
                   acl.privilege_type,
                   NULL::text AS column_name,
                   acl.is_grantable
            FROM relation
            CROSS JOIN LATERAL pg_catalog.aclexplode(
                COALESCE(relation.relacl, pg_catalog.acldefault('r', relation.relowner))
            ) AS acl
            WHERE acl.grantee <> relation.relowner
            UNION ALL
            SELECT CASE WHEN acl.grantee = 0 THEN 'PUBLIC'
                        ELSE pg_catalog.pg_get_userbyid(acl.grantee) END,
                   acl.privilege_type,
                   attribute.attname,
                   acl.is_grantable
            FROM relation
            JOIN pg_catalog.pg_attribute AS attribute ON attribute.attrelid = relation.oid
            CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS acl
            WHERE attribute.attnum > 0 AND NOT attribute.attisdropped
        ), expected(grantee, privilege_type, column_name, is_grantable) AS (
            VALUES
                ('rss_app'::text, 'SELECT'::text, NULL::text, false),
                ('rss_app_read', 'SELECT', NULL, false),
                ('rss_revocation_maintenance', 'SELECT', NULL, false),
                ('rss_revocation_maintenance', 'UPDATE', NULL, false),
                ('rss_revocation_maintenance', 'DELETE', NULL, false),
                ('rss_app', 'INSERT', 'tenant_id', false),
                ('rss_app', 'INSERT', 'device_id', false),
                ('rss_app', 'INSERT', 'serial', false),
                ('rss_app', 'INSERT', 'not_after', false)
        )
        SELECT NOT EXISTS (SELECT * FROM actual EXCEPT SELECT * FROM expected)
                   AS no_unexpected_grants,
               NOT EXISTS (SELECT * FROM expected EXCEPT SELECT * FROM actual)
                   AS no_missing_grants
        "#,
    )
    .fetch_one(connection)
    .await
    .map_err(PgError::RevocationCapability)
}

#[derive(sqlx::FromRow)]
struct MaintenanceRoleProbe {
    attributes_exact: bool,
    no_memberships: bool,
    namespace_capabilities_exact: bool,
    no_extra_relation_capabilities: bool,
    no_extra_function_capabilities: bool,
}

impl MaintenanceRoleProbe {
    fn is_exact(&self) -> bool {
        self.attributes_exact
            && self.no_memberships
            && self.namespace_capabilities_exact
            && self.no_extra_relation_capabilities
            && self.no_extra_function_capabilities
    }
}

async fn load_maintenance_role_probe(
    connection: &mut PgConnection,
) -> Result<MaintenanceRoleProbe, PgError> {
    sqlx::query_as(
        r#"
        WITH target_role AS (
            SELECT role.oid,
                   NOT role.rolcanlogin
                       AND NOT role.rolsuper
                       AND NOT role.rolcreatedb
                       AND NOT role.rolcreaterole
                       AND NOT role.rolinherit
                       AND NOT role.rolreplication
                       AND role.rolbypassrls AS attributes_exact
            FROM pg_catalog.pg_roles AS role
            WHERE role.rolname = 'rss_revocation_maintenance'
        ), target_relation AS (
            SELECT relation.oid
            FROM pg_catalog.pg_class AS relation
            JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = 'public'
              AND relation.relname = 'certificate_revocations'
        ), target_functions AS (
            SELECT procedure.oid
            FROM pg_catalog.pg_proc AS procedure
            JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
            WHERE namespace.nspname = 'public'
              AND procedure.proname IN (
                  'rss_sweep_expired_certificate_revocations',
                  'rss_certificate_revocation_retention_backlog'
              )
              AND procedure.pronargs = 0
        ), namespace_actual AS (
            SELECT namespace.nspname,
                   acl.privilege_type,
                   acl.is_grantable
            FROM target_role AS role
            CROSS JOIN pg_catalog.pg_namespace AS namespace
            CROSS JOIN LATERAL pg_catalog.aclexplode(
                COALESCE(
                    namespace.nspacl,
                    pg_catalog.acldefault('n', namespace.nspowner)
                )
            ) AS acl
            WHERE acl.grantee = role.oid
        ), namespace_expected(nspname, privilege_type, is_grantable) AS (
            VALUES ('public'::name, 'USAGE'::text, false)
        )
        SELECT COALESCE((SELECT role.attributes_exact FROM target_role AS role), false)
                   AS attributes_exact,
               COALESCE((
                   SELECT NOT EXISTS (
                       SELECT 1
                       FROM pg_catalog.pg_auth_members AS membership
                       WHERE membership.roleid = role.oid OR membership.member = role.oid
                   )
                   FROM target_role AS role
               ), false) AS no_memberships,
               NOT EXISTS (
                   SELECT * FROM namespace_actual
                   EXCEPT SELECT * FROM namespace_expected
               )
                   AND NOT EXISTS (
                       SELECT * FROM namespace_expected
                       EXCEPT SELECT * FROM namespace_actual
                   )
                   AND NOT EXISTS (
                       SELECT 1
                       FROM pg_catalog.pg_namespace AS namespace
                       JOIN target_role AS role ON namespace.nspowner = role.oid
                   ) AS namespace_capabilities_exact,
               COALESCE((
                   SELECT NOT EXISTS (
                       SELECT relation.oid
                       FROM pg_catalog.pg_class AS relation
                       WHERE relation.relowner = role.oid
                         AND relation.oid <> COALESCE(
                             (SELECT target_relation.oid FROM target_relation), 0
                         )
                       UNION
                       SELECT relation.oid
                       FROM pg_catalog.pg_class AS relation
                       CROSS JOIN LATERAL pg_catalog.aclexplode(
                           COALESCE(
                               relation.relacl,
                               pg_catalog.acldefault(
                                   CASE WHEN relation.relkind = 'S' THEN 'S'::"char"
                                        ELSE 'r'::"char" END,
                                   relation.relowner
                               )
                           )
                       ) AS acl
                       WHERE acl.grantee = role.oid
                         AND relation.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
                         AND relation.oid <> COALESCE(
                             (SELECT target_relation.oid FROM target_relation), 0
                         )
                   )
                   FROM target_role AS role
               ), false) AS no_extra_relation_capabilities,
               COALESCE((
                   SELECT NOT EXISTS (
                       SELECT procedure.oid
                       FROM pg_catalog.pg_proc AS procedure
                       WHERE procedure.proowner = role.oid
                         AND procedure.oid NOT IN (
                             SELECT target_functions.oid FROM target_functions
                         )
                       UNION
                       SELECT procedure.oid
                       FROM pg_catalog.pg_proc AS procedure
                       CROSS JOIN LATERAL pg_catalog.aclexplode(
                           COALESCE(
                               procedure.proacl,
                               pg_catalog.acldefault('f', procedure.proowner)
                           )
                       ) AS acl
                       WHERE acl.grantee = role.oid
                         AND procedure.oid NOT IN (
                             SELECT target_functions.oid FROM target_functions
                         )
                   )
                   FROM target_role AS role
               ), false) AS no_extra_function_capabilities
        "#,
    )
    .fetch_one(connection)
    .await
    .map_err(PgError::RevocationCapability)
}

#[derive(sqlx::FromRow)]
struct MaintenanceFunctionProbe {
    exact_count: bool,
    security_definer: bool,
    owner_exact: bool,
    language_exact: bool,
    signature_exact: bool,
    search_path_exact: bool,
    body_exact: bool,
    no_unexpected_grants: bool,
    no_missing_grants: bool,
}

impl MaintenanceFunctionProbe {
    fn is_exact(&self) -> bool {
        self.exact_count
            && self.security_definer
            && self.owner_exact
            && self.language_exact
            && self.signature_exact
            && self.search_path_exact
            && self.body_exact
            && self.no_unexpected_grants
            && self.no_missing_grants
    }
}

async fn load_maintenance_function_probe(
    connection: &mut PgConnection,
) -> Result<MaintenanceFunctionProbe, PgError> {
    sqlx::query_as(
        r#"
        WITH target_function AS (
            SELECT procedure.oid,
                   procedure.proname,
                   procedure.proowner,
                   procedure.proacl,
                   procedure.prosecdef,
                   procedure.proconfig,
                   procedure.prorettype,
                   procedure.proretset,
                   procedure.proallargtypes,
                   procedure.proargmodes,
                   procedure.proargnames,
                   procedure.prokind,
                   procedure.prosrc,
                   language.lanname
            FROM pg_catalog.pg_proc AS procedure
            JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
            JOIN pg_catalog.pg_language AS language ON language.oid = procedure.prolang
            WHERE namespace.nspname = 'public'
              AND procedure.proname IN (
                  'rss_sweep_expired_certificate_revocations',
                  'rss_certificate_revocation_retention_backlog'
              )
              AND procedure.pronargs = 0
        ), actual AS (
            SELECT target_function.proname AS function_name,
                   CASE WHEN acl.grantee = 0 THEN 'PUBLIC'
                        ELSE pg_catalog.pg_get_userbyid(acl.grantee) END AS grantee,
                   acl.privilege_type,
                   acl.is_grantable
            FROM target_function
            CROSS JOIN LATERAL pg_catalog.aclexplode(
                COALESCE(
                    target_function.proacl,
                    pg_catalog.acldefault('f', target_function.proowner)
                )
            ) AS acl
            WHERE acl.grantee <> target_function.proowner
        ), expected(function_name, grantee, privilege_type, is_grantable) AS (
            VALUES
                ('rss_sweep_expired_certificate_revocations'::name,
                 'rss_app'::text, 'EXECUTE'::text, false),
                ('rss_certificate_revocation_retention_backlog'::name,
                 'rss_app'::text, 'EXECUTE'::text, false)
        )
        SELECT COALESCE((
                   SELECT pg_catalog.count(*) = 2
                      AND pg_catalog.count(*) FILTER (
                          WHERE target_function.proname =
                              'rss_sweep_expired_certificate_revocations'
                      ) = 1
                      AND pg_catalog.count(*) FILTER (
                          WHERE target_function.proname =
                              'rss_certificate_revocation_retention_backlog'
                      ) = 1
                   FROM target_function
               ), false) AS exact_count,
               COALESCE((
                   SELECT pg_catalog.bool_and(target_function.prosecdef)
                   FROM target_function
               ), false) AS security_definer,
               COALESCE((
                   SELECT pg_catalog.bool_and(
                       pg_catalog.pg_get_userbyid(target_function.proowner)
                           = 'rss_revocation_maintenance'
                   )
                   FROM target_function
               ), false) AS owner_exact,
               COALESCE((
                   SELECT pg_catalog.bool_and(
                       CASE target_function.proname
                           WHEN 'rss_sweep_expired_certificate_revocations'
                               THEN target_function.lanname = 'plpgsql'
                           WHEN 'rss_certificate_revocation_retention_backlog'
                               THEN target_function.lanname = 'sql'
                           ELSE false
                       END
                   )
                   FROM target_function
               ), false) AS language_exact,
               COALESCE((
                   SELECT pg_catalog.bool_and(
                       CASE target_function.proname
                           WHEN 'rss_sweep_expired_certificate_revocations' THEN
                               target_function.prokind = 'f'
                               AND NOT target_function.proretset
                               AND target_function.prorettype =
                                   'pg_catalog.int8'::pg_catalog.regtype
                               AND target_function.proallargtypes IS NULL
                               AND target_function.proargmodes IS NULL
                               AND target_function.proargnames IS NULL
                           WHEN 'rss_certificate_revocation_retention_backlog' THEN
                               target_function.prokind = 'f'
                               AND target_function.proretset
                               AND target_function.prorettype =
                                   'pg_catalog.record'::pg_catalog.regtype
                               AND target_function.proallargtypes = ARRAY[
                                   'pg_catalog.int8'::pg_catalog.regtype::oid,
                                   'pg_catalog.int8'::pg_catalog.regtype::oid
                               ]::oid[]
                               AND target_function.proargmodes = ARRAY[
                                   't'::"char", 't'::"char"
                               ]
                               AND target_function.proargnames = ARRAY[
                                   'depth'::text, 'oldest_age_seconds'::text
                               ]
                           ELSE false
                       END
                   )
                   FROM target_function
               ), false) AS signature_exact,
               COALESCE((
                   SELECT pg_catalog.bool_and(
                       pg_catalog.cardinality(target_function.proconfig) = 1
                       AND 'search_path=pg_catalog, pg_temp' = ANY(target_function.proconfig)
                   )
                   FROM target_function
               ), false) AS search_path_exact,
               COALESCE((
                   SELECT pg_catalog.bool_and(
                       CASE target_function.proname
                           WHEN 'rss_sweep_expired_certificate_revocations' THEN
                               pg_catalog.btrim(target_function.prosrc) = pg_catalog.btrim($sweep_body$
DECLARE
    deleted_rows bigint;
BEGIN
    WITH expired AS (
        SELECT tenant_id, device_id, serial
        FROM public.certificate_revocations
        WHERE not_after <= pg_catalog.clock_timestamp() - interval '5 minutes'
        ORDER BY not_after, tenant_id, device_id, serial
        LIMIT 1000
        FOR UPDATE SKIP LOCKED
    )
    DELETE FROM public.certificate_revocations AS revocation
    USING expired
    WHERE revocation.tenant_id = expired.tenant_id
      AND revocation.device_id = expired.device_id
      AND revocation.serial = expired.serial;

    GET DIAGNOSTICS deleted_rows = ROW_COUNT;
    RETURN deleted_rows;
END;
$sweep_body$)
                           WHEN 'rss_certificate_revocation_retention_backlog' THEN
                               pg_catalog.btrim(target_function.prosrc) = pg_catalog.btrim($backlog_body$
    SELECT pg_catalog.count(*)::bigint AS depth,
           COALESCE(
               pg_catalog.floor(
                   EXTRACT(
                       EPOCH FROM pg_catalog.clock_timestamp()
                           - (pg_catalog.min(not_after) + interval '5 minutes')
                   )
               )::bigint,
               0::bigint
           ) AS oldest_age_seconds
    FROM public.certificate_revocations
    WHERE not_after <= pg_catalog.clock_timestamp() - interval '5 minutes'
$backlog_body$)
                           ELSE false
                       END
                   )
                   FROM target_function
               ), false) AS body_exact,
               NOT EXISTS (SELECT * FROM actual EXCEPT SELECT * FROM expected)
                   AS no_unexpected_grants,
               NOT EXISTS (SELECT * FROM expected EXCEPT SELECT * FROM actual)
                   AS no_missing_grants
        "#,
    )
    .fetch_one(connection)
    .await
    .map_err(PgError::RevocationCapability)
}

impl VerifiedPgWriteStore {
    /// Mint the revocation receipt only after the exact schema/ACL/maintenance gate succeeds.
    pub(crate) async fn verify_revocation_capability(
        &self,
    ) -> Result<RevocationCapabilityReceipt, PgError> {
        let tenant = vocab::TenantId::parse(REVOCATION_CAPABILITY_PROBE_TENANT)
            .map_err(|_| PgError::RevocationSchema)?;
        PgTenantWritePool::new(self)
            .write(
                infra_tenant_scope(tenant),
                |tx| {
                    Box::pin(async move {
                        let schema = load_schema_probe(tx.conn()).await?;
                        if schema.as_ref().is_none_or(|probe| !probe.is_exact()) {
                            return Err(PgError::RevocationSchema);
                        }
                        if !load_relation_acl_probe(tx.conn()).await?.is_exact() {
                            return Err(PgError::RevocationPrivileges);
                        }
                        if !load_maintenance_role_probe(tx.conn()).await?.is_exact() {
                            return Err(PgError::RevocationMaintenanceRole);
                        }
                        let maintenance_functions =
                            load_maintenance_function_probe(tx.conn()).await?;
                        if !maintenance_functions.is_exact() {
                            return Err(PgError::RevocationMaintenanceFunction);
                        }
                        Ok(())
                    })
                },
                PgError::RevocationCapability,
            )
            .await?;
        Ok(RevocationCapabilityReceipt { _seal: () })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MaintenanceFunctionProbe, MaintenanceRoleProbe, PgRevocationStore, RelationAclProbe,
        RevocationCapabilityReceipt, RevocationSchemaProbe,
    };

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn postgres_revocation_store_and_receipt_are_send_sync() {
        assert_send_sync::<PgRevocationStore>();
        assert_send_sync::<RevocationCapabilityReceipt>();
    }

    #[test]
    fn postgres_revocation_schema_probe_fails_closed_on_each_missing_carrier() {
        let exact = RevocationSchemaProbe {
            rls_enabled: true,
            rls_forced: true,
            columns_exact: true,
            primary_key_exact: true,
            serial_check_exact: true,
            time_check_exact: true,
            default_exact: true,
            retention_index_exact: true,
            tenant_policy_exact: true,
        };
        let drifts: [fn(&mut RevocationSchemaProbe); 9] = [
            |probe| probe.rls_enabled = false,
            |probe| probe.rls_forced = false,
            |probe| probe.columns_exact = false,
            |probe| probe.primary_key_exact = false,
            |probe| probe.serial_check_exact = false,
            |probe| probe.time_check_exact = false,
            |probe| probe.default_exact = false,
            |probe| probe.retention_index_exact = false,
            |probe| probe.tenant_policy_exact = false,
        ];
        assert!(exact.is_exact());
        for drift in drifts {
            let mut probe = RevocationSchemaProbe { ..exact };
            drift(&mut probe);
            assert!(!probe.is_exact());
        }
    }

    #[test]
    fn postgres_revocation_acl_probe_fails_closed_on_extra_or_missing_grants() {
        let exact = RelationAclProbe {
            no_unexpected_grants: true,
            no_missing_grants: true,
        };
        assert!(exact.is_exact());
        assert!(
            !RelationAclProbe {
                no_unexpected_grants: false,
                ..exact
            }
            .is_exact()
        );
        assert!(
            !RelationAclProbe {
                no_missing_grants: false,
                ..exact
            }
            .is_exact()
        );
    }

    #[test]
    fn postgres_revocation_maintenance_role_probe_fails_closed_on_each_drift() {
        let exact = MaintenanceRoleProbe {
            attributes_exact: true,
            no_memberships: true,
            namespace_capabilities_exact: true,
            no_extra_relation_capabilities: true,
            no_extra_function_capabilities: true,
        };
        let drifts: [fn(&mut MaintenanceRoleProbe); 5] = [
            |probe| probe.attributes_exact = false,
            |probe| probe.no_memberships = false,
            |probe| probe.namespace_capabilities_exact = false,
            |probe| probe.no_extra_relation_capabilities = false,
            |probe| probe.no_extra_function_capabilities = false,
        ];
        assert!(exact.is_exact());
        for drift in drifts {
            let mut probe = MaintenanceRoleProbe { ..exact };
            drift(&mut probe);
            assert!(!probe.is_exact());
        }
    }

    #[test]
    fn postgres_revocation_maintenance_function_probe_fails_closed_on_each_drift() {
        let exact = MaintenanceFunctionProbe {
            exact_count: true,
            security_definer: true,
            owner_exact: true,
            language_exact: true,
            signature_exact: true,
            search_path_exact: true,
            body_exact: true,
            no_unexpected_grants: true,
            no_missing_grants: true,
        };
        let drifts: [fn(&mut MaintenanceFunctionProbe); 9] = [
            |probe| probe.exact_count = false,
            |probe| probe.security_definer = false,
            |probe| probe.owner_exact = false,
            |probe| probe.language_exact = false,
            |probe| probe.signature_exact = false,
            |probe| probe.search_path_exact = false,
            |probe| probe.body_exact = false,
            |probe| probe.no_unexpected_grants = false,
            |probe| probe.no_missing_grants = false,
        ];
        assert!(exact.is_exact());
        for drift in drifts {
            let mut probe = MaintenanceFunctionProbe { ..exact };
            drift(&mut probe);
            assert!(!probe.is_exact());
        }
    }
}
