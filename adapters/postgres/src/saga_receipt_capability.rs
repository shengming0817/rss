//! Exact startup catalog receipt for the protected Saga receipt persistence boundary.

use sha2::{Digest as _, Sha256};

use crate::pool::{PgError, VerifiedPgWriteStore};

// Generated from `SAGA_RECEIPT_CATALOG_SQL` against the real catalog produced by migration 0086.
const EXPECTED_SAGA_RECEIPT_CATALOG_FINGERPRINT: &str =
    "sha256:2dfcb2b55794e493f11aaa8e366dbe7a3ef50d4b588c2ed63afbdc896c84fa74";

/// Private proof that startup observed the reviewed Saga receipt schema and authority surface.
#[derive(Clone)]
pub(crate) struct SagaReceiptCapabilityReceipt {
    _seal: (),
}

impl SagaReceiptCapabilityReceipt {
    #[cfg(any(test, feature = "test-support"))]
    #[allow(dead_code)]
    pub(crate) fn for_test() -> Self {
        Self { _seal: () }
    }
}

/// Canonical catalog facts deliberately cover the whole reviewed capability rather than merely
/// checking object existence. Any column/constraint/trigger/function body, RLS policy, ACL,
/// maintenance-role, retention-index or fixed-function drift changes the byte-level fingerprint.
const SAGA_RECEIPT_CATALOG_SQL: &str = r#"
WITH saga_tables AS (
    SELECT relation.oid, relation.relowner, relation.relname, relation.relacl,
           relation.relrowsecurity, relation.relforcerowsecurity
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'public'
      AND relation.relname IN (
          'saga_instances', 'saga_journal', 'saga_step_receipts', 'saga_operator_decisions',
          'saga_worker_tenant_index'
      )
      AND relation.relkind = 'r'
), saga_relations AS (
    SELECT relation.oid, relation.relowner, relation.relname, relation.relacl
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'public'
      AND relation.relname IN (
          'saga_instances', 'saga_journal', 'saga_step_receipts', 'saga_operator_decisions',
          'saga_worker_tenant_index'
      )
), guarded_functions AS (
    SELECT procedure.oid, procedure.proowner, procedure.proname, procedure.proacl,
           procedure.prosecdef, procedure.proconfig,
           pg_catalog.pg_get_function_identity_arguments(procedure.oid) AS identity_arguments
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
    WHERE namespace.nspname = 'public'
      AND procedure.proname IN (
          'rss_saga_terminal_at_guard',
          'rss_assert_saga_receipt_has_completed',
          'rss_assert_saga_completed_has_receipt',
          'rss_sweep_terminal_sagas',
          'rss_saga_register',
          'rss_saga_claim',
          'rss_saga_claim_operator',
          'rss_saga_renew_lease',
          'rss_saga_release_lease',
          'rss_saga_apply_lifecycle',
          'rss_saga_append_journal',
          'rss_saga_record_operator_decision',
          'rss_saga_insert_receipt',
          'rss_saga_observe_claim',
          'rss_saga_has_exact_prior_intent',
          'rss_saga_intent_attempt_is_next',
          'rss_saga_lease_is_held',
          'rss_saga_worker_tenant_index_refresh',
          'rss_saga_candidate_tenants',
          'rss_saga_observe_unresolved'
      )
), facts AS (
    SELECT 'table:' || table_.relname || ':rls=' || table_.relrowsecurity::text ||
           ':force=' || table_.relforcerowsecurity::text AS fact
    FROM saga_tables AS table_

    UNION ALL
    SELECT 'column:' || attribute.attnum::text || ':' || attribute.attname || ':' ||
           pg_catalog.format_type(attribute.atttypid, attribute.atttypmod) || ':notnull=' ||
           attribute.attnotnull::text || ':default=' ||
           coalesce(pg_catalog.pg_get_expr(default_.adbin, default_.adrelid), '')
    FROM saga_tables AS table_
    JOIN pg_catalog.pg_attribute AS attribute ON attribute.attrelid = table_.oid
    LEFT JOIN pg_catalog.pg_attrdef AS default_
      ON default_.adrelid = attribute.attrelid AND default_.adnum = attribute.attnum
    WHERE attribute.attnum > 0 AND NOT attribute.attisdropped

    UNION ALL
    SELECT 'constraint:' || relation.relname || ':' || constraint_.conname || ':' ||
           constraint_.contype::text || ':validated=' || constraint_.convalidated::text || ':' ||
           pg_catalog.pg_get_constraintdef(constraint_.oid, false)
    FROM pg_catalog.pg_constraint AS constraint_
    JOIN pg_catalog.pg_class AS relation ON relation.oid = constraint_.conrelid
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'public'
      AND relation.relname IN (
          'saga_instances', 'saga_journal', 'saga_step_receipts', 'saga_operator_decisions',
          'saga_worker_tenant_index'
      )

    UNION ALL
    SELECT 'trigger:' || relation.relname || ':' || trigger_.tgname ||
           ':constraint=' || (trigger_.tgconstraint <> 0)::text ||
           ':enabled=' || trigger_.tgenabled::text ||
           ':deferrable=' || trigger_.tgdeferrable::text ||
           ':initially_deferred=' || trigger_.tginitdeferred::text || ':' ||
           pg_catalog.pg_get_triggerdef(trigger_.oid, false)
    FROM pg_catalog.pg_trigger AS trigger_
    JOIN pg_catalog.pg_class AS relation ON relation.oid = trigger_.tgrelid
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'public'
      AND NOT trigger_.tgisinternal
      AND trigger_.tgname IN (
          'saga_instances_terminal_at_guard',
          'saga_receipt_requires_completed',
          'saga_completed_requires_receipt',
          'saga_worker_tenant_index_refresh'
      )

    UNION ALL
    SELECT 'index:' || index_.relname || ':' || pg_catalog.pg_get_indexdef(index_.oid)
    FROM pg_catalog.pg_class AS index_
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = index_.relnamespace
    WHERE namespace.nspname = 'public'
      AND index_.relname IN (
          'saga_instances_terminal_retention_idx',
          'saga_instances_worker_candidate_idx',
          'saga_instances_unresolved_observation_idx',
          'idx_saga_worker_tenant_index_owner_contract_updated'
      )

    UNION ALL
    SELECT 'policy:' || policy.polname || ':permissive=' || policy.polpermissive::text ||
           ':roles=' || policy.polroles::text || ':using=' ||
           coalesce(pg_catalog.pg_get_expr(policy.polqual, policy.polrelid), '') ||
           ':check=' ||
           coalesce(pg_catalog.pg_get_expr(policy.polwithcheck, policy.polrelid), '')
    FROM saga_tables AS table_
    JOIN pg_catalog.pg_policy AS policy ON policy.polrelid = table_.oid

    UNION ALL
    SELECT 'function:' || function_.proname || '(' || function_.identity_arguments || ')' ||
           ':owner=' || CASE
               WHEN function_.proname = 'rss_sweep_terminal_sagas'
                   THEN pg_catalog.pg_get_userbyid(function_.proowner)
               WHEN function_.proname LIKE 'rss_saga_%'
                   AND function_.proname <> 'rss_saga_terminal_at_guard'
                   THEN pg_catalog.pg_get_userbyid(function_.proowner)
               ELSE '<migration-owner>'
           END ||
           ':security_definer=' || function_.prosecdef::text ||
           ':config=' || coalesce(function_.proconfig::text, '') || ':' ||
           pg_catalog.pg_get_functiondef(function_.oid)
    FROM guarded_functions AS function_

    UNION ALL
    SELECT 'relation_acl:' || relation.relname || ':' ||
           CASE WHEN acl.grantee = relation.relowner THEN '<owner>'
                ELSE coalesce(grantee.rolname, 'PUBLIC') END || ':' || acl.privilege_type ||
           ':grantable=' || acl.is_grantable::text
    FROM saga_relations AS relation
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        coalesce(relation.relacl, pg_catalog.acldefault('r', relation.relowner))
    ) AS acl
    LEFT JOIN pg_catalog.pg_roles AS grantee ON grantee.oid = acl.grantee

    UNION ALL
    SELECT 'column_acl:' || relation.relname || '.' || attribute.attname || ':' ||
           CASE WHEN acl.grantee = relation.relowner THEN '<owner>'
                ELSE coalesce(grantee.rolname, 'PUBLIC') END || ':' ||
           acl.privilege_type || ':grantable=' || acl.is_grantable::text
    FROM saga_relations AS relation
    JOIN pg_catalog.pg_attribute AS attribute ON attribute.attrelid = relation.oid
    CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS acl
    LEFT JOIN pg_catalog.pg_roles AS grantee ON grantee.oid = acl.grantee
    WHERE attribute.attnum > 0 AND NOT attribute.attisdropped

    UNION ALL
    SELECT 'function_acl:' || function_.proname || '(' || function_.identity_arguments || '):' ||
           CASE WHEN acl.grantee = function_.proowner THEN '<owner>'
                ELSE coalesce(grantee.rolname, 'PUBLIC') END || ':' ||
           acl.privilege_type || ':grantable=' || acl.is_grantable::text
    FROM guarded_functions AS function_
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        coalesce(function_.proacl, pg_catalog.acldefault('f', function_.proowner))
    ) AS acl
    LEFT JOIN pg_catalog.pg_roles AS grantee ON grantee.oid = acl.grantee

    UNION ALL
    SELECT 'maintenance_role:' || role.rolname || ':login=' || role.rolcanlogin::text ||
           ':super=' || role.rolsuper::text || ':createdb=' || role.rolcreatedb::text ||
           ':createrole=' || role.rolcreaterole::text || ':inherit=' || role.rolinherit::text ||
           ':replication=' || role.rolreplication::text || ':bypassrls=' || role.rolbypassrls::text
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = 'rss_saga_receipt_maintenance'

    UNION ALL
    SELECT 'maintenance_memberships:' || pg_catalog.count(*)::text
    FROM pg_catalog.pg_auth_members AS membership
    JOIN pg_catalog.pg_roles AS role
      ON role.oid = membership.roleid OR role.oid = membership.member
    WHERE role.rolname = 'rss_saga_receipt_maintenance'

    UNION ALL
    SELECT 'maintenance_schema_acl:' || coalesce(grantee.rolname, 'PUBLIC') || ':' ||
           acl.privilege_type ||
           ':grantable=' || acl.is_grantable::text
    FROM pg_catalog.pg_namespace AS namespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        coalesce(namespace.nspacl, pg_catalog.acldefault('n', namespace.nspowner))
    ) AS acl
    LEFT JOIN pg_catalog.pg_roles AS grantee ON grantee.oid = acl.grantee
    WHERE namespace.nspname = 'public'
      AND grantee.rolname = 'rss_saga_receipt_maintenance'

    UNION ALL
    SELECT 'maintenance_relation_capability:' || namespace.nspname || '.' || relation.relname ||
           ':' || acl.privilege_type || ':grantable=' || acl.is_grantable::text
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(relation.relacl) AS acl
    JOIN pg_catalog.pg_roles AS grantee ON grantee.oid = acl.grantee
    WHERE namespace.nspname !~ '^pg_'
      AND namespace.nspname <> 'information_schema'
      AND relation.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
      AND grantee.rolname = 'rss_saga_receipt_maintenance'

    UNION ALL
    SELECT 'maintenance_function_capability:' || namespace.nspname || '.' ||
           procedure.proname || '(' ||
           pg_catalog.pg_get_function_identity_arguments(procedure.oid) || '):' ||
           acl.privilege_type || ':grantable=' || acl.is_grantable::text
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(procedure.proacl) AS acl
    JOIN pg_catalog.pg_roles AS grantee ON grantee.oid = acl.grantee
    WHERE namespace.nspname !~ '^pg_'
      AND namespace.nspname <> 'information_schema'
      AND grantee.rolname = 'rss_saga_receipt_maintenance'

    UNION ALL
    SELECT 'writer_role:' || role.rolname || ':login=' || role.rolcanlogin::text ||
           ':super=' || role.rolsuper::text || ':createdb=' || role.rolcreatedb::text ||
           ':createrole=' || role.rolcreaterole::text || ':inherit=' || role.rolinherit::text ||
           ':replication=' || role.rolreplication::text || ':bypassrls=' || role.rolbypassrls::text
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = 'rss_saga_writer'

    UNION ALL
    SELECT 'writer_memberships:' || pg_catalog.count(*)::text
    FROM pg_catalog.pg_auth_members AS membership
    JOIN pg_catalog.pg_roles AS role
      ON role.oid = membership.roleid OR role.oid = membership.member
    WHERE role.rolname = 'rss_saga_writer'

    UNION ALL
    SELECT 'writer_schema_acl:' || coalesce(grantee.rolname, 'PUBLIC') || ':' ||
           acl.privilege_type || ':grantable=' || acl.is_grantable::text
    FROM pg_catalog.pg_namespace AS namespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        coalesce(namespace.nspacl, pg_catalog.acldefault('n', namespace.nspowner))
    ) AS acl
    LEFT JOIN pg_catalog.pg_roles AS grantee ON grantee.oid = acl.grantee
    WHERE namespace.nspname = 'public' AND grantee.rolname = 'rss_saga_writer'

    UNION ALL
    SELECT 'writer_relation_capability:' || namespace.nspname || '.' || relation.relname ||
           ':' || acl.privilege_type || ':grantable=' || acl.is_grantable::text
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(relation.relacl) AS acl
    JOIN pg_catalog.pg_roles AS grantee ON grantee.oid = acl.grantee
    WHERE namespace.nspname !~ '^pg_'
      AND namespace.nspname <> 'information_schema'
      AND relation.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
      AND grantee.rolname = 'rss_saga_writer'

    UNION ALL
    SELECT 'writer_function_capability:' || namespace.nspname || '.' ||
           procedure.proname || '(' ||
           pg_catalog.pg_get_function_identity_arguments(procedure.oid) || '):' ||
           acl.privilege_type || ':grantable=' || acl.is_grantable::text
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(procedure.proacl) AS acl
    JOIN pg_catalog.pg_roles AS grantee ON grantee.oid = acl.grantee
    WHERE namespace.nspname !~ '^pg_'
      AND namespace.nspname <> 'information_schema'
      AND grantee.rolname = 'rss_saga_writer'
)
SELECT fact FROM facts ORDER BY fact
"#;

impl VerifiedPgWriteStore {
    /// Mint the receipt only after the complete reviewed catalog surface matches migration 0086.
    pub(crate) async fn verify_saga_receipt_capability(
        &self,
    ) -> Result<SagaReceiptCapabilityReceipt, PgError> {
        let facts: Vec<(String,)> = sqlx::query_as(SAGA_RECEIPT_CATALOG_SQL)
            .fetch_all(self.pool())
            .await
            .map_err(PgError::SagaReceiptCapability)?;
        let actual_fingerprint = fingerprint(facts.iter().map(|(fact,)| fact.as_str()));
        if actual_fingerprint != EXPECTED_SAGA_RECEIPT_CATALOG_FINGERPRINT {
            tracing::error!(
                target: "postgres",
                %actual_fingerprint,
                "saga receipt catalog capability fingerprint mismatch"
            );
            return Err(PgError::SagaReceiptCatalog { actual_fingerprint });
        }
        Ok(SagaReceiptCapabilityReceipt { _seal: () })
    }
}

fn fingerprint<'a>(facts: impl IntoIterator<Item = &'a str>) -> String {
    let mut digest = Sha256::new();
    for fact in facts {
        digest.update(fact.as_bytes());
        digest.update([b'\n']);
    }
    format!("sha256:{:x}", digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::fingerprint;

    #[test]
    fn saga_receipt_catalog_fingerprint_is_order_and_byte_sensitive() {
        let exact = fingerprint(["a", "b"]);
        assert_ne!(exact, fingerprint(["b", "a"]));
        assert_ne!(exact, fingerprint(["a", "b "]));
        assert_ne!(exact, fingerprint(["a"]));
    }
}
