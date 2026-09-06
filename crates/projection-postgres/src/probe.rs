//! Runtime admission checks the roles a session can reach, not only immediately inherited ACLs.
use crate::transaction::sql_error;
use rss_projection::{Error, ErrorKind};
use sqlx::PgPool;

pub(crate) async fn validate(pool: &PgPool) -> Result<(), Error> {
    let safe: bool = sqlx::query_scalar(r#"
WITH reachable AS (
    SELECT * FROM pg_roles WHERE rolname = current_user OR pg_has_role(current_user, oid, 'SET')
), relations AS (
    SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='rss_projection' AND c.relname IN ('sources','events','checkpoints','receipts')
)
SELECT
    session_user = current_user
    AND (SELECT count(*)=4 AND bool_and(relrowsecurity AND relforcerowsecurity) FROM relations)
    AND NOT EXISTS (
        SELECT FROM reachable r WHERE r.rolsuper OR r.rolbypassrls OR r.rolcreaterole
    )
    AND NOT EXISTS (
        SELECT FROM reachable r CROSS JOIN relations c
        WHERE c.relowner=r.oid
           OR has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
           OR has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE,REFERENCES')
    )
    AND NOT EXISTS (
        SELECT FROM reachable r JOIN pg_namespace n ON n.nspname='rss_projection'
        WHERE n.nspowner=r.oid OR has_schema_privilege(r.oid,n.oid,'CREATE')
    )
    AND NOT EXISTS (
        SELECT FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        JOIN pg_roles owner ON owner.oid=p.proowner
        WHERE n.nspname='rss_projection' AND
            ((p.prosecdef AND (owner.rolsuper OR owner.rolbypassrls)) OR p.proowner IN (SELECT oid FROM reachable))
    )
    AND NOT EXISTS (
        SELECT FROM relations c CROSS JOIN LATERAL aclexplode(c.relacl) a
        WHERE a.privilege_type='MAINTAIN' AND
            CASE WHEN a.grantee=0 THEN true ELSE
                EXISTS(SELECT FROM reachable r WHERE r.oid=a.grantee OR pg_has_role(r.oid,a.grantee,'USAGE')) END
    )
    AND (SELECT obj_description(oid,'pg_namespace')='rss-projection-postgres:2'
         FROM pg_namespace WHERE nspname='rss_projection')
"#).fetch_one(pool).await.map_err(|e| sql_error(e, rss_projection::Phase::Admission))?;
    if safe {
        Ok(())
    } else {
        Err(Error::new(ErrorKind::StorageContract))
    }
}
