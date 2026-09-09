//! Runtime admission checks the roles a session can reach, not only immediately inherited ACLs.
use crate::transaction::sql_error;
use rss_projection::{Error, ErrorKind};
use sqlx::PgPool;

pub(crate) async fn validate(pool: &PgPool) -> Result<(), Error> {
    let safe: Option<bool> = sqlx::query_scalar(r#"
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
    -- PUBLIC is never a runtime principal, including implicit/default function EXECUTE.
    AND NOT EXISTS (
        SELECT FROM pg_namespace n
        CROSS JOIN LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a
        WHERE n.nspname='rss_projection' AND a.grantee=0
    )
    AND NOT EXISTS (
        SELECT FROM relations c
        CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
        WHERE a.grantee=0
    )
    AND NOT EXISTS (
        SELECT FROM relations c JOIN pg_attribute p ON p.attrelid=c.oid
        CROSS JOIN LATERAL aclexplode(p.attacl) a WHERE a.grantee=0
    )
    AND NOT EXISTS (
        SELECT FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
        WHERE n.nspname='rss_projection' AND a.grantee=0
    )
    AND NOT EXISTS (
        SELECT FROM (SELECT oid,'tenant_scope'::name AS name FROM relations) e
        FULL JOIN (SELECT * FROM pg_policy WHERE polrelid IN (SELECT oid FROM relations)) p
        ON e.oid=p.polrelid AND e.name=p.polname
        WHERE e.oid IS NULL OR p.oid IS NULL OR NOT p.polpermissive OR p.polcmd<>'*'
        OR p.polroles IS DISTINCT FROM ARRAY[0]::oid[]
        OR pg_get_expr(p.polqual,p.polrelid) IS DISTINCT FROM
            $predicate$(tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)$predicate$
        OR pg_get_expr(p.polwithcheck,p.polrelid) IS DISTINCT FROM
            $predicate$(tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)$predicate$
    )
    AND EXISTS (SELECT FROM pg_attribute WHERE attrelid=to_regclass('rss_projection.checkpoints')
        AND attname='definition_identity' AND atttypid='bytea'::regtype AND attnotnull AND NOT attisdropped)
    AND EXISTS (SELECT FROM pg_constraint WHERE conrelid=to_regclass('rss_projection.checkpoints')
        AND conname='definition_identity_length' AND convalidated
        AND pg_get_constraintdef(oid)='CHECK ((octet_length(definition_identity) = 32))')
    AND NOT EXISTS (
        SELECT FROM (VALUES
            ('rss_projection.initialize(uuid,text,text,text,bigint,boolean,bigint,text[],bytea[])'),
            ('rss_projection.takeover(uuid,text,text,text,uuid)'),
            ('rss_projection.lock_event(uuid,text,text,text,bigint,uuid,bigint,bigint,text,bytea)'),
            ('rss_projection.finish_event(uuid,text,text,text,bigint,uuid,bigint,bigint,text,bytea)')
        ) AS old(signature) WHERE to_regprocedure(signature) IS NOT NULL
    )
    AND NOT EXISTS (
        SELECT FROM (VALUES
            ('rss_projection.initialize(uuid,text,text,text,bigint,boolean,bigint,text[],bytea[],bytea)'),
            ('rss_projection.takeover(uuid,text,text,text,uuid,bytea)'),
            ('rss_projection.lock_event(uuid,text,text,text,bigint,uuid,bigint,bigint,text,bytea,bytea)'),
            ('rss_projection.finish_event(uuid,text,text,text,bigint,uuid,bigint,bigint,text,bytea,bytea)')
        ) AS required(signature)
        WHERE has_function_privilege(current_user, to_regprocedure(signature), 'EXECUTE') IS NOT TRUE
    )
    AND (SELECT obj_description(oid,'pg_namespace')='rss-projection-postgres:3'
         FROM pg_namespace WHERE nspname='rss_projection')
"#).fetch_one(pool).await.map_err(|e| sql_error(e, rss_projection::Phase::Admission))?;
    if safe == Some(true) {
        Ok(())
    } else {
        Err(Error::new(ErrorKind::StorageContract))
    }
}
