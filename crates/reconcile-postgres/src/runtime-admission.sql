WITH reachable AS MATERIALIZED (
    SELECT * FROM pg_roles WHERE rolname = current_user OR pg_has_role(current_user, oid, 'SET')
), relations AS (
    SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='rss_reconcile' AND c.relname IN ('targets')
)
SELECT
    session_user = current_user
    AND (SELECT count(*)=1 AND bool_and(relrowsecurity AND relforcerowsecurity) FROM relations)
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
        SELECT FROM reachable r JOIN pg_namespace n ON n.nspname='rss_reconcile'
        WHERE n.nspowner=r.oid OR has_schema_privilege(r.oid,n.oid,'CREATE')
    )
    AND NOT EXISTS (
        SELECT FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        JOIN pg_roles owner ON owner.oid=p.proowner
        WHERE n.nspname='rss_reconcile' AND
            ((p.prosecdef AND (owner.rolsuper OR owner.rolbypassrls)) OR p.proowner IN (SELECT oid FROM reachable))
    )
    AND NOT EXISTS (
        SELECT FROM relations c CROSS JOIN LATERAL aclexplode(c.relacl) a
        WHERE a.privilege_type='MAINTAIN' AND
            CASE WHEN a.grantee=0 THEN true ELSE
                EXISTS(SELECT FROM reachable r WHERE r.oid=a.grantee OR pg_has_role(r.oid,a.grantee,'USAGE')) END
    )
    AND (SELECT count(*)=1 AND bool_and(polcmd='*' AND polpermissive AND polroles=ARRAY[0::oid]
         AND pg_get_expr(polqual,polrelid)=pg_get_expr(polwithcheck,polrelid)
         AND pg_get_expr(polqual,polrelid) = '(tenant_id = (NULLIF(current_setting(''rss.tenant_id''::text, true), ''''::text))::uuid)')
         FROM pg_policy WHERE polrelid='rss_reconcile.targets'::regclass)
    AND has_schema_privilege(current_user,'rss_reconcile','USAGE')
    AND has_table_privilege(current_user,'rss_reconcile.targets','SELECT')
    AND NOT EXISTS (
        SELECT FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='rss_reconcile' AND (
            NOT has_function_privilege(current_user,p.oid,'EXECUTE')
            OR EXISTS (SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
                       WHERE a.grantee=0 AND a.privilege_type='EXECUTE')
        )
    )
