-- Closed storage security contract. Database administrators remain external trusted operators.
WITH namespace AS (SELECT * FROM pg_namespace WHERE nspname='rss_device_command'),
-- Exact text equality avoids PostgreSQL's truncating text-to-name conversion.
callers AS (SELECT * FROM pg_roles WHERE rolname::text=ANY($1::text[])),
caller_reachable(caller,role) AS (
 SELECT c.oid,r.oid FROM callers c CROSS JOIN pg_roles r
 WHERE r.oid=c.oid OR pg_has_role(c.oid,r.oid,'SET')
),
reachable AS (SELECT r.* FROM pg_roles r WHERE r.oid IN(SELECT role FROM caller_reachable)),
-- SET and INHERIT follow different graph edges. Effective privilege checks below also
-- account for a SET target's inherited privileges (including multi-hop combinations).
external_reachable AS (
 SELECT DISTINCT active.oid FROM pg_roles outsider CROSS JOIN pg_roles active CROSS JOIN namespace n
 WHERE outsider.rolcanlogin AND NOT outsider.rolsuper AND outsider.oid<>n.nspowner
 AND outsider.oid NOT IN(SELECT oid FROM callers)
 AND (active.oid=outsider.oid OR pg_has_role(outsider.oid,active.oid,'SET'))
),
rels AS (SELECT c.* FROM pg_class c JOIN namespace n ON n.oid=c.relnamespace WHERE c.relname IN ('commands','authorities')),
functions AS (SELECT p.* FROM pg_proc p JOIN namespace n ON n.oid=p.pronamespace),
tenant_predicate(value) AS (VALUES ($predicate$(tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)$predicate$)),
acl(owner,grantee,privilege_type,is_grantable) AS (
 SELECT n.nspowner,a.grantee,a.privilege_type,a.is_grantable FROM namespace n
 CROSS JOIN LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a
 UNION ALL SELECT c.relowner,a.grantee,a.privilege_type,a.is_grantable FROM rels c
 CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
 UNION ALL SELECT c.relowner,a.grantee,a.privilege_type,a.is_grantable FROM rels c JOIN pg_attribute p ON p.attrelid=c.oid
 CROSS JOIN LATERAL aclexplode(p.attacl) a
 UNION ALL SELECT p.proowner,a.grantee,a.privilege_type,a.is_grantable FROM functions p
 CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
), checks(priority,reason,valid) AS (VALUES
 (1,'revision',
    (SELECT obj_description(oid,'pg_namespace')='rss-device-command-postgres:1' FROM namespace)
    AND (SELECT count(*)=2 FROM rels)),
 (2,'relations',
    (SELECT bool_and(relkind='r' AND relpersistence='p' AND relowner=(SELECT nspowner FROM namespace)) FROM rels)
    AND NOT EXISTS(SELECT FROM pg_trigger WHERE tgrelid IN(SELECT oid FROM rels) AND NOT tgisinternal)
    AND NOT EXISTS(SELECT FROM pg_rewrite WHERE ev_class IN(SELECT oid FROM rels))),
 (3,'caller_roles',
    (SELECT count(*)=cardinality($1::text[]) AND bool_and(rolcanlogin) FROM callers)
    AND EXISTS(SELECT FROM callers WHERE rolname=current_user)),
 (4,'runtime_role',session_user=current_user
    AND NOT EXISTS(SELECT FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication)
    AND NOT EXISTS(SELECT FROM reachable r CROSS JOIN namespace n WHERE pg_has_role(r.oid,n.nspowner,'USAGE'))
    AND NOT EXISTS(SELECT FROM caller_reachable r JOIN callers c ON c.oid<>r.caller
        WHERE pg_has_role(r.role,c.oid,'USAGE'))),
 (5,'runtime_acl',
    NOT EXISTS(SELECT FROM callers c CROSS JOIN namespace n WHERE NOT has_schema_privilege(c.oid,n.oid,'USAGE'))
    AND NOT EXISTS(SELECT FROM callers c CROSS JOIN rels r WHERE NOT has_table_privilege(c.oid,r.oid,'SELECT'))
    AND NOT EXISTS(SELECT FROM callers c CROSS JOIN functions f WHERE NOT has_function_privilege(c.oid,f.oid,'EXECUTE'))
    AND NOT EXISTS(SELECT FROM reachable r CROSS JOIN rels c
       WHERE has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
          OR has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE,REFERENCES'))
    AND NOT EXISTS(SELECT FROM reachable r CROSS JOIN namespace n WHERE has_schema_privilege(r.oid,n.oid,'CREATE'))
    AND NOT EXISTS(SELECT FROM acl a WHERE
        (a.grantee<>a.owner AND a.grantee NOT IN(SELECT oid FROM callers))
        OR (a.grantee IN(SELECT oid FROM callers) AND (a.is_grantable OR a.privilege_type NOT IN ('USAGE','SELECT','EXECUTE'))))
    -- Non-login bridge roles must not acquire caller/owner capabilities either. Do not
    -- mistake PostgreSQL's ungranted built-in administrative roles for application logins.
    AND NOT EXISTS(SELECT FROM pg_roles r CROSS JOIN namespace n
        WHERE NOT r.rolsuper AND r.oid<>n.nspowner AND r.oid NOT IN(SELECT oid FROM callers)
        AND (pg_has_role(r.oid,n.nspowner,'USAGE') OR pg_has_role(r.oid,n.nspowner,'SET')
            OR EXISTS(SELECT FROM callers c WHERE pg_has_role(r.oid,c.oid,'USAGE') OR pg_has_role(r.oid,c.oid,'SET'))))
    AND NOT EXISTS(SELECT FROM external_reachable r CROSS JOIN namespace n
        WHERE has_schema_privilege(r.oid,n.oid,'USAGE') AND (
            EXISTS(SELECT FROM rels c WHERE has_table_privilege(r.oid,c.oid,'SELECT') OR has_any_column_privilege(r.oid,c.oid,'SELECT'))
            OR EXISTS(SELECT FROM functions p WHERE has_function_privilege(r.oid,p.oid,'EXECUTE'))))),
 (6,'rls_policy',(SELECT bool_and(relrowsecurity AND relforcerowsecurity) FROM rels)
    AND NOT EXISTS (
        SELECT FROM (SELECT oid,'tenant_scope'::name AS name FROM rels) e
        FULL JOIN (SELECT * FROM pg_policy WHERE polrelid IN(SELECT oid FROM rels)) p
        ON e.oid=p.polrelid AND e.name=p.polname
        WHERE e.oid IS NULL OR p.oid IS NULL OR NOT p.polpermissive OR p.polcmd<>'*'
        OR p.polroles IS DISTINCT FROM ARRAY[0]::oid[]
        OR pg_get_expr(p.polqual,p.polrelid) IS DISTINCT FROM (SELECT value FROM tenant_predicate)
        OR pg_get_expr(p.polwithcheck,p.polrelid) IS DISTINCT FROM (SELECT value FROM tenant_predicate)))
)
SELECT reason FROM checks WHERE NOT coalesce(valid,false) ORDER BY priority LIMIT 1
