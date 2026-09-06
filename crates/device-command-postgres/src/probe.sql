-- Closed storage security contract. Database administrators remain external trusted operators.
WITH namespace AS (SELECT * FROM pg_namespace WHERE nspname='rss_device_command'),
runtime AS (SELECT * FROM pg_roles WHERE rolname=current_user),
reachable AS (SELECT * FROM pg_roles WHERE rolname=current_user OR pg_has_role(current_user,oid,'SET')),
rels AS (SELECT c.* FROM pg_class c JOIN namespace n ON n.oid=c.relnamespace WHERE c.relname IN ('commands','authorities')),
required_functions(signature) AS (VALUES
 ('rss_device_command.initialize(uuid,uuid,bigint,bigint)'),
 ('rss_device_command.lock_authority(uuid,uuid)'),
 ('rss_device_command.advance(uuid,uuid,bigint,bigint,bigint,bigint)'),
 ('rss_device_command.enqueue(uuid,uuid,text,bigint,bigint,bytea,bigint,bigint,text,bytea,text)'),
 ('rss_device_command.save(uuid,uuid,text,bigint,text,bigint,bigint,bigint)')),
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
 (2,'runtime_role',session_user=current_user
    AND NOT EXISTS(SELECT FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole)
    AND NOT EXISTS(SELECT FROM reachable r JOIN namespace n ON n.nspowner=r.oid)
    AND NOT EXISTS(SELECT FROM reachable r JOIN rels c ON c.relowner=r.oid)),
 (3,'runtime_acl',
    has_schema_privilege(current_user,(SELECT oid FROM namespace),'USAGE')
    AND NOT EXISTS(SELECT FROM rels WHERE NOT has_table_privilege(current_user,oid,'SELECT'))
    AND NOT EXISTS(SELECT FROM reachable r CROSS JOIN rels c
       WHERE has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
          OR has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE,REFERENCES'))
    AND NOT EXISTS(SELECT FROM reachable r CROSS JOIN namespace n WHERE has_schema_privilege(r.oid,n.oid,'CREATE'))
    AND NOT EXISTS(SELECT FROM acl a WHERE
        (a.grantee<>a.owner AND a.grantee<>(SELECT oid FROM runtime))
        OR (a.grantee=(SELECT oid FROM runtime) AND (a.is_grantable OR a.privilege_type NOT IN ('USAGE','SELECT','EXECUTE'))))
    AND NOT EXISTS(SELECT FROM pg_roles r CROSS JOIN namespace n
        WHERE r.rolcanlogin AND NOT r.rolsuper AND r.oid NOT IN(n.nspowner,(SELECT oid FROM runtime))
        AND has_schema_privilege(r.oid,n.oid,'USAGE') AND (
            EXISTS(SELECT FROM rels c WHERE has_table_privilege(r.oid,c.oid,'SELECT') OR has_any_column_privilege(r.oid,c.oid,'SELECT'))
            OR EXISTS(SELECT FROM functions p WHERE has_function_privilege(r.oid,p.oid,'EXECUTE'))))),
 (4,'rls_policy',(SELECT bool_and(relrowsecurity AND relforcerowsecurity) FROM rels)
    AND NOT EXISTS (
        SELECT FROM (SELECT oid,'tenant_scope'::name AS name FROM rels) e
        FULL JOIN (SELECT * FROM pg_policy WHERE polrelid IN(SELECT oid FROM rels)) p
        ON e.oid=p.polrelid AND e.name=p.polname
        WHERE e.oid IS NULL OR p.oid IS NULL OR NOT p.polpermissive OR p.polcmd<>'*'
        OR p.polroles IS DISTINCT FROM ARRAY[0]::oid[]
        OR pg_get_expr(p.polqual,p.polrelid) IS DISTINCT FROM (SELECT value FROM tenant_predicate)
        OR pg_get_expr(p.polwithcheck,p.polrelid) IS DISTINCT FROM (SELECT value FROM tenant_predicate))),
 (5,'functions',NOT EXISTS (
        SELECT FROM required_functions f LEFT JOIN functions p ON p.oid=to_regprocedure(f.signature)
        LEFT JOIN pg_roles owner ON owner.oid=p.proowner
        WHERE p.oid IS NULL OR NOT p.prosecdef OR owner.rolsuper OR owner.rolbypassrls
        OR p.proowner IS DISTINCT FROM (SELECT nspowner FROM namespace)
        OR p.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, rss_device_command']::text[]
        OR NOT has_function_privilege(current_user,p.oid,'EXECUTE'))
    AND NOT EXISTS(SELECT FROM functions p WHERE NOT EXISTS(SELECT FROM required_functions f WHERE to_regprocedure(f.signature)=p.oid)))
)
SELECT reason FROM checks WHERE NOT coalesce(valid,false) ORDER BY priority LIMIT 1
