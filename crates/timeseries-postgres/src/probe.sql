WITH reachable AS (
 SELECT * FROM pg_roles WHERE rolname=current_user OR pg_has_role(current_user,oid,'SET')
), relations AS (
 SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='rss_timeseries' AND c.relkind IN ('r','p','v','m','f')
), funcs AS (
 SELECT p.* FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='rss_timeseries'
), acl AS (
 SELECT a.grantee,a.is_grantable FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) a WHERE n.nspname='rss_timeseries'
 UNION ALL SELECT a.grantee,a.is_grantable FROM relations c CROSS JOIN LATERAL aclexplode(c.relacl) a
 UNION ALL SELECT a.grantee,a.is_grantable FROM relations c JOIN pg_attribute p ON p.attrelid=c.oid CROSS JOIN LATERAL aclexplode(p.attacl) a
 UNION ALL SELECT a.grantee,a.is_grantable FROM funcs p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
)
SELECT session_user=current_user
 AND has_schema_privilege(current_user,'rss_timeseries','USAGE')
 AND (SELECT count(*)=11 FROM relations WHERE NOT relispartition)
 AND (SELECT bool_and(relpersistence='p' AND relrowsecurity AND relforcerowsecurity AND relkind IN ('r','p')) FROM relations)
 AND (SELECT bool_and(has_table_privilege(current_user,oid,'SELECT')) FROM relations WHERE NOT relispartition)
 AND NOT EXISTS(SELECT FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole OR rolreplication)
 AND NOT EXISTS(SELECT FROM reachable r CROSS JOIN relations c WHERE c.relowner=r.oid OR has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE,REFERENCES'))
 AND NOT EXISTS(SELECT FROM reachable r JOIN pg_namespace n ON n.nspname='rss_timeseries' WHERE n.nspowner=r.oid OR has_schema_privilege(r.oid,n.oid,'CREATE'))
 AND NOT EXISTS(SELECT FROM relations c CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE a.privilege_type='MAINTAIN' AND EXISTS(SELECT FROM reachable r WHERE r.oid=a.grantee OR pg_has_role(r.oid,a.grantee,'USAGE')))
 AND NOT EXISTS(SELECT FROM acl a WHERE a.grantee=0 OR (a.is_grantable AND EXISTS(SELECT FROM reachable r WHERE r.oid=a.grantee OR pg_has_role(r.oid,a.grantee,'USAGE'))))
 AND NOT EXISTS(SELECT FROM pg_auth_members m JOIN reachable r ON m.member=r.oid WHERE m.admin_option)
 AND (SELECT count(*)=22 AND bool_and(proconfig=ARRAY['search_path=pg_catalog, rss_timeseries'] AND CASE WHEN proname='create_partition' THEN NOT prosecdef AND NOT has_function_privilege(current_user,oid,'EXECUTE') ELSE prosecdef AND has_function_privilege(current_user,oid,'EXECUTE') END) FROM funcs)
 AND NOT EXISTS(SELECT FROM funcs f JOIN pg_roles r ON r.oid=f.proowner WHERE r.rolsuper OR r.rolbypassrls OR r.rolcanlogin OR r.rolcreaterole OR r.rolreplication OR r.oid IN(SELECT oid FROM reachable))
 AND NOT EXISTS(SELECT FROM relations c JOIN pg_roles r ON r.oid=c.relowner JOIN pg_namespace n ON n.nspname='rss_timeseries' WHERE r.rolsuper OR r.rolbypassrls OR r.rolcanlogin OR c.relowner<>n.nspowner)
 AND NOT EXISTS(SELECT FROM pg_trigger WHERE tgrelid IN(SELECT oid FROM relations) AND NOT tgisinternal)
 AND NOT EXISTS(SELECT FROM pg_constraint WHERE conrelid IN(SELECT oid FROM relations) AND NOT convalidated)
 AND (SELECT count(*)=(SELECT count(*) FROM relations) AND bool_and(polname='tenant' AND polcmd='*' AND polpermissive AND polroles=ARRAY[0::oid] AND pg_get_expr(polqual,polrelid)=pg_get_expr(polwithcheck,polrelid) AND pg_get_expr(polqual,polrelid)='(tenant_id = (NULLIF(current_setting(''rss.tenant_id''::text, true), ''''::text))::uuid)') FROM pg_policy WHERE polrelid IN(SELECT oid FROM relations))
 AND NOT EXISTS(SELECT FROM relations c WHERE c.relispartition AND (c.relkind<>'r' OR NOT EXISTS(SELECT FROM pg_inherits i WHERE i.inhrelid=c.oid AND i.inhparent='rss_timeseries.samples'::regclass) OR pg_get_expr(c.relpartbound,c.oid)='DEFAULT'))
