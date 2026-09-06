-- current_user is intentionally included: has_table_privilege/has_schema_privilege compute
-- effective inherited privileges even for memberships with INHERIT TRUE and SET FALSE.
-- SET-reachable roles additionally cover permissions the login can gain by switching roles.
WITH reachable AS (
 SELECT * FROM pg_roles WHERE rolname=current_user OR pg_has_role(current_user,oid,'SET')
), relations AS (
 SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='rss_observation' AND c.relname IN ('objects','streams','batches')
), functions AS (
 SELECT p.* FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='rss_observation'
)
SELECT session_user=current_user
 AND (SELECT count(*)=3 AND bool_and(relrowsecurity AND relforcerowsecurity) FROM relations)
 AND NOT EXISTS (SELECT FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole)
 AND NOT EXISTS (SELECT FROM reachable r CROSS JOIN relations c WHERE c.relowner=r.oid
  OR has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  OR has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE,REFERENCES'))
 AND NOT EXISTS (SELECT FROM reachable r JOIN pg_namespace n ON n.nspname='rss_observation' WHERE n.nspowner=r.oid OR has_schema_privilege(r.oid,n.oid,'CREATE'))
 AND (SELECT count(*)=3 AND bool_and(prosecdef AND proconfig @> ARRAY['search_path=pg_catalog, rss_observation']) FROM functions)
 AND NOT EXISTS (SELECT FROM functions f JOIN pg_roles r ON r.oid=f.proowner WHERE r.rolsuper OR r.rolbypassrls OR r.oid IN (SELECT oid FROM reachable))
 AND NOT EXISTS (SELECT FROM functions f CROSS JOIN LATERAL aclexplode(coalesce(f.proacl,acldefault('f',f.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE')
 AND NOT EXISTS (SELECT FROM pg_namespace n CROSS JOIN LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname='rss_observation' AND a.grantee=0)
 AND NOT EXISTS (SELECT FROM relations c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE a.grantee=0)
 AND NOT EXISTS (SELECT FROM pg_attribute att CROSS JOIN LATERAL aclexplode(att.attacl) a WHERE att.attrelid IN (SELECT oid FROM relations) AND a.grantee=0)
 AND (SELECT count(*)=3 AND bool_and(polcmd='*' AND polqual IS NOT NULL AND polwithcheck IS NOT NULL) FROM pg_policy WHERE polrelid IN (SELECT oid FROM relations))
 AND (SELECT count(*)=3 FROM pg_constraint WHERE conrelid IN (SELECT oid FROM relations) AND contype='p')
 AND (SELECT count(*)=2 FROM pg_constraint WHERE conrelid IN (SELECT oid FROM relations) AND contype='f')
 AND (SELECT count(*)=2 FROM pg_constraint WHERE conrelid IN (SELECT oid FROM relations) AND contype='u')
 AND (SELECT obj_description(oid,'pg_namespace')='rss-observation-postgres:1' FROM pg_namespace WHERE nspname='rss_observation')
