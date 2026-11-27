-- current_user is intentionally included: has_table_privilege/has_schema_privilege compute
-- effective inherited privileges even for memberships with INHERIT TRUE and SET FALSE.
-- Follow roles the login can assume or administer, including through another reachable role.
WITH RECURSIVE accessible(oid) AS (
 SELECT oid FROM pg_roles WHERE rolname=current_user
 UNION
 SELECT target.oid FROM accessible a CROSS JOIN pg_roles target
 WHERE pg_has_role(a.oid,target.oid,'SET') OR pg_has_role(a.oid,target.oid,'MEMBER WITH ADMIN OPTION')
), reachable AS (
 SELECT r.* FROM pg_roles r JOIN accessible USING (oid)
), relations AS (
 SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='rss_observation' AND c.relname IN ('objects','streams','batches','journals','admissions')
), functions AS (
 SELECT p.* FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='rss_observation'
)
SELECT session_user=current_user
 AND has_schema_privilege(current_user,'rss_observation','USAGE')
 -- $1 selects the maintenance-only credential. Check direct, inherited and SET privileges.
 AND NOT EXISTS (SELECT FROM reachable r CROSS JOIN functions f
   WHERE has_function_privilege(r.oid,f.oid,'EXECUTE') AND (f.proname='reclaim')<>$1)
 AND (NOT $1 OR NOT EXISTS (SELECT FROM reachable r CROSS JOIN relations c
   WHERE has_any_column_privilege(r.oid,c.oid,'SELECT')))
 -- Runtime reads stream state and durable receipts directly. The definer owns all other table access.
 AND ($1 OR (SELECT bool_and(has_table_privilege(current_user,oid,'SELECT')) FROM relations WHERE relname IN ('streams','batches','journals')))
 AND (SELECT bool_and(has_function_privilege(current_user,oid,'EXECUTE')) FROM functions WHERE (proname='reclaim')=$1)
 AND (SELECT count(*)=5 AND bool_and(relrowsecurity AND relforcerowsecurity) FROM relations)
 AND NOT EXISTS (SELECT FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole)
 AND NOT EXISTS (SELECT FROM reachable r CROSS JOIN relations c WHERE c.relowner=r.oid
  OR has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  OR has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE,REFERENCES'))
 AND NOT EXISTS (SELECT FROM reachable r JOIN pg_namespace n ON n.nspname='rss_observation' WHERE n.nspowner=r.oid OR has_schema_privilege(r.oid,n.oid,'CREATE'))
 AND (SELECT count(*)=4 AND bool_and(prosecdef AND proconfig @> ARRAY['search_path=pg_catalog, rss_observation']) FROM functions)
 AND NOT EXISTS (SELECT FROM functions f JOIN pg_roles r ON r.oid=f.proowner WHERE r.rolsuper OR r.rolbypassrls OR r.oid IN (SELECT oid FROM reachable))
 AND NOT EXISTS (SELECT FROM functions f CROSS JOIN LATERAL aclexplode(coalesce(f.proacl,acldefault('f',f.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE')
 AND NOT EXISTS (SELECT FROM pg_namespace n CROSS JOIN LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname='rss_observation' AND a.grantee=0)
 AND NOT EXISTS (SELECT FROM relations c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE a.grantee=0)
 AND NOT EXISTS (SELECT FROM pg_attribute att CROSS JOIN LATERAL aclexplode(att.attacl) a WHERE att.attrelid IN (SELECT oid FROM relations) AND a.grantee=0)
 AND (SELECT count(*)=5 AND bool_and(polcmd='*' AND polqual IS NOT NULL AND polwithcheck IS NOT NULL) FROM pg_policy WHERE polrelid IN (SELECT oid FROM relations))
 AND (SELECT count(*)=5 FROM pg_constraint WHERE conrelid IN (SELECT oid FROM relations) AND contype='p')
 AND (SELECT count(*)=2 FROM pg_constraint WHERE conrelid IN (SELECT oid FROM relations) AND contype='f')
 AND (SELECT count(*)=2 FROM pg_constraint WHERE conrelid IN (SELECT oid FROM relations) AND contype='u')
 AND (SELECT obj_description(oid,'pg_namespace')='rss-observation-postgres:5' FROM pg_namespace WHERE nspname='rss_observation')
