WITH RECURSIVE accessible(oid) AS (
 SELECT current_user::regrole::oid
 UNION
 SELECT m.roleid FROM accessible a JOIN pg_catalog.pg_auth_members m ON m.member=a.oid
 WHERE m.set_option OR m.inherit_option OR m.admin_option
), reachable AS (
 SELECT r.* FROM pg_catalog.pg_roles r WHERE EXISTS (
  SELECT FROM accessible a WHERE pg_has_role(a.oid,r.oid,'SET') OR pg_has_role(a.oid,r.oid,'USAGE')
 )
), namespace AS (
 SELECT oid,nspowner FROM pg_catalog.pg_namespace WHERE nspname='identity_authority'
), reader AS (
 SELECT to_regprocedure('identity_authority.personnel_facts(uuid,uuid,uuid[],text,text,text[],bigint)') AS oid
)
SELECT coalesce(current_user=session_user
 AND EXISTS (SELECT FROM pg_catalog.pg_stat_activity a WHERE a.pid=pg_backend_pid() AND a.usesysid=current_user::regrole::oid)
 AND has_schema_privilege(current_user,n.oid,'USAGE')
 AND has_function_privilege(current_user,reader.oid,'EXECUTE')
 AND NOT EXISTS (SELECT FROM pg_catalog.pg_proc p, LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) acl
  WHERE p.oid=reader.oid AND acl.grantee=0 AND acl.privilege_type='EXECUTE')
 AND NOT EXISTS (
  SELECT FROM reachable r WHERE n.nspowner=r.oid OR r.rolsuper OR r.rolreplication OR r.rolcreatedb OR r.rolbypassrls OR r.rolcreaterole
    OR has_schema_privilege(r.oid,n.oid,'CREATE,USAGE WITH GRANT OPTION')
    OR has_function_privilege(r.oid,reader.oid,'EXECUTE WITH GRANT OPTION')
    OR EXISTS (SELECT FROM pg_catalog.pg_class c WHERE c.relnamespace=n.oid AND c.relkind='r' AND
     (c.relowner=r.oid OR has_any_column_privilege(r.oid,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')
      OR has_table_privilege(r.oid,c.oid,'DELETE,TRUNCATE,TRIGGER,MAINTAIN')))
    OR EXISTS (SELECT FROM pg_catalog.pg_proc p WHERE p.pronamespace=n.oid AND
     (p.proowner=r.oid OR p.oid<>reader.oid AND has_function_privilege(r.oid,p.oid,'EXECUTE')))
 ),false)
FROM namespace n CROSS JOIN reader
