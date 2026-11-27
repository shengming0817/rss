-- The installation owner creates the definer ports. Check their effective access
-- to the relations and predicate columns used by their SELECT ... FOR SHARE.
WITH ports AS (
 SELECT p.*, n.nspowner FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE p.oid IN ('identity_authority.share_host_tenant()'::regprocedure,
  'identity_authority.share_provider(uuid)'::regprocedure,'identity_authority.share_subject(uuid)'::regprocedure,
  'identity_authority.lock_session(bytea,uuid,text,text,uuid)'::regprocedure)
), locks(port,relation,columns_used) AS (
 VALUES ('share_host_tenant','tenants',ARRAY['tenant_id']),
        ('share_subject','accounts',ARRAY['tenant_id','principal_id']),
        ('share_subject','memberships',ARRAY['tenant_id','principal_id']),
        ('share_provider','providers',ARRAY['tenant_id','provider_id'])
)
SELECT NOT EXISTS(SELECT FROM ports p
 WHERE EXISTS(SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) acl
              WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE')
 OR EXISTS(SELECT FROM pg_roles r WHERE pg_has_role(current_user,r.oid,'SET')
           AND has_function_privilege(r.oid,p.oid,'EXECUTE WITH GRANT OPTION')))
 AND NOT EXISTS(SELECT FROM ports p JOIN locks l ON p.proname=l.port
 WHERE p.proowner<>p.nspowner OR NOT has_schema_privilege(p.proowner,p.pronamespace,'USAGE')
 OR NOT has_any_column_privilege(p.proowner,format('identity_authority.%I',l.relation),'UPDATE')
 OR EXISTS(SELECT FROM unnest(l.columns_used) col WHERE NOT has_column_privilege(
        p.proowner,format('identity_authority.%I',l.relation),col,'SELECT')))
