WITH required_privileges AS (
 SELECT * FROM (VALUES ('runtime','webauthn_rp','SELECT'),('runtime','webauthn_rp','INSERT'),('runtime','webauthn_accounts','SELECT'),('runtime','webauthn_accounts','INSERT'),('runtime','webauthn_accounts','UPDATE'),('runtime','webauthn_accounts','DELETE'),('runtime','webauthn_credentials','SELECT'),('runtime','webauthn_credentials','INSERT'),('runtime','webauthn_credentials','UPDATE'),('runtime','webauthn_credentials','DELETE'),('runtime','webauthn_ceremonies','SELECT'),('runtime','webauthn_ceremonies','INSERT'),('runtime','webauthn_ceremonies','UPDATE'),('runtime','webauthn_ceremonies','DELETE'),('runtime','step_up_grants','SELECT'),('runtime','step_up_grants','INSERT'),('runtime','step_up_grants','UPDATE'),('runtime','step_up_grants','DELETE'),('runtime','password_attempts','SELECT'),('runtime','password_attempts','INSERT'),('runtime','password_attempts','UPDATE'),('runtime','password_attempts','DELETE'),('maintenance','password_attempts','SELECT'),('maintenance','password_attempts','DELETE'),('runtime','platform_challenges','SELECT'),('runtime','platform_challenges','INSERT'),('runtime','platform_challenges','UPDATE'),('runtime','platform_challenges','DELETE'),('runtime','local_profiles','SELECT'),('runtime','local_profiles','INSERT'),('runtime','local_profiles','UPDATE'),('runtime','profile_observations','SELECT'),('runtime','profile_observations','INSERT'),('runtime','profile_observations','UPDATE'),('runtime','profile_observations','DELETE'),('runtime','profile_operations','SELECT'),('runtime','profile_operations','INSERT'),('runtime','profile_operations','DELETE'),('provisioning','schema_version','SELECT'),('provisioning','deployment','SELECT'),('provisioning','tenants','SELECT'),('provisioning','tenant_state','SELECT'),('provisioning','tenants','INSERT'),('provisioning','tenants','UPDATE'),('provisioning','accounts','SELECT'),('provisioning','accounts','INSERT'),('provisioning','memberships','SELECT'),('provisioning','memberships','INSERT'),('provisioning','local_credentials','SELECT'),('provisioning','local_credentials','INSERT'),('provisioning','sessions','SELECT'),('provisioning','providers','SELECT'),('provisioning','external_identities','SELECT'),('runtime','directory_revisions','SELECT'),('runtime','schema_version','SELECT'),('runtime','deployment','SELECT'),('runtime','tenants','SELECT'),('runtime','tenant_state','SELECT'),('runtime','tenants','UPDATE'),('runtime','accounts','SELECT'),('runtime','accounts','INSERT'),('runtime','accounts','UPDATE'),('runtime','memberships','SELECT'),('runtime','memberships','INSERT'),('runtime','memberships','UPDATE'),('runtime','local_credentials','SELECT'),('runtime','local_credentials','INSERT'),('runtime','local_credentials','UPDATE'),('runtime','attempts','SELECT'),('runtime','attempts','INSERT'),('runtime','attempts','UPDATE'),('runtime','attempts','DELETE'),('runtime','sessions','SELECT'),('runtime','sessions','INSERT'),('runtime','sessions','UPDATE'),('runtime','providers','SELECT'),('runtime','providers','INSERT'),('runtime','providers','UPDATE'),('runtime','provider_credentials','SELECT'),('runtime','provider_credentials','INSERT'),('runtime','provider_credentials','UPDATE'),('runtime','external_identities','SELECT'),('runtime','external_identities','INSERT'),('runtime','external_identities','UPDATE'),('runtime','link_intents','SELECT'),('runtime','link_intents','INSERT'),('runtime','link_intents','UPDATE'),('runtime','link_intents','DELETE'),('runtime','oidc_transactions','SELECT'),('runtime','oidc_transactions','INSERT'),('runtime','oidc_transactions','UPDATE'),('runtime','oidc_transactions','DELETE'),('maintenance','schema_version','SELECT'),('maintenance','deployment','SELECT'),('maintenance','tenants','SELECT'),('maintenance','tenant_state','SELECT'),('maintenance','tenants','INSERT'),('maintenance','tenants','UPDATE'),('maintenance','accounts','SELECT'),('maintenance','accounts','INSERT'),('maintenance','memberships','SELECT'),('maintenance','memberships','INSERT'),('maintenance','local_credentials','SELECT'),('maintenance','local_credentials','INSERT')) r(profile,tab,privilege)
), required_columns AS (
 SELECT * FROM (VALUES ('runtime','tenant_state','value','UPDATE'),
 ('maintenance','tenant_state','tenant_id','UPDATE'),('maintenance','tenant_state','tenant_id','INSERT'),('maintenance','tenant_state','kind','INSERT'),
 ('provisioning','tenant_state','tenant_id','INSERT'),('provisioning','tenant_state','kind','INSERT'),
 ('maintenance', 'accounts', 'auth_epoch', 'UPDATE'),('maintenance', 'local_credentials', 'password_hash', 'UPDATE')) r(profile,tab,col,privilege)
), tables AS (
 SELECT c.oid,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='identity_authority' AND c.relkind='r'
), reachable AS (
 SELECT oid FROM pg_roles WHERE pg_has_role(current_user,oid,'SET')
), allowed_functions AS (
 SELECT unnest(ARRAY['identity_authority.share_host_tenant()'::regprocedure,'identity_authority.lock_session(bytea,uuid,text,text,uuid)'::regprocedure,'identity_authority.share_subject(uuid)'::regprocedure,'identity_authority.share_provider(uuid)'::regprocedure]) AS oid WHERE $1='runtime'
), checks AS (
 SELECT
 (NOT EXISTS(SELECT FROM pg_roles WHERE pg_has_role(current_user,oid,'MEMBER') AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication))) AS role_ok,
 (has_schema_privilege(current_user,'identity_authority','USAGE')
 AND NOT EXISTS(SELECT FROM reachable u WHERE has_schema_privilege(u.oid,'identity_authority','CREATE,USAGE WITH GRANT OPTION'))
 AND NOT EXISTS(SELECT FROM reachable u JOIN pg_auth_members m ON m.member=u.oid WHERE m.admin_option)
 AND (SELECT bool_and(coalesce(has_table_privilege(current_user,t.oid,r.privilege),false)) FROM required_privileges r LEFT JOIN tables t ON t.relname=r.tab WHERE r.profile=$1)
 AND NOT EXISTS (
   SELECT FROM reachable u CROSS JOIN tables t CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),('REFERENCES'),('TRIGGER'),('MAINTAIN')) p(privilege)
   WHERE has_table_privilege(u.oid,t.oid,p.privilege) AND NOT
     EXISTS(SELECT FROM required_privileges r WHERE r.profile=$1 AND r.tab=t.relname AND r.privilege=p.privilege)
     OR has_table_privilege(u.oid,t.oid,p.privilege||' WITH GRANT OPTION')
 )
 AND NOT EXISTS (
   SELECT FROM reachable u CROSS JOIN tables t JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum>0 AND NOT a.attisdropped
   CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('REFERENCES')) p(privilege)
   WHERE has_column_privilege(u.oid,t.oid,a.attnum,p.privilege) AND NOT
     (EXISTS(SELECT FROM required_privileges r WHERE r.profile=$1 AND r.tab=t.relname AND r.privilege=p.privilege)
      OR EXISTS(SELECT FROM required_columns r WHERE r.profile=$1 AND r.tab=t.relname AND r.col=a.attname AND r.privilege=p.privilege))
     OR has_column_privilege(u.oid,t.oid,a.attnum,p.privilege||' WITH GRANT OPTION')
 )
 AND NOT EXISTS(SELECT FROM required_columns r JOIN tables t ON t.relname=r.tab WHERE r.profile=$1 AND NOT has_column_privilege(current_user,t.oid,r.col,r.privilege))
 AND NOT EXISTS(SELECT FROM allowed_functions f WHERE NOT has_function_privilege(current_user,f.oid,'EXECUTE'))
 AND NOT EXISTS(SELECT FROM reachable u CROSS JOIN pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
   WHERE n.nspname='identity_authority' AND (has_function_privilege(u.oid,p.oid,'EXECUTE WITH GRANT OPTION') OR
     (has_function_privilege(u.oid,p.oid,'EXECUTE') AND NOT EXISTS(SELECT FROM allowed_functions f WHERE f.oid=p.oid))))
) AS privileges_ok
)
SELECT CASE
 WHEN role_ok IS NOT TRUE THEN 'role'
 WHEN privileges_ok IS NOT TRUE THEN 'privileges'
 ELSE 'ok' END FROM checks
