-- Common startup checks, including profiles whose SQL authority is function-only.
WITH policy_table AS (
 SELECT oid,relowner FROM pg_class WHERE oid=to_regclass('rss_transactional_messaging.policy') AND relkind='r'
), functions(signature,body,definer,volatility,owner,public_read) AS (VALUES
 ('protect_policy_change()',$1::text,false,'v',(SELECT relowner FROM policy_table),false),
 ('lock_outbox_policy()',$2::text,true,'v',(SELECT relowner FROM policy_table),false),
 ('outbox_policy_present()',$3::text,true,'s',(SELECT relowner FROM policy_table),true),
 ('settle_outbox(uuid,bigint,uuid,bigint,text,uuid)',$4::text,true,'v','rss_tmsg_relay'::regrole::oid,false),
 ('archive_claim(uuid,uuid,bigint,bytea,bigint,bigint,boolean,bigint,integer)',$5::text,true,'v',(SELECT relowner FROM policy_table),false),
 ('archive_purge(uuid,uuid,bytea,jsonb)',$6::text,true,'v',(SELECT relowner FROM policy_table),false)
), constraints(name,definition) AS (VALUES
 ('policy_pkey','PRIMARY KEY (revision)'),('policy_revision_check','CHECK ((revision = 1))'),
 ('policy_automatic_window_seconds_check','CHECK ((automatic_window_seconds > 0))'),
 ('policy_safety_seconds_check','CHECK ((safety_seconds > 0))'),
 ('policy_check','CHECK ((receipt_retention_seconds > ((automatic_window_seconds)::bigint + safety_seconds)))'),
 ('policy_retry_initial_seconds_check','CHECK ((retry_initial_seconds > 0))'),
 ('policy_retry_max_seconds_check','CHECK ((retry_max_seconds >= retry_initial_seconds))')
)
SELECT rss_transactional_messaging.outbox_policy_present()
 AND EXISTS(SELECT FROM policy_table t WHERE NOT pg_has_role(current_user,t.relowner,'MEMBER'))
 AND NOT EXISTS(SELECT FROM (VALUES
  ('revision','integer'),('automatic_window_seconds','integer'),('safety_seconds','integer'),
  ('receipt_retention_seconds','integer'),('retry_initial_seconds','integer'),('retry_max_seconds','integer'),
  ('hot_floor_until','timestamp with time zone'),('receipt_floor_until','timestamp with time zone')
 ) e(name,kind) LEFT JOIN pg_attribute a ON a.attrelid=(SELECT oid FROM policy_table)
   AND a.attname=e.name AND NOT a.attisdropped
 WHERE a.attnum IS NULL OR NOT a.attnotnull OR format_type(a.atttypid,a.atttypmod)<>e.kind)
 AND NOT EXISTS(SELECT FROM constraints e LEFT JOIN pg_constraint c ON c.conrelid=(SELECT oid FROM policy_table) AND c.conname=e.name
  WHERE c.oid IS NULL OR c.condeferrable OR NOT c.convalidated OR pg_get_constraintdef(c.oid)<>e.definition)
 AND NOT EXISTS(SELECT FROM pg_roles r CROSS JOIN policy_table t
  WHERE (r.rolname='rss_tmsg_relay' OR pg_has_role(current_user,r.oid,'USAGE') OR pg_has_role(current_user,r.oid,'SET'))
   AND (has_table_privilege(r.oid,t.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
    OR has_any_column_privilege(r.oid,t.oid,'INSERT,UPDATE,REFERENCES')
    OR has_function_privilege(r.oid,'rss_transactional_messaging.lock_outbox_policy()','EXECUTE')<>(r.rolname='rss_tmsg_relay')))
 AND has_table_privilege('rss_tmsg_relay','rss_transactional_messaging.policy','SELECT')
 AND EXISTS(SELECT FROM pg_trigger t WHERE t.tgrelid=(SELECT oid FROM policy_table)
  AND t.tgname='protect_policy_change' AND t.tgenabled='O' AND t.tgtype=19 AND t.tgqual IS NULL
  AND NOT t.tgisinternal AND t.tgattr=''::int2vector AND t.tgfoid='rss_transactional_messaging.protect_policy_change()'::regprocedure)
 AND NOT EXISTS(SELECT FROM functions f LEFT JOIN pg_proc p ON p.oid=to_regprocedure('rss_transactional_messaging.'||f.signature)
  WHERE p.oid IS NULL OR p.prosrc IS DISTINCT FROM f.body OR p.proowner IS DISTINCT FROM f.owner
   OR p.prosecdef<>f.definer OR p.provolatile::text<>f.volatility
   OR p.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, rss_transactional_messaging, pg_temp']
   OR EXISTS(SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) WHERE grantee=0 AND privilege_type='EXECUTE')<>f.public_read)
