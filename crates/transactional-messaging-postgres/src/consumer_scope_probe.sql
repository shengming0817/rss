-- Function bodies come from the single installation artifact, not a second SQL implementation.
WITH functions(signature,body) AS (VALUES
 ('rss_transactional_messaging.consumer_domain_allowed(text)',$1::text),
 ('rss_transactional_messaging.consumer_inbox_allowed(uuid,text,text)',$2::text),
 ('rss_transactional_messaging.projection_scope_matches(text,text)',$3::text)
), scope_table AS (SELECT * FROM pg_class WHERE oid=to_regclass('rss_transactional_messaging.consumer_scope'))
SELECT EXISTS(SELECT FROM scope_table WHERE relkind='r' AND NOT pg_has_role(current_user,relowner,'MEMBER'))
 AND NOT EXISTS(SELECT FROM pg_roles r CROSS JOIN scope_table t WHERE
  (r.rolname='rss_tmsg_relay' OR pg_has_role(current_user,r.oid,'SET') OR pg_has_role(current_user,r.oid,'USAGE'))
  AND (has_table_privilege(r.oid,t.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   OR has_any_column_privilege(r.oid,t.oid,'INSERT,UPDATE,REFERENCES')))
 AND NOT EXISTS(SELECT FROM functions f LEFT JOIN pg_proc p ON p.oid=to_regprocedure(f.signature)
  WHERE p.oid IS NULL OR p.prosrc IS DISTINCT FROM f.body OR NOT p.prosecdef OR p.provolatile<>'s'
   OR p.prorettype<>'boolean'::regtype OR p.proretset OR p.proowner<>'rss_tmsg_relay'::regrole
   OR p.prolang<>(SELECT oid FROM pg_language WHERE lanname='sql')
   OR p.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, rss_transactional_messaging, pg_temp']
   OR NOT has_function_privilege(current_user,p.oid,'EXECUTE'))
 AND EXISTS(SELECT FROM pg_constraint WHERE conrelid='rss_transactional_messaging.consumer_scope'::regclass
  AND contype='p' AND NOT condeferrable AND convalidated AND pg_get_constraintdef(oid)='PRIMARY KEY (login_role)')
 AND NOT EXISTS(SELECT FROM (VALUES('login_role','name'),('domain','text'),('consumer_group','text')) e(name,type)
  LEFT JOIN pg_attribute a ON a.attrelid='rss_transactional_messaging.consumer_scope'::regclass AND a.attname=e.name AND NOT a.attisdropped
  WHERE a.attnum IS NULL OR NOT a.attnotnull OR format_type(a.atttypid,a.atttypmod)<>e.type)
 AND NOT EXISTS(SELECT FROM (VALUES
  ('outbox','outbox_consumer_scope','rss_transactional_messaging.consumer_domain_allowed(domain)'),
  ('inbox','inbox_consumer_scope','rss_transactional_messaging.consumer_inbox_allowed(tenant_id, message_id, consumer_group)'),
  ('consumer_dead_letter','dead_letter_consumer_scope','rss_transactional_messaging.consumer_inbox_allowed(tenant_id, message_id, consumer_group)')
 ) e(relation,name,predicate) LEFT JOIN pg_policy p ON p.polrelid=to_regclass('rss_transactional_messaging.'||e.relation) AND p.polname=e.name
 WHERE p.oid IS NULL OR p.polpermissive OR p.polcmd<>'*' OR p.polroles<>ARRAY[0]::oid[]
 OR pg_get_expr(p.polqual,p.polrelid) IS DISTINCT FROM e.predicate OR pg_get_expr(p.polwithcheck,p.polrelid) IS DISTINCT FROM e.predicate)
