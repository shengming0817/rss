-- Function bodies come from the single installation artifact, not a second SQL implementation.
WITH functions(signature,body,result,retset) AS (VALUES
 ('rss_transactional_messaging.consumer_scope_domain()',$1::text,'text'::regtype,false),
 ('rss_transactional_messaging.consumer_inbox_allowed(uuid,text,text)',$2::text,'boolean'::regtype,false),
 ('rss_transactional_messaging.projection_scope_matches(text,text)',$3::text,'boolean'::regtype,false),
 ('rss_transactional_messaging.local_projection_dr_status(uuid,bigint,uuid)',$4::text,'record'::regtype,true)
), scope_table AS (SELECT * FROM pg_class WHERE oid=to_regclass('rss_transactional_messaging.consumer_scope'))
SELECT EXISTS(SELECT FROM scope_table WHERE relkind='r' AND NOT relrowsecurity AND NOT relforcerowsecurity AND NOT pg_has_role(current_user,relowner,'MEMBER'))
 AND NOT EXISTS(SELECT FROM pg_roles r CROSS JOIN scope_table t WHERE
  (r.rolname='rss_tmsg_relay' OR pg_has_role(current_user,r.oid,'SET') OR pg_has_role(current_user,r.oid,'USAGE'))
  AND (has_table_privilege(r.oid,t.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   OR has_any_column_privilege(r.oid,t.oid,'INSERT,UPDATE,REFERENCES')))
 AND NOT EXISTS(SELECT FROM functions f LEFT JOIN pg_proc p ON p.oid=to_regprocedure(f.signature)
  WHERE p.oid IS NULL OR p.prosrc IS DISTINCT FROM f.body OR NOT p.prosecdef OR p.provolatile<>'s'
   OR p.prorettype<>f.result OR p.proretset<>f.retset OR p.proowner<>'rss_tmsg_relay'::regrole
   OR p.prolang<>(SELECT oid FROM pg_language WHERE lanname='sql')
   OR p.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, rss_transactional_messaging, pg_temp']
   OR (NOT f.retset AND NOT has_function_privilege(current_user,p.oid,'EXECUTE'))
   OR (f.retset AND EXISTS(SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) WHERE grantee=0 AND privilege_type='EXECUTE')))
 AND EXISTS(SELECT FROM pg_constraint WHERE conrelid='rss_transactional_messaging.consumer_scope'::regclass
  AND contype='p' AND NOT condeferrable AND convalidated AND pg_get_constraintdef(oid)='PRIMARY KEY (login_role)')
 AND NOT EXISTS(SELECT FROM (VALUES('login_role','name'),('domain','text'),('consumer_group','text')) e(name,type)
  LEFT JOIN pg_attribute a ON a.attrelid='rss_transactional_messaging.consumer_scope'::regclass AND a.attname=e.name AND NOT a.attisdropped
  WHERE a.attnum IS NULL OR NOT a.attnotnull OR format_type(a.atttypid,a.atttypmod)<>e.type)
 AND NOT EXISTS(SELECT FROM (VALUES
  ('outbox','outbox_consumer_scope','((domain = ( SELECT rss_transactional_messaging.consumer_scope_domain() AS consumer_scope_domain)) IS NOT FALSE)'),
  ('inbox','inbox_consumer_scope','rss_transactional_messaging.consumer_inbox_allowed(tenant_id, message_id, consumer_group)'),
  ('consumer_dead_letter','dead_letter_consumer_scope','rss_transactional_messaging.consumer_inbox_allowed(tenant_id, message_id, consumer_group)')
 ) e(relation,name,predicate) LEFT JOIN pg_policy p ON p.polrelid=to_regclass('rss_transactional_messaging.'||e.relation) AND p.polname=e.name
 WHERE p.oid IS NULL OR p.polpermissive OR p.polcmd<>'*' OR p.polroles<>ARRAY[0]::oid[]
 OR pg_get_expr(p.polqual,p.polrelid) IS DISTINCT FROM e.predicate OR pg_get_expr(p.polwithcheck,p.polrelid) IS DISTINCT FROM e.predicate)

 AND NOT EXISTS(SELECT FROM (VALUES
  ('rss_transactional_messaging.outbox_candidates(uuid,text,timestamptz,timestamptz,integer)',$5::text,false,'s','sql',NULL::text[]),
  ('rss_transactional_messaging.reclaim_published_bodies(bigint,bigint,integer)',$8::text,true,'v','plpgsql',ARRAY['search_path=pg_catalog, rss_transactional_messaging, pg_temp']),
 ('rss_transactional_messaging.outbox_claim_window(uuid,text,timestamptz,bigint,integer,timestamptz,integer)',$7::text,false,'s','sql',NULL::text[]),
 ('rss_transactional_messaging.claim_outbox(uuid,text,integer,bigint)',$6::text,true,'v','plpgsql',ARRAY['search_path=pg_catalog, rss_transactional_messaging, pg_temp'])
 ) f(signature,body,definer,volatility,language,config)
 LEFT JOIN pg_proc p ON p.oid=to_regprocedure(f.signature)
 WHERE p.oid IS NULL OR p.prosrc IS DISTINCT FROM f.body OR p.prosecdef<>f.definer
  OR p.provolatile::text<>f.volatility OR p.prolang<>(SELECT oid FROM pg_language WHERE lanname=f.language)
  OR p.proconfig IS DISTINCT FROM f.config OR p.proowner<>'rss_tmsg_relay'::regrole
  OR p.prorettype<>'record'::regtype OR NOT p.proretset)

 AND NOT EXISTS(SELECT FROM pg_proc p WHERE p.oid=to_regprocedure('rss_transactional_messaging.outbox_claim_window(uuid,text,timestamptz,bigint,integer,timestamptz,integer)')
  AND (has_function_privilege(current_user,p.oid,'EXECUTE') OR EXISTS(SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) WHERE grantee=0 AND privilege_type='EXECUTE')))
 AND EXISTS(SELECT FROM pg_class c JOIN pg_policy p ON p.polrelid=c.oid
  WHERE c.oid=to_regclass('rss_transactional_messaging.outbox_scan') AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity
   AND NOT pg_has_role(current_user,c.relowner,'MEMBER')
   AND (SELECT count(*) FROM pg_policy all_p WHERE all_p.polrelid=c.oid)=1
   AND p.polname='scan_tenant' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0]::oid[]
   AND pg_get_expr(p.polqual,c.oid)=$p$(tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)$p$
   AND pg_get_expr(p.polwithcheck,c.oid)=$p$(tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)$p$)
 AND EXISTS(SELECT FROM pg_constraint c JOIN pg_index i ON i.indexrelid=c.conindid
  WHERE c.conrelid=to_regclass('rss_transactional_messaging.outbox_scan') AND c.contype='p' AND c.conname='outbox_scan_pkey'
   AND NOT c.condeferrable AND c.convalidated AND i.indisvalid AND i.indisready
   AND pg_get_constraintdef(c.oid)='PRIMARY KEY (tenant_id, domain)')
 AND EXISTS(SELECT FROM pg_constraint WHERE conrelid=to_regclass('rss_transactional_messaging.outbox_scan')
  AND contype='c' AND convalidated AND pg_get_constraintdef(oid)='CHECK (((lane >= 0) AND (lane <= 3)))')
 AND (SELECT count(*) FROM pg_attribute WHERE attrelid=to_regclass('rss_transactional_messaging.outbox_scan') AND attnum>0 AND NOT attisdropped)=6
 AND NOT EXISTS(SELECT FROM (VALUES ('tenant_id','uuid'),('domain','text'),('through_at','timestamp with time zone'),
  ('eligible_at','timestamp with time zone'),('source_seq','bigint'),('lane','integer')) e(name,type)
  LEFT JOIN pg_attribute a ON a.attrelid=to_regclass('rss_transactional_messaging.outbox_scan') AND a.attname=e.name AND NOT a.attisdropped
  WHERE a.attnum IS NULL OR NOT a.attnotnull OR format_type(a.atttypid,a.atttypmod)<>e.type
   OR (e.name='domain' AND a.attcollation<>'"C"'::regcollation))
 AND NOT EXISTS(SELECT FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE']) privilege
  WHERE NOT has_table_privilege('rss_tmsg_relay','rss_transactional_messaging.outbox_scan',privilege))
 AND NOT EXISTS(SELECT FROM pg_roles r WHERE (pg_has_role(current_user,r.oid,'SET') OR pg_has_role(current_user,r.oid,'USAGE'))
  AND (has_table_privilege(r.oid,'rss_transactional_messaging.outbox_scan','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   OR has_any_column_privilege(r.oid,'rss_transactional_messaging.outbox_scan','SELECT,INSERT,UPDATE,REFERENCES')))
