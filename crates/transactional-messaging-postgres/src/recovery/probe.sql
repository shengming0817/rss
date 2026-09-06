WITH required(name, privileges) AS (
 VALUES ('consumer_dead_letter', CASE WHEN $1 THEN 'SELECT,INSERT,UPDATE' ELSE 'SELECT,INSERT' END)
 UNION ALL SELECT 'recovery_operations', 'SELECT,INSERT' WHERE $1
 UNION ALL SELECT 'outbox', 'SELECT,INSERT,UPDATE' WHERE $1
), checks AS (
 SELECT c.oid, c.relowner, c.relrowsecurity, c.relforcerowsecurity,
   NOT pg_has_role(current_user,c.relowner,'MEMBER')
   AND c.relrowsecurity AND c.relforcerowsecurity
   AND NOT EXISTS (SELECT 1 FROM unnest(string_to_array(r.privileges,',')) p WHERE NOT has_table_privilege(current_user,c.oid,p))
   AND NOT EXISTS (SELECT 1 FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']) p
     WHERE NOT p=ANY(string_to_array(r.privileges,',')) AND
       (has_table_privilege(current_user,c.oid,p) OR (p IN ('SELECT','INSERT','UPDATE','REFERENCES') AND has_any_column_privilege(current_user,c.oid,CASE WHEN p IN ('SELECT','INSERT','UPDATE','REFERENCES') THEN p ELSE 'SELECT' END)))) AS valid
 FROM required r LEFT JOIN pg_class c ON c.oid=to_regclass('rss_transactional_messaging.'||r.name)
), required_columns(relation,name,type) AS (VALUES
 ('consumer_dead_letter','tenant_id','uuid'),('consumer_dead_letter','id','uuid'),
 ('consumer_dead_letter','message_id','text'),('consumer_dead_letter','consumer_group','text'),
 ('consumer_dead_letter','contract','text'),('consumer_dead_letter','contract_version','text'),
 ('consumer_dead_letter','schema_digest','text'),('consumer_dead_letter','fingerprint','bytea'),
 ('consumer_dead_letter','capsule','bytea'),('consumer_dead_letter','reason','text'),
 ('consumer_dead_letter','recovery_version','bigint'),('consumer_dead_letter','created_at','timestamp with time zone'),
 ('recovery_operations','tenant_id','uuid'),('recovery_operations','operation_id','uuid'),
 ('recovery_operations','request_digest','bytea'),('recovery_operations','target_kind','text'),
 ('recovery_operations','target_key','text'),('recovery_operations','outcome','text'),
 ('recovery_operations','result_version','bigint'),('recovery_operations','replay_message_id','text'),
 ('recovery_operations','resolution','text'),('recovery_operations','evidence_message_id','text'))
SELECT NOT EXISTS (SELECT 1 FROM checks WHERE valid IS NOT TRUE)
 AND NOT EXISTS (SELECT 1 FROM required_columns e LEFT JOIN information_schema.columns a ON a.table_schema='rss_transactional_messaging' AND a.table_name=e.relation AND a.column_name=e.name WHERE (e.relation <> 'recovery_operations' OR $1) AND (a.column_name IS NULL OR a.data_type <> e.type OR a.is_nullable <> CASE WHEN e.name IN ('replay_message_id','resolution','evidence_message_id') THEN 'YES' ELSE 'NO' END))
 AND NOT EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid IN ('rss_transactional_messaging.consumer_dead_letter'::regclass,'rss_transactional_messaging.recovery_operations'::regclass) AND (p.polname <> 'recovery_tenant' OR p.polroles <> ARRAY[0]::oid[] OR NOT p.polpermissive OR p.polcmd <> '*'))
 AND (SELECT count(*) = 2 FROM pg_policy WHERE polrelid IN ('rss_transactional_messaging.consumer_dead_letter'::regclass,'rss_transactional_messaging.recovery_operations'::regclass) AND polname='recovery_tenant' AND pg_get_expr(polqual,polrelid) = '(tenant_id = (NULLIF(current_setting(''rss.tenant_id''::text, true), ''''::text))::uuid)' AND pg_get_expr(polwithcheck,polrelid) = '(tenant_id = (NULLIF(current_setting(''rss.tenant_id''::text, true), ''''::text))::uuid)')
 AND NOT EXISTS (
 SELECT 1 FROM (VALUES
  ('consumer_dead_letter','consumer_dead_letter_capsule_check','CHECK (((octet_length(capsule) >= 1) AND (octet_length(capsule) <= 16777216)))'),
  ('consumer_dead_letter','consumer_dead_letter_fingerprint_check','CHECK ((octet_length(fingerprint) = 32))'),
  ('consumer_dead_letter','consumer_dead_letter_pkey','PRIMARY KEY (tenant_id, id)'),
  ('consumer_dead_letter','consumer_dead_letter_reason_check','CHECK ((reason = ANY (ARRAY[''rejected_permanent''::text, ''rejected_invariant''::text])))'),
  ('consumer_dead_letter','consumer_dead_letter_recovery_version_check','CHECK ((recovery_version > 0))'),
  ('consumer_dead_letter','consumer_dead_letter_tenant_id_message_id_consumer_group_key','UNIQUE (tenant_id, message_id, consumer_group)'),
  ('recovery_operations','operation_shape','CHECK ((((outcome = ''replayed''::text) AND (target_kind = ''consumer''::text) AND (replay_message_id IS NOT NULL) AND (resolution IS NULL) AND (evidence_message_id IS NULL)) OR ((outcome = ''redriven''::text) AND (target_kind = ''outbox''::text) AND (replay_message_id IS NULL) AND (resolution IS NULL) AND (evidence_message_id IS NULL)) OR ((outcome = ''resolved''::text) AND (target_kind = ''outbox''::text) AND (replay_message_id IS NULL) AND (resolution IS NOT NULL) AND (((resolution = ''accepted_gap''::text) AND (evidence_message_id IS NULL)) OR ((resolution = ''compensated''::text) AND (evidence_message_id IS NOT NULL))))))'),
  ('recovery_operations','recovery_operations_outcome_check','CHECK ((outcome = ANY (ARRAY[''replayed''::text, ''redriven''::text, ''resolved''::text])))'),
  ('recovery_operations','recovery_replay_identity','UNIQUE (tenant_id, replay_message_id)'),
 ('recovery_operations','recovery_operations_pkey','PRIMARY KEY (tenant_id, operation_id)'),
  ('recovery_operations','recovery_operations_request_digest_check','CHECK ((octet_length(request_digest) = 32))'),
  ('recovery_operations','recovery_operations_resolution_check','CHECK ((resolution = ANY (ARRAY[''accepted_gap''::text, ''compensated''::text])))'),
  ('recovery_operations','recovery_operations_result_version_check','CHECK ((result_version > 0))'),
  ('recovery_operations','recovery_operations_target_kind_check','CHECK ((target_kind = ANY (ARRAY[''consumer''::text, ''outbox''::text])))')
 ) e(relation,name,definition)
 LEFT JOIN pg_constraint c ON c.conrelid=to_regclass('rss_transactional_messaging.'||e.relation) AND c.conname=e.name
 WHERE (e.relation <> 'recovery_operations' OR $1) AND
 (c.oid IS NULL OR NOT c.convalidated OR c.condeferrable OR pg_get_constraintdef(c.oid)<>e.definition))

 AND NOT EXISTS (SELECT 1 FROM (VALUES
 ('consumer_dead_letter','recovery_version','1'),
 ('consumer_dead_letter','created_at','clock_timestamp()'),
 ('recovery_operations','created_at','clock_timestamp()')
 ) e(relation,name,expression)
 LEFT JOIN pg_attribute a ON a.attrelid=to_regclass('rss_transactional_messaging.'||e.relation) AND a.attname=e.name AND NOT a.attisdropped
 LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
 WHERE (e.relation <> 'recovery_operations' OR $1) AND (d.oid IS NULL OR pg_get_expr(d.adbin,d.adrelid)<>e.expression))
 AND (NOT $1 OR EXISTS (SELECT 1 FROM pg_index i WHERE i.indexrelid=to_regclass('rss_transactional_messaging.recovery_replay_identity')
 AND i.indrelid='rss_transactional_messaging.recovery_operations'::regclass AND i.indisvalid AND i.indisready AND i.indisunique
 AND (SELECT array_agg(a.attname ORDER BY k.ord) FROM unnest(i.indkey) WITH ORDINALITY k(num,ord) JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.num)=ARRAY['tenant_id','replay_message_id']::name[]
 AND i.indpred IS NULL))
