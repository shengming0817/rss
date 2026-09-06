WITH roles AS(SELECT NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AS valid FROM pg_roles WHERE rolname=current_user),
relations AS(SELECT unnest(ARRAY['consumer_dead_letter','archive_jobs','archive_objects']) AS name),
functions AS(SELECT unnest(ARRAY['archive_claim(uuid,uuid,bigint,bytea,bigint,bigint,boolean,bigint)','archive_prepare(uuid,uuid,bytea,jsonb,bytea)','archive_record(uuid,uuid,bytea,uuid,jsonb)','archive_purge(uuid,uuid,bytea,jsonb)','archive_missing(uuid,uuid,bytea,uuid,jsonb)','archive_fault(uuid,uuid,bytea,text)']) AS signature), protected_functions AS(SELECT signature FROM functions UNION ALL SELECT 'archive_fence(uuid,uuid,bytea)'), expected_columns(relation,name,type,nullable) AS (VALUES
('archive_jobs','tenant_id','uuid',false),('archive_jobs','operation_id','uuid',false),('archive_jobs','dead_letter_id','uuid',false),('archive_jobs','request_digest','bytea',false),('archive_jobs','source_version','int8',false),('archive_jobs','hot_seconds','int8',false),('archive_jobs','cold_seconds','int8',false),('archive_jobs','held','bool',false),('archive_jobs','generation','uuid',false),('archive_jobs','lease_token','uuid',true),('archive_jobs','lease_until','timestamptz',true),('archive_jobs','purged','bool',false),('archive_jobs','fault','text',true),
('archive_objects','tenant_id','uuid',false),('archive_objects','operation_id','uuid',false),('archive_objects','generation','uuid',false),('archive_objects','object','jsonb',false),('archive_objects','prepared','bytea',true),('archive_objects','verified','bool',false),('archive_objects','reconciled','bool',false),('archive_objects','last_checked','timestamptz',true)),
expected_constraints(relation,name,definition) AS (VALUES
('archive_jobs','archive_jobs_cold_seconds_check','CHECK ((cold_seconds > 0))'),
('archive_jobs','archive_jobs_fault_check','CHECK ((fault = ANY (ARRAY[''missing''::text, ''evidence''::text])))'),
('archive_jobs','archive_jobs_hot_seconds_check','CHECK ((hot_seconds > 0))'),
('archive_jobs','archive_jobs_pkey','PRIMARY KEY (tenant_id, operation_id)'),
('archive_jobs','archive_jobs_request_digest_check','CHECK ((octet_length(request_digest) = 32))'),
('archive_jobs','archive_jobs_tenant_id_dead_letter_id_fkey','FOREIGN KEY (tenant_id, dead_letter_id) REFERENCES rss_transactional_messaging.consumer_dead_letter(tenant_id, id)'),
('archive_objects','archive_objects_pkey','PRIMARY KEY (tenant_id, generation)'),
('archive_objects','archive_objects_prepared_check','CHECK (((prepared IS NULL) OR ((octet_length(prepared) >= 1) AND (octet_length(prepared) <= 67108864))))'),
('archive_objects','archive_objects_tenant_id_operation_id_fkey','FOREIGN KEY (tenant_id, operation_id) REFERENCES rss_transactional_messaging.archive_jobs(tenant_id, operation_id)')), expected_defaults(relation,name,expression) AS (VALUES
('archive_jobs','purged','false'),('archive_objects','verified','false'),('archive_objects','reconciled','false'))

SELECT (SELECT valid FROM roles)
 AND NOT has_schema_privilege(current_user,'rss_transactional_messaging','CREATE')
 AND NOT EXISTS(SELECT 1 FROM relations r LEFT JOIN pg_class c ON c.oid=to_regclass('rss_transactional_messaging.'||r.name) WHERE c.oid IS NULL OR NOT c.relrowsecurity OR NOT c.relforcerowsecurity OR pg_has_role(current_user,c.relowner,'MEMBER') OR NOT has_table_privilege(current_user,c.oid,'SELECT') OR has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES'))
 AND NOT EXISTS(SELECT 1 FROM protected_functions f LEFT JOIN pg_proc p ON p.oid=to_regprocedure('rss_transactional_messaging.'||f.signature) WHERE p.oid IS NULL OR NOT p.prosecdef OR ('search_path=pg_catalog, rss_transactional_messaging, pg_temp'=ANY(p.proconfig)) IS DISTINCT FROM true OR has_function_privilege(current_user,p.oid,'EXECUTE')<>(f.signature<>'archive_fence(uuid,uuid,bytea)') OR pg_has_role(current_user,p.proowner,'MEMBER') OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE'))
 AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='rss_transactional_messaging' AND has_function_privilege(current_user,p.oid,'EXECUTE') AND NOT EXISTS(SELECT 1 FROM functions f WHERE p.oid=to_regprocedure('rss_transactional_messaging.'||f.signature)))
 AND EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='rss_transactional_messaging' AND table_name='consumer_dead_letter' AND column_name='capsule' AND is_nullable='YES')

 AND NOT EXISTS(SELECT 1 FROM pg_roles r WHERE (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole) AND (pg_has_role(current_user,r.oid,'USAGE') OR pg_has_role(current_user,r.oid,'SET')))
 AND (SELECT count(*)=3 FROM pg_policy p JOIN relations r ON p.polrelid=to_regclass('rss_transactional_messaging.'||r.name))
 AND NOT EXISTS(SELECT 1 FROM relations r LEFT JOIN pg_policy p ON p.polrelid=to_regclass('rss_transactional_messaging.'||r.name)
 WHERE p.oid IS NULL OR p.polname<>CASE WHEN r.name='consumer_dead_letter' THEN 'recovery_tenant' ELSE 'archive_tenant' END OR NOT p.polpermissive OR p.polcmd<>'*' OR p.polroles<>ARRAY[0]::oid[]
 OR pg_get_expr(p.polqual,p.polrelid) IS DISTINCT FROM '(tenant_id = (NULLIF(current_setting(''rss.tenant_id''::text, true), ''''::text))::uuid)'
 OR pg_get_expr(p.polwithcheck,p.polrelid) IS DISTINCT FROM '(tenant_id = (NULLIF(current_setting(''rss.tenant_id''::text, true), ''''::text))::uuid)')
 AND NOT EXISTS(SELECT 1 FROM expected_columns e LEFT JOIN information_schema.columns a ON a.table_schema='rss_transactional_messaging' AND a.table_name=e.relation AND a.column_name=e.name
 WHERE a.column_name IS NULL OR a.udt_name<>e.type OR (a.is_nullable='YES')<>e.nullable)
 AND NOT EXISTS(SELECT 1 FROM expected_constraints e LEFT JOIN pg_constraint c ON c.conrelid=to_regclass('rss_transactional_messaging.'||e.relation) AND c.conname=e.name
 WHERE c.oid IS NULL OR NOT c.convalidated OR c.condeferrable OR pg_get_constraintdef(c.oid)<>e.definition)
 AND NOT EXISTS(SELECT 1 FROM expected_defaults e LEFT JOIN pg_attribute a ON a.attrelid=to_regclass('rss_transactional_messaging.'||e.relation) AND a.attname=e.name LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
 WHERE d.oid IS NULL OR pg_get_expr(d.adbin,d.adrelid)<>e.expression)
 AND EXISTS(SELECT 1 FROM pg_index i WHERE i.indexrelid=to_regclass('rss_transactional_messaging.archive_source') AND i.indrelid='rss_transactional_messaging.archive_jobs'::regclass AND i.indisvalid AND i.indisready AND i.indpred IS NULL
 AND (SELECT array_agg(a.attname ORDER BY k.ord) FROM unnest(i.indkey) WITH ORDINALITY k(num,ord) JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.num)=ARRAY['tenant_id','dead_letter_id']::name[])
