-- Missing schema fails closed. Ordinary execution cannot modify generations or apply recovery.
SELECT to_regclass('rss_transactional_messaging.storage_lineage') IS NOT NULL
 AND to_regclass('rss_transactional_messaging.tenant_epoch') IS NOT NULL
 AND to_regclass('rss_transactional_messaging.dr_members') IS NOT NULL
 AND to_regprocedure('rss_transactional_messaging.claim_outbox(text,integer,bigint)') IS NULL
 AND has_function_privilege(current_user,'rss_transactional_messaging.check_execution()','EXECUTE')
 AND has_table_privilege('rss_tmsg_relay','rss_transactional_messaging.storage_lineage','SELECT')
 AND has_column_privilege('rss_tmsg_relay','rss_transactional_messaging.storage_lineage','singleton','UPDATE')
 AND NOT has_table_privilege('rss_tmsg_relay','rss_transactional_messaging.storage_lineage','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND NOT has_any_column_privilege('rss_tmsg_relay','rss_transactional_messaging.storage_lineage','INSERT,REFERENCES')
 AND NOT has_column_privilege('rss_tmsg_relay','rss_transactional_messaging.storage_lineage','target','UPDATE')
 AND NOT has_column_privilege('rss_tmsg_relay','rss_transactional_messaging.storage_lineage','lineage','UPDATE')
 AND NOT has_table_privilege(current_user,'rss_transactional_messaging.storage_lineage','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
 AND NOT has_table_privilege(current_user,'rss_transactional_messaging.tenant_epoch','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
 AND NOT has_table_privilege(current_user,'rss_transactional_messaging.dr_plans','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
 AND NOT has_table_privilege(current_user,'rss_transactional_messaging.dr_members','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
 AND ($1 OR (NOT has_function_privilege(current_user,'rss_transactional_messaging.apply_dr(uuid,bytea,text,jsonb,jsonb,bigint)','EXECUTE') AND NOT has_function_privilege(current_user,'rss_transactional_messaging.read_dr(uuid,bytea)','EXECUTE')))
 AND NOT EXISTS(SELECT 1 FROM (VALUES ('inbox'),('outbox'),('consumer_dead_letter'),('recovery_operations'),('archive_jobs'),('archive_objects'),('dr_members')) r(name)
 LEFT JOIN pg_trigger t ON t.tgrelid=to_regclass('rss_transactional_messaging.'||r.name) AND t.tgname='execution_fence'
 WHERE t.oid IS NULL OR t.tgenabled<>'O' OR t.tgfoid<>'rss_transactional_messaging.guard_execution()'::regprocedure OR t.tgtype<>31 OR t.tgattr<>''::int2vector OR t.tgisinternal OR t.tgconstraint<>0 OR t.tgqual IS NOT NULL)
 AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='rss_transactional_messaging' AND p.proname IN ('check_execution','guard_execution','apply_dr','read_dr','guard_dr_consumer')
 AND (NOT p.prosecdef OR p.proowner<>'rss_tmsg_relay'::regrole OR NOT('search_path=pg_catalog, rss_transactional_messaging, pg_temp'=ANY(p.proconfig))
 OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE')))

 AND NOT EXISTS(SELECT 1 FROM pg_roles r WHERE (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole) AND (pg_has_role(current_user,r.oid,'USAGE') OR pg_has_role(current_user,r.oid,'SET')))
 AND NOT pg_has_role(current_user,'rss_tmsg_relay','MEMBER')
 AND NOT has_schema_privilege(current_user,'rss_transactional_messaging','CREATE')
 AND (NOT $1 OR (has_function_privilege(current_user,'rss_transactional_messaging.apply_dr(uuid,bytea,text,jsonb,jsonb,bigint)','EXECUTE') AND has_function_privilege(current_user,'rss_transactional_messaging.read_dr(uuid,bytea)','EXECUTE')))
 AND to_regprocedure('rss_transactional_messaging.outbox_lease(bigint,uuid,bigint,bigint)') IS NULL
 AND to_regprocedure('rss_transactional_messaging.settle_outbox(bigint,uuid,bigint,text)') IS NULL
 AND NOT EXISTS(SELECT 1 FROM (VALUES
 ('storage_lineage','singleton','boolean'),('storage_lineage','target','bytea'),('storage_lineage','lineage','bytea'),
 ('tenant_epoch','tenant_id','uuid'),('tenant_epoch','epoch','bigint'),
 ('dr_plans','request_digest','bytea'),('dr_plans','lineage','bytea'),('dr_plans','epoch','bigint'),
 ('dr_members','ordinal','integer'),('dr_members','status','text'),('dr_members','fingerprint','bytea'),
 ('inbox','claim_epoch','bigint'),('outbox','claim_epoch','bigint'),('archive_jobs','claim_epoch','bigint'),('archive_objects','verified_epoch','bigint')
 ) e(relation,column_name,type_name) LEFT JOIN pg_attribute a ON a.attrelid=to_regclass('rss_transactional_messaging.'||e.relation) AND a.attname=e.column_name AND NOT a.attisdropped
 WHERE a.attnum IS NULL OR format_type(a.atttypid,a.atttypmod)<>e.type_name OR NOT a.attnotnull)
 AND NOT EXISTS(SELECT 1 FROM (VALUES
 ('dr_plans','dr_plan_action','CHECK ((((kind <> ''terminate''::text) AND (evidence IS NOT NULL) AND (target_operation IS NULL) AND (target_digest IS NULL)) OR ((kind = ''terminate''::text) AND (evidence IS NULL) AND (target_operation IS NOT NULL) AND (target_digest IS NOT NULL) AND (octet_length(target_digest) = 32))))'),
 ('dr_plans','dr_plans_kind_check','CHECK ((kind = ANY (ARRAY[''database''::text, ''broker''::text, ''terminate''::text])))'),
 ('dr_plans','dr_plans_tenant_id_target_operation_fkey','FOREIGN KEY (tenant_id, target_operation) REFERENCES rss_transactional_messaging.dr_plans(tenant_id, operation_id)'),
 ('dr_plans','dr_plans_tenant_id_target_operation_key','UNIQUE (tenant_id, target_operation)'),
 ('dr_members','dr_member_block_shape','CHECK (((status = ''blocked''::text) = (block_reason IS NOT NULL)))'),
 ('dr_members','dr_member_reason','CHECK ((block_reason = ANY (ARRAY[''deadline_expired''::text, ''permanent_publish_failure''::text])))'),
 ('storage_lineage','storage_lineage_pkey','PRIMARY KEY (singleton)'),
 ('storage_lineage','storage_lineage_singleton_check','CHECK (singleton)'),
 ('tenant_epoch','tenant_epoch_pkey','PRIMARY KEY (tenant_id)'),
 ('tenant_epoch','tenant_epoch_epoch_check','CHECK ((epoch > 0))'),
 ('dr_plans','dr_plans_pkey','PRIMARY KEY (tenant_id, operation_id)'),
 ('dr_plans','dr_plans_tenant_id_lineage_epoch_key','UNIQUE (tenant_id, lineage, epoch)'),
 ('dr_plans','dr_plans_request_digest_check','CHECK ((octet_length(request_digest) = 32))'),
 ('dr_members','dr_members_pkey','PRIMARY KEY (tenant_id, operation_id, ordinal)'),
 ('dr_members','dr_members_tenant_id_operation_id_message_id_consumer_group_key','UNIQUE (tenant_id, operation_id, message_id, consumer_group)')
 ) e(relation,name,definition) LEFT JOIN pg_constraint c ON c.conrelid=to_regclass('rss_transactional_messaging.'||e.relation) AND c.conname=e.name
 WHERE c.oid IS NULL OR NOT c.convalidated OR c.condeferrable OR pg_get_constraintdef(c.oid)<>e.definition)
 AND NOT EXISTS(SELECT 1 FROM (VALUES ('tenant_epoch','tenant_fence'),('dr_plans','dr_tenant'),('dr_members','dr_tenant')) e(relation,policy)
 LEFT JOIN pg_class c ON c.oid=to_regclass('rss_transactional_messaging.'||e.relation)
 LEFT JOIN pg_policy p ON p.polrelid=c.oid AND p.polname=e.policy
 WHERE c.oid IS NULL OR NOT c.relrowsecurity OR NOT c.relforcerowsecurity OR p.oid IS NULL OR NOT p.polpermissive OR p.polcmd<>'*' OR p.polroles<>ARRAY[0]::oid[]
 OR (SELECT count(*) FROM pg_policy x WHERE x.polrelid=c.oid)<>1
 OR pg_get_expr(p.polqual,c.oid) IS DISTINCT FROM $p$(tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)$p$
 OR pg_get_expr(p.polwithcheck,c.oid) IS DISTINCT FROM $p$(tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)$p$)

 AND NOT EXISTS(SELECT 1 FROM (VALUES ('storage_lineage'),('tenant_epoch'),('dr_plans'),('dr_members')) t(name)
 WHERE has_any_column_privilege(current_user,'rss_transactional_messaging.'||t.name,'INSERT,UPDATE,REFERENCES'))
 AND NOT EXISTS(SELECT 1 FROM (VALUES
 ('inbox','dr_consumer','rss_transactional_messaging.guard_dr_consumer()',21,''),
 ('archive_jobs','archive_generation','rss_transactional_messaging.guard_archive_generation()',19,''),
 ('archive_objects','archive_generation','rss_transactional_messaging.guard_archive_generation()',19,'verified')
 ) e(relation,name,function,type,column_name) LEFT JOIN pg_trigger t ON t.tgrelid=to_regclass('rss_transactional_messaging.'||e.relation) AND t.tgname=e.name
 WHERE t.oid IS NULL OR t.tgenabled<>'O' OR t.tgfoid<>to_regprocedure(e.function) OR t.tgtype<>e.type OR t.tgisinternal OR t.tgconstraint<>0 OR t.tgqual IS NOT NULL OR t.tgattr IS DISTINCT FROM CASE WHEN e.column_name='' THEN ''::int2vector ELSE (SELECT a.attnum::text::int2vector FROM pg_attribute a WHERE a.attrelid=t.tgrelid AND a.attname=e.column_name AND NOT a.attisdropped) END)

 AND (NOT $1 OR NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='rss_transactional_messaging' AND c.relkind IN ('r','p')
 AND (has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES'))))
 AND (NOT $1 OR NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='rss_transactional_messaging' AND has_function_privilege(current_user,p.oid,'EXECUTE')
 AND p.oid NOT IN ('rss_transactional_messaging.check_execution()'::regprocedure,'rss_transactional_messaging.apply_dr(uuid,bytea,text,jsonb,jsonb,bigint)'::regprocedure,'rss_transactional_messaging.read_dr(uuid,bytea)'::regprocedure)))

 AND NOT EXISTS(SELECT 1 FROM (VALUES ('dr_plans','target_operation','uuid'),('dr_plans','target_digest','bytea'),('dr_plans','evidence','jsonb'),('dr_members','block_reason','text')) e(relation,column_name,type_name)
 LEFT JOIN pg_attribute a ON a.attrelid=to_regclass('rss_transactional_messaging.'||e.relation) AND a.attname=e.column_name AND NOT a.attisdropped
 WHERE a.attnum IS NULL OR format_type(a.atttypid,a.atttypmod)<>e.type_name OR a.attnotnull)
