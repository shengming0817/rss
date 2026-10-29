WITH expected(table_name,columns,types,required) AS (VALUES
 ('resources',ARRAY['tenant_id','resource','owner_reconciler','owner_entity','owner_token','owner_epoch'],ARRAY['uuid','text','text','text','uuid','bigint'],ARRAY[true,true,false,false,false,false]),
 ('target_resources',ARRAY['tenant_id','reconciler','entity','resource','waiting_ticket'],ARRAY['uuid','text','text','text','bigint'],ARRAY[true,true,true,true,false]),
 ('scans',ARRAY['tenant_id','reconciler','cursor_ticket','high_watermark'],ARRAY['uuid','text','bigint','bigint'],ARRAY[true,true,true,true])
), actual AS (
 SELECT c.relname::text AS table_name,array_agg(a.attname::text ORDER BY a.attnum) AS columns,
  array_agg(format_type(a.atttypid,a.atttypmod) ORDER BY a.attnum) AS types,array_agg(a.attnotnull ORDER BY a.attnum) AS required
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid
 WHERE n.nspname='rss_reconcile' AND c.relname IN ('resources','target_resources','scans') AND a.attnum>0 AND NOT a.attisdropped GROUP BY c.relname
), expected_constraints(table_name,definition) AS (VALUES
 ('resources','PRIMARY KEY (tenant_id, resource)'),
 ('resources','FOREIGN KEY (tenant_id, owner_reconciler, owner_entity) REFERENCES rss_reconcile.targets(tenant_id, reconciler, entity)'),
 ('resources','CHECK ((resource ~ ''^[A-Za-z0-9_.:-]{1,128}$''::text))'),
 ('resources','CHECK ((((owner_token IS NULL) = (owner_reconciler IS NULL)) AND ((owner_token IS NULL) = (owner_entity IS NULL)) AND ((owner_token IS NULL) = (owner_epoch IS NULL))))'),
 ('resources','CHECK (((owner_epoch IS NULL) OR (owner_epoch > 0)))'),
 ('target_resources','PRIMARY KEY (tenant_id, reconciler, entity, resource)'),
 ('target_resources','FOREIGN KEY (tenant_id, reconciler, entity) REFERENCES rss_reconcile.targets(tenant_id, reconciler, entity)'),
 ('target_resources','FOREIGN KEY (tenant_id, resource) REFERENCES rss_reconcile.resources(tenant_id, resource)'),
 ('target_resources','CHECK (((waiting_ticket IS NULL) OR (waiting_ticket > 0)))'),
 ('scans','PRIMARY KEY (tenant_id, reconciler)'),
 ('scans','CHECK ((reconciler ~ ''^[A-Za-z0-9_.:-]{1,128}$''::text))'),
 ('scans','CHECK ((cursor_ticket >= 0))'),
 ('scans','CHECK ((high_watermark >= cursor_ticket))')
), actual_constraints AS (
 SELECT c.relname::text AS table_name,pg_get_constraintdef(k.oid) AS definition,k.convalidated
 FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='rss_reconcile' AND c.relname IN ('resources','target_resources','scans') AND k.contype IN ('p','f','c')
), expected_indexes(name,definition) AS (VALUES
 ('targets_queue','CREATE INDEX targets_queue ON rss_reconcile.targets USING btree (tenant_id, reconciler, queue_ticket) WHERE (next_run IS NOT NULL)'),
 ('targets_unbound','CREATE INDEX targets_unbound ON rss_reconcile.targets USING btree (tenant_id, reconciler) WHERE ((binding_revision = 0) AND (next_run IS NOT NULL))'),
 ('resources_owner','CREATE INDEX resources_owner ON rss_reconcile.resources USING btree (tenant_id, owner_reconciler, owner_entity, owner_token, owner_epoch) WHERE (owner_token IS NOT NULL)'),
 ('resource_waiters','CREATE INDEX resource_waiters ON rss_reconcile.target_resources USING btree (tenant_id, resource, waiting_ticket) WHERE (waiting_ticket IS NOT NULL)')
)
SELECT
 NOT EXISTS(SELECT FROM expected e FULL JOIN actual a USING(table_name) WHERE e.columns IS DISTINCT FROM a.columns OR e.types IS DISTINCT FROM a.types OR e.required IS DISTINCT FROM a.required)
 AND NOT EXISTS(SELECT FROM expected_constraints e FULL JOIN actual_constraints a USING(table_name,definition) WHERE e.table_name IS NULL OR a.table_name IS NULL OR NOT a.convalidated)
 AND NOT EXISTS(SELECT FROM expected_indexes e LEFT JOIN pg_indexes i ON i.schemaname='rss_reconcile' AND i.indexname=e.name WHERE i.indexdef IS DISTINCT FROM e.definition)
 AND NOT EXISTS(SELECT FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='rss_reconcile' AND (NOT i.indisvalid OR NOT i.indisready))
 AND NOT EXISTS(SELECT FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='rss_reconcile' AND NOT t.tgisinternal)
 AND (SELECT count(*)=1 AND bool_and(seqtypid='bigint'::regtype AND seqincrement=1 AND seqmin=1 AND NOT seqcycle)
  FROM pg_sequence s JOIN pg_class c ON c.oid=s.seqrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='rss_reconcile')
