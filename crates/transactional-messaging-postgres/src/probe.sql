-- Probe only the package-owned schema. Existing public tables are intentionally irrelevant.
WITH runtime_role AS (
  SELECT oid, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user
), relay_role AS (
  SELECT oid, rolcanlogin, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'rss_tmsg_relay'
), required(name, privileges) AS (VALUES ('inbox','SELECT,INSERT,UPDATE,DELETE'), ('outbox','SELECT,INSERT')),
columns(relation, name, type, nullable) AS (VALUES
 ('policy','revision','integer',false), ('policy','automatic_window_seconds','bigint',false),
 ('policy','safety_seconds','bigint',false), ('policy','receipt_retention_seconds','bigint',false),
 ('inbox','tenant_id','uuid',false), ('inbox','message_id','text',false),
 ('inbox','consumer_group','text',false), ('inbox','contract','text',false),
 ('inbox','lease_token','uuid',false), ('inbox','lease_until','timestamp with time zone',false),
 ('inbox','receive_count','bigint',false), ('inbox','fingerprint','bytea',true), ('inbox','disposition','text',true),
 ('outbox','seq','bigint',false), ('outbox','tenant_id','uuid',false), ('outbox','message_id','text',false),
 ('outbox','domain','text',false), ('outbox','partition_key','text',true), ('outbox','envelope','jsonb',false),
 ('outbox','fingerprint','bytea',false), ('outbox','status','text',false), ('outbox','retry_count','integer',false),
 ('outbox','retry_after','timestamp with time zone',false), ('outbox','lease_token','uuid',true),
 ('outbox','lease_until','timestamp with time zone',true), ('outbox','automatic_retry_deadline','timestamp with time zone',true)),
functions(signature) AS (VALUES
 ('rss_transactional_messaging.claim_outbox(text,integer,bigint)'),
 ('rss_transactional_messaging.outbox_lease(bigint,uuid,bigint,bigint)'),
 ('rss_transactional_messaging.settle_outbox(bigint,uuid,bigint,text)')),
tenant_predicate(value) AS (VALUES ($predicate$(tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)$predicate$)),
expected_policies(relation, name, roles, predicate) AS (
 SELECT 'rss_transactional_messaging.inbox'::regclass, 'inbox_tenant', ARRAY[0]::oid[], value FROM tenant_predicate
 UNION ALL SELECT 'rss_transactional_messaging.outbox'::regclass, 'outbox_tenant', ARRAY[0]::oid[], value FROM tenant_predicate
 UNION ALL SELECT 'rss_transactional_messaging.outbox'::regclass, 'outbox_relay', ARRAY[oid], 'true' FROM relay_role
), actual_policies AS (
 SELECT * FROM pg_policy WHERE polrelid IN ('rss_transactional_messaging.inbox'::regclass, 'rss_transactional_messaging.outbox'::regclass)
), expected_constraints(relation, name, definition) AS (VALUES
 ('inbox', 'inbox_pkey', 'PRIMARY KEY (tenant_id, message_id, consumer_group)'),
 ('inbox', 'inbox_receipt_shape', 'CHECK ((((fingerprint IS NULL) AND (disposition IS NULL)) OR ((fingerprint IS NOT NULL) AND (octet_length(fingerprint) = 32) AND (disposition IS NOT NULL) AND (disposition = ANY (ARRAY[''succeeded''::text, ''rejected_permanent''::text, ''rejected_invariant''::text])))))'),
 ('inbox', 'inbox_receive_count_check', 'CHECK ((receive_count > 0))'),
 ('outbox', 'outbox_fingerprint_length', 'CHECK ((octet_length(fingerprint) = 32))'),
 ('outbox', 'outbox_lease_shape', 'CHECK (((status = ''publishing''::text) = ((lease_token IS NOT NULL) AND (lease_until IS NOT NULL))))'),
 ('outbox', 'outbox_pkey', 'PRIMARY KEY (seq)'),
 ('outbox', 'outbox_retry_count_check', 'CHECK ((retry_count >= 0))'),
 ('outbox', 'outbox_status_check', 'CHECK ((status = ANY (ARRAY[''pending''::text, ''publishing''::text, ''published''::text, ''dead_letter''::text])))'),
 ('outbox', 'outbox_tenant_id_message_id_key', 'UNIQUE (tenant_id, message_id)'),
 ('policy', 'policy_automatic_window_seconds_check', 'CHECK ((automatic_window_seconds = 86400))'),
 ('policy', 'policy_check', 'CHECK ((receipt_retention_seconds > (automatic_window_seconds + safety_seconds)))'),
 ('policy', 'policy_pkey', 'PRIMARY KEY (revision)'),
 ('policy', 'policy_revision_check', 'CHECK ((revision = 1))'),
 ('policy', 'policy_safety_seconds_check', 'CHECK ((safety_seconds = 86400))')
), expected_defaults(relation, name, expression) AS (VALUES
 ('inbox','receive_count','1'), ('outbox','status', $$'pending'::text$$),
 ('outbox','retry_count','0'), ('outbox','retry_after','clock_timestamp()')
), checks(reason, valid) AS (VALUES
 ('policy', (EXISTS (SELECT 1 FROM rss_transactional_messaging.policy
    WHERE revision = 1 AND automatic_window_seconds = 86400
      AND safety_seconds = 86400 AND receipt_retention_seconds > 172800))),
 ('runtime_role', (NOT EXISTS (SELECT 1 FROM runtime_role WHERE rolsuper OR rolbypassrls))),
 ('runtime_role', (NOT EXISTS (SELECT 1 FROM pg_roles r WHERE (r.rolsuper OR r.rolbypassrls)
    AND (pg_has_role(current_user, r.oid, 'USAGE') OR pg_has_role(current_user, r.oid, 'SET'))))),
 ('relay_role', (EXISTS (SELECT 1 FROM relay_role WHERE NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls))),
 ('runtime_role', (NOT pg_has_role(current_user, 'rss_tmsg_relay', 'MEMBER'))),
 ('columns', (NOT EXISTS (SELECT 1 FROM columns expected LEFT JOIN information_schema.columns actual
    ON actual.table_schema = 'rss_transactional_messaging' AND actual.table_name = expected.relation
      AND actual.column_name = expected.name
    WHERE actual.column_name IS NULL OR actual.data_type <> expected.type
      OR (actual.is_nullable = 'YES') <> expected.nullable))),
 ('constraints', (NOT EXISTS (SELECT 1 FROM (VALUES
    ('inbox', ARRAY['tenant_id','message_id','consumer_group']::name[]),
    ('outbox', ARRAY['tenant_id','message_id']::name[])) expected(relation, columns)
    WHERE NOT EXISTS (SELECT 1 FROM pg_index i
      WHERE i.indrelid = to_regclass('rss_transactional_messaging.' || expected.relation)
        AND i.indisunique AND i.indisvalid AND i.indpred IS NULL
        AND (SELECT array_agg(a.attname ORDER BY key.ord)
          FROM unnest(i.indkey) WITH ORDINALITY key(attnum, ord)
          JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = key.attnum) = expected.columns)))),
 ('runtime_acl', (NOT EXISTS (
    SELECT 1 FROM required r LEFT JOIN pg_class c
      ON c.oid = to_regclass('rss_transactional_messaging.' || r.name)
    WHERE c.oid IS NULL OR NOT c.relrowsecurity OR NOT c.relforcerowsecurity
      OR pg_has_role(current_user, c.relowner, 'MEMBER')
      OR EXISTS (SELECT 1 FROM unnest(string_to_array(r.privileges, ',')) privilege
        WHERE NOT has_table_privilege(current_user, c.oid, privilege))
  ))),
 ('runtime_acl', (has_schema_privilege(current_user, 'rss_transactional_messaging', 'USAGE'))),
 ('runtime_acl', (NOT has_schema_privilege(current_user, 'rss_transactional_messaging', 'CREATE'))),
 ('relay_acl', (NOT has_schema_privilege('rss_tmsg_relay', 'rss_transactional_messaging', 'CREATE'))),
 ('runtime_acl', (NOT has_table_privilege(current_user, 'rss_transactional_messaging.policy', 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))),
 ('runtime_acl', (NOT has_table_privilege(current_user, 'rss_transactional_messaging.outbox', 'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))),
 ('runtime_acl', (NOT has_table_privilege(current_user, 'rss_transactional_messaging.inbox', 'TRUNCATE,REFERENCES,TRIGGER'))),
 ('runtime_acl', (has_sequence_privilege(current_user, 'rss_transactional_messaging.outbox_seq_seq', 'USAGE'))),
 ('runtime_acl', (NOT has_sequence_privilege(current_user, 'rss_transactional_messaging.outbox_seq_seq', 'SELECT,UPDATE'))),
 ('relay_acl', (NOT has_sequence_privilege('rss_tmsg_relay', 'rss_transactional_messaging.outbox_seq_seq', 'USAGE,SELECT,UPDATE'))),
 ('relay_acl', (has_table_privilege('rss_tmsg_relay', 'rss_transactional_messaging.outbox', 'SELECT'))),
 ('relay_acl', (has_table_privilege('rss_tmsg_relay', 'rss_transactional_messaging.outbox', 'UPDATE'))),
 ('relay_acl', (NOT has_table_privilege('rss_tmsg_relay', 'rss_transactional_messaging.outbox', 'INSERT,DELETE,TRUNCATE,REFERENCES,TRIGGER'))),
 ('relay_acl', (NOT has_table_privilege('rss_tmsg_relay', 'rss_transactional_messaging.inbox', 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))),
 ('rls_policy', (NOT EXISTS (SELECT 1 FROM expected_policies e FULL JOIN actual_policies p ON p.polrelid = e.relation AND p.polname = e.name
    WHERE e.name IS NULL OR p.oid IS NULL OR NOT p.polpermissive OR p.polcmd <> '*'
      OR p.polroles IS DISTINCT FROM e.roles
      OR pg_get_expr(p.polqual, p.polrelid) IS DISTINCT FROM e.predicate
      OR pg_get_expr(p.polwithcheck, p.polrelid) IS DISTINCT FROM e.predicate))),
 ('functions', (NOT EXISTS (SELECT 1 FROM functions f LEFT JOIN pg_proc p ON p.oid = to_regprocedure(f.signature)
    WHERE p.oid IS NULL OR NOT p.prosecdef OR p.proowner <> (SELECT oid FROM relay_role)
      OR NOT ('search_path=pg_catalog, rss_transactional_messaging' = ANY(p.proconfig))
      OR NOT has_function_privilege(current_user, p.oid, 'EXECUTE')
      OR EXISTS (SELECT 1 FROM aclexplode(COALESCE(p.proacl, acldefault('f',p.proowner))) a
        WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE')))),
 ('constraints', NOT EXISTS (SELECT 1 FROM expected_constraints e LEFT JOIN pg_constraint c
 ON c.conrelid=to_regclass('rss_transactional_messaging.' || e.relation) AND c.conname=e.name
 WHERE c.oid IS NULL OR NOT c.convalidated OR c.condeferrable
 OR pg_get_constraintdef(c.oid) IS DISTINCT FROM e.definition)),
 ('defaults', NOT EXISTS (SELECT 1 FROM expected_defaults e
 LEFT JOIN pg_attribute a ON a.attrelid=to_regclass('rss_transactional_messaging.' || e.relation) AND a.attname=e.name
 LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
 WHERE pg_get_expr(d.adbin,d.adrelid) IS DISTINCT FROM e.expression)
 AND EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid='rss_transactional_messaging.outbox'::regclass
 AND attname='seq' AND attidentity='a'))
)
SELECT reason FROM checks WHERE NOT COALESCE(valid,false) ORDER BY reason LIMIT 1
