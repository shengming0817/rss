-- PostgreSQL canonical V1 catalog descriptors; compatibility owner is this adapter.
WITH reachable AS (
 SELECT * FROM pg_roles WHERE rolname=current_user OR pg_has_role(current_user,oid,'SET')
), relations AS (
 SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='rss_ledger' AND c.relkind='r'
), funcs AS (
 SELECT p.* FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='rss_ledger'
), acl(grantee,is_grantable) AS (
 SELECT a.grantee,a.is_grantable FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) a WHERE n.nspname='rss_ledger'
 UNION ALL SELECT a.grantee,a.is_grantable FROM relations c CROSS JOIN LATERAL aclexplode(c.relacl) a
 UNION ALL SELECT a.grantee,a.is_grantable FROM relations c JOIN pg_attribute p ON p.attrelid=c.oid CROSS JOIN LATERAL aclexplode(p.attacl) a
 UNION ALL SELECT a.grantee,a.is_grantable FROM funcs p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
), checks(priority,reason,valid) AS (VALUES
(1,'role',session_user=current_user),
(2,'schema',(SELECT obj_description(oid,'pg_namespace')='rss-ledger-postgres:1' AND has_schema_privilege(oid,'USAGE') FROM pg_namespace WHERE nspname='rss_ledger')),
(3,'schema',(SELECT count(*)=2 AND bool_and(relname IN ('heads','entries') AND relpersistence='p' AND has_table_privilege(oid,'SELECT')) FROM relations)),
(4,'role',NOT EXISTS(SELECT FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole OR rolreplication)),
(5,'permissions',NOT EXISTS(SELECT FROM reachable r CROSS JOIN relations c WHERE c.relowner=r.oid OR has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE,REFERENCES'))),
(6,'permissions',NOT EXISTS(SELECT FROM reachable r JOIN pg_namespace n ON n.nspname='rss_ledger' WHERE n.nspowner=r.oid OR has_schema_privilege(r.oid,n.oid,'CREATE'))),
(7,'permissions',NOT EXISTS(SELECT FROM relations c CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE a.grantee=0 OR (a.privilege_type='MAINTAIN' AND EXISTS(SELECT FROM reachable r WHERE r.oid=a.grantee OR pg_has_role(r.oid,a.grantee,'USAGE'))))),
(8,'permissions',NOT EXISTS(SELECT FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) a WHERE n.nspname='rss_ledger' AND a.grantee=0)),
(9,'functions',(SELECT count(*)=2 AND bool_and(prosecdef AND proconfig=ARRAY['search_path=pg_catalog, rss_ledger'] AND has_function_privilege(oid,'EXECUTE') AND prorettype='void'::regtype AND pronargs IN (4,9)) FROM funcs)),
(10,'role',NOT EXISTS(SELECT FROM funcs p JOIN pg_roles r ON r.oid=p.proowner WHERE r.rolsuper OR r.rolbypassrls OR r.rolreplication OR r.rolcanlogin OR r.rolcreaterole OR r.oid IN (SELECT oid FROM reachable))),
(11,'permissions',NOT EXISTS(SELECT FROM funcs p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0)),
(12,'rls',(SELECT count(*)=2 AND bool_and(polname='tenant_scope' AND polcmd='*' AND polpermissive AND polroles=ARRAY[0::oid] AND pg_get_expr(polqual,polrelid)=pg_get_expr(polwithcheck,polrelid) AND pg_get_expr(polqual,polrelid)='(tenant_id = (NULLIF(current_setting(''rss.tenant_id''::text, true), ''''::text))::uuid)') FROM pg_policy WHERE polrelid IN (SELECT oid FROM relations))),
(13,'columns',(SELECT count(*)=15 AND bool_and(attgenerated='' AND attidentity='') FROM pg_attribute WHERE attrelid IN(SELECT oid FROM relations) AND attnum>0 AND NOT attisdropped)),
(14,'constraints',(SELECT count(*)=18 AND count(DISTINCT (conrelid,pg_get_constraintdef(oid)))=18 AND bool_and(convalidated) FROM pg_constraint WHERE conrelid IN(SELECT oid FROM relations))),
(15,'columns',NOT EXISTS (
 SELECT FROM (
    SELECT c.relname::text,a.attname::text,format_type(a.atttypid,a.atttypmod),a.attnotnull
    FROM pg_attribute a JOIN relations c ON c.oid=a.attrelid WHERE a.attnum>0 AND NOT a.attisdropped
    EXCEPT VALUES
    ('heads','tenant_id','uuid',true),('heads','chain_id','text',true),('heads','key_id','text',true),('heads','encoding_version','smallint',true),('heads','seq','bigint',false),('heads','tag','bytea',true),
    ('entries','tenant_id','uuid',true),('entries','chain_id','text',true),('entries','record_id','text',true),('entries','seq','bigint',true),('entries','previous_tag','bytea',true),('entries','tag','bytea',true),('entries','payload','bytea',true),('entries','encoding_version','smallint',true),('entries','key_id','text',true)
 ) invalid_columns
)),
(16,'columns',NOT EXISTS(SELECT FROM pg_attribute a JOIN relations c ON c.oid=a.attrelid WHERE a.attnum>0 AND a.atthasdef)),
(17,'functions',NOT EXISTS(SELECT FROM funcs WHERE (proname,oidvectortypes(proargtypes)) NOT IN (('prepare_append','uuid, text, text, smallint'),('insert_entry','uuid, text, text, bigint, bytea, bytea, bytea, text, smallint')))),
(18,'functions',NOT EXISTS(SELECT FROM pg_trigger WHERE tgrelid IN(SELECT oid FROM relations) AND NOT tgisinternal)),
(19,'constraints',NOT EXISTS (
 SELECT FROM (
    SELECT c.relname::text,pg_get_constraintdef(k.oid) FROM pg_constraint k JOIN relations c ON c.oid=k.conrelid
    EXCEPT VALUES
    ('entries',$d$CHECK (((seq <> 0) OR (previous_tag = decode(repeat('00'::text, 32), 'hex'::text))))$d$),
    ('entries','CHECK ((encoding_version = 1))'),
    ('entries','CHECK (((octet_length(key_id) >= 1) AND (octet_length(key_id) <= 255)))'),
    ('entries','CHECK ((octet_length(payload) <= 1048576))'),
    ('entries','PRIMARY KEY (tenant_id, chain_id, seq)'),
    ('entries','CHECK ((octet_length(previous_tag) = 32))'),
    ('entries','CHECK (((octet_length(record_id) >= 1) AND (octet_length(record_id) <= 255)))'),
    ('entries','CHECK ((seq >= 0))'),('entries','CHECK ((octet_length(tag) = 32))'),
    ('entries','FOREIGN KEY (tenant_id, chain_id) REFERENCES rss_ledger.heads(tenant_id, chain_id)'),
    ('entries','UNIQUE (tenant_id, chain_id, record_id)'),
    ('heads','CHECK (((octet_length(chain_id) >= 1) AND (octet_length(chain_id) <= 255)))'),
    ('heads',$d$CHECK (((seq IS NOT NULL) OR (tag = decode(repeat('00'::text, 32), 'hex'::text))))$d$),
    ('heads','CHECK ((encoding_version = 1))'),
    ('heads','CHECK (((octet_length(key_id) >= 1) AND (octet_length(key_id) <= 255)))'),
    ('heads','PRIMARY KEY (tenant_id, chain_id)'),('heads','CHECK ((seq >= 0))'),('heads','CHECK ((octet_length(tag) = 32))')
 ) invalid_constraints
)
),
(20,'permissions',NOT EXISTS(SELECT FROM pg_attribute a JOIN relations c ON c.oid=a.attrelid CROSS JOIN LATERAL aclexplode(a.attacl) acl WHERE a.attnum>0 AND acl.grantee=0)),
(21,'rls',(SELECT bool_and(relrowsecurity AND relforcerowsecurity) FROM relations)),
(22,'permissions',NOT EXISTS(SELECT FROM acl a CROSS JOIN reachable r WHERE a.is_grantable AND (a.grantee=r.oid OR pg_has_role(r.oid,a.grantee,'USAGE'))) AND NOT EXISTS(SELECT FROM pg_auth_members m JOIN reachable r ON m.member=r.oid WHERE m.admin_option))
) SELECT reason FROM checks WHERE valid IS DISTINCT FROM true ORDER BY priority LIMIT 1
