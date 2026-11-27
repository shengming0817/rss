-- One installation/startup snapshot of the actual role and storage contract.
WITH reachable AS MATERIALIZED (
 SELECT * FROM pg_roles WHERE pg_has_role(current_user,oid,'SET')
), relations AS MATERIALIZED (
 SELECT c.*, n.nspowner FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='rss_audit'
), columns AS MATERIALIZED (
 SELECT a.*, c.relname FROM pg_attribute a JOIN relations c ON c.oid=a.attrelid
 WHERE c.relkind='r' AND a.attnum>0
), constraints AS MATERIALIZED (
 SELECT k.*, c.relname FROM pg_constraint k JOIN relations c ON c.oid=k.conrelid
), functions AS MATERIALIZED (
 SELECT p.*, n.nspowner, l.lanname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='rss_audit'
)
SELECT current_setting('rss.tenant_id',true) AS tenant,
(SELECT session_user = current_user
 AND EXISTS (SELECT 1 FROM pg_namespace n JOIN pg_roles r ON r.oid=n.nspowner
   WHERE n.nspname='rss_audit' AND NOT r.rolcanlogin AND NOT r.rolsuper
     AND NOT r.rolbypassrls AND NOT r.rolcreaterole
     AND NOT pg_has_role(current_user,r.oid,'SET'))
 AND NOT EXISTS (SELECT 1 FROM reachable r WHERE (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb))
 AND NOT EXISTS (SELECT 1 FROM pg_namespace n, reachable r
   WHERE n.nspname='rss_audit'
     AND has_schema_privilege(r.oid,n.oid,'CREATE'))
 AND NOT EXISTS (SELECT 1 FROM pg_auth_members m JOIN reachable r ON r.oid=m.member
   WHERE m.admin_option)) AS roles,

(SELECT count(*)=2 AND array_agg(relname::text ORDER BY relname)=ARRAY['positions','records']
 AND bool_and(relkind IN ('r','S') AND relpersistence='p' AND relowner=nspowner
 AND NOT relispartition AND NOT relhassubclass
 AND NOT EXISTS(SELECT FROM pg_trigger t WHERE t.tgrelid=c.oid AND NOT t.tgisinternal)
 AND NOT EXISTS(SELECT FROM pg_rewrite w WHERE w.ev_class=c.oid))
 FROM relations c WHERE relkind NOT IN ('i','I')) AS schema,
(SELECT bool_and(relrowsecurity AND relforcerowsecurity)
 FROM relations WHERE relkind='r') AS forced_rls,
(SELECT count(*)=3 AND bool_and(i.indisvalid AND i.indisready AND i.indislive AND i.indexprs IS NULL)
 AND count(*) FILTER (WHERE i.indpred IS NULL)=2
 AND count(*) FILTER (WHERE i.indisunique AND i.indimmediate AND am.amname='btree'
   AND i.indnkeyatts=2 AND i.indnatts=2
   AND pg_get_indexdef(i.indexrelid,1,false)='tenant_id'
   AND pg_get_indexdef(i.indexrelid,2,false)='ledger_sequence'
   AND (SELECT array_agg(op.opcname ORDER BY k.ord)
        FROM unnest(i.indclass) WITH ORDINALITY k(oid,ord) JOIN pg_opclass op ON op.oid=k.oid
        WHERE op.opcnamespace='pg_catalog'::regnamespace)=ARRAY['uuid_ops','int8_ops']::name[]
   AND pg_get_expr(i.indpred,i.indrelid)='(ledger_sequence IS NOT NULL)')=1
 FROM pg_index i JOIN relations c ON c.oid=i.indrelid
 JOIN pg_class idx ON idx.oid=i.indexrelid JOIN pg_am am ON am.oid=idx.relam
 WHERE c.relname='records') AS indexes,
(SELECT count(*)=7 AND bool_and(NOT attisdropped AND NOT atthasdef AND attidentity='' AND attgenerated=''
 AND attcollation=CASE WHEN attname IN ('source_id','event_id') THEN 'pg_catalog."C"'::regcollation::oid ELSE 0::oid END)
 AND array_agg(relname||':'||attname||':'||format_type(atttypid,atttypmod)||':'||attnotnull::text ORDER BY relname,attnum)
 = ARRAY['records:tenant_id:uuid:true',
 'records:source_id:text:true','records:event_id:text:true','records:position:bigint:true',
 'records:recorded_at:bigint:true','records:canonical:bytea:true','records:ledger_sequence:bigint:false']
 FROM columns) AS columns,
(SELECT bool_and(convalidated AND NOT condeferrable AND NOT condeferred)
 -- PostgreSQL 18 also catalogs column NOT NULL constraints; the column check covers their shape.
 AND array_agg(relname||':'||pg_get_constraintdef(oid) ORDER BY (relname||':'||pg_get_constraintdef(oid)) COLLATE "C")
   FILTER (WHERE contype<>'n')=$2::text[]
 FROM constraints) AS constraints,
(SELECT count(*)=1 AND array_agg(c.relname::text ORDER BY c.relname)=ARRAY['records']
 AND bool_and(p.polname='tenant_scope' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
 AND pg_get_expr(p.polqual,p.polrelid)=$3 AND pg_get_expr(p.polwithcheck,p.polrelid)=$3)
 FROM pg_policy p JOIN relations c ON c.oid=p.polrelid) AS policies,
(SELECT count(*)=1 AND bool_and(proname='append_batch' AND prosrc=$1
 AND prosecdef AND proowner=nspowner AND proconfig=ARRAY['search_path=pg_catalog, rss_audit']
 AND prokind='f' AND lanname='plpgsql' AND provolatile='v'
 AND pg_get_function_identity_arguments(oid)='p_tenant uuid, p_sources text[], p_events text[], p_recorded bigint[], p_canonical bytea[], p_ledger bigint[]'
 AND prorettype='record'::regtype AND proallargtypes=ARRAY['uuid'::regtype,'text[]'::regtype,'text[]'::regtype,'bigint[]'::regtype,'bytea[]'::regtype,'bigint[]'::regtype,'text'::regtype,'text'::regtype,'bigint'::regtype]::oid[]
 AND proargmodes=ARRAY['i','i','i','i','i','i','t','t','t']::"char"[]
 AND proargnames=ARRAY['p_tenant','p_sources','p_events','p_recorded','p_canonical','p_ledger','source_id','event_id','position']
 AND NOT proisstrict AND NOT proleakproof AND proparallel='u' AND proretset AND pronargdefaults=0)
 FROM functions) AS functions,
(SELECT EXISTS(SELECT FROM pg_sequence q JOIN relations c ON c.oid=q.seqrelid
 WHERE c.relname='positions' AND q.seqtypid='bigint'::regtype AND q.seqincrement=1
 AND q.seqmin=0 AND q.seqmax=9223372036854775807 AND q.seqstart=0 AND q.seqcache=1 AND NOT q.seqcycle)
 AND NOT EXISTS(SELECT FROM relations c CROSS JOIN reachable r WHERE c.relkind='S'
 AND has_sequence_privilege(r.oid,c.oid,'USAGE,SELECT,UPDATE'))
 AND has_schema_privilege(current_user,(SELECT oid FROM pg_namespace WHERE nspname='rss_audit'),'USAGE')
 AND NOT EXISTS (SELECT 1 FROM reachable r WHERE has_schema_privilege(r.oid,(SELECT oid FROM pg_namespace WHERE nspname='rss_audit'),'USAGE WITH GRANT OPTION'))
 AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace,
 reachable r WHERE n.nspname='rss_audit' AND c.relkind='r'
 AND (
 has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 OR has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE,REFERENCES')
 OR has_table_privilege(r.oid,c.oid,'SELECT WITH GRANT OPTION')
 OR has_any_column_privilege(r.oid,c.oid,'SELECT WITH GRANT OPTION')))
 AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='rss_audit' AND c.relkind='r' AND NOT has_table_privilege(current_user,c.oid,'SELECT'))
 AND NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='rss_audit' AND ((CASE WHEN $4::boolean THEN NOT has_function_privilege(current_user,p.oid,'EXECUTE') ELSE EXISTS(SELECT FROM reachable r WHERE has_function_privilege(r.oid,p.oid,'EXECUTE')) END)
 OR EXISTS (SELECT 1 FROM reachable r WHERE has_function_privilege(r.oid,p.oid,'EXECUTE WITH GRANT OPTION'))))
 -- Plain does not require Ledger installation or SELECT, but must not carry sink mutation authority.
 AND ($4::boolean OR (
 NOT EXISTS (SELECT FROM pg_namespace n CROSS JOIN reachable r
 WHERE n.nspname='rss_ledger' AND (pg_has_role(r.oid,n.nspowner,'USAGE')
 OR has_schema_privilege(r.oid,n.oid,'CREATE')))
 AND NOT EXISTS (SELECT FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace CROSS JOIN reachable r
 WHERE n.nspname='rss_ledger' AND (pg_has_role(r.oid,p.proowner,'USAGE')
 OR has_function_privilege(r.oid,p.oid,'EXECUTE')))
 AND NOT EXISTS (SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN reachable r
 WHERE n.nspname='rss_ledger' AND (pg_has_role(r.oid,c.relowner,'USAGE') OR CASE
 WHEN c.relkind='S' THEN has_sequence_privilege(r.oid,c.oid,'USAGE,UPDATE')
 WHEN c.relkind IN ('r','p','v','m','f') THEN
 has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 OR has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE,REFERENCES')
 ELSE false END))
 AND NOT EXISTS (SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 CROSS JOIN LATERAL aclexplode(c.relacl) a CROSS JOIN reachable r
 WHERE n.nspname='rss_ledger' AND a.privilege_type='MAINTAIN'
 AND CASE WHEN a.grantee=0 THEN true ELSE pg_has_role(r.oid,a.grantee,'USAGE') END)
 ))
 AND NOT EXISTS (SELECT 1 FROM (
 SELECT a.grantee,a.is_grantable FROM pg_namespace n,
 LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname='rss_audit'
 UNION ALL SELECT a.grantee,a.is_grantable FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace,
 LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a WHERE n.nspname='rss_audit'
 UNION ALL SELECT a.grantee,a.is_grantable FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace,
 LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE n.nspname='rss_audit'
 UNION ALL SELECT acl.grantee,acl.is_grantable FROM pg_attribute a
 JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace,
 LATERAL aclexplode(a.attacl) acl WHERE n.nspname='rss_audit'
 ) access WHERE grantee=0)) AS privileges
