-- PostgreSQL 17 structural attestation. Privileges and role inheritance are checked separately.
-- No object OIDs, data, owners, statistics, or environment-specific database names participate.
WITH relations AS (
 SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='identity_authority'
), facts AS (
 SELECT jsonb_build_array('relation',c.relname,c.relkind,c.relrowsecurity,c.relforcerowsecurity)::text AS fact FROM relations c
 UNION ALL
 SELECT jsonb_build_array('column',c.relname,a.attname,a.attnum,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid))::text
 FROM relations c JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum WHERE c.relkind='r'
 UNION ALL
 SELECT jsonb_build_array('constraint',c.relname,k.conname,k.convalidated,k.condeferrable,k.condeferred,pg_get_constraintdef(k.oid))::text FROM relations c JOIN pg_constraint k ON k.conrelid=c.oid
 UNION ALL
 SELECT jsonb_build_array('policy',c.relname,p.polname,p.polcmd,p.polpermissive,p.polroles,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid))::text FROM relations c JOIN pg_policy p ON p.polrelid=c.oid
 UNION ALL
 SELECT jsonb_build_array('index',c.relname,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready)::text FROM relations c JOIN pg_index i ON i.indrelid=c.oid
 UNION ALL
 SELECT jsonb_build_array('trigger',c.relname,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid))::text FROM relations c JOIN pg_trigger t ON t.tgrelid=c.oid AND NOT t.tgisinternal
 UNION ALL
 SELECT jsonb_build_array('function',p.proname,pg_get_function_identity_arguments(p.oid),pg_get_functiondef(p.oid),p.prosecdef,p.proconfig)::text FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='identity_authority'
)
SELECT encode(sha256(convert_to(string_agg(fact,E'\n' ORDER BY fact COLLATE "C"),'UTF8')),'hex') FROM facts
