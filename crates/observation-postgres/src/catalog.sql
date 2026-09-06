-- Stable PostgreSQL 16 storage-contract projection. Role OIDs and grants are checked separately.
WITH relations AS (
 SELECT c.oid,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='rss_observation' AND c.relkind='r'
), definitions AS (
 SELECT 'column:'||r.relname||':'||a.attname||':'||format_type(a.atttypid,a.atttypmod)||':'||a.attnotnull::text||':'||a.attgenerated::text||':'||coalesce(pg_get_expr(d.adbin,d.adrelid),'') AS definition
 FROM relations r JOIN pg_attribute a ON a.attrelid=r.oid AND a.attnum>0 AND NOT a.attisdropped
 LEFT JOIN pg_attrdef d ON d.adrelid=r.oid AND d.adnum=a.attnum
 UNION ALL SELECT 'constraint:'||r.relname||':'||c.conname||':'||pg_get_constraintdef(c.oid,true) FROM relations r JOIN pg_constraint c ON c.conrelid=r.oid
 UNION ALL SELECT 'index:'||r.relname||':'||pg_get_indexdef(i.indexrelid) FROM relations r JOIN pg_index i ON i.indrelid=r.oid
 UNION ALL SELECT 'policy:'||r.relname||':'||p.polname||':'||p.polcmd::text||':'||p.polpermissive::text||':'||p.polroles::text||':'||coalesce(pg_get_expr(p.polqual,p.polrelid),'')||':'||coalesce(pg_get_expr(p.polwithcheck,p.polrelid),'') FROM relations r JOIN pg_policy p ON p.polrelid=r.oid
 UNION ALL SELECT 'function:'||pg_get_functiondef(p.oid) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='rss_observation'
)
SELECT md5(string_agg(definition,E'\n' ORDER BY definition)) FROM definitions
