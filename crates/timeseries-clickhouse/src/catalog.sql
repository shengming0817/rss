-- Stable PostgreSQL 16 storage-contract projection. Role OIDs and grants are checked separately.
WITH relations AS (
 SELECT c.oid,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='rss_ts_ch' AND c.relkind IN ('r','p','v') AND NOT c.relispartition
), definitions AS (
 SELECT 'column:'||r.relname||':'||a.attname||':'||format_type(a.atttypid,a.atttypmod)||':'||a.attnotnull::text||':'||a.attcollation::regcollation::text||':'||a.attidentity::text||':'||a.attgenerated::text||':'||coalesce(pg_get_expr(d.adbin,d.adrelid),'') AS definition
 FROM relations r JOIN pg_attribute a ON a.attrelid=r.oid AND a.attnum>0 AND NOT a.attisdropped
 LEFT JOIN pg_attrdef d ON d.adrelid=r.oid AND d.adnum=a.attnum
 UNION ALL SELECT 'partition:'||r.relname||':'||pg_get_partkeydef(r.oid) FROM relations r WHERE r.oid IN (SELECT partrelid FROM pg_partitioned_table)
 UNION ALL SELECT 'constraint:'||r.relname||':'||c.conname||':'||pg_get_constraintdef(c.oid,true) FROM relations r JOIN pg_constraint c ON c.conrelid=r.oid AND c.conparentid=0
 UNION ALL SELECT 'index:'||r.relname||':'||pg_get_indexdef(i.indexrelid) FROM relations r JOIN pg_index i ON i.indrelid=r.oid
 UNION ALL SELECT 'policy:'||r.relname||':'||p.polname||':'||p.polcmd::text||':'||p.polpermissive::text||':'||CASE WHEN p.polroles=ARRAY[0::oid] THEN 'public' WHEN p.polroles=ARRAY[(SELECT relowner FROM pg_class WHERE oid=r.oid)] THEN 'owner' ELSE p.polroles::text END||':'||coalesce(pg_get_expr(p.polqual,p.polrelid),'')||':'||coalesce(pg_get_expr(p.polwithcheck,p.polrelid),'') FROM relations r JOIN pg_policy p ON p.polrelid=r.oid
 UNION ALL SELECT 'view:'||r.relname||':'||pg_get_viewdef(r.oid,true) FROM relations r JOIN pg_class c ON c.oid=r.oid WHERE c.relkind='v'
 UNION ALL SELECT 'options:'||r.relname||':'||coalesce(c.reloptions::text,'') FROM relations r JOIN pg_class c ON c.oid=r.oid
 UNION ALL SELECT 'function:'||pg_get_functiondef(p.oid) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='rss_ts_ch'
)
SELECT md5(string_agg(definition,E'\n' ORDER BY definition)) FROM definitions
