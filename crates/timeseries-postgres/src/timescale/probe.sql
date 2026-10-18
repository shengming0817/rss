WITH reachable AS (
 SELECT * FROM pg_roles WHERE rolname=current_user OR pg_has_role(current_user,oid,'SET')
), relations AS (
 SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='rss_timeseries' AND c.relkind IN ('r','p','v','m','f')
), funcs AS (
 SELECT p.* FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='rss_timeseries'
), acl AS (
 SELECT a.grantee,a.is_grantable FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) a WHERE n.nspname='rss_timeseries'
 UNION ALL SELECT a.grantee,a.is_grantable FROM relations c CROSS JOIN LATERAL aclexplode(c.relacl) a
 UNION ALL SELECT a.grantee,a.is_grantable FROM relations c JOIN pg_attribute p ON p.attrelid=c.oid CROSS JOIN LATERAL aclexplode(p.attacl) a
 UNION ALL SELECT a.grantee,a.is_grantable FROM funcs p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
)
SELECT session_user=current_user
 AND current_setting('server_version_num')::integer BETWEEN 160006 AND 169999
 AND has_schema_privilege(current_user,'rss_timeseries','USAGE')
 AND (SELECT count(*)=12 FROM relations WHERE relkind='r')
 AND (SELECT count(*)=cardinality($3::bigint[]) FROM relations WHERE relkind='v')
 AND (SELECT bool_and(relpersistence='p' AND relkind IN ('r','v') AND CASE WHEN relname='deployment' OR relkind='v' OR ($1 AND relname='samples') THEN NOT relrowsecurity AND NOT relforcerowsecurity ELSE relrowsecurity AND relforcerowsecurity END) FROM relations)
 AND (SELECT bool_and(has_table_privilege(current_user,oid,'SELECT')) FROM relations WHERE relkind='r')
 AND NOT EXISTS(SELECT FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole OR rolreplication)
 AND NOT EXISTS(SELECT FROM reachable r CROSS JOIN relations c WHERE c.relowner=r.oid OR has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE,REFERENCES'))
 AND NOT EXISTS(SELECT FROM reachable r JOIN pg_namespace n ON n.nspname IN ('rss_timeseries','public','_timescaledb_internal','_timescaledb_catalog','_timescaledb_functions') WHERE n.nspowner=r.oid OR has_schema_privilege(r.oid,n.oid,'CREATE'))
 AND NOT EXISTS(SELECT FROM acl a WHERE a.grantee=0 OR (a.is_grantable AND EXISTS(SELECT FROM reachable r WHERE r.oid=a.grantee OR pg_has_role(r.oid,a.grantee,'USAGE'))))
 AND NOT EXISTS(SELECT FROM pg_auth_members m JOIN reachable r ON m.member=r.oid WHERE m.admin_option)
 AND (SELECT count(*)=CASE WHEN $1 THEN 24 ELSE 22 END AND bool_and(proconfig=ARRAY['search_path=pg_catalog, rss_timeseries'] AND CASE WHEN proname IN ('integer_now','project_gauge') THEN NOT has_function_privilege(current_user,oid,'EXECUTE') ELSE prosecdef AND has_function_privilege(current_user,oid,'EXECUTE') END) FROM funcs)
 AND NOT EXISTS(SELECT FROM funcs f JOIN pg_roles r ON r.oid=f.proowner WHERE r.rolsuper OR r.rolbypassrls OR r.rolcanlogin OR r.rolcreaterole OR r.rolreplication OR r.oid IN(SELECT oid FROM reachable))
 AND NOT EXISTS(SELECT FROM relations c JOIN pg_roles r ON r.oid=c.relowner JOIN pg_namespace n ON n.nspname='rss_timeseries' WHERE r.rolsuper OR r.rolbypassrls OR r.rolcanlogin OR c.relowner<>n.nspowner)
 AND NOT EXISTS(SELECT FROM pg_constraint WHERE conrelid IN(SELECT oid FROM relations) AND NOT convalidated)
 AND NOT EXISTS(SELECT FROM pg_trigger t WHERE t.tgrelid IN(SELECT oid FROM relations) AND NOT t.tgisinternal AND NOT
 (t.tgrelid='rss_timeseries.samples'::regclass AND ((t.tgname='ts_insert_blocker' AND t.tgfoid=to_regprocedure('_timescaledb_functions.insert_blocker()')) OR
 ($1 AND t.tgname='project_gauge' AND t.tgfoid=to_regprocedure('rss_timeseries.project_gauge()')) OR
 ($1 AND t.tgname='ts_cagg_invalidation_trigger' AND t.tgfoid=to_regprocedure('_timescaledb_functions.continuous_agg_invalidation_trigger()')))))
 AND (SELECT count(*)=1 FROM timescaledb_information.hypertables WHERE hypertable_schema='rss_timeseries' AND hypertable_name='samples' AND num_dimensions=1)
 AND (SELECT count(*)=1 AND bool_and(column_name='observed_at' AND column_type='bigint'::regtype AND integer_interval=$2) FROM timescaledb_information.dimensions WHERE hypertable_schema='rss_timeseries' AND hypertable_name='samples')
 AND NOT EXISTS(SELECT FROM timescaledb_information.jobs WHERE hypertable_schema='rss_timeseries')
 AND NOT EXISTS(SELECT FROM timescaledb_information.continuous_aggregates WHERE view_schema='rss_timeseries' AND (NOT materialized_only OR compression_enabled OR hypertable_schema<>'rss_timeseries' OR hypertable_name<>'samples' OR NOT view_name=ANY(SELECT 'gauge_'||v FROM unnest($3::bigint[]) v)))
 AND (SELECT count(*)=cardinality($3::bigint[]) FROM timescaledb_information.continuous_aggregates WHERE view_schema='rss_timeseries')

 AND (NOT $1 OR EXISTS(SELECT FROM pg_trigger WHERE tgrelid='rss_timeseries.samples'::regclass AND tgname='project_gauge' AND tgfoid=to_regprocedure('rss_timeseries.project_gauge()') AND tgtype=7 AND tgenabled='O'))
 AND NOT EXISTS(SELECT FROM pg_inherits i JOIN pg_class c ON c.oid=i.inhrelid CROSS JOIN reachable r WHERE i.inhparent='rss_timeseries.samples'::regclass AND (c.relowner=r.oid OR has_table_privilege(r.oid,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(r.oid,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
 AND NOT EXISTS(SELECT FROM pg_policy p JOIN relations c ON c.oid=p.polrelid WHERE p.polname<>'tenant' OR p.polcmd<>'*' OR NOT p.polpermissive OR p.polroles<>ARRAY[0::oid] OR pg_get_expr(p.polqual,p.polrelid) IS DISTINCT FROM pg_get_expr(p.polwithcheck,p.polrelid) OR pg_get_expr(p.polqual,p.polrelid)<>'(tenant_id = (NULLIF(current_setting(''rss.tenant_id''::text, true), ''''::text))::uuid)')

 AND (SELECT bool_and(compression_enabled=$1) FROM timescaledb_information.hypertables WHERE hypertable_schema='rss_timeseries' AND hypertable_name='samples')
 AND (NOT $1 OR EXISTS(SELECT FROM timescaledb_information.hypertable_columnstore_settings WHERE hypertable='rss_timeseries.samples'::regclass AND segmentby='tenant_id,namespace,source,generation,series_digest' AND orderby='observed_at,sequence,sample_id' AND compress_interval_length IS NULL))
