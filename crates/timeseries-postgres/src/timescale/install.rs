use super::{DedicatedTenant, EXTENSION_VERSION, Hypertable};
use rss_timeseries::Error;

fn base(config: &Hypertable, profile: &str, tenant: &str, resolutions: &str) -> String {
    format!(
        r#"
DO $$ BEGIN
 IF NOT EXISTS(SELECT FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace WHERE e.extname='timescaledb' AND e.extversion='{EXTENSION_VERSION}' AND n.nspname='public')
 THEN RAISE EXCEPTION USING ERRCODE='0A000',MESSAGE='unsupported TimescaleDB extension'; END IF;
 IF current_setting('server_version_num')::integer NOT BETWEEN 170006 AND 179999 THEN RAISE EXCEPTION USING ERRCODE='0A000',MESSAGE='unsupported PostgreSQL'; END IF;
END $$;
CREATE TABLE rss_timeseries.deployment (
 singleton boolean PRIMARY KEY CHECK(singleton),
 profile text NOT NULL, tenant uuid, chunk_micros bigint NOT NULL,
 resolutions bigint[] NOT NULL
);
INSERT INTO rss_timeseries.deployment VALUES(true,'{profile}',{tenant},{interval},ARRAY[{resolutions}]::bigint[]);
CREATE SCHEMA rss_timeseries_chunks;
REVOKE ALL ON SCHEMA rss_timeseries_chunks FROM PUBLIC;
SELECT public.create_hypertable('rss_timeseries.samples','observed_at',associated_schema_name=>'rss_timeseries_chunks',chunk_time_interval=>{interval}::bigint,create_default_indexes=>false);
CREATE FUNCTION rss_timeseries.integer_now() RETURNS bigint LANGUAGE sql STABLE
SET search_path=pg_catalog,rss_timeseries AS $$ SELECT floor(extract(epoch FROM statement_timestamp())*1000000)::bigint $$;
SELECT public.set_integer_now_func('rss_timeseries.samples','rss_timeseries.integer_now'::regproc);
"#,
        interval = config.chunk_micros
    )
}
pub(crate) fn shared(config: &Hypertable) -> Result<String, Error> {
    Ok(base(config, "shared", "NULL", ""))
}
pub(crate) fn dedicated(config: &DedicatedTenant) -> Result<String, Error> {
    let resolutions = config
        .resolutions
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let tenant = format!("'{}'::uuid", config.tenant);
    let mut sql = base(&config.hypertable, "dedicated", &tenant, &resolutions);
    sql.push_str(&format!(r#"
DO $$ DECLARE r record; BEGIN
 FOR r IN SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='rss_timeseries' AND c.relkind='r' AND c.relname<>'deployment' LOOP
  EXECUTE format('ALTER TABLE rss_timeseries.%I ADD CONSTRAINT installation_tenant CHECK(tenant_id=%L::uuid)',r.relname,'{tenant}');
 END LOOP;
END $$;
ALTER TABLE rss_timeseries.samples DISABLE ROW LEVEL SECURITY;
ALTER TABLE rss_timeseries.samples NO FORCE ROW LEVEL SECURITY;
DROP POLICY tenant ON rss_timeseries.samples;
ALTER TABLE rss_timeseries.samples ADD COLUMN gauge_kind text;
ALTER TABLE rss_timeseries.samples ADD COLUMN gauge_value numeric;
ALTER TABLE rss_timeseries.samples ADD COLUMN aggregate_visible boolean NOT NULL DEFAULT true;
"#,tenant=config.tenant));
    sql.push_str(include_str!("native.sql"));
    sql.push_str("ALTER TABLE rss_timeseries.samples SET (timescaledb.enable_columnstore=true,timescaledb.segmentby='tenant_id,namespace,source,generation,series_digest',timescaledb.orderby='observed_at,sequence,sample_id');\n");
    for resolution in &config.resolutions {
        sql.push_str(&format!(
            r#"
CREATE MATERIALIZED VIEW rss_timeseries.gauge_{resolution}
WITH (timescaledb.continuous,timescaledb.materialized_only=true) AS
SELECT public.time_bucket({resolution}::bigint,observed_at) AS bucket,
 tenant_id,namespace,source,generation,series_digest,gauge_kind,
 sum(gauge_value) AS total,count(gauge_value) AS valid,
 min(gauge_value) AS minimum,max(gauge_value) AS maximum,
 count(*)-count(gauge_value) AS defects
FROM rss_timeseries.samples
WHERE aggregate_visible AND gauge_kind IN ('i64','u64')
GROUP BY bucket,tenant_id,namespace,source,generation,series_digest,gauge_kind
WITH NO DATA;
"#
        ));
    }
    Ok(sql)
}
