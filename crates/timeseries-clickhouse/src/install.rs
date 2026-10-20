use rss_timeseries::Error;
/// The dedicated external owner executes this exactly once; constructors never run DDL.
pub const CONTROL_SQL: &str = include_str!("../migrations/0001_create_control.sql");
/// ClickHouse owner-executed statements. The server-provisioned named collection
/// rss_ts_ch_guard points only at the PG primary, using its narrow guard credential.
/// libpq must be configured with PGSSLMODE=verify-full and an explicit PGSSLROOTCERT.
pub fn installation_sql(instance: &str) -> Result<Vec<String>, Error> {
    if instance.len() != 36 || !instance.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        return Err(Error::InvalidInput);
    }
    Ok(vec![
        "CREATE DATABASE rss_ts_ch ENGINE=Atomic".into(),
        "CREATE TABLE rss_ts_ch.installation (id String) ENGINE=MergeTree ORDER BY id SETTINGS index_granularity=8192,fsync_after_insert=1,fsync_part_directory=1".into(),
        format!("INSERT INTO rss_ts_ch.installation VALUES ('{instance}')"),
        "CREATE TABLE rss_ts_ch.active_attempts (tenant String,namespace String,attempt String,query_id String,target String,digest String,revision Int64,installation String) ENGINE=PostgreSQL(rss_ts_ch_guard, table='active_attempts',schema='rss_ts_ch')".into(),
        "CREATE TABLE rss_ts_ch.guard_identity (installation String,primary_server UInt8,tls UInt8,guard_user String) ENGINE=PostgreSQL(rss_ts_ch_guard, table='guard_identity',schema='rss_ts_ch')".into(),
        "CREATE TABLE rss_ts_ch.raw (tenant String,namespace String,source String,generation String,sample_id String,series String,subject String,resource String,metric_key String,observed_at Int64,sequence UInt64,received_at Int64,revision Int64,digest String,payload String) ENGINE=ReplacingMergeTree PARTITION BY intDiv(observed_at,2592000000000) ORDER BY (tenant,namespace,series,source,generation,observed_at,sequence,sample_id) SETTINGS index_granularity=8192,non_replicated_deduplication_window=1024,fsync_after_insert=1,fsync_part_directory=1".into(),
        "CREATE TABLE rss_ts_ch.summaries (tenant String,namespace String,object_id String,lo Int64,hi Int64,revision Int64,digest String,payload String) ENGINE=ReplacingMergeTree PARTITION BY intDiv(lo,2592000000000) ORDER BY (tenant,namespace,object_id,lo) SETTINGS index_granularity=8192,non_replicated_deduplication_window=1024,fsync_after_insert=1,fsync_part_directory=1".into(),
    ])
}
