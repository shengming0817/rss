//! Consumer-owned installer: only published migration constants and package-local facts SQL.
pub async fn install(connection: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(rss_observation_postgres::MIGRATION_SQL)
        .execute(&mut *connection)
        .await?;
    sqlx::raw_sql(rss_projection_postgres::MIGRATION_SQL)
        .execute(&mut *connection)
        .await?;
    sqlx::raw_sql(include_str!("facts.sql"))
        .execute(&mut *connection)
        .await?;
    sqlx::raw_sql("GRANT USAGE ON SCHEMA rss_observation,rss_projection TO handoff_runtime; GRANT SELECT ON rss_observation.streams,rss_observation.batches,rss_observation.journals TO handoff_runtime; GRANT SELECT ON ALL TABLES IN SCHEMA rss_projection TO handoff_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_projection TO handoff_runtime; GRANT EXECUTE ON FUNCTION rss_observation.activate(text,numeric,text,text), rss_observation.lock_stream(text), rss_observation.commit_batch(text,text,numeric,bytea,bytea,bigint,text,text,numeric,boolean) TO handoff_runtime; GRANT SELECT,INSERT,UPDATE,DELETE ON public.observation_facts TO handoff_runtime;").execute(connection).await?;
    Ok(())
}
