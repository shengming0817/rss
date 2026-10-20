fn main() -> anyhow::Result<()> {
    let instance: String = rss_examples::pg::read()?;
    let output = serde_json::json!({"control":rss_timeseries_clickhouse::CONTROL_SQL,"clickhouse":rss_timeseries_clickhouse::installation_sql(&instance)?});
    serde_json::to_writer(std::io::stdout(), &output)?;
    Ok(())
}
