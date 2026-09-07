//! Private fixture parameters arrive over stdin, never command arguments or logs.
fn main() -> anyhow::Result<()> {
    let input = serde_json::from_reader(std::io::stdin().lock())?;
    tokio::runtime::Runtime::new()?.block_on(rss_examples::providers::run(input))
}
