#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let code = testkit::launch(std::env::args().skip(1).collect()).await?;
    std::process::exit(code);
}
