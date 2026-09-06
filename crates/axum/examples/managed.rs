use rss_runtime::{ShutdownStack, TotalDrainBudget};
use std::time::Duration;
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let registration = rss_axum::serve_registration(
        listener,
        axum::Router::new(),
        "http",
        Duration::from_secs(1),
    );
    let mut owner = ShutdownStack::try_new(TotalDrainBudget::new(Duration::from_secs(2))?)?;
    let mut startup = owner.startup()?;
    startup.stage_task_with_token(registration);
    startup.commit().finish();
    assert!(owner.shutdown().await?.is_clean());
    Ok(())
}
