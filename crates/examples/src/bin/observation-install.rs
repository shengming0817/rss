//! Install candidate-owned schemas with the separately provisioned migration role.
#[path = "../observation/install.rs"]
mod install;
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let input: rss_examples::pg::Input = rss_examples::pg::read()?;
    let pool = input.pool().await?;
    let mut connection = pool.acquire().await?;
    let owner: bool = sqlx::query_scalar("SELECT session_user=current_user AND current_user='handoff_owner' AND NOT rolsuper AND NOT rolbypassrls FROM pg_roles WHERE rolname=current_user").fetch_one(&mut *connection).await?;
    anyhow::ensure!(owner, "dedicated migration owner required");
    install::install(&mut connection).await?;
    drop(connection);
    pool.close().await;
    Ok(())
}
