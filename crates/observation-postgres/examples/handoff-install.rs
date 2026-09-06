//! External example migrator; use the separately provisioned handoff_owner login.
#[path = "handoff/install.rs"]
mod install;
use sqlx::{
    Connection,
    postgres::{PgConnectOptions, PgSslMode},
};
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let options = std::env::var("MIGRATION_DATABASE_URL")?
        .parse::<PgConnectOptions>()?
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let mut connection = sqlx::PgConnection::connect_with(&options).await?;
    let owner:bool=sqlx::query_scalar("SELECT session_user=current_user AND current_user='handoff_owner' AND NOT rolsuper AND NOT rolbypassrls FROM pg_roles WHERE rolname=current_user").fetch_one(&mut connection).await?;
    anyhow::ensure!(owner, "use the dedicated handoff_owner migration login");
    install::install(&mut connection).await?;
    connection.close().await?;
    Ok(())
}
