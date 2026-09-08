//! Ephemeral PostgreSQL input shared by the four independent public consumers.
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use std::io::Read as _;

/// Supplied by the fixture owner. Credentials are never Debug or serialized to logs.
#[derive(serde::Deserialize)]
pub struct Input {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub password: String,
    pub pg_ca: String,
    pub tenant: String,
}
impl Input {
    pub async fn pool(&self) -> anyhow::Result<sqlx::PgPool> {
        Ok(PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect_with(
                PgConnectOptions::new()
                    .host(&self.host)
                    .port(self.port)
                    .database(&self.database)
                    .username(&self.username)
                    .password(&self.password)
                    .ssl_mode(PgSslMode::VerifyFull)
                    .ssl_root_cert_from_pem(self.pg_ca.as_bytes().to_vec()),
            )
            .await?)
    }
}

pub fn read<T: serde::de::DeserializeOwned>() -> anyhow::Result<T> {
    let mut bytes = Vec::new();
    std::io::stdin().take(65537).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 65536, "fixture input exceeds budget");
    Ok(serde_json::from_slice(&bytes)?)
}
