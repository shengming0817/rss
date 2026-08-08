use std::sync::Arc;

use diport::KeyName;
use postgres::PgRuntimeHandle;
use redis::RedisRuntimeDeps;
use s3::S3RuntimeDeps;
use vault::VaultRuntimeDeps;

pub struct SharedRuntimeDeps {
    pub password_blocklist: Arc<secure::DigestPasswordBlocklist>,
    pub pg: PgRuntimeHandle,
    pub redis: RedisRuntimeDeps,
    pub s3: S3RuntimeDeps,
    pub vault: VaultRuntimeDeps,
    pub settings_config_value_key_name: KeyName,
    pub domain_transport: Arc<dyn distributed::HttpContractTransport>,
}
