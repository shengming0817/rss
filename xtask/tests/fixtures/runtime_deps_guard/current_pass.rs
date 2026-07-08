use std::sync::Arc;

use diport::KeyName;
use postgres::PgRuntimeDeps;
use redis::RedisRuntimeDeps;
use s3::S3RuntimeDeps;
use vault::VaultRuntimeDeps;

pub struct SharedRuntimeDeps {
    pub pg: PgRuntimeDeps,
    pub redis: RedisRuntimeDeps,
    pub s3: S3RuntimeDeps,
    pub vault: VaultRuntimeDeps,
    pub settings_config_value_key_name: KeyName,
    pub domain_transport: Arc<dyn distributed::DomainTransport>,
}
