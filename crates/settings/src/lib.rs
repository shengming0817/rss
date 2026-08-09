//! settings — RSS 版本化配置与 secret 引用域。
//!
//! 本 crate 承载配置与 secret 引用的核心值类型及纯逻辑（`domain`）、版本化配置 CRUD/CAS +
//! 发布/回滚（`application`）、域形配置仓储
//! DI port（`ports::ConfigRepo`，ADR-005 Option 2）与域内 in-mem 实现（`internal`）。所有域类型字段私有，
//! 只经显式构造 funnel 创建——外部不可伪造（ADR-001）。
//!
//! # 实现状态
//!
//! `domain` newtype 校验与配置 `diff` 已写实；`application`
//! 经 Publisher（L2 OutboxFact）打通配置发布/回滚接缝。真实持久化（postgres adapter impl
//! [`ports::ConfigRepo`]）+ axum 挂载（config publish/get/delete/rollback / secret publish/resolve
//! 认证路由）已落（#1430 PERSIST-009 settings 首条 durable module 闭环）。domain / application /
//! adapter 路径已闭环，行为由表驱动单元测试与 trybuild 门守住。
//!
//! # 对标
//!
//! ref: etcd-io/etcd api/etcdserverpb/rpc.proto@main

#![forbid(unsafe_code)]

mod application;
pub(crate) mod domain;
mod internal;
pub mod ports;
mod projection;
mod secret_application;

pub use application::{
    ConfigQueryService, ConfigVersionChangedEvent, ConfigVersionChangedEventError,
    ConfigVersionReconciler, SETTINGS_ROUTE_PREFIX, SettingsDomain,
    SettingsProjectionServingDomain, SettingsService, SettingsServiceError,
    config_version_changed_event_from_message,
};
pub use ports::ConfigEntry;
pub use projection::{
    SettingsProjectionBeginError, SettingsProjectionMetadataQuery, SettingsProjectionQueryRequest,
    SettingsProjectionQueryService,
};
pub use secret_application::{SecretResolveService, SecretService, SecretServiceError};

/// Mint a route-typed config-publish receipt for tests that bypass the HTTP router.
#[cfg(any(test, feature = "test-support"))]
pub fn config_publish_receipt_for_test() -> ports::ConfigPublishReceipt {
    httpserve::ProducerMarker::for_test(generated::http::settings_v1::PRODUCER).into_receipt()
}

/// Mint a route-typed config-delete receipt for tests that bypass the HTTP router.
#[cfg(any(test, feature = "test-support"))]
pub fn config_delete_receipt_for_test() -> ports::ConfigDeleteReceipt {
    httpserve::ProducerMarker::for_test(generated::http::settings_v5::PRODUCER).into_receipt()
}

/// Mint a route-typed config-rollback receipt for tests that bypass the HTTP router.
#[cfg(any(test, feature = "test-support"))]
pub fn config_rollback_receipt_for_test() -> ports::ConfigRollbackReceipt {
    httpserve::ProducerMarker::for_test(generated::http::settings_v6::PRODUCER).into_receipt()
}

/// 返回共享同一 in-mem store 的 secret read repo + mutation UoW，供 seed / journey 注入
/// [`SettingsDomain::new`] 的 secret-publish 路由 State（#1430）；secret-resolve 另经
/// [`SecretResolveService`] 只读能力注入。
///
/// `InMemSecretRepo` 保持 `pub(crate)` 封装，此工厂是唯一对外构造路径；两个 dyn port 类型互不可换，
/// 且写入后 read slot 可立即观察同一 store。仅 `test` / `seed-data` 可用。
#[cfg(any(test, feature = "seed-data"))]
pub fn empty_secret_ports() -> (
    std::sync::Arc<ports::DynSecretRepo<'static>>,
    std::sync::Arc<ports::DynSecretUnitOfWork<'static>>,
) {
    let store = internal::mem::new_secret_store();
    (
        std::sync::Arc::from(ports::DynSecretRepo::new_box(
            internal::mem::InMemSecretRepo::from_shared(std::sync::Arc::clone(&store)),
        )),
        std::sync::Arc::from(ports::DynSecretUnitOfWork::new_box(
            internal::mem::InMemSecretRepo::from_shared(store),
        )),
    )
}
