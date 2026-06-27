//! RW-W settings journey：配置发布 → in-mem outbox → `settings.config-version-changed` 事件闭环，
//! 组装在 bootstrap（compose）+ memory（in-mem DI port）上，端到端证明 settings L2 OutboxFact 接缝
//! 能拼成闭环（对标 identity 登录 → session-created journey）。
//!
//! 接缝覆盖：
//! - bootstrap 组装：`compose` 跑 settings 的 `Domain::init` → Registry 收集配置路由组（声明、不执行）。
//! - DI 注入：settings 经具体 `memory::MemEmitter`（co-tx UoW 须 Sync）发射 config-version-changed fact；clock 注入。
//! - L2 OutboxFact：publish_config CAS 写 v1 → 发 outbox fact → MemBus → 订阅者消费（跨域只经 contract）。
//!
//! 追踪弹边界（同 identity G1）：服务层闭环——配置服务直接调用，不逐字节跑 axum（httpserve mount 留 Join）；
//! 契约 lifecycle=draft（active serving + subscriber 校验留 #1120 订阅缓存）。
//!
//! ref: watermill message/router.go@fbce4d6cd13c8657c668c7e7990fef90d2471b8a（分发循环）

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use diport::{Subscriber, Topic};
use futures::StreamExt;
use generated::event::settings_v1::{
    SettingsConfigChangeKind, SettingsConfigVersionChangedPayload,
};
use generated::http::settings_v1::SettingsConfigPublishRequest;
use memory::{FixedClock, MemBus, MemEmitter};
use primitives::ListenerKind;
use settings::{SettingsDomain, SettingsService, empty_secret_repo};
use tokio_util::sync::CancellationToken;
use vocab::TenantId;

/// canonical UUID 种子租户（TenantId::parse 接受形态）。
const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
/// config-version-changed event 契约 topic（settings 发布）。
const VERSION_CHANGED_TOPIC: &str = "settings.config-version-changed";
/// 固定发布时刻（确定性断言）。
const NOW_SECS: u64 = 1_000;

#[tokio::test(flavor = "multi_thread")]
async fn publish_config_emits_version_changed_end_to_end() -> Result<()> {
    // 1. in-mem 基础设施（DI port provider 替身）。
    let bus = MemBus::new();

    // 2. bootstrap 组装：settings durable module 实例（#1430）经 Domain::init 挂 config-publish /
    //    secret-publish 业务路由组（config 服务 + secret 仓储端口构造器注入）。
    let domain = SettingsDomain::new(
        Arc::new(SettingsService::with_seed(
            MemEmitter::new(bus.clone()),
            Box::new(FixedClock::at_unix_secs(NOW_SECS)),
        )),
        empty_secret_repo(),
    );
    let mut registry = bootstrap::compose(&[&domain])?;
    let route_groups = registry.route_groups();
    assert_eq!(
        route_groups.len(),
        1,
        "config + secret 同 /api/v1/settings 业务路由组"
    );
    assert_eq!(route_groups[0], (ListenerKind::Primary, "/api/v1/settings"));
    // configs_ready 探针经组合根 wire_settings 的 DomainModuleResult 出向（探针包 PgDbReadiness=adapter 类型），
    // 不在域 crate Domain::init 注册——故 compose 后 registry 无探针。
    assert_eq!(
        registry.probe_count(),
        0,
        "探针经 module result 出向、不在 Domain::init 注册"
    );
    // #1430 review F4：finalize_routes() 实跑 route_group register 闭包——config/secret handler 经
    // primary_route_from_spec 剥 generated SPEC.path 前缀 + mount_primary 实际挂载。证明生产路由注册链
    // (compose → finalize_routes → SPEC.path strip/mount) 成立，非仅声明（route_groups 只验声明、不跑闭包）；
    // SPEC.path 与 SETTINGS_ROUTE_PREFIX 漂移会在 primary_route_from_spec 处 Err、于此暴露。
    let finalized = registry.finalize_routes()?;
    assert_eq!(
        finalized.len(),
        1,
        "config + secret 两路由 finalize 进单一 Primary listener"
    );
    assert_eq!(finalized[0].0, ListenerKind::Primary);

    // 3. 订阅 config-version-changed（须先于发布——in-mem 无重放）。
    let token = CancellationToken::new();
    let mut stream = bus
        .subscriber()
        .subscribe(Topic::new(VERSION_CHANGED_TOPIC), token.clone())
        .await?;

    // 4. 发布配置：注入 MemEmitter + 固定时钟，CAS 写 v1 + 发 version-changed fact。
    let service = SettingsService::with_seed(
        MemEmitter::new(bus.clone()),
        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
    );
    let tenant = TenantId::parse(CANON_TENANT)?;
    let response = service
        .publish_config(
            tenant,
            SettingsConfigPublishRequest {
                key: "app.timeout".to_string(),
                value: "30s".to_string(),
            },
        )
        .await?;
    assert_eq!(response.data.key, "app.timeout");
    assert_eq!(response.data.version, 1, "首次发布 = 版本 1");

    // 5. 闭环：从订阅流读到 config-version-changed 事件（有界超时，防发布未达挂死）。
    let message = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await?
        .ok_or_else(|| anyhow!("expected config-version-changed event"))?;
    let payload: SettingsConfigVersionChangedPayload =
        serde_json::from_slice(message.payload.as_bytes())?;
    assert_eq!(payload.key, "app.timeout");
    assert_eq!(payload.version, 1);
    assert_eq!(payload.change_kind, SettingsConfigChangeKind::Published);
    assert_eq!(payload.source_version, None);
    assert_eq!(payload.tenant_id, CANON_TENANT, "租户贯穿闭环");
    assert_eq!(payload.occurred_at, i64::try_from(NOW_SECS)?);

    // 6. 取消订阅流。
    token.cancel();
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn rollback_emits_version_changed_rolled_back_end_to_end() -> Result<()> {
    // 1. in-mem 基础设施。
    let bus = MemBus::new();
    let token = CancellationToken::new();

    // 2. 先订阅，再发布（in-mem 无重放）。
    let mut stream = bus
        .subscriber()
        .subscribe(Topic::new(VERSION_CHANGED_TOPIC), token.clone())
        .await?;

    // 3. service（with_seed 注入 MemEmitter + 固定时钟）。
    let service = SettingsService::with_seed(
        MemEmitter::new(bus.clone()),
        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
    );
    let tenant = TenantId::parse(CANON_TENANT)?;

    // 4. publish v1 + v2。
    service
        .publish_config(
            tenant,
            SettingsConfigPublishRequest {
                key: "app.k".to_string(),
                value: "v1".to_string(),
            },
        )
        .await?;
    service
        .publish_config(
            tenant,
            SettingsConfigPublishRequest {
                key: "app.k".to_string(),
                value: "v2".to_string(),
            },
        )
        .await?;

    // 5. rollback to v1（生成 v3）。
    let resp = service.rollback(tenant, "app.k", 1).await?;
    assert_eq!(resp.data.version, 3, "rollback 应生成 v3");

    // 6. 从订阅流读 3 条事件。
    let mut last_payload: Option<SettingsConfigVersionChangedPayload> = None;
    for _ in 0..3 {
        let message = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await?
            .ok_or_else(|| anyhow!("expected config-version-changed event"))?;
        let payload: SettingsConfigVersionChangedPayload =
            serde_json::from_slice(message.payload.as_bytes())?;
        last_payload = Some(payload);
    }

    // 7. 断言最后一条事件是 rolledBack。
    let last = last_payload.ok_or_else(|| anyhow!("no event received"))?;
    assert_eq!(
        last.change_kind,
        SettingsConfigChangeKind::RolledBack,
        "最后事件应为 rolledBack"
    );
    assert_eq!(last.version, 3, "rolledBack 事件 version 应为 3");
    assert_eq!(
        last.source_version,
        Some(1),
        "rolledBack 事件 source_version 应为 1"
    );
    assert_eq!(last.key, "app.k");
    assert_eq!(last.tenant_id, CANON_TENANT);

    token.cancel();
    Ok(())
}
