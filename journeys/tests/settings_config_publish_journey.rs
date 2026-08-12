//! settings journey：配置发布/读取/回滚/删除 → in-mem outbox → `settings.config-version-changed` 事件闭环，
//! 组装在 bootstrap（compose）+ memory（in-mem DI port）上，端到端证明 settings L2 OutboxFact 接缝
//! 能拼成闭环（对标 identity 登录 → session-created journey）。
//!
//! 接缝覆盖：
//! - bootstrap 组装：`compose` 跑 settings 的 `Domain::init` → Registry 收集配置路由组（声明、不执行）。
//! - DI 注入：settings 经具体 `memory::MemEmitter`（co-tx UoW 须 Sync）发射 config-version-changed fact；clock 注入。
//! - L2 OutboxFact：publish_config CAS 写 v1 → 发 outbox fact → MemBus → 订阅者消费（跨域只经 contract）。
//!
//! 读取每次以 authoritative head revision 校验 cache；事件订阅只优化预热/失效，不参与正确性证明。
//!
//! ref: watermill message/router.go@fbce4d6cd13c8657c668c7e7990fef90d2471b8a（分发循环）

use std::sync::Arc;
use std::time::Duration;
use std::{future::Future, pin::Pin};

use anyhow::{Result, anyhow};
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use common::memory_tenant_signer;
use diport::{
    DynSecretResolver, KEY_TENANT_AUTHORITY, OpaqueActorId, OutboxActor, SecretCoordinate,
    SecretMaterial, SecretResolver, SecretResolverError, Subscriber, Topic,
};
use futures::StreamExt;
use generated::event::settings_v1::{
    SettingsConfigChangeKind, SettingsConfigVersionChangedPayload,
};
use generated::http::settings_v1::SettingsConfigPublishRequest;
use memory::{FixedClock, MemBus, MemEmitter};
use primitives::{AuthPlan, AuthScheme, ListenerKind};
use rss_request_context::{PrincipalKind, TenantId};
use settings::{SecretResolveService, SettingsDomain, SettingsService, empty_secret_ports};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

mod common;

/// canonical UUID 种子租户（TenantId::parse 接受形态）。
const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
/// config-version-changed event 契约 topic（settings 发布）。
const VERSION_CHANGED_TOPIC: &str = "settings.config-version-changed";
/// 固定发布时刻（确定性断言）。
const NOW_SECS: u64 = 1_000;

fn actor(tenant: TenantId) -> Result<OutboxActor> {
    Ok(OutboxActor::scoped(
        rss_request_context::PrincipalKind::Admin,
        OpaqueActorId::from_opaque("settings-journey-actor")?,
        tenant,
        rss_request_context::RowScope::Tenant,
    ))
}

#[derive(Clone)]
struct AllowAuthorizer;

struct MissingSecretResolver;

impl SecretResolver for MissingSecretResolver {
    async fn resolve(
        &self,
        _tenant: TenantId,
        _coordinate: &SecretCoordinate,
    ) -> Result<SecretMaterial, SecretResolverError> {
        Err(SecretResolverError::NotFound)
    }
}

impl httpserve::RouteAuthorizer for AllowAuthorizer {
    fn authorize<'a>(
        &'a self,
        _request: httpserve::RouteAuthorizationRequest,
    ) -> Pin<Box<dyn Future<Output = httpserve::RouteAuthorizationDecision> + Send + 'a>> {
        Box::pin(async { httpserve::RouteAuthorizationDecision::authorizer_local() })
    }
}

async fn route_request(
    router: &axum::Router,
    method: Method,
    uri: &str,
    body: &'static str,
) -> Result<axum::response::Response> {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))?;
    Ok(router.clone().oneshot(request).await?)
}

fn assert_route_matched(status: StatusCode, route: &str) {
    assert_ne!(status, StatusCode::NOT_FOUND, "{route} must be mounted");
    assert_ne!(
        status,
        StatusCode::METHOD_NOT_ALLOWED,
        "{route} must use its generated method"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn publish_config_emits_version_changed_end_to_end() -> Result<()> {
    // 1. in-mem 基础设施（DI port provider 替身）。
    let bus = MemBus::new();

    // 2. bootstrap 组装：settings durable module 经 Domain::init 挂 config publish/get/delete/rollback /
    //    secret-publish 业务路由组（config 服务 + secret read/write typed 端口构造器注入）。
    let (secret_repo, secret_uow) = empty_secret_ports();
    let secret_resolve = Arc::new(SecretResolveService::new(
        Arc::clone(&secret_repo),
        DynSecretResolver::new_box(MissingSecretResolver),
    ));
    let domain = SettingsDomain::new(
        Arc::new(SettingsService::with_seed(
            MemEmitter::with_tenant_metadata_signer(bus.clone(), memory_tenant_signer()),
            Box::new(FixedClock::at_unix_secs(NOW_SECS)),
        )),
        secret_repo,
        secret_uow,
        secret_resolve,
    );
    let mut registry = bootstrap::compose(&[&domain])?;
    let (admission_control, _, _, write_admission) =
        primitives::prepare_dr_admission_controls().into_parts();
    admission_control.start_running()?;
    registry.install_write_admission(write_admission)?;
    let route_groups = registry.route_groups();
    assert_eq!(
        route_groups.len(),
        1,
        "settings active contracts 同 /api/v1/settings 业务路由组"
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
    // GeneratedPrimaryEndpoint 从 typed ROUTE binding 推导 path/method/auth 并实际挂载。证明生产路由注册链
    // (compose → finalize_routes → ROUTE.evidence().path strip/mount) 成立，非仅声明（route_groups 只验声明、不跑闭包）；
    // generated path 与 SETTINGS_ROUTE_PREFIX 漂移会在 mount 处 Err、于此暴露。
    let mut finalized = registry.finalize_routes()?;
    assert_eq!(
        finalized.len(),
        1,
        "config + secret 两路由 finalize 进单一 Primary listener"
    );
    assert_eq!(finalized[0].0, ListenerKind::Primary);

    // 生产 router 逐条请求：证明五个 generated binding 都实际挂载，且 GET/DELETE 共享同一状态并
    // 产生可观察副作用。此时尚未订阅 in-mem bus，路由 smoke 产生的事件不会干扰后续闭环断言。
    let (_, routes) = finalized
        .pop()
        .ok_or_else(|| anyhow!("settings Primary routes must exist"))?;
    let tenant = TenantId::parse(CANON_TENANT)?;
    let router = httpserve::finalize_primary_auth(
        routes,
        AuthPlan::new(ListenerKind::Primary, AuthScheme::FederatedAccessToken)?,
        Arc::new(AllowAuthorizer),
    )?
    .layer(axum::Extension(httpserve::Authenticated::new(
        httpserve::NonRssTestScheme::FederatedAccessToken,
        PrincipalKind::Admin,
        "settings-route-journey",
        Some(tenant),
    )))
    .into_plaintext_router_for_test();

    let publish = route_request(
        &router,
        Method::POST,
        "/api/v1/settings/configs",
        r#"{"key":"route.timeout","value":"30s"}"#,
    )
    .await?;
    assert_route_matched(publish.status(), "settings.config-publish");
    assert_eq!(publish.status(), StatusCode::CREATED);

    let get = route_request(
        &router,
        Method::GET,
        "/api/v1/settings/configs/route.timeout",
        "",
    )
    .await?;
    assert_route_matched(get.status(), "settings.config-get");
    assert_eq!(get.status(), StatusCode::OK);
    let get_body: serde_json::Value =
        serde_json::from_slice(&to_bytes(get.into_body(), usize::MAX).await?)?;
    assert_eq!(get_body["data"]["value"], "30s");

    let rollback = route_request(
        &router,
        Method::POST,
        "/api/v1/settings/configs/route.timeout/rollbacks",
        r#"{"toVersion":1}"#,
    )
    .await?;
    assert_route_matched(rollback.status(), "settings.config-rollback");

    let secret = route_request(
        &router,
        Method::POST,
        "/api/v1/settings/secrets",
        r#"{"key":"db.password","storeId":"vault","refKey":"secret/data/db"}"#,
    )
    .await?;
    assert_route_matched(secret.status(), "settings.secret-publish");

    let delete = route_request(
        &router,
        Method::DELETE,
        "/api/v1/settings/configs/route.timeout",
        "",
    )
    .await?;
    assert_route_matched(delete.status(), "settings.config-delete");
    assert_eq!(delete.status(), StatusCode::NO_CONTENT);

    let get_after_delete = route_request(
        &router,
        Method::GET,
        "/api/v1/settings/configs/route.timeout",
        "",
    )
    .await?;
    assert_eq!(
        get_after_delete.status(),
        StatusCode::NOT_FOUND,
        "DELETE must tombstone the state observed by the GET route"
    );

    // 3. 订阅 config-version-changed（须先于发布——in-mem 无重放）。
    let token = CancellationToken::new();
    let mut stream = bus
        .subscriber()
        .subscribe(Topic::new(VERSION_CHANGED_TOPIC), token.clone())
        .await?;

    // 4. 发布配置：注入 MemEmitter + 固定时钟，CAS 写 v1 + 发 version-changed fact。
    let service = SettingsService::with_seed(
        MemEmitter::with_tenant_metadata_signer(bus.clone(), memory_tenant_signer()),
        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
    );
    let actor = actor(tenant)?;
    let response = service
        .publish_config(
            settings::config_publish_receipt_for_test(),
            tenant,
            actor,
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
    assert!(
        message.metadata().get(KEY_TENANT_AUTHORITY).is_some(),
        "demo memory provider must carry signed tenantAuthority metadata"
    );
    let payload: SettingsConfigVersionChangedPayload =
        serde_json::from_slice(message.payload().as_bytes())?;
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
        MemEmitter::with_tenant_metadata_signer(bus.clone(), memory_tenant_signer()),
        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
    );
    let query = service.config_query_service();
    let tenant = TenantId::parse(CANON_TENANT)?;
    let subject = actor(tenant)?;

    // 4. publish v1 + v2。
    service
        .publish_config(
            settings::config_publish_receipt_for_test(),
            tenant,
            subject.clone(),
            SettingsConfigPublishRequest {
                key: "app.k".to_string(),
                value: "v1".to_string(),
            },
        )
        .await?;
    service
        .publish_config(
            settings::config_publish_receipt_for_test(),
            tenant,
            subject.clone(),
            SettingsConfigPublishRequest {
                key: "app.k".to_string(),
                value: "v2".to_string(),
            },
        )
        .await?;

    // 5. rollback to v1（生成 v3）。
    let resp = service
        .rollback(
            settings::config_rollback_receipt_for_test(),
            tenant,
            subject,
            "app.k",
            1,
        )
        .await?;
    assert_eq!(resp.data.version, 3, "rollback 应生成 v3");
    let restored = query
        .get_config(tenant, "app.k")
        .await?
        .ok_or_else(|| anyhow!("rolled back config must exist"))?;
    assert_eq!(restored.value(), "v1");
    assert_eq!(restored.version(), 3);

    // 6. 从订阅流读 3 条事件。
    let mut last_payload: Option<SettingsConfigVersionChangedPayload> = None;
    for _ in 0..3 {
        let message = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await?
            .ok_or_else(|| anyhow!("expected config-version-changed event"))?;
        let payload: SettingsConfigVersionChangedPayload =
            serde_json::from_slice(message.payload().as_bytes())?;
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

    // 8. delete 追加 v4 tombstone；重复 delete 是 no-op，读取权威 head 后返回 None。
    service
        .delete(
            settings::config_delete_receipt_for_test(),
            tenant,
            actor(tenant)?,
            "app.k",
        )
        .await?;
    service
        .delete(
            settings::config_delete_receipt_for_test(),
            tenant,
            actor(tenant)?,
            "app.k",
        )
        .await?;
    assert!(query.get_config(tenant, "app.k").await?.is_none());
    let deleted_message = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await?
        .ok_or_else(|| anyhow!("expected deleted event"))?;
    let deleted: SettingsConfigVersionChangedPayload =
        serde_json::from_slice(deleted_message.payload().as_bytes())?;
    assert_eq!(deleted.change_kind, SettingsConfigChangeKind::Deleted);
    assert_eq!(deleted.version, 4);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), stream.next())
            .await
            .is_err(),
        "idempotent delete must not emit a second fact"
    );

    token.cancel();
    Ok(())
}
