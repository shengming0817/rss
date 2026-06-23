//! RW-G1 追踪弹 journey：identity 登录 → in-mem outbox → in-mem 分发 → audit append，
//! 组装在 bootstrap（compose）+ eventexec（run_dispatch）+ memory（in-mem DI port）上，
//! 端到端证明 G0 冻结接缝能拼成闭环（通过 = 放行 W 宽扇出，见 #999）。
//!
//! 接缝覆盖：
//! - bootstrap 组装：`compose` 跑 identity/audit 的 `Domain::init` → Registry 收集 route_group（登录路由）
//!   + subscriber（audit 订阅）。
//! - DI 注入：identity 经 `Box<DynPublisher>`（memory）发布；audit 经 `Arc<MemAuditSink>` 落审计；clock 注入。
//! - 跨域事件：identity 发 `identity.session-created` outbox fact → MemBus → audit 订阅消费（跨域只经 contract）。
//! - 分发：bootstrap `SubscriberHandler` 经组合根 adapt 成 eventexec `HandlerFn`，由 `run_dispatch` 驱动。
//!
//! 追踪弹边界（见 #999 计划）：服务层闭环——登录服务直接调用，不逐字节跑 axum（httpserve mount 留 W）；
//! 契约 lifecycle=draft（active serving 校验留 W）；audit domain 哈希链保持冻结。
//!
//! ref: watermill message/router.go@fbce4d6cd13c8657c668c7e7990fef90d2471b8a（分发循环）
//! ref: uber-go/fx app.go@6fab1b2d3a549a67dfcf50b96161a887181c2afa（组合根装配）
//!
//! 注：本 journey **不** feature-gate（rust-standards §命名的 `#[cfg(feature="integration")]` 隔离
//! 针对**需外部资源**的集成测试——DB/broker/网络）。本 journey 全程 in-process（in-mem DI 替身、确定性、
//! 毫秒级），是必须在 `cargo test` / `cargo xtask verify` 默认跑的验收门，故有意不隔离。

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use audit::AuditDomain;
use bootstrap::SubscriberHandler;
use diport::{DynPublisher, Message, Subscriber, Topic};
use eventexec::{Disposition, HandlerFn};
use generated::http::identity_v1::IdentityLoginRequest;
use identity::{IdentityDomain, LoginService};
use memory::{FixedClock, MemAuditSink, MemBus};
use primitives::ListenerKind;
use tokio_util::sync::CancellationToken;

/// canonical UUID 种子租户（TenantId::parse 接受形态）。
const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
/// session-created event 契约 topic（identity 发布 / audit 订阅）。
const SESSION_CREATED_TOPIC: &str = "identity.session-created";
/// 登录种子凭据。
const USERNAME: &str = "alice";
const PASSWORD: &str = "correct-horse";
const SUBJECT: &str = "alice-subject";
/// 固定登录时刻 + 会话 ttl（确定性断言）。
const NOW_SECS: u64 = 1_000;
const TTL_SECS: u64 = 3_600;

/// 把 bootstrap `SubscriberHandler` 适配成 eventexec `HandlerFn`（Ok→Ack / Err→Nack）。
///
/// 这是组合根的职责：bootstrap 与 eventexec 是兄弟服务（互不依赖），handler 类型在此跨接。
fn adapt(handler: Box<dyn SubscriberHandler>) -> HandlerFn {
    let handler: Arc<dyn SubscriberHandler> = Arc::from(handler);
    Arc::new(move |message: Message| {
        let handler = handler.clone();
        Box::pin(async move {
            match handler.handle(message).await {
                Ok(()) => Disposition::Ack,
                Err(e) => {
                    // 兜底可观测：错误在 adapt 点可见（与 eventexec dispatch / audit handler 日志同链）。
                    tracing::warn!(error = %e, "journey: subscriber handler errored, nacking");
                    Disposition::Nack
                }
            }
        })
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn login_publishes_event_audited_end_to_end() -> Result<()> {
    // 1. in-mem 基础设施（DI port provider 替身）。
    let bus = MemBus::new();
    let sink = Arc::new(MemAuditSink::new());

    // 2. bootstrap 组装：identity 声明登录路由组，audit 声明 session-created 订阅。
    let audit_domain = AuditDomain::new(sink.clone());
    let registry = bootstrap::compose(&[&IdentityDomain, &audit_domain])?;

    // 断言 bootstrap 组装了 identity 的 Primary 登录路由（声明收集，register 闭包不执行）。
    let route_groups = registry.route_groups();
    assert_eq!(route_groups.len(), 1, "identity 登录路由组已声明");
    assert_eq!(route_groups[0], (ListenerKind::Primary, "/api/v1/identity"));
    assert_eq!(registry.probe_count(), 0, "追踪弹未注册探针");

    // 3. 取出订阅声明，接到 eventexec 分发驱动（订阅须先于发布——in-mem 无重放）。
    let token = CancellationToken::new();
    let mut dispatchers = Vec::new();
    for (topic, handler) in registry.into_subscribers() {
        assert_eq!(topic, SESSION_CREATED_TOPIC);
        let stream = bus
            .subscriber()
            .subscribe(Topic::new(topic), token.clone())
            .await?;
        dispatchers.push(tokio::spawn(eventexec::run_dispatch(
            stream,
            adapt(handler),
        )));
    }
    assert_eq!(dispatchers.len(), 1, "恰一个 session-created 订阅");

    // 4. 登录：注入 bus publisher + 固定时钟，发布 session-created。
    let login = LoginService::with_seed_user(
        DynPublisher::new_box(bus.publisher()),
        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
        Duration::from_secs(TTL_SECS),
        USERNAME,
        PASSWORD,
        SUBJECT,
        CANON_TENANT,
    );
    let response = login
        .login(IdentityLoginRequest {
            username: USERNAME.to_string(),
            password: PASSWORD.to_string(),
        })
        .await?;
    assert!(!response.data.session_id.is_empty(), "返回会话 id");
    assert_eq!(
        response.data.expires_at,
        i64::try_from(NOW_SECS + TTL_SECS)?,
        "到期 = now + ttl"
    );

    // 5. 等 audit append 闭环（有界超时，防分发未跑挂死）。
    tokio::time::timeout(Duration::from_secs(5), async {
        while sink.is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;

    // 6. 取消分发 + 等任务收敛（stream take_until 据 token 终止）。
    token.cancel();
    for dispatcher in dispatchers {
        dispatcher.await?;
    }

    // 7. 断言闭环：audit sink 恰收到 1 条匹配登录的审计事件。
    let records = sink.records();
    assert_eq!(records.len(), 1, "恰一条审计记录闭环");
    let record = &records[0];
    assert_eq!(record.action, "login");
    assert_eq!(record.resource_kind, "session");
    assert_eq!(
        record.resource_id, response.data.session_id,
        "会话 id 贯穿闭环"
    );
    assert_eq!(record.principal_id, SUBJECT);
    assert_eq!(record.tenant_id.to_string(), CANON_TENANT, "租户贯穿闭环");
    Ok(())
}

/// 负路径：未知用户登录被拒，不发布事件 ⇒ audit sink 保持空（闭环不被错误触发）。
#[tokio::test(flavor = "multi_thread")]
async fn rejected_login_does_not_audit() -> Result<()> {
    let bus = MemBus::new();
    let sink = Arc::new(MemAuditSink::new());
    let registry = bootstrap::compose(&[&IdentityDomain, &AuditDomain::new(sink.clone())])?;

    let token = CancellationToken::new();
    let mut dispatchers = Vec::new();
    for (topic, handler) in registry.into_subscribers() {
        let stream = bus
            .subscriber()
            .subscribe(Topic::new(topic), token.clone())
            .await?;
        dispatchers.push(tokio::spawn(eventexec::run_dispatch(
            stream,
            adapt(handler),
        )));
    }

    let login = LoginService::with_seed_user(
        DynPublisher::new_box(bus.publisher()),
        Box::new(FixedClock::at_unix_secs(NOW_SECS)),
        Duration::from_secs(TTL_SECS),
        USERNAME,
        PASSWORD,
        SUBJECT,
        CANON_TENANT,
    );
    let result = login
        .login(IdentityLoginRequest {
            username: "mallory".to_string(),
            password: PASSWORD.to_string(),
        })
        .await;
    assert!(result.is_err(), "未知用户登录被拒");

    // 给分发一点时间（若有误发布则会被消费）；随后断言 sink 仍空。
    tokio::time::sleep(Duration::from_millis(20)).await;
    token.cancel();
    for dispatcher in dispatchers {
        dispatcher.await?;
    }
    assert!(sink.is_empty(), "登录失败不产生审计事件");
    Ok(())
}
