//! audit 应用层：session→链 append 订阅 handler + 跨租户 admin 读 handler + bootstrap 生命周期。
//!
//! 消费 identity 域 `identity.session-created` event（跨域只经 contract）→ 构造域 [`AuditRecord`] →
//! 经注入的 [`InMemAuditRepo`] **原子封链** append（domain hash chain，#1014 RW-W 写实，取代 G1 的 flat
//! `diport::AuditSink` 路径）。admin 读 handler（`GET /api/v1/audit/entries`，Admin listener）按已认证
//! 租户分页列出审计条目。
//!
//! # 鉴权作用域（本轮租户级；跨租户 super-admin 读 = follow-up）
//!
//! `AppCtx.principal` 是 `Arc<dyn runctx::PrincipalFacet>`（authn 的 `Principal` 经擦除注入；`runctx → authn`
//! 是禁止的依赖环，故 runctx 不按具体类型持有 principal，#1105）。本 handler 只读 ctx **tenant** 做租户级作用域；跨租户
//! （`RowScope::All`，super-admin 派生）+ 专用 `rss_audit_admin` postgres 池 + 501 fail-closed 待 principal
//! facet + 持久化 adapter 落地（docs/rules/audit-ledger.md、tenancy.md）。Admin listener auth 限定可达者。
//!
//! ref: open-telemetry/opentelemetry-rust opentelemetry/src/logs/logger.rs@main（audit sink 接缝）
//! ref: sigstore/sigstore-rs src/rekor（append-only transparency log → 域 hash chain）

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::Json;
use axum::extract::Query;
use axum::extract::rejection::QueryRejection;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use bootstrap::{Domain, KernelError, Registry, SubscriberHandler, SubscriberHandlerError};
use consistency::ConsumerGroup;
use diport::Message;
use futures::future::BoxFuture;
use generated::event::identity_v1::session_created::{
    IdentitySessionCreatedPayload, SUBSCRIPTIONS,
};
use generated::http::audit_v1::{
    AuditEntryView, AuditListEntriesRequest, AuditListEntriesResponse,
};
use httpserve::{Admin, Route};
// ListenerKind 仅测试断言用（lib 经 typed `route_group::<Admin>` 不再传运行期 ListenerKind 值）。
#[cfg(test)]
use primitives::ListenerKind;

use crate::domain::{AuditEntry, AuditError, AuditOutcome, ResourceRef};
use crate::ports::{AuditListResult, AuditPage, AuditRecord, AuditRepo, DynAuditRepo};

/// 本域 DomainId（在 generated `SUBSCRIPTIONS` 中筛选本域那条订阅；非 wire 元数据，是本域身份）。
const AUDIT_DOMAIN: &str = "audit";

/// 审计资源类别（const literal）。
const RESOURCE_KIND_SESSION: &str = "session";
/// 登录动作（`domain:verb`，vocab::Action 形态）。
const ACTION_LOGIN: &str = "identity:login";

/// admin 读路由组 nest 前缀（Admin listener；与 contracts/http/audit/v1 单源对齐）。
const AUDIT_ROUTE_PREFIX: &str = "/api/v1/audit";
/// admin 读路由在路由组内的**相对**路径——route group 经 `finalize_routes` nest 到 [`AUDIT_ROUTE_PREFIX`]
/// 下，组内 route 须用相对路径（axum `Router::nest` 语义）；用完整路径会被前缀再 nest 一次 ⇒ 真实挂载
/// 路径漂移成 `prefix‖full`（F1）。finalize 后真实路径 = `AUDIT_ROUTE_PREFIX` ‖ `AUDIT_ENTRIES_SUBPATH`
/// （= `/api/v1/audit/entries`，contract.toml 声明值）。HTTP codegen 派生 `CONTRACT_ID`/`PATH`/`METHOD`
/// 消除三处手写 metadata 漂移是 follow-up。
const AUDIT_ENTRIES_SUBPATH: &str = "/entries";
const AUDIT_LIST_CONTRACT_ID: &str = "audit.list-entries";

/// 分页上限（上限 500 由 [`vocab::Limit`] 类型 funnel 兜底；下限 ≥1 由 wire 类型 `NonZeroU32` 反序列化层
/// 保证；默认值 50 由 schema default 经 serde 派生）。
const MAX_LIMIT: u32 = 500;

/// i64 unix 秒 → `SystemTime`（负值收口为 epoch）。
fn from_unix_secs(secs: i64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(u64::try_from(secs).unwrap_or(0))
}

/// `SystemTime` → i64 unix 秒（epoch 前 / 溢出收口为 0 / i64::MAX）。
fn to_unix_secs(time: SystemTime) -> i64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// `vocab::PrincipalKind` → wire 字符串（camelCase）。
fn principal_kind_wire(kind: vocab::PrincipalKind) -> &'static str {
    match kind {
        vocab::PrincipalKind::User => "user",
        vocab::PrincipalKind::Device => "device",
        vocab::PrincipalKind::Admin => "admin",
        vocab::PrincipalKind::SuperAdmin => "superAdmin",
        vocab::PrincipalKind::Service => "service",
        vocab::PrincipalKind::Anonymous => "anonymous",
        // reason: 跨 crate non_exhaustive，未知 kind fail-safe 落 "unknown"（不泄、不 panic）。
        _ => "unknown",
    }
}

/// `AuditOutcome` → wire 字符串（同 crate 穷尽 match ⇒ 新变体编译期强制补）。
fn outcome_wire(outcome: AuditOutcome) -> &'static str {
    match outcome {
        AuditOutcome::Success => "success",
        AuditOutcome::Denied => "denied",
        AuditOutcome::Error => "error",
    }
}

/// `EntryHash` 字节 → 不透明 base64url 摘要（wire 用；非可逆校验凭据）。
fn encode_hash(bytes: &[u8; 32]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// 域条目 → wire view（域→wire 转换收口在 handler 层；domain entity 不直接序列化）。
fn to_view(entry: &AuditEntry) -> AuditEntryView {
    AuditEntryView {
        seq: i64::try_from(entry.seq()).unwrap_or(i64::MAX),
        tenant_id: entry.tenant().to_string(),
        actor: entry.actor().as_uuid().to_string(),
        actor_kind: principal_kind_wire(entry.actor_kind()).to_string(),
        action: entry.action().as_str().to_string(),
        resource_kind: entry.resource().kind().to_string(),
        resource_id: entry.resource().id().to_string(),
        outcome: outcome_wire(entry.outcome()).to_string(),
        recorded_at: to_unix_secs(entry.recorded_at()),
        entry_hash: encode_hash(entry.entry_hash().as_bytes()),
    }
}

/// 仓储分页结果 → wire 响应信封（`data` / `nextCursor` / `hasMore`）。
fn to_response(result: AuditListResult) -> AuditListEntriesResponse {
    AuditListEntriesResponse {
        data: result.entries.iter().map(to_view).collect(),
        next_cursor: result.next_cursor.map(|c| c.as_str().to_string()),
        has_more: result.has_more,
    }
}

/// admin 读 handler：按已认证 ctx **租户**分页列出审计条目（跨租户 super-admin 读 = follow-up，见模块 rustdoc）。
async fn list_entries(
    repo: Arc<DynAuditRepo<'static>>,
    request: AuditListEntriesRequest,
    request_id: String,
) -> Response {
    // 租户 fail-closed：缺 ctx（未经认证通道）即 500，不静默落空租户。
    let Ok(tenant) = runctx::try_with(|ctx| *ctx.tenant()) else {
        return httpserve::error::internal_error(&request_id);
    };
    // 下限 ≥1 由 wire 类型 `NonZeroU32` 在反序列化层 type-enforced（F5）：limit=0 / 负值反序列化即失败
    // → QueryRejection → 统一 400（见路由闭包）。此处仅做上限 500 截断（contract 语义）；截断后 ∈[1,500]，
    // Limit::new 必 Ok（Err 分支 fail-closed 防御，不可达）。
    let limit_value = request.limit.get().min(MAX_LIMIT);
    let Ok(limit) = vocab::Limit::new(limit_value as u16) else {
        return httpserve::error::internal_error(&request_id);
    };
    let cursor = match request.cursor.as_deref() {
        None => None,
        Some(raw) => match vocab::Cursor::parse(raw) {
            Ok(parsed) => Some(parsed),
            // 畸形游标是客户端错误（base64url 不透明 token）。
            Err(_) => return httpserve::error::validation_bad_request(&request_id),
        },
    };
    match repo.list(tenant, AuditPage { limit, cursor }).await {
        Ok(result) => Json(to_response(result)).into_response(),
        // 语义无效游标（合法 base64url 但非有效页索引）是客户端错误 → 400（F4）。
        Err(AuditError::InvalidCursor) => httpserve::error::validation_bad_request(&request_id),
        // 链完整性等其它失败不可静默：记录后 500（无 wire 泄漏）。
        Err(error) => {
            tracing::error!(tenant = %tenant, error = %error, "audit handler: list failed");
            httpserve::error::internal_error(&request_id)
        }
    }
}

/// session-created 订阅 handler：解码 payload → 构造 [`AuditRecord`] → [`AuditRepo`] 原子封链 append。
///
/// crate-local（私有 module 内，不外泄）；持 `Arc<DynAuditRepo>`（erased provider）：clone 进 `Send` future
/// （被 eventexec 分发 / `tokio::spawn`；`AuditRepo` Send 变体 future + `DynAuditRepo: Send + Sync` ⇒ `Arc` 可跨 await 持有）。
pub(crate) struct SessionCreatedAuditHandler {
    repo: Arc<DynAuditRepo<'static>>,
}

impl SessionCreatedAuditHandler {
    /// 注入审计仓储构造。
    pub(crate) fn new(repo: Arc<DynAuditRepo<'static>>) -> Self {
        Self { repo }
    }
}

impl SubscriberHandler for SessionCreatedAuditHandler {
    fn handle(&self, message: Message) -> BoxFuture<'static, Result<(), SubscriberHandlerError>> {
        let repo = self.repo.clone();
        Box::pin(async move {
            // 审计管道失败不可静默（合规/运维盲点）：各失败路径结构化记录后再冒泡（Err→驱动侧 Nack）。
            // source 错误不进 Display（PII 边界），但 message_id 进日志便于关联。
            let msg_id = message.id.clone();
            let payload: IdentitySessionCreatedPayload =
                serde_json::from_slice(message.payload.as_bytes()).map_err(|e| {
                    // serde_json::Error Display 含 payload 值片段（PII 边界）；用 classify() 取无 PII 的错误类别。
                    tracing::error!(
                        message_id = msg_id.as_str(),
                        category = ?e.classify(),
                        "audit handler: session-created payload decode failed"
                    );
                    // 永久：malformed payload 重投无意义（F2/C2）。
                    SubscriberHandlerError::permanent(e)
                })?;
            // tenant fail-closed：非 canonical UUID 即拒（tenancy.md），不静默落空租户。
            let tenant = vocab::TenantId::parse(&payload.tenant_id).map_err(|e| {
                tracing::error!(
                    message_id = msg_id.as_str(),
                    error = %e,
                    "audit handler: non-canonical tenant, refusing to audit"
                );
                // 永久：非 canonical 租户重投无意义（F2/C2）。
                SubscriberHandlerError::permanent(e)
            })?;
            // actor：subject 是 typed `uuid::Uuid`（generated `format:uuid`，#1277 F1）——非 UUID 在 payload
            // decode 即 fail-closed（上方 `from_slice`，由 `rejects_non_canonical_subject` 守），此处直接
            // `UserId::new`（无 parse、无失败分支；审计链 actor 是 typed id，不裸 String）。
            let actor = ids::UserId::new(payload.subject);
            let action = vocab::Action::parse(ACTION_LOGIN).map_err(|e| {
                tracing::error!(
                    message_id = msg_id.as_str(),
                    error = %e,
                    "audit handler: invalid audit action literal"
                );
                // 永久：action literal 非法是编程错误，重投无意义（F2/C2）。
                SubscriberHandlerError::permanent(e)
            })?;
            // session_id fail-closed：非 canonical UUID 即拒（审计 resource id 是 typed `ids::SessionId`，
            // 不裸 String；canonical 化后写入，与 tenant/actor 同纪律，F3）。超长输入由 UUID 定长隐式排除。
            let session = ids::SessionId::parse(&payload.session_id).map_err(|e| {
                tracing::error!(
                    message_id = msg_id.as_str(),
                    error = %e,
                    "audit handler: non-canonical session_id, refusing to audit"
                );
                // 永久：非 canonical session_id 重投无意义（F2/C2）。
                SubscriberHandlerError::permanent(e)
            })?;
            let record = AuditRecord {
                tenant,
                actor,
                // reason: identity.session-created 仅在人类用户成功登录时触发（设备 / service principal
                // 使用独立事件；登录失败不创建 session，无事件发布），故 actor_kind 恒为 User。
                actor_kind: vocab::PrincipalKind::User,
                action,
                resource: ResourceRef::new(RESOURCE_KIND_SESSION, session.as_uuid().to_string()),
                // reason: session-created 事件仅成功登录才发布——失败路径无 session，无 event；outcome 恒 Success。
                outcome: AuditOutcome::Success,
                recorded_at: from_unix_secs(payload.occurred_at),
            };
            repo.append(record).await.map_err(|e| {
                tracing::error!(
                    message_id = msg_id.as_str(),
                    error = %e,
                    "audit handler: chain append failed"
                );
                // 瞬态：append/存储失败可恢复，走 ConsumerBase 有界重试预算，不首投即 DLX（F2/C2）。
                SubscriberHandlerError::transient(e)
            })?;
            Ok(())
        })
    }
}

/// audit 域 bootstrap 生命周期：声明 session-created 订阅 + admin 读路由组。
///
/// 持 erased [`Arc<DynAuditRepo>`](crate::ports::DynAuditRepo)（ADR-005 Option 2 域形 repo port 注入；组合根选
/// provider：prod postgres `PgAuditRepo` / demo in-mem [`crate::internal::mem::InMemAuditRepo`]）——订阅 handler +
/// admin 读路由 clone 共享**同一链 store**（故 `Arc`，`DynAuditRepo: Send + Sync`）。链 HMAC key 强度 fail-fast
/// 在组合根构造 [`AuditChainHasher`](crate::ports::AuditChainHasher) 时收口（`new` 返回 `Option`，弱 key → `None`），
/// 不在本域——本域只消费已装配的 erased provider。
pub struct AuditDomain {
    repo: Arc<DynAuditRepo<'static>>,
}

impl AuditDomain {
    /// 注入 erased 审计仓储 provider 构造（组合根经 `Arc::from(DynAuditRepo::new_box(provider))` 装配后注入）。
    pub fn new(repo: Arc<DynAuditRepo<'static>>) -> Self {
        Self { repo }
    }
}

impl Domain for AuditDomain {
    fn init(&self, reg: &mut Registry) -> Result<(), KernelError> {
        // 订阅元数据（contract_id / topic / group）单源自 generated `SUBSCRIPTIONS`（契约 codegen 派生）——
        // 不手维护平行 const，消除 contract↔consumer 漂移（AI-HARD：codegen funnel + golden）。缺失即 fail-fast。
        let spec = SUBSCRIPTIONS
            .iter()
            .find(|s| s.consumer == AUDIT_DOMAIN)
            .ok_or(KernelError::Subscriber)?;
        let group = ConsumerGroup::parse(spec.group).map_err(|_| KernelError::Subscriber)?;
        reg.subscriber(
            spec.contract_id,
            spec.topic,
            group,
            Box::new(SessionCreatedAuditHandler::new(self.repo.clone())),
        )?;

        // admin 读路由组（Admin listener，typed marker；operator/管理面，非业务对外 Primary）。
        let repo = self.repo.clone();
        reg.route_group::<Admin>(AUDIT_ROUTE_PREFIX, move |rb| {
            let handler = axum::routing::get(
                move |headers: axum::http::HeaderMap,
                      query: Result<Query<AuditListEntriesRequest>, QueryRejection>| {
                    let repo = repo.clone();
                    let request_id = headers
                        .get("x-request-id")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                        .to_string();
                    async move {
                        // F6：Query 解析失败（非法 limit / 未知字段）不返回 axum 裸 400——统一 envelope。
                        let Ok(query) = query else {
                            return httpserve::error::validation_bad_request(&request_id);
                        };
                        list_entries(repo, query.0, request_id).await
                    }
                },
            );
            // route group 内用相对 SUBPATH；nest 到 AUDIT_ROUTE_PREFIX 下真实路径 = AUDIT_ENTRIES_PATH（F1）。
            // Admin listener typed builder：`mount`（非-Primary，无 opt-out；Admin 不可携 opt-out）。
            Ok(rb.mount(
                Route {
                    method: axum::http::Method::GET,
                    path: AUDIT_ENTRIES_SUBPATH,
                    contract_id: AUDIT_LIST_CONTRACT_ID,
                },
                handler,
            ))
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::http::StatusCode;
    use tower::ServiceExt as _;

    use crate::domain::AuditChainHasher;
    use crate::domain::test_support::{TestKeyedHasher, keyed_hasher};
    use crate::internal::mem::InMemAuditRepo;

    const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const CANON_SUBJECT: &str = "11111111-2222-4333-8444-555555555555";
    /// canonical UUID session_id（审计 resource id 是 typed `ids::SessionId`，非 uuid 被 fail-closed 拒，F3）。
    const CANON_SESSION: &str = "22222222-3333-4444-8555-666666666666";
    /// contract.toml 声明的完整路径（= `AUDIT_ROUTE_PREFIX` ‖ `AUDIT_ENTRIES_SUBPATH`）；测试据此断言
    /// finalize 后真实挂载路径 + 直挂 handler-logic 测试路径。
    const AUDIT_ENTRIES_PATH: &str = "/api/v1/audit/entries";

    /// erased in-mem 审计仓储（订阅 + 路由共享形：`Arc<DynAuditRepo>`，同生产装配路径）。
    fn repo() -> Arc<DynAuditRepo<'static>> {
        Arc::from(DynAuditRepo::new_box(InMemAuditRepo::new(keyed_hasher(
            0x5a,
        ))))
    }

    #[allow(clippy::expect_used)]
    fn payload_bytes(subject: &str, tenant: &str) -> Vec<u8> {
        payload_bytes_with_session(subject, tenant, CANON_SESSION)
    }

    #[allow(clippy::expect_used)]
    fn payload_bytes_with_session(subject: &str, tenant: &str, session_id: &str) -> Vec<u8> {
        let payload = IdentitySessionCreatedPayload {
            session_id: session_id.to_string(),
            // subject 是 typed `uuid::Uuid`（#1277 F1，schema `format:uuid`）——helper 入参为 canonical UUID 串，
            // 非 UUID 用例（rejects_non_canonical_subject）走 raw JSON、不经本构造器。
            subject: uuid::Uuid::parse_str(subject).expect("canonical subject uuid"),
            tenant_id: tenant.to_string(),
            occurred_at: 1_700_000_000,
        };
        serde_json::to_vec(&payload).expect("encode")
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn session_created_appends_verifiable_chain_entry() {
        let repo = repo();
        let handler = SessionCreatedAuditHandler::new(repo.clone());
        handler
            .handle(Message::new(
                "m-1",
                payload_bytes(CANON_SUBJECT, CANON_TENANT),
            ))
            .await
            .expect("handle ok");

        let tenant = vocab::TenantId::parse(CANON_TENANT).expect("tenant");
        let page = AuditPage {
            limit: vocab::Limit::new(10).expect("limit"),
            cursor: None,
        };
        let listed = repo.list(tenant, page).await.expect("list");
        assert_eq!(listed.entries.len(), 1);
        let entry = &listed.entries[0];
        assert_eq!(entry.seq(), 0);
        assert_eq!(entry.action().as_str(), ACTION_LOGIN);
        assert_eq!(entry.resource().kind(), RESOURCE_KIND_SESSION);
        assert_eq!(entry.resource().id(), CANON_SESSION);
        assert_eq!(entry.actor().as_uuid().to_string(), CANON_SUBJECT);
        // 落库链条可被同 key hasher 验证完整。
        let verifier: AuditChainHasher<TestKeyedHasher> = keyed_hasher(0x5a);
        assert!(verifier.verify(&listed.entries).is_ok());
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn rejects_undecodable_payload_without_appending() {
        let repo = repo();
        let handler = SessionCreatedAuditHandler::new(repo.clone());
        let result = handler
            .handle(Message::new("m-bad", b"not json".to_vec()))
            .await;
        assert!(result.is_err());
        let tenant = vocab::TenantId::parse(CANON_TENANT).expect("tenant");
        let listed = repo
            .list(
                tenant,
                AuditPage {
                    limit: vocab::Limit::new(10).expect("limit"),
                    cursor: None,
                },
            )
            .await
            .expect("list");
        assert!(listed.entries.is_empty());
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn rejects_non_canonical_tenant() {
        let repo = repo();
        let handler = SessionCreatedAuditHandler::new(repo.clone());
        let result = handler
            .handle(Message::new(
                "m",
                payload_bytes(CANON_SUBJECT, "NOT-A-UUID"),
            ))
            .await;
        assert!(result.is_err());
    }

    /// #1277 F1：subject 是 typed `uuid::Uuid`（schema `format:uuid`）——非 UUID subject 在 payload **decode**
    /// 即 fail-closed（serde 反序列化失败），不进链。用 raw JSON（typed 构造器无法表达非 UUID）证 decode-层拒绝。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn rejects_non_canonical_subject() {
        let repo = repo();
        let handler = SessionCreatedAuditHandler::new(repo.clone());
        // 手造 payload JSON：subject 为非 UUID 字符串（typed `uuid::Uuid` 字段无法表达，故走 raw bytes）。
        let raw = format!(
            r#"{{"sessionId":"{CANON_SESSION}","subject":"alice-not-uuid","tenantId":"{CANON_TENANT}","occurredAt":1700000000}}"#
        )
        .into_bytes();
        let result = handler.handle(Message::new("m", raw)).await;
        assert!(
            result.is_err(),
            "非 UUID subject 须在 wire decode 层 fail-closed 拒（typed uuid::Uuid 不可表达）"
        );
    }

    /// F3：非 canonical UUID 的 session_id 被 fail-closed 拒（不进链），与 tenant/actor 同纪律。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn rejects_non_canonical_session_id() {
        let repo = repo();
        let handler = SessionCreatedAuditHandler::new(repo.clone());
        let result = handler
            .handle(Message::new(
                "m",
                payload_bytes_with_session(CANON_SUBJECT, CANON_TENANT, "sess-not-uuid"),
            ))
            .await;
        assert!(result.is_err(), "非 canonical session_id 须拒绝");
        // anti-vacuity：未 append（链空）。
        let listed = repo
            .list(
                vocab::TenantId::parse(CANON_TENANT).expect("tenant"),
                AuditPage {
                    limit: vocab::Limit::new(10).expect("limit"),
                    cursor: None,
                },
            )
            .await
            .expect("list");
        assert!(listed.entries.is_empty(), "非法 session_id 不得进链");
    }

    // 弱 key（<32B）fail-closed 已上移组合根：`AuditChainHasher::new` 返回 `None`（domain/mod.rs
    // `hasher_construction_rejects_keys_shorter_than_32_bytes` 覆盖）；AuditDomain 只消费已装配 provider。

    #[test]
    #[allow(clippy::expect_used)]
    fn audit_domain_declares_subscriber_and_admin_route_group() {
        let domain = AuditDomain::new(repo());
        let reg = bootstrap::compose(&[&domain]).expect("compose ok");
        let groups = reg.route_groups();
        assert!(
            groups
                .iter()
                .any(|(listener, prefix)| matches!(listener, ListenerKind::Admin)
                    && *prefix == AUDIT_ROUTE_PREFIX),
            "admin 读路由组须声明在 Admin listener: {groups:?}"
        );
        let subs = reg.into_subscribers();
        assert_eq!(subs.len(), 1);
        let spec = SUBSCRIPTIONS[0];
        assert_eq!(spec.consumer, AUDIT_DOMAIN);
        assert_eq!(subs[0].contract_id, spec.contract_id);
        assert_eq!(subs[0].topic, spec.topic);
        assert_eq!(subs[0].group.as_str(), spec.group);
    }

    /// 在注入 ctx tenant 的 Router 上 oneshot 一个 GET（参数绑定 + 状态码 + 响应体）。
    #[allow(clippy::expect_used)]
    async fn get_entries(repo: Arc<DynAuditRepo<'static>>, query: &str) -> (StatusCode, Vec<u8>) {
        let app = axum::Router::new().route(
            AUDIT_ENTRIES_PATH,
            axum::routing::get(
                move |headers: axum::http::HeaderMap,
                      q: Result<Query<AuditListEntriesRequest>, QueryRejection>| {
                    let repo = repo.clone();
                    let request_id = headers
                        .get("x-request-id")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                        .to_string();
                    async move {
                        let Ok(q) = q else {
                            return httpserve::error::validation_bad_request(&request_id);
                        };
                        list_entries(repo, q.0, request_id).await
                    }
                },
            ),
        );
        let uri = format!("{AUDIT_ENTRIES_PATH}{query}");
        let request = axum::http::Request::builder()
            .uri(uri)
            .body(axum::body::Body::empty())
            .expect("request");
        let ctx = runctx::test_support::app_ctx(
            vocab::TenantId::parse(CANON_TENANT).expect("tenant"),
            "admin-subject",
        );
        let response = runctx::scope(ctx, async move { app.oneshot(request).await })
            .await
            .expect("oneshot");
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        (status, body.to_vec())
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn admin_read_lists_tenant_entries_with_pagination() {
        let repo = repo();
        let handler = SessionCreatedAuditHandler::new(repo.clone());
        for _ in 0..3 {
            handler
                .handle(Message::new(
                    "m",
                    payload_bytes(CANON_SUBJECT, CANON_TENANT),
                ))
                .await
                .expect("append");
        }
        // 首页 limit=2 → 2 条 + hasMore + nextCursor。
        let (status, body) = get_entries(repo.clone(), "?limit=2").await;
        assert_eq!(status, StatusCode::OK);
        let page1: AuditListEntriesResponse = serde_json::from_slice(&body).expect("decode");
        assert_eq!(page1.data.len(), 2);
        assert!(page1.has_more);
        assert_eq!(page1.data[0].seq, 0);
        assert_eq!(page1.data[0].action, ACTION_LOGIN);
        assert_eq!(page1.data[0].tenant_id, CANON_TENANT);
        assert_eq!(page1.data[0].actor_kind, "user");
        assert_eq!(page1.data[0].outcome, "success");
        let cursor = page1.next_cursor.expect("next cursor");
        // 续页：剩 1 条 + 无更多。
        let (status, body) = get_entries(repo, &format!("?limit=2&cursor={cursor}")).await;
        assert_eq!(status, StatusCode::OK);
        let page2: AuditListEntriesResponse = serde_json::from_slice(&body).expect("decode");
        assert_eq!(page2.data.len(), 1);
        assert!(!page2.has_more);
        assert!(page2.next_cursor.is_none());
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn admin_read_rejects_malformed_cursor() {
        let (status, body) = get_entries(repo(), "?cursor=!!!not-base64!!!").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        // 验证 JSON 信封：error.code == "ERR_CORE_VALIDATION"。
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["error"]["code"], "ERR_CORE_VALIDATION");
    }

    /// F4：合法 base64url 但语义无效（解码后非页索引）的游标 → 400 统一信封（不静默回首页）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn admin_read_rejects_semantically_invalid_cursor() {
        let bogus = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not-a-number");
        let (status, body) = get_entries(repo(), &format!("?cursor={bogus}")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "语义无效游标须 400");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["error"]["code"], "ERR_CORE_VALIDATION");
    }

    /// F5：limit=0（及负值）是无效页大小 → 400（不静默回退 / 无限续页）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn admin_read_rejects_non_positive_limit() {
        for q in ["?limit=0", "?limit=-1"] {
            let (status, body) = get_entries(repo(), q).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{q} 须 400");
            let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
            assert_eq!(json["error"]["code"], "ERR_CORE_VALIDATION");
        }
    }

    /// F6：Query 解析失败（非整数 limit / 未知字段）→ 统一 400 信封（不漏 axum 裸 400 文本）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn admin_read_query_rejection_maps_to_envelope() {
        for q in ["?limit=abc", "?bogus=1"] {
            let (status, body) = get_entries(repo(), q).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{q} 须 400");
            let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
            assert_eq!(
                json["error"]["code"], "ERR_CORE_VALIDATION",
                "{q} 须走统一 validation 信封"
            );
        }
    }

    /// F1/F7：经真实 bootstrap compose + finalize_routes 驱动，断言 contract 路径 `/api/v1/audit/entries`
    /// 命中已挂载 route（无 plan ⇒ fail-closed 非 404），且旧 bug 的 doubled 前缀路径不存在（404）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn admin_read_route_finalizes_at_contract_path() {
        async fn route_status(router: &axum::Router, path: &str) -> StatusCode {
            let request = axum::http::Request::builder()
                .uri(path)
                .body(axum::body::Body::empty())
                .expect("request");
            router
                .clone()
                .oneshot(request)
                .await
                .expect("oneshot")
                .status()
        }

        let domain = AuditDomain::new(repo());
        let mut reg = bootstrap::compose(&[&domain]).expect("compose ok");
        let routers = reg.finalize_routes().expect("finalize ok");
        let (_, admin) = routers
            .into_iter()
            .find(|(listener, _)| matches!(listener, ListenerKind::Admin))
            .expect("admin router");
        // 取回裸 Router 做 oneshot（`#[doc(hidden)]` 测试入口；生产无此 bindable 出口，ROUTE-AUTH-FUNNEL-01）。
        let admin = admin.into_router_for_test();

        // contract 路径命中 route（enforce_layer 无 plan ⇒ fail-closed 403，证明 route 已挂载于此）。
        let hit = route_status(&admin, AUDIT_ENTRIES_PATH).await;
        assert_ne!(
            hit,
            StatusCode::NOT_FOUND,
            "contract 路径 {AUDIT_ENTRIES_PATH} 须命中已挂载 route（实际 {hit}）"
        );
        // 旧 bug（组内用完整路径）会把 route 挂到 doubled 前缀下；该路径不应存在（F1 回归守卫）。
        let doubled = route_status(&admin, "/api/v1/audit/api/v1/audit/entries").await;
        assert_eq!(
            doubled,
            StatusCode::NOT_FOUND,
            "doubled 前缀路径不应存在（F1 回归）"
        );
    }

    /// 链完整性失败（repo.list → `Err(HashMismatch)`）时 admin 读 fail-closed 返回 500 + ERR_CORE_INTERNAL。
    ///
    /// 经 `FailingAuditRepo` 双 直接验 handler 的 `AuditError`→500 映射（repo 层篡改→`HashMismatch` 的实证由
    /// `internal::mem` 的 `list_returns_error_when_chain_tampered` 覆盖；inherent `corrupt_first_entry_hash`
    /// 在 erased `DynAuditRepo` 不可达，故此处用 typed 双更直接测 handler 行为）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn admin_read_fails_closed_when_list_errors() {
        struct FailingAuditRepo;
        impl AuditRepo for FailingAuditRepo {
            async fn append(&self, _record: AuditRecord) -> Result<(), AuditError> {
                Ok(())
            }
            async fn list(
                &self,
                _tenant: vocab::TenantId,
                _page: AuditPage,
            ) -> Result<AuditListResult, AuditError> {
                Err(AuditError::HashMismatch)
            }
            async fn verify_tail(
                &self,
                _tenant: vocab::TenantId,
                _limit: u32,
            ) -> Result<(), AuditError> {
                Err(AuditError::HashMismatch)
            }
        }
        let repo: Arc<DynAuditRepo<'static>> = Arc::from(DynAuditRepo::new_box(FailingAuditRepo));
        let (status, body) = get_entries(repo, "").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["error"]["code"], "ERR_CORE_INTERNAL");
    }

    /// 无 runctx ctx（未经认证通道）⇒ handler fail-closed 500，不静默落空租户。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn admin_read_without_ctx_fails_closed() {
        let response = list_entries(
            repo(),
            AuditListEntriesRequest {
                limit: std::num::NonZeroU32::new(10).expect("nonzero"),
                cursor: None,
            },
            String::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        // 验证 JSON 信封：error.code == "ERR_CORE_INTERNAL"。
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["error"]["code"], "ERR_CORE_INTERNAL");
    }
}
