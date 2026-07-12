//! 每路由鉴权闸：route authz metadata + `resolve_requirement` 纯决策 → HTTP 落地。
//!
//! 偏离说明（相对于任务文档 `from_fn` 方案）：axum 0.8 `from_fn` 生成的 `FromFnLayer`
//! 不满足 `MethodRouter::layer` 的 trait bound（`Next: FromRequest` 不成立）；
//! 改用手写 `EnforceLayer`（`impl tower::Layer`）+ `EnforceService`（`impl tower::Service`），
//! 通过 `tower = { workspace = true }` 引入 Layer/Service trait。
//! endpoint evidence 派生的 `PrimaryRouteAuthz` 存于 `EnforceLayer`，不经 extension 传递——
//! 这样 enforce 在 MethodRouter 层执行时可直接读捕获的 route authz metadata 和外层注入的 AuthPlan /
//! RouteAuthorizer extension。
//!
//! INVARIANT: AUTH-FAILCLOSED-01 { level = "Medium", exec = "manual/opt-in", source = "code" }—— 缺 AuthPlan（finalize_auth 未跑） → fail-closed Deny → 403；
//! 控制面 listener opt-out → Deny → 403（不 Allow，永不降级）。
//!
//! INVARIANT: AUTH-EVIDENCE-REQUIRE-01 { level = "Medium", exec = "manual/opt-in", source = "code" }—— `Require(required)` 路由仅在请求携 [`Authenticated`] 证据、其
//! `principal_kind` 非 `Anonymous`、**且 `scheme()` exact-match `required`** 时放行；缺证据 / `Anonymous` 证据 /
//! 方案不匹配（如 Jwt 证据撞 `Require(Mtls)`）→ fail-closed 401（`Anonymous` = 「已知未认证」；匿名可达路由走
//! generated Public evidence，非 Require）。认证证据由组合根验签桥（外层 `.layer()`）在凭据校验通过后注入，
//! httpserve 自身不构造、不验签（finalize_auth 签名冻结，无 verifier 参）；本 crate 单独 merge 无注入方 →
//! 所有 Require 路由仍 401，零端点放开（Medium，单测 + tests/runtime.rs 集成测试守）。
//!
//! INVARIANT: AUTH-EVIDENCE-MINT-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }—— [`Authenticated`] 私有字段（外部无法 struct-literal 伪造）+
//! `Authenticated::new` 仅组合根可调（`rss_authenticated_callsite` callsite dylint，Medium，与 `AuthPlan` 同治理
//! 姿态），杜绝域 crate `.layer(Extension(Authenticated::new(..)))` 伪造证据绕过 enforce。
//!
//! tower readiness 契约：call 使用的 inner 实例必须是 poll_ready 的实例。
//! 采用 clone-replace 模式：call 入口 clone 一份新实例用于放行分支，原 self.inner
//! 保留 poll_ready 状态（见 `EnforceService::call` 注释）。
//!
//! ref: tokio-rs/axum axum/src/middleware/from_fn.rs@main

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::extract::{FromRequestParts, RawPathParams, Request};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use diport::{AuditEvent, AuditOutcome, AuditSink, AuditSinkError};
use primitives::{AuthRequirement, RequiredScheme, RouteAuthOptOut, resolve_requirement};
use tower::Layer;
use tower::Service;
use vocab::{PrincipalKind, ProjectionField, RoutePermissionId, TenantId};

use crate::middleware::RequestId;
use crate::{PrimaryRouteAuthz, RoutePermission, RouteResourceScope};

/// service-token tenant header binding 解析错误（不携 header 值，避免 PII 进入日志）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceTokenTenantBindingError;

/// 从请求 header 生成 service-token MAC tenant binding。
///
/// 缺失、非 UTF-8、非 canonical tenant id 都 fail-closed；调用方应按认证失败处理。
pub fn service_token_tenant_binding(
    headers: &HeaderMap,
) -> Result<(diport::ServiceTokenTenantBinding, TenantId), ServiceTokenTenantBindingError> {
    let mut values = headers.get_all(diport::SERVICE_TOKEN_TENANT_HEADER).iter();
    let raw = values
        .next()
        .ok_or(ServiceTokenTenantBindingError)?
        .to_str()
        .map_err(|_| ServiceTokenTenantBindingError)?;
    if values.next().is_some() {
        return Err(ServiceTokenTenantBindingError);
    }
    let tenant = TenantId::parse(raw).map_err(|_| ServiceTokenTenantBindingError)?;
    Ok((diport::ServiceTokenTenantBinding::new(tenant), tenant))
}

/// 短路 helper：将已构造的错误响应包装成 `Pin<Box<dyn Future<...>>>` 供 `call` 直接返回。
///
/// 收拢 Deny/401/wildcard 三处 `Box::pin(async move { Ok(resp) })` 为单一调用点，
/// 降低认知复杂度（cognitive_complexity lint 目标 ≤ 15）。
fn short_circuit<E>(
    resp: axum::response::Response,
) -> Pin<Box<dyn Future<Output = Result<axum::response::Response, E>> + Send>> {
    Box::pin(async move { Ok(resp) })
}

/// Atomic generated route evidence plus the parsed method used for routing.
///
/// INVARIANT: ROUTE-META-PROPAGATE-01 { level = "Hard", exec = "native-compile", source = "code", native = "private RouteMeta fields are constructed only by enforce_layer from the endpoint evidence value without mapping" }
#[derive(Clone, Debug)]
pub struct RouteMeta {
    evidence: vocab::HttpRouteEvidence,
    method: axum::http::Method,
}

impl RouteMeta {
    /// Borrow the exact evidence supplied to the endpoint constructor.
    #[must_use]
    pub const fn evidence(&self) -> &vocab::HttpRouteEvidence {
        &self.evidence
    }

    /// Borrow the parsed method used by Axum routing.
    #[must_use]
    pub const fn method(&self) -> &axum::http::Method {
        &self.method
    }

    /// Stable generated contract identifier.
    #[must_use]
    pub const fn contract_id(&self) -> &'static str {
        self.evidence.contract_id()
    }

    /// Successful response status declared by the generated contract.
    #[must_use]
    pub const fn success_status(&self) -> vocab::HttpSuccessStatus {
        self.evidence.success_status()
    }

    /// Request replay semantics declared by the generated contract.
    #[must_use]
    pub const fn idempotency(&self) -> vocab::HttpIdempotency {
        self.evidence.idempotency()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteResource {
    id: String,
}

impl RouteResource {
    pub fn new(id: impl Into<String>) -> Option<Self> {
        let id = id.into();
        let uuid = uuid::Uuid::try_parse(&id).ok()?;
        if uuid.is_nil() || uuid.hyphenated().to_string() != id {
            return None;
        }
        Some(Self { id })
    }

    pub fn id(&self) -> &str {
        &self.id
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedSubject {
    tenant_id: TenantId,
    principal_kind: PrincipalKind,
    principal_id: String,
    resource: Option<RouteResource>,
    projection: ResourceProjection,
}

impl AuthorizedSubject {
    fn new(
        tenant_id: TenantId,
        principal_kind: PrincipalKind,
        principal_id: impl Into<String>,
        resource: Option<RouteResource>,
        projection: ResourceProjection,
    ) -> Self {
        Self {
            tenant_id,
            principal_kind,
            principal_id: principal_id.into(),
            resource,
            projection,
        }
    }

    #[cfg(any(test, feature = "test-util"))]
    pub fn for_test(
        tenant_id: TenantId,
        principal_kind: PrincipalKind,
        principal_id: impl Into<String>,
        resource: Option<RouteResource>,
    ) -> Self {
        Self::new(
            tenant_id,
            principal_kind,
            principal_id,
            resource,
            ResourceProjection::default_masked(),
        )
    }

    #[cfg(any(test, feature = "test-util"))]
    pub fn for_test_with_projection(
        tenant_id: TenantId,
        principal_kind: PrincipalKind,
        principal_id: impl Into<String>,
        resource: Option<RouteResource>,
        projection: ResourceProjection,
    ) -> Self {
        Self::new(
            tenant_id,
            principal_kind,
            principal_id,
            resource,
            projection,
        )
    }

    pub fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    pub fn principal_kind(&self) -> PrincipalKind {
        self.principal_kind
    }

    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }

    pub fn resource(&self) -> Option<&RouteResource> {
        self.resource.as_ref()
    }

    pub fn projection(&self) -> ResourceProjection {
        self.projection
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteAuthorizationRequest {
    pub contract_id: &'static str,
    pub permission: RoutePermissionId,
    pub tenant_id: Option<TenantId>,
    pub principal_kind: PrincipalKind,
    pub principal_id: String,
    pub resource: Option<RouteResource>,
}

/// Field mask carried by route authorization output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldMask {
    bits: u16,
}

impl FieldMask {
    const AUDIT_ACTOR: u16 = 1 << 0;
    const AUDIT_TENANT_ID: u16 = 1 << 1;
    const AUDIT_RESOURCE_ID: u16 = 1 << 2;
    const IDENTITY_PROFILE_SUBJECT: u16 = 1 << 3;
    const IDENTITY_PROFILE_TENANT_ID: u16 = 1 << 4;

    fn default_masked() -> Self {
        Self { bits: 0 }
    }

    fn allowing(fields: &[ProjectionField]) -> Self {
        let mut mask = Self::default_masked();
        for field in fields {
            if let Some(bit) = Self::bit_for(*field) {
                mask.bits |= bit;
            }
        }
        mask
    }

    fn allows(self, field: ProjectionField) -> bool {
        Self::bit_for(field).is_some_and(|bit| self.bits & bit != 0)
    }

    fn bit_for(field: ProjectionField) -> Option<u16> {
        match field {
            ProjectionField::AuditActor => Some(Self::AUDIT_ACTOR),
            ProjectionField::AuditTenantId => Some(Self::AUDIT_TENANT_ID),
            ProjectionField::AuditResourceId => Some(Self::AUDIT_RESOURCE_ID),
            ProjectionField::IdentityProfileSubject => Some(Self::IDENTITY_PROFILE_SUBJECT),
            ProjectionField::IdentityProfileTenantId => Some(Self::IDENTITY_PROFILE_TENANT_ID),
            // reason: future fields must stay masked until explicitly wired.
            _ => None,
        }
    }
}

/// Resource projection consumed by read-model rendering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceProjection {
    mask: FieldMask,
}

impl ResourceProjection {
    const MASKED: &'static str = "<redacted>";

    pub fn default_masked() -> Self {
        Self {
            mask: FieldMask::default_masked(),
        }
    }

    pub(crate) fn allowing(fields: &[ProjectionField]) -> Self {
        Self {
            mask: FieldMask::allowing(fields),
        }
    }

    pub fn allows(self, field: ProjectionField) -> bool {
        self.mask.allows(field)
    }

    pub fn render(self, field: ProjectionField, raw: &str) -> String {
        if self.allows(field) {
            raw.to_string()
        } else {
            Self::MASKED.to_string()
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteAuthorizationDecision {
    Allow,
    AllowWithProjection(ResourceProjection),
    Deny,
}

impl RouteAuthorizationDecision {
    pub fn allow_with_unmasked_fields(fields: &[ProjectionField]) -> Self {
        Self::AllowWithProjection(ResourceProjection::allowing(fields))
    }

    fn projection(self) -> Option<ResourceProjection> {
        match self {
            Self::Allow => Some(ResourceProjection::default_masked()),
            Self::AllowWithProjection(projection) => Some(projection),
            Self::Deny => None,
        }
    }
}

pub trait RouteAuthorizer: Send + Sync + 'static {
    fn authorize<'a>(
        &'a self,
        request: RouteAuthorizationRequest,
    ) -> Pin<Box<dyn Future<Output = RouteAuthorizationDecision> + Send + 'a>>;
}

/// Build an [`AuthorizedSubject`] from already-verified auth evidence and a route authorizer
/// decision.
///
/// This keeps handlers from reading [`Authenticated`] principal fields while preserving the
/// invariant that explicit projection can only enter request handling through
/// [`RouteAuthorizationDecision`].
pub async fn authorize_subject_for_permission(
    authorizer: Option<Arc<dyn RouteAuthorizer>>,
    evidence: Option<&Authenticated>,
    contract_id: &'static str,
    permission: RoutePermissionId,
    tenant_id: TenantId,
    resource: Option<RouteResource>,
) -> Option<AuthorizedSubject> {
    let authorizer = authorizer?;
    let evidence =
        evidence.filter(|evidence| evidence.principal_kind() != PrincipalKind::Anonymous)?;
    let principal_id = evidence.self_scoped_principal_id().to_string();
    let principal_kind = evidence.principal_kind();
    let decision = authorizer
        .authorize(RouteAuthorizationRequest {
            contract_id,
            permission,
            tenant_id: Some(tenant_id),
            principal_kind,
            principal_id: principal_id.clone(),
            resource: resource.clone(),
        })
        .await;
    decision.projection().map(|projection| {
        AuthorizedSubject::new(
            tenant_id,
            principal_kind,
            principal_id,
            resource,
            projection,
        )
    })
}

/// 认证证据 extension：验签桥在凭据校验通过后注入请求 extension，enforce 层据此对 `Require` 路由放行
/// （INVARIANT: AUTH-EVIDENCE-REQUIRE-01 { level = "Medium", exec = "manual/opt-in", source = "code" }）。
///
/// 承载已验证主体的审计快照：已验证的 [`RequiredScheme`]（验签桥实际验证的凭据方案）+
/// [`PrincipalKind`]（主体类别）+ principal subject + tenant。principal subject 是 PII，只允许进入
/// [`diport::AuditEvent`]，不得写入普通 tracing / Debug / metrics label。httpserve 仍不依赖 authn：组合根验签桥
/// 负责把 `authn::Principal` 降维成本类型。`scheme` 用 [`RequiredScheme`]（非 `AuthScheme`）：类型层杜绝
/// 「`NoAuth` 证据」自相矛盾——无认证不产证据。私有字段 + [`Authenticated::new`] 构造 funnel：外部可命名 /
/// 收发、不可篡字段；`new` callsite 由 `rss_authenticated_callsite` dylint 限组合根
/// （AUTH-EVIDENCE-MINT-01）。**不 derive `Serialize`**（内部证据，非 wire 类型）。
///
/// 注入方（验签桥）由组合根外层 `.layer()` 装配，本 crate 不构造（与 `AuthPlan` 同治理姿态：域 crate 不构造、
/// 组合根注入）；对标 tower-http `AsyncAuthorizeRequest::authorize` 内 `request.extensions_mut().insert(principal)`
/// 推送范式。
///
/// ref: tower-rs/tower-http tower-http/src/auth/async_require_authorization.rs@master
#[derive(Clone)]
pub struct Authenticated {
    scheme: RequiredScheme,
    principal_kind: PrincipalKind,
    principal_id: String,
    tenant_id: Option<TenantId>,
}

/// Caller-supplied fields for an audit event whose principal identity must come from verified
/// [`Authenticated`] evidence.
///
/// The type deliberately has no principal id/kind fields: a domain can describe the audited
/// operation, but cannot substitute a different identity. [`Authenticated::audit_event`] is the
/// only conversion to [`diport::AuditEvent`].
pub struct AuthenticatedAuditEvent {
    pub occurred_at: std::time::SystemTime,
    pub tenant_id: Option<TenantId>,
    pub resource_kind: &'static str,
    pub resource_id: String,
    pub action: &'static str,
    pub outcome: AuditOutcome,
    pub request_id: Option<String>,
    pub correlation_id: Option<String>,
}

impl Authenticated {
    /// 构造认证证据（验签桥在凭据校验通过后调用）。`scheme` = 验签桥**实际验证的**凭据方案（enforce 按路由
    /// `Require(required)` exact-match 比对，scheme 不匹配 fail-closed 401，杜绝 scheme 混淆）；`principal_kind`
    /// 为脱敏分类标量；`principal_id` / `tenant_id` 只用于审计事件构造。
    pub fn new(
        scheme: RequiredScheme,
        principal_kind: PrincipalKind,
        principal_id: impl Into<String>,
        tenant_id: Option<TenantId>,
    ) -> Self {
        Self {
            scheme,
            principal_kind,
            principal_id: principal_id.into(),
            tenant_id,
        }
    }

    /// 已验证的凭据方案（enforce 按路由 `Require(required)` exact-match 比对）。
    pub fn scheme(&self) -> RequiredScheme {
        self.scheme
    }

    /// 已认证主体的脱敏分类（供下游审计 / 可观测 / 行级可见域派生消费）。
    pub fn principal_kind(&self) -> PrincipalKind {
        self.principal_kind
    }

    /// 已认证主体 subject（PII）：只暴露给租户作用域 handler 作 self-scoped 身份锚点。
    /// 调用方不得写入 tracing / Debug / metrics label。
    pub fn self_scoped_principal_id(&self) -> &str {
        &self.principal_id
    }

    /// 已认证主体租户；跨租户主体（service / super-admin）可能为 `None`。
    pub fn tenant_id(&self) -> Option<TenantId> {
        self.tenant_id
    }

    /// Bind verified principal identity to caller-supplied operation fields without exposing that
    /// identity for handler-local authorization decisions.
    pub fn audit_event(&self, event: AuthenticatedAuditEvent) -> AuditEvent {
        AuditEvent {
            occurred_at: event.occurred_at,
            principal_id: self.principal_id.clone(),
            principal_kind: self.principal_kind,
            tenant_id: event.tenant_id,
            resource_kind: event.resource_kind,
            resource_id: event.resource_id,
            action: event.action,
            outcome: event.outcome,
            request_id: event.request_id,
            correlation_id: event.correlation_id,
        }
    }
}

impl fmt::Debug for Authenticated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authenticated")
            .field("scheme", &self.scheme)
            .field("principal_kind", &self.principal_kind)
            .field("principal_id", &"<redacted>")
            .field("tenant_id", &self.tenant_id)
            .finish()
    }
}

trait SharedAuditSink: Send + Sync + 'static {
    fn record<'a>(
        &'a self,
        event: AuditEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), AuditSinkError>> + Send + 'a>>;
}

impl<S> SharedAuditSink for S
where
    S: AuditSink + Send + Sync + 'static,
{
    fn record<'a>(
        &'a self,
        event: AuditEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), AuditSinkError>> + Send + 'a>> {
        Box::pin(AuditSink::record(self, event))
    }
}

/// Async audit sink handle usable from axum request extensions.
///
/// The handle keeps a Sync facade over static-dispatched providers (`Arc<S: AuditSink + Send + Sync>`), matching
/// DIPORT-ASYNC-ARC-SEND-01 for multi-request async consumers without serializing the hot path behind a mutex.
#[derive(Clone)]
pub struct AuditSinkHandle {
    inner: Arc<dyn SharedAuditSink>,
}

impl AuditSinkHandle {
    pub fn new<S>(sink: S) -> Self
    where
        S: AuditSink + Send + Sync + 'static,
    {
        Self {
            inner: Arc::new(sink),
        }
    }

    pub async fn record(&self, event: AuditEvent) -> Result<(), AuditSinkError> {
        self.inner.record(event).await
    }
}

impl fmt::Debug for AuditSinkHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuditSinkHandle(<redacted>)")
    }
}

#[derive(Clone)]
pub(crate) struct AuthAudit {
    sink: AuditSinkHandle,
    clock: Arc<dyn diport::Clock>,
}

impl AuthAudit {
    pub(crate) fn new(sink: AuditSinkHandle, clock: Arc<dyn diport::Clock>) -> Self {
        Self { sink, clock }
    }
}

// ── PendingScopeCtx ──────────────────────────────────────────────────────────

/// 待建 ambient scope 的 [`runctx::AppCtx`] 载体——组合根验签桥（外层 layer）在验签得到 **scoped** principal
/// 后插入请求 extension；[`EnforceService`] 在 **`Require`-Allow**（认证路由放行，非 Public opt-out）后取出并
/// `runctx::scope` 绑定 handler（#1105 F2：scope 与 route auth 决策对齐——避免 Public 路由因携有效 Bearer 被
/// 误绑 ambient tenant；验签桥在 enforce 外层、运行期读不到 opt_out，故由 enforce 持决策方建 scope）。
///
/// 字段私有 + [`PendingScopeCtx::into_ctx`] 为 `pub(crate)`：仅 httpserve(enforce) 可取出 `AppCtx` 建 scope，
/// handler 即便从 extension 读到本类型也提取不出 ctx（须经 `runctx::try_current` 正道）。构造
/// [`PendingScopeCtx::new`] 公开供验签桥插入——伪造 `AppCtx` 仍受 runctx `PrincipalFacet` 伪造门约束
/// （外部 crate mint 不出合法 `AppCtx`，见 `rss_principal_facet_impl_allowlist`）。
#[derive(Clone)]
pub struct PendingScopeCtx(runctx::AppCtx);

impl PendingScopeCtx {
    /// 组合根验签桥构造（携已验证 scoped principal 的 `AppCtx`）。
    pub fn new(ctx: runctx::AppCtx) -> Self {
        Self(ctx)
    }

    /// 取出 `AppCtx`（仅 enforce 用于 `runctx::scope`）。
    pub(crate) fn into_ctx(self) -> runctx::AppCtx {
        self.0
    }
}

// ── EnforceLayer ─────────────────────────────────────────────────────────────

/// 鉴权 enforce tower Layer（每路由 opt_out + RouteMeta；Copy + Clone 满足 MethodRouter::layer 约束）。
#[derive(Clone)]
pub(crate) struct EnforceLayer {
    authz: Option<PrimaryRouteAuthz>,
    meta: RouteMeta,
}

/// 返回每路由 enforce layer，可直接用于 `MethodRouter::layer()`。
pub(crate) fn enforce_layer(
    authz: Option<PrimaryRouteAuthz>,
    method: axum::http::Method,
    evidence: vocab::HttpRouteEvidence,
) -> EnforceLayer {
    EnforceLayer {
        authz,
        meta: RouteMeta { evidence, method },
    }
}

/// 鉴权 enforce tower Service（包裹内层 Service，包含捕获的 opt_out + RouteMeta）。
pub(crate) struct EnforceService<S> {
    inner: S,
    authz: Option<PrimaryRouteAuthz>,
    meta: RouteMeta,
}

impl<S: Clone> Clone for EnforceService<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            authz: self.authz.clone(),
            meta: self.meta.clone(),
        }
    }
}

impl<S> Layer<S> for EnforceLayer {
    type Service = EnforceService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        EnforceService {
            inner,
            authz: self.authz.clone(),
            meta: self.meta.clone(),
        }
    }
}

/// 拒绝响应类型别名（降低类型复杂度）。
type DenyFuture<E> = Pin<Box<dyn Future<Output = Result<Response, E>> + Send>>;

const MTLS_ROUTE_PERMISSION: RoutePermissionId = RoutePermissionId::MtlsInvoke;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthDecision {
    Allow,
    Require,
    Deny,
}

impl AuthDecision {
    fn as_label(self) -> &'static str {
        match self {
            AuthDecision::Allow => "allow",
            AuthDecision::Require => "require",
            AuthDecision::Deny => "deny",
        }
    }

    fn audit_outcome(self) -> AuditOutcome {
        match self {
            AuthDecision::Allow => AuditOutcome::Success,
            AuthDecision::Require => AuditOutcome::Failure {
                reason: "unauthorized",
            },
            AuthDecision::Deny => AuditOutcome::Failure {
                reason: "forbidden",
            },
        }
    }
}

/// Enforce the generated success response contract at the serving boundary.
///
/// Error responses remain owned by each handler's error mapping, so only 4xx/5xx statuses may
/// differ from the declared success status. Informational, alternate successful, redirect, and
/// non-standard status classes fail closed instead of silently serving a wire shape that differs
/// from the manifest.
fn response_status_matches_contract(declared: u16, actual: StatusCode) -> bool {
    actual.as_u16() == declared || actual.is_client_error() || actual.is_server_error()
}

fn enforce_declared_success_status(
    meta: &RouteMeta,
    request_id: &str,
    response: Response,
) -> Response {
    let declared = meta.success_status().get();
    let idempotency = meta.idempotency();
    if !response_status_matches_contract(declared, response.status()) {
        tracing::error!(
            contract_id = meta.contract_id(),
            declared_status = declared,
            actual_status = response.status().as_u16(),
            declared_idempotency = ?idempotency,
            "route success status drift"
        );
        return crate::error::internal_error(request_id);
    }
    response
}

/// 决策结果（Allow / Require / Deny）。
///
/// `evidence_scheme` = 请求所携 [`Authenticated`] 证据的已验证方案（无证据 / `Anonymous` 证据 → `None`，见 `call`）。
/// `Require(required)` 仅在 `evidence_scheme == Some(required)`（证据存在且**方案 exact-match**）时放行；无证据或
/// 方案不匹配（如 Jwt 证据撞 `Require(Mtls)`）→ fail-closed 401（AUTH-EVIDENCE-REQUIRE-01，杜绝 scheme 混淆）。
/// `Deny` / wildcard 永远 403，证据不参与（fail-closed 不可降级）。
fn decide_auth(
    requirement: AuthRequirement,
    evidence_scheme: Option<RequiredScheme>,
) -> AuthDecision {
    match requirement {
        AuthRequirement::Allow => AuthDecision::Allow,
        // Require：携已验证证据**且方案 exact-match 路由要求** → 放行；否则 fail-closed 401。
        AuthRequirement::Require(required) if evidence_scheme == Some(required) => {
            AuthDecision::Allow
        }
        AuthRequirement::Require(_) => AuthDecision::Require,
        // Deny + #[non_exhaustive] wildcard 均 fail-closed 403。
        _ => AuthDecision::Deny,
    }
}

#[allow(clippy::cognitive_complexity)]
// reason: tracing macros expand into control-flow that inflates this closed three-way decision logger; the source-level
// logic is only decision x optional principal_kind field.
fn log_auth_decision(
    decision: AuthDecision,
    contract_id: &'static str,
    evidence: Option<&Authenticated>,
) {
    match evidence {
        Some(ev) => match decision {
            AuthDecision::Allow => tracing::debug!(
                contract_id,
                authz.decision = decision.as_label(),
                principal.kind = ?ev.principal_kind(),
                "auth allow"
            ),
            AuthDecision::Require => tracing::warn!(
                contract_id,
                authz.decision = decision.as_label(),
                principal.kind = ?ev.principal_kind(),
                "auth require fail-closed 401"
            ),
            AuthDecision::Deny => tracing::warn!(
                contract_id,
                authz.decision = decision.as_label(),
                principal.kind = ?ev.principal_kind(),
                "auth deny"
            ),
        },
        None => match decision {
            AuthDecision::Allow => tracing::debug!(
                contract_id,
                authz.decision = decision.as_label(),
                "auth allow"
            ),
            AuthDecision::Require => tracing::warn!(
                contract_id,
                authz.decision = decision.as_label(),
                "auth require fail-closed 401"
            ),
            AuthDecision::Deny => tracing::warn!(
                contract_id,
                authz.decision = decision.as_label(),
                "auth deny"
            ),
        },
    }
}

fn auth_audit_event(
    audit: &AuthAudit,
    decision: AuthDecision,
    contract_id: &'static str,
    rid: &str,
    evidence: &Authenticated,
) -> AuditEvent {
    evidence.audit_event(AuthenticatedAuditEvent {
        occurred_at: audit.clock.now(),
        tenant_id: evidence.tenant_id(),
        resource_kind: "http_route",
        resource_id: contract_id.to_string(),
        action: "httpserve:authz",
        outcome: decision.audit_outcome(),
        request_id: (!rid.is_empty()).then(|| rid.to_string()),
        correlation_id: diagctx::correlation().map(|c| c.as_str().to_string()),
    })
}

async fn record_auth_audit(
    audit: Option<AuthAudit>,
    decision: AuthDecision,
    contract_id: &'static str,
    rid: String,
    evidence: Option<Authenticated>,
) -> Result<(), AuditSinkError> {
    let Some(audit) = audit else {
        return Ok(());
    };
    let Some(evidence) = evidence else {
        return Ok(());
    };
    let event = auth_audit_event(&audit, decision, contract_id, &rid, &evidence);
    audit.sink.record(event).await
}

fn reject_response<E>(decision: AuthDecision, rid: &str) -> DenyFuture<E> {
    match decision {
        AuthDecision::Require => short_circuit(crate::error::unauthenticated(rid)),
        AuthDecision::Deny => short_circuit(crate::error::forbidden(rid)),
        AuthDecision::Allow => short_circuit(crate::error::internal_error(rid)),
    }
}

fn route_opt_out(authz: &Option<PrimaryRouteAuthz>) -> Option<RouteAuthOptOut> {
    match authz {
        Some(PrimaryRouteAuthz::OptOut(opt_out)) => Some(*opt_out),
        Some(PrimaryRouteAuthz::Permission(_)) | None => None,
    }
}

fn route_permission(authz: &Option<PrimaryRouteAuthz>) -> Option<RoutePermission> {
    match authz {
        Some(PrimaryRouteAuthz::Permission(permission)) => Some(*permission),
        Some(PrimaryRouteAuthz::OptOut(_)) | None => None,
    }
}

async fn route_resource(
    req: &mut Request,
    scope: RouteResourceScope,
    evidence: &Authenticated,
) -> Option<Option<RouteResource>> {
    match scope {
        RouteResourceScope::None => Some(None),
        RouteResourceScope::SelfSubject => {
            RouteResource::new(evidence.self_scoped_principal_id()).map(Some)
        }
        RouteResourceScope::PathParam(name) => {
            let current = std::mem::replace(req, Request::new(Body::empty()));
            let (mut parts, body) = current.into_parts();
            let params = RawPathParams::from_request_parts(&mut parts, &())
                .await
                .ok();
            *req = Request::from_parts(parts, body);
            params
                .and_then(|params| {
                    params
                        .iter()
                        .find_map(|(param, value)| (param == name).then_some(value))
                        .and_then(RouteResource::new)
                })
                .map(Some)
        }
    }
}

async fn authorize_route_permission(
    req: &mut Request,
    meta: &RouteMeta,
    permission: RoutePermission,
    evidence: &Authenticated,
    authorizer: Option<Arc<dyn RouteAuthorizer>>,
) -> Option<Option<AuthorizedSubject>> {
    let resource = route_resource(req, permission.scope, evidence).await?;
    let principal_id = evidence.self_scoped_principal_id().to_string();
    let principal_kind = evidence.principal_kind();
    let tenant_id = evidence.tenant_id();
    let decision = authorizer?
        .authorize(RouteAuthorizationRequest {
            contract_id: meta.contract_id(),
            permission: permission.permission,
            tenant_id,
            principal_kind,
            principal_id: principal_id.clone(),
            resource: resource.clone(),
        })
        .await;
    decision.projection().map(|projection| {
        tenant_id.map(|tenant_id| {
            AuthorizedSubject::new(
                tenant_id,
                principal_kind,
                principal_id,
                resource,
                projection,
            )
        })
    })
}

async fn authorize_mtls_route(
    meta: &RouteMeta,
    evidence: &Authenticated,
    authorizer: Option<Arc<dyn RouteAuthorizer>>,
) -> bool {
    let Some(authorizer) = authorizer else {
        return false;
    };
    let principal_id = evidence.self_scoped_principal_id().to_string();
    let request = RouteAuthorizationRequest {
        contract_id: meta.contract_id(),
        permission: MTLS_ROUTE_PERMISSION,
        tenant_id: evidence.tenant_id(),
        principal_kind: evidence.principal_kind(),
        principal_id,
        resource: None,
    };
    authorizer.authorize(request).await.projection().is_some()
}

impl<S> Service<Request> for EnforceService<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        // tower readiness 契约：poll_ready 的实例即 call 的实例。
        // clone-replace 模式：用已就绪的 self.inner 替换为新 clone，使 inner（旧实例）
        // 带走 poll_ready 状态；放行分支调 inner.call(req)，不调 self.inner.call(req)。
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        let authz = self.authz.clone();
        let meta = self.meta.clone();
        let plan = req.extensions().get::<primitives::AuthPlan>().copied();
        let audit = req.extensions().get::<AuthAudit>().cloned();
        // 验签桥（组合根外层 layer）校验通过后注入的认证证据；enforce 据其**已验证方案**放行 Require 路由。
        // fail-closed 防御纵深：`Anonymous` 证据视同无证据（→ None）——绝不过 Require（即便验签桥误注入；
        // 匿名可达路由经 generated Public evidence 而非 Require）。方案 exact-match 由 reject_if_needed 比对，
        // 杜绝 scheme 混淆（如 Jwt 证据撞 Require(Mtls)）。AUTH-EVIDENCE-REQUIRE-01。
        let evidence = req.extensions().get::<Authenticated>().cloned();
        let evidence_scheme = req
            .extensions()
            .get::<Authenticated>()
            .filter(|ev| ev.principal_kind() != PrincipalKind::Anonymous)
            .map(|ev| ev.scheme());
        let rid = req
            .extensions()
            .get::<RequestId>()
            .map(|r| r.0.clone())
            .unwrap_or_default();

        // 运行期 route method drift 检测：声明 method 与实际请求 method 不一致时记 warn。
        if req.method() != meta.method {
            tracing::warn!(
                declared = %meta.method,
                actual = %req.method(),
                contract_id = meta.contract_id(),
                "route method drift"
            );
        }

        // RouteMeta 进请求 extension，供下游审计/可观测消费。
        req.extensions_mut().insert(meta.clone());

        let requirement = match plan {
            // fail-closed：finalize_auth 未跑，没有 plan → 拒（AUTH-FAILCLOSED-01）。
            None => AuthRequirement::Deny,
            Some(p) => resolve_requirement(p, route_opt_out(&authz)),
        };
        // 仅**认证路由**（`Require`）放行后建 ambient scope；Public opt-out（`requirement=Allow`）不建——
        // 杜绝 Public 路由因携有效 Bearer 被误绑 ambient tenant（#1105 F2，scope 与 route auth 决策对齐）。
        let is_require = matches!(requirement, AuthRequirement::Require(_));
        let requires_mtls_route_authz =
            matches!(requirement, AuthRequirement::Require(RequiredScheme::Mtls));

        let decision = decide_auth(requirement, evidence_scheme);
        log_auth_decision(decision, meta.contract_id(), evidence.as_ref());

        if decision != AuthDecision::Allow {
            let audit_fut =
                record_auth_audit(audit, decision, meta.contract_id(), rid.clone(), evidence);
            return Box::pin(async move {
                if let Err(error) = audit_fut.await {
                    tracing::error!(
                        contract_id = meta.contract_id(),
                        authz.decision = decision.as_label(),
                        error = %error,
                        "auth audit record failed before reject"
                    );
                    return Ok(crate::error::internal_error(&rid));
                }
                reject_response(decision, &rid).await
            });
        }
        let permission = route_permission(&authz);
        let route_authorizer = req.extensions().get::<Arc<dyn RouteAuthorizer>>().cloned();
        Box::pin(async move {
            if let Some(permission) = permission {
                let Some(evidence_ref) = evidence.as_ref() else {
                    return reject_response(AuthDecision::Deny, &rid).await;
                };
                let authorized = authorize_route_permission(
                    &mut req,
                    &meta,
                    permission,
                    evidence_ref,
                    route_authorizer,
                )
                .await;
                let Some(authorized) = authorized else {
                    if let Err(error) = record_auth_audit(
                        audit,
                        AuthDecision::Deny,
                        meta.contract_id(),
                        rid.clone(),
                        evidence.clone(),
                    )
                    .await
                    {
                        tracing::error!(
                            contract_id = meta.contract_id(),
                            authz.decision = AuthDecision::Deny.as_label(),
                            error = %error,
                            "auth audit record failed before route authz reject"
                        );
                        return Ok(crate::error::internal_error(&rid));
                    }
                    return reject_response(AuthDecision::Deny, &rid).await;
                };
                if let Some(authorized) = authorized {
                    req.extensions_mut().insert(authorized);
                }
            } else if requires_mtls_route_authz {
                let Some(evidence_ref) = evidence.as_ref() else {
                    return reject_response(AuthDecision::Deny, &rid).await;
                };
                if !authorize_mtls_route(&meta, evidence_ref, route_authorizer).await {
                    if let Err(error) = record_auth_audit(
                        audit,
                        AuthDecision::Deny,
                        meta.contract_id(),
                        rid.clone(),
                        evidence.clone(),
                    )
                    .await
                    {
                        tracing::error!(
                            contract_id = meta.contract_id(),
                            authz.decision = AuthDecision::Deny.as_label(),
                            error = %error,
                            "auth audit record failed before mtls route authz reject"
                        );
                        return Ok(crate::error::internal_error(&rid));
                    }
                    return reject_response(AuthDecision::Deny, &rid).await;
                }
            }
            // PendingScopeCtx 总是取走（不残留 extension）；仅 `Require`-Allow 用它建 scope，Public opt-out 丢弃（F2）。
            let pending_ctx = req.extensions_mut().remove::<PendingScopeCtx>();
            let scope_ctx = if is_require {
                pending_ctx.map(PendingScopeCtx::into_ctx)
            } else {
                None
            };
            if let Err(error) =
                record_auth_audit(audit, decision, meta.contract_id(), rid.clone(), evidence).await
            {
                tracing::error!(
                    contract_id = meta.contract_id(),
                    authz.decision = decision.as_label(),
                    error = %error,
                    "auth audit record failed before allow"
                );
                return Ok(crate::error::internal_error(&rid));
            }
            // ambient scope 绑定 handler（+ 下游 diport emit）：scoped 认证主体（有 tenant）才建，跨租户 /
            // Public ⇒ 下游 `runctx::try_current()` fail-closed `MissingCtx`（#1105 F2）。
            let response = match scope_ctx {
                Some(ctx) => runctx::scope(ctx, inner.call(req)).await,
                None => inner.call(req).await,
            }?;
            Ok(enforce_declared_success_status(&meta, &rid, response))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;

    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode, header};
    use axum::routing::get;
    use axum::{Extension, Router};
    use diport::{AuditSink, AuditSinkError};
    use primitives::{AuthPlan, AuthScheme, ListenerKind, RequiredScheme, RouteAuthOptOut};
    use tower::ServiceExt;

    #[test]
    fn route_authorization_projection_defaults_masked_and_allows_only_named_fields()
    -> Result<(), String> {
        let default = ResourceProjection::default_masked();
        assert!(!default.allows(ProjectionField::AuditActor));
        assert!(!default.allows(ProjectionField::AuditTenantId));
        assert!(!default.allows(ProjectionField::AuditResourceId));
        assert!(!default.allows(ProjectionField::IdentityProfileSubject));
        assert!(!default.allows(ProjectionField::IdentityProfileTenantId));
        assert_eq!(
            default.render(ProjectionField::AuditActor, "subject"),
            "<redacted>"
        );

        let decision =
            RouteAuthorizationDecision::allow_with_unmasked_fields(&[ProjectionField::AuditActor]);
        let projection = match decision {
            RouteAuthorizationDecision::AllowWithProjection(projection) => projection,
            other => return Err(format!("expected projection allow, got {other:?}")),
        };
        assert!(projection.allows(ProjectionField::AuditActor));
        assert!(!projection.allows(ProjectionField::AuditTenantId));
        assert!(!projection.allows(ProjectionField::AuditResourceId));
        assert!(!projection.allows(ProjectionField::IdentityProfileSubject));
        assert!(!projection.allows(ProjectionField::IdentityProfileTenantId));
        assert_eq!(
            projection.render(ProjectionField::AuditActor, "subject"),
            "subject"
        );
        assert_eq!(
            projection.render(ProjectionField::AuditResourceId, "resource"),
            "<redacted>"
        );
        Ok(())
    }

    use super::*;

    const TEST_CONTRACT: &str = "test.contract";
    const TEST_BINDING: vocab::ContractBinding = vocab::ContractBinding::from_static(
        "test",
        TEST_CONTRACT,
        "v1",
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    );
    const TEST_EFFECTS: &[vocab::HttpEffectKind] = &[vocab::HttpEffectKind::Auth];
    const TEST_EVIDENCE: vocab::HttpRouteEvidence = vocab::HttpRouteEvidence::from_static(
        TEST_BINDING,
        "/test",
        "GET",
        vocab::HttpSuccessStatus::new(200),
        vocab::HttpIdempotency::Idempotent,
        vocab::HttpRouteAuth::Public,
        None,
        false,
        vocab::HttpConsistencyLevel::LocalOnly,
        vocab::HttpEffectProfile::new(TEST_EFFECTS),
    );
    const TEST_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    #[test]
    #[allow(clippy::expect_used)]
    fn declared_response_status_policy_is_closed_by_http_class() {
        let cases = [
            (100, false),
            (199, false),
            (200, false),
            (201, true),
            (299, false),
            (300, false),
            (399, false),
            (400, true),
            (499, true),
            (500, true),
            (599, true),
            (600, false),
        ];

        for (actual, expected) in cases {
            let actual = StatusCode::from_u16(actual).expect("test status is valid");
            assert_eq!(
                response_status_matches_contract(201, actual),
                expected,
                "unexpected policy for status {actual}"
            );
        }
    }

    #[allow(clippy::unwrap_used)]
    fn tenant() -> TenantId {
        TenantId::parse(TEST_TENANT).unwrap()
    }

    fn authed(scheme: RequiredScheme, kind: PrincipalKind) -> Authenticated {
        Authenticated::new(scheme, kind, "principal-1", Some(tenant()))
    }

    fn tenantless_authed(scheme: RequiredScheme, kind: PrincipalKind) -> Authenticated {
        Authenticated::new(scheme, kind, "platform-principal-1", None)
    }

    type SeenAuthzRequest = (
        &'static str,
        RoutePermissionId,
        Option<TenantId>,
        PrincipalKind,
        String,
    );

    #[derive(Clone)]
    struct TestProjectionAuthorizer {
        decision: RouteAuthorizationDecision,
        seen: Arc<Mutex<Vec<SeenAuthzRequest>>>,
    }

    impl RouteAuthorizer for TestProjectionAuthorizer {
        fn authorize<'a>(
            &'a self,
            request: RouteAuthorizationRequest,
        ) -> Pin<Box<dyn Future<Output = RouteAuthorizationDecision> + Send + 'a>> {
            let decision = self.decision;
            let seen = self.seen.clone();
            Box::pin(async move {
                seen.lock().unwrap_or_else(|e| e.into_inner()).push((
                    request.contract_id,
                    request.permission,
                    request.tenant_id,
                    request.principal_kind,
                    request.principal_id,
                ));
                decision
            })
        }
    }

    #[tokio::test]
    async fn route_authorization_projection_builds_authorized_subject_from_evidence()
    -> Result<(), String> {
        let authorizer_impl = Arc::new(TestProjectionAuthorizer {
            decision: RouteAuthorizationDecision::allow_with_unmasked_fields(&[
                ProjectionField::AuditActor,
            ]),
            seen: Arc::new(Mutex::new(Vec::new())),
        });
        let authorizer: Arc<dyn RouteAuthorizer> = authorizer_impl.clone();
        let evidence = authed(RequiredScheme::Jwt, PrincipalKind::Admin);

        let subject = authorize_subject_for_permission(
            Some(authorizer),
            Some(&evidence),
            TEST_CONTRACT,
            vocab::AUDIT_READ_PERMISSION,
            tenant(),
            None,
        )
        .await
        .ok_or_else(|| "expected authorized subject".to_string())?;

        assert_eq!(subject.tenant_id(), tenant());
        assert_eq!(subject.principal_kind(), PrincipalKind::Admin);
        assert_eq!(subject.principal_id(), "principal-1");
        assert!(subject.projection().allows(ProjectionField::AuditActor));
        assert!(
            !subject
                .projection()
                .allows(ProjectionField::AuditResourceId)
        );

        let seen = authorizer_impl
            .seen
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0],
            (
                TEST_CONTRACT,
                vocab::AUDIT_READ_PERMISSION,
                Some(tenant()),
                PrincipalKind::Admin,
                "principal-1".to_string()
            )
        );
        Ok(())
    }

    #[derive(Clone)]
    struct RecordingAuditSink {
        events: Arc<Mutex<Vec<AuditEvent>>>,
        fail: Arc<AtomicBool>,
    }

    impl RecordingAuditSink {
        fn new() -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
                fail: Arc::new(AtomicBool::new(false)),
            }
        }

        fn failing() -> Self {
            let sink = Self::new();
            sink.fail.store(true, Ordering::SeqCst);
            sink
        }

        fn events(&self) -> Vec<AuditEvent> {
            self.events
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
    }

    impl AuditSink for RecordingAuditSink {
        async fn record(&self, event: AuditEvent) -> Result<(), AuditSinkError> {
            if self.fail.load(Ordering::SeqCst) {
                return Err(AuditSinkError::new(std::io::Error::other("audit-failed")));
            }
            self.events
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(event);
            Ok(())
        }

        async fn shutdown(&self) -> Result<(), AuditSinkError> {
            Ok(())
        }
    }

    struct TestClock;

    impl diport::Clock for TestClock {
        fn now(&self) -> SystemTime {
            SystemTime::UNIX_EPOCH
        }
    }

    fn audit_ext(sink: RecordingAuditSink) -> AuthAudit {
        AuthAudit::new(AuditSinkHandle::new(sink), Arc::new(TestClock))
    }

    #[allow(clippy::unwrap_used)]
    fn build_router(opt_out: Option<RouteAuthOptOut>, plan: Option<AuthPlan>) -> Router {
        let mut router = Router::new().route(
            "/test",
            get(|| async { "ok" }).layer(enforce_layer(
                opt_out.map(PrimaryRouteAuthz::OptOut),
                Method::GET,
                TEST_EVIDENCE,
            )),
        );
        if let Some(p) = plan {
            router = router.layer(Extension(p));
        }
        router
    }

    #[allow(clippy::unwrap_used)]
    fn build_router_with_audit(
        opt_out: Option<RouteAuthOptOut>,
        plan: Option<AuthPlan>,
        sink: RecordingAuditSink,
    ) -> Router {
        build_router(opt_out, plan).layer(Extension(audit_ext(sink)))
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn no_plan_is_403() {
        let router = build_router(None, None);
        let req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn public_opt_out_with_jwt_plan_is_200() {
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::Jwt).unwrap();
        let router = build_router(Some(RouteAuthOptOut::Public), Some(plan));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn require_without_auth_header_is_401() {
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::Jwt).unwrap();
        let router = build_router(None, Some(plan));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn require_with_authenticated_evidence_is_200() {
        // AUTH-EVIDENCE-REQUIRE-01：Require(Jwt) + 请求携 Authenticated 证据 → 放行 200。
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::Jwt).unwrap();
        let router = build_router(None, Some(plan));
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        // 验签桥范式：外层 layer 校验通过后注入证据；此处直接 insert 模拟该接缝。
        req.extensions_mut()
            .insert(authed(RequiredScheme::Jwt, PrincipalKind::User));
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn require_with_mismatched_scheme_is_401() {
        // AUTH-EVIDENCE-REQUIRE-01 scheme exact-match：Require(Jwt) 路由 + Mtls 方案证据 → scheme 不匹配 → 401。
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::Jwt).unwrap();
        let router = build_router(None, Some(plan));
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(authed(RequiredScheme::Mtls, PrincipalKind::User));
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn require_with_anonymous_evidence_is_401() {
        // AUTH-EVIDENCE-REQUIRE-01 fail-closed 防御纵深：`Anonymous` 证据视同无证据 → 仍 401。
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::Jwt).unwrap();
        let router = build_router(None, Some(plan));
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(authed(RequiredScheme::Jwt, PrincipalKind::Anonymous));
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn deny_with_evidence_is_still_403() {
        // 证据不降级 Deny：无 plan → Deny；即便携 Authenticated 证据，仍 fail-closed 403（AUTH-FAILCLOSED-01）。
        let router = build_router(None, None);
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(authed(RequiredScheme::Jwt, PrincipalKind::User));
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn allow_records_success_audit_event() {
        let sink = RecordingAuditSink::new();
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::Jwt).unwrap();
        let router = build_router_with_audit(None, Some(plan), sink.clone());
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(authed(RequiredScheme::Jwt, PrincipalKind::User));
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let events = sink.events();
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.principal_id, "principal-1");
        assert_eq!(event.principal_kind, PrincipalKind::User);
        assert_eq!(event.tenant_id, Some(tenant()));
        assert_eq!(event.resource_kind, "http_route");
        assert_eq!(event.resource_id, TEST_CONTRACT);
        assert_eq!(event.action, "httpserve:authz");
        assert_eq!(event.outcome, AuditOutcome::Success);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn require_without_evidence_does_not_forge_audit_event() {
        let sink = RecordingAuditSink::new();
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::Jwt).unwrap();
        let router = build_router_with_audit(None, Some(plan), sink.clone());
        let req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(sink.events().is_empty());
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn tenantless_authenticated_evidence_still_records_audit_event() {
        let sink = RecordingAuditSink::new();
        let plan = AuthPlan::new(ListenerKind::Internal, AuthScheme::ServiceToken).unwrap();
        let router = build_router_with_audit(None, Some(plan), sink.clone());
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(tenantless_authed(
            RequiredScheme::ServiceToken,
            PrincipalKind::Service,
        ));
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].principal_id, "platform-principal-1");
        assert_eq!(events[0].principal_kind, PrincipalKind::Service);
        assert_eq!(events[0].tenant_id, None);
        assert_eq!(events[0].outcome, AuditOutcome::Success);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn require_scheme_mismatch_records_unauthorized_audit_event() {
        let sink = RecordingAuditSink::new();
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::Jwt).unwrap();
        let router = build_router_with_audit(None, Some(plan), sink.clone());
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(authed(RequiredScheme::Mtls, PrincipalKind::User));
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].outcome,
            AuditOutcome::Failure {
                reason: "unauthorized"
            }
        );
        assert_eq!(events[0].principal_kind, PrincipalKind::User);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn deny_with_evidence_records_forbidden_audit_event() {
        let sink = RecordingAuditSink::new();
        let router = build_router_with_audit(None, None, sink.clone());
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(authed(RequiredScheme::Jwt, PrincipalKind::User));
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].outcome,
            AuditOutcome::Failure {
                reason: "forbidden"
            }
        );
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn allow_audit_failure_fails_closed_500() {
        let sink = RecordingAuditSink::failing();
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::Jwt).unwrap();
        let router = build_router_with_audit(None, Some(plan), sink);
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(authed(RequiredScheme::Jwt, PrincipalKind::User));
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn deny_audit_failure_fails_closed_500() {
        let sink = RecordingAuditSink::failing();
        let router = build_router_with_audit(None, None, sink);
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(authed(RequiredScheme::Jwt, PrincipalKind::User));
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn require_with_auth_header_is_fail_closed_401() {
        // fail-closed：httpserve 不验签——裸 Authorization header 非证据，仅请求携 Authenticated
        // extension（验签桥注入）才放行，故带 header 仍 401。
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::Jwt).unwrap();
        let router = build_router(None, Some(plan));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .header(header::AUTHORIZATION, "Bearer token")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn require_with_empty_auth_header_is_401() {
        // F1 fail-closed：空 Authorization header 也一律 401。
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::Jwt).unwrap();
        let router = build_router(None, Some(plan));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .header(header::AUTHORIZATION, "")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn require_with_whitespace_auth_header_is_401() {
        // F1 fail-closed：纯空白 Authorization header 也一律 401。
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::Jwt).unwrap();
        let router = build_router(None, Some(plan));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .header(header::AUTHORIZATION, "   ")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn control_plane_opt_out_is_403() {
        // Internal listener + opt-out → Deny（AUTH-FAILCLOSED-01）。
        let plan = AuthPlan::new(ListenerKind::Internal, AuthScheme::ServiceToken).unwrap();
        let router = build_router(Some(RouteAuthOptOut::Public), Some(plan));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
