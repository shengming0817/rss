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
//! INVARIANT: AUTH-EVIDENCE-REQUIRE-01 { level = "Medium", exec = "manual/opt-in", source = "code" }——
//! `Require(required)` 路由仅在请求携 [`Authenticated`] 证据、其 `principal_kind` 非 `Anonymous`、
//! **且 `scheme()` exact-match `required`** 时放行；`RssAccessToken` 证据仅在 [`PrincipalKind::User`]
//! 时计入。缺证据 / `Anonymous` / non-User `RssAccessToken` / 方案不匹配（如 RSS access 证据撞
//! `Require(Mtls)`）→ fail-closed 401（`Anonymous` = 「已知未认证」；匿名可达路由走 generated Public
//! evidence，非 Require）。认证证据由组合根验签桥（外层 `.layer()`）在凭据校验通过后注入，httpserve
//! 自身不构造、不验签（finalize_auth 签名冻结，无 verifier 参）；本 crate 单独 merge 无注入方 → 所有
//! Require 路由仍 401，零端点放开。Medium canonical：单测
//! `require_with_rss_access_token_non_user_evidence_is_401`；`tests/runtime.rs` 守缺证据 / scheme
//! mismatch / allow 路径（不复制 non-User 矩阵）。
//!
//! INVARIANT: AUTH-EVIDENCE-MINT-01 { level = "Hard", exec = "native-compile", source = "code", native = "capability token + crate graph" }—— [`Authenticated`] 私有字段使非法 shape 不可表示；
//! production profile-specific constructors 要求 [`authmint::AuthenticatedMint`]（组合根经 deny.toml wrappers 持有）；
//! test-util：RSS Access success mint 仅 [`Authenticated::new_rss_user_for_test`] /
//! [`Authenticated::new_rss_user_tenantless_for_test`]；[`Authenticated::new`] 只接受 [`NonRssTestScheme`]；
//! reject-matrix [`Authenticated::new_for_evidence_reject_matrix`] 不能 mint `RssAccessToken`+User。
//! Medium exact mint allowlist + proof-consuming 由 `rss_authenticated_callsite` 守（assembly 内 defense-in-depth；
//! 同 lint 另守 Principal accessor / AuthGrant / JWT / ConfigValue，AUTHN-FUNNEL-CALLSITE-01）。
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
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use diport::{AuditEvent, AuditOutcome, AuditSink, AuditSinkError};
use primitives::{AuthRequirement, RequiredScheme, RouteAuthOptOut, resolve_requirement};
use tower::Layer;
use tower::Service;
use vocab::{PrincipalKind, ProjectionField, RoutePermissionId, TenantId};

use crate::auth_audit::record_auth_audit;
use crate::middleware::VerifiedRequestId;
use crate::{PrimaryRouteAuthz, RoutePermission, RouteResourceScope, RouteTenantBinding};

const BEARER_SCHEME: &[u8] = b"Bearer";
const BEARER_PREFIX_LENGTH: usize = BEARER_SCHEME.len() + 1;

/// service-token tenant header binding 解析错误（不携 header 值，避免 PII 进入日志）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceTokenTenantBindingError;

/// Closed failure reason for an exact-one canonical tenant header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TenantHeaderError {
    /// More than one field value was supplied, even if byte-identical.
    #[error("duplicate tenant header")]
    Duplicate,
    /// The field is missing, oversized, non-UTF-8, or not a canonical tenant identifier.
    #[error("malformed tenant header")]
    Malformed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TenantBindingParseError {
    Duplicate,
    Invalid,
}

/// Parse one canonical tenant header through a byte-bounded, exact-one trust boundary.
///
/// A canonical hyphenated UUID is exactly 36 ASCII bytes. The byte boundary is checked before
/// UTF-8 conversion or UUID parsing.
pub fn exact_tenant_header(headers: &HeaderMap, name: &str) -> Result<TenantId, TenantHeaderError> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(TenantHeaderError::Malformed)?;
    if values.next().is_some() {
        return Err(TenantHeaderError::Duplicate);
    }
    if value.as_bytes().len() != 36 {
        return Err(TenantHeaderError::Malformed);
    }
    let raw = value.to_str().map_err(|_| TenantHeaderError::Malformed)?;
    TenantId::parse(raw).map_err(|_| TenantHeaderError::Malformed)
}

fn parse_service_token_tenant_binding(
    headers: &HeaderMap,
) -> Result<diport::ServiceTokenTenantBinding, TenantBindingParseError> {
    let tenant =
        exact_tenant_header(headers, diport::SERVICE_TOKEN_TENANT_HEADER).map_err(|error| {
            match error {
                TenantHeaderError::Duplicate => TenantBindingParseError::Duplicate,
                TenantHeaderError::Malformed => TenantBindingParseError::Invalid,
            }
        })?;
    Ok(diport::ServiceTokenTenantBinding::new(tenant))
}

/// 从请求 header 生成 service-token tenant challenger。
///
/// 缺失、非 UTF-8、非 canonical tenant id 都 fail-closed；调用方应按认证失败处理。
pub fn service_token_tenant_binding(
    headers: &HeaderMap,
) -> Result<diport::ServiceTokenTenantBinding, ServiceTokenTenantBindingError> {
    parse_service_token_tenant_binding(headers).map_err(|_| ServiceTokenTenantBindingError)
}

/// Closed rejection reason for bearer credential extraction.
///
/// The variants deliberately carry no request data, preventing credentials and tenant identifiers
/// from entering logs, metrics, or error responses through this error value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BearerCredentialError {
    /// More than one value was supplied for an exact-one authentication header.
    #[error("duplicate authentication header")]
    Duplicate,
    /// The credential or required service-token tenant binding is malformed or missing.
    #[error("malformed bearer credential")]
    Malformed,
    /// The authorization scheme is not Bearer.
    #[error("unsupported authorization scheme")]
    UnsupportedScheme,
    /// The encoded credential exceeds its profile's hard byte boundary.
    #[error("bearer credential exceeds profile limit")]
    TooLarge,
}

/// Bounded bearer input extracted at the HTTP trust boundary.
///
/// Fields are private and there is no public constructor: callers can only obtain this value after
/// exact-one header validation and profile-specific size checks. Converting the bounded input into
/// a [`diport::RawCredential`] remains owned by the authn funnel.
pub struct ExtractedBearerCredential {
    profile: diport::TokenProfile,
    token: String,
    service_tenant: Option<diport::ServiceTokenTenantBinding>,
}

impl ExtractedBearerCredential {
    /// Consume the boundary value into the authn funnel inputs.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        diport::TokenProfile,
        String,
        Option<diport::ServiceTokenTenantBinding>,
    ) {
        (self.profile, self.token, self.service_tenant)
    }
}

/// Extract a bearer credential for the listener-fixed token profile.
///
/// The profile is a trusted runtime binding. It is never inferred from attacker-controlled token
/// headers, claims, or auxiliary HTTP headers. Authorization is exact-one: duplicate values are
/// rejected even when byte-identical.
pub fn extract_bearer_credential(
    headers: &HeaderMap,
    profile: diport::TokenProfile,
) -> Result<Option<ExtractedBearerCredential>, BearerCredentialError> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(BearerCredentialError::Duplicate);
    }

    let policy = profile.policy();
    let value_bytes = value.as_bytes();
    // "Bearer " is seven ASCII bytes. This preflight happens before UTF-8 conversion and bounds
    // the complete header value while still accepting a raw token exactly at the profile limit.
    if value_bytes.len()
        > policy
            .maximum_token_length()
            .saturating_add(BEARER_PREFIX_LENGTH)
    {
        return Err(BearerCredentialError::TooLarge);
    }

    let separator = value_bytes
        .iter()
        .position(|byte| *byte == b' ')
        .ok_or(BearerCredentialError::Malformed)?;
    let (scheme, token_with_separator) = value_bytes.split_at(separator);
    if !scheme.eq_ignore_ascii_case(BEARER_SCHEME) {
        return Err(BearerCredentialError::UnsupportedScheme);
    }
    let token_bytes = token_with_separator
        .get(1..)
        .ok_or(BearerCredentialError::Malformed)?;
    if token_bytes.is_empty() || token_bytes.iter().any(u8::is_ascii_whitespace) {
        return Err(BearerCredentialError::Malformed);
    }
    if token_bytes.len() > policy.maximum_token_length() {
        return Err(BearerCredentialError::TooLarge);
    }
    let raw = value
        .to_str()
        .map_err(|_| BearerCredentialError::Malformed)?;
    let token = raw
        .get(BEARER_PREFIX_LENGTH..)
        .ok_or(BearerCredentialError::Malformed)?;

    let service_tenant = match profile {
        diport::TokenProfile::RssAccess
        | diport::TokenProfile::FederatedAccess
        | diport::TokenProfile::ProjectionOperator => None,
        diport::TokenProfile::ServiceToken => {
            let parts = match parse_service_token_tenant_binding(headers) {
                Ok(parts) => parts,
                Err(TenantBindingParseError::Duplicate) => {
                    return Err(BearerCredentialError::Duplicate);
                }
                Err(TenantBindingParseError::Invalid) => {
                    return Err(BearerCredentialError::Malformed);
                }
            };
            Some(parts)
        }
    };

    Ok(Some(ExtractedBearerCredential {
        profile,
        token: token.to_owned(),
        service_tenant,
    }))
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
    contract_id: &'static str,
    permission: RoutePermissionId,
    tenant_id: TenantId,
    principal_kind: PrincipalKind,
    principal_id: String,
    resource: Option<RouteResource>,
    projection: ResourceProjection,
}

impl AuthorizedSubject {
    fn new(
        contract_id: &'static str,
        permission: RoutePermissionId,
        tenant_id: TenantId,
        principal_kind: PrincipalKind,
        principal_id: impl Into<String>,
        resource: Option<RouteResource>,
        projection: ResourceProjection,
    ) -> Self {
        Self {
            contract_id,
            permission,
            tenant_id,
            principal_kind,
            principal_id: principal_id.into(),
            resource,
            projection,
        }
    }

    #[cfg(any(test, feature = "test-util"))]
    pub fn for_test(
        contract_id: &'static str,
        permission: RoutePermissionId,
        tenant_id: TenantId,
        principal_kind: PrincipalKind,
        principal_id: impl Into<String>,
        resource: Option<RouteResource>,
    ) -> Self {
        Self::new(
            contract_id,
            permission,
            tenant_id,
            principal_kind,
            principal_id,
            resource,
            ResourceProjection::default_masked(),
        )
    }

    #[cfg(any(test, feature = "test-util"))]
    pub fn for_test_with_projection(
        contract_id: &'static str,
        permission: RoutePermissionId,
        tenant_id: TenantId,
        principal_kind: PrincipalKind,
        principal_id: impl Into<String>,
        resource: Option<RouteResource>,
        projection: ResourceProjection,
    ) -> Self {
        Self::new(
            contract_id,
            permission,
            tenant_id,
            principal_kind,
            principal_id,
            resource,
            projection,
        )
    }

    /// Exact generated contract identity authorized for this subject.
    #[must_use]
    pub const fn contract_id(&self) -> &'static str {
        self.contract_id
    }

    /// Exact closed route permission authorized for this subject.
    #[must_use]
    pub const fn permission(&self) -> RoutePermissionId {
        self.permission
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
    pub federated_permissions: Option<Box<[vocab::GrantPermission]>>,
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
            federated_permissions: evidence.federated_permissions(),
        })
        .await;
    decision.projection().map(|projection| {
        AuthorizedSubject::new(
            contract_id,
            permission,
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
/// Medium：enforce 滤掉 non-User `RssAccessToken` / `Anonymous` / scheme mismatch → fail-closed 401。
/// Hard mint 收口见模块级 AUTH-EVIDENCE-MINT-01（production mint + test-util
/// [`NonRssTestScheme`] / [`Self::new_rss_user_for_test`] / reject-matrix 非 User）。
///
/// 承载已验证主体的审计快照：已验证的 [`RequiredScheme`]（验签桥实际验证的凭据方案）+
/// [`PrincipalKind`]（主体类别）+ principal subject + tenant。principal subject 是 PII，只允许进入
/// [`diport::AuditEvent`]，不得写入普通 tracing / Debug / metrics label。httpserve 仍不依赖 authn：组合根验签桥
/// 负责把 `authn::Principal` 降维成本类型。`scheme` 用 [`RequiredScheme`]（非 `AuthScheme`）：类型层杜绝
/// 「`NoAuth` 证据」自相矛盾——无认证不产证据。私有字段 + profile-specific constructors 构造 funnel：
/// 外部可命名 / 收发、不可篡字段；production mint 须持 [`authmint::AuthenticatedMint`]（AUTH-EVIDENCE-MINT-01 Hard：
/// token + deny.toml wrappers 限制持有方为 httpserve 与 assembly 组合根）+ Medium exact mint allowlist /
/// proof-consuming（`rss_authenticated_callsite`，assembly 内 defense-in-depth）。
/// **不 derive `Serialize`**（内部证据，非 wire 类型）。
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
    service_caller: Option<vocab::ServiceCallerDomain>,
    federated_permissions: Option<Box<[vocab::GrantPermission]>>,
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

/// Test-only schemes admitted by [`Authenticated::new`].
/// RSS Access is excluded: tenanted success → [`Authenticated::new_rss_user_for_test`];
/// tenantless ambient/authz success-edge → [`Authenticated::new_rss_user_tenantless_for_test`];
/// reject-matrix shapes → [`Authenticated::new_for_evidence_reject_matrix`].
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonRssTestScheme {
    Mtls,
    ServiceToken,
    FederatedAccessToken,
}

#[cfg(any(test, feature = "test-util"))]
impl From<NonRssTestScheme> for RequiredScheme {
    fn from(scheme: NonRssTestScheme) -> Self {
        match scheme {
            NonRssTestScheme::Mtls => RequiredScheme::Mtls,
            NonRssTestScheme::ServiceToken => RequiredScheme::ServiceToken,
            NonRssTestScheme::FederatedAccessToken => RequiredScheme::FederatedAccessToken,
        }
    }
}

/// Non-User principal kinds for RssAccessToken reject-matrix fixtures.
///
/// [`PrincipalKind::User`] is excluded at the type level: tenanted success →
/// [`Authenticated::new_rss_user_for_test`]; tenantless ambient/authz success-edge →
/// [`Authenticated::new_rss_user_tenantless_for_test`].
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RssAccessRejectMatrixKind {
    Device,
    Admin,
    SuperAdmin,
    Service,
    Anonymous,
}

#[cfg(any(test, feature = "test-util"))]
impl From<RssAccessRejectMatrixKind> for PrincipalKind {
    fn from(kind: RssAccessRejectMatrixKind) -> Self {
        match kind {
            RssAccessRejectMatrixKind::Device => PrincipalKind::Device,
            RssAccessRejectMatrixKind::Admin => PrincipalKind::Admin,
            RssAccessRejectMatrixKind::SuperAdmin => PrincipalKind::SuperAdmin,
            RssAccessRejectMatrixKind::Service => PrincipalKind::Service,
            RssAccessRejectMatrixKind::Anonymous => PrincipalKind::Anonymous,
        }
    }
}

impl Authenticated {
    /// Test-only constructor for non-RSS schemes.
    ///
    /// Not for [`RequiredScheme::RssAccessToken`] success fixtures（use
    /// [`Self::new_rss_user_for_test`] / [`Self::new_rss_user_tenantless_for_test`]）and not for
    /// reject matrices that need illegal RSS shapes（use
    /// [`Self::new_for_evidence_reject_matrix`]）.
    #[cfg(any(test, feature = "test-util"))]
    pub fn new(
        scheme: NonRssTestScheme,
        principal_kind: PrincipalKind,
        principal_id: impl Into<String>,
        tenant_id: Option<TenantId>,
    ) -> Self {
        Self {
            scheme: scheme.into(),
            principal_kind,
            principal_id: principal_id.into(),
            tenant_id,
            service_caller: None,
            federated_permissions: None,
        }
    }

    /// Test-only mint for AUTH-EVIDENCE-REQUIRE-01 reject matrices.
    ///
    /// Always [`RequiredScheme::RssAccessToken`] + non-User [`RssAccessRejectMatrixKind`].
    /// Cannot mint `RssAccessToken`+[`PrincipalKind::User`] (compile-time). Must not be used for
    /// LocalOnly/success-path fixtures — tenantless RSS User ambient/authz edges use
    /// [`Self::new_rss_user_tenantless_for_test`].
    #[cfg(any(test, feature = "test-util"))]
    pub fn new_for_evidence_reject_matrix(
        principal_kind: RssAccessRejectMatrixKind,
        principal_id: impl Into<String>,
        tenant_id: Option<TenantId>,
    ) -> Self {
        Self {
            scheme: RequiredScheme::RssAccessToken,
            principal_kind: principal_kind.into(),
            principal_id: principal_id.into(),
            tenant_id,
            service_caller: None,
            federated_permissions: None,
        }
    }

    /// Test-only federated evidence with verified permissions（journeys 等不得依赖 `authmint`）。
    #[cfg(any(test, feature = "test-util"))]
    pub fn new_federated_for_test(
        principal_kind: PrincipalKind,
        principal_id: impl Into<String>,
        tenant_id: Option<TenantId>,
        permissions: &diport::VerifiedFederatedPermissions,
    ) -> Self {
        Self {
            scheme: RequiredScheme::FederatedAccessToken,
            principal_kind,
            principal_id: principal_id.into(),
            tenant_id,
            service_caller: None,
            federated_permissions: Some(permissions.as_slice().to_vec().into_boxed_slice()),
        }
    }

    /// Test-only RSS User evidence with forced tenant（journeys 等不得依赖 `authmint`）。
    #[cfg(any(test, feature = "test-util"))]
    pub fn new_rss_user_for_test(principal_id: impl Into<String>, tenant_id: TenantId) -> Self {
        Self {
            scheme: RequiredScheme::RssAccessToken,
            principal_kind: PrincipalKind::User,
            principal_id: principal_id.into(),
            tenant_id: Some(tenant_id),
            service_caller: None,
            federated_permissions: None,
        }
    }

    /// Test-only RSS User evidence with no tenant.
    ///
    /// Ambient/authz success-edge fixture（e.g. settings ambient 403, httpserve audit 200
    /// tenantless）— **not** reject-matrix. Passes AUTH-EVIDENCE-REQUIRE-01 evidence filter
    /// (`RssAccessToken`+[`PrincipalKind::User`]); downstream ambient/PDP may still deny.
    #[cfg(any(test, feature = "test-util"))]
    pub fn new_rss_user_tenantless_for_test(principal_id: impl Into<String>) -> Self {
        Self {
            scheme: RequiredScheme::RssAccessToken,
            principal_kind: PrincipalKind::User,
            principal_id: principal_id.into(),
            tenant_id: None,
            service_caller: None,
            federated_permissions: None,
        }
    }

    /// Construct federated access evidence.
    ///
    /// Requires [`authmint::AuthenticatedMint`] (AUTH-EVIDENCE-MINT-01 Hard).
    pub fn new_federated(
        _mint: authmint::AuthenticatedMint,
        principal_kind: PrincipalKind,
        principal_id: impl Into<String>,
        tenant_id: Option<TenantId>,
        permissions: &diport::VerifiedFederatedPermissions,
    ) -> Self {
        Self {
            scheme: RequiredScheme::FederatedAccessToken,
            principal_kind,
            principal_id: principal_id.into(),
            tenant_id,
            service_caller: None,
            federated_permissions: Some(permissions.as_slice().to_vec().into_boxed_slice()),
        }
    }

    /// Construct local RSS User authentication evidence after durable grant validation.
    /// Grant correlation remains in identity-owned request evidence.
    ///
    /// Requires [`authmint::AuthenticatedMint`] (AUTH-EVIDENCE-MINT-01 Hard).
    pub fn new_rss_user(
        _mint: authmint::AuthenticatedMint,
        principal_id: impl Into<String>,
        tenant_id: TenantId,
    ) -> Self {
        Self {
            scheme: RequiredScheme::RssAccessToken,
            principal_kind: PrincipalKind::User,
            principal_id: principal_id.into(),
            tenant_id: Some(tenant_id),
            service_caller: None,
            federated_permissions: None,
        }
    }

    /// Construct mTLS transport evidence for a verified service peer.
    ///
    /// Requires [`authmint::AuthenticatedMint`] (AUTH-EVIDENCE-MINT-01 Hard).
    pub fn new_mtls(_mint: authmint::AuthenticatedMint, principal_id: impl Into<String>) -> Self {
        Self {
            scheme: RequiredScheme::Mtls,
            principal_kind: PrincipalKind::Service,
            principal_id: principal_id.into(),
            tenant_id: None,
            service_caller: None,
            federated_permissions: None,
        }
    }

    /// Construct service-token evidence with its verified closed caller domain.
    ///
    /// Requires [`authmint::AuthenticatedMint`] (AUTH-EVIDENCE-MINT-01 Hard).
    pub fn new_service(
        _mint: authmint::AuthenticatedMint,
        tenant_id: TenantId,
        caller: vocab::ServiceCallerDomain,
    ) -> Self {
        Self {
            scheme: RequiredScheme::ServiceToken,
            principal_kind: PrincipalKind::Service,
            principal_id: caller.as_str().to_owned(),
            tenant_id: Some(tenant_id),
            service_caller: Some(caller),
            federated_permissions: None,
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

    /// Verified closed service caller, present only for service-token evidence.
    pub(crate) fn service_caller_domain(&self) -> Option<vocab::ServiceCallerDomain> {
        self.service_caller
    }

    fn federated_permissions(&self) -> Option<Box<[vocab::GrantPermission]>> {
        self.federated_permissions
            .as_deref()
            .map(|permissions| permissions.to_vec().into_boxed_slice())
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

    pub(crate) fn now(&self) -> std::time::SystemTime {
        self.clock.now()
    }

    pub(crate) async fn record(&self, event: AuditEvent) -> Result<(), AuditSinkError> {
        self.sink.record(event).await
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

    fn matches_authenticated(&self, authenticated: &Authenticated) -> bool {
        authenticated.tenant_id() == Some(*self.0.tenant())
            && self.0.principal().kind() == authenticated.principal_kind()
            && self
                .0
                .principal()
                .matches_subject(authenticated.self_scoped_principal_id())
    }
}

// ── EnforceLayer ─────────────────────────────────────────────────────────────

/// 鉴权 enforce tower Layer（每路由 opt_out + RouteMeta；Copy + Clone 满足 MethodRouter::layer 约束）。
#[derive(Clone)]
pub(crate) struct EnforceLayer {
    authz: Option<PrimaryRouteAuthz>,
    meta: RouteMeta,
    write_admission: RouteWriteAdmission,
}

#[derive(Clone)]
pub(crate) enum RouteWriteAdmission {
    ReadOnly,
    Mutation(primitives::WriteAdmission),
}

/// 返回每路由 enforce layer，可直接用于 `MethodRouter::layer()`。
pub(crate) fn enforce_layer(
    authz: Option<PrimaryRouteAuthz>,
    method: axum::http::Method,
    evidence: vocab::HttpRouteEvidence,
    write_admission: RouteWriteAdmission,
) -> EnforceLayer {
    EnforceLayer {
        authz,
        meta: RouteMeta { evidence, method },
        write_admission,
    }
}

/// 鉴权 enforce tower Service（包裹内层 Service，包含捕获的 opt_out + RouteMeta）。
pub(crate) struct EnforceService<S> {
    inner: S,
    authz: Option<PrimaryRouteAuthz>,
    meta: RouteMeta,
    write_admission: RouteWriteAdmission,
}

impl<S: Clone> Clone for EnforceService<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            authz: self.authz.clone(),
            meta: self.meta.clone(),
            write_admission: self.write_admission.clone(),
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
            write_admission: self.write_admission.clone(),
        }
    }
}

/// 拒绝响应类型别名（降低类型复杂度）。
type DenyFuture<E> = Pin<Box<dyn Future<Output = Result<Response, E>> + Send>>;

const MTLS_ROUTE_PERMISSION: RoutePermissionId = RoutePermissionId::MtlsInvoke;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthDecision {
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

    pub(crate) fn audit_outcome(self) -> AuditOutcome {
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
/// 方案不匹配（如 RSS access 证据撞 `Require(Mtls)`）→ fail-closed 401（AUTH-EVIDENCE-REQUIRE-01，杜绝 scheme 混淆）。
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
        Some(PrimaryRouteAuthz::Permission(_) | PrimaryRouteAuthz::ServiceCaller(_)) | None => None,
    }
}

fn route_permission(authz: &Option<PrimaryRouteAuthz>) -> Option<RoutePermission> {
    match authz {
        Some(PrimaryRouteAuthz::Permission(permission)) => Some(*permission),
        Some(PrimaryRouteAuthz::OptOut(_) | PrimaryRouteAuthz::ServiceCaller(_)) | None => None,
    }
}

fn route_service_caller_policy(
    authz: &Option<PrimaryRouteAuthz>,
) -> Option<crate::ServiceCallerPolicy> {
    match authz {
        Some(PrimaryRouteAuthz::ServiceCaller(policy)) => Some(*policy),
        Some(PrimaryRouteAuthz::Permission(_) | PrimaryRouteAuthz::OptOut(_)) | None => None,
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
            federated_permissions: evidence.federated_permissions(),
        })
        .await;
    decision.projection().map(|projection| {
        tenant_id.map(|tenant_id| {
            AuthorizedSubject::new(
                meta.contract_id(),
                permission.permission,
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
        federated_permissions: evidence.federated_permissions(),
    };
    authorizer.authorize(request).await.projection().is_some()
}

fn authorize_service_route(
    meta: &RouteMeta,
    evidence: &Authenticated,
    policy: Option<crate::ServiceCallerPolicy>,
) -> bool {
    let Some(policy) = policy else {
        return false;
    };
    policy.matches_contract(meta.contract_id())
        && evidence.principal_kind() == PrincipalKind::Service
        && evidence
            .service_caller_domain()
            .is_some_and(|caller| policy.allows(caller))
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
        let write_admission = self.write_admission.clone();
        let plan = req.extensions().get::<primitives::AuthPlan>().copied();
        let audit = req.extensions().get::<AuthAudit>().cloned();
        // 验签桥（组合根外层 layer）校验通过后注入的认证证据；enforce 据其**已验证方案**放行 Require 路由。
        // fail-closed 防御纵深：`Anonymous` 证据视同无证据（→ None）——绝不过 Require（即便验签桥误注入；
        // 匿名可达路由经 generated Public evidence 而非 Require）。方案 exact-match 由 reject_if_needed 比对，
        // 杜绝 scheme 混淆（如 RSS access 证据撞 Require(Mtls)）。AUTH-EVIDENCE-REQUIRE-01。
        let evidence = req.extensions().get::<Authenticated>().cloned();
        let evidence_scheme = req
            .extensions()
            .get::<Authenticated>()
            .filter(|ev| {
                ev.principal_kind() != PrincipalKind::Anonymous
                    && (ev.scheme() != RequiredScheme::RssAccessToken
                        || ev.principal_kind() == PrincipalKind::User)
            })
            .map(|ev| ev.scheme());
        let rid = req
            .extensions()
            .get::<VerifiedRequestId>()
            .map(|r| r.as_str().to_owned())
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
        let requires_service_route_authz = matches!(
            requirement,
            AuthRequirement::Require(RequiredScheme::ServiceToken)
        );

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
        let service_caller_policy = route_service_caller_policy(&authz);
        let route_authorizer = req.extensions().get::<Arc<dyn RouteAuthorizer>>().cloned();
        let ambient_binding_matches =
            req.extensions()
                .get::<PendingScopeCtx>()
                .is_some_and(|pending| {
                    evidence
                        .as_ref()
                        .is_some_and(|authenticated| pending.matches_authenticated(authenticated))
                });
        Box::pin(async move {
            if let Some(permission) = permission {
                let Some(evidence_ref) = evidence.as_ref() else {
                    return reject_response(AuthDecision::Deny, &rid).await;
                };
                if permission.tenant_binding == RouteTenantBinding::Ambient
                    && !ambient_binding_matches
                {
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
                            "auth audit record failed before ambient tenant reject"
                        );
                        return Ok(crate::error::internal_error(&rid));
                    }
                    return reject_response(AuthDecision::Deny, &rid).await;
                }
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
            } else if requires_service_route_authz {
                let Some(evidence_ref) = evidence.as_ref() else {
                    return reject_response(AuthDecision::Deny, &rid).await;
                };
                if !authorize_service_route(&meta, evidence_ref, service_caller_policy) {
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
                            "auth audit record failed before service caller reject"
                        );
                        return Ok(crate::error::internal_error(&rid));
                    }
                    return reject_response(AuthDecision::Deny, &rid).await;
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
            let _write_permit = if let RouteWriteAdmission::Mutation(admission) = write_admission {
                match admission.try_enter() {
                    Ok(permit) => Some(permit),
                    Err(
                        primitives::AdmissionError::Paused | primitives::AdmissionError::Stopped,
                    ) => {
                        return Ok(crate::error::provider_unavailable(&rid));
                    }
                    Err(_) => return Ok(crate::error::internal_error(&rid)),
                }
            } else {
                None
            };
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;

    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode, header};
    use axum::routing::get;
    use axum::{Extension, Router};
    use diport::{AuditSink, AuditSinkError};
    use primitives::{AuthPlan, AuthScheme, ListenerKind, RouteAuthOptOut};
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
        vocab::HttpContractOwner::domain("test"),
        TEST_BINDING,
        "/test",
        "GET",
        &[],
        vocab::HttpSuccessStatus::new(200),
        vocab::HttpIdempotency::Idempotent,
        vocab::HttpRouteAuth::Public,
        None,
        false,
        vocab::http::HttpResourceSharing::TenantScoped,
        vocab::HttpConsistencyLevel::LocalOnly,
        vocab::HttpEffectProfile::new(TEST_EFFECTS),
    );
    const TEST_WRITE_EFFECTS: &[vocab::HttpEffectKind] = &[vocab::HttpEffectKind::BusinessWrite];
    const TEST_WRITE_EVIDENCE: vocab::HttpRouteEvidence = vocab::HttpRouteEvidence::from_static(
        vocab::HttpContractOwner::domain("test"),
        TEST_BINDING,
        "/write",
        "POST",
        &[],
        vocab::HttpSuccessStatus::new(200),
        vocab::HttpIdempotency::Idempotent,
        vocab::HttpRouteAuth::Public,
        None,
        false,
        vocab::http::HttpResourceSharing::TenantScoped,
        vocab::HttpConsistencyLevel::LocalOnly,
        vocab::HttpEffectProfile::new(TEST_WRITE_EFFECTS),
    );
    const TEST_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    #[test]
    #[allow(clippy::expect_used)]
    fn service_route_authorization_binds_verified_caller_to_exact_contract() {
        let tenant = TenantId::parse(TEST_TENANT).expect("tenant fixture");
        let evidence = Authenticated::new_service(
            authmint::AuthenticatedMint::capability(),
            tenant,
            vocab::ServiceCallerDomain::MaintenanceOperator,
        );
        let meta = RouteMeta {
            evidence: TEST_EVIDENCE,
            method: Method::GET,
        };

        assert!(authorize_service_route(
            &meta,
            &evidence,
            Some(crate::ServiceCallerPolicy::exact(
                TEST_CONTRACT,
                vocab::ServiceCallerDomain::MaintenanceOperator,
            )),
        ));
        assert!(!authorize_service_route(
            &meta,
            &evidence,
            Some(crate::ServiceCallerPolicy::exact(
                "test.other-contract",
                vocab::ServiceCallerDomain::MaintenanceOperator,
            )),
        ));
    }

    // INVARIANT: service-route authz requires typed `service_caller` on evidence — matching
    // contract + PrincipalKind::Service alone is insufficient. With a singleton
    // `ServiceCallerDomain`, this locks *missing* domain / non-token Service peers, not
    // `allows()==false` for a distinct domain variant. Anti-vacuity: typed allowlisted
    // MaintenanceOperator + matching contract must still allow.
    #[test]
    #[allow(clippy::expect_used)]
    fn authorize_service_route_denied_when_typed_caller_domain_missing() {
        let tenant = TenantId::parse(TEST_TENANT).expect("tenant fixture");
        let meta = RouteMeta {
            evidence: TEST_EVIDENCE,
            method: Method::GET,
        };
        let policy = crate::ServiceCallerPolicy::exact(
            TEST_CONTRACT,
            vocab::ServiceCallerDomain::MaintenanceOperator,
        );

        let with_typed_domain = Authenticated::new_service(
            authmint::AuthenticatedMint::capability(),
            tenant,
            vocab::ServiceCallerDomain::MaintenanceOperator,
        );
        assert!(
            authorize_service_route(&meta, &with_typed_domain, Some(policy)),
            "typed allowlisted caller + matching contract must allow (anti-vacuity)"
        );
        assert!(
            policy.allows(vocab::ServiceCallerDomain::MaintenanceOperator),
            "ServiceCallerPolicy::allows must admit the exact policy domain (anti-vacuity)"
        );

        // ServiceToken scheme + Service kind, but `service_caller` absent on evidence → deny.
        let missing_domain = Authenticated::new(
            NonRssTestScheme::ServiceToken,
            PrincipalKind::Service,
            vocab::ServiceCallerDomain::MaintenanceOperator.as_str(),
            Some(tenant),
        );
        assert!(
            !authorize_service_route(&meta, &missing_domain, Some(policy)),
            "Service evidence lacking typed caller domain must deny"
        );

        // mTLS Service peer is PrincipalKind::Service but carries no service-token domain.
        let mtls_peer =
            Authenticated::new_mtls(authmint::AuthenticatedMint::capability(), "mtls-peer");
        assert!(
            !authorize_service_route(&meta, &mtls_peer, Some(policy)),
            "mTLS Service peer must not satisfy service-token caller allowlist"
        );
    }

    fn bearer_headers(value: axum::http::HeaderValue) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, value);
        headers
    }

    #[test]
    fn bearer_credential_rejects_missing_malformed_and_unsupported_inputs() {
        let missing = HeaderMap::new();
        assert_eq!(
            extract_bearer_credential(&missing, diport::TokenProfile::RssAccess)
                .map(|credential| credential.is_none()),
            Ok(true)
        );

        for malformed in ["Bearer", "Bearer ", "Bearer  token", "Bearer token extra"] {
            let headers = bearer_headers(axum::http::HeaderValue::from_static(malformed));
            assert_eq!(
                extract_bearer_credential(&headers, diport::TokenProfile::RssAccess).map(|_| ()),
                Err(BearerCredentialError::Malformed),
                "input must be malformed: {malformed:?}"
            );
        }

        let unsupported =
            bearer_headers(axum::http::HeaderValue::from_static("Basic dXNlcjpwYXNz"));
        assert_eq!(
            extract_bearer_credential(&unsupported, diport::TokenProfile::RssAccess).map(|_| ()),
            Err(BearerCredentialError::UnsupportedScheme)
        );
    }

    #[test]
    fn bearer_credential_rejects_duplicate_authorization_values() {
        for second in ["Bearer first", "Bearer second"] {
            let mut headers = HeaderMap::new();
            headers.append(
                header::AUTHORIZATION,
                axum::http::HeaderValue::from_static("Bearer first"),
            );
            headers.append(
                header::AUTHORIZATION,
                axum::http::HeaderValue::from_static(second),
            );
            assert_eq!(
                extract_bearer_credential(&headers, diport::TokenProfile::RssAccess).map(|_| ()),
                Err(BearerCredentialError::Duplicate)
            );
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn bearer_credential_uses_listener_profile_and_accepts_case_insensitive_scheme() {
        for (profile, scheme) in [
            (diport::TokenProfile::RssAccess, "bearer"),
            (diport::TokenProfile::FederatedAccess, "BEARER"),
            (diport::TokenProfile::ServiceToken, "BeArEr"),
        ] {
            let value = format!("{scheme} opaque.token.value");
            let mut headers = bearer_headers(
                axum::http::HeaderValue::from_str(&value)
                    .expect("test authorization value is valid"),
            );
            if profile == diport::TokenProfile::ServiceToken {
                headers.insert(
                    diport::SERVICE_TOKEN_TENANT_HEADER,
                    axum::http::HeaderValue::from_static(TEST_TENANT),
                );
            }

            let credential = extract_bearer_credential(&headers, profile)
                .expect("valid profile-specific credential")
                .expect("credential must be present");
            let (actual_profile, token, service_tenant) = credential.into_parts();
            assert_eq!(actual_profile, profile);
            assert_eq!(token, "opaque.token.value");
            assert_eq!(
                service_tenant.is_some(),
                profile == diport::TokenProfile::ServiceToken
            );
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn bearer_credential_accepts_profile_limit_and_rejects_limit_plus_one() {
        let limit = diport::TokenProfile::RssAccess
            .policy()
            .maximum_token_length();
        for (token_length, expected) in [
            (limit, Ok(())),
            (
                limit.saturating_add(1),
                Err(BearerCredentialError::TooLarge),
            ),
        ] {
            let value = format!("Bearer {}", "a".repeat(token_length));
            let headers = bearer_headers(
                axum::http::HeaderValue::from_str(&value)
                    .expect("bounded test authorization value is valid"),
            );
            assert_eq!(
                extract_bearer_credential(&headers, diport::TokenProfile::RssAccess).map(|_| ()),
                expected
            );
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn bearer_credential_size_check_precedes_utf8_conversion() {
        let limit = diport::TokenProfile::RssAccess
            .policy()
            .maximum_token_length();
        let mut value = b"Bearer ".to_vec();
        value.extend(std::iter::repeat_n(0x80, limit.saturating_add(1)));
        let headers = bearer_headers(
            axum::http::HeaderValue::from_bytes(&value)
                .expect("HTTP permits obs-text bytes in a field value"),
        );

        assert_eq!(
            extract_bearer_credential(&headers, diport::TokenProfile::RssAccess).map(|_| ()),
            Err(BearerCredentialError::TooLarge)
        );
    }

    #[test]
    fn service_bearer_credential_requires_exact_one_canonical_tenant_header() {
        let base = bearer_headers(axum::http::HeaderValue::from_static("Bearer service.token"));
        assert_eq!(
            extract_bearer_credential(&base, diport::TokenProfile::ServiceToken).map(|_| ()),
            Err(BearerCredentialError::Malformed)
        );

        for second in [TEST_TENANT, "11111111-1111-4111-8111-111111111111"] {
            let mut headers = base.clone();
            headers.append(
                diport::SERVICE_TOKEN_TENANT_HEADER,
                axum::http::HeaderValue::from_static(TEST_TENANT),
            );
            headers.append(
                diport::SERVICE_TOKEN_TENANT_HEADER,
                axum::http::HeaderValue::from_static(second),
            );
            assert_eq!(
                extract_bearer_credential(&headers, diport::TokenProfile::ServiceToken).map(|_| ()),
                Err(BearerCredentialError::Duplicate)
            );
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn exact_tenant_header_rejects_duplicate_oversized_and_non_utf8_values() {
        let mut duplicate = HeaderMap::new();
        duplicate.append(
            "x-tenant-id",
            axum::http::HeaderValue::from_static(TEST_TENANT),
        );
        duplicate.append(
            "x-tenant-id",
            axum::http::HeaderValue::from_static(TEST_TENANT),
        );
        assert_eq!(
            exact_tenant_header(&duplicate, "x-tenant-id"),
            Err(TenantHeaderError::Duplicate)
        );

        let oversized = bearer_headers(axum::http::HeaderValue::from_static("Bearer token"));
        let mut oversized = oversized;
        oversized.insert(
            "x-tenant-id",
            axum::http::HeaderValue::from_str(&"a".repeat(37)).expect("valid header bytes"),
        );
        assert_eq!(
            exact_tenant_header(&oversized, "x-tenant-id"),
            Err(TenantHeaderError::Malformed)
        );

        let mut non_utf8 = HeaderMap::new();
        non_utf8.insert(
            "x-tenant-id",
            axum::http::HeaderValue::from_bytes(&[0x80; 36]).expect("HTTP permits obs-text bytes"),
        );
        assert_eq!(
            exact_tenant_header(&non_utf8, "x-tenant-id"),
            Err(TenantHeaderError::Malformed)
        );
    }

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

    fn authed(scheme: NonRssTestScheme, kind: PrincipalKind) -> Authenticated {
        Authenticated::new(scheme, kind, "principal-1", Some(tenant()))
    }

    fn rss_user_authed() -> Authenticated {
        Authenticated::new_rss_user_for_test("principal-1", tenant())
    }

    fn reject_matrix_authed(kind: RssAccessRejectMatrixKind) -> Authenticated {
        Authenticated::new_for_evidence_reject_matrix(kind, "principal-1", Some(tenant()))
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
        let evidence = Authenticated::new_for_evidence_reject_matrix(
            RssAccessRejectMatrixKind::Admin,
            "principal-1",
            Some(tenant()),
        );

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
        assert_eq!(subject.contract_id(), TEST_CONTRACT);
        assert_eq!(subject.permission(), vocab::AUDIT_READ_PERMISSION);
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
                RouteWriteAdmission::ReadOnly,
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
    fn build_counted_router_with_audit(
        plan: Option<AuthPlan>,
        sink: RecordingAuditSink,
        handler_calls: Arc<AtomicUsize>,
    ) -> Router {
        let mut router = Router::new()
            .route(
                "/test",
                get(move || {
                    let handler_calls = Arc::clone(&handler_calls);
                    async move {
                        handler_calls.fetch_add(1, Ordering::SeqCst);
                        "ok"
                    }
                })
                .layer(enforce_layer(
                    None,
                    Method::GET,
                    TEST_EVIDENCE,
                    RouteWriteAdmission::ReadOnly,
                )),
            )
            .layer(Extension(audit_ext(sink)));
        if let Some(plan) = plan {
            router = router.layer(Extension(plan));
        }
        router
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
    async fn write_admission_runs_after_auth_and_blocks_handler_while_paused() {
        let (control, _, _, writes) = primitives::prepare_dr_admission_controls().into_parts();
        let epoch = primitives::AdmissionEpochId::new(uuid::Uuid::new_v4()).unwrap();
        control.pause_all(epoch).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let handler_calls = Arc::clone(&calls);
        let router = Router::new().route(
            "/write",
            axum::routing::post(move || {
                let handler_calls = Arc::clone(&handler_calls);
                async move {
                    handler_calls.fetch_add(1, Ordering::SeqCst);
                    "ok"
                }
            })
            .layer(enforce_layer(
                Some(PrimaryRouteAuthz::OptOut(RouteAuthOptOut::Public)),
                Method::POST,
                TEST_WRITE_EVIDENCE,
                RouteWriteAdmission::Mutation(writes),
            )),
        );

        let unauthenticated = Request::builder()
            .method(Method::POST)
            .uri("/write")
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(unauthenticated).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let authenticated = Request::builder()
            .method(Method::POST)
            .uri("/write")
            .body(Body::empty())
            .unwrap();
        let response = router
            .layer(Extension(
                AuthPlan::new(ListenerKind::Primary, AuthScheme::RssAccessToken).unwrap(),
            ))
            .oneshot(authenticated)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn public_opt_out_with_jwt_plan_is_200() {
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::RssAccessToken).unwrap();
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
    async fn inventory_auth_require_without_auth_header_is_401() {
        let handler_calls = Arc::new(AtomicUsize::new(0));
        let sink = RecordingAuditSink::new();
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::RssAccessToken).unwrap();
        let router =
            build_counted_router_with_audit(Some(plan), sink.clone(), Arc::clone(&handler_calls));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(handler_calls.load(Ordering::SeqCst), 0);
        assert!(sink.events().is_empty());
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn require_with_authenticated_evidence_is_200() {
        // AUTH-EVIDENCE-REQUIRE-01：Require(RssAccessToken) + 请求携 Authenticated 证据 → 放行 200。
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::RssAccessToken).unwrap();
        let router = build_router(None, Some(plan));
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        // 验签桥范式：外层 layer 校验通过后注入证据；此处直接 insert 模拟该接缝。
        req.extensions_mut().insert(rss_user_authed());
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn require_with_mismatched_scheme_is_401() {
        // AUTH-EVIDENCE-REQUIRE-01 scheme exact-match：Require(RssAccessToken) 路由 + Mtls 方案证据 → scheme 不匹配 → 401。
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::RssAccessToken).unwrap();
        let router = build_router(None, Some(plan));
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(authed(NonRssTestScheme::Mtls, PrincipalKind::User));
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn require_with_anonymous_evidence_is_401() {
        // AUTH-EVIDENCE-REQUIRE-01 fail-closed 防御纵深：`Anonymous` 证据视同无证据 → 仍 401。
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::RssAccessToken).unwrap();
        let router = build_router(None, Some(plan));
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(reject_matrix_authed(RssAccessRejectMatrixKind::Anonymous));
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn require_with_rss_access_token_non_user_evidence_is_401() {
        // AUTH-EVIDENCE-REQUIRE-01 Medium：RssAccessToken + non-User 证据不计入放行 → 401。
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::RssAccessToken).unwrap();
        let router = build_router(None, Some(plan));
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(reject_matrix_authed(RssAccessRejectMatrixKind::Admin));
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
        req.extensions_mut().insert(rss_user_authed());
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn inventory_auth_allow_records_success_audit_event() {
        let handler_calls = Arc::new(AtomicUsize::new(0));
        let sink = RecordingAuditSink::new();
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::RssAccessToken).unwrap();
        let router =
            build_counted_router_with_audit(Some(plan), sink.clone(), Arc::clone(&handler_calls));
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(rss_user_authed());
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(handler_calls.load(Ordering::SeqCst), 1);

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
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::RssAccessToken).unwrap();
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
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::RssAccessToken).unwrap();
        let router = build_router_with_audit(None, Some(plan), sink.clone());
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        // Tenantless RSS User ambient/authz success-edge — not reject-matrix.
        req.extensions_mut()
            .insert(Authenticated::new_rss_user_tenantless_for_test(
                "platform-principal-1",
            ));
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].principal_id, "platform-principal-1");
        assert_eq!(events[0].principal_kind, PrincipalKind::User);
        assert_eq!(events[0].tenant_id, None);
        assert_eq!(events[0].outcome, AuditOutcome::Success);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn require_scheme_mismatch_records_unauthorized_audit_event() {
        let sink = RecordingAuditSink::new();
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::RssAccessToken).unwrap();
        let router = build_router_with_audit(None, Some(plan), sink.clone());
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(authed(NonRssTestScheme::Mtls, PrincipalKind::User));
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
    async fn inventory_auth_deny_with_evidence_records_forbidden_audit_event() {
        let handler_calls = Arc::new(AtomicUsize::new(0));
        let sink = RecordingAuditSink::new();
        let router =
            build_counted_router_with_audit(None, sink.clone(), Arc::clone(&handler_calls));
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(rss_user_authed());
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(handler_calls.load(Ordering::SeqCst), 0);

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
    async fn inventory_auth_allow_audit_failure_skips_handler_and_success_runs_it_once() {
        let handler_calls = Arc::new(AtomicUsize::new(0));
        let sink = RecordingAuditSink::failing();
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::RssAccessToken).unwrap();
        let router = build_counted_router_with_audit(Some(plan), sink, Arc::clone(&handler_calls));
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(rss_user_authed());
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(handler_calls.load(Ordering::SeqCst), 0);

        let sink = RecordingAuditSink::new();
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::RssAccessToken).unwrap();
        let router = build_counted_router_with_audit(Some(plan), sink, Arc::clone(&handler_calls));
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(rss_user_authed());
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(handler_calls.load(Ordering::SeqCst), 1);
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
        req.extensions_mut().insert(rss_user_authed());
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn require_with_auth_header_is_fail_closed_401() {
        // fail-closed：httpserve 不验签——裸 Authorization header 非证据，仅请求携 Authenticated
        // extension（验签桥注入）才放行，故带 header 仍 401。
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::RssAccessToken).unwrap();
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
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::RssAccessToken).unwrap();
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
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::RssAccessToken).unwrap();
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
