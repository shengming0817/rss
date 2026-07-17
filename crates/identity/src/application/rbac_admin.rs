//! RBAC 角色管理应用服务（#1190 US5）——角色分配 / 撤销编排 + L2 OutboxFact 角色事件发布。
//!
//! [`RbacAdminService`] 经注入的 [`RoleReadRepo`](crate::ports::RoleReadRepo)（校验角色存在）+
//! [`RoleBindingLifecycle`](crate::ports::RoleBindingLifecycle)（binding co-tx 写 + 角色事件 outbox 同事务）
//! 落角色绑定，并在同一本地事务发布 `identity.role-{assigned,revoked}`（L2，事件 draft——audit 消费延 #1017）。
//!
//! 必填依赖走构造器位置参（缺失即编译错误，rust-standards §工程护栏）；`Clock` 位置参注入（禁系统时钟）。
//! 错误为库错误枚举（const-literal message，不返回 HTTP 状态码——handler 层映射，error-handling.md）。
//!
//! ref: casbin/casbin-rs src/rbac/default_role_manager.rs@master（RBAC-with-domains：binding = subject+role+tenant
//! 三元组，对齐 `g(r.sub,p.sub,r.dom)` 多租隔离）

use std::sync::Arc;

use consistency::{EventEntry, EventTopic, IdemKey, OutboxPayload};
use diport::{
    Clock, EnvelopeSubjectId, OpaqueActorId, OutboxActor, OutboxEmitError, OutboxEnvelopeParts,
};
use generated::event::identity_v1::role_assigned::{
    IdentityRoleAssignedPayload, IdentityRoleAssignedPayloadActorKind, SPEC as ROLE_ASSIGNED_SPEC,
};
use generated::event::identity_v1::role_revoked::{
    IdentityRoleRevokedPayload, IdentityRoleRevokedPayloadActorKind, SPEC as ROLE_REVOKED_SPEC,
};
use uuid::Uuid;
use vocab::TenantId;

use super::unix_secs;
use crate::domain::{IdentityError, RoleBinding, RoleId};
use crate::ports::{
    DynRoleBindingLifecycle, DynRoleReadRepo, RoleBindingLifecycle, RoleReadRepo,
    RolesAssignProducerReceipt, RolesRevokeProducerReceipt, TenantRepoScope,
};

/// 发布域（tracing span 标签）。从契约绑定单源派生（= contract.toml `domain`，两 role 事件同域 `identity`）。
const RBAC_DOMAIN: &str = ROLE_ASSIGNED_SPEC.contract().domain();

/// 角色管理失败。库错误枚举（const-literal message；handler 层映射状态码）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RbacAdminError {
    /// 目标角色不存在（assign 前置校验失败）。
    #[error("role not found")]
    RoleNotFound,
    /// 角色仓储查询失败（RoleReadRepo 错误通道）。
    #[error("role lookup failed")]
    RoleLookup(#[source] IdentityError),
    /// 角色事件 payload 编码失败（原始错误进 source，不进 Display）。
    #[error("role-event payload encode failed")]
    PayloadEncode(#[source] serde_json::Error),
    /// outbox entry 构造失败（topic / event-id 非法——系统生成值，理论不可达，fail-closed）。
    #[error("role-event outbox entry build failed")]
    EntryBuild,
    /// binding 写 + outbox append 的 **co-tx** 写失败（原始错误进 source，已 PII-redacted，不进 Display）。
    #[error("role binding co-tx write failed")]
    BindingWrite(#[source] OutboxEmitError),
}

/// RBAC 角色管理应用服务。必填依赖走构造器位置参（缺失即编译错误）。
///
/// 注入形态 `Arc<DynRoleReadRepo>` + `Arc<DynRoleBindingLifecycle>`：域形端口基 trait 为 `Send + Sync`，使本
/// service 可作 axum handler 共享 state（PR5b），且 `assign_role`/`revoke_role` future 为 `Send`。
pub struct RbacAdminService {
    roles: Arc<DynRoleReadRepo<'static>>,
    bindings: Arc<DynRoleBindingLifecycle<'static>>,
    clock: Box<dyn Clock>,
}

impl RbacAdminService {
    /// 组合根构造：3 必填依赖位置参（缺失即编译错误）。`clock` 位置参注入（禁系统时钟）。
    pub fn new(
        roles: Arc<DynRoleReadRepo<'static>>,
        bindings: Arc<DynRoleBindingLifecycle<'static>>,
        clock: Box<dyn Clock>,
    ) -> Self {
        Self {
            roles,
            bindings,
            clock,
        }
    }

    /// **角色分配（L2）**：校验角色存在 → 构 [`RoleBinding`] + `identity.role-assigned` outbox entry →
    /// co-tx 落 binding + 发事件（both-or-neither）。跨租 find→None ⇒ `RoleNotFound`（不泄露存在性）。
    ///
    /// `actor` = 执行本次分配的**操作者**（authenticated principal，opaque 规范 UUID）；`subject` = 被授予
    /// 角色的**目标主体**。两者分离（data-model.md `assignedBy`）：payload 同时携 `assigned_by`(actor) 与
    /// `subject`(target)，envelope `subject_id` 取 **actor opaque id**（FR-020 非 PII originator），不写 target。
    ///
    /// `skip_all` 略过 `subject`(PII) / `role_id` / `actor`；审计归因走 audit/event payload 与 persisted-only
    /// outbox actor，不把 actor opaque id 写入默认 tracing span。
    #[tracing::instrument(
        skip_all,
        fields(domain = RBAC_DOMAIN, operation = "assign_role", tenant_id = %tenant),
        err
    )]
    pub async fn assign_role(
        &self,
        receipt: RolesAssignProducerReceipt,
        tenant: TenantId,
        actor: ids::UserId,
        actor_kind: vocab::PrincipalKind,
        subject: String,
        role_id: RoleId,
    ) -> Result<(), RbacAdminError> {
        let tenant_scope = TenantRepoScope::from_authenticated_tenant(tenant);
        // 1. 角色存在校验（跨租 find→None ⇒ 同 RoleNotFound，不区分以免存在性泄露）。
        if self
            .roles
            .find(tenant_scope, role_id.clone())
            .await
            .map_err(RbacAdminError::RoleLookup)?
            .is_none()
        {
            return Err(RbacAdminError::RoleNotFound);
        }

        // 2. 构 payload（generated DTO）：assigned_by = actor 规范 UUID；subject = 目标主体（PII redacted）。
        let now = self.clock.now();
        let payload = IdentityRoleAssignedPayload {
            role_id: role_id.as_str().to_string(),
            subject: subject.clone(),
            assigned_by: actor.as_uuid(),
            actor_kind: role_assigned_actor_kind_wire(actor_kind)?,
            tenant_id: tenant.to_string(),
            occurred_at: unix_secs(now),
        };
        let bytes = serde_json::to_vec(&payload).map_err(RbacAdminError::PayloadEncode)?;
        let entry = EventEntry::new(
            EventTopic::parse(ROLE_ASSIGNED_SPEC.topic())
                .map_err(|_| RbacAdminError::EntryBuild)?,
            IdemKey::parse(&Uuid::new_v4().to_string()).map_err(|_| RbacAdminError::EntryBuild)?,
            OutboxPayload::from_reviewed_event_bytes(bytes),
        );
        // envelope subject_id = **actor** opaque id（FR-020 非 PII originator），非 target subject（F2）。
        let actor_subject = actor.as_uuid().hyphenated().to_string();
        let subject_id = EnvelopeSubjectId::from_opaque(actor_subject.clone())
            .map_err(|_| RbacAdminError::EntryBuild)?;
        let actor = OutboxActor::scoped(
            actor_kind,
            OpaqueActorId::from_opaque(actor_subject).map_err(|_| RbacAdminError::EntryBuild)?,
            tenant,
            vocab::ScopedTenant::Tenant,
        );
        let envelope =
            OutboxEnvelopeParts::new(ROLE_ASSIGNED_SPEC.contract(), tenant, subject_id, actor);

        // 3. L2 co-tx（binding 行 + outbox 行同一事务原子写入）。
        let binding = RoleBinding::new(subject, role_id, tenant);
        self.bindings
            .assign_and_emit(receipt, tenant_scope, binding, entry, envelope)
            .await
            .map_err(RbacAdminError::BindingWrite)
    }

    /// **角色撤销（L2）**：仅撤目标 binding（`(tenant, role_id, subject)` 键）+ 发 `identity.role-revoked`
    /// （co-tx）。命中返回 `Ok(true)`；未命中（不存在 / 跨租）→ `Ok(false)`（不发事件、隐藏存在性、幂等）。
    ///
    /// `actor` = 执行撤销的操作者（opaque 规范 UUID）；`subject` = 被撤角色的目标主体。两者分离
    /// （data-model.md `revokedBy`）：payload 携 `revoked_by`(actor) + `subject`(target)，envelope `subject_id`
    /// 取 **actor opaque id**（FR-020），不写 target。
    ///
    /// `skip_all` 略过 `subject`(PII) / `role_id` / `actor`；审计归因走 audit/event payload 与 persisted-only
    /// outbox actor，不把 actor opaque id 写入默认 tracing span。
    #[tracing::instrument(
        skip_all,
        fields(domain = RBAC_DOMAIN, operation = "revoke_role", tenant_id = %tenant),
        err
    )]
    pub async fn revoke_role(
        &self,
        receipt: RolesRevokeProducerReceipt,
        tenant: TenantId,
        actor: ids::UserId,
        actor_kind: vocab::PrincipalKind,
        role_id: RoleId,
        subject: String,
    ) -> Result<bool, RbacAdminError> {
        let tenant_scope = TenantRepoScope::from_authenticated_tenant(tenant);
        let now = self.clock.now();
        let payload = IdentityRoleRevokedPayload {
            role_id: role_id.as_str().to_string(),
            subject: subject.clone(),
            revoked_by: actor.as_uuid(),
            actor_kind: role_revoked_actor_kind_wire(actor_kind)?,
            tenant_id: tenant.to_string(),
            occurred_at: unix_secs(now),
        };
        let bytes = serde_json::to_vec(&payload).map_err(RbacAdminError::PayloadEncode)?;
        let entry = EventEntry::new(
            EventTopic::parse(ROLE_REVOKED_SPEC.topic()).map_err(|_| RbacAdminError::EntryBuild)?,
            IdemKey::parse(&Uuid::new_v4().to_string()).map_err(|_| RbacAdminError::EntryBuild)?,
            OutboxPayload::from_reviewed_event_bytes(bytes),
        );
        // envelope subject_id = **actor** opaque id（FR-020），非 target subject（F2）。
        let actor_subject = actor.as_uuid().hyphenated().to_string();
        let subject_id = EnvelopeSubjectId::from_opaque(actor_subject.clone())
            .map_err(|_| RbacAdminError::EntryBuild)?;
        let actor = OutboxActor::scoped(
            actor_kind,
            OpaqueActorId::from_opaque(actor_subject).map_err(|_| RbacAdminError::EntryBuild)?,
            tenant,
            vocab::ScopedTenant::Tenant,
        );
        let envelope =
            OutboxEnvelopeParts::new(ROLE_REVOKED_SPEC.contract(), tenant, subject_id, actor);

        self.bindings
            .revoke_and_emit(receipt, tenant_scope, role_id, subject, entry, envelope)
            .await
            .map_err(RbacAdminError::BindingWrite)
    }
}

fn role_assigned_actor_kind_wire(
    kind: vocab::PrincipalKind,
) -> Result<IdentityRoleAssignedPayloadActorKind, RbacAdminError> {
    match kind {
        vocab::PrincipalKind::User => Ok(IdentityRoleAssignedPayloadActorKind::User),
        vocab::PrincipalKind::Device => Ok(IdentityRoleAssignedPayloadActorKind::Device),
        vocab::PrincipalKind::Admin => Ok(IdentityRoleAssignedPayloadActorKind::Admin),
        vocab::PrincipalKind::SuperAdmin => Ok(IdentityRoleAssignedPayloadActorKind::SuperAdmin),
        vocab::PrincipalKind::Service => Ok(IdentityRoleAssignedPayloadActorKind::Service),
        vocab::PrincipalKind::Anonymous => Ok(IdentityRoleAssignedPayloadActorKind::Anonymous),
        _ => Err(RbacAdminError::EntryBuild),
    }
}

fn role_revoked_actor_kind_wire(
    kind: vocab::PrincipalKind,
) -> Result<IdentityRoleRevokedPayloadActorKind, RbacAdminError> {
    match kind {
        vocab::PrincipalKind::User => Ok(IdentityRoleRevokedPayloadActorKind::User),
        vocab::PrincipalKind::Device => Ok(IdentityRoleRevokedPayloadActorKind::Device),
        vocab::PrincipalKind::Admin => Ok(IdentityRoleRevokedPayloadActorKind::Admin),
        vocab::PrincipalKind::SuperAdmin => Ok(IdentityRoleRevokedPayloadActorKind::SuperAdmin),
        vocab::PrincipalKind::Service => Ok(IdentityRoleRevokedPayloadActorKind::Service),
        vocab::PrincipalKind::Anonymous => Ok(IdentityRoleRevokedPayloadActorKind::Anonymous),
        _ => Err(RbacAdminError::EntryBuild),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::internal::mem::{InMemRoleBindingLifecycle, InMemRoleRepo};
    use crate::ports::{DynRoleBindingLifecycle, DynRoleReadRepo};
    use generated::http::identity_v1::{
        roles_assign::PRODUCER as ROLES_ASSIGN_PRODUCER,
        roles_revoke::PRODUCER as ROLES_REVOKE_PRODUCER,
    };
    use httpserve::ProducerMarker;

    const TENANT_A: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const TENANT_B: &str = "00000000-0000-4000-8000-000000000001";

    struct FixedClock(SystemTime);
    impl Clock for FixedClock {
        fn now(&self) -> SystemTime {
            self.0
        }
    }

    // reason: 测试断言用 expect 暴露失败因（item-level carve-out，error-handling.md §Carve-out 禁 module-level）。
    #[allow(clippy::expect_used)]
    fn tid(raw: &str) -> TenantId {
        TenantId::parse(raw).expect("canonical tenant parses")
    }

    fn role(raw: &str) -> RoleId {
        RoleId::new(raw.to_string())
    }

    fn assign_receipt() -> RolesAssignProducerReceipt {
        ProducerMarker::for_test(ROLES_ASSIGN_PRODUCER).into_receipt()
    }

    fn revoke_receipt() -> RolesRevokeProducerReceipt {
        ProducerMarker::for_test(ROLES_REVOKE_PRODUCER).into_receipt()
    }

    /// 固定操作者（authenticated principal，opaque 规范 UUID）——与 target subject 区分。
    fn actor() -> ids::UserId {
        ids::UserId::new(uuid::Uuid::from_u128(0xACC0))
    }

    /// 操作者在 envelope `subject_id` 的期望形（hyphenated UUID，opaque originator）。
    fn actor_subject_id() -> String {
        actor().as_uuid().hyphenated().to_string()
    }

    fn clock() -> Box<dyn Clock> {
        Box::new(FixedClock(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        ))
    }

    /// 构造 service + 返回 binding 替身探针（共享 Arc 存储，供 emit / binding 断言）。
    fn service_with(
        repo: InMemRoleRepo,
        bindings: InMemRoleBindingLifecycle,
    ) -> (RbacAdminService, InMemRoleBindingLifecycle) {
        let probe = bindings.clone();
        let svc = RbacAdminService::new(
            Arc::from(DynRoleReadRepo::new_box(repo)),
            Arc::from(DynRoleBindingLifecycle::new_box(bindings)),
            clock(),
        );
        (svc, probe)
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn assign_persists_binding_and_emits_one_role_assigned() {
        let t = tid(TENANT_A);
        let r = role("admin");
        let (svc, probe) = service_with(
            InMemRoleRepo::new().with_role(t, &r),
            InMemRoleBindingLifecycle::new(),
        );

        svc.assign_role(
            assign_receipt(),
            t,
            actor(),
            vocab::PrincipalKind::Admin,
            "alice".to_string(),
            r.clone(),
        )
        .await
        .expect("assign ok");

        assert!(probe.has_binding(t, &r, "alice"), "binding 应落地");
        let emitted = probe.emitted();
        assert_eq!(emitted.len(), 1, "应恰发一条事件");
        assert_eq!(emitted[0].topic, "identity.role-assigned", "topic 不符");
        let payload: IdentityRoleAssignedPayload =
            serde_json::from_slice(&emitted[0].payload).expect("payload 解码");
        assert_eq!(payload.role_id, "admin");
        assert_eq!(payload.subject, "alice", "payload 携 target subject");
        assert_eq!(
            payload.assigned_by,
            actor().as_uuid(),
            "payload assigned_by = actor"
        );
        assert_eq!(
            payload.actor_kind,
            IdentityRoleAssignedPayloadActorKind::Admin,
            "payload actorKind = authenticated actor kind"
        );
        assert_eq!(payload.tenant_id, t.to_string());
        // envelope（F2/F3）：contract 绑定 + 租户 scope + subject_id = **actor opaque id**（非 target，FR-020）。
        assert_eq!(emitted[0].contract_id, "identity.role-assigned");
        assert_eq!(emitted[0].env_tenant, t.to_string());
        assert_eq!(
            emitted[0].subject_id,
            actor_subject_id(),
            "envelope subject_id 须是 actor opaque id"
        );
        assert_ne!(
            emitted[0].subject_id, "alice",
            "envelope 不得写 target subject（FR-020 opaque originator）"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn assign_unknown_role_errors_and_emits_nothing() {
        let t = tid(TENANT_A);
        // repo 空 ⇒ 角色不存在。
        let (svc, probe) = service_with(InMemRoleRepo::new(), InMemRoleBindingLifecycle::new());

        let err = svc
            .assign_role(
                assign_receipt(),
                t,
                actor(),
                vocab::PrincipalKind::Admin,
                "alice".to_string(),
                role("ghost"),
            )
            .await
            .expect_err("未知角色应失败");
        assert!(matches!(err, RbacAdminError::RoleNotFound));
        assert!(probe.emitted().is_empty(), "错误路径不发事件");
        assert!(
            !probe.has_binding(t, &role("ghost"), "alice"),
            "不落 binding"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn assign_cross_tenant_hides_existence() {
        // 安全配对（IDENTITY-AUTHZ-TENANT-01 assign 分支）：角色属 tenant A，tenant B 调 assign → 跨租
        // find→None ⇒ RoleNotFound（不区分「不存在」与「跨租」，隐藏存在性）+ 不落 binding + 不发事件。
        let t_a = tid(TENANT_A);
        let t_b = tid(TENANT_B);
        let r = role("admin");
        let (svc, probe) = service_with(
            InMemRoleRepo::new().with_role(t_a, &r),
            InMemRoleBindingLifecycle::new(),
        );

        let err = svc
            .assign_role(
                assign_receipt(),
                t_b,
                actor(),
                vocab::PrincipalKind::Admin,
                "alice".to_string(),
                r.clone(),
            )
            .await
            .expect_err("跨租角色应 RoleNotFound（隐藏存在性）");
        assert!(matches!(err, RbacAdminError::RoleNotFound));
        assert!(!probe.has_binding(t_b, &r, "alice"), "跨租不落 binding");
        assert!(probe.emitted().is_empty(), "跨租不发事件");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn assign_cotx_failure_persists_nothing(/* L2 原子性 */) {
        let t = tid(TENANT_A);
        let r = role("admin");
        let (svc, probe) = service_with(
            InMemRoleRepo::new().with_role(t, &r),
            InMemRoleBindingLifecycle::failing(),
        );

        let err = svc
            .assign_role(
                assign_receipt(),
                t,
                actor(),
                vocab::PrincipalKind::Admin,
                "alice".to_string(),
                r.clone(),
            )
            .await
            .expect_err("co-tx 写失败应冒泡");
        assert!(matches!(err, RbacAdminError::BindingWrite(_)));
        assert!(
            !probe.has_binding(t, &r, "alice"),
            "失败 ⇒ binding 不落（both-or-neither）"
        );
        assert!(probe.emitted().is_empty(), "失败 ⇒ 事件不记");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn revoke_existing_binding_removes_and_emits_role_revoked() {
        let t = tid(TENANT_A);
        let r = role("admin");
        let (svc, probe) = service_with(
            InMemRoleRepo::new(),
            InMemRoleBindingLifecycle::new().with_binding(t, &r, "alice"),
        );

        let revoked = svc
            .revoke_role(
                revoke_receipt(),
                t,
                actor(),
                vocab::PrincipalKind::Admin,
                r.clone(),
                "alice".to_string(),
            )
            .await
            .expect("revoke ok");

        assert!(revoked, "命中应返回 true");
        assert!(!probe.has_binding(t, &r, "alice"), "binding 应被撤");
        let emitted = probe.emitted();
        assert_eq!(emitted.len(), 1);
        assert_eq!(emitted[0].topic, "identity.role-revoked");
        let payload: IdentityRoleRevokedPayload =
            serde_json::from_slice(&emitted[0].payload).expect("payload 解码");
        assert_eq!(payload.subject, "alice", "role-revoked 须含 target subject");
        assert_eq!(
            payload.revoked_by,
            actor().as_uuid(),
            "payload revoked_by = actor"
        );
        assert_eq!(
            payload.actor_kind,
            IdentityRoleRevokedPayloadActorKind::Admin,
            "payload actorKind = authenticated actor kind"
        );
        // envelope（F2/F3）：contract 绑定 + subject_id = actor opaque id（非 target）。
        assert_eq!(emitted[0].contract_id, "identity.role-revoked");
        assert_eq!(
            emitted[0].subject_id,
            actor_subject_id(),
            "envelope subject_id 须是 actor opaque id（非 target）"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn revoke_cross_tenant_is_noop_and_hides_existence() {
        let t_a = tid(TENANT_A);
        let t_b = tid(TENANT_B);
        let r = role("admin");
        // binding 属 tenant A；tenant B 尝试撤销。
        let (svc, probe) = service_with(
            InMemRoleRepo::new(),
            InMemRoleBindingLifecycle::new().with_binding(t_a, &r, "alice"),
        );

        let revoked = svc
            .revoke_role(
                revoke_receipt(),
                t_b,
                actor(),
                vocab::PrincipalKind::Admin,
                r.clone(),
                "alice".to_string(),
            )
            .await
            .expect("revoke ok");

        assert!(!revoked, "跨租未命中应返回 false（隐藏存在性）");
        assert!(
            probe.has_binding(t_a, &r, "alice"),
            "tenant A 的 binding 不受影响"
        );
        assert!(probe.emitted().is_empty(), "未命中不发事件");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn revoke_cotx_failure_binding_remains_and_emits_nothing() {
        // L2 原子性对称（assign_cotx_failure 的 revoke 侧）：命中 binding 但 co-tx 写失败 ⇒ both-or-neither：
        // binding 仍在、事件不记，错误冒泡 BindingWrite。
        let t = tid(TENANT_A);
        let r = role("admin");
        let (svc, probe) = service_with(
            InMemRoleRepo::new(),
            InMemRoleBindingLifecycle::failing().with_binding(t, &r, "alice"),
        );

        let err = svc
            .revoke_role(
                revoke_receipt(),
                t,
                actor(),
                vocab::PrincipalKind::Admin,
                r.clone(),
                "alice".to_string(),
            )
            .await
            .expect_err("co-tx 写失败应冒泡");
        assert!(matches!(err, RbacAdminError::BindingWrite(_)));
        assert!(
            probe.has_binding(t, &r, "alice"),
            "失败 ⇒ binding 不撤（both-or-neither）"
        );
        assert!(probe.emitted().is_empty(), "失败 ⇒ 事件不记");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn assigns_mint_distinct_event_ids() {
        // **同一 (tenant, subject, role)** 连续两次 assign：payload 字节相同（occurredAt 固定 clock + 同字段），
        // 故 IdemKey/EventId 独立性**只能**由捕获的 idem_key 不同来证明（anti-vacuity：若 build_entry 用常量
        // EventId 则两 idem_key 相同、断言失败）。
        let t = tid(TENANT_A);
        let r = role("admin");
        let (svc, probe) = service_with(
            InMemRoleRepo::new().with_role(t, &r),
            InMemRoleBindingLifecycle::new(),
        );

        svc.assign_role(
            assign_receipt(),
            t,
            actor(),
            vocab::PrincipalKind::Admin,
            "alice".to_string(),
            r.clone(),
        )
        .await
        .expect("assign 1");
        svc.assign_role(
            assign_receipt(),
            t,
            actor(),
            vocab::PrincipalKind::Admin,
            "alice".to_string(),
            r.clone(),
        )
        .await
        .expect("assign 2");

        let emitted = probe.emitted();
        assert_eq!(emitted.len(), 2);
        assert_eq!(
            emitted[0].payload, emitted[1].payload,
            "同 subject/role/clock ⇒ payload 字节相同（隔离 EventId 维度）"
        );
        assert_ne!(
            emitted[0].idem_key, emitted[1].idem_key,
            "EventId/IdemKey 须每事件独立 mint（非复用业务键）"
        );
    }
}
