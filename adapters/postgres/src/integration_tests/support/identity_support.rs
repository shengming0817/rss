use super::*;

// ── AuthGrant login root: grant + initial refresh + outbox one transaction ─────

pub(in super::super) use std::time::{Duration, SystemTime};

pub(in super::super) use diport::OutboxEnvelopeParts;

pub(in super::super) use identity::ports::{
    AccountSecuritySnapshot, AuthGrantLifecycle, AuthGrantValidator, IdentityError,
    IdentitySecurityLifecycle, LoginGrantMutation, RefreshTokenStore,
};
pub(in super::super) use rss_request_context::TenantId;

pub(in super::super) async fn seed_auth_grant_account(
    store: &PgStore,
    tenant: rss_request_context::TenantId,
    user_id: ids::UserId,
) -> Result<(), sqlx::Error> {
    let tenant = tenant.to_string();
    let user = user_id.as_uuid().to_string();
    let mut tx = store.pool.begin().await?;
    sqlx::query(
        "INSERT INTO credentials \
         (tenant_id, user_id, login, password_hash, version) \
         VALUES ($1::uuid, $2::uuid, $3, 'auth-grant-test-phc-not-used', 1)",
    )
    .bind(&tenant)
    .bind(&user)
    .bind(format!("auth-grant-{user}"))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO account_security_states \
         (tenant_id, user_id, status, authn_epoch, version, status_changed_at, updated_at) \
         VALUES ($1::uuid, $2::uuid, 'active', 0, 1, to_timestamp($3), to_timestamp($3))",
    )
    .bind(&tenant)
    .bind(&user)
    .bind(i64::try_from(TEST_OCCURRED_SECS).expect("test timestamp fits PostgreSQL bigint"))
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

pub(in super::super) fn auth_grant_fixture(
    tenant: rss_request_context::TenantId,
    user_id: ids::UserId,
    grant_id: &str,
    refresh_id: &str,
    hash: [u8; 32],
) -> (AuthGrant, identity::ports::RefreshTokenRecord) {
    let created = SystemTime::UNIX_EPOCH + Duration::from_secs(TEST_OCCURRED_SECS);
    let grant = identity::test_support::auth_grant(
        grant_id,
        user_id,
        tenant,
        created,
        AuthnEpoch::ZERO,
        created + Duration::from_secs(3_600),
        created,
    );
    let refresh = identity::test_support::initial_refresh(
        &grant,
        refresh_id,
        hash,
        created,
        created + Duration::from_secs(3_600),
    );
    (grant, refresh)
}

#[derive(Clone)]
pub(in super::super) struct RefreshProducerCase {
    pub(in super::super) tenant: rss_request_context::TenantId,
    pub(in super::super) user_id: ids::UserId,
    pub(in super::super) grant: AuthGrant,
    pub(in super::super) old: identity::ports::RefreshTokenRecord,
    pub(in super::super) rotation: identity::ports::RefreshRotation,
}

impl RefreshProducerCase {
    #[allow(clippy::expect_used, reason = "generated UUID fixture is canonical")]
    pub(in super::super) fn new(tenant: rss_request_context::TenantId) -> Self {
        let issued = SystemTime::UNIX_EPOCH + Duration::from_secs(TEST_OCCURRED_SECS);
        let user_id = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())
            .expect("generated refresh user id must be valid");
        let grant = identity::test_support::auth_grant(
            &uuid::Uuid::new_v4().to_string(),
            user_id,
            tenant,
            issued,
            AuthnEpoch::ZERO,
            SystemTime::UNIX_EPOCH + Duration::from_secs(4_000_000_000),
            issued,
        );
        let mut old_hash = [0_u8; 32];
        old_hash[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        old_hash[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        let old = identity::test_support::initial_refresh(
            &grant,
            &uuid::Uuid::new_v4().to_string(),
            old_hash,
            issued,
            grant.expires_at(),
        );
        let mut next_hash = [0_u8; 32];
        next_hash[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        next_hash[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        let rotation = identity::test_support::refresh_rotation(
            &old,
            &uuid::Uuid::new_v4().to_string(),
            next_hash,
            issued + Duration::from_secs(1),
        );
        Self {
            tenant,
            user_id,
            grant,
            old,
            rotation,
        }
    }

    pub(in super::super) async fn seed(
        &self,
        app: &PgStore,
        owner: &PgStore,
    ) -> Result<(), TestError> {
        seed_auth_grant_account(owner, self.tenant, self.user_id).await?;
        let (mutation, entry, envelope) = auth_grant_login_parts(
            &unique_event_id("refresh-producer-seed"),
            self.grant.clone(),
            self.old.clone(),
        );
        let _ =
            crate::PgAuthGrantLifecycle::new(app, fixed_clock())
                .persist_login_grant(
                    login_producer_receipt(),
                    identity_scope(self.tenant),
                    mutation,
                    reviewed_generated_event::<
                        generated::event::identity_v1::session_created::Contract,
                    >(entry, envelope)
                    .await?,
                )
                .await?;
        Ok(())
    }

    pub(in super::super) fn rotation_command(&self) -> identity::ports::RefreshExecutionCommand {
        identity::test_support::refresh_rotation_command(
            self.old.clone(),
            self.grant.clone(),
            self.rotation.clone(),
            self.rotation.new_record().issued_at(),
        )
    }
}

pub(in super::super) async fn refresh_producer_snapshot(
    owner: &PgStore,
    case: &RefreshProducerCase,
) -> Result<(String, i64, i64, i64), sqlx::Error> {
    sqlx::query_as(
        "SELECT \
         (SELECT status FROM auth_grants WHERE tenant_id = $1::uuid AND grant_id = $2), \
         (SELECT count(*) FROM refresh_tokens \
          WHERE tenant_id = $1::uuid AND auth_grant_id = $2 AND status = 'active'), \
         (SELECT count(*) FROM refresh_tokens \
          WHERE tenant_id = $1::uuid AND auth_grant_id = $2 AND status <> 'revoked'), \
         (SELECT count(*) FROM outbox \
          WHERE tenant_id = $1::uuid AND contract_id = $3)",
    )
    .bind(case.tenant.to_string())
    .bind(case.grant.id().to_wire())
    .bind(identity::ports::SECURITY_EVENT_CONTRACT.contract_id())
    .fetch_one(&owner.pool)
    .await
}

pub(in super::super) struct AuthGrantValidationPdp(diport::VerifiedClaims);

impl diport::Pdp for AuthGrantValidationPdp {
    async fn verify(
        &self,
        _raw: &diport::RawCredential,
    ) -> Result<diport::VerifiedClaims, diport::PdpError> {
        Ok(self.0.clone())
    }
}

pub(in super::super) async fn auth_grant_validation_input(
    tenant: rss_request_context::TenantId,
    user_id: ids::UserId,
    grant_id: &str,
    auth_time: i64,
    authn_epoch: i64,
) -> Result<authn::AccessGrantValidationInput, TestError> {
    let grant = diport::VerifiedAccessGrantFacts::try_new(
        grant_id,
        uuid::Uuid::new_v4().to_string(),
        auth_time,
        authn_epoch,
    )?;
    let claims = diport::VerifiedClaims::rss_user(user_id, tenant, grant);
    let pdp = diport::DynPdp::new_box(AuthGrantValidationPdp(claims));
    let (verified, _principal) =
        authn::verify_rss_access("e30.eyJzdWIiOiJhdXRoLWdyYW50LXZhbGlkYXRvciJ9.c2ln", &pdp).await?;
    let receipt = verified
        .grant_receipt()
        .ok_or("RSS access fixture must carry an authentication grant")?;
    Ok(receipt.into_validation_input())
}

#[allow(clippy::expect_used)]
pub(in super::super) fn auth_grant_login_parts(
    event_id: &str,
    grant: AuthGrant,
    refresh: identity::ports::RefreshTokenRecord,
) -> (
    LoginGrantMutation,
    consistency::EventEntry,
    OutboxEnvelopeParts,
) {
    let occurred_at = i64::try_from(
        grant
            .created_at()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("test grant creation must follow the Unix epoch")
            .as_secs(),
    )
    .expect("test grant creation must fit the generated timestamp");
    let entry = generated_entry(
        generated::event::identity_v1::session_created::FACT,
        &generated::event::identity_v1::session_created::IdentitySessionCreatedPayload {
            session_id: grant.id().as_uuid(),
            subject: grant.user_id().as_uuid(),
            tenant_id: grant.tenant().as_uuid(),
            occurred_at,
        },
        IdemKey::parse(event_id).expect("test event id must be a valid idempotency key"),
    )
    .expect("generated session-created fixture must serialize");
    let envelope = OutboxEnvelopeParts::new(
        generated::event::identity_v1::session_created::CONTRACT,
        grant.tenant(),
        subject_id(&grant.user_id().as_uuid().to_string()),
        actor_for(grant.tenant()),
    );
    (
        LoginGrantMutation::for_test(grant, refresh),
        entry,
        envelope,
    )
}

pub(in super::super) async fn auth_grant_login_counts(
    store: &PgStore,
    grant_id: &str,
    refresh_id: &str,
    event_id: &str,
) -> Result<(i64, i64, i64), sqlx::Error> {
    sqlx::query_as(
        "SELECT \
         (SELECT count(*) FROM auth_grants WHERE grant_id = $1), \
         (SELECT count(*) FROM refresh_tokens WHERE id = $2::uuid), \
         (SELECT count(*) FROM outbox WHERE event_id = $3)",
    )
    .bind(grant_id)
    .bind(refresh_id)
    .bind(event_id)
    .fetch_one(&store.pool)
    .await
}

#[allow(clippy::too_many_arguments)]
pub(in super::super) async fn raw_refresh_insert(
    store: &PgStore,
    tenant: rss_request_context::TenantId,
    refresh_id: &str,
    grant_id: &str,
    user_id: ids::UserId,
    epoch: i64,
    grant_status: &str,
    hash_byte: u8,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    sqlx::query(
        "INSERT INTO refresh_tokens \
         (id, tenant_id, auth_grant_id, user_id, authn_epoch_at_issue, auth_grant_status, \
          token_hash, parent_id, lineage_id, status, issued_at, expires_at) \
         VALUES ($1::uuid, $2::uuid, $3, $4::uuid, $5, $6, $7, NULL, $1::uuid, \
                 'active', now(), now() + interval '1 hour')",
    )
    .bind(refresh_id)
    .bind(tenant.to_string())
    .bind(grant_id)
    .bind(user_id.as_uuid().to_string())
    .bind(epoch)
    .bind(grant_status)
    .bind(vec![hash_byte; 32])
    .execute(&store.pool)
    .await
}

// ───────────────────────────────────────────────────────────────────────────
// PgRoleRepo（identity 角色仓储）集成测试（#1250）：CRUD / upsert / tenant 行级隔离 / 并发收敛。
//
// 构造 `Role` 经 `Role::hydrate`（pub funnel，无需 identity test-support）；`RoleId` 经 `role.id().clone()`
// 取得——RoleId 构造封闭（`pub(crate)` parse/new），测试不可裸 mint，符合 funnel 设计（外部可读不可伪造）。
// ───────────────────────────────────────────────────────────────────────────

pub(in super::super) use identity::ports::{
    AbacAttribute, AttributeKey, DynRoleBindingLifecycle, DynRoleReadRepo, EqualityPredicate,
    MembershipPredicate, Operator, OperatorInput, OrderingPredicate, POLICY_ATTR_PRINCIPAL_KIND,
    Policy, PolicyCondition, PolicyEffect, PolicyId, PolicyLifecycle, PolicyObligations,
    PolicyPage, PolicyRepo, PolicyRouteScope, PolicyRule, PolicyScalarInput, PolicyValue,
    PolicyValueRef, PolicyValueType, PolicyVersion, ResourceSecurityFactKey,
    ResourceSecurityFactReadRepo, ResourceSecurityFactResolution, Role, RoleBinding,
    RoleBindingLifecycle, RoleBindingReadRepo, RoleDefinitionLifecycle, RolePage, RoleReadRepo,
    ScalarOperandInput, StringPredicate, TypedPolicyValueInput,
};

pub(in super::super) use crate::{
    PgPolicyLifecycle, PgPolicyRepo, PgResourceSecurityFactRepo, PgRoleBindingLifecycle,
    PgRoleBindingReadRepo, PgRoleDefinitionLifecycle, PgRoleRepo,
};

pub(in super::super) const ROLE_TENANT_A: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

pub(in super::super) const ROLE_TENANT_B: &str = "550e8400-e29b-41d4-a716-446655440000";

pub(in super::super) fn role_mutation_actor(
    tenant: TenantId,
) -> identity::ports::RoleMutationActor {
    identity::test_support::role_mutation_actor(
        &tenant.to_string(),
        "11111111-2222-4333-8444-555555555555",
        rss_request_context::PrincipalKind::Admin,
    )
}

pub(in super::super) fn role_tenant(
    raw: &str,
) -> Result<TenantId, Box<dyn std::error::Error + Send + Sync>> {
    Ok(TenantId::parse(raw)?)
}

pub(in super::super) const POLICY_CONTRACT_ID: &str = "identity.roles";

pub(in super::super) const POLICY_PERMISSION: &str = "identity:role:read";

pub(in super::super) const RESOURCE_SECURITY_FACT_DEVICE_ID: &str =
    "11111111-2222-4333-8444-555555555555";

pub(in super::super) const POLICY_UPDATED_CONTRACT: vocab::ContractBinding =
    generated::event::identity_v1::policy_updated::CONTRACT;

pub(in super::super) fn policy_time(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

pub(in super::super) fn policy_scope() -> Result<PolicyRouteScope, IdentityError> {
    PolicyRouteScope::parse(POLICY_CONTRACT_ID, POLICY_PERMISSION)
}

pub(in super::super) fn policy_id(raw: &str) -> Result<PolicyId, IdentityError> {
    PolicyId::parse(raw).map_err(|_| IdentityError::InvalidPolicy)
}

pub(in super::super) fn policy_version(raw: u32) -> Result<PolicyVersion, IdentityError> {
    PolicyVersion::new(raw)
}

pub(in super::super) fn policy_rule(
    effect: PolicyEffect,
    obligations: PolicyObligations,
) -> Result<PolicyRule, IdentityError> {
    Ok(PolicyRule::with_obligations(
        PolicyCondition::new(
            AttributeKey::parse(POLICY_ATTR_PRINCIPAL_KIND)
                .map_err(|_| IdentityError::InvalidPolicy)?,
            Operator::try_from(OperatorInput::Equality {
                predicate: EqualityPredicate::Eq,
                operand: ScalarOperandInput::Literal(TypedPolicyValueInput::new(
                    PolicyValueType::String,
                    PolicyScalarInput::String("admin".to_string()),
                )),
            })
            .map_err(|_| IdentityError::InvalidPolicy)?,
        ),
        effect,
        obligations,
    ))
}

pub(in super::super) fn policy_fixture(
    id: &str,
    tenant: TenantId,
    version: u32,
    effective_from: u64,
    effective_until: Option<u64>,
    effect: PolicyEffect,
    obligations: PolicyObligations,
) -> Result<Policy, IdentityError> {
    let scope = policy_scope()?;
    let rules = vec![policy_rule(effect, obligations)?];
    if version == 1 {
        Policy::build(
            id,
            tenant,
            scope,
            policy_time(effective_from),
            effective_until.map(policy_time),
            rules,
        )
    } else {
        Policy::hydrate(
            id,
            tenant,
            scope,
            version,
            policy_time(effective_from),
            effective_until.map(policy_time),
            rules,
        )
    }
}

pub(in super::super) fn first_policy_obligations(policy: &Policy) -> PolicyObligations {
    policy
        .rules()
        .first()
        .map(|rule| rule.obligations().clone())
        .unwrap_or_else(PolicyObligations::empty)
}

pub(in super::super) fn policy_rejection(err: &IdentityError) -> bool {
    matches!(err, IdentityError::InvalidPolicy)
}

pub(in super::super) fn principal_kind_rule_json(operator_json: &str) -> String {
    format!(
        r#"{{"rules":[{{"condition":{{"attribute":"{POLICY_ATTR_PRINCIPAL_KIND}","operator":{operator_json}}},"effect":"allow"}}]}}"#
    )
}

pub(in super::super) fn policy_lifecycle_event(
    tenant: TenantId,
    policy_id: &str,
    change_kind: &'static str,
    version: PolicyVersion,
) -> Result<(EventEntry, diport::OutboxEnvelopeParts), IdentityError> {
    policy_lifecycle_event_with_id(
        tenant,
        policy_id,
        change_kind,
        version,
        &uuid::Uuid::new_v4().to_string(),
    )
}

pub(in super::super) fn policy_lifecycle_event_with_id(
    tenant: TenantId,
    policy_id: &str,
    change_kind: &'static str,
    version: PolicyVersion,
    event_id: &str,
) -> Result<(EventEntry, diport::OutboxEnvelopeParts), IdentityError> {
    let actor = uuid::Uuid::from_u128(0xA11CE);
    use generated::event::identity_v1::policy_updated::{
        IdentityPolicyUpdatedPayload, IdentityPolicyUpdatedPayloadActorKind,
        IdentityPolicyUpdatedPayloadChangeKind,
    };
    let change_kind = match change_kind {
        "created" => IdentityPolicyUpdatedPayloadChangeKind::Created,
        "updated" => IdentityPolicyUpdatedPayloadChangeKind::Updated,
        "deactivated" => IdentityPolicyUpdatedPayloadChangeKind::Deactivated,
        _ => return Err(IdentityError::InvalidPolicy),
    };
    let payload = IdentityPolicyUpdatedPayload {
        policy_id: policy_id.to_string(),
        change_kind,
        version: std::num::NonZeroU32::new(version.get()).ok_or(IdentityError::InvalidPolicy)?,
        contract_id: POLICY_CONTRACT_ID.to_string(),
        permission: POLICY_PERMISSION.to_string(),
        updated_by: actor,
        actor_kind: IdentityPolicyUpdatedPayloadActorKind::Admin,
        tenant_id: tenant.to_string(),
        occurred_at: expected_occurred_at(),
    };
    let entry = generated_entry(
        generated::event::identity_v1::policy_updated::FACT,
        &payload,
        IdemKey::parse(event_id).map_err(|_| IdentityError::InvalidPolicy)?,
    )
    .map_err(|error| IdentityError::Storage(Box::new(error)))?;
    let actor_subject = actor.hyphenated().to_string();
    let envelope = diport::OutboxEnvelopeParts::new(
        POLICY_UPDATED_CONTRACT,
        tenant,
        diport::EnvelopeSubjectId::from_opaque(actor_subject.clone())
            .map_err(|_| IdentityError::InvalidPolicy)?,
        diport::OutboxActor::scoped(
            rss_request_context::PrincipalKind::Admin,
            diport::OpaqueActorId::from_opaque(actor_subject)
                .map_err(|_| IdentityError::InvalidPolicy)?,
            tenant,
            rss_request_context::RowScope::Tenant,
        ),
    );
    Ok((entry, envelope))
}

pub(in super::super) async fn policy_create_and_emit(
    lifecycle: &PgPolicyLifecycle,
    tenant: TenantId,
    policy: Policy,
) -> Result<Policy, IdentityError> {
    let (entry, envelope) =
        policy_lifecycle_event(tenant, policy.id().as_str(), "created", policy.version())?;
    lifecycle
        .create_and_emit(
            policies_create_producer_receipt(),
            identity_scope(tenant),
            policy,
            reviewed_generated_event::<generated::event::identity_v1::policy_updated::Contract>(
                entry, envelope,
            )
            .await
            .map_err(IdentityError::Storage)?,
        )
        .await
}

pub(in super::super) async fn policy_update_and_emit(
    lifecycle: &PgPolicyLifecycle,
    tenant: TenantId,
    policy: Policy,
    expected: PolicyVersion,
) -> Result<Policy, IdentityError> {
    let (entry, envelope) = policy_lifecycle_event(
        tenant,
        policy.id().as_str(),
        "updated",
        expected.next_checked()?,
    )?;
    lifecycle
        .update_and_emit(
            policies_update_producer_receipt(),
            identity_scope(tenant),
            policy,
            expected,
            reviewed_generated_event::<generated::event::identity_v1::policy_updated::Contract>(
                entry, envelope,
            )
            .await
            .map_err(IdentityError::Storage)?,
        )
        .await
}

pub(in super::super) async fn policy_deactivate_and_emit(
    lifecycle: &PgPolicyLifecycle,
    tenant: TenantId,
    id: PolicyId,
    expected: PolicyVersion,
) -> Result<bool, IdentityError> {
    let (entry, envelope) =
        policy_lifecycle_event(tenant, id.as_str(), "deactivated", expected.next_checked()?)?;
    lifecycle
        .deactivate_and_emit(
            policies_deactivate_producer_receipt(),
            identity_scope(tenant),
            id,
            expected,
            reviewed_generated_event::<generated::event::identity_v1::policy_updated::Contract>(
                entry, envelope,
            )
            .await
            .map_err(IdentityError::Storage)?,
        )
        .await
}

pub(in super::super) async fn policy_update_and_emit_event(
    lifecycle: &PgPolicyLifecycle,
    tenant: TenantId,
    policy: Policy,
    expected: PolicyVersion,
    event_id: &str,
) -> Result<Policy, IdentityError> {
    let (entry, envelope) = policy_lifecycle_event_with_id(
        tenant,
        policy.id().as_str(),
        "updated",
        expected.next_checked()?,
        event_id,
    )?;
    lifecycle
        .update_and_emit(
            policies_update_producer_receipt(),
            identity_scope(tenant),
            policy,
            expected,
            reviewed_generated_event::<generated::event::identity_v1::policy_updated::Contract>(
                entry, envelope,
            )
            .await
            .map_err(IdentityError::Storage)?,
        )
        .await
}

pub(in super::super) async fn policy_deactivate_and_emit_event(
    lifecycle: &PgPolicyLifecycle,
    tenant: TenantId,
    id: PolicyId,
    expected: PolicyVersion,
    event_id: &str,
) -> Result<bool, IdentityError> {
    let (entry, envelope) = policy_lifecycle_event_with_id(
        tenant,
        id.as_str(),
        "deactivated",
        expected.next_checked()?,
        event_id,
    )?;
    lifecycle
        .deactivate_and_emit(
            policies_deactivate_producer_receipt(),
            identity_scope(tenant),
            id,
            expected,
            reviewed_generated_event::<generated::event::identity_v1::policy_updated::Contract>(
                entry, envelope,
            )
            .await
            .map_err(IdentityError::Storage)?,
        )
        .await
}

pub(in super::super) async fn policy_outbox_exists(
    store: &PgStore,
    event_id: &str,
) -> Result<bool, IdentityError> {
    let count: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(event_id)
        .fetch_one(&store.pool)
        .await
        .map_err(|e| IdentityError::Storage(Box::new(e)))?;
    Ok(count.0 == 1)
}

pub(in super::super) async fn insert_raw_policy_and_load(
    store: &PgStore,
    repo: &PgPolicyRepo,
    id: &str,
    rules_json: &str,
) -> Result<(), IdentityError> {
    let tenant = TenantId::parse(ROLE_TENANT_A).map_err(|_| IdentityError::InvalidPolicy)?;
    sqlx::query("DELETE FROM abac_policies WHERE tenant_id = $1::uuid")
        .bind(ROLE_TENANT_A)
        .execute(&store.pool)
        .await
        .map_err(|e| IdentityError::Storage(Box::new(e)))?;
    sqlx::query(
        "INSERT INTO abac_policies \
         (tenant_id, id, version, contract_id, permission, effective_from, effective_until, rules) \
         VALUES ($1::uuid, $2, 1, $3, $4, to_timestamp(10), NULL, $5::jsonb)",
    )
    .bind(ROLE_TENANT_A)
    .bind(id)
    .bind(POLICY_CONTRACT_ID)
    .bind(POLICY_PERMISSION)
    .bind(rules_json)
    .execute(&store.pool)
    .await
    .map_err(|e| IdentityError::Storage(Box::new(e)))?;

    repo.list_effective(identity_scope(tenant), policy_scope()?, policy_time(20))
        .await
        .map(|_| ())
}

// ───────────────────────────────────────────────────────────────────────────
// PgCredentialRepo（identity 凭据仓储）集成测试（#1316）：find/save/upsert · authenticate 三态（含成功清锁）·
// 折叠锁定态原子 RMW（累计→锁→lazy-unlock 持久化）· password-change CAS · 跨租 fail-closed · F2 未知主体不建行 ·
// information_schema 明文列断言（DoD）。
//
// 构造 `Credential` 经 `Credential::hydrate`（pub funnel + secure typed test seam）；`LoginIdentifier` 经
// `identity::test_support::login_identifier`（`pub(crate)` funnel 经 test-support feature 暴露，同
// `test_support::session` 范式）。锁定策略阈值（5 次 / 15min 窗口 / 15min TTL）域 `AccountLockout` 单源，
// adapter 仅 I/O；`now` 由测试直传（确定性，无需 Clock）。known/wrong/correct/lazy-unlock 行为镜像 in-mem
// `InMemCredentialRepo` 单测（crates/identity/src/internal/mem.rs），此处证 postgres provider 行为等价 + durable。
// ───────────────────────────────────────────────────────────────────────────

pub(in super::super) use identity::ports::{
    AccountSecurityReadRepo, AccountStatus, AuthOutcome, Credential, CredentialRepo,
    LoginIdentifier,
};

pub(in super::super) use crate::{PgAccountSecurityRepo, PgCredentialRepo};

pub(in super::super) const CRED_TENANT_A: &str = "a1a2a3a4-b1b2-4c3c-8d4d-e1e2e3e4e5e6";

pub(in super::super) const CRED_TENANT_B: &str = "b9b8b7b6-c5c4-4a3a-8f2f-d1d2d3d4d5d6";

pub(in super::super) const CRED_USER_ALICE: &str = "11111111-2222-4333-8444-555555555555";

pub(in super::super) const CRED_USER_BOB: &str = "22222222-3333-4444-8555-666666666666";

// 锁定 TTL（域 AccountLockout 单源镜像；仅供测试时间步进推算，非生产复刻）。
pub(in super::super) const LOCK_TTL_SECS: u64 = 15 * 60;

// 测试基准时刻（well-after-epoch，避开 unix_secs 的 epoch 前钳零边界）。
pub(in super::super) const CRED_BASE_SECS: u64 = 1_700_000_000;

pub(in super::super) type CredHelperResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub(in super::super) fn cred_tenant(raw: &str) -> CredHelperResult<TenantId> {
    Ok(TenantId::parse(raw)?)
}

pub(in super::super) fn cred_uid(raw: &str) -> CredHelperResult<ids::UserId> {
    Ok(ids::UserId::parse(raw)?)
}

pub(in super::super) fn authenticated_user(outcome: AuthOutcome) -> CredHelperResult<ids::UserId> {
    match outcome {
        AuthOutcome::Authenticated(state) => Ok(state.user_id()),
        other => Err(format!("expected authenticated outcome, got {other:?}").into()),
    }
}

// 登录查找键（经 test-support funnel；known 主体亦可 `cred.login().clone()`，未知主体仅经此入口）。
pub(in super::super) fn login_id(raw: &str) -> LoginIdentifier {
    identity::test_support::login_identifier(raw)
}

pub(in super::super) fn raw_password(raw: &str) -> secure::RawPassword {
    secure::RawPassword::new(raw.to_owned())
}

pub(in super::super) fn test_password_hash(
    password: &str,
) -> CredHelperResult<secure::PasswordHash> {
    Ok(secure::PasswordHash::for_test(raw_password(password))?)
}

pub(in super::super) fn password_matches(
    password: &str,
    hash: &secure::PasswordHash,
) -> CredHelperResult<bool> {
    Ok(matches!(
        secure::verify_password(raw_password(password), Some(hash))?,
        secure::PasswordVerification::Verified(_)
    ))
}

pub(in super::super) fn make_cred_with_hash(
    login: &str,
    user: &str,
    hash: secure::PasswordHash,
    version: u32,
    tenant: TenantId,
) -> CredHelperResult<Credential> {
    Ok(Credential::hydrate(
        login,
        cred_uid(user)?,
        tenant,
        hash,
        version,
    ))
}

pub(in super::super) fn make_cred(
    login: &str,
    user: &str,
    password: &str,
    version: u32,
    tenant: TenantId,
) -> CredHelperResult<Credential> {
    make_cred_with_hash(login, user, test_password_hash(password)?, version, tenant)
}

pub(in super::super) fn cred_epoch(secs: u64) -> std::time::SystemTime {
    std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs)
}

// 直查持久化 failure_count（断言锁定态原子推进 / 清零）。
pub(in super::super) async fn db_failure_count(
    store: &PgStore,
    tenant: &str,
    login: &str,
) -> CredHelperResult<i64> {
    let row: (i64,) = sqlx::query_as(
        "SELECT failure_count FROM credentials WHERE tenant_id = $1::uuid AND login = $2",
    )
    .bind(tenant)
    .bind(login)
    .fetch_one(&store.pool)
    .await?;
    Ok(row.0)
}

pub(in super::super) async fn owner_credential_snapshot(
    owner: &PgStore,
    tenant: TenantId,
    login: &str,
) -> Result<Option<(i64, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT version, password_hash FROM credentials \
         WHERE tenant_id = $1::uuid AND login = $2",
    )
    .bind(tenant.to_string())
    .bind(login)
    .fetch_optional(&owner.pool)
    .await
}

pub(in super::super) type CredentialAuthState = (i64, String, i64, Option<i64>, Option<i64>);

pub(in super::super) async fn owner_credential_auth_state(
    owner: &PgStore,
    tenant: TenantId,
    login: &str,
) -> Result<Option<CredentialAuthState>, sqlx::Error> {
    sqlx::query_as(
        "SELECT version, password_hash, failure_count, \
         extract(epoch from lockout_window_start)::bigint, \
         extract(epoch from locked_until)::bigint \
         FROM credentials WHERE tenant_id = $1::uuid AND login = $2",
    )
    .bind(tenant.to_string())
    .bind(login)
    .fetch_optional(&owner.pool)
    .await
}

// 直查持久化 locked_until epoch（NULL → None；断言 lazy-unlock 持久化解锁）。
pub(in super::super) async fn db_locked_until(
    store: &PgStore,
    tenant: &str,
    login: &str,
) -> CredHelperResult<Option<i64>> {
    let row: (Option<i64>,) = sqlx::query_as(
        "SELECT extract(epoch from locked_until)::bigint \
         FROM credentials WHERE tenant_id = $1::uuid AND login = $2",
    )
    .bind(tenant)
    .bind(login)
    .fetch_one(&store.pool)
    .await?;
    Ok(row.0)
}
