//! Shared journey test helpers: [`CapturingVerifier`], [`audit_domain`], [`session_created_subscription`],
//! and shared constants ([`CANON_TENANT`] / [`AUDIT_KEY`] / …).
//!
//! This module is compiled into each including test binary separately (via `mod common;`). Items
//! unused in one binary would trigger `dead_code` under `-D warnings` — `#![allow(dead_code)]`
//! is the standard Rust idiom for shared integration-test helper modules.
#![allow(dead_code)]

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use audit::ports::{
    AuditChainHasher, AuditListTenantAppender, DynAuditReadRepo, DynAuditWriteRepo,
};
use audit::{AuditDomain, InMemAuditRepo};
use diport::{
    DynKeyProvider, EncryptOutput, EnvelopeMetadata, KeyName, KeyProvider, KeyProviderError,
    KeyRef, KeyVersion, OutboxEmitError, RedactedBytes,
};
use eventexec::event::ReviewedEvent;
use eventexec::{DlxHotKeyName, TenantAuthority, TenantAuthorityBinding};
use generated::event::identity_v1::session_created;
use identity::ports::{
    AccountReactivationLifecycle, AccountSecurityReadRepo, AccountStatusSetProducerReceipt,
    AuthOutcome, Credential, CredentialRepo, DynAccountSecurityReadRepo, DynAuthGrantLifecycle,
    DynCredentialRepo, DynPolicyLifecycle, DynPolicyRepo, DynResourceAttributeReadRepo,
    DynRoleBindingLifecycle, DynRoleBindingReadRepo, DynRoleReadRepo, IdentityError,
    IdentitySecurityLifecycle, LoginIdentifier, LogoutAllProducerReceipt,
    LogoutCurrentProducerReceipt, PasswordChangeProducerReceipt, PoliciesCreateProducerReceipt,
    PoliciesDeactivateProducerReceipt, PoliciesUpdateProducerReceipt, Policy, PolicyId,
    PolicyLifecycle, PolicyListResult, PolicyPage, PolicyRepo, PolicyRouteScope, PolicyVersion,
    RefreshExecutionCommand, RefreshExecutionOutcome, RefreshProducerReceipt, ResourceAttributeKey,
    ResourceAttributeReadRepo, ResourceAttributeResolution, ResourceAttributeResourceId, Role,
    RoleBinding, RoleBindingLifecycle, RoleBindingReadRepo, RoleId, RoleListResult, RolePage,
    RoleReadRepo, RolesAssignProducerReceipt, RolesRevokeProducerReceipt, TenantRepoScope,
};
use identity::{
    AccountSecurityState, AccountStatusSetCommand, CredentialSecurityReceipt,
    CredentialSecurityService, IdentityDomain, IdentityDomainDeps, LoginService, LogoutAllCommand,
    LogoutCurrentCommand, PasswordChangeCommand, PolicyManageService, RbacAdminService,
    ReactivateAccountCommand, RefreshService,
};
use primitives::{Mac, MacAlgorithm, MacKey, MacVerifier};
use vocab::TenantId;

/// canonical UUID 种子租户（TenantId::parse 接受形态）。
pub const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
/// session-created event 契约 topic（identity 发布 / audit 订阅）。
pub const SESSION_CREATED_TOPIC: &str = "identity.session-created";
/// 登录种子密码。
pub const PASSWORD: &str = "correct-horse";
/// 登录标识（`request.username`）——#1277 F1：可为任意非 uuid 用户名，仅作凭据查找键，不写 wire/audit。
pub const LOGIN_USERNAME: &str = "alice";
/// canonical actor subject（credential 携带的 `ids::UserId`）——登录成功后写 payload/envelope/session
/// subject + 审计 actor。与登录标识解耦（#1277 F1）。
pub const CANON_USER: &str = "11111111-2222-4333-8444-555555555555";
/// journey 审计链 HMAC key（固定 32B）。
pub const AUDIT_KEY: [u8; 32] = [0x5a; 32];
/// 固定登录时刻（确定性断言）。
pub const NOW_SECS: u64 = 1_000;
/// 会话 ttl（确定性断言）。
pub const TTL_SECS: u64 = 3_600;

const BLOCKED_PASSWORD_DIGEST: [u8; 32] = [
    0x2e, 0x2b, 0x24, 0xf8, 0xee, 0x40, 0xbb, 0x84, 0x7f, 0xe8, 0x5b, 0xb2, 0x33, 0x36, 0xa3, 0x9e,
    0xf5, 0x94, 0x8e, 0x6b, 0x49, 0xd8, 0x97, 0x41, 0x9c, 0xed, 0x68, 0x76, 0x6b, 0x16, 0x96, 0x7a,
];

pub fn password_policy() -> secure::PasswordPolicy {
    secure::PasswordPolicy::new(Arc::new(
        secure::DigestPasswordBlocklist::from_nonempty_sha256_digests(
            BLOCKED_PASSWORD_DIGEST,
            std::iter::empty(),
        ),
    ))
}

#[derive(Clone, Default)]
pub struct NoopAuditSink;

impl diport::AuditSink for NoopAuditSink {
    async fn record(&self, _event: diport::AuditEvent) -> Result<(), diport::AuditSinkError> {
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), diport::AuditSinkError> {
        Ok(())
    }
}

impl AuditListTenantAppender for NoopAuditSink {
    async fn append(
        &self,
        command: audit::ports::AuditListTenantAppend,
    ) -> Result<(), diport::AuditSinkError> {
        let (_scope, event, _observation) = command.into_parts();
        diport::AuditSink::record(self, event).await
    }
}

struct FixedAuditClock;

impl diport::Clock for FixedAuditClock {
    fn now(&self) -> std::time::SystemTime {
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(NOW_SECS)
    }
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// 审计链 HMAC 测试 verifier：捕获每次 `sign` 调用的 message（append **AND** verify 路径均会调用 `sign`，
/// 不止 append），并以确定性折叠产出 32B 标签（链一致）。`audited().len()` 计的是全部 `sign` 调用次数，
/// 含 `verify_integrity` 在内的读路径——非仅 append 次数。W 阶段审计落**域内哈希链**（无外部 sink），
/// journey 经注入此 verifier 端到端断言审计 sign 次数 + 内容贯穿。非加密——journey 只需确定性 + 可计数/可检视。
#[derive(Clone, Default)]
pub struct CapturingVerifier {
    messages: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl CapturingVerifier {
    pub fn audited(&self) -> Vec<Vec<u8>> {
        self.messages
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn is_empty(&self) -> bool {
        self.messages
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
    }
}

impl MacVerifier for CapturingVerifier {
    fn sign(&self, key: &MacKey, _algorithm: MacAlgorithm, message: &[u8]) -> Mac {
        self.messages
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(message.to_vec());
        // 确定性折叠（FNV-1a 变体；journey 只需链一致）。
        let mut acc = FNV_OFFSET;
        for &b in key.as_bytes().iter().chain(message) {
            acc ^= u64::from(b);
            acc = acc.wrapping_mul(FNV_PRIME);
        }
        let mut out = [0u8; 32];
        for chunk in out.chunks_mut(8) {
            chunk.copy_from_slice(&acc.to_be_bytes());
            acc = acc.wrapping_mul(FNV_PRIME);
        }
        Mac::from_bytes(out.to_vec())
    }

    fn verify(&self, key: &MacKey, algorithm: MacAlgorithm, message: &[u8], tag: &Mac) -> bool {
        primitives::constant_time_eq(
            self.sign(key, algorithm, message).as_bytes(),
            tag.as_bytes(),
        )
    }
}

#[allow(clippy::expect_used)]
pub fn tenant_authority() -> Arc<TenantAuthority> {
    Arc::new(
        TenantAuthority::new(
            Arc::new(CapturingVerifier::default()),
            MacKey::from_bytes(vec![0x42; 32]),
            3600,
            60,
            Arc::new(|| NOW_SECS as i64),
        )
        .expect("32B tenant authority key satisfies minimum"),
    )
}

struct MemoryTenantSigner {
    authority: Arc<TenantAuthority>,
}

impl memory::TenantMetadataSigner for MemoryTenantSigner {
    fn sign_tenant_metadata(
        &self,
        binding: memory::TenantMetadataBinding<'_>,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.authority.sign(TenantAuthorityBinding::new(
            binding.tenant(),
            binding.domain(),
            binding.contract_id(),
            binding.topic(),
            binding.message_id(),
        ))?)
    }
}

pub fn memory_tenant_signer() -> Arc<dyn memory::TenantMetadataSigner> {
    Arc::new(MemoryTenantSigner {
        authority: tenant_authority(),
    })
}

pub fn signed_metadata(
    domain: &str,
    contract_id: &str,
    topic: &str,
    message_id: &str,
) -> anyhow::Result<EnvelopeMetadata> {
    let authority = tenant_authority();
    let tenant = TenantId::parse(CANON_TENANT)?;
    let token = authority.sign(TenantAuthorityBinding::new(
        tenant,
        domain,
        contract_id,
        topic,
        message_id,
    ))?;
    let mut metadata = EnvelopeMetadata::empty();
    metadata.insert_wire_pair(diport::KEY_TENANT_ID, CANON_TENANT);
    metadata.insert_wire_pair(diport::KEY_TENANT_AUTHORITY, token);
    metadata.insert_wire_pair(
        diport::KEY_SCHEMA_VERSION,
        generated::event::identity_v1::session_created::CONTRACT.version(),
    );
    metadata.insert_wire_pair(
        diport::KEY_SCHEMA_HASH,
        generated::event::identity_v1::session_created::CONTRACT.schema_hash(),
    );
    Ok(metadata)
}

#[derive(Clone)]
struct JourneyKeyProvider;

impl KeyProvider for JourneyKeyProvider {
    async fn encrypt(
        &self,
        key: KeyName,
        plaintext: secure::Plaintext,
        _aad: secure::DerivedAad,
    ) -> Result<EncryptOutput, KeyProviderError> {
        let ciphertext: Vec<u8> = plaintext.expose().iter().map(|byte| byte ^ 0xA5).collect();
        Ok(EncryptOutput::new(
            ciphertext,
            KeyRef::new(key, KeyVersion::new(1)),
        ))
    }

    async fn decrypt(
        &self,
        ciphertext: RedactedBytes,
        _key: KeyRef,
        _aad: secure::DerivedAad,
    ) -> Result<secure::Plaintext, KeyProviderError> {
        let plaintext: Vec<u8> = ciphertext
            .into_bytes()
            .into_iter()
            .map(|byte| byte ^ 0xA5)
            .collect();
        Ok(secure::Plaintext::new(plaintext))
    }

    async fn rewrap(
        &self,
        _ciphertext: RedactedBytes,
        _key: KeyRef,
        _aad: secure::DerivedAad,
    ) -> Result<EncryptOutput, KeyProviderError> {
        Err(KeyProviderError::new(
            diport::key_provider::KeyProviderErrorKind::Forbidden,
            std::io::Error::other("journey key provider does not rewrap"),
        ))
    }

    async fn shutdown(&self) -> Result<(), KeyProviderError> {
        Ok(())
    }
}

pub fn journey_key_provider() -> Box<diport::DynKeyProvider<'static>> {
    DynKeyProvider::new_box(JourneyKeyProvider)
}

/// Mandatory receipt encryption and integrity bundle for PostgreSQL Saga journeys.
pub fn saga_receipt_protection() -> anyhow::Result<postgres::PgSagaReceiptProtection> {
    let integrity = secure::SagaReceiptIntegrityKeyring::new(
        secure::VersionedSagaReceiptIntegrityKey::new(
            secure::SagaReceiptIntegrityKeyId::parse("saga-provider-integration")?,
            secure::RedactionHashKey::from_bytes(vec![0x51; 32])?,
        ),
        Vec::new(),
    )?;
    Ok(postgres::PgSagaReceiptProtection::new(
        DynKeyProvider::new_box(JourneyKeyProvider),
        integrity,
    ))
}

#[allow(clippy::expect_used)]
pub fn dlx_payload_protector() -> postgres::DlxPayloadProtector {
    postgres::DlxPayloadProtector::new(
        DynKeyProvider::new_box(JourneyKeyProvider),
        DlxHotKeyName::try_new("journey-dlx").expect("valid journey dlx key name"),
    )
}

/// 构造 journey 用 audit 域 + 共享捕获句柄（注入捕获 verifier + 固定 32B key）。
///
/// API：经 `AuditChainHasher::new`（`Option`，弱 key → `None`）+
/// `InMemAuditRepo::new` + 共享 provider 的 read/write wrappers 装配后经 `AuditDomain::new`
/// （不可失败）注入——组合根装配路径与生产 `PgAuditRepo` 同形。
#[allow(clippy::expect_used)]
pub fn audit_domain() -> (
    AuditDomain<NoopAuditSink>,
    CapturingVerifier,
    Arc<DynAuditWriteRepo<'static>>,
) {
    let verifier = CapturingVerifier::default();
    let hasher = AuditChainHasher::new(verifier.clone(), MacKey::from_bytes(AUDIT_KEY.to_vec()))
        .expect("32B audit key satisfies MIN_KEY_LEN");
    let provider = Arc::new(InMemAuditRepo::new(hasher));
    let write_repo: Arc<DynAuditWriteRepo<'static>> =
        Arc::from(DynAuditWriteRepo::new_box(Arc::clone(&provider)));
    let read_repo: Arc<DynAuditReadRepo<'static>> = Arc::from(DynAuditReadRepo::new_box(provider));
    let domain = AuditDomain::new(read_repo, None, NoopAuditSink, Arc::new(FixedAuditClock));
    (domain, verifier, write_repo)
}

struct NoopRoleRepo;

impl RoleReadRepo for NoopRoleRepo {
    async fn find(
        &self,
        _scope: TenantRepoScope,
        _id: RoleId,
    ) -> Result<Option<Role>, IdentityError> {
        Ok(None)
    }

    async fn list(
        &self,
        _scope: TenantRepoScope,
        _page: RolePage,
    ) -> Result<RoleListResult, IdentityError> {
        Ok(RoleListResult {
            roles: Vec::new(),
            has_more: false,
        })
    }
}

struct NoopRoleBindingLifecycle;

impl RoleBindingLifecycle for NoopRoleBindingLifecycle {
    async fn assign_and_emit(
        &self,
        _receipt: RolesAssignProducerReceipt,
        _scope: TenantRepoScope,
        _binding: RoleBinding,
        _event: ReviewedEvent,
    ) -> Result<(), OutboxEmitError> {
        Ok(())
    }

    async fn revoke_and_emit(
        &self,
        _receipt: RolesRevokeProducerReceipt,
        _scope: TenantRepoScope,
        _role_id: RoleId,
        _subject: String,
        _event: ReviewedEvent,
    ) -> Result<bool, OutboxEmitError> {
        Ok(false)
    }
}

struct NoopRoleBindingReadRepo;

impl RoleBindingReadRepo for NoopRoleBindingReadRepo {
    async fn list_for_subject(
        &self,
        _scope: TenantRepoScope,
        _subject: String,
    ) -> Result<Vec<RoleBinding>, IdentityError> {
        Ok(Vec::new())
    }
}

struct NoopPolicyRepo;

impl PolicyRepo for NoopPolicyRepo {
    async fn find(
        &self,
        _scope: TenantRepoScope,
        _id: PolicyId,
    ) -> Result<Option<Policy>, IdentityError> {
        Ok(None)
    }

    async fn list_active(
        &self,
        _scope: TenantRepoScope,
        _page: PolicyPage,
    ) -> Result<PolicyListResult, IdentityError> {
        Ok(PolicyListResult {
            policies: Vec::new(),
            has_more: false,
        })
    }

    async fn list_effective(
        &self,
        _tenant_scope: TenantRepoScope,
        _scope: PolicyRouteScope,
        _at: std::time::SystemTime,
    ) -> Result<Vec<Policy>, IdentityError> {
        Ok(Vec::new())
    }
}

struct NoopResourceAttributeRepo;

impl ResourceAttributeReadRepo for NoopResourceAttributeRepo {
    async fn resolve_effective(
        &self,
        _tenant_scope: TenantRepoScope,
        _scope: PolicyRouteScope,
        _resource_id: ResourceAttributeResourceId,
        mut required_keys: Vec<ResourceAttributeKey>,
        _at: std::time::SystemTime,
    ) -> Result<ResourceAttributeResolution, IdentityError> {
        let Some(key) = required_keys.pop() else {
            return Ok(ResourceAttributeResolution::Known(Vec::new()));
        };
        Ok(ResourceAttributeResolution::Missing(key))
    }
}

struct NoopPolicyLifecycle;

impl PolicyLifecycle for NoopPolicyLifecycle {
    async fn create_and_emit(
        &self,
        _receipt: PoliciesCreateProducerReceipt,
        _scope: TenantRepoScope,
        policy: Policy,
        _event: ReviewedEvent,
    ) -> Result<Policy, IdentityError> {
        Ok(policy)
    }

    async fn update_and_emit(
        &self,
        _receipt: PoliciesUpdateProducerReceipt,
        _scope: TenantRepoScope,
        policy: Policy,
        _expected: PolicyVersion,
        _event: ReviewedEvent,
    ) -> Result<Policy, IdentityError> {
        Ok(policy)
    }

    async fn deactivate_and_emit(
        &self,
        _receipt: PoliciesDeactivateProducerReceipt,
        _scope: TenantRepoScope,
        _id: PolicyId,
        _expected: PolicyVersion,
        _event: ReviewedEvent,
    ) -> Result<bool, IdentityError> {
        Ok(false)
    }
}

/// 构造 identity 域，并为本 journey 不触达的 RBAC 端点注入 no-op 依赖。
pub fn identity_domain<S>(
    login: Arc<LoginService<S>>,
    refresh: Arc<RefreshService<S>>,
    credential_security: Arc<CredentialSecurityService>,
) -> IdentityDomain<S>
where
    S: diport::Signer + Send + Sync + 'static,
{
    let roles: Arc<DynRoleReadRepo<'static>> = Arc::from(DynRoleReadRepo::new_box(NoopRoleRepo));
    let binding_lifecycle: Arc<DynRoleBindingLifecycle<'static>> =
        Arc::from(DynRoleBindingLifecycle::new_box(NoopRoleBindingLifecycle));
    let binding_reads: Arc<DynRoleBindingReadRepo<'static>> =
        Arc::from(DynRoleBindingReadRepo::new_box(NoopRoleBindingReadRepo));
    let policies: Arc<DynPolicyRepo<'static>> = Arc::from(DynPolicyRepo::new_box(NoopPolicyRepo));
    let resource_attribute_reads: Arc<DynResourceAttributeReadRepo<'static>> = Arc::from(
        DynResourceAttributeReadRepo::new_box(NoopResourceAttributeRepo),
    );
    let policy_lifecycle: Arc<DynPolicyLifecycle<'static>> =
        Arc::from(DynPolicyLifecycle::new_box(NoopPolicyLifecycle));
    let rbac = Arc::new(RbacAdminService::new(
        roles.clone(),
        binding_lifecycle,
        Box::new(memory::FixedClock::at_unix_secs(NOW_SECS)),
    ));
    let policy_manage = Arc::new(PolicyManageService::new(
        Arc::clone(&policies),
        policy_lifecycle,
        Box::new(memory::FixedClock::at_unix_secs(NOW_SECS)),
    ));
    IdentityDomain::new(IdentityDomainDeps {
        login,
        refresh,
        credential_security,
        rbac_admin: rbac,
        policy_manage,
        roles,
        binding_reads,
        policies,
        resource_attribute_reads,
        clock: Arc::new(memory::FixedClock::at_unix_secs(NOW_SECS)),
    })
}

fn unavailable_identity_provider() -> IdentityError {
    IdentityError::ProviderUnavailable(Box::new(std::io::Error::other(
        "credential security is unavailable in this in-memory journey",
    )))
}

struct FailClosedCredentialRepo;

impl CredentialRepo for FailClosedCredentialRepo {
    async fn find_by_user_id(
        &self,
        _scope: TenantRepoScope,
        _user_id: ids::UserId,
    ) -> Result<Option<Credential>, IdentityError> {
        Err(unavailable_identity_provider())
    }

    async fn authenticate(
        &self,
        _scope: TenantRepoScope,
        _login: LoginIdentifier,
        _candidate: secure::RawPassword,
        _now: SystemTime,
    ) -> Result<AuthOutcome, IdentityError> {
        Err(unavailable_identity_provider())
    }

    async fn insert(
        &self,
        _scope: TenantRepoScope,
        _credential: Credential,
    ) -> Result<(), IdentityError> {
        Err(unavailable_identity_provider())
    }
}

struct FailClosedAccountSecurityReadRepo;

impl AccountSecurityReadRepo for FailClosedAccountSecurityReadRepo {
    async fn find(
        &self,
        _scope: TenantRepoScope,
        _user_id: ids::UserId,
    ) -> Result<Option<AccountSecurityState>, IdentityError> {
        Err(unavailable_identity_provider())
    }
}

struct FailClosedIdentitySecurityLifecycle;

impl IdentitySecurityLifecycle for FailClosedIdentitySecurityLifecycle {
    async fn execute_refresh(
        &self,
        _receipt: RefreshProducerReceipt,
        _scope: TenantRepoScope,
        _command: RefreshExecutionCommand,
    ) -> Result<RefreshExecutionOutcome, IdentityError> {
        Err(unavailable_identity_provider())
    }

    async fn execute_password_change(
        &self,
        _receipt: PasswordChangeProducerReceipt,
        _scope: TenantRepoScope,
        _command: PasswordChangeCommand,
    ) -> Result<CredentialSecurityReceipt, IdentityError> {
        Err(unavailable_identity_provider())
    }

    async fn execute_account_status_set(
        &self,
        _receipt: AccountStatusSetProducerReceipt,
        _scope: TenantRepoScope,
        _command: AccountStatusSetCommand,
    ) -> Result<CredentialSecurityReceipt, IdentityError> {
        Err(unavailable_identity_provider())
    }

    async fn execute_logout_current(
        &self,
        _receipt: LogoutCurrentProducerReceipt,
        _scope: TenantRepoScope,
        _command: LogoutCurrentCommand,
    ) -> Result<CredentialSecurityReceipt, IdentityError> {
        Err(unavailable_identity_provider())
    }

    async fn execute_logout_all(
        &self,
        _receipt: LogoutAllProducerReceipt,
        _scope: TenantRepoScope,
        _command: LogoutAllCommand,
    ) -> Result<CredentialSecurityReceipt, IdentityError> {
        Err(unavailable_identity_provider())
    }
}

impl AccountReactivationLifecycle for FailClosedIdentitySecurityLifecycle {
    async fn execute_reactivation(
        &self,
        _scope: TenantRepoScope,
        _command: ReactivateAccountCommand,
    ) -> Result<AccountSecurityState, IdentityError> {
        Err(unavailable_identity_provider())
    }
}

/// Closed, fail-closed credential-security fixture for journeys that intentionally exercise only
/// the in-memory login/event path. PostgreSQL-backed journeys must inject their production
/// lifecycle instead.
pub fn fail_closed_credential_security(
    grants: Arc<DynAuthGrantLifecycle<'static>>,
) -> Arc<CredentialSecurityService> {
    Arc::new(CredentialSecurityService::new(
        Arc::from(DynCredentialRepo::new_box(FailClosedCredentialRepo)),
        grants,
        DynAccountSecurityReadRepo::new_box(FailClosedAccountSecurityReadRepo),
        FailClosedIdentitySecurityLifecycle,
        FailClosedIdentitySecurityLifecycle,
        password_policy(),
        Box::new(memory::FixedClock::at_unix_secs(NOW_SECS)),
    ))
}

/// 取 session-created 订阅绑定（audit 域可能还声明其它 event subscriptions）。
pub fn session_created_subscription(
    mut registry: bootstrap::Registry,
) -> anyhow::Result<bootstrap::SubscriberBinding> {
    registry
        .drain_subscribers()
        .into_iter()
        .find(|sub| {
            sub.contract_id() == session_created::CONTRACT_ID
                && sub.topic() == session_created::TOPIC
                && sub.consumer() == "audit"
        })
        .ok_or_else(|| anyhow::anyhow!("session-created 订阅缺失"))
}
