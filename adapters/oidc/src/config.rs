//! 验签器构造期配置：[`AccessStaticKeySource`]（静态验签 key 源）+ [`VerifierConfig`]（issuer/audience/claim 名/
//! leeway/federated kind allowlist）。全部经 builder fail-fast 校验——误配在组合根接线 / 测试 setup 期暴露，不在每次
//! 验签静默失败（Option 范式：累加可忽略空输入，最终 `build` 必校验）。
//!
//! **key 格式（SEC1 点/bytes）跨 JWKS PR（#1109/T003）稳定**：T003 增 live JWKS 时复用同形 key 注入——
//! ES256 = SEC1 未压缩点（JWKS `x`·`y` 拼接同形 `0x04||x||y`）；HS256 = 共享密钥字节。service-token
//! HS256 key selection requires `kid`; [`AccessStaticKeySourceBuilder::add_hs256_secret`] uses the explicit default
//! kid `"default"` and signers must include that JOSE header.
//!
//! 路径隔离（防 alg-confusion，INVARIANT: OIDC-ALG-KEYPATH-01 { level = "Medium", exec = "manual/opt-in", source = "code" }）：ES256 公钥集只服务 JWT 路径，HS256 密钥集
//! 只服务 service-token 路径——[`crate::verify`] 按 scheme 选 key 集 + 校 token alg 匹配。

use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use diport::{
    FederatedAccessProfile, ProjectionOperatorTokenProfile, RssAccessProfile, ServiceTokenProfile,
    TokenProfileMarker,
};
use p256::ecdsa::VerifyingKey;
use sha2::{Digest as _, Sha256};

/// IdP↔RP 时钟漂移容忍（秒）。60s 是工业标准 skew 容忍（设 0 会因正常漂移误拒合法 token）。
const DEFAULT_LEEWAY_SECS: u64 = 60;
/// leeway 上限（秒）。300s（5min）是工业 skew 容忍上限——超此值等于近似关闭 exp/nbf 时间校验（极大
/// leeway 把 exp 饱和到 `i64::MAX`、nbf 饱和到 `i64::MIN`），故构造期 fail-fast 拒（安全边界前移）。
const MAX_LEEWAY_SECS: u64 = 300;
/// Replay-store operation budget upper bound. Runtime callers must choose an explicit, non-zero
/// budget; this cap prevents configuration from silently recreating an effectively unbounded call.
const MAX_SERVICE_TOKEN_REPLAY_TIMEOUT: Duration = Duration::from_secs(60);
/// HS256 共享密钥最小字节数。RFC 7518 §3.2：HMAC-SHA256 key 不得短于 hash 输出（256-bit = 32 bytes），
/// 短密钥削弱 MAC 强度，故构造期 fail-fast 拒（空密钥是其子集）。`pub(crate)`：JWKS `oct` key 解析（[`crate::jwks`]）
/// 复用同一最小强度约束（单源）。
pub(crate) const MIN_HS256_SECRET_BYTES: usize = 32;
/// 默认 tenant claim 名（从 JWT extra 取 `tenant_id` 字段，可经 builder 覆盖）。
const DEFAULT_TENANT_CLAIM: &str = "tenant_id";
/// 默认 kind claim 名（从 JWT extra 取 `kind` 字段，可经 builder 覆盖）。
const DEFAULT_KIND_CLAIM: &str = "kind";

/// 构造期配置错误（fail-fast）。`#[non_exhaustive]`：新增校验项不破坏 match。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// issuer 为空（验签必须锁定可信签发者）。
    #[error("oidc issuer must not be empty")]
    EmptyIssuer,
    /// audience 为空（验签必须锁定本服务 audience，防 token 重放到别的 RP）。
    #[error("oidc audience must not be empty")]
    EmptyAudience,
    /// 未注入任何符合 profile 的验签 key。
    #[error("oidc key source must not be empty")]
    NoKeys,
    /// tenant / kind claim 名为空（配空名等于无声吞掉映射）。
    #[error("oidc claim name must not be empty")]
    EmptyClaimName,
    /// ES256 公钥格式非法（非 SEC1 未压缩点 / 非 P-256 曲线点）。公钥非敏感，原始 parse 错误不入此变体。
    #[error("oidc ES256 public key is malformed (expect SEC1 uncompressed P-256 point)")]
    InvalidEs256Key,
    /// HS256 共享密钥过弱（短于 256-bit / 32 bytes，含空密钥）。弱 MAC key 削弱 service-token 验签强度。
    #[error("oidc HS256 secret too weak (require >= 32 bytes / 256-bit)")]
    WeakHs256Secret,
    /// Every static key requires a non-empty exact key id.
    #[error("oidc key id must not be empty")]
    EmptyKid,
    /// Retirement schedule entries must use unique key ids.
    #[error("oidc retirement schedule key ids must be unique")]
    DuplicateKid,
    /// leeway 超过上限（> 300s）。极大 leeway 近似关闭 exp/nbf 时间校验，安全边界前移 fail-fast 拒。
    #[error("oidc leeway exceeds maximum (300s)")]
    LeewayTooLarge,
    /// 重复设置 key 源（`keys` 与 `keys_jwks` 互斥，二次调用即冲突）。互斥配置不静默覆盖，构造期 fail-fast。
    #[error("oidc key source set more than once (keys/keys_jwks are mutually exclusive)")]
    ConflictingKeySources,
    /// service-token key present without a durable replay store.
    #[error("oidc service-token replay store is required")]
    MissingReplayStore,
    /// replay-store timeout must be explicit, non-zero, and operationally bounded.
    #[error("oidc service-token replay timeout must be between 1ns and 60s")]
    ReplayTimeoutOutOfRange,
    /// Federated access must declare the exact typed permission universe it accepts.
    #[error("oidc federated permission universe must not be empty")]
    MissingFederatedPermissions,
    /// Repeating a permission is configuration drift rather than an idempotent builder update.
    #[error("oidc federated permission universe contains a duplicate")]
    DuplicateFederatedPermission,
}

/// 单把验签 key + 非空 `kid`。所有 key source 都只允许 exact-kid lookup。
pub(crate) struct KeyEntry<K> {
    pub(crate) kid: String,
    pub(crate) key: K,
}

/// transport-agnostic 验签 key 快照：ES256 公钥集（JWT 路径）+ HS256 密钥集（service-token 路径），各带 kid。
/// 静态源（[`AccessStaticKeySource`]）build 期生成一份不变快照；JWKS 文件源（[`crate::jwks::JwksKeySource`]）后台
/// 刷新时整体替换快照（`Arc` 原子换出，读侧零撕裂）。两集物理隔离（OIDC-ALG-KEYPATH-01：[`crate::verify`]
/// 按 scheme 选集）。
pub(crate) struct KeySet {
    es256: Vec<KeyEntry<VerifyingKey>>,
    hs256: Vec<KeyEntry<Vec<u8>>>,
}

impl KeySet {
    pub(crate) fn access(es256: Vec<KeyEntry<VerifyingKey>>) -> Self {
        Self {
            es256,
            hs256: Vec::new(),
        }
    }

    pub(crate) fn service_token(hs256: Vec<KeyEntry<Vec<u8>>>) -> Self {
        Self {
            es256: Vec::new(),
            hs256,
        }
    }

    /// Access-token ES256 candidate selected by exact, non-empty `kid`.
    pub(crate) fn es256_candidates<'a>(
        &'a self,
        token_kid: &'a str,
    ) -> impl Iterator<Item = &'a VerifyingKey> + 'a {
        self.es256
            .iter()
            .filter(move |e| e.kid == token_kid)
            .map(|e| &e.key)
    }

    /// Service-token HS256 candidate selected by exact, non-empty `kid`.
    pub(crate) fn hs256_candidates<'a>(
        &'a self,
        token_kid: &'a str,
    ) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.hs256
            .iter()
            .filter(move |e| e.kid == token_kid)
            .map(|e| e.key.as_slice())
    }

    /// ES256 集大小（脱敏失败日志的 keys_tried 计数用）。
    pub(crate) fn es256_len(&self) -> usize {
        self.es256.len()
    }
    /// HS256 集大小（脱敏失败日志计数用）。
    pub(crate) fn hs256_len(&self) -> usize {
        self.hs256.len()
    }
    /// 两集是否都空（builder fail-fast / JWKS 刷新「绝不 swap 空集」guard 用）。
    pub(crate) fn is_empty(&self) -> bool {
        self.es256.is_empty() && self.hs256.is_empty()
    }

    /// Exact-kid presence in the current snapshot (ES256 or HS256).
    pub(crate) fn has_kid(&self, kid: &str) -> bool {
        self.es256.iter().any(|e| e.kid == kid) || self.hs256.iter().any(|e| e.kid == kid)
    }

    /// Canonical key-material fingerprints for access-profile isolation.
    ///
    /// `kid` is deliberately excluded: the same P-256 point under different identifiers is still
    /// the same trust root. `VerifyingKey` is normalized to the uncompressed SEC1 encoding before
    /// SHA-256 so compressed/uncompressed source encodings cannot bypass the comparison.
    pub(crate) fn es256_fingerprints(&self) -> HashSet<[u8; 32]> {
        self.es256
            .iter()
            .map(|entry| {
                let canonical = entry.key.to_encoded_point(false);
                Sha256::digest(canonical.as_bytes()).into()
            })
            .collect()
    }
}

/// 验签 key 源（**闭合** enum：静态注入 vs JWKS 文件源——闭集，外部 crate 无法新增变体/伪造，类型层 Hard）。
/// [`VerifierConfig`] 持有；[`crate::verify`] 经 [`KeySource::snapshot`] 取当前快照验签（同步、零 await）。
pub(crate) enum KeySource {
    /// 构造期静态注入的 key（无后台任务；快照不变）。
    Static(Arc<KeySet>),
    /// 本地文件 JWKS 源（外部 agent 刷新 + 后台 poll 重载；持刷新句柄，关闭需停任务）。
    Jwks(crate::jwks::JwksKeySource),
}

impl KeySource {
    /// 取当前验签 key 快照（`Static` 返回不变 Arc；`Jwks` 取后台刷新的最新快照）。
    pub(crate) fn snapshot(&self) -> Arc<KeySet> {
        match self {
            KeySource::Static(set) => Arc::clone(set),
            KeySource::Jwks(src) => src.snapshot(),
        }
    }

    /// 关闭 key 源（`Static` 无后台任务 → no-op；`Jwks` 取消 poll 任务 + await 收敛）。由
    /// [`crate::OidcProvider`] 的 `ManagedResource::shutdown` 级联调用。
    pub(crate) async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
        match self {
            // reason: 静态源 key 构造期注入、无 infra 句柄 / 后台任务，关闭无需显式动作。
            KeySource::Static(_) => Ok(()),
            KeySource::Jwks(src) => src.shutdown().await,
        }
    }

    /// 配置是否「无 key」（`build` fail-fast 用）。`Static` 看快照是否空；`Jwks` 构造期已 fail-fast 初始非空，
    /// 运行期失败保留 last-good（degraded 经 `is_ready` 反映），**不**视作空配置 → 始终非空。
    pub(crate) fn is_empty(&self) -> bool {
        match self {
            KeySource::Static(set) => set.is_empty(),
            KeySource::Jwks(_) => false,
        }
    }
}

/// Keyed ES256 static key source for RSS/federated access profiles.
pub struct AccessStaticKeySource {
    set: Arc<KeySet>,
}

impl AccessStaticKeySource {
    pub fn builder() -> AccessStaticKeySourceBuilder {
        AccessStaticKeySourceBuilder::default()
    }

    pub(crate) fn snapshot(&self) -> Arc<KeySet> {
        Arc::clone(&self.set)
    }
}

#[derive(Default)]
pub struct AccessStaticKeySourceBuilder {
    es256: Vec<KeyEntry<VerifyingKey>>,
}

impl AccessStaticKeySourceBuilder {
    /// Add one P-256 key with a required, exact-match `kid`.
    pub fn add_es256_sec1(
        mut self,
        kid: impl Into<String>,
        sec1_point: &[u8],
    ) -> Result<Self, ConfigError> {
        let kid = kid.into();
        if kid.trim().is_empty() {
            return Err(ConfigError::EmptyKid);
        }
        let key =
            VerifyingKey::from_sec1_bytes(sec1_point).map_err(|_| ConfigError::InvalidEs256Key)?;
        self.es256.push(KeyEntry { kid, key });
        Ok(self)
    }

    pub fn build(self) -> AccessStaticKeySource {
        AccessStaticKeySource {
            set: Arc::new(KeySet::access(self.es256)),
        }
    }
}

/// Keyed HS256 static key source for the service-token profile.
pub struct ServiceTokenKeySource {
    set: Arc<KeySet>,
}

impl ServiceTokenKeySource {
    pub fn builder() -> ServiceTokenKeySourceBuilder {
        ServiceTokenKeySourceBuilder::default()
    }

    pub(crate) fn snapshot(&self) -> Arc<KeySet> {
        Arc::clone(&self.set)
    }
}

#[derive(Default)]
pub struct ServiceTokenKeySourceBuilder {
    hs256: Vec<KeyEntry<Vec<u8>>>,
}

impl ServiceTokenKeySourceBuilder {
    pub fn add_hs256_secret(
        mut self,
        kid: impl Into<String>,
        secret: &[u8],
    ) -> Result<Self, ConfigError> {
        let kid = kid.into();
        if kid.trim().is_empty() {
            return Err(ConfigError::EmptyKid);
        }
        if secret.len() < MIN_HS256_SECRET_BYTES {
            return Err(ConfigError::WeakHs256Secret);
        }
        self.hs256.push(KeyEntry {
            kid,
            key: secret.to_vec(),
        });
        Ok(self)
    }

    pub fn build(self) -> ServiceTokenKeySource {
        ServiceTokenKeySource {
            set: Arc::new(KeySet::service_token(self.hs256)),
        }
    }
}

/// Immutable kid → verify-until (unix seconds) map for signing-key retirement.
///
/// Keys past their deadline (`now_unix > verify_until`) are rejected at verify time even if still
/// present in the JWKS/static snapshot. Deadline instant itself remains verifiable.
#[derive(Clone, Debug, Default)]
pub struct RetirementSchedule {
    deadlines: HashMap<String, i64>,
}

impl RetirementSchedule {
    /// Build from `(kid, verify_until)` entries. Empty / whitespace-only kid is rejected.
    /// Duplicate kids fail fast (same uniqueness rule as the signing key ring).
    pub fn from_entries(
        entries: impl IntoIterator<Item = (String, i64)>,
    ) -> Result<Self, ConfigError> {
        let mut deadlines = HashMap::new();
        for (kid, verify_until) in entries {
            if kid.trim().is_empty() {
                return Err(ConfigError::EmptyKid);
            }
            if deadlines.insert(kid, verify_until).is_some() {
                return Err(ConfigError::DuplicateKid);
            }
        }
        Ok(Self { deadlines })
    }

    /// Configured verify-until deadline for `kid`, if any.
    pub fn verify_until_for(&self, kid: &str) -> Option<i64> {
        self.deadlines.get(kid).copied()
    }

    /// `true` when `kid` has a deadline and `now_unix` is strictly after it.
    pub fn is_retired(&self, kid: &str, now_unix: i64) -> bool {
        self.verify_until_for(kid)
            .is_some_and(|verify_until| now_unix > verify_until)
    }
}

struct VerifierCore {
    issuer: String,
    audience: String,
    tenant_claim: String,
    kind_claim: String,
    /// operator 信任本 IdP 可 assert 的 kind claim 值集。**默认空** → 空集时一律剥离 kind（→ None），杜绝
    /// 外部 IdP 擅自 assert RSS 特权 kind（INVARIANT: OIDC-KIND-ALLOWLIST-01， { level = "Medium", exec = "manual/opt-in", source = "code" }secure-by-default）。
    kind_allowlist: HashSet<String>,
    federated_permission_allowlist: HashSet<vocab::GrantPermission>,
    leeway_secs: u64,
    keys: KeySource,
    /// Optional retirement deadlines; `None` = no deadline filtering (legacy behavior).
    retirement_schedule: Option<RetirementSchedule>,
    service_token_replay: ServiceTokenReplayProtection,
}

enum ServiceTokenReplayProtection {
    Disabled,
    Scoped {
        store: Arc<diport::DynServiceTokenReplayStore<'static>>,
        timeout: Duration,
    },
}

/// A verifier configuration bound at compile time to exactly one token profile.
pub struct VerifierConfig<P: TokenProfileMarker> {
    core: VerifierCore,
    profile: PhantomData<fn() -> P>,
}

impl<P: TokenProfileMarker> VerifierConfig<P> {
    pub(crate) fn issuer(&self) -> &str {
        &self.core.issuer
    }
    pub(crate) fn audience(&self) -> &str {
        &self.core.audience
    }
    pub(crate) fn tenant_claim(&self) -> &str {
        &self.core.tenant_claim
    }
    pub(crate) fn kind_claim(&self) -> &str {
        &self.core.kind_claim
    }
    /// kind 值是否在 operator 信任集（OIDC-KIND-ALLOWLIST-01）。
    pub(crate) fn is_kind_trusted(&self, kind: &str) -> bool {
        self.core.kind_allowlist.contains(kind)
    }
    pub(crate) fn is_federated_permission_trusted(
        &self,
        permission: vocab::GrantPermission,
    ) -> bool {
        self.core
            .federated_permission_allowlist
            .contains(&permission)
    }
    pub(crate) fn leeway_secs(&self) -> u64 {
        self.core.leeway_secs
    }
    pub(crate) fn keys(&self) -> &KeySource {
        &self.core.keys
    }
    pub(crate) fn retirement_schedule(&self) -> Option<&RetirementSchedule> {
        self.core.retirement_schedule.as_ref()
    }
    pub(crate) fn service_token_replay_store(
        &self,
    ) -> Option<(&diport::DynServiceTokenReplayStore<'static>, Duration)> {
        match &self.core.service_token_replay {
            ServiceTokenReplayProtection::Disabled => None,
            ServiceTokenReplayProtection::Scoped { store, timeout } => {
                Some((store.as_ref(), *timeout))
            }
        }
    }
}

/// Typed verifier builder. Profile-specific impl blocks expose only the matching key APIs.
pub struct VerifierConfigBuilder<P: TokenProfileMarker> {
    issuer: String,
    audience: String,
    tenant_claim: String,
    kind_claim: String,
    kind_allowlist: HashSet<String>,
    federated_permission_allowlist: HashSet<vocab::GrantPermission>,
    leeway_secs: u64,
    keys: Option<KeySource>,
    retirement_schedule: Option<RetirementSchedule>,
    service_token_replay_store:
        Option<(Arc<diport::DynServiceTokenReplayStore<'static>>, Duration)>,
    /// 是否重复设置 key 源（`keys`/`keys_jwks` 二次调用即 true）→ `build` fail-fast 拒（互斥不静默覆盖，#254 F3）。
    key_source_conflict: bool,
    profile: PhantomData<fn() -> P>,
}

impl<P: TokenProfileMarker> VerifierConfigBuilder<P> {
    fn base(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            tenant_claim: DEFAULT_TENANT_CLAIM.to_string(),
            kind_claim: DEFAULT_KIND_CLAIM.to_string(),
            kind_allowlist: HashSet::new(),
            federated_permission_allowlist: HashSet::new(),
            leeway_secs: DEFAULT_LEEWAY_SECS,
            keys: None,
            retirement_schedule: None,
            service_token_replay_store: None,
            key_source_conflict: false,
            profile: PhantomData,
        }
    }

    /// Attach an optional retirement schedule. Absent schedule preserves legacy verify behavior.
    #[must_use]
    pub fn retirement_schedule(mut self, schedule: RetirementSchedule) -> Self {
        self.retirement_schedule = Some(schedule);
        self
    }

    fn set_key_source(&mut self, source: KeySource) {
        if self.keys.is_some() {
            self.key_source_conflict = true;
        }
        self.keys = Some(source);
    }

    fn with_tenant_claim(mut self, name: impl Into<String>) -> Self {
        self.tenant_claim = name.into();
        self
    }

    fn with_kind_claim(mut self, name: impl Into<String>) -> Self {
        self.kind_claim = name.into();
        self
    }

    fn with_trusted_kind(mut self, kind: impl Into<String>) -> Self {
        self.kind_allowlist.insert(kind.into());
        self
    }

    fn with_leeway_secs(mut self, secs: u64) -> Self {
        self.leeway_secs = secs;
        self
    }

    fn with_service_token_replay_store(
        mut self,
        store: Arc<diport::DynServiceTokenReplayStore<'static>>,
        timeout: Duration,
    ) -> Self {
        self.service_token_replay_store = Some((store, timeout));
        self
    }

    fn finish(
        self,
        require_replay: bool,
        require_federated_permissions: bool,
    ) -> Result<VerifierConfig<P>, ConfigError> {
        if self.key_source_conflict {
            return Err(ConfigError::ConflictingKeySources);
        }
        if require_federated_permissions && self.federated_permission_allowlist.is_empty() {
            return Err(ConfigError::MissingFederatedPermissions);
        }
        // 纯空白等同无效（trim 后为空 → 运行时误拒所有 token），构造期拒而非静默失败。
        if self.issuer.trim().is_empty() {
            return Err(ConfigError::EmptyIssuer);
        }
        if self.audience.trim().is_empty() {
            return Err(ConfigError::EmptyAudience);
        }
        if self.tenant_claim.trim().is_empty() || self.kind_claim.trim().is_empty() {
            return Err(ConfigError::EmptyClaimName);
        }
        // leeway 上限 fail-fast——极大值近似关闭 exp/nbf 时间校验。
        if self.leeway_secs > MAX_LEEWAY_SECS {
            return Err(ConfigError::LeewayTooLarge);
        }
        let keys = self
            .keys
            .filter(|k| !k.is_empty())
            .ok_or(ConfigError::NoKeys)?;
        let service_token_replay = match self.service_token_replay_store {
            Some((_store, timeout))
                if timeout.is_zero() || timeout > MAX_SERVICE_TOKEN_REPLAY_TIMEOUT =>
            {
                return Err(ConfigError::ReplayTimeoutOutOfRange);
            }
            Some((store, timeout)) => ServiceTokenReplayProtection::Scoped { store, timeout },
            None if require_replay => {
                return Err(ConfigError::MissingReplayStore);
            }
            None => ServiceTokenReplayProtection::Disabled,
        };
        Ok(VerifierConfig {
            core: VerifierCore {
                issuer: self.issuer,
                audience: self.audience,
                tenant_claim: self.tenant_claim,
                kind_claim: self.kind_claim,
                kind_allowlist: self.kind_allowlist,
                federated_permission_allowlist: self.federated_permission_allowlist,
                leeway_secs: self.leeway_secs,
                keys,
                retirement_schedule: self.retirement_schedule,
                service_token_replay,
            },
            profile: PhantomData,
        })
    }
}

/// Non-empty, duplicate-free permission universe accepted by one FederatedAccess verifier.
pub struct FederatedPermissionUniverse(HashSet<vocab::GrantPermission>);

impl FederatedPermissionUniverse {
    pub fn try_new(
        permissions: impl IntoIterator<Item = vocab::GrantPermission>,
    ) -> Result<Self, ConfigError> {
        let mut universe = HashSet::new();
        for permission in permissions {
            if !universe.insert(permission) {
                return Err(ConfigError::DuplicateFederatedPermission);
            }
        }
        if universe.is_empty() {
            return Err(ConfigError::MissingFederatedPermissions);
        }
        Ok(Self(universe))
    }
}

impl VerifierConfigBuilder<RssAccessProfile> {
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self::base(issuer, audience)
    }
}

impl VerifierConfigBuilder<ServiceTokenProfile> {
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self::base(issuer, audience)
    }
}

impl VerifierConfigBuilder<ProjectionOperatorTokenProfile> {
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self::base(issuer, audience)
    }

    /// Projection operator verification accepts only a live ES256 JWKS source. There is no
    /// static-secret or issuer-side builder for this profile.
    #[must_use]
    pub fn keys_jwks(mut self, keys: crate::jwks::JwksKeySource) -> Self {
        self.set_key_source(KeySource::Jwks(keys));
        self
    }

    #[must_use]
    pub fn replay_store(
        self,
        store: Arc<diport::DynServiceTokenReplayStore<'static>>,
        timeout: Duration,
    ) -> Self {
        self.with_service_token_replay_store(store, timeout)
    }

    #[must_use]
    pub fn leeway_secs(self, secs: u64) -> Self {
        self.with_leeway_secs(secs)
    }

    pub fn build(self) -> Result<VerifierConfig<ProjectionOperatorTokenProfile>, ConfigError> {
        self.finish(true, false)
    }
}

macro_rules! impl_access_builder {
    ($profile:ty, $require_federated_permissions:expr) => {
        impl VerifierConfigBuilder<$profile> {
            #[must_use]
            pub fn keys_static(mut self, keys: AccessStaticKeySource) -> Self {
                self.set_key_source(KeySource::Static(keys.snapshot()));
                self
            }

            #[must_use]
            pub fn keys_jwks(mut self, keys: crate::jwks::JwksKeySource) -> Self {
                self.set_key_source(KeySource::Jwks(keys));
                self
            }

            #[must_use]
            pub fn keys_isolated_jwks(
                mut self,
                keys: crate::jwks::IsolatedJwksKeySource<$profile>,
            ) -> Self {
                self.set_key_source(KeySource::Jwks(keys.into_inner()));
                self
            }

            #[must_use]
            pub fn tenant_claim(self, name: impl Into<String>) -> Self {
                self.with_tenant_claim(name)
            }

            #[must_use]
            pub fn kind_claim(self, name: impl Into<String>) -> Self {
                self.with_kind_claim(name)
            }

            #[must_use]
            pub fn leeway_secs(self, secs: u64) -> Self {
                self.with_leeway_secs(secs)
            }

            pub fn build(self) -> Result<VerifierConfig<$profile>, ConfigError> {
                self.finish(false, $require_federated_permissions)
            }
        }
    };
}

impl_access_builder!(RssAccessProfile, false);
impl_access_builder!(FederatedAccessProfile, true);

impl VerifierConfigBuilder<FederatedAccessProfile> {
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        permissions: FederatedPermissionUniverse,
    ) -> Self {
        let mut builder = Self::base(issuer, audience);
        builder.federated_permission_allowlist = permissions.0;
        builder
    }

    /// Admit one closed federated principal kind asserted by this IdP.
    #[must_use]
    pub fn trust_kind(self, kind: impl Into<String>) -> Self {
        self.with_trusted_kind(kind)
    }
}

impl VerifierConfigBuilder<ServiceTokenProfile> {
    #[must_use]
    pub fn keys_hs256(mut self, keys: ServiceTokenKeySource) -> Self {
        self.set_key_source(KeySource::Static(keys.snapshot()));
        self
    }

    #[must_use]
    pub fn replay_store(
        self,
        store: Arc<diport::DynServiceTokenReplayStore<'static>>,
        timeout: Duration,
    ) -> Self {
        self.with_service_token_replay_store(store, timeout)
    }

    #[must_use]
    pub fn leeway_secs(self, secs: u64) -> Self {
        self.with_leeway_secs(secs)
    }

    pub fn build(self) -> Result<VerifierConfig<ServiceTokenProfile>, ConfigError> {
        self.finish(true, false)
    }
}

#[cfg(test)]
mod tests {
    //! builder fail-fast 单测：覆盖每个 ConfigError 变体 + happy path。
    //! item-level `#[allow(clippy::expect_used)]` 按 error-handling.md §Carve-out 标注在用到 expect 的 fn 上。

    use std::sync::Arc;

    use super::*;

    struct NoopReplayStore;

    impl diport::ServiceTokenReplayStore for NoopReplayStore {
        async fn check_and_record(
            &self,
            _key: &diport::ServiceTokenReplayKey,
            _expires_at: std::time::SystemTime,
            _deadline: diport::ServiceTokenReplayDeadline,
        ) -> Result<diport::ServiceTokenReplayDisposition, diport::ServiceTokenReplayStoreError>
        {
            Ok(diport::ServiceTokenReplayDisposition::Recorded)
        }
    }

    fn replay_store() -> Arc<diport::DynServiceTokenReplayStore<'static>> {
        diport::DynServiceTokenReplayStore::new_arc(NoopReplayStore)
    }

    /// 合法 ES256 SEC1 点（来自固定标量 0x42；**仅测试 fixture，永非生产 key**）。
    #[allow(clippy::expect_used)]
    fn valid_es256_sec1() -> Vec<u8> {
        p256::ecdsa::SigningKey::from_slice(&[0x42u8; 32])
            .expect("valid scalar")
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    /// fixture：含一把合法 ES256 key 的 AccessStaticKeySource。
    #[allow(clippy::expect_used)]
    fn es256_key_source() -> AccessStaticKeySource {
        AccessStaticKeySource::builder()
            .add_es256_sec1("test-es256", &valid_es256_sec1())
            .expect("valid es256 key")
            .build()
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn empty_issuer_returns_error() {
        let result = VerifierConfigBuilder::<diport::RssAccessProfile>::new("", "aud")
            .keys_static(es256_key_source())
            .build();
        assert!(matches!(result, Err(ConfigError::EmptyIssuer)));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn empty_audience_returns_error() {
        let result = VerifierConfigBuilder::<diport::RssAccessProfile>::new("https://iss", "")
            .keys_static(es256_key_source())
            .build();
        assert!(matches!(result, Err(ConfigError::EmptyAudience)));
    }

    #[test]
    fn no_keys_returns_error() {
        // 未调用 .keys_static() → NoKeys。
        let result =
            VerifierConfigBuilder::<diport::RssAccessProfile>::new("https://iss", "aud").build();
        assert!(matches!(result, Err(ConfigError::NoKeys)));
    }

    #[test]
    fn empty_key_source_returns_error() {
        // 调用 .keys_static() 但 AccessStaticKeySource 两集均空 → NoKeys。
        let keys = AccessStaticKeySource::builder().build();
        let result = VerifierConfigBuilder::<diport::RssAccessProfile>::new("https://iss", "aud")
            .keys_static(keys)
            .build();
        assert!(matches!(result, Err(ConfigError::NoKeys)));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn empty_tenant_claim_name_returns_error() {
        let result = VerifierConfigBuilder::<diport::RssAccessProfile>::new("https://iss", "aud")
            .keys_static(es256_key_source())
            .tenant_claim("")
            .build();
        assert!(matches!(result, Err(ConfigError::EmptyClaimName)));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn empty_kind_claim_name_returns_error() {
        let result = VerifierConfigBuilder::<diport::RssAccessProfile>::new("https://iss", "aud")
            .keys_static(es256_key_source())
            .kind_claim("")
            .build();
        assert!(matches!(result, Err(ConfigError::EmptyClaimName)));
    }

    #[test]
    fn invalid_es256_key_returns_error() {
        // 传入格式非法字节（非 SEC1 未压缩点）→ InvalidEs256Key。
        let result = AccessStaticKeySource::builder().add_es256_sec1("test-es256", &[0u8; 10]);
        assert!(matches!(result, Err(ConfigError::InvalidEs256Key)));
    }

    #[test]
    fn empty_hs256_secret_returns_weak_error() {
        // 空密钥是「过弱」的子集（len 0 < 32）。
        let result = ServiceTokenKeySource::builder().add_hs256_secret("svc-a", b"");
        assert!(matches!(result, Err(ConfigError::WeakHs256Secret)));
    }

    #[test]
    fn short_hs256_secret_returns_weak_error() {
        // 31 bytes（< 256-bit）→ 拒。
        let result = ServiceTokenKeySource::builder().add_hs256_secret("svc-a", &[0x11u8; 31]);
        assert!(matches!(result, Err(ConfigError::WeakHs256Secret)));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn hs256_secret_at_min_boundary_accepted() {
        // 恰好 32 bytes（256-bit）→ 接受。
        let ks = ServiceTokenKeySource::builder()
            .add_hs256_secret("svc-a", &[0x22u8; MIN_HS256_SECRET_BYTES])
            .expect("32-byte secret accepted")
            .build();
        assert!(!ks.snapshot().is_empty());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn hs256_service_token_key_requires_replay_store() {
        let keys = ServiceTokenKeySource::builder()
            .add_hs256_secret("svc-a", &[0x33u8; MIN_HS256_SECRET_BYTES])
            .expect("hs256 key")
            .build();
        let result =
            VerifierConfigBuilder::<diport::ServiceTokenProfile>::new("https://iss", "aud")
                .keys_hs256(keys)
                .build();
        assert!(matches!(result, Err(ConfigError::MissingReplayStore)));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn hs256_service_token_key_with_replay_store_builds() {
        let keys = ServiceTokenKeySource::builder()
            .add_hs256_secret("svc-a", &[0x44u8; MIN_HS256_SECRET_BYTES])
            .expect("hs256 key")
            .build();
        let config =
            VerifierConfigBuilder::<diport::ServiceTokenProfile>::new("https://iss", "aud")
                .keys_hs256(keys)
                .replay_store(replay_store(), Duration::from_secs(5))
                .build()
                .expect("replay store satisfies service-token config gate");
        assert_eq!(config.issuer(), "https://iss");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn replay_store_timeout_must_be_nonzero_and_bounded() {
        for timeout in [Duration::ZERO, Duration::from_secs(61)] {
            let keys = ServiceTokenKeySource::builder()
                .add_hs256_secret("svc-a", &[0x45u8; MIN_HS256_SECRET_BYTES])
                .expect("hs256 key")
                .build();
            let result =
                VerifierConfigBuilder::<diport::ServiceTokenProfile>::new("https://iss", "aud")
                    .keys_hs256(keys)
                    .replay_store(replay_store(), timeout)
                    .build();
            assert!(matches!(result, Err(ConfigError::ReplayTimeoutOutOfRange)));
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn happy_path_build_succeeds() {
        let config = VerifierConfigBuilder::<diport::RssAccessProfile>::new(
            "https://issuer.example",
            "rss-api",
        )
        .keys_static(es256_key_source())
        .leeway_secs(30)
        .build()
        .expect("valid config");
        assert_eq!(config.issuer(), "https://issuer.example");
        assert_eq!(config.audience(), "rss-api");
        assert_eq!(config.leeway_secs(), 30);
        assert!(!config.is_kind_trusted("user"));
        assert!(!config.is_kind_trusted("admin"));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn leeway_at_max_boundary_accepted() {
        // 恰好 300s → 接受。
        let config = VerifierConfigBuilder::<diport::RssAccessProfile>::new("https://iss", "aud")
            .keys_static(es256_key_source())
            .leeway_secs(MAX_LEEWAY_SECS)
            .build()
            .expect("300s leeway accepted");
        assert_eq!(config.leeway_secs(), MAX_LEEWAY_SECS);
    }

    #[test]
    fn leeway_above_max_returns_error() {
        // 301s → 拒。
        let result = VerifierConfigBuilder::<diport::RssAccessProfile>::new("https://iss", "aud")
            .keys_static(es256_key_source())
            .leeway_secs(MAX_LEEWAY_SECS + 1)
            .build();
        assert!(matches!(result, Err(ConfigError::LeewayTooLarge)));
    }

    #[test]
    fn leeway_u64_max_returns_error() {
        // u64::MAX（饱和运算近似关闭时间校验）→ 拒。
        let result = VerifierConfigBuilder::<diport::RssAccessProfile>::new("https://iss", "aud")
            .keys_static(es256_key_source())
            .leeway_secs(u64::MAX)
            .build();
        assert!(matches!(result, Err(ConfigError::LeewayTooLarge)));
    }

    #[test]
    fn whitespace_issuer_returns_error() {
        let result = VerifierConfigBuilder::<diport::RssAccessProfile>::new("   ", "aud")
            .keys_static(es256_key_source())
            .build();
        assert!(matches!(result, Err(ConfigError::EmptyIssuer)));
    }

    #[test]
    fn whitespace_audience_returns_error() {
        let result = VerifierConfigBuilder::<diport::RssAccessProfile>::new("https://iss", "  \t ")
            .keys_static(es256_key_source())
            .build();
        assert!(matches!(result, Err(ConfigError::EmptyAudience)));
    }

    #[test]
    fn whitespace_claim_name_returns_error() {
        let result = VerifierConfigBuilder::<diport::RssAccessProfile>::new("https://iss", "aud")
            .keys_static(es256_key_source())
            .tenant_claim("   ")
            .build();
        assert!(matches!(result, Err(ConfigError::EmptyClaimName)));
    }

    #[test]
    fn retirement_schedule_rejects_empty_kid() {
        let result = RetirementSchedule::from_entries([("".into(), 1_700_000_000)]);
        assert!(matches!(result, Err(ConfigError::EmptyKid)));
        let whitespace = RetirementSchedule::from_entries([("  \t".into(), 1)]);
        assert!(matches!(whitespace, Err(ConfigError::EmptyKid)));
    }

    #[test]
    fn retirement_schedule_rejects_duplicate_kid() {
        let result = RetirementSchedule::from_entries([("k1".into(), 100), ("k1".into(), 200)]);
        assert!(matches!(result, Err(ConfigError::DuplicateKid)));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn retirement_schedule_deadline_window_and_lookup() {
        let schedule = RetirementSchedule::from_entries([("k1".into(), 100), ("k2".into(), 200)])
            .expect("valid schedule");
        assert_eq!(schedule.verify_until_for("k1"), Some(100));
        assert_eq!(schedule.verify_until_for("missing"), None);
        // Deadline instant itself is still verifiable (`now > until` is false at equality).
        assert!(!schedule.is_retired("k1", 100));
        assert!(schedule.is_retired("k1", 101));
        assert!(!schedule.is_retired("missing", 10_000));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn retirement_schedule_optional_on_builder() {
        let schedule =
            RetirementSchedule::from_entries([("test-es256".into(), 1_700_000_000)]).expect("ok");
        let config = VerifierConfigBuilder::<diport::RssAccessProfile>::new("https://iss", "aud")
            .keys_static(es256_key_source())
            .retirement_schedule(schedule)
            .build()
            .expect("valid config");
        assert_eq!(
            config
                .retirement_schedule()
                .and_then(|s| s.verify_until_for("test-es256")),
            Some(1_700_000_000)
        );
        let without = VerifierConfigBuilder::<diport::RssAccessProfile>::new("https://iss", "aud")
            .keys_static(es256_key_source())
            .build()
            .expect("valid config");
        assert!(without.retirement_schedule().is_none());
    }

    #[test]
    fn federated_permission_universe_rejects_empty_and_duplicates() {
        assert!(matches!(
            FederatedPermissionUniverse::try_new([]),
            Err(ConfigError::MissingFederatedPermissions)
        ));
        let permission =
            vocab::GrantPermission::route(vocab::RoutePermissionId::SettingsConfigPublish);
        assert!(matches!(
            FederatedPermissionUniverse::try_new([permission, permission]),
            Err(ConfigError::DuplicateFederatedPermission)
        ));
    }
}
