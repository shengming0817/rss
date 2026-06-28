//! 验签器构造期配置：[`StaticKeySource`]（静态验签 key 源）+ [`VerifierConfig`]（issuer/audience/claim 名/
//! leeway/kind allowlist）。全部经 builder fail-fast 校验——误配在组合根接线 / 测试 setup 期暴露，不在每次
//! 验签静默失败（Option 范式：累加可忽略空输入，最终 `build` 必校验）。
//!
//! **key 格式（SEC1 点/bytes）跨 JWKS PR（#1109/T003）稳定**：T003 增 live JWKS 时复用同形 key 注入——
//! ES256 = SEC1 未压缩点（JWKS `x`·`y` 拼接同形 `0x04||x||y`）；HS256 = 共享密钥字节。T003 若引入 kid
//! 索引将以**新增可选 kid 参数**方式向下兼容，不破坏现有无-kid 调用。
//!
//! 路径隔离（防 alg-confusion，INVARIANT: OIDC-ALG-KEYPATH-01 { level = "Medium", exec = "manual/opt-in", source = "code" }）：ES256 公钥集只服务 JWT 路径，HS256 密钥集
//! 只服务 service-token 路径——[`crate::verify`] 按 scheme 选 key 集 + 校 token alg 匹配。

use std::collections::HashSet;
use std::sync::Arc;

use p256::ecdsa::VerifyingKey;

/// IdP↔RP 时钟漂移容忍（秒）。60s 是工业标准 skew 容忍（设 0 会因正常漂移误拒合法 token）。
const DEFAULT_LEEWAY_SECS: u64 = 60;
/// leeway 上限（秒）。300s（5min）是工业 skew 容忍上限——超此值等于近似关闭 exp/nbf 时间校验（极大
/// leeway 把 exp 饱和到 `i64::MAX`、nbf 饱和到 `i64::MIN`），故构造期 fail-fast 拒（安全边界前移）。
const MAX_LEEWAY_SECS: u64 = 300;
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
    /// 未注入任何验签 key（ES256 + HS256 集都空 → 无法验签）。
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
    /// leeway 超过上限（> 300s）。极大 leeway 近似关闭 exp/nbf 时间校验，安全边界前移 fail-fast 拒。
    #[error("oidc leeway exceeds maximum (300s)")]
    LeewayTooLarge,
    /// 重复设置 key 源（`keys` 与 `keys_jwks` 互斥，二次调用即冲突）。互斥配置不静默覆盖，构造期 fail-fast。
    #[error("oidc key source set more than once (keys/keys_jwks are mutually exclusive)")]
    ConflictingKeySources,
}

/// 单把验签 key + 其可选 `kid`（key id）。`kid = None` = untagged（静态 key / 无 id 的 JWK）。
pub(crate) struct KeyEntry<K> {
    pub(crate) kid: Option<String>,
    pub(crate) key: K,
}

/// transport-agnostic 验签 key 快照：ES256 公钥集（JWT 路径）+ HS256 密钥集（service-token 路径），各带 kid。
/// 静态源（[`StaticKeySource`]）build 期生成一份不变快照；JWKS 文件源（[`crate::jwks::JwksKeySource`]）后台
/// 刷新时整体替换快照（`Arc` 原子换出，读侧零撕裂）。两集物理隔离（OIDC-ALG-KEYPATH-01：[`crate::verify`]
/// 按 scheme 选集）。
pub(crate) struct KeySet {
    es256: Vec<KeyEntry<VerifyingKey>>,
    hs256: Vec<KeyEntry<Vec<u8>>>,
}

/// kid 候选规则（**单源**）：untagged key（`kid=None`）永远候选；tagged key 仅当 token kid 精确匹配才候选。
/// `kid` 只缩小候选集，最终仍须签名校验——非信任根。
///
/// **untagged=通配的安全边界（#254 F1）**：`kid=None` 的 entry **只可能**来自 operator 注入的静态源
/// （[`StaticKeySource`]，无 kid 概念、operator 受信，通配 = 既有盲扫 back-compat）——动态 **JWKS 源强制每个
/// key 带 kid**（[`crate::jwks`] `require_kid`），故 JWKS 快照永无 untagged entry，未知/缺失 kid 的 token → 无候选
/// → fail-closed（spec FR-005；绝不让无-kid JWK 变成任意 token 的通配 key）。
fn entry_matches(entry_kid: Option<&str>, token_kid: Option<&str>) -> bool {
    entry_kid.is_none() || entry_kid == token_kid
}

impl KeySet {
    /// 由已解析的 ES256 / HS256 entry 装箱（[`StaticKeySourceBuilder::build`] / [`crate::jwks`] 解析后调）。
    pub(crate) fn new(es256: Vec<KeyEntry<VerifyingKey>>, hs256: Vec<KeyEntry<Vec<u8>>>) -> Self {
        Self { es256, hs256 }
    }

    /// JWT 路径候选 ES256 公钥（按 `token_kid` 过滤，见 [`entry_matches`]）。
    pub(crate) fn es256_candidates<'a>(
        &'a self,
        token_kid: Option<&'a str>,
    ) -> impl Iterator<Item = &'a VerifyingKey> + 'a {
        self.es256
            .iter()
            .filter(move |e| entry_matches(e.kid.as_deref(), token_kid))
            .map(|e| &e.key)
    }

    /// service-token 路径候选 HS256 共享密钥（按 `token_kid` 过滤）。
    pub(crate) fn hs256_candidates<'a>(
        &'a self,
        token_kid: Option<&'a str>,
    ) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.hs256
            .iter()
            .filter(move |e| entry_matches(e.kid.as_deref(), token_kid))
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

    /// 两集是否都空（`VerifierConfigBuilder::build` fail-fast / JWKS 刷新「绝不 swap 空集」guard 用）。
    pub(crate) fn is_empty(&self) -> bool {
        self.es256.is_empty() && self.hs256.is_empty()
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

/// 静态验签 key 源：构造期注入的不变 [`KeySet`] 快照（ES256 公钥集 + HS256 密钥集，untagged）。字段私有 +
/// 唯一构造入口 = [`StaticKeySourceBuilder`]（外部不可伪造）。
pub struct StaticKeySource {
    set: Arc<KeySet>,
}

impl StaticKeySource {
    /// 新建累加式 builder。
    pub fn builder() -> StaticKeySourceBuilder {
        StaticKeySourceBuilder::default()
    }

    /// 取静态 key 快照（与 [`KeySource::snapshot`] 同形；`KeySource::Static` 包装 + 测试复用）。空集判定经
    /// 快照的 [`KeySet::is_empty`]（[`KeySource::is_empty`] 分派），不在本类型重复。
    pub(crate) fn snapshot(&self) -> Arc<KeySet> {
        Arc::clone(&self.set)
    }
}

/// [`StaticKeySource`] 累加式 builder。每次 `add_*` 即时 fail-fast 校验 key 格式（误配在 setup 期暴露）。
#[derive(Default)]
pub struct StaticKeySourceBuilder {
    es256: Vec<VerifyingKey>,
    hs256: Vec<Vec<u8>>,
}

impl StaticKeySourceBuilder {
    /// 注入一把 ES256（P-256）公钥（SEC1 **未压缩**点 `0x04 || x(32) || y(32)`，65 字节）。
    ///
    /// 选 SEC1 未压缩点而非 PEM：JWKS（#1109/T003）下发 `x`/`y` base64url，拼 `0x04||x||y` 即同形——构造器
    /// 签名跨 JWKS PR 稳定，无需 PEM↔JWKS 转换层。组合根有 PEM 时在边界转 SEC1 点注入。
    ///
    /// 组合根持 PEM 时的转换方式（T004 接线参考）：
    /// ```text
    /// // 需 p256 crate 开启 `pem` feature。
    /// let vk = p256::ecdsa::VerifyingKey::from_public_key_pem(pem_str)?;
    /// let sec1_bytes = vk.to_encoded_point(false).as_bytes().to_vec(); // 未压缩点
    /// builder.add_es256_sec1(&sec1_bytes)?;
    /// ```
    /// 本接口不内置 PEM 入口（保持最小 dep），T004 组合根接线时按需在边界完成转换。
    pub fn add_es256_sec1(mut self, sec1_point: &[u8]) -> Result<Self, ConfigError> {
        let key =
            VerifyingKey::from_sec1_bytes(sec1_point).map_err(|_| ConfigError::InvalidEs256Key)?;
        self.es256.push(key);
        Ok(self)
    }

    /// 注入一把 HS256 共享密钥（service-token 路径）。短于 256-bit / 32 bytes（含空密钥）fail-fast 拒。
    pub fn add_hs256_secret(mut self, secret: &[u8]) -> Result<Self, ConfigError> {
        if secret.len() < MIN_HS256_SECRET_BYTES {
            return Err(ConfigError::WeakHs256Secret);
        }
        self.hs256.push(secret.to_vec());
        Ok(self)
    }

    /// 装箱成不变 [`KeySet`] 快照（静态 key 全 untagged → `kid=None`，验签时盲扫，保既有行为）。key 集可任一为
    /// 空——某 scheme 无 key 时该路径验签必失败；两集都空由 `VerifierConfigBuilder::build` 拒。
    pub fn build(self) -> StaticKeySource {
        let es256 = self
            .es256
            .into_iter()
            .map(|key| KeyEntry { kid: None, key })
            .collect();
        let hs256 = self
            .hs256
            .into_iter()
            .map(|key| KeyEntry { kid: None, key })
            .collect();
        StaticKeySource {
            set: Arc::new(KeySet::new(es256, hs256)),
        }
    }
}

/// 注入验签配置（构造侧经 [`VerifierConfigBuilder`] 提供；字段私有 + 唯一构造入口 = builder，外部不可伪造）。
///
/// 单实例绑定**单一** issuer + audience。多 IdP / 多 audience：组合根为每个 IdP 建独立 [`crate::OidcProvider`]
/// 实例（#1109 接线时组合根职责）。
pub struct VerifierConfig {
    issuer: String,
    audience: String,
    tenant_claim: String,
    kind_claim: String,
    /// operator 信任本 IdP 可 assert 的 kind claim 值集。**默认空** → 空集时一律剥离 kind（→ None），杜绝
    /// 外部 IdP 擅自 assert RSS 特权 kind（INVARIANT: OIDC-KIND-ALLOWLIST-01， { level = "Medium", exec = "manual/opt-in", source = "code" }secure-by-default）。
    kind_allowlist: HashSet<String>,
    leeway_secs: u64,
    keys: KeySource,
}

impl VerifierConfig {
    pub(crate) fn issuer(&self) -> &str {
        &self.issuer
    }
    pub(crate) fn audience(&self) -> &str {
        &self.audience
    }
    pub(crate) fn tenant_claim(&self) -> &str {
        &self.tenant_claim
    }
    pub(crate) fn kind_claim(&self) -> &str {
        &self.kind_claim
    }
    /// kind 值是否在 operator 信任集（OIDC-KIND-ALLOWLIST-01）。
    pub(crate) fn is_kind_trusted(&self, kind: &str) -> bool {
        self.kind_allowlist.contains(kind)
    }
    pub(crate) fn leeway_secs(&self) -> u64 {
        self.leeway_secs
    }
    pub(crate) fn keys(&self) -> &KeySource {
        &self.keys
    }
}

/// [`VerifierConfig`] 累加式 builder：注入 issuer / audience / [`StaticKeySource`] / 可配置 tenant·kind claim 名 /
/// kind allowlist / leeway。`build()` 做最终 fail-fast 校验。
pub struct VerifierConfigBuilder {
    issuer: String,
    audience: String,
    tenant_claim: String,
    kind_claim: String,
    kind_allowlist: HashSet<String>,
    leeway_secs: u64,
    keys: Option<KeySource>,
    /// 是否重复设置 key 源（`keys`/`keys_jwks` 二次调用即 true）→ `build` fail-fast 拒（互斥不静默覆盖，#254 F3）。
    key_source_conflict: bool,
}

impl VerifierConfigBuilder {
    /// 新建 builder。tenant/kind claim 名默认 `"tenant_id"` / `"kind"`；leeway 默认 60s。
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            tenant_claim: DEFAULT_TENANT_CLAIM.to_string(),
            kind_claim: DEFAULT_KIND_CLAIM.to_string(),
            kind_allowlist: HashSet::new(),
            leeway_secs: DEFAULT_LEEWAY_SECS,
            keys: None,
            key_source_conflict: false,
        }
    }

    /// 注入**静态**验签 key 源（必填——未注入或空集 → `build` fail-fast 拒）。A2∥C 解耦：PR-C 经此传
    /// [`StaticKeySource`]，与 JWKS 文件源（[`Self::keys_jwks`]）互斥二选一。
    #[must_use]
    pub fn keys(mut self, keys: StaticKeySource) -> Self {
        self.set_key_source(KeySource::Static(keys.snapshot()));
        self
    }

    /// 注入 **JWKS 文件源**（[`crate::jwks::JwksKeySource`]，外部 agent 刷新 + 后台 poll 轮转）。JWKS 源构造期
    /// 已 fail-fast 初始非空，故 `build` 不再拒空。
    ///
    /// 与 [`Self::keys`] **互斥**：二次设置任一 key 源 → `build` 返回 [`ConfigError::ConflictingKeySources`]
    /// （fail-fast，不静默覆盖，#254 F3）。被覆盖的旧 JWKS 源经其 `Drop` 兜底取消后台任务（[`crate::jwks`]）。
    #[must_use]
    pub fn keys_jwks(mut self, keys: crate::jwks::JwksKeySource) -> Self {
        self.set_key_source(KeySource::Jwks(keys));
        self
    }

    /// 写 key 源槽；若已设置 → 标记冲突（`build` fail-fast）。互斥单源，避免链式静默覆盖。
    fn set_key_source(&mut self, source: KeySource) {
        if self.keys.is_some() {
            self.key_source_conflict = true;
        }
        self.keys = Some(source);
    }

    /// 覆盖 tenant claim 名（如 `"org"` / `"tid"`）。
    #[must_use]
    pub fn tenant_claim(mut self, name: impl Into<String>) -> Self {
        self.tenant_claim = name.into();
        self
    }

    /// 覆盖 kind claim 名（如 `"typ"` / `"principal_kind"`）。
    #[must_use]
    pub fn kind_claim(mut self, name: impl Into<String>) -> Self {
        self.kind_claim = name.into();
        self
    }

    /// 信任本 IdP 可 assert 的一个 kind claim 值（链式多次累加）。**未调用即不信任任何 kind**
    /// （默认空 allowlist → 验签时一律剥离 kind → None，OIDC-KIND-ALLOWLIST-01）。
    #[must_use]
    pub fn trust_kind(mut self, kind: impl Into<String>) -> Self {
        self.kind_allowlist.insert(kind.into());
        self
    }

    /// 覆盖时钟偏差容忍（秒）。默认 60s，上限 300s（超限 `build()` fail-fast 拒）。
    #[must_use]
    pub fn leeway_secs(mut self, secs: u64) -> Self {
        self.leeway_secs = secs;
        self
    }

    /// 最终 fail-fast 校验 + 装箱。
    pub fn build(self) -> Result<VerifierConfig, ConfigError> {
        // 互斥 key 源二次设置 → fail-fast（#254 F3，不静默覆盖）。
        if self.key_source_conflict {
            return Err(ConfigError::ConflictingKeySources);
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
        Ok(VerifierConfig {
            issuer: self.issuer,
            audience: self.audience,
            tenant_claim: self.tenant_claim,
            kind_claim: self.kind_claim,
            kind_allowlist: self.kind_allowlist,
            leeway_secs: self.leeway_secs,
            keys,
        })
    }
}

#[cfg(test)]
mod tests {
    //! builder fail-fast 单测：覆盖每个 ConfigError 变体 + happy path。
    //! item-level `#[allow(clippy::expect_used)]` 按 error-handling.md §Carve-out 标注在用到 expect 的 fn 上。

    use super::*;

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

    /// fixture：含一把合法 ES256 key 的 StaticKeySource。
    #[allow(clippy::expect_used)]
    fn es256_key_source() -> StaticKeySource {
        StaticKeySource::builder()
            .add_es256_sec1(&valid_es256_sec1())
            .expect("valid es256 key")
            .build()
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn empty_issuer_returns_error() {
        let result = VerifierConfigBuilder::new("", "aud")
            .keys(es256_key_source())
            .build();
        assert!(matches!(result, Err(ConfigError::EmptyIssuer)));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn empty_audience_returns_error() {
        let result = VerifierConfigBuilder::new("https://iss", "")
            .keys(es256_key_source())
            .build();
        assert!(matches!(result, Err(ConfigError::EmptyAudience)));
    }

    #[test]
    fn no_keys_returns_error() {
        // 未调用 .keys() → NoKeys。
        let result = VerifierConfigBuilder::new("https://iss", "aud").build();
        assert!(matches!(result, Err(ConfigError::NoKeys)));
    }

    #[test]
    fn empty_key_source_returns_error() {
        // 调用 .keys() 但 StaticKeySource 两集均空 → NoKeys。
        let keys = StaticKeySource::builder().build();
        let result = VerifierConfigBuilder::new("https://iss", "aud")
            .keys(keys)
            .build();
        assert!(matches!(result, Err(ConfigError::NoKeys)));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn empty_tenant_claim_name_returns_error() {
        let result = VerifierConfigBuilder::new("https://iss", "aud")
            .keys(es256_key_source())
            .tenant_claim("")
            .build();
        assert!(matches!(result, Err(ConfigError::EmptyClaimName)));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn empty_kind_claim_name_returns_error() {
        let result = VerifierConfigBuilder::new("https://iss", "aud")
            .keys(es256_key_source())
            .kind_claim("")
            .build();
        assert!(matches!(result, Err(ConfigError::EmptyClaimName)));
    }

    #[test]
    fn invalid_es256_key_returns_error() {
        // 传入格式非法字节（非 SEC1 未压缩点）→ InvalidEs256Key。
        let result = StaticKeySource::builder().add_es256_sec1(&[0u8; 10]);
        assert!(matches!(result, Err(ConfigError::InvalidEs256Key)));
    }

    #[test]
    fn empty_hs256_secret_returns_weak_error() {
        // 空密钥是「过弱」的子集（len 0 < 32）。
        let result = StaticKeySource::builder().add_hs256_secret(b"");
        assert!(matches!(result, Err(ConfigError::WeakHs256Secret)));
    }

    #[test]
    fn short_hs256_secret_returns_weak_error() {
        // 31 bytes（< 256-bit）→ 拒。
        let result = StaticKeySource::builder().add_hs256_secret(&[0x11u8; 31]);
        assert!(matches!(result, Err(ConfigError::WeakHs256Secret)));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn hs256_secret_at_min_boundary_accepted() {
        // 恰好 32 bytes（256-bit）→ 接受。
        let ks = StaticKeySource::builder()
            .add_hs256_secret(&[0x22u8; MIN_HS256_SECRET_BYTES])
            .expect("32-byte secret accepted")
            .build();
        assert!(!ks.snapshot().is_empty());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn happy_path_build_succeeds() {
        let config = VerifierConfigBuilder::new("https://issuer.example", "rss-api")
            .keys(es256_key_source())
            .trust_kind("user")
            .leeway_secs(30)
            .build()
            .expect("valid config");
        assert_eq!(config.issuer(), "https://issuer.example");
        assert_eq!(config.audience(), "rss-api");
        assert_eq!(config.leeway_secs(), 30);
        assert!(config.is_kind_trusted("user"));
        assert!(!config.is_kind_trusted("admin"));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn leeway_at_max_boundary_accepted() {
        // 恰好 300s → 接受。
        let config = VerifierConfigBuilder::new("https://iss", "aud")
            .keys(es256_key_source())
            .leeway_secs(MAX_LEEWAY_SECS)
            .build()
            .expect("300s leeway accepted");
        assert_eq!(config.leeway_secs(), MAX_LEEWAY_SECS);
    }

    #[test]
    fn leeway_above_max_returns_error() {
        // 301s → 拒。
        let result = VerifierConfigBuilder::new("https://iss", "aud")
            .keys(es256_key_source())
            .leeway_secs(MAX_LEEWAY_SECS + 1)
            .build();
        assert!(matches!(result, Err(ConfigError::LeewayTooLarge)));
    }

    #[test]
    fn leeway_u64_max_returns_error() {
        // u64::MAX（饱和运算近似关闭时间校验）→ 拒。
        let result = VerifierConfigBuilder::new("https://iss", "aud")
            .keys(es256_key_source())
            .leeway_secs(u64::MAX)
            .build();
        assert!(matches!(result, Err(ConfigError::LeewayTooLarge)));
    }

    #[test]
    fn whitespace_issuer_returns_error() {
        let result = VerifierConfigBuilder::new("   ", "aud")
            .keys(es256_key_source())
            .build();
        assert!(matches!(result, Err(ConfigError::EmptyIssuer)));
    }

    #[test]
    fn whitespace_audience_returns_error() {
        let result = VerifierConfigBuilder::new("https://iss", "  \t ")
            .keys(es256_key_source())
            .build();
        assert!(matches!(result, Err(ConfigError::EmptyAudience)));
    }

    #[test]
    fn whitespace_claim_name_returns_error() {
        let result = VerifierConfigBuilder::new("https://iss", "aud")
            .keys(es256_key_source())
            .tenant_claim("   ")
            .build();
        assert!(matches!(result, Err(ConfigError::EmptyClaimName)));
    }
}
