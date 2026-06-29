//! `KeyProvider` —— provider-agnostic 信封加解密 DI port（可替换：Vault Transit / 本地软件 AEAD / test）。
//!
//! 字段级数据保护（at-rest storage-encryption）设计单源 **ADR-011 §D6**
//! （`docs/architecture/202606271536-011-field-protection-boundary.md`）：`KeyProvider` 是 provider-agnostic
//! 可替换 DI 注入 port（签名只引基础 / port 自定义类型，不引域实体），按 ADR-005 §2.1 category line 归 `diport`
//! （ADR-003 dynosaur Send 变体范式）。`adapters/vault` 经 DIP 内向边 impl encrypt/decrypt/rewrap（#1466），
//! 不被域依赖；域持久化路径经组合根注入的 `Box<DynKeyProvider>` 消费（#1467）。
//!
//! ## 与 `secure::Aead` 的边界
//!
//! - `secure::Aead`（sync 静态分发原语，`seal`/`open` → `CiphertextEnvelope`/`Plaintext`）= **本地 AEAD codec**，非 DI port。
//! - `KeyProvider`（async DI port）= **provider-agnostic KMS 接缝**：组合根可注入 Vault Transit（远端 KMS，密文是
//!   `vault:vN:` opaque 串）或本地软件 provider。故 port 签名用 **opaque 密文字节 [`crate::RedactedBytes`] + [`KeyRef`]
//!   元数据**，**不引** `secure::CiphertextEnvelope`（那是软件 AEAD 的具体 DEK/nonce/tag 格式，会把 provider 假设
//!   泄进 port、破坏 Vault 适配）。
//!
//! ## 数据保护不变式（类型层复用，Hard）
//!
//! - **AAD 必填 + 受信派生**（`FIELDPROT-AAD-DERIVE-FROM-CTX-01`）：encrypt/decrypt/rewrap 的 `aad: DerivedAad` 是
//!   必填位置参；[`secure::DerivedAad`] 只能经 [`secure::ProtectionContext`] funnel 派生，envelope 存储的 AAD 回灌即类型错误。
//! - **no-decrypt-in-debug**（`FIELDPROT-NODBG-DECRYPT-01`）：明文出入用 [`secure::Plaintext`]（`Debug=<redacted>` + Drop-zeroize）。
//! - **密文脱敏**（`DIPORT-DTO-BYTES-REDACT-01`）：密文用 [`crate::RedactedBytes`]（`Debug=<redacted>`、可读字节）。
//! - **错误源脱敏**（`DIPORT-ERR-SOURCE-REDACT-01`）：[`KeyProviderError`] 经 [`crate::RedactedSource`] 脱敏内层错误。
//! - **解密访问审计 + 错误源脱敏**（`FIELDPROT-KEYPROV-AUDIT-01`，Medium，**执行体 #1466**）：[`KeyProviderLocal::decrypt`]
//!   实现者义务——解密访问经 tracing span 审计 + 错误源脱敏（错误链不泄漏密钥/明文）。本 PR 是接口切片，
//!   接口层在 `decrypt` rustdoc 声明该义务（不阻断审计路径），守卫执行体落 #1466。
//! - **key-id 等值-only 匹配**（ADR-011 §D3，防 timing oracle）：[`KeyName`]/[`KeyVersion`]/[`KeyRef`] **不** derive
//!   `PartialEq`/`Eq`，仅经 `ct_eq` 比较——对标 `secure::BlindIndexValue` 的等值-only 范式，类型层杜绝非常数时间
//!   `==` 匹配 key 标识。常数时间**严格性**按维度分级：[`KeyVersion`]（定长 4-byte u32 BE）严格常数时间，是
//!   timing oracle 防护核心维度；[`KeyName`] 对变长字符串经 `constant_time_eq` 比内容、但长度差异会短路（key 名是
//!   非机密配置元数据，长度泄漏可接受）。
//!
//! ## Keyset / rotation 模型（#1474）
//!
//! [`KeyName`] 是 provider keyset 名称；[`KeyVersion`] 是该 keyset 下的 cryptographic key version；
//! [`KeyRef`] 是调用方随密文持久化的稳定 envelope reference。新写只通过 [`KeyProviderLocal::encrypt`] 选择
//! provider current-primary，旧密文只通过持久化的 [`KeyRef`] 读取 previous-read 窗口，重包裹只通过
//! [`KeyProviderLocal::rewrap`] 写回 current-primary。禁旧 key 属 provider policy（例如 Vault
//! `min_decryption_version`），不是 runtime adapter 的兼容分支。

use dynosaur::dynosaur;
use primitives::crypto::constant_time_eq;
use secure::{DerivedAad, Plaintext};

use crate::redacted::RedactedSource;
use crate::redacted_bytes::RedactedBytes;

/// key provider 操作的失败分类（**in-process** 路由用：retry / no-retry / operator 告警 / 排障映射）。
///
/// 对标同 crate `SecretResolverError` 变体 / `PublishErrorKind`。与脱敏正交：`kind` 供进程内调用方分类、
/// **不进 wire**（[`KeyProviderError`] 的 `Display` 仍是单一安全摘要常量、不泄漏 kind）。解密验证类失败
/// （AAD-mismatch / 坏密文 / 错版本）**收敛单一 [`Rejected`](Self::Rejected)**、不区分维度（对标
/// `secure::AeadError::Open`，杜绝 downgrade oracle）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyProviderErrorKind {
    /// 命名 key 不存在（permanent，不重试）。
    NotFound,
    /// 策略拒绝该操作（permanent，不重试）。
    Forbidden,
    /// provider / KMS 暂不可达（**可重试**）。
    Unavailable,
    /// 操作超时（**可重试**）。
    Timeout,
    /// 解密验证失败——AAD-mismatch / 坏密文 / 错版本**收敛单一 kind**（不区分维度，防降级探测；permanent，不重试）。
    Rejected,
}

/// key provider 操作失败（encrypt / decrypt / rewrap / shutdown）。
///
/// 双通道分流：[`kind`](Self::kind) 是 **in-process** 失败分类（retry / no-retry 路由，[`KeyProviderErrorKind`]）；
/// `Display` 是 provider 无关的单一安全摘要常量（不含 runtime 数据、**不泄漏 kind**、不区分失败维度，防降级探测）；
/// source 经 [`RedactedSource`] 脱敏（`Debug`/`Display` 固定 `<redacted>`、`Error::source()` 恒 `None`），原始错误不经
/// 任何 `Error` 接口暴露（避免密钥材料 / 明文经错误链泄漏，ADR-011 §D5）。
/// INVARIANT: DIPORT-ERR-SOURCE-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }。
#[derive(Debug, thiserror::Error)]
#[error("key provider operation failed")]
pub struct KeyProviderError {
    kind: KeyProviderErrorKind,
    #[source]
    source: RedactedSource,
}

impl KeyProviderError {
    /// 按失败分类 `kind` 把 adapter 内部错误包成 key provider 失败。原始错误仅作 internal source 保留、不经
    /// `Display` 暴露；`kind` 仅供进程内 retry/no-retry 分类、不进 wire。
    pub fn new<E>(kind: KeyProviderErrorKind, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            kind,
            source: RedactedSource::new(source),
        }
    }
    /// 进程内失败分类（retry / no-retry 路由；不进 wire、不入 `Display`）。
    pub fn kind(&self) -> KeyProviderErrorKind {
        self.kind
    }
}

/// [`KeyRef`] / [`KeyVersion`] 解析失败（输入格式校验，非 provider 操作）。
///
/// 与 [`KeyProviderError`] 分开：解析错误关乎**输入 token 形态**，不含 adapter 内部细节，故是 plain `thiserror`
/// 枚举（无 [`RedactedSource`]），对标 `CertSerialError`。message const literal，无 PII。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KeyParseError {
    /// token / name / version 段为空。
    #[error("key reference segment is empty")]
    Empty,
    /// token 不是 `<name>:<version>` 形态（缺 `:` 分隔）。
    #[error("key reference is not in `name:version` form")]
    Malformed,
    /// version 段不是合法 `u32`。
    #[error("key version is not a valid u32")]
    Version,
}

/// 命名 key 标识——选哪个 provider key（Vault Transit key name）；encrypt 入参 + [`KeyRef`] 组成项。
///
/// 非机密元数据（key 名是配置，非密钥材料），`Debug` 可见。**不** derive `PartialEq`/`Eq`——key 标识匹配走
/// `ct_eq`（ADR-011 §D3 防 timing oracle）。**fallible [`try_new`](Self::try_new)（拒空名）**：空名会令
/// [`KeyRef::to_token`] 产出 `:<ver>` 这种 [`KeyRef::parse`] 解不回来的 token，故空名在类型层**不可构造**——
/// `parse ⇄ to_token` round-trip 由构造边界保证（非 callsite 纪律，类型层 Hard）。
#[derive(Debug, Clone)]
pub struct KeyName(String);

impl KeyName {
    /// 由字符串构造 key 名；空名 fail-closed [`KeyParseError::Empty`]（保 [`KeyRef`] token round-trip：空名不可构造）。
    pub fn try_new(name: impl Into<String>) -> Result<Self, KeyParseError> {
        let name = name.into();
        if name.is_empty() {
            return Err(KeyParseError::Empty);
        }
        Ok(Self(name))
    }
    /// 借出底层 key 名。
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// 等值-only 比较 key 名（无 `==`，强制经此入口）。内容经 `constant_time_eq`，但 key 名变长——长度差异
    /// 会短路（key 名是**非机密**配置元数据，长度泄漏可接受）。严格常数时间是 [`KeyVersion::ct_eq`]（定长）。
    pub fn ct_eq(&self, other: &Self) -> bool {
        constant_time_eq(self.0.as_bytes(), other.0.as_bytes())
    }
}

/// key 轮换版本——`current-primary` 写 / `previous-read` 解（ADR-011 §D3）。
///
/// `parse` typed 解析（从存储的 token）；**不** derive `PartialEq`/`Eq`——版本匹配走 `ct_eq`（防 timing oracle）。
#[derive(Debug, Clone, Copy)]
pub struct KeyVersion(u32);

impl KeyVersion {
    /// 由数值构造版本。
    pub fn new(version: u32) -> Self {
        Self(version)
    }
    /// 从字符串解析版本（空 → [`KeyParseError::Empty`]，非数 → [`KeyParseError::Version`]）。
    pub fn parse(raw: &str) -> Result<Self, KeyParseError> {
        if raw.is_empty() {
            return Err(KeyParseError::Empty);
        }
        raw.parse::<u32>()
            .map(Self)
            .map_err(|_| KeyParseError::Version)
    }
    /// 借出底层版本号。
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    /// 常数时间比较版本号（防 timing oracle）。
    pub fn ct_eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.0.to_be_bytes(), &other.0.to_be_bytes())
    }
}

/// 完整 key 引用（name + version）——decrypt / rewrap 入参（按 version 选 previous-read key）+ encrypt 输出
/// （携「实际用了哪个 key/version」供调用方存储）。
///
/// 调用方必须把该引用与密文原子持久化；rotate 后新写返回新版本，旧记录在 provider previous-read window 内
/// 继续按旧版本解，rewrap 成功后用新返回值替换旧引用。若 provider 禁旧版本，旧 [`KeyRef`] 解密应
/// fail-closed 为 [`KeyProviderErrorKind::Rejected`]。
///
/// `parse` ⇄ [`KeyRef::to_token`] / [`Display`](std::fmt::Display) 对称的 `<name>:<version>` token 是其存储/线
/// 形态单源（调用方与密文一并落库 + 读回解析）。**不** derive `PartialEq`/`Eq`——经 `ct_eq` 等值-only 匹配
/// （name + version **均**比对、非短路；version 定长严格常数时间，ADR-011 §D3 防 timing oracle）。
#[derive(Debug, Clone)]
pub struct KeyRef {
    name: KeyName,
    version: KeyVersion,
}

impl KeyRef {
    /// 由 name + version 构造。
    pub fn new(name: KeyName, version: KeyVersion) -> Self {
        Self { name, version }
    }
    /// 从 `<name>:<version>` token 解析（version 取最后一个 `:` 之后；name 可含 `:`）。
    /// 与 [`Self::to_token`] 对称：`KeyRef::parse(&kref.to_token())` 还原 `kref`（name/version 相等）。
    /// 空名经 [`KeyName::try_new`] fail-closed [`KeyParseError::Empty`]（与构造边界同源）。
    pub fn parse(token: &str) -> Result<Self, KeyParseError> {
        let (name, version) = token.rsplit_once(':').ok_or(KeyParseError::Malformed)?;
        Ok(Self {
            name: KeyName::try_new(name)?,
            version: KeyVersion::parse(version)?,
        })
    }
    /// 规范化为 `<name>:<version>` 存储/线 token（与 [`Self::parse`] 对称，[`Display`](std::fmt::Display) 同形）。
    /// 调用方据此把 key 引用与密文一并落库——格式单源在此，杜绝手写 `format!` 与 `parse` 漂移。
    pub fn to_token(&self) -> String {
        self.to_string()
    }
    /// 借出 key 名。
    pub fn name(&self) -> &KeyName {
        &self.name
    }
    /// 取 key 版本。
    pub fn version(&self) -> KeyVersion {
        self.version
    }
    /// 等值-only 比较完整引用：name 与 version **均**比对、非短路（先各算后 `&`，防 timing oracle；
    /// version 定长严格常数时间，name 变长长度可短路——见 [`KeyName::ct_eq`]）。
    pub fn ct_eq(&self, other: &Self) -> bool {
        let name_eq = self.name.ct_eq(&other.name);
        let version_eq = self.version.ct_eq(&other.version);
        name_eq & version_eq
    }
}

// `<name>:<version>` 存储/线形态单源（与 [`KeyRef::parse`] 对称）。`to_token` 委托此处，唯一格式定义点。
impl std::fmt::Display for KeyRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.name.as_str(), self.version.as_u32())
    }
}

/// 加密 / 重包裹结果：opaque 密文 + 实际使用的 [`KeyRef`]（provider 无关；Vault Transit 产 `vault:vN:` opaque 串）。
///
/// PII 边界：密文经 [`RedactedBytes`] 持有（`Debug=<redacted>`、字节可读供落库），`key` 是非机密元数据可见——
/// `derive(Debug)` 即安全：`EncryptOutput { ciphertext: <redacted>, key: KeyRef { .. } }`。
#[derive(Debug, Clone)]
pub struct EncryptOutput {
    ciphertext: RedactedBytes,
    key: KeyRef,
}

impl EncryptOutput {
    /// 由 opaque 密文字节 + key 引用构造。
    pub fn new(ciphertext: impl Into<Vec<u8>>, key: KeyRef) -> Self {
        Self {
            ciphertext: RedactedBytes::new(ciphertext),
            key,
        }
    }
    /// 借出 opaque 密文字节（供落库 / 传输）。
    pub fn ciphertext(&self) -> &[u8] {
        self.ciphertext.as_bytes()
    }
    /// 实际使用的 key 引用（调用方与密文一并存储，供后续 decrypt/rewrap）。
    pub fn key(&self) -> &KeyRef {
        &self.key
    }
}

/// provider-agnostic 信封加解密 DI port（async）。
///
/// 公开 [`KeyProvider`] 是 **Send 变体**（adapters `impl KeyProvider for ...`），[`DynKeyProvider`] 是其
/// dyn-compatible wrapper（组合根经 `Box<DynKeyProvider>` 注入）。基 trait 自身要求 `Send + Sync`：settings
/// durable repo 会被 axum state 共享，故持有的 KeyProvider handle 必须可跨线程共享。所有参数 by-value
/// （无生命周期）→ dynosaur `dyn(box)` dyn-compatible 保证。
///
/// 轮换语义（ADR-011 §D3 / #1474）：`encrypt` 用 provider current-primary 版本；`decrypt` 按 [`KeyRef`]
/// 的 version 读取 provider previous-read 窗口；`rewrap` 把旧密文重包裹到 current-primary（不把 plaintext
/// 带回 adapter）。
#[trait_variant::make(KeyProvider: Send)]
#[dynosaur(pub DynKeyProvider = dyn(box) KeyProvider, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 加 Send+Sync 是 settings 持久化 repo 的共享状态硬需求；Send 由 trait_variant 生成的
// `KeyProvider` 变体 + dynosaur `DynKeyProvider` 承载（DI 注入走 Send wrapper）。ADR-003 既定 dyn-port 范式。
pub trait KeyProviderLocal: Send + Sync {
    /// 用 `key` 的 current-primary 版本加密 `plaintext`，绑定 `aad`；返回 opaque 密文 + 实际 [`KeyRef`]。
    async fn encrypt(
        &self,
        key: KeyName,
        plaintext: Plaintext,
        aad: DerivedAad,
    ) -> Result<EncryptOutput, KeyProviderError>;

    /// 按 `key`（含 version → previous-read 选 key）解密 `ciphertext`，绑定 `aad`；AAD/版本不符 fail-closed。
    ///
    /// **实现者义务（#1466 落地，`INVARIANT: FIELDPROT-KEYPROV-AUDIT-01`， { level = "Medium", exec = "manual/opt-in", source = "code" }对标 [`secure::Aead::open`] 调用方义务）**：
    /// - 解密访问须发射 tracing span 审计（含 `key_name` / `key_version` / `aad.coordinates()` 维度，**不含明文/密钥材料**）。
    /// - [`KeyProviderError`] 自身不携带失败维度上下文（防降级探测），故实现须在 `Err` 分支于 span 内记录 key/version
    ///   元数据（如 `tracing::error!(key = %key, "key provider decrypt failed")`），保证生产可观测性。
    /// - 错误源经 [`RedactedSource`] 脱敏（错误链不泄漏密钥/明文，ADR-011 §D5）。
    async fn decrypt(
        &self,
        ciphertext: RedactedBytes,
        key: KeyRef,
        aad: DerivedAad,
    ) -> Result<Plaintext, KeyProviderError>;

    /// 把 `ciphertext` 重包裹到 current-primary（不重新加密 plaintext），返回新密文 + 新 [`KeyRef`]。
    async fn rewrap(
        &self,
        ciphertext: RedactedBytes,
        key: KeyRef,
        aad: DerivedAad,
    ) -> Result<EncryptOutput, KeyProviderError>;

    /// 异步释放 provider 资源（无 async Drop；同 [`crate::Signer`] 范式）。
    async fn shutdown(&self) -> Result<(), KeyProviderError>;
}

#[cfg(test)]
mod tests {
    use super::{
        DynKeyProvider, EncryptOutput, KeyName, KeyParseError, KeyProvider, KeyProviderError,
        KeyProviderErrorKind, KeyRef, KeyVersion,
    };
    use crate::RedactedBytes;
    use secure::{DerivedAad, Plaintext, ProtectionContext};
    use vocab::tenant::TenantId;

    const TENANT_A: &str = "11111111-2222-4333-8444-555555555555";

    // 测试 helper：派生失败即测试设置错误，应 panic 暴露（item-level carve-out，对齐 aead/protection 范式）。
    #[allow(clippy::expect_used)]
    fn aad(key: &str, field: &str, ver: u32) -> DerivedAad {
        let tenant = TenantId::parse(TENANT_A).expect("canonical tenant");
        ProtectionContext::authenticated_request(tenant, key, field, ver)
            .expect("ctx")
            .derive()
    }

    // 单源 AAD fixture（dyn-injection / mockall smoke 共用，三次以上抽 helper）。
    fn sample_aad() -> DerivedAad {
        aad("k", "f", 1)
    }

    // 单源 KeyName fixture（拒空名 try_new，测试设置失败即 panic 暴露）。
    #[allow(clippy::expect_used)]
    fn key_name(name: &str) -> KeyName {
        KeyName::try_new(name).expect("non-empty key name")
    }

    // ---- 错误源脱敏（DIPORT-ERR-SOURCE-REDACT-01）+ typed kind 分类 ----
    #[test]
    fn key_provider_error_wraps_and_redacts_source() {
        let err = KeyProviderError::new(
            KeyProviderErrorKind::Unavailable,
            std::io::Error::other("leak-marker-kp"),
        );
        assert_eq!(err.to_string(), "key provider operation failed");
        // kind 供 in-process 分类（retry/no-retry），但 Display 不泄漏 kind（防降级探测）。
        assert_eq!(err.kind(), KeyProviderErrorKind::Unavailable);
        assert!(!err.to_string().to_lowercase().contains("unavailable"));
        assert!(std::error::Error::source(&err).is_some());
        // anti-vacuity：内层 io error 的 Debug 确实携带 marker（证明 "!contains" 非空转）。
        assert!(
            format!("{:?}", std::io::Error::other("leak-marker-kp")).contains("leak-marker-kp"),
            "前提失效：内层 Debug 未携 marker"
        );
        assert!(
            !format!("{err:?}").contains("leak-marker-kp"),
            "wrapper Debug 泄漏 source: {err:?}"
        );
    }

    // ---- F1: KeyName 拒空名（空名不可构造 → KeyRef token round-trip 类型层闭合） ----
    #[test]
    fn key_name_try_new_rejects_empty() {
        assert!(matches!(KeyName::try_new(""), Err(KeyParseError::Empty)));
        // 非空名可构造，as_str 还原。
        assert_eq!(key_name("config-protection").as_str(), "config-protection");
    }

    // ---- KeyVersion typed parse + 常数时间比较 ----
    #[test]
    #[allow(clippy::expect_used)]
    fn key_version_parse_roundtrips() {
        let v = KeyVersion::parse("7").expect("valid version");
        assert_eq!(v.as_u32(), 7);
    }

    #[test]
    fn key_version_parse_rejects_bad_input() {
        assert!(matches!(
            KeyVersion::parse("v3"),
            Err(KeyParseError::Version)
        ));
        assert!(matches!(KeyVersion::parse(""), Err(KeyParseError::Empty)));
        // u32 溢出边界（u32::MAX + 1）：parse::<u32> overflow → Version（fail-closed，不静默截断）。
        assert!(matches!(
            KeyVersion::parse("4294967296"),
            Err(KeyParseError::Version)
        ));
    }

    #[test]
    fn key_version_ct_eq_matches_only_equal() {
        let a = KeyVersion::new(3);
        let b = KeyVersion::new(3);
        let c = KeyVersion::new(4);
        assert!(a.ct_eq(&b), "equal versions must match");
        assert!(!a.ct_eq(&c), "different versions must not match");
    }

    // ---- KeyRef typed parse + 常数时间比较（name + version 双维） ----
    #[test]
    #[allow(clippy::expect_used)]
    fn key_ref_parse_roundtrips() {
        let r = KeyRef::parse("config-protection:5").expect("valid keyref");
        assert_eq!(r.name().as_str(), "config-protection");
        assert_eq!(r.version().as_u32(), 5);
    }

    #[test]
    fn key_ref_parse_rejects_malformed() {
        assert!(matches!(
            KeyRef::parse("noversion"),
            Err(KeyParseError::Malformed)
        ));
        assert!(matches!(KeyRef::parse(":5"), Err(KeyParseError::Empty)));
        assert!(matches!(
            KeyRef::parse("name:bad"),
            Err(KeyParseError::Version)
        ));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn key_ref_token_round_trips_with_parse_and_display() {
        // to_token ⇄ parse 对称 + Display 同形（存储/线 token 单源；name 含 `:` 经 rsplit 仍还原）。
        for token in ["config-protection:5", "a:b:7", "n:0"] {
            let kr = KeyRef::parse(token).expect("valid keyref");
            assert_eq!(kr.to_token(), token, "to_token must round-trip parse");
            assert_eq!(format!("{kr}"), token, "Display must equal token");
            let reparsed = KeyRef::parse(&kr.to_token()).expect("re-parse");
            assert!(kr.ct_eq(&reparsed), "parse(to_token) must equal original");
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn key_ref_ct_eq_requires_both_name_and_version() {
        let base = KeyRef::parse("k:1").expect("kr");
        let same = KeyRef::parse("k:1").expect("kr");
        let diff_ver = KeyRef::parse("k:2").expect("kr");
        let diff_name = KeyRef::parse("x:1").expect("kr");
        assert!(base.ct_eq(&same), "identical keyref must match");
        assert!(!base.ct_eq(&diff_ver), "version mismatch must fail-closed");
        assert!(!base.ct_eq(&diff_name), "name mismatch must fail-closed");
    }

    // ---- PII Debug：密文脱敏、key 元数据可见 ----
    #[test]
    #[allow(clippy::expect_used)]
    fn encrypt_output_debug_redacts_ciphertext_keeps_key_visible() {
        // anti-vacuity：裸 Vec<u8> Debug 把 0xDE 渲染成 "222"。
        assert!(format!("{:?}", vec![0xDE_u8]).contains("222"));
        let out = EncryptOutput::new(vec![0xDE, 0xAD], KeyRef::parse("kn:9").expect("kr"));
        let dbg = format!("{out:?}");
        assert!(!dbg.contains("222"), "ciphertext 字节泄漏(0xDE=222): {dbg}");
        assert!(dbg.contains("<redacted>"), "缺 <redacted>: {dbg}");
        assert!(dbg.contains("kn"), "key name 应可见: {dbg}");
        assert!(dbg.contains('9'), "key version 应可见: {dbg}");
    }

    // ---- dyn 注入 smoke：Box<DynKeyProvider> + tokio::spawn（multi_thread 验 Send） ----
    struct NoopKeyProvider;
    impl KeyProvider for NoopKeyProvider {
        async fn encrypt(
            &self,
            key: KeyName,
            _plaintext: Plaintext,
            _aad: DerivedAad,
        ) -> Result<EncryptOutput, KeyProviderError> {
            Ok(EncryptOutput::new(
                b"ct".to_vec(),
                KeyRef::new(key, KeyVersion::new(1)),
            ))
        }
        async fn decrypt(
            &self,
            _ciphertext: RedactedBytes,
            _key: KeyRef,
            _aad: DerivedAad,
        ) -> Result<Plaintext, KeyProviderError> {
            Ok(Plaintext::new(b"pt".to_vec()))
        }
        async fn rewrap(
            &self,
            _ciphertext: RedactedBytes,
            key: KeyRef,
            _aad: DerivedAad,
        ) -> Result<EncryptOutput, KeyProviderError> {
            Ok(EncryptOutput::new(b"ct2".to_vec(), key))
        }
        async fn shutdown(&self) -> Result<(), KeyProviderError> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn key_provider_is_dyn_injectable() {
        fn assert_send_sync<T: Send + Sync>(_: &T) {}
        let kp: Box<DynKeyProvider> = DynKeyProvider::new_box(NoopKeyProvider);
        assert_send_sync(&kp);
        let joined = tokio::spawn(async move {
            let enc = kp
                .encrypt(
                    key_name("config-protection"),
                    Plaintext::new(b"secret".to_vec()),
                    sample_aad(),
                )
                .await;
            let Ok(out) = enc else { return false };
            let key = out.key().clone();
            let ct = RedactedBytes::new(out.ciphertext());
            let dec = kp.decrypt(ct.clone(), key.clone(), sample_aad()).await;
            if dec.map(|pt| pt.expose() == b"pt").unwrap_or(false) {
                let re = kp.rewrap(ct, key, sample_aad()).await;
                re.is_ok() && kp.shutdown().await.is_ok()
            } else {
                false
            }
        })
        .await;
        assert!(matches!(joined, Ok(true)));
    }

    // #1049 PORT-SHAPE：native-AFIT mockall mock 可装入 dynosaur Send 变体 DynKeyProvider。
    mockall::mock! {
        TestKeyProvider {}
        impl KeyProvider for TestKeyProvider {
            async fn encrypt(&self, key: KeyName, plaintext: Plaintext, aad: DerivedAad)
                -> Result<EncryptOutput, KeyProviderError>;
            async fn decrypt(&self, ciphertext: RedactedBytes, key: KeyRef, aad: DerivedAad)
                -> Result<Plaintext, KeyProviderError>;
            async fn rewrap(&self, ciphertext: RedactedBytes, key: KeyRef, aad: DerivedAad)
                -> Result<EncryptOutput, KeyProviderError>;
            async fn shutdown(&self) -> Result<(), KeyProviderError>;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mockall_mock_loads_into_dyn_key_provider() {
        let mut mock = MockTestKeyProvider::new();
        mock.expect_encrypt().returning(|key, _pt, _aad| {
            Ok(EncryptOutput::new(
                vec![9, 9],
                KeyRef::new(key, KeyVersion::new(2)),
            ))
        });
        let kp: Box<DynKeyProvider> = DynKeyProvider::new_box(mock);
        let joined = tokio::spawn(async move {
            kp.encrypt(key_name("k"), Plaintext::new(b"x".to_vec()), sample_aad())
                .await
        })
        .await;
        assert!(matches!(joined, Ok(Ok(ref out)) if out.ciphertext() == [9, 9]));
    }
}
