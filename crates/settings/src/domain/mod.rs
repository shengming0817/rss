//! settings 域类型与纯逻辑（dylint 守护区：此模块内类型禁止 derive Serialize/Deserialize）。
//!
//! 所有类型字段私有，构造经显式 funnel；不序列化到 wire。
//!
//! 新增 secret 引用类型（`SecretKey`/`SecretRef`/`StoreId`/`SecretEntry`/`SecretRepoError`），
//! 材料永不落库——只存「外部 store 引用坐标」（#1274 批次①）。
//!
//! # 实现状态
//!
//! 域行为已写实（issue #1013）：newtype 校验 funnel、CAS 版本号与 `diff`。`SettingKey` / `ConfigEntry` /
//! `SettingsError` 为 `pub`——出现在公开 [`crate::ports::ConfigRepo`] 签名（域形 port，
//! ADR-005 Option 2）；字段仍私有、构造仍经 `pub(crate)` funnel（外部可命名/收发、不可伪造）。
//!
//! # 对标
//!
//! ref: etcd-io/etcd api/etcdserverpb/rpc.proto@main
//! 采纳版本化配置的强类型 CAS 模型；域类型不派生 wire 序列化。

// ---------------------------------------------------------------------------
// SettingKey
// ---------------------------------------------------------------------------

/// 防 key 无界膨胀进 DB/event_id。
const MAX_KEY_LEN: usize = 256;

/// 配置键 newtype（私有字段；构造经 `parse` funnel；含 namespace 校验）。
///
/// 格式要求：`<namespace>.<key>`，两段均非空，字符集 `[a-zA-Z0-9_-]`。
/// 非法格式从类型层不可表达——只能经 `parse` 进入（ADR-004 newtype funnel）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SettingKey(String);

impl SettingKey {
    /// 解析并校验配置键格式（`<namespace>.<key>`，恰两段、均非空、字符集 `[a-zA-Z0-9_-]`）；并拒敏感命名空间。
    pub fn parse(raw: &str) -> Result<Self, SettingsError> {
        if raw.len() > MAX_KEY_LEN {
            return Err(SettingsError::KeyInvalid);
        }
        let mut segments = raw.split('.');
        let (Some(namespace), Some(key), None) =
            (segments.next(), segments.next(), segments.next())
        else {
            return Err(SettingsError::KeyInvalid);
        };
        if !is_key_segment(namespace) || !is_key_segment(key) {
            return Err(SettingsError::KeyInvalid);
        }
        // 敏感 namespace 守卫（#1249 F2）：settings 明文落库不承载 secret——key 命中敏感词即拒（fail-closed）。
        if is_sensitive_key(raw) {
            return Err(SettingsError::SensitiveKey);
        }
        Ok(Self(raw.to_string()))
    }

    /// 取键字符串引用。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 配置键段字符集：非空 + `[a-zA-Z0-9_-]`。
fn is_key_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
}

/// 敏感配置键守卫（#1249 F2）：settings 配置值明文落库（postgres `config_entries.value text`），故**禁止**
/// 承载 secret——key 任一处含 `secret`/`token`/`password`/`credential`（大小写不敏感子串）即拒。
///
/// fail-closed **宁误拒**：substring 匹配会过拒形似但非 secret 的 key（如 `app.token_bucket`），这是刻意的安全
/// 取舍（明文落库面零容忍）；合法 secret 经 AEAD 加密 / Vault reference 的彻底支持见 #1274（届时放开 + 加密
/// 存储）。守卫落在 `SettingKey::parse` 单一 newtype funnel（构造唯一入口，类型层不可绕过）。
fn is_sensitive_key(raw: &str) -> bool {
    const SENSITIVE: &[&str] = &["secret", "token", "password", "credential"];
    let lower = raw.to_ascii_lowercase();
    SENSITIVE.iter().any(|needle| lower.contains(needle))
}

// ---------------------------------------------------------------------------
// ConfigValue
// ---------------------------------------------------------------------------

/// 配置值 newtype（私有字段；opaque `String` 终态）。
///
/// ConfigValue 是不透明字节/字符串的封装——类型化解释（string / number / bool / JSON blob 等）
/// 由消费侧 typed getter 承担，不改 ConfigValue 本身（ADR-004 冻结终态，无破坏式修改计划）。
///
/// **`Debug` 已手动实现以 redact 值内容**——配置值可能含密钥/secret，不输出原始内容。
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ConfigValue(String);

impl std::fmt::Debug for ConfigValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConfigValue(<redacted>)")
    }
}

impl ConfigValue {
    /// 由原始字符串构造（opaque 终态；不在此做类型化解释）。
    pub(crate) fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// 取值字符串引用。
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// ConfigVersion
// ---------------------------------------------------------------------------

/// 配置条目版本 newtype（乐观并发；私有字段）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ConfigVersion(u64);

impl ConfigVersion {
    /// 由版本号构造。
    pub(crate) fn new(v: u64) -> Self {
        Self(v)
    }

    /// 取底层版本号。
    pub(crate) fn get(&self) -> u64 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// ConfigEntry
// ---------------------------------------------------------------------------

/// 单条配置条目（key + value + tenant + version；私有字段）。
///
/// `Debug` 输出经由字段类型传导：`ConfigValue` 已 redact，其余字段安全可输出。
#[derive(Debug, Clone)]
pub struct ConfigEntry {
    key: SettingKey,
    value: ConfigValue,
    tenant: vocab::TenantId,
    version: ConfigVersion,
}

/// 配置仓储当前版本头；显式区分活跃值与删除墓碑，避免调用方把 tombstone 当作不存在并重用版本号。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigHead {
    /// 当前最高版本是活跃配置。
    Active(u64),
    /// 当前最高版本是删除墓碑。
    Deleted(u64),
}

impl ConfigHead {
    /// 当前最高版本号（无论活跃或已删除）。
    pub fn version(self) -> u64 {
        match self {
            Self::Active(version) | Self::Deleted(version) => version,
        }
    }
}

/// 配置删除墓碑；不携带配置值，且版本必须由应用层从 [`ConfigHead`] 单调推进。
#[derive(Debug, Clone)]
pub struct ConfigTombstone {
    key: SettingKey,
    tenant: vocab::TenantId,
    version: ConfigVersion,
}

impl ConfigTombstone {
    pub(crate) fn new(key: SettingKey, tenant: vocab::TenantId, version: ConfigVersion) -> Self {
        Self {
            key,
            tenant,
            version,
        }
    }

    /// 供持久化 adapter / conformance fixture 重建 typed tombstone。
    pub fn hydrate(key: SettingKey, tenant: vocab::TenantId, version: u64) -> Self {
        Self::new(key, tenant, ConfigVersion::new(version))
    }

    /// 删除目标 key。
    pub fn key(&self) -> &SettingKey {
        &self.key
    }

    /// 删除目标租户。
    pub fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }

    /// 墓碑版本。
    pub fn version(&self) -> u64 {
        self.version.get()
    }
}

/// 唯一配置写模型；新增/回滚与删除都必须经同一个 co-transaction UoW。
#[derive(Debug, Clone)]
pub enum ConfigMutation {
    /// 写入活跃配置版本。
    Put(ConfigEntry),
    /// 写入删除墓碑。
    Delete(ConfigTombstone),
}

impl ConfigMutation {
    /// mutation 所属租户。
    pub fn tenant(&self) -> vocab::TenantId {
        match self {
            Self::Put(entry) => entry.tenant(),
            Self::Delete(tombstone) => tombstone.tenant(),
        }
    }

    /// mutation 的 key。
    pub fn key(&self) -> &SettingKey {
        match self {
            Self::Put(entry) => entry.key(),
            Self::Delete(tombstone) => tombstone.key(),
        }
    }

    /// mutation 版本。
    pub fn version(&self) -> u64 {
        match self {
            Self::Put(entry) => entry.version(),
            Self::Delete(tombstone) => tombstone.version(),
        }
    }
}

impl ConfigEntry {
    /// 构造配置条目（构造器必填参数；缺失即编译错误）。`pub(crate)` funnel：外部可收发不可伪造。
    pub(crate) fn new(
        key: SettingKey,
        value: ConfigValue,
        tenant: vocab::TenantId,
        version: ConfigVersion,
    ) -> Self {
        Self {
            key,
            value,
            tenant,
            version,
        }
    }

    /// 从受信源（adapter DB row）跨 crate 重建条目（受控构造 funnel：字段私有 + 经此入口，外部不可伪造）。
    ///
    /// adapter（如 postgres）从**已校验**持久化行 hydrate：`value` 为 opaque 原始串（不在此重新类型化解释）、
    /// `version` 为持久化版本号。与 [`ConfigEntry::new`] 同 funnel（私有字段），但 `pub` 供独立 adapter crate
    /// 跨 crate 构造（#1215 / ADR-005 Option 2：域形实体经域 crate `pub` 入口由 adapter 重建）。
    pub fn hydrate(
        key: SettingKey,
        value: impl Into<String>,
        tenant: vocab::TenantId,
        version: u64,
    ) -> Self {
        Self {
            key,
            value: ConfigValue::new(value),
            tenant,
            version: ConfigVersion::new(version),
        }
    }

    /// 取键引用（`SettingKey` 已 `pub`；出现在公开 [`crate::ports::ConfigRepo`] 签名 + adapter 持久化读取路径）。
    pub fn key(&self) -> &SettingKey {
        &self.key
    }

    /// 取配置值原始串（opaque；内部 `ConfigValue` newtype 不外泄——wire / adapter 面以裸 `&str` 表达）。
    pub fn value(&self) -> &str {
        self.value.as_str()
    }

    /// 取租户 ID。
    pub fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }

    /// 取版本号（wire / adapter 面以裸 `u64` 表达，不外泄内部 `ConfigVersion` newtype）。
    pub fn version(&self) -> u64 {
        self.version.get()
    }
}

// ---------------------------------------------------------------------------
// ConfigDelta
// ---------------------------------------------------------------------------

/// 两条 [`ConfigEntry`] 差异描述（diff 输出类型）。
///
/// `ValueChanged` 存 [`ConfigValue`] 而非裸 `String`——`ConfigValue` 的 redacted `Debug`
/// 自动传导，避免原始配置值（可能含密钥/secret）经 `{:?}` 泄漏（F3 安全修复）。
// reason: L0 纯逻辑 diff 的输出类型，当前仅 #[cfg(test)] 表驱动覆盖消费；value-changed 投影 consumer
// 接入待后续单元（projection #1122），非 test 编译暂无使用路径。
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ConfigDelta {
    /// 值无变化。
    Unchanged,
    /// 值发生变化（old/new 均为 `ConfigValue`，Debug 输出已 redact）。
    ValueChanged { old: ConfigValue, new: ConfigValue },
    /// key 或 tenant 不同——比较无意义（programming error）。
    KeyMismatch,
}

// ---------------------------------------------------------------------------
// Secret 引用模型（#1274 批次①）
// 材料永不落库——只存「外部 store 引用坐标」，材料在 diport::SecretResolver 调用栈内存活。
// ---------------------------------------------------------------------------

/// secret store 标识 newtype（单段非空 + `[a-zA-Z0-9_-]` 字符集 + 长度 ≤ `MAX_KEY_LEN`）。
///
/// 对标配置键的 `SettingKey` newtype funnel：单一构造入口 `parse`，非法值不可表达（ADR-004）。
#[derive(Clone, PartialEq, Eq, Hash, secure::Redact)]
pub struct StoreId(#[redact(sensitivity = internal)] String);

impl StoreId {
    /// 解析 store 标识（单段：非空 + `[a-zA-Z0-9_-]` + `len <= MAX_KEY_LEN`）。
    pub fn parse(raw: &str) -> Result<Self, SettingsError> {
        if raw.is_empty() || raw.len() > MAX_KEY_LEN || !is_key_segment(raw) {
            return Err(SettingsError::SecretRefInvalid);
        }
        Ok(Self(raw.to_string()))
    }

    /// 借出底层标识。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// secret 路径 newtype（两段 `<ns>.<key>`；**不**调用 `is_sensitive_key` 守卫）。
///
/// 注意：secret 路径是敏感命名 key 的合法归宿——`settings.config_entries` 明文落库不承载 secret，
/// 但 `secret_entries` 只存坐标引用（材料在 diport seam 解析）；故 secret key 命名不拒敏感词，
/// 与 [`SettingKey::parse`] 分叉。
#[derive(Clone, PartialEq, Eq, Hash, secure::Redact)]
pub struct SecretKey(#[redact(sensitivity = internal)] String);

impl SecretKey {
    /// 解析 secret 路径（两段 `<namespace>.<key>`，各段非空 + `[a-zA-Z0-9_-]`；**不**拒敏感词）。
    pub fn parse(raw: &str) -> Result<Self, SettingsError> {
        if raw.len() > MAX_KEY_LEN {
            return Err(SettingsError::SecretKeyInvalid);
        }
        let mut segments = raw.split('.');
        let (Some(namespace), Some(key), None) =
            (segments.next(), segments.next(), segments.next())
        else {
            return Err(SettingsError::SecretKeyInvalid);
        };
        if !is_key_segment(namespace) || !is_key_segment(key) {
            return Err(SettingsError::SecretKeyInvalid);
        }
        // is_sensitive_key 守卫**不**应用于 secret 路径——见 rustdoc 说明。
        Ok(Self(raw.to_string()))
    }

    /// 借出底层路径字符串。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 外部 secret store 的引用坐标（store_id + ref_key + optional version）。
///
/// **`Debug` 手动实现输出 `SecretRef(<redacted>)`**——坐标（store 标识 / 路径）可能内嵌
/// 租户 / 应用拓扑信息，经 Debug 进日志等同于路径泄漏。使用 accessor 方法读取具体字段。
/// 对齐 `diport::SecretCoordinate` / `ConfigValue` 脱敏范式（#1274 F3 安全修复）。
///
/// # Construction funnel
///
/// 跨 crate 只收已校验 [`SecretRef`]；[`SecretRef::parse`] 是唯一公开构造 funnel。
/// INVARIANT: SETTINGS-SECRET-REF-FUNNEL-01 { level = "Hard", exec = "native-compile", source = "code", native = "private fields, sole public SecretRef::parse, and hydrate accepting only SecretRef" } —— 不存在 stringly / 跳过校验的公开构造入口（#1329）。
#[derive(Clone, PartialEq, Eq)]
pub struct SecretRef {
    store_id: StoreId,
    key: String,
    version: Option<String>,
}

impl SecretRef {
    /// 解析并校验 secret 引用。`ref_key` 是 store 内**路径**（允许 `/` 分隔，与 adapter 按段解析同源，
    /// 见 `vault::secret_resolver`）：非空 + 无控制字符/空白 + `len <= MAX_KEY_LEN` + 每个 `/`-分段须
    /// 非空且非 `.` / `..`（路径穿越防御，**权威 funnel**——非法坐标从此不可表达）。`version` 若 Some
    /// 同样长度上限。
    ///
    /// INVARIANT: SETTINGS-SECRET-REF-FUNNEL-01 { level = "Hard", exec = "native-compile", source = "code", native = "private fields, sole public SecretRef::parse, and hydrate accepting only SecretRef" } —— 唯一公开构造入口；跨 crate / adapter hydrate 必须先经本 funnel。
    pub fn parse(
        store_id: StoreId,
        ref_key: &str,
        version: Option<&str>,
    ) -> Result<Self, SettingsError> {
        if ref_key.is_empty() || ref_key.len() > MAX_KEY_LEN {
            return Err(SettingsError::SecretRefInvalid);
        }
        // 宽松字符校验：无控制字符 / 无 ASCII 空白（允许 '/' 等路径分隔符）。
        if ref_key
            .chars()
            .any(|c| c.is_control() || c.is_ascii_whitespace())
        {
            return Err(SettingsError::SecretRefInvalid);
        }
        // 路径穿越防御（F1，权威坐标 funnel）：refKey 按 '/' 分段，每段须非空且非 '.' / '..'——
        // 杜绝 "myapp/../evil"、前导/尾随/连续 '/'（空段）。adapter 按段 push 时 '..' 会被 broker
        // 解释为上跳目录，故穿越在 domain parse 处 fail-closed（newtype funnel，Hard）。
        if ref_key
            .split('/')
            .any(|seg| seg.is_empty() || seg == "." || seg == "..")
        {
            return Err(SettingsError::SecretRefInvalid);
        }
        // version 与 ref_key 同字符集守卫（控制字符 / ASCII 空白拒绝）：防 `\r\n` 等经 adapter 拼入远端
        // 请求头 / URL 触发注入——secret-publish 路由（#1430）已使本 funnel wire-reachable，权威校验须自洽。
        if let Some(v) = version
            && (v.is_empty()
                || v.len() > MAX_KEY_LEN
                || v.chars().any(|c| c.is_control() || c.is_ascii_whitespace()))
        {
            return Err(SettingsError::SecretRefInvalid);
        }
        Ok(Self {
            store_id,
            key: ref_key.to_string(),
            version: version.map(|v| v.to_string()),
        })
    }

    /// 取 store 标识引用。
    pub fn store_id(&self) -> &StoreId {
        &self.store_id
    }

    /// 取 secret 路径引用（store 内的 key 路径）。
    pub fn ref_key(&self) -> &str {
        &self.key
    }

    /// 取版本引用（`None` 表示最新版）。
    pub fn ref_version(&self) -> Option<&str> {
        self.version.as_deref()
    }
}

impl std::fmt::Debug for SecretRef {
    /// PII 边界（对齐 diport::SecretCoordinate Debug 范式）：store_id / ref_key / version
    /// 可能含租户 / 应用标识 + Vault 路径（内部拓扑）⇒ 只输出固定占位，原文不经 Debug 泄漏。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretRef(<redacted>)")
    }
}

/// secret 条目版本 newtype（乐观并发；镜像 `ConfigVersion`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SecretVersion(u64);

impl SecretVersion {
    pub(crate) fn new(v: u64) -> Self {
        Self(v)
    }
    pub(crate) fn get(self) -> u64 {
        self.0
    }
}

/// 单条 secret 引用条目（key + secret_ref 坐标 + tenant + version；字段私有）。
///
/// **材料永不落库**：`SecretEntry` 只存坐标引用（`SecretRef`），material 由
/// [`diport::SecretResolver::resolve`] 在调用栈内获取，不持久化、不进 `SecretEntry` 字段。
#[derive(Debug, Clone)]
pub struct SecretEntry {
    key: SecretKey,
    secret_ref: SecretRef,
    tenant: vocab::TenantId,
    version: SecretVersion,
}

impl SecretEntry {
    /// 构造 secret 条目（构造器必填参数；`pub(crate)` funnel——外部可收发不可伪造）。
    pub(crate) fn new(
        key: SecretKey,
        secret_ref: SecretRef,
        tenant: vocab::TenantId,
        version: SecretVersion,
    ) -> Self {
        Self {
            key,
            secret_ref,
            tenant,
            version,
        }
    }

    /// 从已校验 [`SecretRef`] 跨 crate 重建条目（`pub` 供独立 adapter crate 使用）。
    ///
    /// 对齐 [`SecretEntry::new`]：直接存 `secret_ref`，不再接收 stringly 坐标。
    /// INVARIANT: SETTINGS-SECRET-REF-FUNNEL-01 { level = "Hard", exec = "native-compile", source = "code", native = "private fields, sole public SecretRef::parse, and hydrate accepting only SecretRef" } —— 调用方必须先经 [`SecretRef::parse`]（唯一公开构造 funnel）；本方法不二次校验。
    pub fn hydrate(
        key: SecretKey,
        secret_ref: SecretRef,
        tenant: vocab::TenantId,
        version: u64,
    ) -> Self {
        Self {
            key,
            secret_ref,
            tenant,
            version: SecretVersion::new(version),
        }
    }

    /// 取 secret 键引用。
    pub fn key(&self) -> &SecretKey {
        &self.key
    }

    /// 取 secret 引用坐标。
    pub fn secret_ref(&self) -> &SecretRef {
        &self.secret_ref
    }

    /// 取租户 ID。
    pub fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }

    /// 取版本号（wire / adapter 面以裸 `u64` 表达）。
    pub fn version(&self) -> u64 {
        self.version.get()
    }
}

/// secret 仓储端口错误（精确镜像 `ConfigRepoError`）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecretRepoError {
    /// 版本冲突（乐观并发写：entry.version() ≠ 当前最高版本 + 1）。
    #[error("secret version conflict")]
    VersionConflict,
    /// 底层存储错误（持久化失败；原始错误进 `#[source]`，不进 Display / wire）。
    #[error("secret storage error")]
    Storage(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// 计算两条配置条目的差异（纯函数，L0；key 或 tenant 不同返回 `KeyMismatch`）。
// reason: L0 纯逻辑，当前仅 #[cfg(test)] 表驱动覆盖；value-changed 投影 consumer 接入待后续单元
// （projection #1122），非 test 编译暂无使用路径。
#[allow(dead_code)]
pub(crate) fn diff(a: &ConfigEntry, b: &ConfigEntry) -> ConfigDelta {
    if a.key().as_str() != b.key().as_str() || a.tenant() != b.tenant() {
        return ConfigDelta::KeyMismatch;
    }
    if a.value() == b.value() {
        ConfigDelta::Unchanged
    } else {
        ConfigDelta::ValueChanged {
            old: ConfigValue::new(a.value()),
            new: ConfigValue::new(b.value()),
        }
    }
}

// ---------------------------------------------------------------------------
// 错误枚举
// ---------------------------------------------------------------------------

/// settings 域**校验**错误（库枚举；message 为 const 静态字面量）。出现在 `SettingKey::parse` 等 funnel 与
/// 公开 [`crate::ports::ConfigRepo`] 派生签名 ⇒ `pub`。仓储 / UoW 存储与并发错误见 [`ConfigRepoError`]（分层）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SettingsError {
    /// 配置键格式非法（namespace 校验未通过）。
    #[error("setting key is invalid")]
    KeyInvalid,
    /// 配置键命中敏感命名空间（secret/token/password/credential）——settings 明文落库不承载 secret（#1249 F2）。
    #[error(
        "setting key uses a sensitive namespace; store secrets in a secret store, not settings"
    )]
    SensitiveKey,
    /// secret key 格式非法（必须为 `<namespace>.<key>`，两段均非空 + `[a-zA-Z0-9_-]`）。
    #[error("secret key is invalid")]
    SecretKeyInvalid,
    /// secret 引用格式非法（store_id / ref_key / version 不符合约束）。
    #[error("secret reference is invalid")]
    SecretRefInvalid,
}

/// 配置仓储 / UoW 端口错误（[`crate::ports::ConfigRepo`] / [`crate::ports::ConfigUnitOfWork`] 返回）。
///
/// **业务错误与基础设施错误分层**（#1226）：[`ConfigRepoError::VersionConflict`] 是乐观并发 CAS 业务冲突
/// （读后重写重试可恢复）；[`ConfigRepoError::Storage`] 包底层持久化错误（如 sqlx），保留 `#[source]` 链供
/// 服务端日志（adapter 侧经 `secure::redact_error` 脱敏，永不进 wire）。域 crate **不依赖**具体存储 driver，
/// 故 `Storage` 持 `Box<dyn Error + Send + Sync>`——adapter 在边界把存储错误装箱注入（保留 source、零 sqlx 反向依赖）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigRepoError {
    /// 版本冲突（乐观并发写：`entry.version()` ≠ 当前最高版本 + 1）。
    #[error("config version conflict")]
    VersionConflict,
    /// 同一 event id 已持久化为不同稳定事实；不得按 CAS 版本冲突重试。
    #[error("config outbox fact conflict")]
    OutboxFactConflict(#[source] consistency::OutboxFactConflict),
    /// 字段保护 provider 不可用（KMS/KeyProvider 超时、不可达或配置拒绝），调用方可按基础设施错误处理。
    #[error("config value protection unavailable")]
    ProtectionUnavailable(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// 字段保护认证失败（AAD mismatch / 坏密文 / 坏 key ref / 存储 envelope 损坏），fail-closed。
    #[error("config value protection authentication failed")]
    ProtectionAuthFailure(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// 底层存储错误（持久化失败；原始错误进 `#[source]`，不进 Display / wire）。
    #[error("config storage error")]
    Storage(#[source] Box<dyn std::error::Error + Send + Sync>),
}

// ---------------------------------------------------------------------------
// 测试（L0 表驱动；底座域纯逻辑目标 ≥90%）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    const TENANT_A: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const TENANT_B: &str = "00000000-0000-4000-8000-000000000abc";

    // 测试 helper：解析已知合法常量 —— expect item-level carve-out（error-handling.md §Carve-out）。
    #[allow(clippy::expect_used)]
    fn tenant(raw: &str) -> vocab::TenantId {
        vocab::TenantId::parse(raw).expect("canonical uuid")
    }

    // --- SettingKey::parse -------------------------------------------------

    #[rstest]
    #[case("app.timeout", true)]
    #[case("ns_1.key-2", true)]
    #[case("App.Key", true)]
    #[case("nodot", false)]
    #[case("a.b.c", false)]
    #[case(".key", false)]
    #[case("ns.", false)]
    #[case("ns.k ey", false)]
    #[case("ns.k@y", false)]
    #[case("", false)]
    fn setting_key_parse_validates_two_segments(#[case] raw: &str, #[case] ok: bool) {
        assert_eq!(SettingKey::parse(raw).is_ok(), ok, "raw={raw}");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn setting_key_roundtrips_as_str() {
        let key = SettingKey::parse("app.timeout").expect("valid");
        assert_eq!(key.as_str(), "app.timeout");
    }

    // F2 守卫：格式合法但命中敏感命名空间（secret/token/password/credential，大小写不敏感子串）→ SensitiveKey。
    #[rstest]
    #[case("app.secret")] // 命中 "secret"
    #[case("db.password")] // 命中 "password"
    #[case("auth.token")] // 命中 "token"
    #[case("svc.credential")] // 命中 "credential"
    #[case("app.API_TOKEN")] // 大小写不敏感
    #[case("app.token_bucket")] // fail-closed 过拒（形似非 secret，刻意拒）
    fn setting_key_rejects_sensitive_namespace(#[case] raw: &str) {
        assert!(matches!(
            SettingKey::parse(raw),
            Err(SettingsError::SensitiveKey)
        ));
    }

    // 非敏感 key（含与敏感词无关字符）正常通过——守卫不误伤普通 key。
    #[rstest]
    #[case("app.timeout")]
    #[case("app.k")]
    #[case("ui.theme")]
    fn setting_key_accepts_non_sensitive(#[case] raw: &str) {
        assert!(SettingKey::parse(raw).is_ok());
    }

    // --- diff --------------------------------------------------------------

    #[allow(clippy::expect_used)]
    fn entry(key: &str, value: &str, t: &str, version: u64) -> ConfigEntry {
        ConfigEntry::new(
            SettingKey::parse(key).expect("valid key"),
            ConfigValue::new(value),
            tenant(t),
            ConfigVersion::new(version),
        )
    }

    #[test]
    fn diff_unchanged_when_value_equal() {
        let a = entry("app.k", "v1", TENANT_A, 1);
        let b = entry("app.k", "v1", TENANT_A, 2);
        assert_eq!(diff(&a, &b), ConfigDelta::Unchanged);
    }

    #[test]
    fn diff_value_changed() {
        let a = entry("app.k", "v1", TENANT_A, 1);
        let b = entry("app.k", "v2", TENANT_A, 2);
        assert_eq!(
            diff(&a, &b),
            ConfigDelta::ValueChanged {
                old: ConfigValue::new("v1"),
                new: ConfigValue::new("v2"),
            }
        );
    }

    #[test]
    fn diff_key_mismatch_on_different_key() {
        let a = entry("app.k1", "v", TENANT_A, 1);
        let b = entry("app.k2", "v", TENANT_A, 1);
        assert_eq!(diff(&a, &b), ConfigDelta::KeyMismatch);
    }

    #[test]
    fn diff_key_mismatch_on_different_tenant() {
        let a = entry("app.k", "v", TENANT_A, 1);
        let b = entry("app.k", "v", TENANT_B, 1);
        assert_eq!(diff(&a, &b), ConfigDelta::KeyMismatch);
    }

    #[test]
    fn config_value_debug_is_redacted() {
        let dbg = format!("{:?}", ConfigValue::new("super-secret"));
        assert!(!dbg.contains("super-secret"), "value leaked: {dbg}");
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn setting_key_max_len_rejected() {
        // 超过 MAX_KEY_LEN 的 key 应被拒。
        let long = format!("{}a.{}", "a".repeat(128), "b".repeat(128));
        assert!(long.len() > MAX_KEY_LEN);
        assert!(SettingKey::parse(&long).is_err(), "超长 key 应 KeyInvalid");
    }

    // --- SecretKey::parse -------------------------------------------------

    /// 合法两段 secret key（含敏感命名——secret path 刻意放开）→ Ok。
    #[rstest]
    #[case("vault.password")] // 含 "password"——secret path 不拒敏感词
    #[case("auth.token")] // 含 "token"——同上
    #[case("app.secret")] // 含 "secret"——同上
    #[case("ns1.key-2")]
    #[case("db.credentials")] // 含 "credential"——同上
    fn secret_key_accepts_sensitive_naming(#[case] raw: &str) {
        assert!(
            SecretKey::parse(raw).is_ok(),
            "secret key '{raw}' 应 Ok（不拒敏感词）"
        );
    }

    /// 非法格式 → `Err(SecretKeyInvalid)`。
    #[rstest]
    #[case("nodot")] // 单段
    #[case("")] // 空
    #[case("a.b.c")] // 三段
    #[case(".key")] // 首段空
    #[case("ns.")] // 尾段空
    #[case("ns.k ey")] // 含空白
    #[case("ns.k@y")] // 非法字符
    fn secret_key_rejects_invalid(#[case] raw: &str) {
        assert!(
            matches!(SecretKey::parse(raw), Err(SettingsError::SecretKeyInvalid)),
            "raw='{raw}' 应 SecretKeyInvalid"
        );
    }

    #[test]
    fn secret_key_rejects_over_max_len() {
        // 超过 MAX_KEY_LEN（256）应 SecretKeyInvalid。
        let long = format!("{}a.{}", "a".repeat(128), "b".repeat(128));
        assert!(long.len() > MAX_KEY_LEN);
        assert!(
            matches!(
                SecretKey::parse(&long),
                Err(SettingsError::SecretKeyInvalid)
            ),
            "超长 secret key 应 SecretKeyInvalid"
        );
    }

    /// 关键安全分叉锁：同一敏感 raw（`db.password`）在 SecretKey::parse 为 Ok，
    /// 在 SettingKey::parse 为 Err(SensitiveKey)——锁定两路行为对称互补。
    #[rstest]
    #[case("db.password")]
    #[case("auth.token")]
    #[case("app.secret")]
    fn secret_and_setting_key_parse_fork(#[case] raw: &str) {
        // secret 路径放开敏感词 → Ok
        assert!(
            SecretKey::parse(raw).is_ok(),
            "SecretKey::parse('{raw}') 应 Ok"
        );
        // config 路径仍拒敏感词 → SensitiveKey
        assert!(
            matches!(SettingKey::parse(raw), Err(SettingsError::SensitiveKey)),
            "SettingKey::parse('{raw}') 应 SensitiveKey"
        );
    }

    // --- StoreId::parse ---------------------------------------------------

    #[rstest]
    #[case("vault", true)]
    #[case("store1", true)]
    #[case("my-store", true)]
    #[case("", false)] // 空
    #[case("a.b", false)] // 含点（单段校验不允许）
    #[case("has space", false)] // 含空白
    fn store_id_parse_validates(#[case] raw: &str, #[case] ok: bool) {
        assert_eq!(StoreId::parse(raw).is_ok(), ok, "raw='{raw}'");
    }

    #[test]
    fn store_id_rejects_over_max_len() {
        let long = "a".repeat(MAX_KEY_LEN + 1);
        assert!(
            matches!(StoreId::parse(&long), Err(SettingsError::SecretRefInvalid)),
            "超长 store_id 应 SecretRefInvalid"
        );
    }

    // --- SecretRef::parse -------------------------------------------------

    #[allow(clippy::expect_used)]
    fn store(s: &str) -> StoreId {
        StoreId::parse(s).expect("valid store id")
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn secret_ref_parse_valid() {
        let sid = store("vault");
        let r = SecretRef::parse(sid, "db/password", Some("v1")).expect("valid ref");
        assert_eq!(r.store_id().as_str(), "vault");
        assert_eq!(r.ref_key(), "db/password");
        assert_eq!(r.ref_version(), Some("v1"));
    }

    #[test]
    fn secret_ref_parse_version_none_ok() {
        let sid = store("vault");
        assert!(SecretRef::parse(sid, "db/password", None).is_ok());
    }

    #[test]
    fn secret_ref_parse_empty_ref_key_err() {
        let sid = store("vault");
        assert!(
            matches!(
                SecretRef::parse(sid, "", None),
                Err(SettingsError::SecretRefInvalid)
            ),
            "空 ref_key 应 SecretRefInvalid"
        );
    }

    #[rstest]
    #[case("key with space")]
    #[case("key\twith\ttab")]
    #[case("key\nwith\nnewline")]
    fn secret_ref_parse_control_or_whitespace_in_key_err(#[case] bad_key: &str) {
        let sid = store("vault");
        assert!(
            matches!(
                SecretRef::parse(sid, bad_key, None),
                Err(SettingsError::SecretRefInvalid)
            ),
            "ref_key='{bad_key}' 应 SecretRefInvalid"
        );
    }

    /// version 与 ref_key 同字符集守卫（#1430）：含控制字符 / ASCII 空白的 refVersion → SecretRefInvalid，
    /// 防 `\r\n` 等经 adapter 拼入远端请求头注入。
    #[rstest]
    #[case("v 1")]
    #[case("v\t1")]
    #[case("v\r\n1")]
    fn secret_ref_parse_control_or_whitespace_in_version_err(#[case] bad_version: &str) {
        let sid = store("vault");
        assert!(
            matches!(
                SecretRef::parse(sid, "db/password", Some(bad_version)),
                Err(SettingsError::SecretRefInvalid)
            ),
            "refVersion='{bad_version}' 应 SecretRefInvalid"
        );
    }

    /// F1 路径穿越防御：refKey 含 `.` / `..` 分段或空段（前导/尾随/连续 '/'）→ SecretRefInvalid。
    /// adapter 按段 push 时 `..` 会被 broker 解释为上跳目录，故穿越在 domain parse 处 fail-closed。
    #[rstest]
    #[case("myapp/../evil")] // '..' 段
    #[case("../evil")] // 前导 '..'
    #[case("a/./b")] // '.' 段
    #[case(".")] // 仅 '.'
    #[case("..")] // 仅 '..'
    #[case("/leading")] // 前导 '/' → 空段
    #[case("trailing/")] // 尾随 '/' → 空段
    #[case("a//b")] // 连续 '/' → 空段
    fn secret_ref_parse_path_traversal_err(#[case] bad_key: &str) {
        let sid = store("vault");
        assert!(
            matches!(
                SecretRef::parse(sid, bad_key, None),
                Err(SettingsError::SecretRefInvalid)
            ),
            "穿越/空段 ref_key='{bad_key}' 应 SecretRefInvalid"
        );
    }

    /// Anti-vacuity：合法多段路径（含 '-' / '_' / '.' 在段内）应被接受——证明穿越守卫非恒拒。
    #[rstest]
    #[case("myapp/db-password")]
    #[case("team/tenant_a/api.key")]
    #[case("single")]
    fn secret_ref_parse_valid_path_ok(#[case] good_key: &str) {
        let sid = store("vault");
        assert!(
            SecretRef::parse(sid, good_key, None).is_ok(),
            "合法路径 ref_key='{good_key}' 应被接受"
        );
    }

    #[test]
    fn secret_ref_parse_empty_version_err() {
        let sid = store("vault");
        assert!(
            matches!(
                SecretRef::parse(sid, "db/password", Some("")),
                Err(SettingsError::SecretRefInvalid)
            ),
            "空 version 应 SecretRefInvalid"
        );
    }

    // --- SecretEntry::hydrate + accessors round-trip ----------------------

    #[test]
    #[allow(clippy::expect_used)]
    fn secret_entry_hydrate_accessors_roundtrip() {
        let key = SecretKey::parse("vault.db").expect("valid key");
        let sid = StoreId::parse("mystore").expect("valid store");
        let secret_ref =
            SecretRef::parse(sid, "path/to/secret", Some("v2")).expect("valid secret ref");
        let t = tenant(TENANT_A);
        let entry = SecretEntry::hydrate(key.clone(), secret_ref, t, 42);
        assert_eq!(entry.key().as_str(), "vault.db");
        assert_eq!(entry.secret_ref().ref_key(), "path/to/secret");
        assert_eq!(entry.secret_ref().store_id().as_str(), "mystore");
        assert_eq!(entry.secret_ref().ref_version(), Some("v2"));
        assert_eq!(entry.tenant(), t);
        assert_eq!(entry.version(), 42);
    }

    // --- SecretRef Debug 脱敏（Finding 3）--------------------------------

    /// SecretRef Debug 输出为 `SecretRef(<redacted>)`，不含 store_id / ref_key 明文。
    #[test]
    #[allow(clippy::expect_used)]
    fn secret_ref_debug_redacts() {
        let sid = StoreId::parse("my-secret-store").expect("valid");
        let r = SecretRef::parse(sid, "db/super-password", None).expect("valid ref");
        let dbg = format!("{r:?}");
        assert_eq!(dbg, "SecretRef(<redacted>)", "Debug 应完全脱敏: {dbg}");
        assert!(
            !dbg.contains("my-secret-store"),
            "store_id 不应出现在 Debug: {dbg}"
        );
        assert!(
            !dbg.contains("db/super-password"),
            "ref_key 不应出现在 Debug: {dbg}"
        );
        // anti-vacuity：明文确实在字段里（Store / key 取值存在）。
        assert_eq!(r.store_id().as_str(), "my-secret-store");
        assert_eq!(r.ref_key(), "db/super-password");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn store_id_debug_redacts() {
        fn assert_redact<T: secure::Redact>() {}
        assert_redact::<StoreId>();
        let value = StoreId::parse("store-debug-marker").expect("valid store id");
        assert_eq!(value.as_str(), "store-debug-marker");
        let dbg = format!("{value:?}");
        assert_eq!(dbg, "StoreId(<redacted>)");
        assert!(!dbg.contains("store-debug-marker"));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn secret_key_debug_redacts() {
        fn assert_redact<T: secure::Redact>() {}
        assert_redact::<SecretKey>();
        let value = SecretKey::parse("debug.secret_marker").expect("valid secret key");
        assert_eq!(value.as_str(), "debug.secret_marker");
        let dbg = format!("{value:?}");
        assert_eq!(dbg, "SecretKey(<redacted>)");
        assert!(!dbg.contains("debug.secret_marker"));
    }
}
