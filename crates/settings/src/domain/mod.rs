//! settings 域类型与纯逻辑（dylint 守护区：此模块内类型禁止 derive Serialize/Deserialize）。
//!
//! 所有类型字段私有，构造经显式 funnel；不序列化到 wire。
//!
//! 新增 secret 引用类型（`SecretKey`/`SecretRef`/`StoreId`/`SecretEntry`/`SecretRepoError`），
//! 材料永不落库——只存「外部 store 引用坐标」（#1274 批次①）。
//!
//! # 实现状态（RW-W 行为）
//!
//! 签名冻结（G0）已补真实行为（issue #1013）：newtype 校验 funnel、CAS 版本号、`diff` /
//! `evaluate_flag`（全 11 RolloutOperator + 百分比一致性哈希分桶）。`SettingKey` / `ConfigEntry` /
//! `SettingsError` 由 `pub(crate)` 升 `pub`——出现在公开 [`crate::ports::ConfigRepo`] 签名（域形 port，
//! ADR-005 Option 2）；字段仍私有、构造仍经 `pub(crate)` funnel（外部可命名/收发、不可伪造）。其余类型
//! （Flag* / Rollout* / ConfigValue / ConfigVersion）仅域内 + 内部 `FlagStore` 消费，保持 `pub(crate)`。
//!
//! # 对标
//!
//! ref: Unleash/unleash-types-rs src/client_features.rs@main
//! 采纳：`RolloutOperator::Unknown` 前向兼容、Constraint operator 集、Strategy 全约束 AND + 百分比分桶。
//! 偏离：unleash 裸 String + derive Serialize → RSS 强类型 newtype + 域类型不 derive Serialize；
//! 缺属性 fail-closed（不匹配），weight 0–1000 → 百分比 0–100。

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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StoreId(String);

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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretKey(String);

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

    /// 受信 DB 行 hydrate（不再校验——字段已来自持久化行）。`pub(crate)` funnel。
    pub(crate) fn from_parts(store_id: StoreId, key: String, version: Option<String>) -> Self {
        Self {
            store_id,
            key,
            version,
        }
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

    /// 从受信源（adapter DB row）跨 crate 重建条目（`pub` 供独立 adapter crate 使用；内部经
    /// `SecretRef::from_parts` 直构，不再校验——受信 DB 行）。
    pub fn hydrate(
        key: SecretKey,
        store_id: StoreId,
        ref_key: impl Into<String>,
        ref_version: Option<String>,
        tenant: vocab::TenantId,
        version: u64,
    ) -> Self {
        Self {
            key,
            secret_ref: SecretRef::from_parts(store_id, ref_key.into(), ref_version),
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

// ---------------------------------------------------------------------------
// FlagKey
// ---------------------------------------------------------------------------

/// feature flag 键 newtype（私有字段；构造经 `parse` funnel）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct FlagKey(String);

impl FlagKey {
    /// 解析 flag 键（非空，字符集 `[a-zA-Z0-9_.-]`）。
    pub(crate) fn parse(raw: &str) -> Result<Self, SettingsError> {
        if raw.len() > MAX_KEY_LEN {
            return Err(SettingsError::KeyInvalid);
        }
        let valid = !raw.is_empty()
            && raw
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
        if valid {
            Ok(Self(raw.to_string()))
        } else {
            Err(SettingsError::KeyInvalid)
        }
    }

    /// 取键字符串引用。
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// RolloutOperator
// ---------------------------------------------------------------------------

/// 灰度规则运算符（`#[non_exhaustive]` + `Unknown` 前向兼容变体；ref: unleash-types-rs client_features.rs）。
// reason: evaluate_flag 仅 match 读取各变体（L0 求值已交付）；变体**构造**由订阅缓存 consumer（#1120，
// 消费 flag.updated 事件填充 FlagState）/ 测试承担——本 PR 不落地 flag 写入路径，非 test lib 无构造路径。
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum RolloutOperator {
    /// 属性值在给定集合中。
    In,
    /// 属性值不在给定集合中。
    NotIn,
    /// 字符串前缀匹配。
    StrStartsWith,
    /// 字符串后缀匹配。
    StrEndsWith,
    /// 字符串包含。
    StrContains,
    /// 数值范围（`[min, max]`）。
    NumInRange,
    /// 语义版本大于等于。
    SemVerGte,
    /// 语义版本小于等于。
    SemVerLte,
    /// 日期时间在某时间点之后。
    DateAfter,
    /// 日期时间在某时间点之前。
    DateBefore,
    /// 未知运算符（前向兼容；ref: unleash-types-rs Unknown 变体）。求值恒不匹配（fail-closed）。
    Unknown,
}

// ---------------------------------------------------------------------------
// RolloutPercentage
// ---------------------------------------------------------------------------

/// 灰度百分比 newtype（`u16`，validate 0..=100；超界返 `SettingsError::PercentageOutOfRange`）。
///
/// ref: unleash-types-rs weight 整数范围（0–1000）→ RSS 用 0–100 更直观。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RolloutPercentage(u16);

impl RolloutPercentage {
    /// 构造（0..=100，超界返错误）。
    // reason: 百分比构造由 flag 写入路径（订阅缓存 consumer #1120 / 测试）承担；本 PR 求值侧只读 `get`，
    // 非 test lib 无构造路径（同 [`RolloutOperator`] 理由）。
    #[allow(dead_code)]
    pub(crate) fn new(pct: u16) -> Result<Self, SettingsError> {
        if pct <= 100 {
            Ok(Self(pct))
        } else {
            Err(SettingsError::PercentageOutOfRange)
        }
    }

    /// 解析字符串（等同于 `parse::<u16>()` + `new`；非数值 / 超界均返 `PercentageOutOfRange`）。
    // reason: 同 `new`——flag 写入路径构造，本 PR 求值侧不消费。
    #[allow(dead_code)]
    pub(crate) fn parse(raw: &str) -> Result<Self, SettingsError> {
        let pct = raw
            .parse::<u16>()
            .map_err(|_| SettingsError::PercentageOutOfRange)?;
        Self::new(pct)
    }

    /// 取底层值（0..=100）。
    pub(crate) fn get(&self) -> u16 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// RolloutRule
// ---------------------------------------------------------------------------

/// 单条灰度规则（constraint；ref: unleash-types-rs Constraint 形态）。
///
/// 字段私有，构造经位置参 funnel。
///
/// **`Debug` 已手动实现**——`values` 列表可能含用户/设备敏感属性值，只输出 `value_count`
/// 等非敏感摘要，不输出原始 values（F5 安全修复）。
#[derive(Clone)]
pub(crate) struct RolloutRule {
    /// 求值上下文属性名。
    context_field: String,
    operator: RolloutOperator,
    /// 参数值列表（string 形态；运算符语义决定解码方式）。
    values: Vec<String>,
}

impl std::fmt::Debug for RolloutRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RolloutRule")
            .field("context_field", &self.context_field)
            .field("operator", &self.operator)
            .field("value_count", &self.values.len())
            .finish()
    }
}

impl RolloutRule {
    /// 构造灰度规则（必填参数；缺失即编译错误）。
    // reason: 规则构造由 flag 写入路径（订阅缓存 consumer #1120 / 测试）承担；本 PR matches_rule 只读
    // accessor，非 test lib 无构造路径（同 [`RolloutOperator`] 理由）。
    #[allow(dead_code)]
    pub(crate) fn new(
        context_field: impl Into<String>,
        operator: RolloutOperator,
        values: Vec<String>,
    ) -> Self {
        Self {
            context_field: context_field.into(),
            operator,
            values,
        }
    }

    /// 取上下文属性名。
    pub(crate) fn context_field(&self) -> &str {
        &self.context_field
    }

    /// 取运算符。
    pub(crate) fn operator(&self) -> RolloutOperator {
        self.operator
    }

    /// 取参数值切片。
    pub(crate) fn values(&self) -> &[String] {
        &self.values
    }
}

// ---------------------------------------------------------------------------
// EvalContext
// ---------------------------------------------------------------------------

/// feature flag 求值上下文（携带调用方属性 kv 对）。
///
/// 字段私有，构造经位置参 funnel；属性 map 用 `Vec<(String, String)>` 保序、
/// 允许重复键（行为 PR 再决策是否改 HashMap）。
///
/// **`Debug` 已手动实现**——`attrs` 含 user/device/tenant/email 等 PII，只输出
/// `attr_count` 摘要，不输出原始键值（F5 安全修复）。
#[derive(Clone)]
pub(crate) struct EvalContext {
    /// 属性键值对（保序）。
    attrs: Vec<(String, String)>,
}

impl std::fmt::Debug for EvalContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvalContext")
            .field("attr_count", &self.attrs.len())
            .finish()
    }
}

impl EvalContext {
    /// 构造求值上下文（从属性切片）。
    pub(crate) fn new(attrs: &[(String, String)]) -> Self {
        Self {
            attrs: attrs.to_vec(),
        }
    }

    /// 按键取第一个匹配属性值（不存在返回 `None`）。
    pub(crate) fn get(&self, key: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// 返回属性切片。
    // reason: 公开求值上下文 accessor，当前仅 #[cfg(test)] 断言消费；W 投影 / handler 绑定接入待后续单元。
    #[allow(dead_code)]
    pub(crate) fn attrs(&self) -> &[(String, String)] {
        &self.attrs
    }
}

// ---------------------------------------------------------------------------
// FlagDecision
// ---------------------------------------------------------------------------

/// feature flag 求值决策（`#[non_exhaustive]`；闭值集含 Enabled/Disabled）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum FlagDecision {
    /// Flag 对该上下文启用。
    Enabled,
    /// Flag 对该上下文禁用。
    Disabled,
}

// ---------------------------------------------------------------------------
// FlagState
// ---------------------------------------------------------------------------

/// feature flag 完整状态快照（私有字段；不 derive Serialize）。
///
/// 字段私有，构造经位置参 funnel；`evaluate_flag` 消费此类型做决策。
#[derive(Debug, Clone)]
pub(crate) struct FlagState {
    key: FlagKey,
    /// flag 是否全局启用（优先于 rules）。
    enabled: bool,
    /// flag 数据是否陈旧（上游同步延迟时置 true）。
    stale: bool,
    /// 灰度规则列表（全部满足时生效；ref: unleash-types-rs Constraint 列表语义）。
    rules: Vec<RolloutRule>,
    /// 百分比灰度（`None` 表示不限制百分比）。
    percentage: Option<RolloutPercentage>,
}

impl FlagState {
    /// 构造 flag 状态快照（必填参数；缺失即编译错误）。
    // reason: flag 快照构造由订阅缓存 consumer（#1120，消费 flag.updated 事件填充）/ 测试承担；本 PR
    // evaluate_flag 只读 accessor 求值，非 test lib 无构造路径（同 [`RolloutOperator`] 理由）。
    #[allow(dead_code)]
    pub(crate) fn new(
        key: FlagKey,
        enabled: bool,
        stale: bool,
        rules: Vec<RolloutRule>,
        percentage: Option<RolloutPercentage>,
    ) -> Self {
        Self {
            key,
            enabled,
            stale,
            rules,
            percentage,
        }
    }

    /// 取 flag 键引用。
    pub(crate) fn key(&self) -> &FlagKey {
        &self.key
    }

    /// flag 是否全局启用。
    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }

    /// flag 数据是否陈旧。
    ///
    /// stale=true 时 evaluate_flag 仍返回确定性结果（不 fail-closed）；调用方如需陈旧降级须在上层自行检查。
    // reason: 陈旧标记 accessor，当前仅 #[cfg(test)] / 订阅缓存 consumer（#1120）消费；本 PR 求值不依赖
    // staleness（求值对陈旧快照仍确定性），非 test 编译暂无使用路径。
    #[allow(dead_code)]
    pub(crate) fn stale(&self) -> bool {
        self.stale
    }

    /// 取规则切片。
    pub(crate) fn rules(&self) -> &[RolloutRule] {
        &self.rules
    }

    /// 取百分比灰度（`None` 表示不限制）。
    pub(crate) fn percentage(&self) -> Option<&RolloutPercentage> {
        self.percentage.as_ref()
    }
}

// ---------------------------------------------------------------------------
// 纯逻辑函数（L0 本地计算）
// ---------------------------------------------------------------------------

/// 对 flag 状态与求值上下文计算决策（纯函数，L0）。
///
/// - `enabled=false` 直接返回 `Disabled`。
/// - 规则列表全部满足（AND）+ 百分比分桶通过 → `Enabled`，否则 `Disabled`。
/// - 缺上下文属性 / 解析失败 / `Unknown` 运算符 → 该规则不匹配（fail-closed）。
pub(crate) fn evaluate_flag(flag: &FlagState, ctx: &EvalContext) -> FlagDecision {
    if !flag.enabled() {
        return FlagDecision::Disabled;
    }
    if !flag.rules().iter().all(|rule| matches_rule(rule, ctx)) {
        return FlagDecision::Disabled;
    }
    if let Some(pct) = flag.percentage()
        && !passes_percentage(flag.key(), ctx, pct.get())
    {
        return FlagDecision::Disabled;
    }
    FlagDecision::Enabled
}

/// 单条规则求值：缺属性即不匹配（fail-closed），否则按运算符语义比较。
fn matches_rule(rule: &RolloutRule, ctx: &EvalContext) -> bool {
    let Some(actual) = ctx.get(rule.context_field()) else {
        return false;
    };
    let values = rule.values();
    match rule.operator() {
        RolloutOperator::In => values.iter().any(|v| v == actual),
        RolloutOperator::NotIn => !values.iter().any(|v| v == actual),
        RolloutOperator::StrStartsWith => values.iter().any(|v| actual.starts_with(v.as_str())),
        RolloutOperator::StrEndsWith => values.iter().any(|v| actual.ends_with(v.as_str())),
        RolloutOperator::StrContains => values.iter().any(|v| actual.contains(v.as_str())),
        RolloutOperator::NumInRange => num_in_range(actual, values),
        RolloutOperator::SemVerGte => cmp_semver(actual, values, true),
        RolloutOperator::SemVerLte => cmp_semver(actual, values, false),
        RolloutOperator::DateAfter => cmp_date(actual, values, true),
        RolloutOperator::DateBefore => cmp_date(actual, values, false),
        RolloutOperator::Unknown => false,
    }
}

/// `[min, max]` 闭区间数值匹配；values 非 2 元或任一解析失败 → false（fail-closed）。
fn num_in_range(actual: &str, values: &[String]) -> bool {
    let [min, max] = values else {
        return false;
    };
    let (Ok(actual), Ok(min), Ok(max)) = (
        actual.parse::<f64>(),
        min.parse::<f64>(),
        max.parse::<f64>(),
    ) else {
        return false;
    };
    min <= actual && actual <= max
}

/// 语义版本比较（`gte=true` → `actual >= values[0]`，否则 `<=`）；解析失败 / values 空 → false。
fn cmp_semver(actual: &str, values: &[String], gte: bool) -> bool {
    let Some(target) = values.first() else {
        return false;
    };
    let (Ok(actual), Ok(target)) = (
        semver::Version::parse(actual),
        semver::Version::parse(target),
    ) else {
        return false;
    };
    if gte {
        actual >= target
    } else {
        actual <= target
    }
}

/// RFC3339 日期比较（`after=true` → `actual > values[0]`，否则 `<`）；解析失败 / values 空 → false。
fn cmp_date(actual: &str, values: &[String], after: bool) -> bool {
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;
    let Some(target) = values.first() else {
        return false;
    };
    let (Ok(actual), Ok(target)) = (
        OffsetDateTime::parse(actual, &Rfc3339),
        OffsetDateTime::parse(target, &Rfc3339),
    ) else {
        return false;
    };
    if after {
        actual > target
    } else {
        actual < target
    }
}

/// flag 键 + sticky 标识的稳定哈希落桶 `[0,100)`，`< pct` 通过。
///
/// sticky 标识取上下文中首个出现的 [`STICKY_KEYS`]（user/device/session）；缺失则用空串（分桶仅由
/// flag 键决定）。确定性：同一 (flag, sticky) 在多次求值 / 多 flag 间稳定（一致性灰度体验）。
/// 哈希 = FNV-1a 64-bit（dep-free，确定性，golden 表测锁定），非加密用途。
fn passes_percentage(key: &FlagKey, ctx: &EvalContext, pct: u16) -> bool {
    let sticky = STICKY_KEYS.iter().find_map(|k| ctx.get(k)).unwrap_or("");
    let bucket = (fnv1a64(&format!("{}:{}", key.as_str(), sticky)) % 100) as u16;
    bucket < pct
}

/// 百分比分桶 sticky 标识优先级（首个出现者胜）。
const STICKY_KEYS: &[&str] = &[
    "userId",
    "user_id",
    "deviceId",
    "device_id",
    "sessionId",
    "session_id",
];

/// FNV-1a 64-bit offset basis。
const FNV1A64_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
/// FNV-1a 64-bit prime。
const FNV1A64_PRIME: u64 = 0x0000_0100_0000_01b3;

/// FNV-1a 64-bit 非加密稳定哈希（确定性、dep-free）。
fn fnv1a64(s: &str) -> u64 {
    let mut hash: u64 = FNV1A64_OFFSET_BASIS;
    for byte in s.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV1A64_PRIME);
    }
    hash
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
    /// 灰度百分比超出 0..=100 范围。
    #[error("percentage out of range; must be 0..=100")]
    PercentageOutOfRange,
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

    // --- FlagKey::parse ----------------------------------------------------

    #[rstest]
    #[case("new-checkout", true)]
    #[case("ui.v2_beta", true)]
    #[case("", false)]
    #[case("has space", false)]
    #[case("emoji😀", false)]
    fn flag_key_parse_validates_charset(#[case] raw: &str, #[case] ok: bool) {
        assert_eq!(FlagKey::parse(raw).is_ok(), ok, "raw={raw}");
    }

    // --- RolloutPercentage -------------------------------------------------

    #[rstest]
    #[case(0, true)]
    #[case(50, true)]
    #[case(100, true)]
    #[case(101, false)]
    #[case(1000, false)]
    fn rollout_percentage_new_bounds(#[case] pct: u16, #[case] ok: bool) {
        assert_eq!(RolloutPercentage::new(pct).is_ok(), ok);
    }

    #[rstest]
    #[case("0", true)]
    #[case("100", true)]
    #[case("101", false)]
    #[case("abc", false)]
    #[case("-1", false)]
    fn rollout_percentage_parse(#[case] raw: &str, #[case] ok: bool) {
        assert_eq!(RolloutPercentage::parse(raw).is_ok(), ok, "raw={raw}");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn rollout_percentage_get_roundtrips() {
        assert_eq!(RolloutPercentage::new(42).expect("ok").get(), 42);
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

    // --- evaluate_flag: enabled short-circuit ------------------------------

    #[allow(clippy::expect_used)]
    fn flag(enabled: bool, rules: Vec<RolloutRule>, pct: Option<u16>) -> FlagState {
        FlagState::new(
            FlagKey::parse("the-flag").expect("valid"),
            enabled,
            false,
            rules,
            pct.map(|p| RolloutPercentage::new(p).expect("valid pct")),
        )
    }

    fn ctx(pairs: &[(&str, &str)]) -> EvalContext {
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        EvalContext::new(&owned)
    }

    #[test]
    fn evaluate_disabled_flag_short_circuits() {
        let f = flag(false, vec![], None);
        assert_eq!(evaluate_flag(&f, &ctx(&[])), FlagDecision::Disabled);
    }

    #[test]
    fn evaluate_enabled_no_rules_no_pct() {
        let f = flag(true, vec![], None);
        assert_eq!(evaluate_flag(&f, &ctx(&[])), FlagDecision::Enabled);
    }

    #[test]
    fn evaluate_missing_attr_fails_closed() {
        let rule = RolloutRule::new("region", RolloutOperator::In, vec!["us".to_string()]);
        let f = flag(true, vec![rule], None);
        // 缺 region 属性 ⇒ 规则不匹配 ⇒ Disabled。
        assert_eq!(evaluate_flag(&f, &ctx(&[])), FlagDecision::Disabled);
    }

    // --- evaluate_flag: 全 11 operator（含 Unknown）-------------------------

    #[rstest]
    // In / NotIn
    #[case(RolloutOperator::In, vec!["us", "eu"], "region", "us", true)]
    #[case(RolloutOperator::In, vec!["us"], "region", "eu", false)]
    #[case(RolloutOperator::NotIn, vec!["us"], "region", "eu", true)]
    #[case(RolloutOperator::NotIn, vec!["us"], "region", "us", false)]
    // 字符串
    #[case(RolloutOperator::StrStartsWith, vec!["beta-"], "build", "beta-42", true)]
    #[case(RolloutOperator::StrStartsWith, vec!["beta-"], "build", "ga-42", false)]
    #[case(RolloutOperator::StrEndsWith, vec!["-ios"], "platform", "mobile-ios", true)]
    #[case(RolloutOperator::StrEndsWith, vec!["-ios"], "platform", "mobile-web", false)]
    #[case(RolloutOperator::StrContains, vec!["dev"], "channel", "internal-dev-ring", true)]
    #[case(RolloutOperator::StrContains, vec!["dev"], "channel", "prod", false)]
    // 数值范围
    #[case(RolloutOperator::NumInRange, vec!["1", "10"], "score", "5", true)]
    #[case(RolloutOperator::NumInRange, vec!["1", "10"], "score", "11", false)]
    #[case(RolloutOperator::NumInRange, vec!["1"], "score", "5", false)]
    #[case(RolloutOperator::NumInRange, vec!["1", "10"], "score", "x", false)]
    // NumInRange values=3元 false（三个元素不是 [min,max] 二元，fail-closed）
    #[case(RolloutOperator::NumInRange, vec!["1","10","20"], "score", "5", false)]
    // semver
    #[case(RolloutOperator::SemVerGte, vec!["1.2.0"], "appVer", "1.3.0", true)]
    #[case(RolloutOperator::SemVerGte, vec!["1.2.0"], "appVer", "1.1.0", false)]
    #[case(RolloutOperator::SemVerLte, vec!["2.0.0"], "appVer", "1.9.9", true)]
    #[case(RolloutOperator::SemVerLte, vec!["2.0.0"], "appVer", "2.0.1", false)]
    #[case(RolloutOperator::SemVerGte, vec!["1.2.0"], "appVer", "not-semver", false)]
    // SemVerGte/SemVerLte values=[] false case
    #[case(RolloutOperator::SemVerGte, vec![], "appVer", "1.0.0", false)]
    #[case(RolloutOperator::SemVerLte, vec![], "appVer", "1.0.0", false)]
    // 日期（RFC3339）
    #[case(RolloutOperator::DateAfter, vec!["2026-01-01T00:00:00Z"], "ts", "2026-06-01T00:00:00Z", true)]
    #[case(RolloutOperator::DateAfter, vec!["2026-01-01T00:00:00Z"], "ts", "2025-06-01T00:00:00Z", false)]
    #[case(RolloutOperator::DateBefore, vec!["2026-01-01T00:00:00Z"], "ts", "2025-06-01T00:00:00Z", true)]
    #[case(RolloutOperator::DateBefore, vec!["2026-01-01T00:00:00Z"], "ts", "bad-date", false)]
    // DateAfter/DateBefore values=[] false case
    #[case(RolloutOperator::DateAfter, vec![], "ts", "2026-06-01T00:00:00Z", false)]
    #[case(RolloutOperator::DateBefore, vec![], "ts", "2025-06-01T00:00:00Z", false)]
    // Unknown 前向兼容 ⇒ 永不匹配
    #[case(RolloutOperator::Unknown, vec!["x"], "k", "x", false)]
    fn evaluate_single_operator(
        #[case] op: RolloutOperator,
        #[case] values: Vec<&str>,
        #[case] field: &str,
        #[case] attr: &str,
        #[case] expect_enabled: bool,
    ) {
        let rule = RolloutRule::new(field, op, values.iter().map(|s| s.to_string()).collect());
        let f = flag(true, vec![rule], None);
        let want = if expect_enabled {
            FlagDecision::Enabled
        } else {
            FlagDecision::Disabled
        };
        assert_eq!(evaluate_flag(&f, &ctx(&[(field, attr)])), want);
    }

    #[test]
    fn evaluate_rules_are_anded() {
        let r1 = RolloutRule::new("region", RolloutOperator::In, vec!["us".to_string()]);
        let r2 = RolloutRule::new(
            "platform",
            RolloutOperator::StrEndsWith,
            vec!["-ios".to_string()],
        );
        let f = flag(true, vec![r1, r2], None);
        // 两规则都满足 → Enabled。
        assert_eq!(
            evaluate_flag(&f, &ctx(&[("region", "us"), ("platform", "x-ios")])),
            FlagDecision::Enabled
        );
        // 仅一条满足 → Disabled（AND）。
        assert_eq!(
            evaluate_flag(&f, &ctx(&[("region", "us"), ("platform", "x-web")])),
            FlagDecision::Disabled
        );
    }

    // --- 百分比一致性哈希分桶 ------------------------------------------------

    #[test]
    fn percentage_zero_disables_all() {
        let f = flag(true, vec![], Some(0));
        for user in ["u1", "u2", "u3", "u4", "u5"] {
            assert_eq!(
                evaluate_flag(&f, &ctx(&[("userId", user)])),
                FlagDecision::Disabled,
                "user={user}"
            );
        }
    }

    #[test]
    fn percentage_hundred_enables_all() {
        let f = flag(true, vec![], Some(100));
        for user in ["u1", "u2", "u3", "u4", "u5"] {
            assert_eq!(
                evaluate_flag(&f, &ctx(&[("userId", user)])),
                FlagDecision::Enabled,
                "user={user}"
            );
        }
    }

    #[test]
    fn percentage_bucketing_is_deterministic() {
        // 同一 (flag, userId) 多次求值结果稳定。
        let f = flag(true, vec![], Some(50));
        let first = evaluate_flag(&f, &ctx(&[("userId", "stable-user")]));
        for _ in 0..10 {
            assert_eq!(evaluate_flag(&f, &ctx(&[("userId", "stable-user")])), first);
        }
    }

    #[test]
    fn percentage_bucketing_distributes_roughly() {
        // 50% 分桶对大量用户应落在 enabled 数量的合理区间（非全 0 / 全 1，证明分桶非平凡）。
        let f = flag(true, vec![], Some(50));
        let enabled = (0..1000)
            .filter(|i| {
                evaluate_flag(&f, &ctx(&[("userId", &format!("user-{i}"))]))
                    == FlagDecision::Enabled
            })
            .count();
        assert!(
            (350..=650).contains(&enabled),
            "50% 分桶落 {enabled}/1000，超出合理区间"
        );
    }

    #[test]
    fn fnv1a64_is_stable_golden() {
        // golden：锁定 FNV-1a 实现不漂移（改算法即破，consistency 灰度体验保证）。
        assert_eq!(fnv1a64(""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a64("a"), 0xaf63_dc4c_8601_ec8c);
    }

    #[test]
    fn flag_state_accessors_roundtrip() {
        let f = flag(true, vec![], Some(30));
        assert!(f.enabled());
        assert!(!f.stale());
        assert_eq!(f.key().as_str(), "the-flag");
        assert!(f.rules().is_empty());
        assert_eq!(f.percentage().map(RolloutPercentage::get), Some(30));
    }

    #[test]
    fn eval_context_get_and_attrs() {
        let c = ctx(&[("a", "1"), ("b", "2")]);
        assert_eq!(c.get("a"), Some("1"));
        assert_eq!(c.get("missing"), None);
        assert_eq!(c.attrs().len(), 2);
    }

    #[test]
    fn rollout_rule_debug_redacts_values() {
        let rule = RolloutRule::new(
            "email",
            RolloutOperator::In,
            vec!["secret@x.com".to_string()],
        );
        let dbg = format!("{rule:?}");
        assert!(!dbg.contains("secret@x.com"), "values leaked: {dbg}");
        assert!(dbg.contains("value_count"));
    }

    #[test]
    fn eval_context_debug_redacts_attrs() {
        let dbg = format!("{:?}", ctx(&[("email", "a@b.com")]));
        assert!(!dbg.contains("a@b.com"), "attrs leaked: {dbg}");
        assert!(dbg.contains("attr_count"));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn percentage_no_sticky_attr_falls_back_to_flag_key() {
        // 空上下文（无 sticky 属性）⇒ 分桶仅由 flag key 决定 ⇒ 两次求值结果相等（确定性）。
        let f = flag(true, vec![], Some(50));
        let first = evaluate_flag(&f, &ctx(&[]));
        let second = evaluate_flag(&f, &ctx(&[]));
        assert_eq!(first, second, "无 sticky attr 时分桶应确定性");
    }

    #[test]
    fn setting_key_max_len_rejected() {
        // 超过 MAX_KEY_LEN 的 key 应被拒。
        let long = format!("{}a.{}", "a".repeat(128), "b".repeat(128));
        assert!(long.len() > MAX_KEY_LEN);
        assert!(SettingKey::parse(&long).is_err(), "超长 key 应 KeyInvalid");
    }

    #[test]
    fn flag_key_max_len_rejected() {
        let long = "a".repeat(MAX_KEY_LEN + 1);
        assert!(
            FlagKey::parse(&long).is_err(),
            "超长 flag key 应 KeyInvalid"
        );
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
        let t = tenant(TENANT_A);
        let entry = SecretEntry::hydrate(
            key.clone(),
            sid,
            "path/to/secret",
            Some("v2".to_string()),
            t,
            42,
        );
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
}
