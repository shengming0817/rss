//! HashiCorp Vault KV v2 secret 解析 adapter（`GET {addr}/v1/{store.mount}/data/{prefix}/{refKey…}`
//! → `diport::SecretMaterial`）。
//!
//! **坐标模型单源（per-store mount + refKey 路径）**：mount 与 key 前缀**只来自命中的
//! [`StoreBinding`]**（`(tenant, storeId)` allowlist 条目），无全局 mount——`(tenant, storeId)`
//! 唯一决定 `mount + prefix`（对标 external-secrets `SecretStoreRef` + Vault KV v2 `mountPath`）。
//! `coord.key()`（domain `SecretRef.refKey`，允许 `/`）是 store 内**路径**，按 `/` 逐段解析（与
//! domain 同源），非单段 leaf。
//!
//! **租户隔离（TenantStoreAllowlist，网络前 fail-closed）**：`resolve` 先查 allowlist；
//! 未命中直接返 `Forbidden`，不发任何 HTTP 请求；wrong-tenant 与 unknown-store 不可区分，
//! 不给租户提供拓扑 oracle。命中后的 Vault 401/403 是 provider credential/policy 故障，归类为
//! `StoreUnreachable`，不会伪装成本地 allowlist 拒绝。
//!
//! **KV v2 envelope**：成功 200 响应形如 `{"data":{"data":{"value":"..."}}}` 。adapter
//! 取内层 `data.data.value` 字段的 UTF-8 字节作为 secret 材料（约定 key = `"value"`，单一
//! 约定字段路径）。字段缺失 / 非字符串 → `NotFound`（畸形 kv 路径视作"未找到"）。
//!
//! **path-traversal 防御（分层 fail-closed）**：mount / prefix 的穿越段在
//! [`TenantStoreAllowlist::new`] 构造期拒（可信配置）；`coord.key()`（refKey）的穿越段
//! （`.` / `..` / 空段）在 domain `SecretRef::parse`（权威 funnel）+ 本 adapter resolve（defense-in-depth，
//! 零信任：coord 理论上可来自非 domain 路径）双重 fail-closed——命中即返 `NotFound`，不发网络请求。
//! 合法段经 `Url::path_segments_mut().push()` percent-encode（对标 transit.rs segment push 范式）。
//!
//! **日志脱敏**：tracing 字段只含低基数静态标签（`category`/`status`），绝不含 url / token /
//! 请求体 / 响应体 / secret 材料。
//!
//! ref: hashicorp/vault api/kv_v2.go（KV v2 `ReadSecretWithVersion`：
//! `GET {mount}/data/{path}?version={n}`）。

use std::collections::HashMap;
use std::time::Duration;

use diport::{
    ManagedResource, SecretCoordinate, SecretMaterial, SecretResolver, SecretResolverError,
    ShutdownError,
};
use vocab::TenantId;

use crate::{VaultBaseUrlError, VaultToken, validate_vault_base_url};

/// Vault token header（复用 transit 范式）。
const VAULT_TOKEN_HEADER: &str = "X-Vault-Token";
/// 诊断操作标签（低基数闭值集）。
const OP_KV_SEND: &str = "kv-send";
const OP_KV_READ: &str = "kv-read";

/// KV v2 envelope 中约定的 secret 字段名（`data.data.value`）。
///
/// reason: 约定单一字段 `"value"` 而非 `data.data` 整个 map 序列化——
/// 1. 简化反序列化路径（避免 HashMap<String,serde_json::Value> + 递归 / 类型断言）；
/// 2. 材料边界清晰（bytes = value 字符串的 UTF-8，无需决定 map→bytes 的编码策略）；
/// 3. 与 external-secrets 写入 Vault 的约定字段 `value` 对齐（生产惯例）。
///
/// 业务若存多字段 kv，可通过 `key` 坐标区分不同 secret path（而非同一 path 多字段），
/// 不需改 envelope 约定。
const KV_PAYLOAD_FIELD: &str = "value";

// ── 内部错误类型（不跨 port 边界，仅用于 sign_impl 同范式的状态映射） ──────────────────

/// KV v2 非 2xx 响应状态码诊断（内部，不进 wire，参见 transit::NonSuccessStatus 范式）。
#[derive(Debug, thiserror::Error)]
#[error("vault kv v2 returned non-success status")]
struct NonSuccessStatus(u16);

/// 响应 200 但 `data.data.value` 缺失 / 非字符串（畸形 kv 或约定字段不存在）。
#[derive(Debug, thiserror::Error)]
#[error("vault kv v2 response missing expected payload field")]
struct MissingPayloadField;

/// Reserved relative key resolved by the active Vault capability readiness sampler.
pub const SECRET_RESOLVER_READINESS_KEY: &str = ".rss-readiness";

/// One canonical, allowlisted readiness target derived from the authorization map itself.
#[derive(Clone, secure::Redact)]
pub struct SecretResolverReadinessTarget {
    #[redact(sensitivity = internal)]
    tenant: TenantId,
    #[redact(sensitivity = internal)]
    coordinate: SecretCoordinate,
}

impl SecretResolverReadinessTarget {
    /// Tenant whose explicit binding owns this canary target.
    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }

    /// Coordinate under the exact store alias/prefix authorized for the tenant.
    #[must_use]
    pub const fn coordinate(&self) -> &SecretCoordinate {
        &self.coordinate
    }
}

// ── TenantStoreAllowlist ───────────────────────────────────────────────────────────────────

/// 把 `(TenantId, store_id)` 解析成 KV 挂载点 + 前缀路径的静态映射。
///
/// **安全语义**：未命中 = 该租户无权访问该 store（`Forbidden`，网络前 fail-closed）。
/// 组合根构造时注入，运行期只读——线程安全无需锁。
///
/// # Invariant
///
/// 只能由 [`TenantStoreAllowlist::new`] 构造，且始终非空、没有重复 `(tenant, store)` 授权，
/// 不同 tenant 的规范化 Vault 物理命名空间互不重叠。同 tenant 可用多个显式 store alias
/// 指向同一命名空间。
#[derive(Debug)]
pub struct TenantStoreAllowlist {
    entries: HashMap<(TenantId, String), StoreBinding>,
}

/// 某 `(tenant, store_id)` 对应的 Vault KV v2 挂载点 + key 前缀（**坐标模型单源**——
/// resolve 时 URL 的 mount + prefix 只取此处，无全局 mount）。
///
/// `mount` 对应 `GET /v1/{mount}/data/...`（**load-bearing**：每次 resolve 由此构造 URL，
/// 见 [`kv_resolve_impl`]）；`kv_path_prefix` 是 key 路径前缀（如 `"tenant-a/"`），后接
/// `coord.key()` 的逐段路径。前缀可空字符串（无前缀直挂 key）。两者的穿越段均在
/// [`TenantStoreAllowlist::new`] 构造期拒。
#[derive(Clone, Debug)]
pub struct StoreBinding {
    /// Vault KV v2 mount 点（如 `"secret"` / `"team/secrets"`）；非空、各段非 `.` / `..`。
    pub mount: String,
    /// key 路径前缀（如 `"tenant-a/"` 或空字符串）。
    pub kv_path_prefix: String,
}

/// Construction errors owned exclusively by [`TenantStoreAllowlist`].
///
/// Keeping authorization-map invariants separate from resolver transport configuration lets
/// offline validation depend only on errors it can actually produce.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TenantStoreAllowlistError {
    /// allowlist 必须至少包含一个显式 binding。
    #[error("vault tenant store allowlist must not be empty")]
    EmptyStoreAllowlist,
    /// 同一 `(tenant, store)` 不得重复授权。
    #[error("vault tenant store allowlist contains a duplicate binding")]
    DuplicateStoreBinding,
    /// 不同 tenant 的 Vault 物理命名空间不得重叠。
    #[error("vault tenant store allowlist contains an overlapping cross-tenant namespace")]
    OverlappingTenantNamespace,
    /// KV v2 mount 为空。
    #[error("vault kv mount must not be empty (e.g. secret or team/secrets)")]
    EmptyMount,
    /// KV v2 mount 含非法 path 段（空段 / `.` / `..`）。
    #[error("vault kv mount has an invalid path segment (empty, '.', or '..')")]
    InvalidMountSegment,
    /// `StoreBinding.kv_path_prefix` 含非法 path 段（空段 / `.` / `..`，路径穿越风险）。
    #[error("store binding kv_path_prefix has an invalid path segment (empty, '.', or '..')")]
    InvalidPrefixSegment,
}

impl TenantStoreAllowlist {
    /// 由 `(tenant_id, store_id) -> StoreBinding` 条目构造 allowlist。
    ///
    /// **唯一不变式入口**：拒绝空集合、重复 `(tenant, store)`，并拒绝不同 tenant 在同一
    /// 规范化 mount 下拥有相同或互为祖先/后代的 prefix（空 prefix 覆盖整个 mount）。每条
    /// `StoreBinding` 的 `mount`（经 [`parse_kv_mount_segments`]：非空 + 各段非 `.` / `..`）与
    /// `kv_path_prefix`（经 [`parse_kv_prefix_segments`]：可空 + 各段非 `.` / `..` / 空）也在此
    /// 校验。运行期因此只消费已证明隔离的只读映射。
    pub fn new(
        entries: impl IntoIterator<Item = ((TenantId, String), StoreBinding)>,
    ) -> Result<Self, TenantStoreAllowlistError> {
        let mut map = HashMap::new();
        let mut namespaces: Vec<(TenantId, Vec<String>, Vec<String>)> = Vec::new();
        for ((tid, sid), mut binding) in entries {
            if map.contains_key(&(tid, sid.clone())) {
                return Err(TenantStoreAllowlistError::DuplicateStoreBinding);
            }

            let mount = parse_kv_mount_segments(&binding.mount)?;
            let prefix = parse_kv_prefix_segments(&binding.kv_path_prefix)?
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            if namespaces
                .iter()
                .any(|(other_tenant, other_mount, other_prefix)| {
                    *other_tenant != tid
                        && *other_mount == mount
                        && (prefix.starts_with(other_prefix) || other_prefix.starts_with(&prefix))
                })
            {
                return Err(TenantStoreAllowlistError::OverlappingTenantNamespace);
            }

            binding.mount = mount.join("/");
            binding.kv_path_prefix = prefix.join("/");
            namespaces.push((tid, mount, prefix));
            map.insert((tid, sid), binding);
        }
        if map.is_empty() {
            return Err(TenantStoreAllowlistError::EmptyStoreAllowlist);
        }
        Ok(Self { entries: map })
    }

    /// 按 `(tenant, store_id)` 查询 [`StoreBinding`]；未命中返 `None`（禁止访问）。
    pub fn lookup(&self, tenant: TenantId, store_id: &str) -> Option<&StoreBinding> {
        self.entries.get(&(tenant, store_id.to_string()))
    }

    fn readiness_targets(&self) -> Vec<SecretResolverReadinessTarget> {
        let mut targets = self
            .entries
            .keys()
            .map(|(tenant, store_id)| SecretResolverReadinessTarget {
                tenant: *tenant,
                coordinate: SecretCoordinate::new(
                    store_id.clone(),
                    SECRET_RESOLVER_READINESS_KEY,
                    None,
                ),
            })
            .collect::<Vec<_>>();
        targets.sort_by(|left, right| {
            left.tenant
                .to_string()
                .cmp(&right.tenant.to_string())
                .then_with(|| left.coordinate.store_id().cmp(right.coordinate.store_id()))
        });
        targets
    }
}

// ── VaultSecretResolver ───────────────────────────────────────────────────────────────────

/// HashiCorp Vault KV v2 secret 解析 adapter（`#[cfg(feature="backend")]`）。
///
/// **构造器**：
/// - [`new`](Self::new)——https-only（fail-fast）。
/// - `new_allow_http`——仅在 `test-support` / 本 crate 测试编译图中存在的 HTTP opt-in。
///
/// **必填位置参**（构造器缺失即编译错误）：`client` / `addr` / `token` / `timeout` / `stores`
/// 均为必填——符合 `rss` 构造器必填参数规范（non-Option 位置参，Hard）。**无全局 mount**——
/// mount 是 per-store 坐标，随 [`StoreBinding`] 注入（F1，坐标模型单源）。
pub struct VaultSecretResolver {
    client: reqwest::Client,
    base: reqwest::Url,
    token: VaultToken,
    timeout: Duration,
    stores: TenantStoreAllowlist,
}

/// 构造期配置校验错误（镜像 `VaultConfigError`，fail-fast 而非静默 noop）。
#[derive(Debug, thiserror::Error)]
pub enum VaultSecretResolverConfigError {
    /// Vault 地址为空。
    #[error("vault address must not be empty (expected base url, e.g. https://vault.example:8200)")]
    EmptyAddr,
    /// Vault 地址不是合法 URL。
    #[error("vault address is not a valid url (expected e.g. https://vault.example:8200)")]
    InvalidAddr,
    /// Vault 地址使用非 https scheme 且未经 `new_allow_http` 显式放行。
    #[error("vault address must use https; use new_allow_http for local dev http opt-in")]
    InsecureScheme,
    /// Vault token 为空。
    #[error(
        "vault token must not be empty (provide via composition root / Vault Agent, not hardcoded)"
    )]
    EmptyToken,
}

impl VaultSecretResolver {
    /// Derive every live capability canary from the same validated authorization map.
    #[must_use]
    pub fn readiness_targets(&self) -> Vec<SecretResolverReadinessTarget> {
        self.stores.readiness_targets()
    }

    /// 构造 KV v2 secret 解析 adapter（**https-only**）。`client` 由组合根预配置 TLS 后注入；
    /// `addr` 是 base URL；`timeout` 是请求级超时（必填）；`stores` 是租户 store allowlist（必填，
    /// 构造期注入）。mount 是 per-store 坐标（随 [`StoreBinding`]），不在此传全局 mount（F1）。
    pub fn new(
        client: reqwest::Client,
        addr: impl Into<String>,
        token: impl Into<String>,
        timeout: Duration,
        stores: TenantStoreAllowlist,
    ) -> Result<Self, VaultSecretResolverConfigError> {
        let token = VaultToken::new(token.into());
        Self::build(client, addr.into(), token, timeout, stores, false)
    }

    /// 同 [`new`](Self::new)，但**显式放行 http**——仅用于本地 dev / 集成测试（具名 typed opt-in，
    /// greppable；不降级 [`new`](Self::new) 的 https-only 强制）。
    #[cfg(any(test, feature = "test-support"))]
    pub fn new_allow_http(
        client: reqwest::Client,
        addr: impl Into<String>,
        token: impl Into<String>,
        timeout: Duration,
        stores: TenantStoreAllowlist,
    ) -> Result<Self, VaultSecretResolverConfigError> {
        let token = VaultToken::new(token.into());
        Self::build(client, addr.into(), token, timeout, stores, true)
    }

    fn build(
        client: reqwest::Client,
        addr: String,
        token: VaultToken,
        timeout: Duration,
        stores: TenantStoreAllowlist,
        allow_http: bool,
    ) -> Result<Self, VaultSecretResolverConfigError> {
        if token.as_str().trim().is_empty() {
            return Err(VaultSecretResolverConfigError::EmptyToken);
        }
        let base = validate_vault_base_url(&addr, allow_http).map_err(|error| match error {
            VaultBaseUrlError::Empty => VaultSecretResolverConfigError::EmptyAddr,
            VaultBaseUrlError::Invalid => VaultSecretResolverConfigError::InvalidAddr,
            VaultBaseUrlError::InsecureScheme => VaultSecretResolverConfigError::InsecureScheme,
        })?;
        Ok(Self {
            client,
            base,
            token,
            timeout,
            stores,
        })
    }
}

/// 把 KV mount 规范化为 path 段集（去首尾 `/` 后按 `/` 拆分），拒绝空段 / `.` / `..`。
fn parse_kv_mount_segments(mount: &str) -> Result<Vec<String>, TenantStoreAllowlistError> {
    let trimmed = mount.trim().trim_matches('/');
    if trimmed.is_empty() {
        return Err(TenantStoreAllowlistError::EmptyMount);
    }
    let mut segments = Vec::new();
    for segment in trimmed.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(TenantStoreAllowlistError::InvalidMountSegment);
        }
        segments.push(segment.to_string());
    }
    Ok(segments)
}

/// 把 `kv_path_prefix` 规范化为路径段集，拒绝 `.` / `..` / 空段（路径穿越防御）。
///
/// 允许空前缀（空字符串 → 返回空 Vec，表示无前缀直挂 key）；
/// 非空前缀每段经同等校验（对齐 [`parse_kv_mount_segments`]）。
fn parse_kv_prefix_segments(prefix: &str) -> Result<Vec<&str>, TenantStoreAllowlistError> {
    let trimmed = prefix.trim_matches('/');
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let mut segments = Vec::new();
    for segment in trimmed.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(TenantStoreAllowlistError::InvalidPrefixSegment);
        }
        segments.push(segment);
    }
    Ok(segments)
}

/// 错误日志分级（镜像 transit classify_status 范式）：`(低基数类别, 安全相关位)`。
/// 401/403 → error!（安全告警）；429/5xx → warn!（依赖 / 限流）；其余 → warn!（客户端错误）。
fn classify_kv_status(status: u16) -> (&'static str, bool) {
    match status {
        401 | 403 => ("auth_error", true),
        429 => ("rate_limited", false),
        s if s >= 500 => ("server_error", false),
        _ => ("client_error", false),
    }
}

/// 执行 Vault KV v2 GET 并解析材料。
///
/// URL 形如 `{base}/v1/{store.mount…}/data/{prefix_seg…}/{refKey_seg…}`；`?version=N` 当
/// `coord.version()` 为 `Some` 时附加。mount + prefix 取命中的 [`StoreBinding`]（F1 坐标模型单源，
/// 无全局 mount）；`coord.key()`（refKey）是 store 内路径，按 `/` 逐段解析（与 domain `SecretRef`
/// 允许 `/` 同源）。各段经 `path_segments_mut().push()` percent-encode；穿越段（`.` / `..` / 空）
/// fail-closed（domain parse 权威 + 此处 defense-in-depth）。
#[tracing::instrument(
    name = "vault.kv.resolve",
    skip_all,
    fields(resource = "vault", operation = "kv-resolve")
)]
async fn kv_resolve_impl(
    client: &reqwest::Client,
    base: &reqwest::Url,
    token: &str,
    binding: &StoreBinding,
    coord: &SecretCoordinate,
    timeout: Duration,
) -> Result<SecretMaterial, SecretResolverError> {
    // refKey 穿越 defense-in-depth（domain `SecretRef::parse` 已权威 fail-closed；此处再防——
    // 零信任：coord 理论上可来自非 domain 路径）。命中 '.' / '..' / 空段 → fail-closed `NotFound`
    // （坐标不指向合法 secret 位置），网络前拦截；不把穿越段 push 进 URL。
    if coord
        .key()
        .split('/')
        .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return Err(SecretResolverError::NotFound);
    }

    let mut url = base.clone();

    // 构造路径：/v1/{store.mount…}/data/{prefix_segs…}/{refKey_segs…}
    // 每段独立 push → percent-encode（防路径段注入 / 穿越）。
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|()| SecretResolverError::store_unreachable(MissingPayloadField))?;

        segments.pop_if_empty().push("v1");

        // per-store mount（binding.mount，已在 TenantStoreAllowlist::new 校验非空 + 非穿越段）。
        // 按 '/' 逐段 push（嵌套 mount 如 "team/secrets" 展成多段）。
        for seg in binding
            .mount
            .trim_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
        {
            segments.push(seg);
        }
        segments.push("data");

        // prefix 可能含 '/'（如 "tenant-a/"）。prefix 来自组合根可信配置，按 '/' 拆分逐段 push
        // （嵌套 prefix 如 "team/tenant-a" 展成多段；对标 parse_mount_segments 范式）。
        for seg in binding
            .kv_path_prefix
            .trim_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
        {
            segments.push(seg);
        }

        // refKey 是 store 内**路径**（domain `SecretRef` 允许 '/'）：按 '/' 逐段 push，每段独立
        // percent-encode（与 domain 坐标同源，F1）。穿越段已在函数入口 fail-closed，此处只 push
        // 合法非空段（如 "myapp/db-password" → .../myapp/db-password 嵌套路径）。
        for seg in coord.key().split('/') {
            segments.push(seg);
        }
    }

    // 附加 ?version=N（仅当 coord.version() 为 Some）。
    if let Some(ver) = coord.version() {
        url.query_pairs_mut().append_pair("version", ver);
    }

    let response = client
        .get(url)
        .header(VAULT_TOKEN_HEADER, token)
        .timeout(timeout)
        .send()
        .await
        .map_err(|e| kv_warn_and_wrap(OP_KV_SEND, e))?;

    let status = response.status();
    let code = status.as_u16();

    if !status.is_success() {
        let (category, security_relevant) = classify_kv_status(code);
        if security_relevant {
            tracing::error!(
                target: "vault",
                status = code,
                category,
                "vault kv v2 returned non-success status"
            );
        } else {
            tracing::warn!(
                target: "vault",
                status = code,
                category,
                "vault kv v2 returned non-success status"
            );
        }

        // 状态码语义映射（与任务规格对齐）：
        //   404 无 ?version → NotFound；404 有 version → VersionNotFound。
        //   401/403 → StoreUnreachable（provider credential / policy failure）。
        //   429/5xx → StoreUnreachable（fail-closed）。
        return match code {
            401 | 403 => Err(SecretResolverError::store_unreachable(NonSuccessStatus(
                code,
            ))),
            404 => {
                if coord.version().is_some() {
                    Err(SecretResolverError::VersionNotFound)
                } else {
                    Err(SecretResolverError::NotFound)
                }
            }
            429 => Err(SecretResolverError::store_unreachable(NonSuccessStatus(
                code,
            ))),
            _ if code >= 500 => Err(SecretResolverError::store_unreachable(NonSuccessStatus(
                code,
            ))),
            _ => Err(SecretResolverError::NotFound),
        };
    }

    let body = response
        .bytes()
        .await
        .map_err(|e| kv_warn_and_wrap(OP_KV_READ, e))?;

    parse_kv_response(&body)
}

/// reqwest 错误 → `SecretResolverError`（低基数日志 + fail-closed 包装）。
/// timeout → `Timeout`；connect / 其余 → `StoreUnreachable`（不打印 Display，
/// 杜绝 endpoint URL 进日志——比泛 adapter 的 `redact_error(Display)` funnel 更保守）。
fn kv_warn_and_wrap(operation: &str, err: reqwest::Error) -> SecretResolverError {
    let category = classify_kv_reqwest_error(&err);
    tracing::warn!(
        target: "vault",
        operation = operation,
        category,
        "vault kv v2 request failed"
    );
    if err.is_timeout() {
        SecretResolverError::Timeout
    } else {
        SecretResolverError::store_unreachable(err)
    }
}

/// reqwest 错误四元谓词 → 低基数静态标签（无 `Display`，防 URL 泄漏）。
fn classify_kv_reqwest_error(err: &reqwest::Error) -> &'static str {
    if err.is_timeout() {
        "timeout"
    } else if err.is_connect() {
        "connect"
    } else if err.is_decode() {
        "decode"
    } else if err.is_request() {
        "request"
    } else {
        "other"
    }
}

/// 解析 KV v2 成功响应 `{"data":{"data":{"value":"..."}}}` → `SecretMaterial`。
///
/// 取 `data.data.value` 字段（字符串，UTF-8 bytes）。缺失 / 非字符串 → `NotFound`
/// （畸形 kv path 视作"未找到"；不反序列化 vault 错误体）。
fn parse_kv_response(body: &[u8]) -> Result<SecretMaterial, SecretResolverError> {
    #[derive(serde::Deserialize)]
    struct Outer {
        // reason: 只反序列化 data.data.value；Vault 错误体 `{"errors":[..]}` 内容刻意不
        // 反序列化（可能含 policy / mount 名等拓扑信息）——非 2xx 已由调用方提前 reject，
        // 畸形 2xx（缺 data / value）落 MissingPayloadField → NotFound。
        data: Option<Inner>,
    }
    #[derive(serde::Deserialize)]
    struct Inner {
        data: Option<serde_json::Value>,
    }

    let envelope: Outer =
        serde_json::from_slice(body).map_err(|_| SecretResolverError::NotFound)?;

    let value_str = envelope
        .data
        .and_then(|inner| inner.data)
        .and_then(|map| map.get(KV_PAYLOAD_FIELD).cloned())
        .and_then(|v| v.as_str().map(|s| s.to_string()));

    match value_str {
        Some(s) => Ok(SecretMaterial::new(s.into_bytes())),
        None => Err(SecretResolverError::NotFound),
    }
}

// ── diport trait impls ────────────────────────────────────────────────────────────────────

impl ManagedResource for VaultSecretResolver {
    fn name(&self) -> &str {
        "vault-secret-resolver"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        // reason: reqwest::Client 无显式 close——连接池随 drop 静默释放。KV v2 是短暂 HTTP 调用
        // （无长连接 streaming / in-flight 长任务），无 graceful drain 需求，故 shutdown 即 Ok。
        Ok(())
    }
}

impl SecretResolver for VaultSecretResolver {
    async fn resolve(
        &self,
        tenant: TenantId,
        coord: &SecretCoordinate,
    ) -> Result<SecretMaterial, SecretResolverError> {
        // 安全：先查 allowlist——未命中直接 Forbidden，不发网络请求（不给租户拓扑 oracle）。
        let binding = self
            .stores
            .lookup(tenant, coord.store_id())
            .ok_or(SecretResolverError::Forbidden)?;

        kv_resolve_impl(
            &self.client,
            &self.base,
            self.token.as_str(),
            binding,
            coord,
            self.timeout,
        )
        .await
    }
}

// ── 纯函数单测（无 live 后端）────────────────────────────────────────────────────────────

#[cfg(test)]
mod unit_tests {
    use super::{classify_kv_status, parse_kv_response};
    use diport::SecretResolverError;

    // ── classify_kv_status ──────────────────────────────────────────────────────────────

    #[test]
    fn classify_status_maps_to_low_cardinality_category_and_severity() {
        let cases = [
            (401u16, "auth_error", true),
            (403, "auth_error", true),
            (429, "rate_limited", false),
            (500, "server_error", false),
            (503, "server_error", false),
            (404, "client_error", false),
            (400, "client_error", false),
            (418, "client_error", false),
        ];
        for (status, category, security) in cases {
            assert_eq!(
                classify_kv_status(status),
                (category, security),
                "status {status}"
            );
        }
    }

    // ── parse_kv_response ────────────────────────────────────────────────────────────────

    #[test]
    #[allow(clippy::expect_used)]
    fn parse_kv_ok_extracts_value_bytes() {
        let body = br#"{"data":{"data":{"value":"s3cr3t"}}}"#;
        let material = parse_kv_response(body).expect("should succeed");
        assert_eq!(material.expose(), b"s3cr3t");
    }

    #[test]
    fn parse_kv_missing_value_field_is_not_found() {
        let body = br#"{"data":{"data":{"other":"x"}}}"#;
        assert!(matches!(
            parse_kv_response(body),
            Err(SecretResolverError::NotFound)
        ));
    }

    #[test]
    fn parse_kv_data_null_is_not_found() {
        let body = br#"{"data":{"data":null}}"#;
        assert!(matches!(
            parse_kv_response(body),
            Err(SecretResolverError::NotFound)
        ));
    }

    #[test]
    fn parse_kv_outer_data_null_is_not_found() {
        let body = br#"{"data":null}"#;
        assert!(matches!(
            parse_kv_response(body),
            Err(SecretResolverError::NotFound)
        ));
    }

    #[test]
    fn parse_kv_vault_errors_envelope_is_not_found() {
        // Vault 错误体（`{"errors":[..]}`，无 data）→ NotFound（不反序列化错误内容）。
        let body = br#"{"errors":["permission denied"]}"#;
        assert!(matches!(
            parse_kv_response(body),
            Err(SecretResolverError::NotFound)
        ));
    }

    #[test]
    fn parse_kv_malformed_json_is_not_found() {
        assert!(matches!(
            parse_kv_response(b"not json"),
            Err(SecretResolverError::NotFound)
        ));
    }

    #[test]
    fn parse_kv_value_non_string_is_not_found() {
        // value 是数值而非字符串 → as_str() None → NotFound。
        let body = br#"{"data":{"data":{"value":42}}}"#;
        assert!(matches!(
            parse_kv_response(body),
            Err(SecretResolverError::NotFound)
        ));
    }
}

// ── wiremock 集成测试（backend feature）────────────────────────────────────────────────────

#[cfg(all(test, feature = "backend"))]
mod backend_tests {
    use std::time::Duration;

    use super::{
        StoreBinding, TenantStoreAllowlist, TenantStoreAllowlistError, VaultSecretResolver,
        VaultSecretResolverConfigError,
    };
    use diport::{ManagedResource, SecretCoordinate, SecretResolver, SecretResolverError};
    use vocab::TenantId;

    // ── 常量 / helper ───────────────────────────────────────────────────────────────────

    const ADDR: &str = "https://vault.example:8200";
    const TOKEN: &str = "s.testtoken";
    const TIMEOUT: Duration = Duration::from_secs(30);

    #[allow(clippy::expect_used)]
    fn tenant_a() -> TenantId {
        TenantId::parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").expect("canonical uuid")
    }

    #[allow(clippy::expect_used)]
    fn tenant_b() -> TenantId {
        TenantId::parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").expect("canonical uuid")
    }

    fn store_x() -> &'static str {
        "storeX"
    }

    #[allow(clippy::expect_used)]
    fn simple_allowlist() -> TenantStoreAllowlist {
        TenantStoreAllowlist::new([(
            (tenant_a(), store_x().to_string()),
            StoreBinding {
                mount: "secret".to_string(),
                kv_path_prefix: String::new(),
            },
        )])
        .expect("valid simple allowlist")
    }

    /// 指向被拒端口的 base URL（用于 StoreUnreachable 测试，镜像 transit.rs refused_base）。
    #[allow(clippy::expect_used)]
    fn refused_base() -> reqwest::Url {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener);
        reqwest::Url::parse(&format!("http://127.0.0.1:{port}/")).expect("valid base url")
    }

    #[allow(clippy::expect_used)]
    async fn single_request(server: &wiremock::MockServer) -> wiremock::Request {
        let mut reqs = server
            .received_requests()
            .await
            .expect("wiremock request recording enabled");
        assert_eq!(reqs.len(), 1, "exactly one request expected");
        reqs.remove(0)
    }

    // ── ctor fail-fast ──────────────────────────────────────────────────────────────────

    #[test]
    fn new_rejects_empty_addr() {
        assert!(matches!(
            VaultSecretResolver::new(
                reqwest::Client::new(),
                "",
                TOKEN,
                TIMEOUT,
                simple_allowlist()
            ),
            Err(VaultSecretResolverConfigError::EmptyAddr)
        ));
    }

    #[test]
    fn new_rejects_invalid_url() {
        assert!(matches!(
            VaultSecretResolver::new(
                reqwest::Client::new(),
                "not a url",
                TOKEN,
                TIMEOUT,
                simple_allowlist()
            ),
            Err(VaultSecretResolverConfigError::InvalidAddr)
        ));
    }

    #[test]
    fn new_rejects_sensitive_base_url_components_without_disclosure() {
        const MARKER: &str = "vault-url-secret-marker";
        for addr in [
            "https://vault-url-secret-marker@vault.example:8200",
            "https://vault.example:8200?token=vault-url-secret-marker",
            "https://vault.example:8200#vault-url-secret-marker",
        ] {
            let result = VaultSecretResolver::new(
                reqwest::Client::new(),
                addr,
                TOKEN,
                TIMEOUT,
                simple_allowlist(),
            );
            assert!(matches!(
                &result,
                Err(VaultSecretResolverConfigError::InvalidAddr)
            ));
            if let Err(error) = result {
                let rendered = format!("{error:?} {error}");
                assert!(!rendered.contains(MARKER), "error must be value-free");
            }
        }
    }

    #[test]
    fn new_rejects_http_scheme() {
        assert!(matches!(
            VaultSecretResolver::new(
                reqwest::Client::new(),
                "http://vault.example:8200",
                TOKEN,
                TIMEOUT,
                simple_allowlist()
            ),
            Err(VaultSecretResolverConfigError::InsecureScheme)
        ));
    }

    #[test]
    fn new_allow_http_accepts_http() {
        assert!(
            VaultSecretResolver::new_allow_http(
                reqwest::Client::new(),
                "http://127.0.0.1:8200",
                TOKEN,
                TIMEOUT,
                simple_allowlist()
            )
            .is_ok()
        );
    }

    #[test]
    fn new_rejects_empty_token() {
        assert!(matches!(
            VaultSecretResolver::new(
                reqwest::Client::new(),
                ADDR,
                "",
                TIMEOUT,
                simple_allowlist()
            ),
            Err(VaultSecretResolverConfigError::EmptyToken)
        ));
    }

    /// F1：mount 是 per-store 坐标，校验从全局构造器迁到 `TenantStoreAllowlist::new`——
    /// 空 binding.mount → EmptyMount。
    #[test]
    fn allowlist_rejects_empty_binding_mount() {
        assert!(matches!(
            TenantStoreAllowlist::new([(
                (tenant_a(), store_x().to_string()),
                StoreBinding {
                    mount: String::new(),
                    kv_path_prefix: String::new(),
                },
            )]),
            Err(TenantStoreAllowlistError::EmptyMount)
        ));
    }

    /// F1：binding.mount 含穿越段（`secret/..`）→ InvalidMountSegment（构造期 fail-closed）。
    #[test]
    fn allowlist_rejects_binding_mount_path_traversal() {
        assert!(matches!(
            TenantStoreAllowlist::new([(
                (tenant_a(), store_x().to_string()),
                StoreBinding {
                    mount: "secret/..".to_string(),
                    kv_path_prefix: String::new(),
                },
            )]),
            Err(TenantStoreAllowlistError::InvalidMountSegment)
        ));
    }

    #[test]
    fn allowlist_rejects_empty_entries() {
        let result: Result<TenantStoreAllowlist, TenantStoreAllowlistError> =
            TenantStoreAllowlist::new(std::iter::empty());
        assert!(matches!(
            result,
            Err(TenantStoreAllowlistError::EmptyStoreAllowlist)
        ));
    }

    #[test]
    fn allowlist_rejects_duplicate_tenant_store_binding() {
        let binding = StoreBinding {
            mount: "secret".to_string(),
            kv_path_prefix: "tenants/a".to_string(),
        };
        assert!(matches!(
            TenantStoreAllowlist::new([
                ((tenant_a(), store_x().to_string()), binding.clone()),
                ((tenant_a(), store_x().to_string()), binding),
            ]),
            Err(TenantStoreAllowlistError::DuplicateStoreBinding)
        ));
    }

    #[test]
    fn allowlist_rejects_cross_tenant_namespace_overlap() {
        for (prefix_a, prefix_b) in [
            ("tenants/shared", "tenants/shared"),
            ("tenants/shared", "tenants/shared/nested"),
            ("tenants/shared/nested", "tenants/shared"),
            ("", "tenants/shared"),
        ] {
            let result = TenantStoreAllowlist::new([
                (
                    (tenant_a(), "store-a".to_string()),
                    StoreBinding {
                        mount: "/secret/".to_string(),
                        kv_path_prefix: prefix_a.to_string(),
                    },
                ),
                (
                    (tenant_b(), "store-b".to_string()),
                    StoreBinding {
                        mount: "secret".to_string(),
                        kv_path_prefix: prefix_b.to_string(),
                    },
                ),
            ]);
            assert!(
                matches!(
                    result,
                    Err(TenantStoreAllowlistError::OverlappingTenantNamespace)
                ),
                "cross-tenant overlap must fail for {prefix_a:?} and {prefix_b:?}: {result:?}"
            );
        }
    }

    #[test]
    fn allowlist_accepts_same_tenant_alias_overlap_and_cross_tenant_disjoint_namespaces() {
        let allowlist = TenantStoreAllowlist::new([
            (
                (tenant_a(), "store-a".to_string()),
                StoreBinding {
                    mount: "secret".to_string(),
                    kv_path_prefix: "tenants/a".to_string(),
                },
            ),
            (
                (tenant_a(), "store-a-alias".to_string()),
                StoreBinding {
                    mount: "/secret/".to_string(),
                    kv_path_prefix: "tenants/a/nested".to_string(),
                },
            ),
            (
                (tenant_b(), "store-b".to_string()),
                StoreBinding {
                    mount: "secret".to_string(),
                    kv_path_prefix: "tenants/b".to_string(),
                },
            ),
        ]);
        assert!(
            allowlist.is_ok(),
            "disjoint namespaces must pass: {allowlist:?}"
        );
    }

    #[test]
    fn new_accepts_valid_config() {
        assert!(
            VaultSecretResolver::new(
                reqwest::Client::new(),
                ADDR,
                TOKEN,
                TIMEOUT,
                simple_allowlist()
            )
            .is_ok()
        );
    }

    // ── 租户隔离（网络前 Forbidden）────────────────────────────────────────────────────────

    /// 已注册 (A, storeX)；用 tenant B 查 storeX → Forbidden，wiremock 零请求（网络前拒）。
    #[tokio::test]
    async fn tenant_isolation_rejected_wrong_tenant() {
        let server = wiremock::MockServer::start().await;
        // 注册 catch-all，任何请求都会被记录；确认 zero 请求即可。
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;

        #[allow(clippy::expect_used)]
        let resolver = VaultSecretResolver::new_allow_http(
            reqwest::Client::new(),
            server.uri(),
            TOKEN,
            TIMEOUT,
            simple_allowlist(),
        )
        .expect("valid config");

        let coord = SecretCoordinate::new(store_x(), "mykey", None);
        let result = resolver.resolve(tenant_b(), &coord).await;
        assert!(
            matches!(result, Err(SecretResolverError::Forbidden)),
            "expected Forbidden, got {result:?}"
        );
        let reqs = server.received_requests().await.unwrap_or_default();
        assert_eq!(
            reqs.len(),
            0,
            "must not send any network request before allowlist check"
        );
    }

    /// 已注册 (A, storeX)；用 tenant A 查 storeY（未登记）→ Forbidden，wiremock 零请求。
    #[tokio::test]
    async fn tenant_isolation_rejected_wrong_store() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;

        #[allow(clippy::expect_used)]
        let resolver = VaultSecretResolver::new_allow_http(
            reqwest::Client::new(),
            server.uri(),
            TOKEN,
            TIMEOUT,
            simple_allowlist(),
        )
        .expect("valid config");

        let coord = SecretCoordinate::new("storeY", "mykey", None);
        let result = resolver.resolve(tenant_a(), &coord).await;
        assert!(
            matches!(result, Err(SecretResolverError::Forbidden)),
            "expected Forbidden, got {result:?}"
        );
        let reqs = server.received_requests().await.unwrap_or_default();
        assert_eq!(
            reqs.len(),
            0,
            "must not send any network request before allowlist check"
        );
    }

    // ── KV happy path ───────────────────────────────────────────────────────────────────

    // expect carve-out 集中此处（error-handling.md §Carve-out，item-level）：happy path 断言 Ok 后
    // 再 .expect("ok") 取值；构造器期望合法配置成功。测试体不散落 `unwrap`。
    #[allow(clippy::expect_used)]
    #[tokio::test]
    async fn resolve_kv_happy_path_returns_material() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"data":{"data":{"value":"s3cr3t"}}}"#),
            )
            .mount(&server)
            .await;

        let resolver = VaultSecretResolver::new_allow_http(
            reqwest::Client::new(),
            server.uri(),
            TOKEN,
            Duration::from_secs(5),
            simple_allowlist(),
        )
        .expect("valid config");

        let coord = SecretCoordinate::new(store_x(), "mykey", None);
        let result = resolver.resolve(tenant_a(), &coord).await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        assert_eq!(result.expect("ok").expose(), b"s3cr3t");
    }

    // ── refKey 路径分段 + per-store mount + header（F1）──────────────────────────────────

    /// F1：refKey（store 内路径，含 `/`）按段展开为嵌套 path（**非**单段 `%2F` 编码），
    /// 且 X-Vault-Token header 存在。`myapp/db-password` → `/v1/secret/data/myapp/db-password`。
    #[tokio::test]
    async fn resolve_refkey_path_splits_into_segments_and_sends_token_header() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r#"{"data":{"data":{"value":"ok"}}}"#),
            )
            .mount(&server)
            .await;

        // allowlist：tenant_a + storeX → mount=secret, prefix 空。
        #[allow(clippy::expect_used)]
        let resolver = VaultSecretResolver::new_allow_http(
            reqwest::Client::new(),
            server.uri(),
            TOKEN,
            Duration::from_secs(5),
            simple_allowlist(),
        )
        .expect("valid config");

        let coord = SecretCoordinate::new(store_x(), "myapp/db-password", None);
        let result = resolver.resolve(tenant_a(), &coord).await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");

        let req = single_request(&server).await;
        let path = req.url.path();
        // 嵌套路径段（与 domain refKey '/' 同源）；绝不出现单段 %2F 编码。
        assert_eq!(
            path, "/v1/secret/data/myapp/db-password",
            "refKey '/' 应展为嵌套段（非 %2F 单段编码）; got path: {path}"
        );
        assert!(
            !path.contains("%2F"),
            "refKey 不应被编码成单段 %2F; got path: {path}"
        );
        assert_eq!(
            req.headers
                .get("X-Vault-Token")
                .and_then(|v| v.to_str().ok()),
            Some(TOKEN),
            "X-Vault-Token header must be present"
        );
    }

    /// F1：per-store `binding.mount` 进入 URL（嵌套 mount `team/secrets` → `/v1/team/secrets/data/...`）；
    /// 证明 mount 是 load-bearing 坐标（不再使用全局 mount）。
    #[tokio::test]
    async fn resolve_uses_per_store_binding_mount() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r#"{"data":{"data":{"value":"ok"}}}"#),
            )
            .mount(&server)
            .await;

        #[allow(clippy::expect_used)]
        let stores = TenantStoreAllowlist::new([(
            (tenant_a(), store_x().to_string()),
            StoreBinding {
                mount: "team/secrets".to_string(),
                kv_path_prefix: "tenant-a".to_string(),
            },
        )])
        .expect("valid allowlist");

        #[allow(clippy::expect_used)]
        let resolver = VaultSecretResolver::new_allow_http(
            reqwest::Client::new(),
            server.uri(),
            TOKEN,
            Duration::from_secs(5),
            stores,
        )
        .expect("valid config");

        let coord = SecretCoordinate::new(store_x(), "db", None);
        let result = resolver.resolve(tenant_a(), &coord).await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");

        let req = single_request(&server).await;
        assert_eq!(
            req.url.path(),
            "/v1/team/secrets/data/tenant-a/db",
            "per-store mount + prefix + refKey 应同源展为路径段; got: {}",
            req.url.path()
        );
    }

    /// F1 defense-in-depth：refKey 含穿越段（`../x`）→ resolve fail-closed `NotFound`，零网络请求。
    /// （domain `SecretRef::parse` 已权威拒；adapter 再防——零信任 coord 可能绕过 domain。）
    #[tokio::test]
    async fn resolve_traversal_refkey_fail_closed_not_found() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;

        #[allow(clippy::expect_used)]
        let resolver = VaultSecretResolver::new_allow_http(
            reqwest::Client::new(),
            server.uri(),
            TOKEN,
            Duration::from_secs(5),
            simple_allowlist(),
        )
        .expect("valid config");

        let coord = SecretCoordinate::new(store_x(), "../x", None);
        let result = resolver.resolve(tenant_a(), &coord).await;
        assert!(
            matches!(result, Err(SecretResolverError::NotFound)),
            "穿越 refKey 应 fail-closed NotFound, got {result:?}"
        );
        let reqs = server.received_requests().await.unwrap_or_default();
        assert_eq!(reqs.len(), 0, "穿越 refKey 不得发出网络请求（网络前拦截）");
    }

    // ── StoreUnreachable fail-closed ───────────────────────────────────────────────────

    #[tokio::test]
    async fn store_unreachable_fail_closed() {
        // allowlist 命中，但目标端口无监听 → connect 失败 → StoreUnreachable（无 panic / 无值）。
        let base = refused_base().to_string();

        #[allow(clippy::expect_used)]
        let allowlist = TenantStoreAllowlist::new([(
            (tenant_a(), store_x().to_string()),
            StoreBinding {
                mount: "secret".to_string(),
                kv_path_prefix: String::new(),
            },
        )])
        .expect("valid allowlist");

        #[allow(clippy::expect_used)]
        let resolver = VaultSecretResolver::new_allow_http(
            reqwest::Client::new(),
            &base,
            TOKEN,
            Duration::from_secs(5),
            allowlist,
        )
        .expect("valid config");

        let coord = SecretCoordinate::new(store_x(), "mykey", None);
        let result = resolver.resolve(tenant_a(), &coord).await;
        assert!(
            matches!(result, Err(SecretResolverError::StoreUnreachable { .. })),
            "expected StoreUnreachable, got {result:?}"
        );
    }

    // ── 状态码映射 ──────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn resolve_404_is_not_found() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        #[allow(clippy::expect_used)]
        let resolver = VaultSecretResolver::new_allow_http(
            reqwest::Client::new(),
            server.uri(),
            TOKEN,
            Duration::from_secs(5),
            simple_allowlist(),
        )
        .expect("valid config");

        let coord = SecretCoordinate::new(store_x(), "mykey", None);
        let result = resolver.resolve(tenant_a(), &coord).await;
        assert!(
            matches!(result, Err(SecretResolverError::NotFound)),
            "expected NotFound, got {result:?}"
        );
    }

    #[tokio::test]
    async fn resolve_provider_auth_failure_is_store_unreachable() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

        for status in [401, 403] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(status))
                .mount(&server)
                .await;

            #[allow(clippy::expect_used)]
            let resolver = VaultSecretResolver::new_allow_http(
                reqwest::Client::new(),
                server.uri(),
                TOKEN,
                Duration::from_secs(5),
                simple_allowlist(),
            )
            .expect("valid config");

            let coord = SecretCoordinate::new(store_x(), "mykey", None);
            let result = resolver.resolve(tenant_a(), &coord).await;
            assert!(
                matches!(result, Err(SecretResolverError::StoreUnreachable { .. })),
                "provider status {status} must be StoreUnreachable, got {result:?}"
            );
        }
    }

    /// 带 ?version 参数的 404 → VersionNotFound。
    #[tokio::test]
    async fn resolve_version_404_is_version_not_found() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        #[allow(clippy::expect_used)]
        let resolver = VaultSecretResolver::new_allow_http(
            reqwest::Client::new(),
            server.uri(),
            TOKEN,
            Duration::from_secs(5),
            simple_allowlist(),
        )
        .expect("valid config");

        // version = Some("3") → 404 应映射 VersionNotFound。
        let coord = SecretCoordinate::new(store_x(), "mykey", Some("3".to_string()));
        let result = resolver.resolve(tenant_a(), &coord).await;
        assert!(
            matches!(result, Err(SecretResolverError::VersionNotFound)),
            "expected VersionNotFound, got {result:?}"
        );
    }

    #[tokio::test]
    async fn resolve_500_is_store_unreachable() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        #[allow(clippy::expect_used)]
        let resolver = VaultSecretResolver::new_allow_http(
            reqwest::Client::new(),
            server.uri(),
            TOKEN,
            Duration::from_secs(5),
            simple_allowlist(),
        )
        .expect("valid config");

        let coord = SecretCoordinate::new(store_x(), "mykey", None);
        let result = resolver.resolve(tenant_a(), &coord).await;
        assert!(
            matches!(result, Err(SecretResolverError::StoreUnreachable { .. })),
            "expected StoreUnreachable, got {result:?}"
        );
    }

    /// wiremock delay > timeout → Err(Timeout)。
    #[tokio::test]
    async fn resolve_timeout_is_timeout() {
        use std::time::Duration;

        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_secs(10))
                    .set_body_string(r#"{"data":{"data":{"value":"x"}}}"#),
            )
            .mount(&server)
            .await;

        #[allow(clippy::expect_used)]
        let resolver = VaultSecretResolver::new_allow_http(
            reqwest::Client::new(),
            server.uri(),
            TOKEN,
            Duration::from_millis(50), // 极短 timeout → 必超时
            simple_allowlist(),
        )
        .expect("valid config");

        let coord = SecretCoordinate::new(store_x(), "mykey", None);
        let result = resolver.resolve(tenant_a(), &coord).await;
        assert!(
            matches!(result, Err(SecretResolverError::Timeout)),
            "expected Timeout, got {result:?}"
        );
    }

    // ── redaction ───────────────────────────────────────────────────────────────────────

    /// SecretMaterial Debug 不含明文（由 diport 类型保证；端到端验证材料已出 kv_resolve_impl）。
    // expect carve-out 集中此处（item-level）：构造器合法配置 + Ok resolve 后取材料。
    #[allow(clippy::expect_used)]
    #[tokio::test]
    async fn material_debug_does_not_expose_plaintext() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"data":{"data":{"value":"supersecret"}}}"#),
            )
            .mount(&server)
            .await;

        let resolver = VaultSecretResolver::new_allow_http(
            reqwest::Client::new(),
            server.uri(),
            TOKEN,
            Duration::from_secs(5),
            simple_allowlist(),
        )
        .expect("valid config");

        let coord = SecretCoordinate::new(store_x(), "mykey", None);
        let material = resolver.resolve(tenant_a(), &coord).await.expect("ok");
        let dbg = format!("{material:?}");
        assert_eq!(
            dbg, "SecretMaterial(<redacted>)",
            "material Debug must be opaque"
        );
        assert!(
            !dbg.contains("supersecret"),
            "Debug must not expose plaintext"
        );
    }

    // ── ManagedResource lifecycle ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn lifecycle_name_and_shutdown() {
        #[allow(clippy::expect_used)]
        let resolver = VaultSecretResolver::new(
            reqwest::Client::new(),
            ADDR,
            TOKEN,
            TIMEOUT,
            simple_allowlist(),
        )
        .expect("valid config");
        assert_eq!(ManagedResource::name(&resolver), "vault-secret-resolver");
        assert!(ManagedResource::shutdown(&resolver).await.is_ok());
    }

    // ── Finding 2 路径穿越防御 ─────────────────────────────────────────────────────────

    /// `StoreBinding.kv_path_prefix` 含 `..` / `.` / 空段 → `TenantStoreAllowlist::new` 失败。
    ///
    /// Anti-vacuity：验证合法前缀（如 `"tenant-a/subdir"`）能正常构造，确认守卫非恒真。
    #[test]
    fn store_binding_rejects_path_traversal() {
        let tenant = tenant_a();

        // 含 `..` → 拒绝
        let result = TenantStoreAllowlist::new([(
            (tenant, "store".to_string()),
            StoreBinding {
                mount: "secret".to_string(),
                kv_path_prefix: "tenant/../evil".to_string(),
            },
        )]);
        assert!(
            result.is_err(),
            "kv_path_prefix 含 '..' 应被拒绝，实际: {result:?}"
        );

        // 含 `.` → 拒绝
        let result = TenantStoreAllowlist::new([(
            (tenant, "store".to_string()),
            StoreBinding {
                mount: "secret".to_string(),
                kv_path_prefix: "./tenant".to_string(),
            },
        )]);
        assert!(
            result.is_err(),
            "kv_path_prefix 含 '.' 应被拒绝，实际: {result:?}"
        );

        // anti-vacuity：合法前缀 `"tenant-a/subdir"` 应成功构造
        #[allow(clippy::expect_used)]
        let ok = TenantStoreAllowlist::new([(
            (tenant, "store".to_string()),
            StoreBinding {
                mount: "secret".to_string(),
                kv_path_prefix: "tenant-a/subdir".to_string(),
            },
        )]);
        assert!(ok.is_ok(), "合法 kv_path_prefix 应被接受，实际: {ok:?}");
    }
}
