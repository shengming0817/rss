//! `SecretResolver` —— provider-agnostic secret 解析 port（对标 external-secrets SecretsClient.GetSecret；
//! secret 材料只在调用栈存活、永不持久化）。

use dynosaur::dynosaur;

use rss_redact::RedactedSource;

/// secret store 操作失败。
///
/// PII 边界（**类型层 Hard**，与 [`crate::SignerError`] / [`crate::ObjectStoreError`] 同范式）：
/// `StoreUnreachable` 变体的 `source`（provider 错误，可能携 endpoint / 凭据细节）经 [`RedactedSource`]
/// 脱敏（`Debug`/`Display` 固定 `<redacted>`、`Error::source()` 恒 `None`——原始错误不经任何 `Error`
/// 接口暴露，fail-closed），见 INVARIANT: DIPORT-ERR-SOURCE-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }。所有 `Display` message
/// 均为 const literal——无 runtime 数据拼 `format!`。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecretResolverError {
    /// secret store 不可达（provider 网络 / 权限 / 超时等）。原始错误内部保留，不进 `Display` / wire。
    #[error("secret store unreachable")]
    StoreUnreachable {
        #[source]
        source: RedactedSource,
    },
    /// secret key 在指定 store 中不存在。
    #[error("secret not found")]
    NotFound,
    /// 指定版本的 secret 不存在（key 存在但版本无此记录）。
    #[error("secret version not found")]
    VersionNotFound,
    /// secret 解析超时（store 响应超过配置上限）。
    #[error("secret resolution timed out")]
    Timeout,
    /// 调用方对该 secret 无访问权限（IAM / RBAC 拒绝）。
    #[error("secret access forbidden")]
    Forbidden,
}

impl SecretResolverError {
    /// 把 adapter 内部错误包成 store 不可达（[`Self::StoreUnreachable`]）。原始错误仅 owned 保留，
    /// 不经任何 `Error` 接口暴露（PII 边界，fail-closed）。
    pub fn store_unreachable<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::StoreUnreachable {
            source: RedactedSource::new(source),
        }
    }
}

/// secret store 中某条 secret 的外部坐标（store id + key + optional version）。
///
/// **不含 secret 材料**——只是指向材料的指针坐标（对标 external-secrets `SecretReference`、
/// `ObjectKey` 同范式）。
///
/// PII 边界（**类型层 Hard**）：`store_id` / `key` / `version` 可能内嵌租户 / 应用标识；经
/// `#[derive(rss_redact::Redact)]` 字段级脱敏（每字段 `#[redact(sensitivity = secret)]` → `Fixed`），派生 `Debug`
/// 渲染 `SecretCoordinate { store_id: <redacted>, key: <redacted>, version: <redacted> }`——使任意消费方的
/// `{coord:?}` 不泄漏原文（#1360 替换手写 `Debug`）。
///
/// `Clone`/`PartialEq`/`Eq`：坐标无状态、可安全复制 + 比较（不含材料，拷贝无 PII 泄漏风险）。
///
/// INVARIANT: DIPORT-SECRETCOORD-DEBUG-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（回归见 `pii_debug::secret_coordinate_debug_redacts`）。
#[derive(Clone, PartialEq, Eq, rss_redact::Redact)]
pub struct SecretCoordinate {
    #[redact(sensitivity = secret)]
    store_id: String,
    #[redact(sensitivity = secret)]
    key: String,
    #[redact(sensitivity = secret)]
    version: Option<String>,
}

impl SecretCoordinate {
    /// 构造 secret 坐标。
    pub fn new(
        store_id: impl Into<String>,
        key: impl Into<String>,
        version: Option<String>,
    ) -> Self {
        Self {
            store_id: store_id.into(),
            key: key.into(),
            version,
        }
    }

    /// 借出 store 标识。
    pub fn store_id(&self) -> &str {
        &self.store_id
    }

    /// 借出 secret key。
    pub fn key(&self) -> &str {
        &self.key
    }

    /// 借出版本（`None` 表示取最新版）。
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }
}

/// 解析所得 secret 字节（内存中的原始材料）。
///
/// **零信任 PII 边界（类型层 Hard）**：
/// - `#[derive(zeroize::ZeroizeOnDrop)]`——drop 时自动清零，材料不在栈 / 堆上残留。
/// - **不** derive `Clone`——无所有权逃逸路径，调用栈外不可持有副本。
/// - **不** derive serde——永不序列化到 wire / 日志。
/// - **`#[derive(rss_redact::Redact)]`**（`#[redact(sensitivity = secret)]` → `Fixed`）派生 `Debug` 渲染
///   `SecretMaterial(<redacted>)`——tracing / 日志采集不得经 `{:?}` 泄漏（#1360 替换手写 `Debug`）。
/// - `expose(&self) -> &[u8]`——唯一受控借出路径，无 `into_vec` / `as_string` / `Display` owned 逃逸。
///
/// INVARIANT: DIPORT-SECRETMATERIAL-PII-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（回归见 `pii_debug::secret_material_debug_is_opaque`）。
#[derive(zeroize::ZeroizeOnDrop, rss_redact::Redact)]
pub struct SecretMaterial(#[redact(sensitivity = secret)] Vec<u8>);

impl SecretMaterial {
    /// 由字节构造 secret 材料（adapter 侧唯一入口）。
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// 受控借出材料字节（唯一借出路径；无 into_vec / as_string / Display owned 逃逸——类型层 Hard）。
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

/// secret 解析 provider DI port（async）。
///
/// 公开 [`SecretResolver`] 是 **Send + Sync 变体**（adapters `impl SecretResolver for ...`），
/// [`DynSecretResolver`] 是其 dyn-compatible wrapper（组合根经 `Box<DynSecretResolver>` 注入）。
/// 非 Send 基 trait `SecretResolverLocal` 仅供静态分发窄场景，不在 crate 根 re-export。
///
/// **fail-closed 契约**：`resolve` 遇 store 不可达 / 超时须返 `Err`，**绝不**返回 stale 或空材料
/// 充数——零信任边界要求 secret 读取须 fresh 且授权，静默降级即破 fail-closed。
///
/// **tenant 显式参**：每次解析须带 [`rss_request_context::TenantId`] 做 store allowlist / RLS 校验——多租环境下
/// 同一 provider 实例服务多租，tenant 分隔在 port 签名层 Hard 约束（不经 ambient ctx 隐式传播）。
///
/// dyn-safe 约束（ADR-003 §4.6）：方法 `&self`、参数 / 返回为具体类型（owned / ref）、provider
/// 必须 `Send + Sync`，使唯一 resolver capability 可由 HTTP dispatch 与 readiness sampler 共享。
#[trait_variant::make(SecretResolver: Send + Sync)]
#[dynosaur(pub DynSecretResolver = dyn(box) SecretResolver, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为 native AFIT；Send + Sync 由 trait_variant 生成的 `SecretResolver` 变体 +
// dynosaur `DynSecretResolver` 承载（DI 注入走共享 provider wrapper）。
pub trait SecretResolverLocal {
    /// 按坐标解析 secret 材料（fail-closed：store 不可达 / 超时返 `Err`，绝不返 stale/空；
    /// `tenant` 做 store allowlist / RLS 分隔）。
    async fn resolve(
        &self,
        tenant: rss_request_context::TenantId,
        coord: &SecretCoordinate,
    ) -> Result<SecretMaterial, SecretResolverError>;
}

#[cfg(test)]
mod smoke {
    //! build smoke：证明 async DI port 可 native AFIT impl + 经 `Box<DynSecretResolver>` 动态注入。
    use super::{
        DynSecretResolver, SecretCoordinate, SecretMaterial, SecretResolver, SecretResolverError,
    };
    use rss_request_context::TenantId;

    #[allow(clippy::expect_used)]
    fn tenant() -> TenantId {
        TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("canonical uuid")
    }

    fn sample_coord() -> SecretCoordinate {
        SecretCoordinate::new("vault-prod", "db/password", None)
    }

    struct NoopSecretResolver;
    impl SecretResolver for NoopSecretResolver {
        // reason: smoke/test-only noop——永不在生产组合根注入。
        async fn resolve(
            &self,
            _tenant: TenantId,
            _coord: &SecretCoordinate,
        ) -> Result<SecretMaterial, SecretResolverError> {
            Ok(SecretMaterial::new(Vec::new()))
        }
    }

    // multi_thread + spawn：boxed future 须 Send（trait_variant Send 变体）才能跨 worker 调度——
    // current-thread 不暴露 Send 违规，故用 multi_thread 真正验证 dyn 注入的 Send 语义。
    #[tokio::test(flavor = "multi_thread")]
    async fn secret_resolver_is_dyn_injectable() {
        let resolver: Box<DynSecretResolver> = DynSecretResolver::new_box(NoopSecretResolver);
        let t = tenant();
        let c = sample_coord();
        let joined = tokio::spawn(async move { resolver.resolve(t, &c).await.is_ok() }).await;
        assert!(matches!(joined, Ok(true)));
    }

    mockall::mock! {
        TestSecretResolver {}
        impl SecretResolver for TestSecretResolver {
            async fn resolve(
                &self,
                tenant: TenantId,
                coord: &SecretCoordinate,
            ) -> Result<SecretMaterial, SecretResolverError>;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mockall_mock_loads_into_dyn_secret_resolver() {
        let mut mock = MockTestSecretResolver::new();
        mock.expect_resolve()
            .returning(|_, _| Ok(SecretMaterial::new(vec![0xAB, 0xCD])));
        let resolver: Box<DynSecretResolver> = DynSecretResolver::new_box(mock);
        let t = tenant();
        let c = sample_coord();
        let joined = tokio::spawn(async move { resolver.resolve(t, &c).await }).await;
        assert!(matches!(joined, Ok(Ok(ref m)) if m.expose() == [0xAB, 0xCD]));
    }

    #[test]
    fn secret_resolver_error_wraps_source() {
        let err = SecretResolverError::store_unreachable(std::io::Error::other("leak-marker-sr"));
        assert_eq!(err.to_string(), "secret store unreachable");
        assert!(std::error::Error::source(&err).is_some());
        // anti-vacuity：内层 Debug 确实携 marker。
        assert!(
            format!("{:?}", std::io::Error::other("leak-marker-sr")).contains("leak-marker-sr"),
            "前提失效：内层 Debug 未携 marker"
        );
        // wrapper Debug 经 RedactedSource 脱敏——不展开内层。
        assert!(
            !format!("{err:?}").contains("leak-marker-sr"),
            "wrapper Debug 泄漏 source: {err:?}"
        );
        // Finding 9：错误链应止于 RedactedSource（source 的 source 为 None）——不用 unwrap（clippy::unwrap_used）。
        let chain_tail = std::error::Error::source(&err).and_then(std::error::Error::source);
        assert!(
            chain_tail.is_none(),
            "链应止于 RedactedSource（source 的 source 应为 None）：{chain_tail:?}"
        );
    }
}

#[cfg(test)]
mod pii_debug {
    //! PII 边界回归：`SecretMaterial` / `SecretCoordinate` 字节/坐标 Debug 脱敏 + `ZeroizeOnDrop` 编译期证明。
    //! INVARIANT: DIPORT-SECRETMATERIAL-PII-REDACT-01 / DIPORT-SECRETCOORD-DEBUG-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }。
    use super::{SecretCoordinate, SecretMaterial};

    #[test]
    fn secret_material_debug_is_opaque() {
        // anti-vacuity：原始 Vec<u8> Debug 把 0xDE 渲染成 "222"，证明 "!contains(222)" 检测非空转。
        assert!(
            format!("{:?}", vec![0xDE_u8]).contains("222"),
            "前提失效：检测字节不在原始 Debug"
        );
        let m = SecretMaterial::new(vec![0xDE, 0xAD]);
        assert_eq!(format!("{m:?}"), "SecretMaterial(<redacted>)");
    }

    #[test]
    fn secret_coordinate_debug_redacts() {
        let coord = SecretCoordinate::new("vault-prod", "db/password", Some("v3".to_string()));
        let dbg = format!("{coord:?}");
        // #[derive(Redact)] 字段级渲染：字段名（非敏感）保留、每字段值 → <redacted>（Fixed，含 version
        // 不泄 Some/None）。脱敏边界不变（INVARIANT: DIPORT-SECRETCOORD-DEBUG-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }）。
        assert_eq!(
            dbg,
            "SecretCoordinate { store_id: <redacted>, key: <redacted>, version: <redacted> }"
        );
        // anti-vacuity：store_id / key / version 明文本不在 Debug 输出中。
        assert!(!dbg.contains("vault-prod"), "store_id 泄漏: {dbg}");
        assert!(!dbg.contains("db/password"), "key 泄漏: {dbg}");
        assert!(!dbg.contains("v3"), "version 泄漏: {dbg}");
    }

    #[test]
    fn secret_coordinate_debug_redacts_absent_version() {
        // version = None：Fixed mode 不读值，仍渲染 `version: <redacted>`——不泄 Some/None 区分。
        let coord = SecretCoordinate::new("vault-prod", "db/password", None);
        assert_eq!(
            format!("{coord:?}"),
            "SecretCoordinate { store_id: <redacted>, key: <redacted>, version: <redacted> }"
        );
    }

    // 编译期证明 SecretMaterial 实现 ZeroizeOnDrop（类型约束不满足 → 编译失败）。
    fn _assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    #[test]
    fn secret_material_implements_zeroize_on_drop() {
        _assert_zeroize_on_drop::<SecretMaterial>();
    }
}
