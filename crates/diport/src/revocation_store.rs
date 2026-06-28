//! `RevocationStore` —— 证书撤销 provider DI port（可替换：softca in-mem Ledger / DB CRL / OCSP）。
//!
//! 对标 rustls/webpki CRL 撤销检查（`find_serial(serial) -> Option<RevokedCert>` 的 serial-as-key 范式，
//! `UnknownStatusPolicy { Allow, Deny }` 显式策略枚举）；偏离点：RSS 是 multi-tenant 设备 PKI，撤销
//! **写**侧（`revoke`）+ **查**侧（`is_revoked`）均把 [`CertScope`]（tenant + device）作为**必填位置参**做
//! correct-by-construction 隔离，杜绝跨租户 / 跨设备撤销越权——webpki 的 CRL distribution-point URI 匹配
//! 不适用。ref: rustls webpki/src/crl/types.rs@main。

use dynosaur::dynosaur;
use ids::DeviceId;
use vocab::TenantId;

use crate::redacted::RedactedSource;

/// 撤销存储操作失败。
///
/// PII 边界（与 [`crate::SignerError`] 同范式）：`Display` 仅输出 provider 无关的安全摘要常量（不含 runtime
/// 数据）；原始 provider 错误包入 [`RedactedSource`]——其 `Debug` / `Display` 固定 `<redacted>`、`Error::source()`
/// 恒 `None`。故本类型经 `#[source]` 的 `Error::source()` 虽返回 `Some(&RedactedSource)`（链遍历到此即止），
/// 原始错误仍不经任何 `Error` 接口暴露，fail-closed，见 INVARIANT: DIPORT-ERR-SOURCE-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }。
#[derive(Debug, thiserror::Error)]
#[error("revocation store operation failed")]
pub struct RevocationStoreError {
    #[source]
    source: RedactedSource,
}

impl RevocationStoreError {
    /// 把 adapter 内部错误包成撤销存储失败。原始错误仅作 internal source 保留，不经 `Display` 暴露（PII 边界）。
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: RedactedSource::new(source),
        }
    }
}

/// 证书序列号（RFC 5280 `serialNumber` 八位组）——撤销 ledger 的查找键。typed fallible funnel
/// （私有字段，唯一构造入口 [`CertSerial::try_new`] 收口长度校验）。
///
/// **非机密**：序列号是 CRL / 证书的公开字段（对标 webpki `BorrowedRevokedCert.serial_number: &[u8]`），故
/// `Debug` 有意可见原值——不进 PII 脱敏（与 [`crate::Signature`] 等密码学物料相反）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CertSerial(Vec<u8>);

impl CertSerial {
    /// RFC 5280 §4.1.2.2：`serialNumber` 上限 20 字节。
    const MAX_LEN: usize = 20;

    /// 由序列号八位组构造，收口 RFC 5280 §4.1.2.2 长度约束（1–20 字节、非空）。
    ///
    /// **与 [`crate::KeyId`] / [`crate::SigningPurpose`] 的 infallible funnel 相反**：serial 来自不可信
    /// 解析链路 / 跨 provider 输入（DER 证书 `serialNumber`、外部 CRL / OCSP），合法性不能靠调用方约定，故
    /// 收口成 typed fallible funnel——非法 serial 在 [`CertSerial`] 类型层不可表达，撤销 store 只接受合法键。
    pub fn try_new(bytes: impl Into<Vec<u8>>) -> Result<Self, CertSerialError> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(CertSerialError::Empty);
        }
        if bytes.len() > Self::MAX_LEN {
            return Err(CertSerialError::TooLong);
        }
        Ok(Self(bytes))
    }
    /// 借出序列号八位组。
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// [`CertSerial::try_new`] 构造失败——serial 不满足 RFC 5280 §4.1.2.2 长度约束。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CertSerialError {
    /// 空序列号——不是合法 `serialNumber`（RFC 5280 §4.1.2.2 要求 1–20 字节正整数）。
    #[error("certificate serial number must not be empty")]
    Empty,
    /// 超过 RFC 5280 §4.1.2.2 的 20 字节上限。
    #[error("certificate serial number exceeds 20 octets (RFC 5280 §4.1.2.2)")]
    TooLong,
}

/// 证书撤销作用域（撤销 / 查询的**必填位置参**）——tenant + device 二维隔离。
///
/// 撤销 ledger 按 `(CertScope, CertSerial)` 键隔离：tenant A 不能撤销 / 看见 tenant B 的证书，同租户内
/// device 维度进一步隔离（设备退役只影响该设备的证书）。隔离 correct-by-construction（scope 是键的一部分，
/// 非运行期 gate）。`Copy`——成员均为 `Copy` 的 uuid newtype。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CertScope {
    tenant: TenantId,
    device: DeviceId,
}

impl CertScope {
    /// 由租户 + 设备标识构造撤销作用域。
    pub fn new(tenant: TenantId, device: DeviceId) -> Self {
        Self { tenant, device }
    }
    /// 借出租户标识。
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }
    /// 借出设备标识。
    pub fn device(&self) -> DeviceId {
        self.device
    }
}

/// 证书撤销 provider DI port（async）。
///
/// 公开 [`RevocationStore`] 是 **Send 变体**（adapters `impl RevocationStore for ...`），[`DynRevocationStore`]
/// 是其 dyn-compatible wrapper（组合根经 `Box<DynRevocationStore>` 注入）。非 Send 基 trait
/// `RevocationStoreLocal` 仅供静态分发窄场景，不在 crate 根 re-export（见 crate rustdoc）。
///
/// dyn-safe 约束（ADR-003 §4.6）：方法 `&self`、参数 / 返回为具体类型、supertrait 仅 Send、
/// 带 `async fn shutdown`（无 async Drop）。
#[trait_variant::make(RevocationStore: Send)]
#[dynosaur(pub DynRevocationStore = dyn(box) RevocationStore, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `RevocationStore` 变体 +
// dynosaur `DynRevocationStore` 承载（DI 注入走 Send wrapper）。这是 ADR-003 既定 dyn-port 范式。
pub trait RevocationStoreLocal {
    /// 在给定 [`CertScope`] 下撤销 `serial` 标识的证书（**幂等**：重复撤销同一 `(scope, serial)` 不报错，
    /// provider 戳 / 保留首次撤销时刻）。
    async fn revoke(
        &self,
        serial: CertSerial,
        scope: CertScope,
    ) -> Result<(), RevocationStoreError>;

    /// 查询给定 [`CertScope`] 下 `serial` 标识的证书是否已撤销。scope 不匹配（异租户 / 异设备）一律
    /// 返回 `false`——租户 / 设备隔离（对标 webpki `find_serial` 返回 `None` = 未命中 = 未撤销）。
    async fn is_revoked(
        &self,
        serial: CertSerial,
        scope: CertScope,
    ) -> Result<bool, RevocationStoreError>;

    /// 异步释放 provider 资源（无 async Drop；infra teardown 显式异步）。
    ///
    /// 与 [`crate::ManagedResource::shutdown`] 的关系同 [`crate::SignerLocal::shutdown`]：有 infra 资源
    /// （连接 / 句柄）的 store adapter 应**同时** `impl ManagedResource`，由 `bootstrap::ShutdownStack`
    /// 统一逆序编排关闭；本方法是 port-local 关闭路径。
    async fn shutdown(&self) -> Result<(), RevocationStoreError>;
}

#[cfg(test)]
mod smoke {
    //! build smoke：证明 async DI port 可 native AFIT impl + 经 `Box<DynRevocationStore>` 动态注入。
    use super::{
        CertScope, CertSerial, CertSerialError, DynRevocationStore, RevocationStore,
        RevocationStoreError,
    };
    use ids::DeviceId;
    use vocab::TenantId;

    const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const DEVICE: &str = "11111111-2222-3333-4444-555555555555";

    #[test]
    fn revocation_store_error_wraps_source() {
        let err = RevocationStoreError::new(std::io::Error::other("leak-marker-rev"));
        assert_eq!(err.to_string(), "revocation store operation failed");
        assert!(std::error::Error::source(&err).is_some());
        // 端到端：derive(Debug) 经 RedactedSource 脱敏、不展开内层 source（anti-vacuity 前置）。
        assert!(
            format!("{:?}", std::io::Error::other("leak-marker-rev")).contains("leak-marker-rev"),
            "前提失效：内层 Debug 未携 marker"
        );
        assert!(
            !format!("{err:?}").contains("leak-marker-rev"),
            "wrapper Debug 泄漏 source: {err:?}"
        );
    }

    // unwrap carve-out 集中此 helper（item-level，error-handling.md §Carve-out）：canonical 常量保证 parse 成功。
    #[allow(clippy::unwrap_used)]
    fn sample_tenant_device() -> (TenantId, DeviceId) {
        (
            TenantId::parse(TENANT).unwrap(),
            DeviceId::parse(DEVICE).unwrap(),
        )
    }

    fn sample_scope() -> CertScope {
        let (tenant, device) = sample_tenant_device();
        CertScope::new(tenant, device)
    }

    // canonical 合法 serial（1–20 字节）construct helper——unwrap carve-out 集中此 helper（item-level）。
    #[allow(clippy::unwrap_used)]
    fn sample_serial(bytes: impl Into<Vec<u8>>) -> CertSerial {
        CertSerial::try_new(bytes).unwrap()
    }

    #[test]
    fn cert_serial_try_new_validates_rfc5280_length() {
        // 空 → Empty（非合法 serialNumber）
        assert_eq!(CertSerial::try_new(vec![]), Err(CertSerialError::Empty));
        // 1 字节 → ok（下界）
        assert!(CertSerial::try_new(vec![0x01]).is_ok());
        // 20 字节 → ok（RFC 5280 上限）
        assert!(CertSerial::try_new(vec![0xAB; 20]).is_ok());
        // 21 字节 → TooLong（越界）
        assert_eq!(
            CertSerial::try_new(vec![0xAB; 21]),
            Err(CertSerialError::TooLong)
        );
    }

    #[test]
    fn cert_scope_and_serial_construct_and_access() {
        let (tenant, device) = sample_tenant_device();
        let scope = CertScope::new(tenant, device);
        // CertScope 访问器（无 re-parse，复用已解析值）
        assert_eq!(scope.tenant(), tenant);
        assert_eq!(scope.device(), device);
        // CertSerial newtype funnel（非机密：Debug 可见原值）
        let serial = sample_serial(vec![0x01, 0x02, 0x03]);
        assert_eq!(serial.as_bytes(), &[0x01, 0x02, 0x03]);
        assert!(
            format!("{serial:?}").contains('1'),
            "serial 非机密、Debug 应可见"
        );
    }

    // noop store（is_revoked 恒 false）：本 smoke 只验 **dyn 注入形态 + Send**，不验业务语义；
    // revoke→is_revoked round-trip / scope 隔离 / 幂等等语义由 adapters/softca `revocation_tests` 覆盖。
    struct NoopRevocationStore;
    impl RevocationStore for NoopRevocationStore {
        async fn revoke(
            &self,
            _serial: CertSerial,
            _scope: CertScope,
        ) -> Result<(), RevocationStoreError> {
            Ok(())
        }
        async fn is_revoked(
            &self,
            _serial: CertSerial,
            _scope: CertScope,
        ) -> Result<bool, RevocationStoreError> {
            Ok(false)
        }
        async fn shutdown(&self) -> Result<(), RevocationStoreError> {
            Ok(())
        }
    }

    // multi_thread + spawn：boxed future 须 Send（trait_variant Send 变体）才能跨 worker 调度——
    // current-thread 不暴露 Send 违规，故用 multi_thread 真正验证 dyn 注入的 Send 语义。
    #[tokio::test(flavor = "multi_thread")]
    async fn revocation_store_is_dyn_injectable() {
        let store: Box<DynRevocationStore> = DynRevocationStore::new_box(NoopRevocationStore);
        let scope = sample_scope();
        let joined = tokio::spawn(async move {
            store.revoke(sample_serial(vec![0xAA]), scope).await.is_ok()
                && !store
                    .is_revoked(sample_serial(vec![0xAA]), scope)
                    .await
                    .unwrap_or(true)
                && store.shutdown().await.is_ok()
        })
        .await;
        assert!(matches!(joined, Ok(true)));
    }

    // 验证 mockall mock（native-AFIT，非 #[async_trait]）可装入 dynosaur Send 变体的 `DynRevocationStore`
    // + 跨 spawn（Send future）。对标 signer.rs 的 mockall_mock_loads_into_dyn_signer。
    mockall::mock! {
        TestStore {}
        impl RevocationStore for TestStore {
            async fn revoke(&self, serial: CertSerial, scope: CertScope) -> Result<(), RevocationStoreError>;
            async fn is_revoked(&self, serial: CertSerial, scope: CertScope) -> Result<bool, RevocationStoreError>;
            async fn shutdown(&self) -> Result<(), RevocationStoreError>;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mockall_mock_loads_into_dyn_revocation_store() {
        let mut mock = MockTestStore::new();
        mock.expect_is_revoked().returning(|_, _| Ok(true));
        let store: Box<DynRevocationStore> = DynRevocationStore::new_box(mock);
        let scope = sample_scope();
        let joined =
            tokio::spawn(async move { store.is_revoked(sample_serial(vec![0x01]), scope).await })
                .await;
        assert!(matches!(joined, Ok(Ok(true))));
    }
}
