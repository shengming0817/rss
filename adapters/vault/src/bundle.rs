//! vault capability bundle（#1498 / RW-W-hardening）：把 secret-resolution 能力派发 +
//! managed-resource/rollback 单源派生收口到单一装配出口，杜绝组合根回退多通道手写（D5）。
//!
//! 泛化自 pg `PgRuntimeDeps`/`PgDomainDeps`（#1422/#1423，ADR-010 §2.2）。vault 当前 live 能力
//! `SecretResolver` 由 **settings 域消费**（`SecretService`），故经 per-domain [`VaultDomainDeps<D>`]
//! + sealed [`caps`] 隔离派发（与 pg `PgDomainDeps<caps::Settings>` 同范式）。
//!
//! `VaultSigner`（`diport::Signer`，provider-agnostic infra）当前**无 live 消费**（deviceloop 证书签发
//! 待落地）——故本 PR **不**在 bundle 装 signer / 不造空 `VaultInfraDeps` 壳（避免预设未来需求 / 死代码）；
//! signer 随其消费方落地时加入 `VaultInfraDeps`（#1498 follow-up 范式同此 bundle）。
//!
//! ## 构造模型（vault TLS-agnostic 注入）
//!
//! 与 pg `setup`（内部 connect）不同：vault adapter **TLS-agnostic**——`reqwest::Client`（预配置 TLS）
//! 由组合根注入，`VaultSecretResolver` 在组合根 DI 期构造（env → addr/token/allowlist）。故
//! [`VaultRuntimeDeps::new`] 接受已构造的 resolver 并 `Arc` 化——bundle 是 **dispatch + lifecycle 装配
//! 出口**，resolver 构造留组合根（vault 注入模型，非 pg 自连模型）。
//!
//! ## INVARIANT
//!
//! - **VAULT-BUNDLE-DOMAIN-01**（Hard，sealed marker + typed function choice）：per-domain 能力隔离——
//!   `D: VaultDomain` 是 sealed marker（[`caps`]），外部 crate 无法新增域 marker；`secret_resolver()` 仅
//!   `VaultDomainDeps<caps::Settings>` 可用（anti-vacuity = `VaultDomainDeps` rustdoc 的 `compile_fail` doctest）。
//! - **VAULT-BUNDLE-RESOLVER-02**（Hard）：bundle 私有持 `Arc<VaultSecretResolver>`，dispatch（service）与
//!   guard（shutdown）共享同一 Arc，单源 lifecycle——dispatch 不泄漏 `Arc<VaultSecretResolver>` 本身
//!   （经 [`SharedVaultResolver`] delegating handle 出 `Box<DynSecretResolver>`）。
//!
//! ## 单源装配（`runtime_resources`）
//!
//! adapter **不依赖 `bootstrap`**（与 pg adapter 一致），故经
//! [`VaultRuntimeDeps::runtime_resources`] 单源派生 `Vec<Box<DynManagedResource>>`（仅 `diport` 类型），
//! 组合根以 crate-private `ProviderOutput` 将该原语转换为完整 `DomainModuleResult`，再经统一 `merge`
//! 路径装配。trait 策略留在 runtime，adapter 不命名也不依赖 `bootstrap`。
//! resolver / key-provider shutdown 是 noop（reqwest 无显式 close），但仍经单源出口注册——与 pg 同纪律、作 D5 live 样板。
//!
//! ## 开源对标
//!
//! `ref: oxidecomputer/omicron nexus/src/context.rs@8eb92537bd12598dfd2c861f897a88962fabf684`——
//! `Arc<ServerContext>` 共享 infra clone 进各 server（RSS `SharedRuntimeDeps` 同 lineage）。本模块对应：
//! `Arc<VaultSecretResolver>` 私有持有 + `for_domain::<D>()` 派发受控句柄（对标 pg `for_domain`）。

use std::marker::PhantomData;
use std::sync::Arc;

use diport::{
    DynKeyProvider, DynManagedResource, DynSecretResolver, EncryptOutput, KeyName, KeyProvider,
    KeyProviderError, KeyRef, ManagedResource, RedactedBytes, SecretCoordinate, SecretMaterial,
    SecretResolver, SecretResolverError, ShutdownError,
};
use secure::{DerivedAad, Plaintext};
use vocab::TenantId;

use crate::{VaultKeyProvider, VaultSecretResolver};

/// per-domain 能力 marker 的 sealed 封闭——外部 crate 无法新增域 marker（无法 impl `Sealed`）。
mod sealed {
    pub trait Sealed {}
}

/// vault capability bundle 的 per-domain marker（sealed）。
///
/// 实现集封闭在本 crate（[`caps`] 下的 ZST）；外部 crate 既不能命名内层 `Sealed`、也不能新增 marker，
/// 故 `VaultDomainDeps<D>` 的 `D` 只能是本 crate 声明的域（VAULT-BUNDLE-DOMAIN-01）。
pub trait VaultDomain: sealed::Sealed {}

/// per-domain 能力 marker ZST。
///
/// `caps` 命名避开 `rss_domain_no_serialize` 的 `domain` 模块启发式（照 pg `caps` 范式）。当前仅
/// `Settings`（vault SecretResolver 的 live 消费域）；其它域随真实消费落地增加。
pub mod caps {
    /// settings 域能力 marker。
    pub struct Settings;
}

impl sealed::Sealed for caps::Settings {}
impl VaultDomain for caps::Settings {}

/// 组合根级 vault 能力包：私有持 `Arc<VaultSecretResolver>`，派发 per-domain 受控句柄并产出 shutdown 资源。
///
/// 经 [`VaultRuntimeDeps::new`] 构造（resolver 由组合根 DI 注入，vault TLS-agnostic 模型）。`Clone` 廉价
/// （仅 `Arc` clone）。不暴露 `Arc<VaultSecretResolver>`（VAULT-BUNDLE-RESOLVER-02）。
#[derive(Clone)]
pub struct VaultRuntimeDeps {
    resolver: Arc<VaultSecretResolver>,
    key_provider: Arc<VaultKeyProvider>,
}

impl VaultRuntimeDeps {
    /// 由组合根注入已构造的 [`VaultSecretResolver`] + [`VaultKeyProvider`]（vault TLS-agnostic：
    /// `reqwest::Client` + addr/token/mount 在组合根 DI 期组装）。`Arc` 化以在 dispatch（service）与
    /// guard（shutdown）间共享单源 lifecycle。
    #[must_use]
    pub fn new(resolver: VaultSecretResolver, key_provider: VaultKeyProvider) -> Self {
        Self {
            resolver: Arc::new(resolver),
            key_provider: Arc::new(key_provider),
        }
    }

    /// 派发 per-domain 受控句柄（`Arc<VaultSecretResolver>` clone + `PhantomData<D>`）。`D` sealed marker
    /// 使跨域调用编译期被拒（VAULT-BUNDLE-DOMAIN-01）。
    #[must_use]
    pub fn for_domain<D: VaultDomain>(&self) -> VaultDomainDeps<D> {
        VaultDomainDeps {
            resolver: Arc::clone(&self.resolver),
            key_provider: Arc::clone(&self.key_provider),
            _marker: PhantomData,
        }
    }

    /// **单源** managed-resource/rollback 原语：runtime-local `ProviderOutput` 消费本方法的完整结果，
    /// 转换为 `DomainModuleResult` 后进入统一 `merge` 路径，杜绝逐 channel 手写
    /// `register_detached`（D5）。
    #[must_use]
    pub fn runtime_resources(&self) -> Vec<Box<DynManagedResource<'static>>> {
        vec![
            DynManagedResource::new_box(VaultResolverGuard(Arc::clone(&self.resolver))),
            DynManagedResource::new_box(VaultKeyProviderGuard(Arc::clone(&self.key_provider))),
        ]
    }
}

/// per-domain 受控 vault 能力句柄（`Clone`，内部 `Arc` 廉价 clone）。
///
/// 私有持 `Arc<VaultSecretResolver>`，只暴露**所属域 `D`** 的能力。`D` 是 sealed marker（[`caps`]），
/// 跨域调用编译期被拒（VAULT-BUNDLE-DOMAIN-01 anti-vacuity）：
///
/// `VaultDomainDeps<bool>` 不可表达（`bool: VaultDomain` 未满足，sealed 外部无法新增 marker）：
///
/// ```compile_fail
/// use vault::VaultDomainDeps;
/// // E0277：`bool` 不 impl `VaultDomain`（sealed marker，外部无法新增）。
/// fn bad(d: VaultDomainDeps<bool>) {
///     let _ = d;
/// }
/// ```
///
/// 本域能力可用（正向）：
///
/// ```
/// use vault::{VaultDomainDeps, caps};
/// fn settings_ok(d: VaultDomainDeps<caps::Settings>) {
///     let _ = d.secret_resolver();
/// }
/// ```
pub struct VaultDomainDeps<D: VaultDomain> {
    resolver: Arc<VaultSecretResolver>,
    key_provider: Arc<VaultKeyProvider>,
    _marker: PhantomData<D>,
}

// 手写 `Clone`：避免 `#[derive(Clone)]` 引入多余的 `D: Clone` bound（marker 是 ZST，与 Clone 无关）。
impl<D: VaultDomain> Clone for VaultDomainDeps<D> {
    fn clone(&self) -> Self {
        Self {
            resolver: Arc::clone(&self.resolver),
            key_provider: Arc::clone(&self.key_provider),
            _marker: PhantomData,
        }
    }
}

impl VaultDomainDeps<caps::Settings> {
    /// settings 域 secret 解析句柄（`Box<DynSecretResolver>`，注入 `SecretService`）。经
    /// [`SharedVaultResolver`] delegating handle 共享 bundle 的 `Arc<VaultSecretResolver>`——不泄漏
    /// `Arc` 本身（VAULT-BUNDLE-RESOLVER-02）；与 runtime_resources guard 同一底层 resolver。
    #[must_use]
    pub fn secret_resolver(&self) -> Box<DynSecretResolver<'static>> {
        DynSecretResolver::new_box(SharedVaultResolver(Arc::clone(&self.resolver)))
    }

    /// settings 域字段保护 KeyProvider 句柄。经 delegating handle 共享 bundle 的 `Arc<VaultKeyProvider>`，
    /// 不泄漏 Arc 本身；可多次调用以给 read/write repo 各一份 owned dyn box。
    #[must_use]
    pub fn key_provider(&self) -> Box<DynKeyProvider<'static>> {
        DynKeyProvider::new_box(SharedVaultKeyProvider(Arc::clone(&self.key_provider)))
    }
}

/// `Arc<VaultSecretResolver>` 的 `SecretResolver` delegating handle——`DynSecretResolver::new_box` 需
/// owned `impl SecretResolver`，而 `Arc<VaultSecretResolver>` 无 blanket impl，故经 newtype 委托
/// （让 service dispatch 与 shutdown guard 共享同一 Arc，不泄漏 Arc 本身）。
struct SharedVaultResolver(Arc<VaultSecretResolver>);

impl SecretResolver for SharedVaultResolver {
    async fn resolve(
        &self,
        tenant: TenantId,
        coord: &SecretCoordinate,
    ) -> Result<SecretMaterial, SecretResolverError> {
        self.0.resolve(tenant, coord).await
    }
}

/// `Arc<VaultKeyProvider>` 的 `KeyProvider` delegating handle。
struct SharedVaultKeyProvider(Arc<VaultKeyProvider>);

impl KeyProvider for SharedVaultKeyProvider {
    async fn encrypt(
        &self,
        key: KeyName,
        plaintext: Plaintext,
        aad: DerivedAad,
    ) -> Result<EncryptOutput, KeyProviderError> {
        self.0.encrypt(key, plaintext, aad).await
    }

    async fn decrypt(
        &self,
        ciphertext: RedactedBytes,
        key: KeyRef,
        aad: DerivedAad,
    ) -> Result<Plaintext, KeyProviderError> {
        self.0.decrypt(ciphertext, key, aad).await
    }

    async fn rewrap(
        &self,
        ciphertext: RedactedBytes,
        key: KeyRef,
        aad: DerivedAad,
    ) -> Result<EncryptOutput, KeyProviderError> {
        self.0.rewrap(ciphertext, key, aad).await
    }

    async fn shutdown(&self) -> Result<(), KeyProviderError> {
        KeyProvider::shutdown(&*self.0).await
    }
}

/// `Arc<VaultSecretResolver>` 的 `ManagedResource` guard wrapper——`Arc` 非 fundamental ⇒ 不能直接
/// `impl ManagedResource for Arc<VaultSecretResolver>`（孤儿规则），故经 newtype（对标 `PgStoreGuard`）。
/// shutdown 委托 resolver（reqwest 无 close，noop），name = `"vault-secret-resolver"`。
/// crate 内可见（`pub(crate)`）：组合根只经 `runtime_resources()` 消费 `Box<DynManagedResource>`，
/// 无需命名 guard 类型本身。
pub(crate) struct VaultResolverGuard(Arc<VaultSecretResolver>);

impl ManagedResource for VaultResolverGuard {
    fn name(&self) -> &str {
        self.0.name()
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.0.shutdown().await
    }
}

pub(crate) struct VaultKeyProviderGuard(Arc<VaultKeyProvider>);

impl ManagedResource for VaultKeyProviderGuard {
    fn name(&self) -> &str {
        self.0.name()
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        ManagedResource::shutdown(&*self.0).await
    }
}

#[cfg(test)]
mod tests {
    //! bundle 单元测：wiremock-free（构造合法 resolver + allowlist），覆盖 funnel 派发 + 单源
    //! runtime_resources + sealed-caps 共享 Arc。
    //! INVARIANT: VAULT-BUNDLE-DOMAIN-01 / VAULT-BUNDLE-RESOLVER-02 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }（compile_fail doctest 见
    //! `VaultDomainDeps` rustdoc）。

    use super::*;
    use std::time::Duration;

    use crate::{TenantStoreAllowlist, VaultKeyProvider};

    const ADDR: &str = "https://vault.example:8200";
    const TOKEN: &str = "s.testtoken";
    const TIMEOUT: Duration = Duration::from_secs(30);

    #[allow(clippy::expect_used)] // reason: 合法配置 resolver 必成功；item-level carve-out。
    fn resolver() -> VaultSecretResolver {
        let stores = TenantStoreAllowlist::new(std::iter::empty()).expect("empty allowlist ok");
        VaultSecretResolver::new(reqwest::Client::new(), ADDR, TOKEN, TIMEOUT, stores)
            .expect("valid config")
    }

    #[allow(clippy::expect_used)] // reason: 合法配置 key provider 必成功；item-level carve-out。
    fn key_provider() -> VaultKeyProvider {
        VaultKeyProvider::new(reqwest::Client::new(), ADDR, TOKEN, "transit", TIMEOUT)
            .expect("valid config")
    }

    fn deps() -> VaultRuntimeDeps {
        VaultRuntimeDeps::new(resolver(), key_provider())
    }

    #[test]
    fn for_domain_shares_resolver_arc() {
        let d = deps();
        let s: VaultDomainDeps<caps::Settings> = d.for_domain();
        // VAULT-BUNDLE-RESOLVER-02：句柄内部 resolver 与 runtime deps 同一 Arc（in-crate 验证私有字段）。
        assert!(
            Arc::ptr_eq(&s.resolver, &d.resolver),
            "for_domain clone 共享 resolver Arc"
        );
        assert!(
            Arc::ptr_eq(&s.key_provider, &d.key_provider),
            "for_domain clone 共享 key provider Arc"
        );
    }

    #[test]
    fn domain_deps_clone_shares_resolver() {
        let s: VaultDomainDeps<caps::Settings> = deps().for_domain();
        let c = s.clone();
        assert!(
            Arc::ptr_eq(&s.resolver, &c.resolver),
            "clone 廉价共享 resolver Arc（非深拷贝）"
        );
        assert!(
            Arc::ptr_eq(&s.key_provider, &c.key_provider),
            "clone 廉价共享 key provider Arc（非深拷贝）"
        );
    }

    #[test]
    fn settings_secret_resolver_constructs() {
        let s: VaultDomainDeps<caps::Settings> = deps().for_domain();
        // 纯 Arc clone + delegating handle 装箱，无 I/O；构造成功即覆盖（绕 must_use 用 let _）。
        let _ = s.secret_resolver();
    }

    #[test]
    fn settings_key_provider_constructs() {
        let s: VaultDomainDeps<caps::Settings> = deps().for_domain();
        let _ = s.key_provider();
    }

    #[test]
    fn runtime_resources_single_sources_resolver_guard() {
        let resources = deps().runtime_resources();
        assert_eq!(
            resources.len(),
            2,
            "vault 当前产 resolver + key-provider 两条受管资源"
        );
        assert_eq!(
            resources[0].name(),
            "vault-secret-resolver",
            "单源 resource 即 vault resolver guard"
        );
        assert_eq!(
            resources[1].name(),
            "vault-key-provider",
            "单源 resource 即 vault key provider guard"
        );
    }

    #[tokio::test]
    async fn resolver_guard_shutdown_is_noop_ok() {
        let resources = deps().runtime_resources();
        // resolver shutdown noop（reqwest 无 close）→ 单源 guard 干净收敛。
        assert!(resources[0].shutdown().await.is_ok());
    }
}
