//! oidc adapter —— RSS workspace（W 阶段真身，#1011 OIDC JWT 验签切片）。
//!
//! 单一 `OidcProvider`：
//! - 始终 `impl diport::ManagedResource`（已冻结，ADAPTER-PORT-FREEZE-04）。
//! - `backend` feature 开时增补 `impl diport::Pdp`（jsonwebtoken 验签 JWT → `VerifiedClaims`）。
//!
//! feature-off（default build）：空壳编译、freeze smoke 类型断言仍有效；不引入 jsonwebtoken/ring。
//! feature-on（`--features backend`）：持有注入的 issuer / audience / 解码 key 集 + 可配置 tenant·kind claim 名。
//! **key 在构造期注入**（无 live JWKS-over-HTTP discovery）——JWKS 拉取 + 轮转 = follow-up（#1109，同 s3
//! deferred live MinIO 范式）。`ServiceToken` scheme 一律 `Untrusted`（OIDC provider 不签 RSS service token，
//! 另有验签器）。ADR-006 §5：本 PR 仅 crate 交付、**不**接入任何生产可达 httpserve 认证路径（验签空窗保护，
//! 挂载 + live discovery 留 #1109）。crate 保持 `forbid(unsafe_code)`（继承 workspace lints；只 import diport
//! trait + jsonwebtoken，不 invoke dynosaur 宏）。

#[cfg(feature = "backend")]
mod verify;

#[cfg(feature = "backend")]
pub use verify::{Algorithm, ConfigError, VerifierConfig, VerifierConfigBuilder};

use diport::{ManagedResource, ShutdownError};

/// OIDC JWT 验签 adapter（sealed-marker）。
///
/// `backend` feature 关时为空壳（仅供 freeze smoke 类型断言）；开时持有验签配置（issuer / audience /
/// 注入解码 key + 可配置 tenant·kind claim 名）。无 infra 句柄（key 注入、纯计算验签）。
pub struct OidcProvider {
    #[cfg(feature = "backend")]
    config: verify::VerifierConfig,
}

#[cfg(feature = "backend")]
impl OidcProvider {
    /// 由验签配置构造（组合根 / 测试经 [`VerifierConfigBuilder`] 注入 issuer / audience / 解码 key 集 +
    /// 可配置 tenant·kind claim 名）。fail-fast 校验集中在 builder `build()`——本构造只接受已校验的
    /// `VerifierConfig`（其字段私有、唯一构造入口是 builder），故 infallible。
    pub fn new(config: verify::VerifierConfig) -> Self {
        Self { config }
    }
}

impl ManagedResource for OidcProvider {
    fn name(&self) -> &str {
        "oidc"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        // reason: key 注入、纯计算验签，无 infra 句柄 / 后台 JWKS 刷新任务需释放（本切片不做 live discovery）。
        // 关闭无需显式动作（同 s3：连接器在构造侧持有）。JWKS 刷新句柄于 #1109 落地时在此释放。
        Ok(())
    }
}

#[cfg(feature = "backend")]
impl diport::Pdp for OidcProvider {
    async fn verify(
        &self,
        raw: &diport::RawCredential,
    ) -> Result<diport::VerifiedClaims, diport::PdpError> {
        // scheme dispatch + 验签 + claim 映射 + 脱敏日志全在 verify 模块（控制 lib.rs 认知复杂度）。
        // 纯计算（key 注入），无 await——async 仅为满足 port 签名（#1109 接 live JWKS 时在此 await）。
        verify::verify_credential(&self.config, raw)
    }
}

#[cfg(test)]
mod smoke {
    //! build smoke：编译期断言 sealed-marker 已 impl 冻结的 diport DI port trait（PhantomData 绑定检查，
    //! 不构造、不执行 body）。
    //! INVARIANT: ADAPTER-PORT-FREEZE-04 —— sealed-marker impl 冻结的 diport DI port trait（`ManagedResource`
    //! 始终；`Pdp` 于 backend）；去掉任一 impl 即编译失败（anti-vacuity）。
    use core::marker::PhantomData;

    fn assert_managed_resource<T: diport::ManagedResource>(_: PhantomData<T>) {}

    #[test]
    fn impls_managed_resource() {
        assert_managed_resource(PhantomData::<super::OidcProvider>);
    }

    #[cfg(feature = "backend")]
    fn assert_pdp<T: diport::Pdp>(_: PhantomData<T>) {}

    #[cfg(feature = "backend")]
    #[test]
    fn impls_pdp() {
        assert_pdp(PhantomData::<super::OidcProvider>);
    }
}
