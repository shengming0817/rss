//! oidc adapter —— RSS workspace（#1195 / 1109-A1 真 crypto 验签切片）。
//!
//! 单一 `OidcProvider`：
//! - 始终 `impl diport::ManagedResource`（已冻结，ADAPTER-PORT-FREEZE-04）。
//! - `backend` feature 开时增补 `impl diport::Pdp`（纯 RustCrypto 验签 → `VerifiedClaims`）。
//!
//! feature-off（default build）：空壳编译、freeze smoke 类型断言仍有效；不引入任何 crypto dep。
//! feature-on（`--features backend`）：持有注入的 `VerifierConfig`（issuer / audience / [`StaticKeySource`] /
//! 可配置 tenant·kind claim 名 / kind allowlist / leeway）+ **注入的 `diport::Clock`**（exp/nbf 校验取注入时钟，
//! 禁系统时钟，rust-standards「Clock 构造器位置参」护栏）。验签链：三段解析 → SupportedAlg 白名单 → alg-key
//! 路径隔离闸（JWT=ES256 / ServiceToken=HS256）→ 签名/MAC 校验（p256 / hmac+sha2 常数时间）→ exp/nbf/iss/aud →
//! 映射 claims。**key 在构造期注入**（无 live JWKS-over-HTTP discovery）——JWKS 拉取 + 轮转 = follow-up
//! （#1109/T003，`StaticKeySource` 构造器签名为此留稳）。
//!
//! ADR-006 §5：本 PR 仅 crate 交付、**不**接入任何生产可达 httpserve 认证路径（验签空窗保护；组合根接线 +
//! authn 验签桥 = #1109/T004 安全同批门）。crate 保持 `forbid(unsafe_code)`（继承 workspace lints）。

#[cfg(feature = "backend")]
mod claims;
#[cfg(feature = "backend")]
mod config;
#[cfg(feature = "backend")]
mod jwks;
#[cfg(feature = "backend")]
mod jws;
#[cfg(feature = "backend")]
mod verify;

#[cfg(feature = "backend")]
pub use config::{
    ConfigError, StaticKeySource, StaticKeySourceBuilder, VerifierConfig, VerifierConfigBuilder,
};
#[cfg(feature = "backend")]
pub use jwks::{JwksError, JwksKeySource, JwksReadinessHandle};

use diport::{ManagedResource, ShutdownError};

/// OIDC JWT / service-token 验签 adapter（sealed-marker）。
///
/// `backend` feature 关时为空壳（仅供 freeze smoke 类型断言）；开时持有验签配置 + 注入时钟。无 infra 句柄
/// （key 构造期注入、纯计算验签）。
pub struct OidcProvider {
    #[cfg(feature = "backend")]
    config: config::VerifierConfig,
    #[cfg(feature = "backend")]
    clock: Box<dyn diport::Clock>,
}

#[cfg(feature = "backend")]
impl OidcProvider {
    /// 由验签配置 + 注入时钟构造（组合根 / 测试经 [`VerifierConfigBuilder`] + [`StaticKeySource`] 注入）。
    ///
    /// `clock` 是**必填构造器位置参**（非 `Option`、非默认系统时钟）——rust-standards §工程护栏「Clock 是
    /// 构造器位置参；禁止默认取系统时钟」。fail-fast 校验集中在 builder `build()`，本构造只接受已校验的
    /// `VerifierConfig`（字段私有、唯一构造入口是 builder），故 infallible。
    pub fn new(config: config::VerifierConfig, clock: Box<dyn diport::Clock>) -> Self {
        Self { config, clock }
    }
}

impl ManagedResource for OidcProvider {
    fn name(&self) -> &str {
        "oidc"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        // 级联关闭 key 源：静态源 no-op（key 构造期注入、无句柄）；JWKS 文件源停后台 poll 刷新任务 + await
        // 收敛（#1109/T003）。OidcProvider 是组合根注册的唯一 ManagedResource，关闭经此下沉到 key source。
        #[cfg(feature = "backend")]
        {
            self.config.keys().shutdown().await
        }
        // reason: feature-off 空壳无 config / key 源 / 后台任务，关闭无显式动作（仅 freeze smoke 类型断言）。
        #[cfg(not(feature = "backend"))]
        {
            Ok(())
        }
    }
}

#[cfg(feature = "backend")]
impl diport::Pdp for OidcProvider {
    async fn verify(
        &self,
        raw: &diport::RawCredential,
    ) -> Result<diport::VerifiedClaims, diport::PdpError> {
        // scheme dispatch + 验签 + claim 映射全在 verify 模块（控制 lib.rs 认知复杂度）。纯计算（key + clock
        // 注入），无 await——async 仅为满足 port 签名（#1109 接 live JWKS 时在此 await）。
        verify::verify_credential(&self.config, self.clock.as_ref(), raw)
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
