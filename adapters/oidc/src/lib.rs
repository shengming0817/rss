//! Profile-typed JWT verifier adapter.
//!
//! [`OidcProvider<P>`] binds one sealed token profile to one verifier configuration. Production
//! runtime composition wraps it in the exhaustive `ProfileBinding` enum and derives the matching
//! authn funnel from that same variant, so a listener cannot select a profile from untrusted token
//! data.
//! Before parsing a compact token, the provider checks that [`diport::RawCredential::profile`]
//! matches `P`.
//!
//! With `backend` enabled, access profiles accept keyed ES256 material from
//! [`AccessStaticKeySource`], [`JwksKeySource`], or [`IsolatedJwksKeySource`]. The service-token
//! profile accepts keyed HS256 material only from [`ServiceTokenKeySource`] and requires a durable
//! replay store. RSS and federated access providers therefore have no HS256 builder method, while
//! the service-token provider has no ES256 or JWKS builder method.
//!
//! Verification is fail-closed and ordered as follows: encoded-size and compact-JWS checks;
//! exact protected `alg`/`typ`/`kid` validation; exact-`kid` key selection; standard JWS signature
//! verification over `header.payload`; required time, issuer, audience, `token_use`, principal-kind,
//! and tenant semantics (service-token signed typed `tenant_id` is the authority; exact-one
//! `X-Tenant-ID` is challenger-only equality after typed claims, before replay consume); finally
//! service-token `jti` replay consumption. JWKS refreshes publish an all-or-nothing last-good
//! snapshot and expose readiness through the runtime resource graph.
//!
//! Without `backend`, the provider remains a crypto-free type shell used by adapter-port compile
//! checks.

#![deny(rustdoc::broken_intra_doc_links)]

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
    AccessStaticKeySource, AccessStaticKeySourceBuilder, ConfigError, FederatedPermissionUniverse,
    RetirementSchedule, ServiceTokenKeySource, ServiceTokenKeySourceBuilder, VerifierConfig,
    VerifierConfigBuilder,
};
#[cfg(feature = "backend")]
pub use jwks::{
    AccessJwksKeyIsolation, AccessJwksKeyIsolationGeneration, IsolatedJwksKeySource, JwksError,
    JwksKeySource, JwksReadinessHandle, RssSigningKeyProofError, prove_rss_signer_matches_jwks,
};

use std::marker::PhantomData;

use diport::{ManagedResource, ShutdownError, TokenProfileMarker};

/// OIDC JWT / service-token 验签 adapter（sealed-marker）。
///
/// `backend` feature 关时为空壳（仅供 freeze smoke 类型断言）；开时持有验签配置 + 注入时钟。key
/// 构造期注入；service-token 验签还会异步调用配置中注入的 durable replay-store port。
pub struct OidcProvider<P: TokenProfileMarker> {
    #[cfg(feature = "backend")]
    config: config::VerifierConfig<P>,
    #[cfg(feature = "backend")]
    clock: Box<dyn diport::Clock>,
    profile: PhantomData<fn() -> P>,
}

#[cfg(feature = "backend")]
impl<P: TokenProfileMarker> OidcProvider<P> {
    /// 由验签配置 + 注入时钟构造。
    ///
    /// 组合根与测试经 [`VerifierConfigBuilder`] 配置 profile-specific key source：
    /// access 使用 [`AccessStaticKeySource`] / [`JwksKeySource`] /
    /// [`IsolatedJwksKeySource`]，service-token 使用 [`ServiceTokenKeySource`]。`clock`
    /// 是必填位置参数；fail-fast 校验集中在 builder `build()`，本构造只接受字段私有的已校验
    /// [`VerifierConfig`]，故为 infallible。
    pub fn new(config: config::VerifierConfig<P>, clock: Box<dyn diport::Clock>) -> Self {
        Self {
            config,
            clock,
            profile: PhantomData,
        }
    }
}

impl<P: TokenProfileMarker> ManagedResource for OidcProvider<P> {
    fn name(&self) -> &str {
        "oidc"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        // 级联关闭 key 源：静态源 no-op（key 构造期注入、无句柄）；JWKS 文件源停后台 poll 刷新任务 + await
        // 收敛。OidcProvider 是组合根注册的 ManagedResource，关闭经此下沉到 key source。
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
impl<P: TokenProfileMarker> diport::Pdp for OidcProvider<P> {
    async fn verify(
        &self,
        raw: &diport::RawCredential,
    ) -> Result<diport::VerifiedClaims, diport::PdpError> {
        // scheme dispatch + 验签 + claim 映射全在 verify 模块（控制 lib.rs 认知复杂度）；service-token
        // replay consume 是真正异步 durable I/O。
        verify::verify_credential(&self.config, self.clock.as_ref(), raw).await
    }
}

#[cfg(test)]
mod smoke {
    //! build smoke：编译期断言 sealed-marker 已 impl 冻结的 diport DI port trait（PhantomData 绑定检查，
    //! 不构造、不执行 body）。
    //! INVARIANT: ADAPTER-PORT-FREEZE-04 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }—— sealed-marker impl 冻结的 diport DI port trait（`ManagedResource`
    //! 始终；`Pdp` 于 backend）；去掉任一 impl 即编译失败（anti-vacuity）。
    use core::marker::PhantomData;

    fn assert_managed_resource<T: diport::ManagedResource>(_: PhantomData<T>) {}

    #[test]
    fn impls_managed_resource() {
        assert_managed_resource(PhantomData::<super::OidcProvider<diport::RssAccessProfile>>);
    }

    #[cfg(feature = "backend")]
    fn assert_pdp<T: diport::Pdp>(_: PhantomData<T>) {}

    #[cfg(feature = "backend")]
    #[test]
    fn impls_pdp() {
        assert_pdp(PhantomData::<super::OidcProvider<diport::RssAccessProfile>>);
    }
}
