//! primitives — RSS 引擎层纯计算原语（crypto / authplan / healthz / circuitbreaker）。
//!
//! 引擎层 L0：trait 均 sync 静态分发、非 DI port（ADR-004 C1）；值类型字段私有、不 derive serde（C6）。
//! DI port（`Clock` 位参禁默认系统时钟、`ManagedResource` LIFO，ADR-001/ADR-003）**不在此**——
//! 归未来的 diport crate（spec tasks.md T012 / TD01）。
//!
//! ref: sony/gobreaker v2/gobreaker.go@master（circuitbreaker 三态状态机）；
//! uber-go/fx lifecycle.go@master（healthz 生命周期边界）。

pub mod authplan;
pub mod circuitbreaker;
pub mod crypto;
pub mod healthz;

pub use authplan::{
    AuthPlan, AuthPlanError, AuthRequirement, AuthScheme, ListenerKind, RequiredScheme,
    RouteAuthOptOut, resolve_requirement,
};
pub use circuitbreaker::{
    BreakerConfig, BreakerConfigError, BreakerEvent, CallOutcome, CircuitCounts, CircuitState,
    allows_request, next_state,
};
pub use crypto::{
    Digest, DigestAlgorithm, Digester, Mac, MacAlgorithm, MacKey, MacVerifier, constant_time_eq,
};
pub use healthz::{HealthCheck, HealthReport, HealthStatus, ProbeName, ProbeNameError};

#[cfg(test)]
mod smoke {
    //! build smoke：证明 sync 纯计算 trait 可被泛型静态分发消费 + 闭值集 / 值类型 / 纯函数签名可引用。
    use crate::authplan::{
        AuthPlan, AuthRequirement, AuthScheme, ListenerKind, RequiredScheme, RouteAuthOptOut,
        resolve_requirement,
    };
    use crate::circuitbreaker::{
        BreakerConfig, BreakerEvent, CallOutcome, CircuitCounts, CircuitState, allows_request,
        next_state,
    };
    use crate::crypto::{
        Digest, DigestAlgorithm, Digester, Mac, MacAlgorithm, MacKey, MacVerifier,
    };
    use crate::healthz::HealthStatus;

    // 证明：sync 纯计算 trait 可被泛型静态分发消费（native，无 dynosaur/async-trait）。
    fn _consume_digester<D: Digester>(d: &D, input: &[u8]) -> Digest {
        d.digest(DigestAlgorithm::Sha256, input)
    }
    fn _consume_mac_verifier<M: MacVerifier>(
        m: &M,
        key: &MacKey,
        algorithm: MacAlgorithm,
        msg: &[u8],
        tag: &Mac,
    ) -> bool {
        m.verify(key, algorithm, msg, tag)
    }

    // 证明：trait 可被 impl（签名形状闭合；body 为最简合法实现）。
    struct NoopDigester;
    impl Digester for NoopDigester {
        fn digest(&self, _algorithm: DigestAlgorithm, _input: &[u8]) -> Digest {
            // reason: noop 仅用于 smoke 证签名可静态分发，永不生产使用。
            Digest::from_bytes(Vec::new())
        }
    }

    struct NoopMacVerifier;
    impl MacVerifier for NoopMacVerifier {
        fn sign(&self, _key: &MacKey, _algorithm: MacAlgorithm, _message: &[u8]) -> Mac {
            // reason: noop 仅用于 smoke 证签名可静态分发，永不生产使用。
            Mac::from_bytes(Vec::new())
        }
        fn verify(
            &self,
            _key: &MacKey,
            _algorithm: MacAlgorithm,
            _message: &[u8],
            tag: &Mac,
        ) -> bool {
            // reason: noop verifier 仅用于 smoke 编译测试，常数时间比较空标签（永不在生产使用）。
            crate::crypto::constant_time_eq(tag.as_bytes(), &[])
        }
    }

    // 闭值集 enum / 值类型 / 纯函数签名可被引用消费（编译期）。
    #[test]
    fn type_and_fn_signatures_are_consumable() {
        let _state: CircuitState = CircuitState::HalfOpen;
        let _event = BreakerEvent::Call(CallOutcome::Success);
        let _scheme = AuthScheme::NoAuth;
        let _kind = ListenerKind::Internal;
        let _opt = RouteAuthOptOut::Public;
        let _sev = HealthStatus::Degraded;
        let _req = AuthRequirement::Require(RequiredScheme::RssAccessToken);
        let _mac_alg = MacAlgorithm::HmacSha256;

        // 函数指针绑定证明签名形状。
        let _f: fn(CircuitState, CircuitCounts, BreakerConfig, BreakerEvent) -> CircuitState =
            next_state;
        let _g: fn(CircuitState, CircuitCounts, BreakerConfig) -> bool = allows_request;
        let _h: fn(AuthPlan, Option<RouteAuthOptOut>) -> AuthRequirement = resolve_requirement;
        let _i = _consume_digester::<NoopDigester>;
        let _j = _consume_mac_verifier::<NoopMacVerifier>;
    }
}
