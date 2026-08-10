//! 边缘防护策略（body-limit 上限 + security-headers 值集）——默认安全、可经 [`EdgeHardening`] 注入覆盖。
//!
//! [`BodyLimit`] 控制 Content-Length 检查门限（body_limit 中间件读此值判 413）；
//! [`SecurityHeaders`] 携一批默认安全响应头，经 [`tower_http::set_header::SetResponseHeaderLayer`]
//! 在 [`crate::routes::AuthenticatedRoutes::sealed_router`] 中统一叠层。
//!
//! ref: tower-http tower-http/src/set_header/response.rs@master（SetResponseHeaderLayer API）

use axum::http::{HeaderName, HeaderValue};
use tower_http::set_header::SetResponseHeaderLayer;

// ── header name constants（≥3 次使用抽 const；rust-standards §命名）────────────────────────────────
const HDR_X_CONTENT_TYPE_OPTIONS: &str = "x-content-type-options";
const HDR_X_FRAME_OPTIONS: &str = "x-frame-options";
const HDR_REFERRER_POLICY: &str = "referrer-policy";
const HDR_CONTENT_SECURITY_POLICY: &str = "content-security-policy";
const HDR_CROSS_ORIGIN_RESOURCE_POLICY: &str = "cross-origin-resource-policy";
const HDR_CACHE_CONTROL: &str = "cache-control";
const HDR_STRICT_TRANSPORT_SECURITY: &str = "strict-transport-security";

/// 请求体大小上限（bytes）——内部以 [`std::num::NonZeroUsize`] 存储，类型层禁止 0（AI-HARD）。
///
/// `new(0)` 在类型层不可表达（编译错误），消除原 Soft「调用方应避免 0」口头约定。
#[derive(Clone, Copy, Debug)]
pub struct BodyLimit(std::num::NonZeroUsize);

impl BodyLimit {
    /// 默认上限：1 MiB（1024 × 1024 bytes）。
    pub const DEFAULT: BodyLimit = BodyLimit(match std::num::NonZeroUsize::new(1024 * 1024) {
        Some(n) => n,
        None => unreachable!(),
    });

    /// 以非零字节数构造上限（`new(0)` 类型层不可表达——误配编译错误）。
    pub fn new(bytes: std::num::NonZeroUsize) -> Self {
        Self(bytes)
    }

    /// 上限字节数。
    pub fn bytes(self) -> usize {
        self.0.get()
    }
}

impl Default for BodyLimit {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// 安全响应头值集（默认：所有头开启）。
///
/// 各头按 OWASP Secure Headers Project 推荐值预设；`Cache-Control` 使用 `if_not_present`（允许
/// handler 自行覆写），其余启用的头均 `overriding`（框架统一强制）。HSTS 内层策略恒开启；是否可在
/// wire 上发送由持有真实 transport scheme 的 `httpd` adapter 最终裁决，plaintext 响应会被移除。
#[derive(Clone, Debug)]
pub struct SecurityHeaders {
    x_content_type_options: HeaderValue,
    x_frame_options: HeaderValue,
    referrer_policy: HeaderValue,
    content_security_policy: HeaderValue,
    cross_origin_resource_policy: Option<HeaderValue>,
    cache_control: HeaderValue,
    hsts: HeaderValue,
}

impl Default for SecurityHeaders {
    fn default() -> Self {
        Self {
            x_content_type_options: HeaderValue::from_static("nosniff"),
            x_frame_options: HeaderValue::from_static("DENY"),
            referrer_policy: HeaderValue::from_static("no-referrer"),
            content_security_policy: HeaderValue::from_static(
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
            ),
            cross_origin_resource_policy: Some(HeaderValue::from_static("same-origin")),
            cache_control: HeaderValue::from_static("no-store"),
            hsts: HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        }
    }
}

impl SecurityHeaders {
    /// 显式关闭框架的 CORP 策略，让 handler 自己决定是否以及如何发送该响应头。
    ///
    /// 默认仍为 overriding `same-origin`；只提供窄 opt-out，不开放任意值配置面。
    pub fn without_corp(self) -> Self {
        Self {
            cross_origin_resource_policy: None,
            ..self
        }
    }

    /// 产出各头对应的 tower-http response header layer 列表（供 sealed_router 逐层叠加）。
    ///
    /// 返回 `Vec<SetResponseHeaderLayer<HeaderValue>>`，调用方 for-each `.layer(hl)` 叠在 axum Router。
    /// 所有 layer 类型统一（`M = HeaderValue`），可同类型 Vec 收集。
    pub(crate) fn response_layers(&self) -> Vec<SetResponseHeaderLayer<HeaderValue>> {
        let mut layers: Vec<SetResponseHeaderLayer<HeaderValue>> = Vec::with_capacity(8);

        layers.push(SetResponseHeaderLayer::overriding(
            HeaderName::from_static(HDR_X_CONTENT_TYPE_OPTIONS),
            self.x_content_type_options.clone(),
        ));
        layers.push(SetResponseHeaderLayer::overriding(
            HeaderName::from_static(HDR_X_FRAME_OPTIONS),
            self.x_frame_options.clone(),
        ));
        layers.push(SetResponseHeaderLayer::overriding(
            HeaderName::from_static(HDR_REFERRER_POLICY),
            self.referrer_policy.clone(),
        ));
        layers.push(SetResponseHeaderLayer::overriding(
            HeaderName::from_static(HDR_CONTENT_SECURITY_POLICY),
            self.content_security_policy.clone(),
        ));
        if let Some(ref corp) = self.cross_origin_resource_policy {
            layers.push(SetResponseHeaderLayer::overriding(
                HeaderName::from_static(HDR_CROSS_ORIGIN_RESOURCE_POLICY),
                corp.clone(),
            ));
        }
        // Cache-Control：if_not_present，允许 handler 自行覆写缓存策略。
        layers.push(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static(HDR_CACHE_CONTROL),
            self.cache_control.clone(),
        ));
        // 内层 HSTS 恒存在；plaintext wire response 由持有真实 scheme 的 httpd adapter 删除。
        layers.push(SetResponseHeaderLayer::overriding(
            HeaderName::from_static(HDR_STRICT_TRANSPORT_SECURITY),
            self.hsts.clone(),
        ));

        layers
    }
}

/// 边缘防护配置（body-limit + security-headers）。
///
/// 以 [`Default`] 安全值初始化；组合根可经 [`crate::routes::AuthenticatedRoutes::with_edge_hardening`]
/// 覆盖（如调整 `body_limit`，或显式关闭框架 CORP 策略）。HSTS 的最终 wire 裁决属于
/// 持有真实 transport scheme 的 `httpd` adapter。
///
/// INVARIANT: BODYLIMIT-BEFORE-AUTH-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }——`EdgeHardening` 经 `sealed_router` 唯一 funnel 叠层，
/// 保证每个 bindable router 都带 body-limit 且 outer 于 auth（结构性 Hard：不经 sealed_router 无法 bind）。
#[derive(Clone, Debug, Default)]
pub struct EdgeHardening {
    pub body_limit: BodyLimit,
    pub headers: SecurityHeaders,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_limit_default_bytes() {
        assert_eq!(BodyLimit::DEFAULT.bytes(), 1_048_576, "1 MiB = 1024×1024");
        assert_eq!(BodyLimit::default().bytes(), 1_048_576);
    }

    #[allow(clippy::unwrap_used)]
    // reason: test — 512 is a known non-zero constant; unwrap is an infallible assertion.
    #[test]
    fn body_limit_new_custom() {
        let limit = BodyLimit::new(std::num::NonZeroUsize::new(512).unwrap());
        assert_eq!(limit.bytes(), 512);
    }

    #[test]
    fn edge_hardening_default_has_all_security_headers() {
        let hardening = EdgeHardening::default();
        let layers = hardening.headers.response_layers();
        // 默认应有 7 层（含 HSTS）
        assert_eq!(
            layers.len(),
            7,
            "默认 SecurityHeaders 应产出 7 层（含 HSTS）"
        );
    }

    #[test]
    fn security_headers_without_corp_removes_only_corp_layer() {
        let headers = SecurityHeaders::default().without_corp();
        assert_eq!(
            headers.response_layers().len(),
            6,
            "without_corp 应只移除 CORP 层"
        );
        assert!(headers.cross_origin_resource_policy.is_none());
        assert_eq!(
            headers.hsts,
            HeaderValue::from_static("max-age=63072000; includeSubDomains"),
            "CORP opt-out 不得弱化 HSTS 内层策略"
        );
    }

    /// SecurityHeaders 默认值断言：确保各 overriding 头的 value 正确。
    /// 通过构造 layer 后的字段是内部的，改为直接对 Default 结构做响应头集成测试（见 routes 集成测试）。
    /// 此处验证 layer 非空与 HSTS 必填闭值。
    #[test]
    fn security_headers_layers_nonempty_by_default() {
        let h = SecurityHeaders::default();
        assert!(!h.response_layers().is_empty());
        assert_eq!(
            h.hsts,
            HeaderValue::from_static("max-age=63072000; includeSubDomains")
        );
    }
}
