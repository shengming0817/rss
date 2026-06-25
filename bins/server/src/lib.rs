//! server — RSS 组合根（Root 层）：从配置构造生产验签 provider，按 listener 装配
//! `finalize_routes → finalize_auth → .layer(verify_bridge)` 的认证接线接缝。
//!
//! 本 crate（#1198 / T004 / PR-C）只落地**认证接线接缝 + e2e**；socket bind / `axum::serve` / 信号优雅关停 /
//! 全量生产域注册 / 全量 config 编排 = **Join #1017**。live JWKS 远程拉取 + 轮转 = **T003/#1197**（本 PR 用
//! `StaticKeySource` 构造期注入 key，构造器签名已为其留稳）。
//!
//! 安全同批门（ADR-006 §5）：依赖图引真 verifier（`oidc` backend）、不引 stub Pdp（`memory` 经 deny.toml 禁
//! server/rss；bins 生产 `src/` 无内联 `impl diport::Pdp`，`rss_pdp_impl_adapter_only` dylint 守 +
//! `cargo xtask verify` 的 pdp-allow 计数门守逃生门用量）。`OidcProvider` 必填 `VerifierConfig` + `Box<dyn Clock>`
//! ⇒ 无 key/clock 不可构造（编译期守）。
//!
//! NOTE: `bins/server` 与 `bins/rss` 的 `auth_bridge.rs` / `lib.rs` / `tests/auth_e2e.rs` **字节级同步**
//! （仅 crate 名不同，tasks.md T004.2 既定 duplicate-now）；改一处须同步另一处；逻辑增长时提取 `assemblies/authwire` 再删副本。

pub mod auth_bridge;

use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Context as _;
use base64::Engine as _;
use oidc::OidcProvider;
use primitives::{AuthPlan, AuthScheme, ListenerKind, RequiredScheme};

/// 生产系统时钟（组合根注入 `OidcProvider`）。
///
/// 组合根是 sanctioned 直读系统时钟点（`diport::Clock` rustdoc：「prod `SystemClock` 内部调 `SystemTime::now`，
/// 受 clippy `disallowed_methods` 约束、仅在 adapter / 组合根 item-level 解禁」）。
pub struct SystemClock;

impl diport::Clock for SystemClock {
    fn now(&self) -> SystemTime {
        // reason: 组合根生产时钟——唯一 sanctioned 直读系统时钟点（rust-standards「Clock 构造器位置参」的 prod 实现）。
        #[allow(clippy::disallowed_methods)]
        SystemTime::now()
    }
}

/// 从 env 构造生产验签 `OidcProvider`（issuer / audience / ES256·HS256 静态 key）。
///
/// - `RSS_OIDC_ISSUER` / `RSS_OIDC_AUDIENCE`：必填。
/// - `RSS_OIDC_TRUSTED_KINDS`：**必填**——本 IdP 可 assert 的 principal kind 逗号分隔白名单（如 `user,admin,device`）。
///   secure-by-default（OIDC-KIND-ALLOWLIST-01）：未配置则验签器剥离所有 kind → `Principal` 派生恒 `TokenInvalid`
///   → JWT **全 401**（评审 F1 修复的生产失效根因），故构造期 fail-fast 拒空。
/// - `RSS_OIDC_ES256_SEC1_B64URL`：JWT 路径 ES256 公钥，base64url(SEC1 未压缩点)，逗号分隔可多把（可选）。
/// - `RSS_OIDC_HS256_SECRET_B64URL`：service-token 路径 HS256 密钥，base64url（可选）。
///
/// 薄壳：注入 `std::env::var` 读取器，委托可测核心 [`build_provider_from`]。
pub fn build_provider() -> anyhow::Result<OidcProvider> {
    build_provider_from(|name| std::env::var(name).ok())
}

/// 由注入的配置读取器构造 `OidcProvider`（DI：测试传 fake getter，无 env 副作用——workspace `forbid(unsafe)`
/// 下测试不能 `set_var`，故读取器入参化）。错误只含变量**名**，不含值（无 PII / 无 secret 泄漏）。
fn build_provider_from(get: impl Fn(&str) -> Option<String>) -> anyhow::Result<OidcProvider> {
    let issuer = get("RSS_OIDC_ISSUER")
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_OIDC_ISSUER"))?;
    let audience = get("RSS_OIDC_AUDIENCE")
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_OIDC_AUDIENCE"))?;
    let trusted_kinds = get("RSS_OIDC_TRUSTED_KINDS")
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_OIDC_TRUSTED_KINDS"))?;
    provider_from_b64(
        &issuer,
        &audience,
        &trusted_kinds,
        get("RSS_OIDC_ES256_SEC1_B64URL").as_deref(),
        get("RSS_OIDC_HS256_SECRET_B64URL").as_deref(),
        Box::new(SystemClock),
    )
}

/// 由已读出的配置串装配生产 `OidcProvider`（纯函数，无 env 副作用——**生产装配唯一路径**，e2e 经此覆盖以杜绝
/// 测试/生产配置漂移，评审 F2）。
///
/// - `trusted_kinds_csv`：逗号分隔 trusted principal kind（`.trust_kind` 白名单，OIDC-KIND-ALLOWLIST-01）；解析后
///   **空集 fail-fast**——无 trusted kind 的 provider 验签 JWT 恒剥离 kind → 派生 `TokenInvalid` → 全 401（F1 根因）。
/// - `es256_csv` = 逗号分隔 base64url(SEC1 未压缩点)；`hs256_b64` = base64url HS256 密钥。两集皆空时
///   `VerifierConfigBuilder::build` fail-fast 拒（无 key 的 provider 验签恒失败、是配置错误）。
/// - `clock`：验签时钟（构造器位置参，rust-standards「Clock 是构造器位置参」）。生产传 [`SystemClock`]，
///   e2e 传 `FixedClock` 经**同一生产装配路径**覆盖（评审 F2：杜绝测试/生产配置漂移）。
pub fn provider_from_b64(
    issuer: &str,
    audience: &str,
    trusted_kinds_csv: &str,
    es256_csv: Option<&str>,
    hs256_b64: Option<&str>,
    clock: Box<dyn diport::Clock>,
) -> anyhow::Result<OidcProvider> {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut keys = oidc::StaticKeySource::builder();
    if let Some(es) = es256_csv {
        for part in es.split(',').filter(|s| !s.is_empty()) {
            let sec1 = b64
                .decode(part)
                .context("RSS_OIDC_ES256_SEC1_B64URL not valid base64url")?;
            keys = keys
                .add_es256_sec1(&sec1)
                .map_err(|e| anyhow::anyhow!("invalid ES256 key: {e}"))?;
        }
    }
    if let Some(hs) = hs256_b64 {
        let secret = b64
            .decode(hs)
            .context("RSS_OIDC_HS256_SECRET_B64URL not valid base64url")?;
        keys = keys
            .add_hs256_secret(&secret)
            .map_err(|e| anyhow::anyhow!("weak HS256 secret: {e}"))?;
    }

    let mut builder = oidc::VerifierConfigBuilder::new(issuer, audience).keys(keys.build());
    let mut trusted = 0usize;
    for kind in trusted_kinds_csv
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        builder = builder.trust_kind(kind);
        trusted += 1;
    }
    if trusted == 0 {
        // F1 根因 fail-fast：无 trusted kind ⇒ JWT 的 kind 被剥离 ⇒ Principal 派生 TokenInvalid ⇒ 全 401。
        anyhow::bail!(
            "RSS_OIDC_TRUSTED_KINDS must list ≥1 trusted principal kind (else all JWTs 401)"
        );
    }
    let config = builder
        .build()
        .map_err(|e| anyhow::anyhow!("invalid verifier config: {e}"))?;
    Ok(OidcProvider::new(config, clock))
}

/// listener → 认证方案策略（runtime-api.md §Listener：单 listener 单 scheme）。
fn auth_scheme(listener: ListenerKind) -> AuthScheme {
    match listener {
        ListenerKind::Primary | ListenerKind::Admin => AuthScheme::Jwt,
        ListenerKind::Internal => AuthScheme::ServiceToken,
        ListenerKind::Health => AuthScheme::NoAuth,
        // ListenerKind non_exhaustive——未知 listener fail-closed 要求 JWT 认证（绝不默认 NoAuth）+ 配置期 warn 埋点。
        _ => {
            tracing::warn!(listener = ?listener, "unknown ListenerKind; fail-closed to JWT auth scheme");
            AuthScheme::Jwt
        }
    }
}

/// listener → 验签桥应验证的方案（`NoAuth` listener 不挂桥 ⇒ `None`）。
///
/// `Mtls`（传输层鉴权，非本桥职责）与 `non_exhaustive` 未知方案均 → `None`（不挂桥 ⇒ 该 listener 的 Require
/// 路由由 enforce fail-closed 401）+ 配置期 warn 埋点（消除「required_scheme 说要 Mtls 桥、但 bridge 不支持 Mtls」
/// 的死代码 + 不一致，评审 F2）。
fn required_scheme(listener: ListenerKind) -> Option<RequiredScheme> {
    match auth_scheme(listener) {
        AuthScheme::Jwt | AuthScheme::JwtFromAssembly => Some(RequiredScheme::Jwt),
        AuthScheme::ServiceToken => Some(RequiredScheme::ServiceToken),
        AuthScheme::NoAuth => None,
        other => {
            tracing::warn!(scheme = ?other, "listener auth scheme has no verify-bridge; Require routes fail-closed 401");
            None
        }
    }
}

/// 排空 registry 的 per-listener `UnfinalizedRoutes`，按 listener 装配 `finalize_auth` + 外层验签桥。
///
/// 每 listener：`finalize_auth(routes, plan)`（消费 `UnfinalizedRoutes` 产 `AuthenticatedRoutes`，注入
/// AuthPlan 与 framework 中间件）→ 据 `required_scheme` 叠外层 `verify_bridge`（`NoAuth` listener 无桥）。
/// 产出 `AuthenticatedRoutes` 交 #1017 经 `into_make_service` 绑 socket + serve——bind 点天生只能消费已认证
/// router（ROUTE-AUTH-FUNNEL-01/02：未跑 finalize_auth 的 router 无 bindable 出口）。
pub fn assemble_authed_routers(
    mut registry: bootstrap::Registry,
    provider: Arc<OidcProvider>,
) -> anyhow::Result<Vec<(ListenerKind, httpserve::AuthenticatedRoutes)>> {
    let mut out = Vec::new();
    for (listener, routes) in registry.finalize_routes().context("finalize_routes")? {
        let scheme = auth_scheme(listener);
        let plan = AuthPlan::new(listener, scheme).context("build auth plan")?;
        let authed = httpserve::finalize_auth(routes, plan).context("finalize_auth")?;
        let required = required_scheme(listener);
        let wired = match required {
            Some(req) => auth_bridge::apply_verify_bridge(authed, provider.clone(), req),
            None => authed,
        };
        // 装配决策可观测：operator 启动时从日志核查每 listener 的 auth scheme + 是否挂验签桥
        //（闭值枚举，无 PII）——否则「Primary 究竟 Jwt+桥 还是意外 NoAuth」从日志无从核查。
        tracing::info!(
            listener = ?listener,
            auth_scheme = ?scheme,
            verify_bridge = required.is_some(),
            "listener auth wiring assembled"
        );
        out.push((listener, wired));
    }
    Ok(out)
}

/// 生产组合根入口：构造 provider → compose 域 → 装配认证接线。
///
/// 本 PR（#1198）域图为空；socket bind / serve / 信号优雅关停 / 全量生产域注册 = **Join #1017**。
pub fn run() -> anyhow::Result<()> {
    let provider = Arc::new(build_provider()?);
    let registry = bootstrap::compose(&[]).context("compose domains")?;
    let _authed = assemble_authed_routers(registry, provider)?;
    // TODO(#1017): 消费 `_authed`——对每个 `(listener, AuthenticatedRoutes)` 调 `.into_make_service()`（**唯一**
    //   bindable 出口，ROUTE-AUTH-FUNNEL-02）→ `axum::serve(<该 listener 的 socket>, make_service)`；+ 信号优雅
    //   关停 + 全量生产域注册（identity/settings/audit/...）。`_authed` 当前被 drop（bind 点未接线）；接线时
    //   勿绕开 `into_make_service` 改走裸 router 路径（类型层已封死，见 httpserve::routes）。
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const B64: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::URL_SAFE_NO_PAD;

    /// 测试时钟（这些测试只验构造成功/失败，不验 token exp，故 SystemClock 即可）。
    fn clk() -> Box<dyn diport::Clock> {
        Box::new(SystemClock)
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn auth_scheme_per_listener() {
        assert_eq!(auth_scheme(ListenerKind::Primary), AuthScheme::Jwt);
        assert_eq!(auth_scheme(ListenerKind::Admin), AuthScheme::Jwt);
        assert_eq!(
            auth_scheme(ListenerKind::Internal),
            AuthScheme::ServiceToken
        );
        assert_eq!(auth_scheme(ListenerKind::Health), AuthScheme::NoAuth);
    }

    #[test]
    fn required_scheme_maps_and_health_is_none() {
        assert_eq!(
            required_scheme(ListenerKind::Primary),
            Some(RequiredScheme::Jwt)
        );
        assert_eq!(
            required_scheme(ListenerKind::Internal),
            Some(RequiredScheme::ServiceToken)
        );
        assert_eq!(required_scheme(ListenerKind::Health), None);
    }

    #[test]
    fn provider_from_b64_empty_keys_fails_fast() {
        // 无任何 key → VerifierConfigBuilder::build fail-fast（无 key 的 provider 是配置错误）。
        assert!(
            provider_from_b64("https://issuer.test", "rss", "user", None, None, clk()).is_err()
        );
    }

    #[test]
    fn provider_from_b64_empty_trusted_kinds_fails_fast() {
        // 评审 F1：无 trusted kind ⇒ JWT kind 被剥离 ⇒ 派生 TokenInvalid ⇒ 全 401，构造期 fail-fast 拒。
        let secret = B64.encode([7u8; 32]);
        let r = provider_from_b64(
            "https://issuer.test",
            "rss",
            "  ,  ",
            None,
            Some(&secret),
            clk(),
        );
        assert!(matches!(&r, Err(e) if e.to_string().contains("RSS_OIDC_TRUSTED_KINDS")));
    }

    #[test]
    fn build_provider_from_missing_trusted_kinds_fails_fast() {
        // issuer + audience 在、trusted kinds 缺 → fail-fast（F1 生产失效根因守）。
        let get = |k: &str| match k {
            "RSS_OIDC_ISSUER" => Some("https://issuer.test".to_string()),
            "RSS_OIDC_AUDIENCE" => Some("rss".to_string()),
            _ => None,
        };
        assert!(
            matches!(&build_provider_from(get), Err(e) if e.to_string().contains("RSS_OIDC_TRUSTED_KINDS"))
        );
    }

    #[test]
    fn build_provider_from_missing_issuer_fails_fast() {
        // 注入恒空读取器 → 缺 RSS_OIDC_ISSUER fail-fast（错误含变量名，不读真 env）。
        // OidcProvider 无 Debug（不能 expect_err），用 matches! 既断言 Err 又锁错误文案。
        let result = build_provider_from(|_| None);
        assert!(matches!(&result, Err(e) if e.to_string().contains("RSS_OIDC_ISSUER")));
    }

    #[test]
    fn build_provider_from_missing_audience_fails_fast() {
        // issuer 存在、audience 缺失 → fail-fast 命中 audience 那行（独立于 issuer 缺失路径）。
        let get = |k: &str| (k == "RSS_OIDC_ISSUER").then(|| "https://issuer.test".to_string());
        let result = build_provider_from(get);
        assert!(matches!(&result, Err(e) if e.to_string().contains("RSS_OIDC_AUDIENCE")));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_provider_from_happy_hs256() {
        let secret = B64.encode([7u8; 32]);
        let get = |k: &str| match k {
            "RSS_OIDC_ISSUER" => Some("https://issuer.test".to_string()),
            "RSS_OIDC_AUDIENCE" => Some("rss".to_string()),
            "RSS_OIDC_TRUSTED_KINDS" => Some("user,admin".to_string()),
            "RSS_OIDC_HS256_SECRET_B64URL" => Some(secret.clone()),
            _ => None,
        };
        build_provider_from(get).expect("issuer + aud + trusted kinds + hs256 key ⇒ 构造成功");
    }

    #[test]
    fn system_clock_now_is_after_epoch() {
        use diport::Clock as _;
        // 覆盖组合根生产时钟读点（disallowed_methods item-level 解禁线）。
        assert!(SystemClock.now() > SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn provider_from_b64_bad_base64_fails_fast() {
        // ES256 串非 base64url → fail-fast（误配在 setup 期暴露，非运行时静默）。
        let bad = provider_from_b64(
            "https://issuer.test",
            "rss",
            "user",
            Some("!!not-b64!!"),
            None,
            clk(),
        );
        assert!(bad.is_err());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn provider_from_b64_with_hs256_ok() {
        let secret = B64.encode([7u8; 32]);
        let p = provider_from_b64(
            "https://issuer.test",
            "rss",
            "user",
            None,
            Some(&secret),
            clk(),
        );
        assert!(
            p.is_ok(),
            "有效 HS256 key + issuer/aud + trusted kind ⇒ 构造成功"
        );
        let _ = p.expect("ok");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn assemble_empty_registry_yields_no_routers() {
        let secret = B64.encode([7u8; 32]);
        let provider = Arc::new(
            provider_from_b64(
                "https://issuer.test",
                "rss",
                "user",
                None,
                Some(&secret),
                clk(),
            )
            .expect("provider"),
        );
        let registry = bootstrap::compose(&[]).expect("compose empty");
        let routers = assemble_authed_routers(registry, provider).expect("assemble ok");
        assert!(routers.is_empty(), "空域图 ⇒ 无 per-listener router");
    }
}
