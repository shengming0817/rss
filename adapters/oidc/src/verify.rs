//! JWT 验签映射（jsonwebtoken decode → `diport::VerifiedClaims`；失败 → `PdpError`）。逻辑拆出 lib.rs 控认知复杂度。
//!
//! 验签链：scheme dispatch（`Jwt` 走签名验签 / `ServiceToken` → `Untrusted`）→ 逐 key 试解（签名 + exp/nbf +
//! iss + aud，algorithm allowlist 拒 `alg:none` 与对称算法混淆）→ 成功取 `sub` → subject、可配置 tenant·kind
//! claim 透传。错误经 `secure::redact_error` + `tracing::warn` 记录顶层摘要后**归类**到 `PdpError` 三变体（不
//! 透传 source 链）。PII 边界：**绝不**记录原始 token（含签名 / payload）；只记 reason 闭值标签。`kind` →
//! `PrincipalKind` 策略归 authn（非本层，见 `diport::pdp` rustdoc）——adapter 只透传原始 claim 串。
//!
//! ref: Keats/jsonwebtoken src/validation.rs（`Validation{algorithms,iss,aud,validate_exp,validate_nbf,
//! required_spec_claims}`）+ src/decoding.rs（`decode::<T>`, `DecodingKey::{from_rsa_pem,from_ec_pem}`）@v9.3.1。

use diport::{CredentialScheme, PdpError, RawCredential, VerifiedClaims};
use jsonwebtoken::{DecodingKey, Validation, decode};
use serde::Deserialize;

/// 对外暴露 jsonwebtoken 的算法枚举（组合根 / 测试经 builder 绑定每把 key 的算法 allowlist）。直接 re-export
/// 而非镜像一层，避免无谓映射（优雅简洁）；对称算法由 builder 拒绝（见 [`VerifierConfigBuilder`]）。
pub use jsonwebtoken::Algorithm;

/// 验签器构造期配置错误（fail-fast：误配在组合根接线 / 测试 setup 期暴露，不在每次验签静默失败）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// issuer 为空（验签必须锁定可信签发者）。
    #[error("oidc issuer must not be empty")]
    EmptyIssuer,
    /// audience 为空（验签必须锁定本服务 audience，防 token 重放到别的 RP）。
    #[error("oidc audience must not be empty")]
    EmptyAudience,
    /// 未注入任何解码 key（无 key 无法验签）。
    #[error("oidc decoding key set must not be empty")]
    NoDecodingKeys,
    /// tenant / kind claim 名为空（配空名等于无声吞掉映射）。
    #[error("oidc claim name must not be empty")]
    EmptyClaimName,
    /// 某把 key 的算法 allowlist 为空（无算法 = 无法验签该 key）。
    #[error("oidc decoding key algorithm allowlist must not be empty")]
    EmptyAlgorithms,
    /// 算法 allowlist 含对称（HMAC）算法。OIDC 验签器只接受非对称算法——否则 RS256→HS256 key-confusion：
    /// 攻击者以公钥当 HMAC 密钥伪造签名（INVARIANT: OIDC-ALG-ASYMMETRIC-ONLY-01）。
    #[error("oidc verifier must not accept symmetric (HMAC) algorithms")]
    SymmetricAlgorithm,
    /// PEM 解析失败（key 格式非法）。原始 parse 错误不入 wire / 此变体（公钥非敏感，但保持归类一致）。
    #[error("oidc decoding key is malformed")]
    InvalidKey,
}

/// 单把解码 key + 其允许算法（allowlist 锁在 key 上：RS* key 只验 RS*，杜绝 alg 混淆）。
struct VerifyKey {
    key: DecodingKey,
    algorithms: Vec<Algorithm>,
}

/// 注入验签配置（构造侧经 [`VerifierConfigBuilder`] 提供；字段私有 + 唯一构造入口 = builder，外部不可伪造）。
pub struct VerifierConfig {
    issuer: String,
    audience: String,
    keys: Vec<VerifyKey>,
    tenant_claim: String,
    kind_claim: String,
}

/// 验签后反序列化的 claims（私有 DTO，非域实体）。`sub` 必有；`exp`/`iss`/`aud`/`nbf` 由 jsonwebtoken
/// `Validation` 内部独立校验（不经本 `T`）；其余（含可配置 tenant/kind claim）经 `flatten` 落 `extra`，按
/// 配置名取字符串值。
#[derive(Deserialize)]
struct Claims {
    sub: String,
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

/// `VerifierConfig` 累加式 builder：注入 issuer / audience / 解码 key（每把绑定算法 allowlist）/ 可配置
/// tenant·kind claim 名。`build()` 做最终 fail-fast 校验（option 范式：累加可忽略空输入，最终 build 必校验）。
pub struct VerifierConfigBuilder {
    issuer: String,
    audience: String,
    tenant_claim: String,
    kind_claim: String,
    keys: Vec<VerifyKey>,
}

impl VerifierConfigBuilder {
    /// 新建 builder。tenant/kind claim 名默认 `"tenant_id"` / `"kind"`，经 [`Self::tenant_claim`] /
    /// [`Self::kind_claim`] 覆盖。
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            tenant_claim: "tenant_id".to_string(),
            kind_claim: "kind".to_string(),
            keys: Vec::new(),
        }
    }

    /// 覆盖 tenant claim 名（如 `"org"` / `"tid"`）。
    #[must_use]
    pub fn tenant_claim(mut self, name: impl Into<String>) -> Self {
        self.tenant_claim = name.into();
        self
    }

    /// 覆盖 kind claim 名（如 `"typ"` / `"principal_kind"`）。
    #[must_use]
    pub fn kind_claim(mut self, name: impl Into<String>) -> Self {
        self.kind_claim = name.into();
        self
    }

    /// 注入一把 RSA 公钥（PEM，SPKI 或 PKCS#1）+ 其算法 allowlist（如 `&[Algorithm::RS256]`）。
    pub fn add_rsa_pem_key(
        self,
        pem: &[u8],
        algorithms: &[Algorithm],
    ) -> Result<Self, ConfigError> {
        let key = DecodingKey::from_rsa_pem(pem).map_err(|_| ConfigError::InvalidKey)?;
        self.push_key(key, algorithms)
    }

    /// 注入一把 EC 公钥（PEM）+ 其算法 allowlist（如 `&[Algorithm::ES256]`）。
    pub fn add_ec_pem_key(self, pem: &[u8], algorithms: &[Algorithm]) -> Result<Self, ConfigError> {
        let key = DecodingKey::from_ec_pem(pem).map_err(|_| ConfigError::InvalidKey)?;
        self.push_key(key, algorithms)
    }

    /// 校验算法 allowlist（非空 + 无对称）后入队。algorithm allowlist 绑定每把 key——RS* key 只验 RS*。
    fn push_key(mut self, key: DecodingKey, algorithms: &[Algorithm]) -> Result<Self, ConfigError> {
        if algorithms.is_empty() {
            return Err(ConfigError::EmptyAlgorithms);
        }
        if algorithms.iter().any(is_symmetric) {
            return Err(ConfigError::SymmetricAlgorithm);
        }
        self.keys.push(VerifyKey {
            key,
            algorithms: algorithms.to_vec(),
        });
        Ok(self)
    }

    /// 最终 fail-fast 校验 + 装箱。
    pub fn build(self) -> Result<VerifierConfig, ConfigError> {
        if self.issuer.is_empty() {
            return Err(ConfigError::EmptyIssuer);
        }
        if self.audience.is_empty() {
            return Err(ConfigError::EmptyAudience);
        }
        if self.keys.is_empty() {
            return Err(ConfigError::NoDecodingKeys);
        }
        if self.tenant_claim.is_empty() || self.kind_claim.is_empty() {
            return Err(ConfigError::EmptyClaimName);
        }
        Ok(VerifierConfig {
            issuer: self.issuer,
            audience: self.audience,
            keys: self.keys,
            tenant_claim: self.tenant_claim,
            kind_claim: self.kind_claim,
        })
    }
}

/// 对称（HMAC）算法判定——OIDC 验签器一律拒（防 key-confusion）。
fn is_symmetric(alg: &Algorithm) -> bool {
    matches!(alg, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512)
}

/// scheme dispatch：`Jwt` 走签名验签；其余（`ServiceToken` + 未来 scheme，`CredentialScheme` 为
/// `#[non_exhaustive]`）一律 `Untrusted`——OIDC provider 只签 JWT，service-token 等另有验签器（fail-closed）。
pub(crate) fn verify_credential(
    config: &VerifierConfig,
    raw: &RawCredential,
) -> Result<VerifiedClaims, PdpError> {
    match raw.scheme() {
        CredentialScheme::Jwt => verify_jwt(config, raw.token()),
        other => {
            // fail-closed：不记 token；scheme tag（闭值集、非 PII）入日志足够诊断。
            tracing::warn!(
                target: "oidc",
                resource = "oidc",
                reason = "non_jwt_scheme",
                scheme = ?other,
                "oidc rejects non-jwt credential scheme"
            );
            Err(PdpError::Untrusted)
        }
    }
}

/// 逐 key 试解（多 key 支持轮转 / 多 IdP）：任一把成功即接受；全失败按最后错误归类。
fn verify_jwt(config: &VerifierConfig, token: &str) -> Result<VerifiedClaims, PdpError> {
    let mut last_err = None;
    for vk in &config.keys {
        let validation = build_validation(config, &vk.algorithms);
        match decode::<Claims>(token, &vk.key, &validation) {
            Ok(data) => return Ok(map_claims(config, data.claims)),
            Err(err) => last_err = Some(err),
        }
    }
    Err(classify(last_err))
}

/// 构造 `Validation`：algorithm allowlist（拒 `alg:none` 与不在集内的算法）+ iss/aud 锁定 + exp/nbf 校验 +
/// 强制 `exp`/`iss`/`aud` 存在（拒无 exp 的永久 token）。
fn build_validation(config: &VerifierConfig, algorithms: &[Algorithm]) -> Validation {
    // reason: algorithms 非空由 builder 保证；first 必 Some——取首算法作 seed 后即被 v.algorithms 全集覆盖，
    // 故 unwrap_or 的 fallback 永不命中（仅为静态消除 panic 路径，不退化为 indexing/expect）。
    let seed = algorithms.first().copied().unwrap_or(Algorithm::RS256);
    let mut v = Validation::new(seed);
    v.algorithms = algorithms.to_vec();
    v.set_issuer(&[config.issuer.as_str()]);
    v.set_audience(&[config.audience.as_str()]);
    v.validate_exp = true;
    v.validate_nbf = true;
    v.set_required_spec_claims(&["exp", "iss", "aud"]);
    v
}

/// `sub` → subject（必有）；可配置 tenant·kind claim 按名从 extra 取字符串值（缺失 / 非字符串 → None）。
fn map_claims(config: &VerifierConfig, claims: Claims) -> VerifiedClaims {
    let tenant = string_claim(&claims.extra, &config.tenant_claim);
    let kind = string_claim(&claims.extra, &config.kind_claim);
    VerifiedClaims::new(claims.sub, tenant, kind)
}

/// 从 extra 取字符串型 claim（非字符串 / 缺失 → None，不强转、不 panic）。
fn string_claim(extra: &serde_json::Map<String, serde_json::Value>, name: &str) -> Option<String> {
    extra.get(name).and_then(|v| v.as_str()).map(str::to_owned)
}

/// 把 jsonwebtoken 错误**归类**到 `PdpError` 三变体；记脱敏顶层摘要（reason 闭值标签 + redacted Display，
/// **不**记 token）。catch-all → `Untrusted`（`ErrorKind` `#[non_exhaustive]`，新变体 fail-closed）。
fn classify(err: Option<jsonwebtoken::errors::Error>) -> PdpError {
    use jsonwebtoken::errors::ErrorKind;
    let Some(err) = err else {
        // keys 非空保证至少试解一次——本支理论不可达；fail-closed。
        return PdpError::Untrusted;
    };
    let (reason, mapped) = match err.kind() {
        ErrorKind::ExpiredSignature => ("expired", PdpError::Expired),
        ErrorKind::ImmatureSignature => ("not_yet_valid", PdpError::Expired),
        ErrorKind::InvalidSignature => ("bad_signature", PdpError::InvalidSignature),
        ErrorKind::InvalidIssuer | ErrorKind::InvalidAudience => {
            ("untrusted_iss_or_aud", PdpError::Untrusted)
        }
        ErrorKind::InvalidAlgorithm | ErrorKind::InvalidAlgorithmName => {
            ("alg_not_allowed", PdpError::InvalidSignature)
        }
        // 解析 / 格式错误（malformed header/payload、base64 坏、缺 required claim、缺 sub 等）→ 不受信。
        _ => ("malformed_or_other", PdpError::Untrusted),
    };
    tracing::warn!(
        target: "oidc",
        resource = "oidc",
        reason = reason,
        error = %secure::redact_error(&err),
        "oidc jwt verification failed"
    );
    mapped
}

#[cfg(test)]
mod tests {
    // reason: 测试集中 expect/unwrap/panic 于 setup 与断言（item-level carve-out，符 error-handling.md §Carve-out）。
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::{Algorithm, ConfigError, VerifierConfig, VerifierConfigBuilder, verify_credential};
    use diport::{PdpError, RawCredential};
    use jsonwebtoken::{EncodingKey, Header, encode, get_current_timestamp};
    use serde_json::json;

    const ISS: &str = "https://issuer.example";
    const AUD: &str = "rss-api";

    // 一次性抛弃测试密钥对（offline `openssl genpkey` 生成；**仅测试 fixture，永非生产 key**）。
    // key1 = 主验签对；key2 = 不匹配对（坏签名 / 多 key 轮转覆盖）。RSA 经 jsonwebtoken 自带 PEM reader（ring
    // 后端），不引入 `rsa` crate（deny.toml ban）。
    const PRIV1: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDgGelnJxCckC+q
vJXnI0x7iBticCc0VNrt2ZcqvhGxDKyGQYGQLjoYWH8wvpRNche8S487AXPdOGyv
Pe8gOfA2B3sp7+B/XeiRaOAR2ocSmjUKM955N4JhlE9K3fMeAFGrZ6DNSRGl/QfI
jdjx4cuRbAAyyNTxsQ98OrvnoAfk+kQTxIQybycc5v0IXfUTyvGuRu7+NsjR0ffY
k+I6SALls3LPVIWDGygNZyWHzdHb7mEWrNRrD8UgVFWk0L4ndJDp6fg6Ca+P5LWB
FhTZntpDUbfm9v5JOr4Z/3bXdhBMWrmuYeuCtlS5aBjzzdMUq1LZOJGqIh7c6v0o
UNWa2/rNAgMBAAECggEABTOsxotyWAQDyz2J6D3aRGLOKeyLCGyw0UUT/HbBf9/Y
sFwcZw2fpRmGyEmgNSUBFoqVdkvsFdY9tZqlLpURtZtaWUibaDF0mM17qAZvzLd+
JDC8iQlIEj5IUedRgaCFxMoIwkMgMP9s2xOp1cGFQWiln4goYzzWLG7Llk6RaFf4
tPvexGBd/rwms5WerC6Ata57AxjPDHO1Yxnn8gKazExox0qBkJze0d7iGnmirbCs
9VccoMsku5Om1fEAvy2t5zma2ElIiPu7fG0Q4AtCHDV3f5WABo9eWQrCAqy14hGn
QqyY4ZUiE2Nmo9Y2ziT8GpcuKPleTjrBOYVSt0t7QQKBgQD3Rd343OMPVUIdRdfa
ZtLOp+M6/10LpGjUnZBgTS71zSRH9yhkih9Ey2Z+aTROdnxa90i3pmSzQ54d5Sz/
KtnLLrIpHwrZmAKg01Zka9xIw5wmFRCRFVEQFbsscvDsajSmiphBieEoqxFA6vAL
oqK4qWXXh+SCuYi6cXCCX7TwwQKBgQDoAq+vGEUOoiJsclM9VU577mtTzxah/3fj
sZqIi5yYqR8JPQKLj0VwR7toqx4YGnU9BayQOd+ckvs6d68SzZT+tgq9U/AD0pBC
LCmSikLxLE/vH8Xt+JGkL+sXimN5Uu8d+yEemozIrnbQFdlA7WDIXiMfwCCIuiep
85OBnXsBDQKBgQCuetpaVGLT2vE//pyFO7DcqZKpeq+JG4XtIRFTIqNURmCndztF
VkEiJfQ4lruV8f1lor/o9rxv0fKsXZ4Wn4H24QhOA92AFMcl/HolegaCQaTZKlv6
Q/RjSTI99w0RhQ+JxJoTBNuf+rW9/QlM7IGtk7qNDxKrO4fDJ3CgTjA7AQKBgQCf
Ooi8UJnEaz3Y07WRGGTe5Ug/opbT43KykAeQwtBcbWVhf7+pbFCpuHFEanwi6rWf
ha9i5HU1DiLhg5Zh/znMfb9tJJhK504ePBTj/4Pl5RWO9W1v3vKFjmV4KIAQmfyF
xP579HG+oQ3lzbjmuIN9wC228rLhY3EpUIPhpuTuWQKBgD5N61sNLSVV2cy4og2d
JiZotdftXOdcbQ463NkfAPQ1rvZGpXZ15+Z5BYHvKbJJC4DUhsnmcQdpjJkPRTXG
3BJIkmZjljF2asNhKbr6kb2Fgwd+XZ4nxy4Afy9M94EBTeojotZbtmKYjBgyuRtu
TjzFzD//fKgqGb19+Whf4HFF
-----END PRIVATE KEY-----
";
    const PUB1: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4BnpZycQnJAvqryV5yNM
e4gbYnAnNFTa7dmXKr4RsQyshkGBkC46GFh/ML6UTXIXvEuPOwFz3Thsrz3vIDnw
Ngd7Ke/gf13okWjgEdqHEpo1CjPeeTeCYZRPSt3zHgBRq2egzUkRpf0HyI3Y8eHL
kWwAMsjU8bEPfDq756AH5PpEE8SEMm8nHOb9CF31E8rxrkbu/jbI0dH32JPiOkgC
5bNyz1SFgxsoDWclh83R2+5hFqzUaw/FIFRVpNC+J3SQ6en4Ogmvj+S1gRYU2Z7a
Q1G35vb+STq+Gf9213YQTFq5rmHrgrZUuWgY883TFKtS2TiRqiIe3Or9KFDVmtv6
zQIDAQAB
-----END PUBLIC KEY-----
";
    const PRIV2: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCwLn6E2yEbnC6I
5BY/T82RlfaPVqEVVwgKkdC6UFgm61p8gWkloyz+0fw7P6/eJ7QtG4AVFYD9fs1D
znG6aryXgeER7fo3kuDb5wkbRfxGVg1iF30fK9Ys3pV/ibNn3nY5qYlGpPaKUDms
qDSKMvnC80ZdvWAJ+UeFKn66/JX2+4MAqkv2/9z+kfu9dBKgIofHP3g7T61/k4hG
8bq+CT9+6LSDrUEG9cGJpB2Kx4CmBX+k4jmLq5PjKL4x7pt5PGWPGH42MC80SN8G
xT8HaelQdCQlJyDzvT/1fJGW68Kn87q3wKXf/T7eB+NuSC9xS1VJRK/6a9wFe11+
uymIjkyRAgMBAAECggEAA38LtZYd6UTrXz30A1IBislkowXxhMl1LFUGFPFz22Nd
qIV+rT+YjK7E/DXEhyKHcsL2QuzaIkW0O/uOghgcyZ6rJVKBPf23IsQKKCl2kvyB
j9wWmIITojCxW65jUh0OAHFQ6ycKSbbDez28C69M6bGPWJxByfbhhIbyLIKnVPcy
qR54N+qWTu9BOYoT88RgplPoyIGFaV1mJ2nIC5+g3XgIbn9rVWitNZx8/CQiSruw
Zk7OXdLO9KPVE0zWda9tNZeTNd3k/qn2fBPAg2vcCv68qiPcknXXSHDyi4LcbpBu
ye0PjTlHwI0pH6zTgxGKTT8QxEPAdIZYQyVwMkhCQQKBgQDzx3DUHDDxjt/CqFlS
1CcBP/kRsticYdFPQQs/ky699RJOeZitrDwwxJj0n8TfIMpwAekPbTR6zH+cH6C1
hnJKJXBC9DQ9nI6ufFcmfi/hJ8qKLFeeCgJhT4uHMHb0fU5362nKMsTs5DM/QRUx
+3jawzD7VP19/iUd280FKIjfQQKBgQC5A4kx5rsLRUPjeU8osVUKpwDlF4fsz06N
Wxg6TawEgKrt5pSaRw0mLK0/zK+m/x0wfAuFsmp+oVAudWFMENqv0yfPG1WFGVEG
OZsqjKv4nNcWutahLMuEIiNJRgJBwxYT912d02o/e049iIeOgFSW4sO5svKi0XrH
gW2mdC5pUQKBgEMgQeNGN/vr+ZViQeZa4LqpYO4MrzSwgrAuGujQoGhSGU5ekToR
WSmcmPmTHOTL5LJe9Ev5KCBAO0tEMj6J3OKp2HW3RMNKXseRGXZR/OEk0dKmTyIH
Y4xkGOmK4NaFwpumySSSQkNwuuPKCgoPUsH6SXyLdJnC53mHUrb+6GGBAoGBAI/o
UC6gaZy6o7OsCAZ+6McAX5HSW8e2+EK7OH0hLUvTSSEC2VOnMHMhDSEy9O3QQcQU
uGGmBW+5ycRZSPUBpxhcBfryJ/L/XiaZaDgQczNNy3/ClG+JiEOeyhOUgOzl8aZW
IltAtsPqBVGXgNk2uJUkjVlD97btebL02XU/qVoBAoGAP7qkBwyPYXXJ+TIfeBh6
9sbB7rvcDYh7+U/yZdlG7/Y4ZMGUV5qBbfMhGzDoLyZcYKSdtVHn4XvtPYu7nvxo
nFDbgSZCL+vpfDz8ciFy8hQ1h5HowDodp6imzfTMcR13R7LFgbbKQkY+kXn1DF7G
iD3rNAnVxRPfFAP5fQOW7iA=
-----END PRIVATE KEY-----
";
    const PUB2: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsC5+hNshG5wuiOQWP0/N
kZX2j1ahFVcICpHQulBYJutafIFpJaMs/tH8Oz+v3ie0LRuAFRWA/X7NQ85xumq8
l4HhEe36N5Lg2+cJG0X8RlYNYhd9HyvWLN6Vf4mzZ952OamJRqT2ilA5rKg0ijL5
wvNGXb1gCflHhSp+uvyV9vuDAKpL9v/c/pH7vXQSoCKHxz94O0+tf5OIRvG6vgk/
fui0g61BBvXBiaQdiseApgV/pOI5i6uT4yi+Me6beTxljxh+NjAvNEjfBsU/B2np
UHQkJScg870/9XyRluvCp/O6t8Cl3/0+3gfjbkgvcUtVSUSv+mvcBXtdfrspiI5M
kQIDAQAB
-----END PUBLIC KEY-----
";

    /// 主验签配置：单把 PUB1 / RS256 + 默认 tenant·kind claim 名。
    fn config() -> VerifierConfig {
        VerifierConfigBuilder::new(ISS, AUD)
            .add_rsa_pem_key(PUB1.as_bytes(), &[Algorithm::RS256])
            .expect("rsa key")
            .build()
            .expect("config")
    }

    /// 以指定私钥 + 算法签出 token。
    fn mint(priv_pem: &str, alg: Algorithm, claims: serde_json::Value) -> String {
        let key = EncodingKey::from_rsa_pem(priv_pem.as_bytes()).expect("encoding key");
        encode(&Header::new(alg), &claims, &key).expect("encode")
    }

    /// 远未来 exp（有效）。
    fn future_exp() -> u64 {
        get_current_timestamp() + 3600
    }

    #[test]
    fn valid_rs256_token_maps_claims() {
        let token = mint(
            PRIV1,
            Algorithm::RS256,
            json!({"sub": "alice", "iss": ISS, "aud": AUD, "exp": future_exp(),
                   "tenant_id": "tenant-7", "kind": "user"}),
        );
        let vc = verify_credential(&config(), &RawCredential::jwt(token)).expect("verify ok");
        assert_eq!(vc.subject(), "alice");
        assert_eq!(vc.tenant(), Some("tenant-7"));
        assert_eq!(vc.kind(), Some("user"));
    }

    #[test]
    fn tenant_kind_absent_yields_none() {
        let token = mint(
            PRIV1,
            Algorithm::RS256,
            json!({"sub": "bob", "iss": ISS, "aud": AUD, "exp": future_exp()}),
        );
        let vc = verify_credential(&config(), &RawCredential::jwt(token)).expect("verify ok");
        assert_eq!(vc.subject(), "bob");
        assert_eq!(vc.tenant(), None);
        assert_eq!(vc.kind(), None);
    }

    #[test]
    fn non_string_tenant_claim_yields_none() {
        let token = mint(
            PRIV1,
            Algorithm::RS256,
            json!({"sub": "carol", "iss": ISS, "aud": AUD, "exp": future_exp(), "tenant_id": 12345}),
        );
        let vc = verify_credential(&config(), &RawCredential::jwt(token)).expect("verify ok");
        assert_eq!(vc.tenant(), None);
    }

    // 表驱动：同把 PUB1/RS256 签名有效，仅 claim 时窗 / iss / aud / required 变化 → 对应 PdpError。
    #[rstest::rstest]
    #[case::expired(json!({"sub": "a", "iss": ISS, "aud": AUD, "exp": get_current_timestamp() - 7200}))]
    #[case::nbf_future(json!({"sub": "a", "iss": ISS, "aud": AUD, "exp": get_current_timestamp() + 7200, "nbf": get_current_timestamp() + 3600}))]
    fn jwt_time_window_violations_map_expired(#[case] claims: serde_json::Value) {
        let token = mint(PRIV1, Algorithm::RS256, claims);
        let r = verify_credential(&config(), &RawCredential::jwt(token));
        assert!(matches!(r, Err(PdpError::Expired)), "got {r:?}");
    }

    #[rstest::rstest]
    #[case::wrong_iss(json!({"sub": "a", "iss": "https://evil", "aud": AUD, "exp": get_current_timestamp() + 3600}))]
    #[case::wrong_aud(json!({"sub": "a", "iss": ISS, "aud": "other-rp", "exp": get_current_timestamp() + 3600}))]
    #[case::missing_exp(json!({"sub": "a", "iss": ISS, "aud": AUD}))]
    fn jwt_untrusted_or_malformed_claims_map_untrusted(#[case] claims: serde_json::Value) {
        let token = mint(PRIV1, Algorithm::RS256, claims);
        let r = verify_credential(&config(), &RawCredential::jwt(token));
        assert!(matches!(r, Err(PdpError::Untrusted)), "got {r:?}");
    }

    #[test]
    fn bad_signature_rejected() {
        // 以 PRIV2 签名、用 PUB1 验签 → 签名不匹配。
        let token = mint(
            PRIV2,
            Algorithm::RS256,
            json!({"sub": "a", "iss": ISS, "aud": AUD, "exp": future_exp()}),
        );
        let r = verify_credential(&config(), &RawCredential::jwt(token));
        assert!(matches!(r, Err(PdpError::InvalidSignature)), "got {r:?}");
    }

    #[test]
    fn algorithm_mismatch_rejected() {
        // token 以 HS256 签名；config 只允许 RS256 → alg 不在 allowlist → 拒（防 RS256→HS256 key-confusion）。
        let key = EncodingKey::from_secret(b"shared-secret");
        let token = encode(
            &Header::new(Algorithm::HS256),
            &json!({"sub": "a", "iss": ISS, "aud": AUD, "exp": future_exp()}),
            &key,
        )
        .expect("encode hs256");
        let r = verify_credential(&config(), &RawCredential::jwt(token));
        assert!(matches!(r, Err(PdpError::InvalidSignature)), "got {r:?}");
    }

    #[test]
    fn malformed_token_rejected() {
        for bad in ["not-a-jwt", "a.b", "...", "garbage", ""] {
            let r = verify_credential(&config(), &RawCredential::jwt(bad));
            assert!(
                matches!(r, Err(PdpError::Untrusted)),
                "bad={bad:?} got {r:?}"
            );
        }
    }

    #[test]
    fn service_token_scheme_rejected() {
        let r = verify_credential(&config(), &RawCredential::service_token("whatever"));
        assert!(matches!(r, Err(PdpError::Untrusted)), "got {r:?}");
    }

    #[test]
    fn multi_key_rotation_second_key_succeeds() {
        // config 注入 [PUB1, PUB2]；token 由 PRIV2 签 → 第二把 key 验签成功。
        let cfg = VerifierConfigBuilder::new(ISS, AUD)
            .add_rsa_pem_key(PUB1.as_bytes(), &[Algorithm::RS256])
            .expect("k1")
            .add_rsa_pem_key(PUB2.as_bytes(), &[Algorithm::RS256])
            .expect("k2")
            .build()
            .expect("config");
        let token = mint(
            PRIV2,
            Algorithm::RS256,
            json!({"sub": "d", "iss": ISS, "aud": AUD, "exp": future_exp()}),
        );
        let r = verify_credential(&cfg, &RawCredential::jwt(token));
        assert!(r.is_ok(), "got {r:?}");
    }

    // ---- 构造期 fail-fast ----

    #[test]
    fn builder_empty_issuer_fails() {
        let r = VerifierConfigBuilder::new("", AUD)
            .add_rsa_pem_key(PUB1.as_bytes(), &[Algorithm::RS256])
            .expect("k")
            .build();
        assert!(matches!(r, Err(ConfigError::EmptyIssuer)));
    }

    #[test]
    fn builder_empty_audience_fails() {
        let r = VerifierConfigBuilder::new(ISS, "")
            .add_rsa_pem_key(PUB1.as_bytes(), &[Algorithm::RS256])
            .expect("k")
            .build();
        assert!(matches!(r, Err(ConfigError::EmptyAudience)));
    }

    #[test]
    fn builder_no_keys_fails() {
        let r = VerifierConfigBuilder::new(ISS, AUD).build();
        assert!(matches!(r, Err(ConfigError::NoDecodingKeys)));
    }

    #[test]
    fn builder_empty_claim_name_fails() {
        let r = VerifierConfigBuilder::new(ISS, AUD)
            .tenant_claim("")
            .add_rsa_pem_key(PUB1.as_bytes(), &[Algorithm::RS256])
            .expect("k")
            .build();
        assert!(matches!(r, Err(ConfigError::EmptyClaimName)));
    }

    #[test]
    fn builder_rejects_hmac_algorithm() {
        let r = VerifierConfigBuilder::new(ISS, AUD)
            .add_rsa_pem_key(PUB1.as_bytes(), &[Algorithm::HS256]);
        assert!(
            matches!(r, Err(ConfigError::SymmetricAlgorithm)),
            "got err variant"
        );
    }

    #[test]
    fn builder_rejects_empty_algorithms() {
        let r = VerifierConfigBuilder::new(ISS, AUD).add_rsa_pem_key(PUB1.as_bytes(), &[]);
        assert!(
            matches!(r, Err(ConfigError::EmptyAlgorithms)),
            "got err variant"
        );
    }

    #[test]
    fn builder_rejects_malformed_key() {
        let r =
            VerifierConfigBuilder::new(ISS, AUD).add_rsa_pem_key(b"not a pem", &[Algorithm::RS256]);
        assert!(matches!(r, Err(ConfigError::InvalidKey)), "got err variant");
    }

    // ---- 生命周期（ManagedResource 始终 impl）+ async Pdp dyn 注入 ----

    #[tokio::test]
    async fn lifecycle_name_and_shutdown() {
        use diport::ManagedResource;
        let provider = crate::OidcProvider::new(config());
        assert_eq!(provider.name(), "oidc");
        assert!(provider.shutdown().await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pdp_dyn_injection_verifies() {
        // multi_thread + spawn：boxed future 须 Send（trait_variant Send 变体）才能跨 worker 调度。
        use diport::Pdp as _; // Box<DynPdp> 的 verify 经 Pdp trait 调用（须在 scope）。
        let provider = crate::OidcProvider::new(config());
        let pdp: Box<diport::DynPdp> = diport::DynPdp::new_box(provider);
        let token = mint(
            PRIV1,
            Algorithm::RS256,
            json!({"sub": "e", "iss": ISS, "aud": AUD, "exp": future_exp()}),
        );
        let raw = RawCredential::jwt(token);
        let joined = tokio::spawn(async move { pdp.verify(&raw).await.is_ok() }).await;
        assert!(matches!(joined, Ok(true)), "got {joined:?}");
    }

    // ---- PII 边界：失败路径不把原始 token 写进日志 ----

    // 须经 nextest（进程隔离，.config/nextest.toml）跑：本断言依赖 thread-local 捕获 subscriber 看到
    // classify 的 `warn!` callsite。`cargo test` 单进程下别的失败路径测试先以 no-op subscriber 命中同一
    // callsite，会把其 interest 全局缓存为 never，污染本测试（tracing callsite-cache 已知行为）。nextest
    // 每测试独立进程 ⇒ 无污染、确定性通过；nextest 是本仓 canonical runner（make verify / CI）。
    #[test]
    fn failure_does_not_log_raw_token() {
        use std::io::Write;
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct Buf(Arc<Mutex<Vec<u8>>>);
        impl Write for Buf {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("lock").extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buf {
            type Writer = Buf;
            fn make_writer(&'a self) -> Buf {
                self.clone()
            }
        }

        let buf = Buf(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_max_level(tracing::Level::WARN)
            .finish();

        // PRIV2 签 / PUB1 验 → 坏签名 → 走 classify 的 warn 日志路径。
        let token = mint(
            PRIV2,
            Algorithm::RS256,
            json!({"sub": "marker-subject", "iss": ISS, "aud": AUD, "exp": future_exp()}),
        );
        let token_clone = token.clone();
        tracing::subscriber::with_default(subscriber, || {
            let _ = verify_credential(&config(), &RawCredential::jwt(token_clone));
        });

        let logged = String::from_utf8(buf.0.lock().expect("lock").clone()).expect("utf8");
        assert!(
            logged.contains("oidc jwt verification failed"),
            "warn not emitted: {logged}"
        );
        assert!(logged.contains("reason"), "reason field absent: {logged}");
        assert!(
            !logged.contains(token.as_str()),
            "raw token leaked into logs: {logged}"
        );
    }
}
