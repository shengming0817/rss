//! JWS 三段解析 + base64url 解码 + header 算法白名单（[`SupportedAlg`]）。
//!
//! 只做**结构解析与算法识别**，不验签（签名校验在 [`crate::verify`]）。`alg=none` / RS* / PS* / 未知 →
//! 不在 [`SupportedAlg`] 闭枚举 → 类型层不可表达 → fail-closed 拒（INVARIANT: OIDC-ALG-WHITELIST-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }）。
//!
//! ref: RFC 7515 §7.1（JWS Compact Serialization：`header.payload.signature`，各段 base64url 无填充）；
//! spiffe/rust-spiffe src/bundle/jwt + src/svid/jwt（3 段 split + base64url header 解析范式）。

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;

/// 支持的验签算法白名单（**闭枚举** → RS256 / `none` / 未知在类型层不可表达；防 alg-confusion 的第一道闸）。
///
/// INVARIANT: OIDC-ALG-WHITELIST-01 { level = "Medium", exec = "manual/opt-in", source = "code" }—— 仅 ES256（非对称，JWT 路径）+ HS256（对称，service-token 路径）。
/// 新增算法须显式扩枚举 + 扩 [`crate::verify`] 验签器 + 扩测试（anti-vacuity：删任一分支即编译失败）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedAlg {
    /// ECDSA P-256 + SHA-256（JWT 路径，非对称公钥验签）。
    Es256,
    /// HMAC-SHA256（service-token 路径，对称共享密钥）。
    Hs256,
}

impl SupportedAlg {
    /// JOSE `alg` header 值 → 白名单算法；白名单外（含 `none` / `RS256` / `PS256` / 未知）→ `None`（fail-closed）。
    fn from_jose(alg: &str) -> Option<Self> {
        match alg {
            "ES256" => Some(Self::Es256),
            "HS256" => Some(Self::Hs256),
            _ => None,
        }
    }
}

/// 解析后的 JWS（无 PII 暴露途径——本类型不 derive `Debug`，签名 / payload 字节不进观测面）。
pub struct Jws {
    /// 白名单算法。
    pub alg: SupportedAlg,
    /// 验签消息：`header_b64 + "." + payload_b64` 的 ASCII 字节（JWS Signing Input，RFC 7515 §5.1）。
    pub signing_input: Vec<u8>,
    /// 已 base64url 解码的 payload JSON 字节（供 [`crate::claims`] 反序列化）。
    pub payload: Vec<u8>,
    /// 已 base64url 解码的签名 / MAC 字节。
    pub signature: Vec<u8>,
    /// JOSE header `kid`（key id，RFC 7515 §4.1.4）：多 key 源（JWKS 轮转，#1109/T003）按 id 选验签 key；
    /// 无 kid 时按 untagged key 盲扫（保静态 key 行为）。`kid` 是选 key hint、**非**信任根——最终仍须签名校验。
    pub kid: Option<String>,
}

/// JWS protected header：取 `alg`（必）+ `kid`（可选，JWKS 选 key 用）。
#[derive(Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

/// 解析失败分类（结构 / 编码 / 算法白名单）。两者由 [`crate::verify`] 一律归 `InvalidSignature`——畸形或
/// 不支持算法的 token 不可用（区别于签发者不受信的 `Untrusted`）。
#[derive(Debug, PartialEq, Eq)]
pub enum JwsError {
    /// 段数 ≠ 3 / 空 header·payload 段 / base64url 解码失败 / header JSON 非法。
    Malformed,
    /// `header.alg` 不在白名单（含 `none` / RS* / 未知）。
    UnsupportedAlg,
}

/// 三段解析 + base64url 解码 + 算法白名单。**不验签**（签名校验在 [`crate::verify`]）。
pub fn parse(token: &str) -> Result<Jws, JwsError> {
    let mut segments = token.split('.');
    // 恰好 3 段（第 4 个 next 必为 None）；header / payload 段非空。签名段允许为空串（如 `h.p.`）——但
    // 其 alg 必 ∈ 白名单（`none` 已被 UnsupportedAlg 拒），空签名 decode 为空 vec、验签时必然失败（fail-closed）。
    let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(JwsError::Malformed);
    };
    if header_b64.is_empty() || payload_b64.is_empty() {
        return Err(JwsError::Malformed);
    }
    let header_bytes = decode_segment(header_b64)?;
    let header: Header = serde_json::from_slice(&header_bytes).map_err(|_| JwsError::Malformed)?;
    let alg = SupportedAlg::from_jose(&header.alg).ok_or(JwsError::UnsupportedAlg)?;
    let payload = decode_segment(payload_b64)?;
    let signature = decode_segment(signature_b64)?;
    let signing_input = format!("{header_b64}.{payload_b64}").into_bytes();
    Ok(Jws {
        alg,
        signing_input,
        payload,
        signature,
        kid: header.kid,
    })
}

/// base64url（URL_SAFE_NO_PAD）解一段；失败 → `Malformed`。
fn decode_segment(segment: &str) -> Result<Vec<u8>, JwsError> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| JwsError::Malformed)
}

#[cfg(test)]
mod tests {
    // 测试 expect carve-out 按 error-handling.md §Carve-out 用 **item-level** `#[allow(clippy::expect_used)]`
    // 逐 fn 标注（非 module-level）——与 s3/redis adapter 测试同范式（workspace clippy expect_used = deny）。
    use super::*;

    #[test]
    fn supported_alg_from_jose_whitelist() {
        assert_eq!(SupportedAlg::from_jose("ES256"), Some(SupportedAlg::Es256));
        assert_eq!(SupportedAlg::from_jose("HS256"), Some(SupportedAlg::Hs256));
    }

    #[test]
    fn supported_alg_rejects_non_whitelist() {
        // alg-confusion 第一道闸：RS256 / none / 未知 一律 None（fail-closed）。
        for alg in [
            "RS256", "PS256", "ES384", "HS384", "none", "None", "", "es256",
        ] {
            assert_eq!(SupportedAlg::from_jose(alg), None, "alg `{alg}` 必须被拒");
        }
    }

    #[test]
    fn parse_rejects_wrong_segment_count() {
        // Jws 不 derive Debug/PartialEq（持签名/payload 字节，PII）；用 matches! 判错误变体。
        for token in ["", "onlyone", "two.parts", "four.seg.ment.s"] {
            assert!(
                matches!(parse(token), Err(JwsError::Malformed)),
                "token `{token}`"
            );
        }
    }

    #[test]
    fn parse_rejects_empty_header_or_payload_segment() {
        // 用合法 base64url 签名段，确保被拒因是空 header/payload 段（非签名段）。
        assert!(matches!(parse(".eyJhIjoxfQ.aGk"), Err(JwsError::Malformed)));
        assert!(matches!(
            parse("eyJhbGciOiJFUzI1NiJ9..aGk"),
            Err(JwsError::Malformed)
        ));
    }

    #[test]
    fn parse_rejects_bad_base64url_header() {
        // `@@@` 非 base64url 字符 → Malformed。
        assert!(matches!(
            parse("@@@.eyJhIjoxfQ.aGk"),
            Err(JwsError::Malformed)
        ));
    }

    #[test]
    fn parse_rejects_alg_none() {
        // 经典 alg:none 攻击：header alg="none" + 空签名段。结构合法但 alg 不在白名单 → UnsupportedAlg。
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"a"}"#);
        let token = format!("{header}.{payload}.");
        assert!(matches!(parse(&token), Err(JwsError::UnsupportedAlg)));
    }

    #[test]
    fn parse_rejects_rs256_alg() {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#);
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"a"}"#);
        let token = format!("{header}.{payload}.c2ln");
        assert!(matches!(parse(&token), Err(JwsError::UnsupportedAlg)));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn parse_accepts_well_formed_es256_header() {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256"}"#);
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"alice"}"#);
        let token = format!("{header}.{payload}.c2lnbmF0dXJl");
        let jws = parse(&token).expect("well-formed ES256 应解析成功");
        assert_eq!(jws.alg, SupportedAlg::Es256);
        assert_eq!(
            jws.signing_input,
            format!("{header}.{payload}").into_bytes()
        );
        assert_eq!(jws.payload, br#"{"sub":"alice"}"#);
        // 无 kid header → None（保静态盲扫行为）。
        assert_eq!(jws.kid, None);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn parse_extracts_kid_when_present() {
        // header 含 kid → Jws.kid = Some（JWKS 轮转按 id 选 key）。
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","kid":"key-2024"}"#);
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"alice"}"#);
        let token = format!("{header}.{payload}.c2lnbmF0dXJl");
        let jws = parse(&token).expect("well-formed ES256+kid 应解析成功");
        assert_eq!(jws.kid.as_deref(), Some("key-2024"));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn parse_ignores_unknown_header_fields() {
        // 未知 header 字段（如 typ/cty/x5t）不影响解析；kid 缺省 → None。
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT","cty":"x"}"#);
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"svc"}"#);
        let token = format!("{header}.{payload}.c2ln");
        let jws = parse(&token).expect("额外 header 字段应被忽略");
        assert_eq!(jws.alg, SupportedAlg::Hs256);
        assert_eq!(jws.kid, None);
    }
}
