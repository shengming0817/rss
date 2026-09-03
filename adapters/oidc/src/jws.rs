//! JWS 三段解析 + base64url 解码 + header 算法白名单（[`SupportedAlg`]）。
//!
//! 只做**结构解析与算法识别**，不验签（签名校验在 [`crate::verify`]）。`alg=none` / RS* / PS* / 未知 →
//! 不在 [`SupportedAlg`] 闭枚举 → 类型层不可表达 → fail-closed 拒。
//!
//! ref: RFC 7515 §7.1（JWS Compact Serialization：`header.payload.signature`，各段 base64url 无填充）；
//! spiffe/rust-spiffe src/bundle/jwt + src/svid/jwt（3 段 split + base64url header 解析范式）。

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;

use diport::TokenPolicy;

/// 支持的验签算法白名单（**闭枚举** → RS256 / `none` / 未知在类型层不可表达；防 alg-confusion 的第一道闸）。
///
/// 仅 ES256（非对称，JWT 路径）+ HS256（对称，service-token 路径）。
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
    /// Exact protected-header token type. The verifier compares it with the bound profile policy.
    pub typ: String,
    /// JOSE header `kid`（key id，RFC 7515 §4.1.4）。所有 profile 都要求非空 `kid`，key lookup
    /// 只做 exact match，不存在 untagged blind scan。
    pub kid: String,
}

#[derive(Default)]
struct NoCriticalHeader;

impl<'de> Deserialize<'de> for NoCriticalHeader {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Err(serde::de::Error::custom(
            "critical protected-header extensions are unsupported",
        ))
    }
}

/// JWS protected header：`alg` / `typ` / `kid` 均必填且大小写敏感。未知 non-critical 字段继续忽略；
/// 当前没有实现任何 critical extension，因此 `crit` 只要出现就拒绝（包括 `[]` / `null` / 非数组）。
#[derive(Deserialize)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
    #[serde(default, rename = "crit")]
    _crit: NoCriticalHeader,
}

/// 解析失败分类（结构 / 编码 / 算法白名单）。两者由 [`crate::verify`] 一律归 `InvalidSignature`——畸形或
/// 不支持算法的 token 不可用（区别于签发者不受信的 `Untrusted`）。
#[derive(Debug, PartialEq, Eq)]
pub enum JwsError {
    /// 段数 ≠ 3 / 空 header·payload 段 / base64url 解码失败 / header JSON 非法。
    Malformed,
    /// Total compact token or one encoded segment exceeds the profile policy.
    TooLarge,
    /// `header.alg` 不在白名单（含 `none` / RS* / 未知）。
    UnsupportedAlg,
}

/// 三段解析 + base64url 解码 + 算法白名单。**不验签**（签名校验在 [`crate::verify`]）。
///
/// Length checks happen before base64 decode, JSON parsing, signing-input allocation, key lookup,
/// crypto, or replay I/O. Limits are inclusive: exactly-at-limit input proceeds; `limit + 1`
/// returns [`JwsError::TooLarge`].
pub fn parse(token: &str, policy: TokenPolicy) -> Result<Jws, JwsError> {
    if token.len() > policy.maximum_token_length() {
        return Err(JwsError::TooLarge);
    }
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
    if header_b64.len() > policy.maximum_header_length()
        || payload_b64.len() > policy.maximum_payload_length()
        || signature_b64.len() > policy.maximum_signature_length()
    {
        return Err(JwsError::TooLarge);
    }
    let header_bytes = decode_segment(header_b64)?;
    let header: Header = serde_json::from_slice(&header_bytes).map_err(|_| JwsError::Malformed)?;
    if header.kid.is_empty() || header.typ.is_empty() {
        return Err(JwsError::Malformed);
    }
    let alg = SupportedAlg::from_jose(&header.alg).ok_or(JwsError::UnsupportedAlg)?;
    let payload = decode_segment(payload_b64)?;
    let signature = decode_segment(signature_b64)?;
    let signing_input = format!("{header_b64}.{payload_b64}").into_bytes();
    Ok(Jws {
        alg,
        signing_input,
        payload,
        signature,
        typ: header.typ,
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
    // 测试 expect carve-out
    // 逐 fn 标注（非 module-level）——与 s3/redis adapter 测试同范式（workspace clippy expect_used = deny）。
    use super::*;

    fn parse_rss(token: &str) -> Result<Jws, JwsError> {
        parse(token, diport::TokenProfile::RssAccess.policy())
    }

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
                matches!(parse_rss(token), Err(JwsError::Malformed)),
                "token `{token}`"
            );
        }
    }

    #[test]
    fn parse_rejects_empty_header_or_payload_segment() {
        // 用合法 base64url 签名段，确保被拒因是空 header/payload 段（非签名段）。
        assert!(matches!(
            parse_rss(".eyJhIjoxfQ.aGk"),
            Err(JwsError::Malformed)
        ));
        assert!(matches!(
            parse_rss("eyJhbGciOiJFUzI1NiJ9..aGk"),
            Err(JwsError::Malformed)
        ));
    }

    #[test]
    fn parse_rejects_bad_base64url_header() {
        // `@@@` 非 base64url 字符 → Malformed。
        assert!(matches!(
            parse_rss("@@@.eyJhIjoxfQ.aGk"),
            Err(JwsError::Malformed)
        ));
    }

    #[test]
    fn parse_rejects_alg_none() {
        // 经典 alg:none 攻击：header alg="none" + 空签名段。结构合法但 alg 不在白名单 → UnsupportedAlg。
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"at+jwt","kid":"key-1"}"#);
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"a"}"#);
        let token = format!("{header}.{payload}.");
        assert!(matches!(parse_rss(&token), Err(JwsError::UnsupportedAlg)));
    }

    #[test]
    fn parse_rejects_rs256_alg() {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"at+jwt","kid":"key-1"}"#);
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"a"}"#);
        let token = format!("{header}.{payload}.c2ln");
        assert!(matches!(parse_rss(&token), Err(JwsError::UnsupportedAlg)));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn parse_accepts_well_formed_es256_header() {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"at+jwt","kid":"key-1"}"#);
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"alice"}"#);
        let token = format!("{header}.{payload}.c2lnbmF0dXJl");
        let jws = parse_rss(&token).expect("well-formed ES256 应解析成功");
        assert_eq!(jws.alg, SupportedAlg::Es256);
        assert_eq!(
            jws.signing_input,
            format!("{header}.{payload}").into_bytes()
        );
        assert_eq!(jws.payload, br#"{"sub":"alice"}"#);
        assert_eq!(jws.typ, "at+jwt");
        assert_eq!(jws.kid, "key-1");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn parse_extracts_kid_when_present() {
        // header 含 kid → Jws.kid = Some（JWKS 轮转按 id 选 key）。
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"at+jwt","kid":"key-2024"}"#);
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"alice"}"#);
        let token = format!("{header}.{payload}.c2lnbmF0dXJl");
        let jws = parse_rss(&token).expect("well-formed ES256+kid 应解析成功");
        assert_eq!(jws.kid, "key-2024");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn parse_ignores_unknown_header_fields() {
        // 未知 header 字段（如 typ/cty/x5t）不影响解析；kid 缺省 → None。
        let header = URL_SAFE_NO_PAD
            .encode(br#"{"alg":"HS256","typ":"rss-service+jwt","kid":"svc-1","cty":"x"}"#);
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"svc"}"#);
        let token = format!("{header}.{payload}.c2ln");
        let jws = parse(&token, diport::TokenProfile::ServiceToken.policy())
            .expect("额外 header 字段应被忽略");
        assert_eq!(jws.alg, SupportedAlg::Hs256);
        assert_eq!(jws.kid, "svc-1");
    }

    #[test]
    fn parse_rejects_any_critical_header_parameter() {
        for crit in [r#"["future"]"#, "[]", "null", r#""future""#] {
            let header = URL_SAFE_NO_PAD.encode(
                format!(r#"{{"alg":"ES256","typ":"at+jwt","kid":"key-1","crit":{crit}}}"#)
                    .as_bytes(),
            );
            let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"alice"}"#);
            let token = format!("{header}.{payload}.c2ln");

            assert!(
                matches!(parse_rss(&token), Err(JwsError::Malformed)),
                "当前实现不支持 critical extension，crit={crit} 必须 fail-closed"
            );
        }
    }

    fn assert_too_large(token: &str, boundary: &str) {
        let error = parse_rss(token).err().map(|error| format!("{error:?}"));
        assert_eq!(
            error.as_deref(),
            Some("TooLarge"),
            "{boundary} 超限输入必须归类为 TooLarge，不能落入结构/编码错误"
        );
    }

    #[test]
    fn total_encoded_length_accepts_limit_and_rejects_limit_plus_one() {
        let policy = diport::TokenProfile::RssAccess.policy();
        for total in [
            policy.maximum_token_length() - 1,
            policy.maximum_token_length(),
        ] {
            let header_len = policy.maximum_header_length();
            let signature_len = policy.maximum_signature_length();
            let payload_len = total - header_len - signature_len - 2;
            let token = format!(
                "{}.{}.{}",
                "a".repeat(header_len),
                "a".repeat(payload_len),
                "a".repeat(signature_len)
            );
            assert!(
                !matches!(parse_rss(&token), Err(JwsError::TooLarge)),
                "total={total} 在 inclusive 上限内不得归类为 TooLarge"
            );
        }

        let token = "a".repeat(policy.maximum_token_length() + 1);
        assert_too_large(&token, "token total encoded length");
    }

    #[test]
    fn header_encoded_length_accepts_limit_and_rejects_limit_plus_one() {
        let policy = diport::TokenProfile::RssAccess.policy();
        for raw_len in [3_071, 3_072] {
            let prefix = r#"{"alg":"ES256","typ":"at+jwt","kid":"key-1","x":""#;
            let suffix = r#""}"#;
            let filler = "a".repeat(raw_len - prefix.len() - suffix.len());
            let header = URL_SAFE_NO_PAD.encode(format!("{prefix}{filler}{suffix}").as_bytes());
            assert!(
                header.len() == policy.maximum_header_length() - 1
                    || header.len() == policy.maximum_header_length()
            );
            let token = format!("{header}.e30.c2ln");
            assert!(
                parse_rss(&token).is_ok(),
                "header={} 在 inclusive 上限内必须完成解析",
                header.len()
            );
        }

        let header = "a".repeat(policy.maximum_header_length() + 1);
        let token = format!("{header}.e30.c2ln");
        assert_too_large(&token, "protected header encoded length");
    }

    #[test]
    fn payload_encoded_length_accepts_limit_and_rejects_limit_plus_one() {
        let policy = diport::TokenProfile::RssAccess.policy();
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"at+jwt","kid":"key-1"}"#);
        for raw_len in [9_215, 9_216] {
            let payload = URL_SAFE_NO_PAD.encode(vec![0_u8; raw_len]);
            let payload_len = payload.len();
            assert!(
                payload_len == policy.maximum_payload_length() - 1
                    || payload_len == policy.maximum_payload_length()
            );
            let token = format!("{header}.{payload}.c2ln");
            assert!(
                parse_rss(&token).is_ok(),
                "payload={payload_len} 在 inclusive 上限内必须完成解析"
            );
        }

        let payload = "a".repeat(policy.maximum_payload_length() + 1);
        let token = format!("{header}.{payload}.c2ln");
        assert_too_large(&token, "payload encoded length");
    }

    #[test]
    fn signature_encoded_length_accepts_limit_and_rejects_limit_plus_one() {
        let policy = diport::TokenProfile::RssAccess.policy();
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"at+jwt","kid":"key-1"}"#);
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"alice"}"#);
        for raw_len in [767, 768] {
            let signature = URL_SAFE_NO_PAD.encode(vec![0_u8; raw_len]);
            let signature_len = signature.len();
            assert!(
                signature_len == policy.maximum_signature_length() - 1
                    || signature_len == policy.maximum_signature_length()
            );
            let token = format!("{header}.{payload}.{signature}");
            assert!(
                parse_rss(&token).is_ok(),
                "signature={signature_len} 在 inclusive 上限内必须完成解析"
            );
        }

        let signature = "a".repeat(policy.maximum_signature_length() + 1);
        let token = format!("{header}.{payload}.{signature}");
        assert_too_large(&token, "signature encoded length");
    }
}
