//! HashiCorp Vault Transit `sign` 调用映射（`POST {addr}/v1/{mount}/sign/{key}` → `diport::Signature`）。
//!
//! 请求体 `{"input": base64(message)}`、成功响应 `{"data":{"signature":"vault:vN:<b64>"}}`、错误响应
//! `{"errors":[...]}`（非 2xx 状态码）形状对标 vaultrs `SignDataRequest`/`SignDataResponse`。
//! ref: jmgilman/vaultrs vaultrs/src/api/transit/requests.rs@master（`SignDataRequest`：`{mount}/sign/{name}` + base64 `input`）。

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use diport::{SignRequest, Signature, SignerError};

use crate::SignatureMarshaling;

/// URL-safe base64 engine（Vault Transit `jws` marshaling 响应编码：`-`/`_` 替换 `+`/`/`，无 padding）。
/// `DecodePaddingMode::Indifferent`：Vault 响应带或不带 padding 均可解码，健壮对接。
const BASE64_URL: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_encode_padding(false),
);

/// Vault token header（`X-Vault-Token`）。
const VAULT_TOKEN_HEADER: &str = "X-Vault-Token";
/// 失败诊断 `operation` 闭值集（低基数静态标签）：发请求阶段 / 读响应阶段。
const OP_SIGN_SEND: &str = "sign-send";
const OP_SIGN_READ: &str = "sign-read";

/// `addr` 不是合法 base URL（无法作 Transit 端点基地址）。
#[derive(Debug, thiserror::Error)]
#[error("vault address is not a valid base url")]
struct InvalidAddr;

/// Transit `sign` 非 2xx 响应（auth / policy / key 不存在 / Vault 不可用等）。携带 HTTP status code 作
/// **内部诊断字段**（`#[derive(Debug)]` 读它供 vault 内日志 / 诊断）：经 [`SignerError`] 包装后 source 在 port
/// 边界仍 redacted（`DIPORT-ERR-SOURCE-REDACT-01` 不破），status code 不外泄给调用方。状态码不进 `Display`
/// （const literal，error-handling.md §Message——runtime 数据只走 tracing 字段）。
#[derive(Debug, thiserror::Error)]
#[error("vault transit sign returned non-success status")]
struct NonSuccessStatus(u16);

/// Transit `sign` 2xx 响应缺 `data.signature`（畸形 / 非签名响应 / `{"errors":[..]}`）。
#[derive(Debug, thiserror::Error)]
#[error("vault transit sign response missing signature")]
struct MissingSignature;

/// `data.signature` 不是合法 Vault Transit tagged 签名（缺 `vault:v<N>:` 前缀 / 版本非数字）。
#[derive(Debug, thiserror::Error)]
#[error("vault transit signature is not a valid vault:vN: tagged value")]
struct MalformedSignature;

/// 构造 Transit `sign` 请求体：`input` 始终 STANDARD base64（Vault 要求），`marshaling_algorithm` 显式声明
/// 编码方式（`"asn1"` = ASN.1 DER + STANDARD base64 响应；`"jws"` = raw r‖s + URL-safe base64 响应）。
/// 不声明则 Vault 默认 `asn1`，但**显式声明**消除了对 Vault 版本默认值的隐式依赖（F1，#1252）。
/// input encoding 恒为 STANDARD；只有**响应**签名的编码随 marshaling 变化。
pub(crate) fn build_sign_body(
    message: &[u8],
    marshaling: SignatureMarshaling,
) -> serde_json::Value {
    let marshaling_str = match marshaling {
        SignatureMarshaling::Asn1 => "asn1",
        SignatureMarshaling::Jws => "jws",
    };
    serde_json::json!({
        "input": BASE64.encode(message),
        "marshaling_algorithm": marshaling_str,
    })
}

/// 解析 Transit `sign` 成功响应 `{"data":{"signature":"vault:vN:<b64>"}}` → [`Signature`]（**原始签名字节**，
/// 符合 `diport::Signature` = 签名结果字节契约）。缺 `data.signature` / `{"data":null}` / `{"errors":[..]}`
/// → `MissingSignature`；前缀·版本·base64 非法 → `MalformedSignature`（经 [`SignerError`] 脱敏）。
/// `marshaling` 决定响应体 `<b64>` 段使用 STANDARD（`Asn1`）还是 URL-safe（`Jws`）base64 解码。
pub(crate) fn parse_sign_response(
    body: &[u8],
    marshaling: SignatureMarshaling,
) -> Result<Signature, SignerError> {
    #[derive(serde::Deserialize)]
    struct Envelope {
        // reason: 只反序列化 data.signature；Vault 错误体 `{"errors":[..]}` 的 errors 内容（可能含 policy /
        // key 名等拓扑信息）刻意不反序列化——杜绝其进入日志 / 错误；非 2xx 已由 sign_impl 提前 reject，
        // 畸形 2xx（缺 signature / data:null）落 MissingSignature。
        data: Option<SignData>,
    }
    #[derive(serde::Deserialize)]
    struct SignData {
        signature: String,
    }
    let envelope: Envelope = serde_json::from_slice(body).map_err(SignerError::new)?;
    match envelope.data {
        Some(data) => decode_vault_signature(&data.signature, marshaling),
        None => Err(SignerError::new(MissingSignature)),
    }
}

/// Vault Transit `vault:v<N>:<b64>` → 原始签名字节。校验 `vault:v` 前缀 + 数字版本段，再按 `marshaling`
/// 选 base64 引擎 decode `<b64>` 部分（version 是 Vault 验签元数据，对 provider-agnostic `diport::Signature`
/// 无意义，剥离）：`Asn1` = STANDARD；`Jws` = URL-safe（Vault jws 响应用 `-`/`_` 替换 `+`/`/`，无 padding）。
/// reason: 不复用 Vault tagged 串作 opaque token——`diport::Signature` 契约是签名字节（signer.rs），消费方
/// （JWT/JWS 用 Jws；deviceloop 证书签发用 Asn1）需原始字节；若业务确需 Vault verify 的 tagged token，应拆
/// 独立 verify-capable port。
fn decode_vault_signature(
    tagged: &str,
    marshaling: SignatureMarshaling,
) -> Result<Signature, SignerError> {
    let rest = tagged
        .strip_prefix("vault:v")
        .ok_or_else(|| SignerError::new(MalformedSignature))?;
    let (version, b64) = rest
        .split_once(':')
        .ok_or_else(|| SignerError::new(MalformedSignature))?;
    if version.is_empty() || !version.bytes().all(|b| b.is_ascii_digit()) {
        return Err(SignerError::new(MalformedSignature));
    }
    let bytes = match marshaling {
        SignatureMarshaling::Asn1 => BASE64.decode(b64).map_err(SignerError::new)?,
        SignatureMarshaling::Jws => BASE64_URL.decode(b64).map_err(SignerError::new)?,
    };
    Ok(Signature::new(bytes))
}

/// 执行 Transit `sign`：`POST {base}/v1/{mount…}/sign/{key}`，header `X-Vault-Token`，请求级 `timeout`。
/// `base` 已在构造期校验 scheme（https / 显式 http）。`mount_segments`（构造期按 `/` 拆分校验）逐段 push、`key`
/// 单段 push——均经 `Url::path_segments_mut` percent-encode（杜绝路径段注入）。`token` / `message` 绝不进 span / 日志。
/// `marshaling` 决定请求体 `marshaling_algorithm` 字段与响应 `<b64>` 段解码引擎（`Asn1`=STANDARD；`Jws`=URL-safe）。
#[tracing::instrument(
    name = "vault.transit.sign",
    skip_all,
    fields(resource = "vault", operation = "sign", key = request.key.as_str(), purpose = request.purpose.as_str())
)]
pub(crate) async fn sign_impl(
    client: &reqwest::Client,
    base: &reqwest::Url,
    token: &str,
    mount_segments: &[String],
    timeout: Duration,
    marshaling: SignatureMarshaling,
    request: SignRequest,
) -> Result<Signature, SignerError> {
    let mut url = base.clone();
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|()| SignerError::new(InvalidAddr))?;
        // pop_if_empty：去掉 base 根路径 "/" 产生的尾空段，避免 `//v1`。mount 已拆好的多段逐段 push（嵌套 mount
        // `team/transit` → `team/transit` 而非 `team%2Ftransit`，F3）；key 单段 push（防注入，F1 percent-encode）。
        segments
            .pop_if_empty()
            .push("v1")
            .extend(mount_segments)
            .push("sign")
            .push(request.key.as_str());
    }
    // reason: serde_json::Value 序列化理论上不失败（无非序列化字段）；用 map_err 而非 expect 符合库错误规范
    // （error-handling.md），无需 item-level #[allow]。
    let payload = serde_json::to_vec(&build_sign_body(request.message.as_bytes(), marshaling))
        .map_err(SignerError::new)?;

    let response = client
        .post(url)
        .header(VAULT_TOKEN_HEADER, token)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        // F4: 请求级 timeout（防注入的 Client 未配 timeout 时无限等待）。
        .timeout(timeout)
        .body(payload)
        .send()
        .await
        .map_err(|e| warn_and_wrap(OP_SIGN_SEND, e))?;

    let status = response.status();
    if !status.is_success() {
        let code = status.as_u16();
        let (category, security_relevant) = classify_status(code);
        // #1180 分级：401/403（token / ACL / policy 授权失败）= 安全告警级 → error!（运维须单独告警、与依赖
        // 抖动区分）；429 限流 / 5xx 依赖不可用 / 其它 4xx → warn!。tracing level 须静态，故按 security_relevant
        // 在两个 callsite 分流。`category`（4 值闭值集）是低基数告警分组字段;`status` 是原始 HTTP 码（HTTP 语义
        // 闭集、非无界，仅作诊断而非告警分组键）。二者均非 PII，不打印 endpoint URL / token / 响应体。
        if security_relevant {
            tracing::error!(
                target: "vault",
                status = code,
                category,
                "vault transit sign returned non-success status"
            );
        } else {
            tracing::warn!(
                target: "vault",
                status = code,
                category,
                "vault transit sign returned non-success status"
            );
        }
        return Err(SignerError::new(NonSuccessStatus(code)));
    }

    let body = response
        .bytes()
        .await
        .map_err(|e| warn_and_wrap(OP_SIGN_READ, e))?;
    parse_sign_response(&body, marshaling)
}

/// 记录低基数诊断（reqwest 错误归类为静态类别，**不打印其 `Display`**——杜绝 endpoint URL / 请求详情进日志；
/// 比泛 adapter 的 `redact_error(Display)` funnel 更保守，契合 secrets-backend 敏感度）后把底层错误包成
/// [`SignerError`]（PII 边界：原始错误经 `RedactedSource` 不外泄）。`key`/`purpose` 已在 `#[instrument]` span。
fn warn_and_wrap(operation: &str, err: reqwest::Error) -> SignerError {
    tracing::warn!(
        target: "vault",
        operation = operation,
        category = classify_reqwest_error(&err),
        "vault transit sign request failed"
    );
    SignerError::new(err)
}

/// 非 2xx HTTP 状态 → `(低基数告警类别, 安全相关位)`（#1180）。与 [`classify_reqwest_error`] 同范式：闭值集、
/// 不进 `Display`。`category` 供运维告警规则区分授权失败 / 限流 / 依赖不可用 / 客户端错误;安全相关位
/// （401/403 = token/ACL/policy 授权失败）决定日志级别（`error!` vs `warn!`，level 须静态故在 callsite 分流）。
/// 纯函数 → 表驱动单测（`mod tests::classify_status_*`）。
fn classify_status(status: u16) -> (&'static str, bool) {
    match status {
        401 | 403 => ("auth_error", true),
        429 => ("rate_limited", false),
        s if s >= 500 => ("server_error", false),
        // catch-all：其余 4xx（404 键/mount 不存在、400 请求畸形、422 等）均客户端错误、非安全告警。
        // 新增安全相关状态（如未来 407）须显式加 arm + 改 security_relevant，扩展即显式代码改动（非隐藏漂移）。
        _ => ("client_error", false),
    }
}

/// reqwest 错误 → 低基数静态标签（不经 `Display`，杜绝 URL/请求详情泄漏；供告警规则区分失败类别）。
/// 类别判定委托纯函数 [`classify_error_kind`]：`reqwest::Error` 无公开构造器、无法表驱动直测，故把可测的
/// 映射逻辑抽出，本函数仅做 `reqwest::Error` → 四元谓词的薄提取（阅读保障）。
fn classify_reqwest_error(err: &reqwest::Error) -> &'static str {
    classify_error_kind(
        err.is_timeout(),
        err.is_connect(),
        err.is_decode(),
        err.is_request(),
    )
}

/// reqwest 错误四元谓词 → 低基数静态类别（优先级：timeout ▷ connect ▷ decode ▷ request ▷ other）。
/// 纯函数 → 表驱动单测（`mod tests::classify_error_kind_*`）锁定映射 + 优先级。
fn classify_error_kind(timeout: bool, connect: bool, decode: bool, request: bool) -> &'static str {
    if timeout {
        "timeout"
    } else if connect {
        "connect"
    } else if decode {
        "decode"
    } else if request {
        "request"
    } else {
        "other"
    }
}

#[cfg(test)]
mod tests {
    //! Transit 请求体构造 / 响应解析纯逻辑（无 live 后端，确定性）。
    use base64::Engine as _;

    use super::{BASE64, BASE64_URL, build_sign_body, parse_sign_response};
    use crate::SignatureMarshaling;

    #[test]
    fn build_sign_body_base64_encodes_input() {
        // base64("payload") == "cGF5bG9hZA=="（STANDARD，含 padding）。input 始终 STANDARD base64。
        let body = build_sign_body(b"payload", SignatureMarshaling::Asn1);
        assert_eq!(body["input"].as_str(), Some("cGF5bG9hZA=="));
    }

    #[test]
    fn build_sign_body_empty_message_encodes_empty_input() {
        let body = build_sign_body(b"", SignatureMarshaling::Asn1);
        assert_eq!(body["input"].as_str(), Some(""));
    }

    #[test]
    fn build_sign_body_binary_bytes_encode_correctly() {
        // 真实用途是 CSR / 证书 DER 等二进制字节（含 \x00/\xFF），验确定性 base64（非纯 ASCII 路径）。
        // input 始终 STANDARD base64，与 marshaling 无关。
        let message: &[u8] = &[0x00, 0xFF, 0xAB];
        let expected = BASE64.encode(message); // 锚定期望 = 同一 STANDARD 引擎输出（"AP+r"）。
        assert_eq!(expected, "AP+r");
        assert_eq!(
            build_sign_body(message, SignatureMarshaling::Asn1)["input"].as_str(),
            Some(expected.as_str())
        );
    }

    #[test]
    fn build_sign_body_asn1_includes_marshaling_algorithm_asn1() {
        // Asn1 marshaling → 请求体显式携带 `"marshaling_algorithm":"asn1"`，消除对 Vault 默认值的隐式依赖（#1252）。
        let body = build_sign_body(b"msg", SignatureMarshaling::Asn1);
        assert_eq!(
            body["marshaling_algorithm"].as_str(),
            Some("asn1"),
            "Asn1 marshaling must send marshaling_algorithm=asn1"
        );
    }

    #[test]
    fn build_sign_body_jws_includes_marshaling_algorithm_jws() {
        // Jws marshaling → 请求体显式携带 `"marshaling_algorithm":"jws"`（JWT/JWS 消费方需 raw r‖s，#1252）。
        let body = build_sign_body(b"msg", SignatureMarshaling::Jws);
        assert_eq!(
            body["marshaling_algorithm"].as_str(),
            Some("jws"),
            "Jws marshaling must send marshaling_algorithm=jws"
        );
    }

    #[test]
    fn build_sign_body_jws_input_is_still_standard_base64() {
        // Jws marshaling 下 input 仍为 STANDARD base64（只有响应 body 的签名段用 url-safe，anti-vacuity）。
        let message: &[u8] = &[0xFB]; // STANDARD: "+w=="; URL_SAFE: "-w"。
        let body = build_sign_body(message, SignatureMarshaling::Jws);
        assert_eq!(
            body["input"].as_str(),
            Some("+w=="),
            "input must always be STANDARD base64 regardless of marshaling"
        );
        assert_eq!(body["marshaling_algorithm"].as_str(), Some("jws"));
    }

    #[test]
    fn parse_ok_decodes_tagged_signature_to_raw_bytes() {
        // base64("rawsig") == "cmF3c2ln"；解码后返回原始字节（剥离 vault:v1: 前缀），符合 diport::Signature 字节契约。
        let body = br#"{"data":{"signature":"vault:v1:cmF3c2ln"}}"#;
        assert!(matches!(
            parse_sign_response(body, SignatureMarshaling::Asn1),
            Ok(sig) if sig.as_bytes() == b"rawsig"
        ));
    }

    #[test]
    fn parse_jws_decodes_url_safe_base64() {
        // anti-vacuity：0xFB 在 STANDARD base64 编码为 "+w=="，在 URL_SAFE（无 padding）编码为 "-w"。
        // `vault:v1:-w` 经 Jws 路径（BASE64_URL）解码 → [0xFB]；Asn1（BASE64）路径下 "-" 不在字母表 → Err。
        // 此测证明 Jws 路径确实使用 URL-safe 引擎（非仅名义区分）。
        let url_safe_b64 = BASE64_URL.encode([0xFB_u8]); // "-w"（URL_SAFE，无 padding）
        assert_eq!(
            url_safe_b64, "-w",
            "0xFB must encode to '-w' in url-safe no-pad base64"
        );
        let body_str = format!(r#"{{"data":{{"signature":"vault:v1:{url_safe_b64}"}}}}"#);
        // Jws 路径：成功 decode → [0xFB]
        assert!(
            matches!(
                parse_sign_response(body_str.as_bytes(), SignatureMarshaling::Jws),
                Ok(sig) if sig.as_bytes() == [0xFB_u8]
            ),
            "Jws path must decode url-safe base64 '-w' to [0xFB]"
        );
        // Asn1 路径：'-' 不在 STANDARD 字母表 → Err（anti-vacuity：两路径确实不同）
        assert!(
            parse_sign_response(body_str.as_bytes(), SignatureMarshaling::Asn1).is_err(),
            "Asn1 path must fail on url-safe base64 char '-'"
        );
    }

    #[test]
    fn parse_signature_missing_prefix_is_err() {
        let body = br#"{"data":{"signature":"cmF3c2ln"}}"#;
        assert!(parse_sign_response(body, SignatureMarshaling::Asn1).is_err());
    }

    #[test]
    fn parse_signature_non_numeric_version_is_err() {
        let body = br#"{"data":{"signature":"vault:vX:cmF3c2ln"}}"#;
        assert!(parse_sign_response(body, SignatureMarshaling::Asn1).is_err());
    }

    #[test]
    fn parse_signature_invalid_base64_is_err() {
        // `vault:v1:` 前缀合法、版本数字合法，但 base64 体非法（'!' 不在字母表）→ MalformedSignature/解码错误。
        let body = br#"{"data":{"signature":"vault:v1:!!!"}}"#;
        assert!(parse_sign_response(body, SignatureMarshaling::Asn1).is_err());
    }

    #[test]
    fn parse_vault_errors_envelope_is_err() {
        // 非 2xx 体（`{"errors":[..]}`，无 data）→ Err（缺 signature）。
        let body = br#"{"errors":["permission denied"]}"#;
        assert!(parse_sign_response(body, SignatureMarshaling::Asn1).is_err());
    }

    #[test]
    fn parse_data_null_is_err() {
        // 显式 `{"data":null}`（与 data 缺失不同形状，但同走 None 分支）→ Err。
        let body = br#"{"data":null}"#;
        assert!(parse_sign_response(body, SignatureMarshaling::Asn1).is_err());
    }

    #[test]
    fn parse_missing_signature_field_is_err() {
        // 2xx 但 data 无 signature 字段（畸形）→ Err。
        let body = br#"{"data":{}}"#;
        assert!(parse_sign_response(body, SignatureMarshaling::Asn1).is_err());
    }

    #[test]
    fn parse_malformed_json_is_err() {
        assert!(parse_sign_response(b"not json", SignatureMarshaling::Asn1).is_err());
    }

    #[test]
    fn classify_status_maps_to_low_cardinality_category_and_severity() {
        use super::classify_status;
        // #1180：非 2xx 状态 → (低基数告警类别, 安全相关位)。安全相关位决定 sign_impl 选 error!/warn!
        // （level 须静态，故在 callsite 分流——本表锁定「哪些状态走 error 级」这一决策本身）。
        // (status, expected_category, expected_security_relevant)
        let cases = [
            (401u16, "auth_error", true), // 认证失败（token 无效 / 缺失）→ 安全告警级
            (403, "auth_error", true),    // ACL / policy 拒绝 → 安全告警级
            (429, "rate_limited", false), // 限流 → 退避级（warn）
            (500, "server_error", false), // Vault 内部错误 → 依赖告警级（warn）
            (503, "server_error", false), // Vault 不可用 → 依赖告警级（warn）
            (502, "server_error", false), // 网关错误（≥500 区段下界外的其它 5xx）
            (400, "client_error", false), // 请求畸形 → 客户端错误（warn）
            (404, "client_error", false), // 键 / mount 不存在 → 客户端错误
            (418, "client_error", false), // 其它 4xx 兜底
        ];
        for (status, category, security) in cases {
            assert_eq!(
                classify_status(status),
                (category, security),
                "status {status} classification"
            );
        }
    }

    #[test]
    fn classify_error_kind_maps_predicates_with_priority() {
        use super::classify_error_kind;
        // (timeout, connect, decode, request, expected)。优先级 timeout ▷ connect ▷ decode ▷ request ▷ other。
        // 测 reqwest 错误映射的全部 5 个出口 + 高位谓词盖过低位（reqwest::Error 无公开构造器，故测可达的
        // 四元谓词纯映射;reqwest::Error → 四元 bool 的提取由 classify_reqwest_error 薄包装、阅读保障）。
        let cases = [
            (true, false, false, false, "timeout"),
            (false, true, false, false, "connect"),
            (false, false, true, false, "decode"),
            (false, false, false, true, "request"),
            (false, false, false, false, "other"),
            (true, true, true, true, "timeout"), // 优先级：timeout 盖过其余
            (false, true, true, true, "connect"), // connect 盖过 decode/request
            (false, false, true, true, "decode"), // decode 盖过 request
        ];
        for (timeout, connect, decode, request, expected) in cases {
            assert_eq!(
                classify_error_kind(timeout, connect, decode, request),
                expected,
                "({timeout},{connect},{decode},{request})"
            );
        }
    }
}

#[cfg(all(test, feature = "backend"))]
mod sign_impl_tests {
    //! `sign_impl` HTTP 编排层 4 分支 + 路径 percent-encode / `X-Vault-Token` header 确定性单测：wiremock
    //! loopback canned 响应，reqwest 真发请求测真实编排（无 live Vault、不抽 transport trait）。纯函数接缝
    //! （build_sign_body / parse_sign_response / classify_status）见 `mod tests`。对标 adapters/s3 backend_tests
    //! 「传输边界 mock、测真实编排」范式。
    //!
    //! 4 分支覆盖：① send 失败（连接被拒，端到端经 `warn_and_wrap` → `classify_reqwest_error` connect 路径）
    //! ② 非 2xx（含 error!/warn! 两个安全分级 callsite） ④ 2xx 成功 → parse_sign_response。③ `bytes()` 读取
    //! 失败：与 ① 同形（`warn_and_wrap`，仅 OP 常量 OP_SIGN_READ vs OP_SIGN_SEND 不同），wiremock 无法稳定触发
    //! 响应体读取中断、不为单一分支引第二套机制（优雅简洁），由 ① 经 `warn_and_wrap` 端到端覆盖 + 阅读保障。
    //! （`classify_reqwest_error` 的类别映射逻辑由 `mod tests::classify_error_kind_*` 表驱动全覆盖。）
    use std::time::Duration;

    use diport::{KeyId, SignRequest, Signature, SignerError, SigningPurpose};
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::sign_impl;
    use crate::SignatureMarshaling;

    // reason: header 可达性验证用占位值（断言 X-Vault-Token 被注入），非真实 token / token 格式规范。
    const TOKEN: &str = "test-token";
    const OK_BODY: &str = r#"{"data":{"signature":"vault:v1:cmF3c2ln"}}"#; // base64("rawsig")=="cmF3c2ln"

    // base Url = mock server 地址。expect 的 item-level carve-out 集中此处（error-handling.md §Carve-out）。
    #[allow(clippy::expect_used)]
    fn base_url(server: &MockServer) -> reqwest::Url {
        reqwest::Url::parse(&server.uri()).expect("mock server uri is a valid base url")
    }

    fn sign_request(key: &str) -> SignRequest {
        SignRequest {
            key: KeyId::new(key),
            purpose: SigningPurpose::new("unit-test"),
            message: b"hello-rss".to_vec().into(),
        }
    }

    // 固定 mount=["transit"] + timeout=200ms 调 sign_impl（直接传 http base Url；scheme 校验在 VaultSigner::new，
    // 非 sign_impl 职责，故无需构造 VaultSigner）。Asn1：OK_BODY 含 STANDARD base64 "cmF3c2ln" = "rawsig"。
    async fn call(server: &MockServer, key: &str) -> Result<Signature, SignerError> {
        sign_impl(
            &reqwest::Client::new(),
            &base_url(server),
            TOKEN,
            &["transit".to_string()],
            Duration::from_millis(200),
            SignatureMarshaling::Asn1,
            sign_request(key),
        )
        .await
    }

    // 取唯一一次收到的请求（断言 percent-encode / header 用）。expect carve-out 集中此处。
    #[allow(clippy::expect_used)]
    async fn single_request(server: &MockServer) -> wiremock::Request {
        let mut reqs = server
            .received_requests()
            .await
            .expect("wiremock request recording enabled by default");
        assert_eq!(reqs.len(), 1, "exactly one request expected");
        reqs.remove(0)
    }

    #[tokio::test]
    async fn sign_2xx_success_decodes_signature() {
        // Branch 4：2xx → parse_sign_response 剥 vault:v1: 前缀 base64 decode → 原始字节。
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(OK_BODY))
            .mount(&server)
            .await;
        assert!(matches!(call(&server, "my-key").await, Ok(sig) if sig.as_bytes() == b"rawsig"));
    }

    #[tokio::test]
    async fn sign_encodes_key_path_segment_and_sends_token_header() {
        // 安全（F1）：key="../x" 必须 percent-encode 成单段 `..%2Fx`（而非路径穿越 `/v1/transit/x`）;
        // 且请求带 X-Vault-Token header。catch-all 响应 200，直接 inspect 收到的请求断言真实 wire 形态。
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(OK_BODY))
            .mount(&server)
            .await;
        assert!(call(&server, "../x").await.is_ok());
        let req = single_request(&server).await;
        assert_eq!(
            req.url.path(),
            "/v1/transit/sign/..%2Fx",
            "key segment must be percent-encoded (no path traversal)"
        );
        assert_eq!(
            req.headers
                .get("X-Vault-Token")
                .and_then(|v| v.to_str().ok()),
            Some(TOKEN)
        );
    }

    #[tokio::test]
    async fn sign_non_success_statuses_are_err() {
        // Branch 2：非 2xx → Err（NonSuccessStatus）。覆盖 error!（401/403）+ warn!（429/5xx/4xx）两个安全分级
        // callsite;分类映射本身由 mod tests::classify_status_* 锁定（错误经 SignerError 脱敏，return 值不暴露
        // category/level，故分级正确性测在纯函数侧、分支命中测在此）。
        for status in [400u16, 401, 403, 429, 500, 503] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(status).set_body_string(r#"{"errors":["x"]}"#))
                .mount(&server)
                .await;
            assert!(
                call(&server, "k").await.is_err(),
                "status {status} must map to Err"
            );
        }
    }

    // 指向无监听者的本地端口（绑定 :0 取系统分配端口后立即释放）→ 连接必被拒。expect carve-out 集中此处。
    #[allow(clippy::expect_used)]
    fn refused_base() -> reqwest::Url {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener); // 释放 → 端口回到未监听态。
        reqwest::Url::parse(&format!("http://127.0.0.1:{port}/")).expect("valid base url")
    }

    #[tokio::test]
    async fn sign_send_connection_refused_is_err() {
        // Branch 1：send 失败——指向无监听者端口 → 连接被拒 → warn_and_wrap(OP_SIGN_SEND) → Err。确定性、
        // 无 lingering mock server（无 nextest leaky）;直接覆盖 classify_reqwest_error 的 connect 分支。
        // F4 请求级 timeout 在 sign_impl 无条件设置（`.timeout(timeout)`），阅读保障——不另起 lingering-server
        // 超时测试以免 leaky。
        let result = sign_impl(
            &reqwest::Client::new(),
            &refused_base(),
            TOKEN,
            &["transit".to_string()],
            Duration::from_secs(5),
            SignatureMarshaling::Asn1,
            sign_request("k"),
        )
        .await;
        assert!(result.is_err());
    }
}
