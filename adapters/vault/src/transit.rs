//! HashiCorp Vault Transit `sign` 调用映射（`POST {addr}/v1/{mount}/sign/{key}` → `diport::Signature`）。
//!
//! 请求体 `{"input": base64(message)}`、成功响应 `{"data":{"signature":"vault:vN:<b64>"}}`、错误响应
//! `{"errors":[...]}`（非 2xx 状态码）形状对标 vaultrs `SignDataRequest`/`SignDataResponse`。
//! ref: jmgilman/vaultrs vaultrs/src/api/transit/requests.rs@master（`SignDataRequest`：`{mount}/sign/{name}` + base64 `input`）。

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use diport::{SignRequest, Signature, SignerError};

/// Vault token header（`X-Vault-Token`）。
const VAULT_TOKEN_HEADER: &str = "X-Vault-Token";
/// 失败诊断 `operation` 闭值集（低基数静态标签）：发请求阶段 / 读响应阶段。
const OP_SIGN_SEND: &str = "sign-send";
const OP_SIGN_READ: &str = "sign-read";

/// `addr` 不是合法 base URL（无法作 Transit 端点基地址）。
#[derive(Debug, thiserror::Error)]
#[error("vault address is not a valid base url")]
struct InvalidAddr;

/// Transit `sign` 非 2xx 响应（auth / policy / key 不存在 / Vault 不可用等）。状态码经 tracing 字段下发
/// （低基数、非 PII），不进 `Display`（const literal，error-handling.md §Message）。
#[derive(Debug, thiserror::Error)]
#[error("vault transit sign returned non-success status")]
struct NonSuccessStatus;

/// Transit `sign` 2xx 响应缺 `data.signature`（畸形 / 非签名响应 / `{"errors":[..]}`）。
#[derive(Debug, thiserror::Error)]
#[error("vault transit sign response missing signature")]
struct MissingSignature;

/// `data.signature` 不是合法 Vault Transit tagged 签名（缺 `vault:v<N>:` 前缀 / 版本非数字）。
#[derive(Debug, thiserror::Error)]
#[error("vault transit signature is not a valid vault:vN: tagged value")]
struct MalformedSignature;

/// 构造 Transit `sign` 请求体 `{"input": base64(message)}`（vaultrs `SignDataRequest.input` = base64 明文）。
pub(crate) fn build_sign_body(message: &[u8]) -> serde_json::Value {
    serde_json::json!({ "input": BASE64.encode(message) })
}

/// 解析 Transit `sign` 成功响应 `{"data":{"signature":"vault:vN:<b64>"}}` → [`Signature`]（**原始签名字节**，
/// 符合 `diport::Signature` = 签名结果字节契约，被 deviceloop 证书签发消费）。缺 `data.signature` / `{"data":null}`
/// / `{"errors":[..]}` → `MissingSignature`；前缀·版本·base64 非法 → `MalformedSignature`（经 [`SignerError`] 脱敏）。
pub(crate) fn parse_sign_response(body: &[u8]) -> Result<Signature, SignerError> {
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
        Some(data) => decode_vault_signature(&data.signature),
        None => Err(SignerError::new(MissingSignature)),
    }
}

/// Vault Transit `vault:v<N>:<base64>` → 原始签名字节。校验 `vault:v` 前缀 + 数字版本段，再 STANDARD base64
/// decode `<base64>` 部分（version 是 Vault 验签元数据，对 provider-agnostic `diport::Signature` 无意义，剥离）。
/// reason: 不复用 Vault tagged 串作 opaque token——`diport::Signature` 契约是签名字节（signer.rs），消费方
/// （deviceloop 证书签发）需原始字节；若业务确需 Vault verify 的 tagged token，应拆独立 verify-capable port。
fn decode_vault_signature(tagged: &str) -> Result<Signature, SignerError> {
    let rest = tagged
        .strip_prefix("vault:v")
        .ok_or_else(|| SignerError::new(MalformedSignature))?;
    let (version, b64) = rest
        .split_once(':')
        .ok_or_else(|| SignerError::new(MalformedSignature))?;
    if version.is_empty() || !version.bytes().all(|b| b.is_ascii_digit()) {
        return Err(SignerError::new(MalformedSignature));
    }
    let bytes = BASE64.decode(b64).map_err(SignerError::new)?;
    Ok(Signature::new(bytes))
}

/// 执行 Transit `sign`：`POST {base}/v1/{mount…}/sign/{key}`，header `X-Vault-Token`，请求级 `timeout`。
/// `base` 已在构造期校验 scheme（https / 显式 http）。`mount_segments`（构造期按 `/` 拆分校验）逐段 push、`key`
/// 单段 push——均经 `Url::path_segments_mut` percent-encode（杜绝路径段注入）。`token` / `message` 绝不进 span / 日志。
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
    let payload =
        serde_json::to_vec(&build_sign_body(&request.message)).map_err(SignerError::new)?;

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
        tracing::warn!(
            target: "vault",
            status = status.as_u16(),
            "vault transit sign returned non-success status"
        );
        return Err(SignerError::new(NonSuccessStatus));
    }

    let body = response
        .bytes()
        .await
        .map_err(|e| warn_and_wrap(OP_SIGN_READ, e))?;
    parse_sign_response(&body)
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

/// reqwest 错误 → 低基数静态标签（不经 `Display`，杜绝 URL/请求详情泄漏；供告警规则区分失败类别）。
fn classify_reqwest_error(err: &reqwest::Error) -> &'static str {
    if err.is_timeout() {
        "timeout"
    } else if err.is_connect() {
        "connect"
    } else if err.is_decode() {
        "decode"
    } else if err.is_request() {
        "request"
    } else {
        "other"
    }
}

#[cfg(test)]
mod tests {
    //! Transit 请求体构造 / 响应解析纯逻辑（无 live 后端，确定性）。
    use base64::Engine as _;

    use super::{BASE64, build_sign_body, parse_sign_response};

    #[test]
    fn build_sign_body_base64_encodes_input() {
        // base64("payload") == "cGF5bG9hZA=="（STANDARD，含 padding）。
        let body = build_sign_body(b"payload");
        assert_eq!(body["input"].as_str(), Some("cGF5bG9hZA=="));
    }

    #[test]
    fn build_sign_body_empty_message_encodes_empty_input() {
        let body = build_sign_body(b"");
        assert_eq!(body["input"].as_str(), Some(""));
    }

    #[test]
    fn build_sign_body_binary_bytes_encode_correctly() {
        // 真实用途是 CSR / 证书 DER 等二进制字节（含 \x00/\xFF），验确定性 base64（非纯 ASCII 路径）。
        let message: &[u8] = &[0x00, 0xFF, 0xAB];
        let expected = BASE64.encode(message); // 锚定期望 = 同一 STANDARD 引擎输出（"AP+r"）。
        assert_eq!(expected, "AP+r");
        assert_eq!(
            build_sign_body(message)["input"].as_str(),
            Some(expected.as_str())
        );
    }

    #[test]
    fn parse_ok_decodes_tagged_signature_to_raw_bytes() {
        // base64("rawsig") == "cmF3c2ln"；解码后返回原始字节（剥离 vault:v1: 前缀），符合 diport::Signature 字节契约。
        let body = br#"{"data":{"signature":"vault:v1:cmF3c2ln"}}"#;
        assert!(matches!(
            parse_sign_response(body),
            Ok(sig) if sig.as_bytes() == b"rawsig"
        ));
    }

    #[test]
    fn parse_signature_missing_prefix_is_err() {
        let body = br#"{"data":{"signature":"cmF3c2ln"}}"#;
        assert!(parse_sign_response(body).is_err());
    }

    #[test]
    fn parse_signature_non_numeric_version_is_err() {
        let body = br#"{"data":{"signature":"vault:vX:cmF3c2ln"}}"#;
        assert!(parse_sign_response(body).is_err());
    }

    #[test]
    fn parse_signature_invalid_base64_is_err() {
        // `vault:v1:` 前缀合法、版本数字合法，但 base64 体非法（'!' 不在字母表）→ MalformedSignature/解码错误。
        let body = br#"{"data":{"signature":"vault:v1:!!!"}}"#;
        assert!(parse_sign_response(body).is_err());
    }

    #[test]
    fn parse_vault_errors_envelope_is_err() {
        // 非 2xx 体（`{"errors":[..]}`，无 data）→ Err（缺 signature）。
        let body = br#"{"errors":["permission denied"]}"#;
        assert!(parse_sign_response(body).is_err());
    }

    #[test]
    fn parse_data_null_is_err() {
        // 显式 `{"data":null}`（与 data 缺失不同形状，但同走 None 分支）→ Err。
        let body = br#"{"data":null}"#;
        assert!(parse_sign_response(body).is_err());
    }

    #[test]
    fn parse_missing_signature_field_is_err() {
        // 2xx 但 data 无 signature 字段（畸形）→ Err。
        let body = br#"{"data":{}}"#;
        assert!(parse_sign_response(body).is_err());
    }

    #[test]
    fn parse_malformed_json_is_err() {
        assert!(parse_sign_response(b"not json").is_err());
    }
}
