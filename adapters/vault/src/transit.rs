//! HashiCorp Vault Transit `sign` 调用映射（`POST {addr}/v1/{mount}/sign/{key}` → `diport::Signature`）。
//!
//! 请求体 `{"input": base64(message)}`、成功响应 `{"data":{"signature":"vault:vN:<b64>"}}`、错误响应
//! `{"errors":[...]}`（非 2xx 状态码）形状对标 vaultrs `SignDataRequest`/`SignDataResponse`。
//! ref: jmgilman/vaultrs vaultrs/src/api/transit/requests.rs@master（`SignDataRequest`：`{mount}/sign/{name}` + base64 `input`）。

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use diport::key_provider::KeyProviderErrorKind;
use diport::{
    EncryptOutput, KeyName, KeyProviderError, KeyRef, KeyVersion, RedactedBytes, SignRequest,
    Signature, SignerError,
};
use secure::{DerivedAad, Plaintext};

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
const OP_KEY_PROVIDER_SEND: &str = "key-provider-send";
const OP_KEY_PROVIDER_READ: &str = "key-provider-read";
/// Vault Transit sentinel：`key_version = 0` means "use latest/current primary" for encrypt/rewrap.
const LATEST_KEY_VERSION: u32 = 0;

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

/// Transit KeyProvider 响应缺 `data.ciphertext`。
#[derive(Debug, thiserror::Error)]
#[error("vault transit key provider response missing ciphertext")]
struct MissingCiphertext;

/// Transit KeyProvider 响应缺 `data.plaintext`。
#[derive(Debug, thiserror::Error)]
#[error("vault transit key provider response missing plaintext")]
struct MissingPlaintext;

/// Transit KeyProvider 响应缺 `data.key_version`。
#[derive(Debug, thiserror::Error)]
#[error("vault transit key provider response missing key version")]
struct MissingKeyVersion;

/// Transit KeyProvider 密文不是合法 UTF-8 Vault tagged ciphertext。
#[derive(Debug, thiserror::Error)]
#[error("vault transit ciphertext is not valid utf-8")]
struct InvalidCiphertextUtf8;

/// Transit KeyProvider 密文不是合法 `vault:vN:` tagged ciphertext。
#[derive(Debug, thiserror::Error)]
#[error("vault transit ciphertext is not a valid vault:vN: tagged value")]
struct MalformedCiphertext;

/// Transit KeyProvider 密文 tag 版本与调用方携带的 [`KeyRef`] 版本不一致。
#[derive(Debug, thiserror::Error)]
#[error("vault transit ciphertext key version does not match key reference")]
struct CiphertextVersionMismatch;

/// Transit KeyProvider 响应中 ciphertext tag 版本与 `data.key_version` 元数据不一致。
#[derive(Debug, thiserror::Error)]
#[error("vault transit key provider response has mismatched ciphertext and metadata versions")]
struct ResponseVersionMismatch;

/// `addr` 不是合法 base URL（无法作 KeyProvider Transit 端点基地址）。
#[derive(Debug, thiserror::Error)]
#[error("vault address is not a valid base url for key provider")]
struct InvalidKeyProviderAddr;

/// Transit KeyProvider 非 2xx 响应。HTTP status 只留在内部 Debug，不进 Display。
#[derive(Debug, thiserror::Error)]
#[error("vault transit key provider returned non-success status")]
struct KeyProviderNonSuccessStatus(u16);

#[derive(Clone, Copy)]
enum KeyProviderOperation {
    Encrypt,
    Decrypt,
    Rewrap,
}

#[derive(Clone, Copy)]
pub(crate) struct TransitHttp<'a> {
    client: &'a reqwest::Client,
    base: &'a reqwest::Url,
    token: &'a str,
    mount_segments: &'a [String],
    timeout: Duration,
}

impl<'a> TransitHttp<'a> {
    pub(crate) fn new(
        client: &'a reqwest::Client,
        base: &'a reqwest::Url,
        token: &'a str,
        mount_segments: &'a [String],
        timeout: Duration,
    ) -> Self {
        Self {
            client,
            base,
            token,
            mount_segments,
            timeout,
        }
    }

    fn endpoint_url(
        &self,
        operation: KeyProviderOperation,
        key_name: &str,
    ) -> Result<reqwest::Url, KeyProviderError> {
        let mut url = self.base.clone();
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|()| key_provider_unavailable(InvalidKeyProviderAddr))?;
            segments
                .pop_if_empty()
                .push("v1")
                .extend(self.mount_segments)
                .push(operation.path_segment())
                .push(key_name);
        }
        Ok(url)
    }
}

impl KeyProviderOperation {
    fn path_segment(self) -> &'static str {
        match self {
            Self::Encrypt => "encrypt",
            Self::Decrypt => "decrypt",
            Self::Rewrap => "rewrap",
        }
    }

    fn label(self) -> &'static str {
        self.path_segment()
    }
}

/// 构造 Transit `sign` 请求体：`input` 按 Vault API 要求使用 STANDARD base64；JWT 签名表示固定为
/// JWS raw r‖s。显式声明 `jws`，避免依赖 Vault 的 ASN.1 默认值（#1252）。
pub(crate) fn build_sign_body(message: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "input": BASE64.encode(message),
        "marshaling_algorithm": "jws",
    })
}

/// 单一 AAD→Vault context funnel：RSS `DerivedAad` 的 canonical bytes 经 STANDARD base64 编码后放入
/// Vault Transit `context`。KeyProvider 路径**不**生成 `associated_data` 字段；settings Transit key 必须
/// `derived=true`，由组合根 wrong-AAD self-check 证明。rewrap 依赖 Vault 对 `context` 的原生支持，保留
/// “不解密明文”的 rewrap 语义。
pub(crate) fn build_context(aad: &DerivedAad) -> String {
    BASE64.encode(aad.as_canonical_bytes())
}

pub(crate) fn build_encrypt_body(plaintext: &Plaintext, aad: &DerivedAad) -> serde_json::Value {
    serde_json::json!({
        "plaintext": BASE64.encode(plaintext.expose()),
        "context": build_context(aad),
        // `0` is Vault's latest/current-primary selector. New ciphertext must never pin an old
        // key version after rotation.
        "key_version": LATEST_KEY_VERSION,
    })
}

pub(crate) fn build_decrypt_body(ciphertext: &str, aad: &DerivedAad) -> serde_json::Value {
    serde_json::json!({
        "ciphertext": ciphertext,
        // No key_version override on decrypt: Vault derives the previous-read key from
        // `vault:vN:` and enforces min_decryption_version policy.
        "context": build_context(aad),
    })
}

pub(crate) fn build_rewrap_body(ciphertext: &str, aad: &DerivedAad) -> serde_json::Value {
    serde_json::json!({
        "ciphertext": ciphertext,
        "context": build_context(aad),
        // Rewrap always targets the current primary.
        "key_version": LATEST_KEY_VERSION,
    })
}

/// 解析 Transit `sign` 成功响应 `{"data":{"signature":"vault:vN:<b64>"}}` → [`Signature`]（**原始签名字节**，
/// 符合 `diport::Signature` = 签名结果字节契约）。缺 `data.signature` / `{"data":null}` / `{"errors":[..]}`
/// → `MissingSignature`；前缀·版本·base64 非法 → `MalformedSignature`（经 [`SignerError`] 脱敏）。
/// 响应签名固定按 Vault JWS 的 URL-safe base64 解码。
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

pub(crate) fn parse_encrypt_response(
    body: &[u8],
    key: KeyName,
) -> Result<EncryptOutput, KeyProviderError> {
    let (ciphertext, key_version) = parse_ciphertext_response(body)?;
    Ok(EncryptOutput::new(
        ciphertext.into_bytes(),
        KeyRef::new(key, KeyVersion::new(key_version)),
    ))
}

pub(crate) fn parse_rewrap_response(
    body: &[u8],
    key: KeyName,
) -> Result<EncryptOutput, KeyProviderError> {
    parse_encrypt_response(body, key)
}

pub(crate) fn parse_decrypt_response(body: &[u8]) -> Result<Plaintext, KeyProviderError> {
    #[derive(serde::Deserialize)]
    struct Envelope {
        data: Option<DecryptData>,
    }
    #[derive(serde::Deserialize)]
    struct DecryptData {
        plaintext: Option<String>,
    }

    let envelope: Envelope = serde_json::from_slice(body).map_err(key_provider_unavailable)?;
    let plaintext = envelope
        .data
        .and_then(|data| data.plaintext)
        .ok_or_else(|| key_provider_unavailable(MissingPlaintext))?;
    let bytes = BASE64.decode(plaintext).map_err(key_provider_unavailable)?;
    Ok(Plaintext::new(bytes))
}

fn parse_ciphertext_response(body: &[u8]) -> Result<(String, u32), KeyProviderError> {
    #[derive(serde::Deserialize)]
    struct Envelope {
        data: Option<CiphertextData>,
    }
    #[derive(serde::Deserialize)]
    struct CiphertextData {
        ciphertext: Option<String>,
        key_version: Option<u32>,
    }

    let envelope: Envelope = serde_json::from_slice(body).map_err(key_provider_unavailable)?;
    let data = envelope
        .data
        .ok_or_else(|| key_provider_unavailable(MissingCiphertext))?;
    let ciphertext = data
        .ciphertext
        .ok_or_else(|| key_provider_unavailable(MissingCiphertext))?;
    let ciphertext_version =
        parse_vault_ciphertext_version(&ciphertext).map_err(key_provider_unavailable)?;
    let key_version = data
        .key_version
        .ok_or_else(|| key_provider_unavailable(MissingKeyVersion))?;
    ensure_response_versions_match(&ciphertext_version, KeyVersion::new(key_version))
        .map_err(key_provider_unavailable)?;
    Ok((ciphertext, key_version))
}

/// Vault Transit `vault:v<N>:<base64url>` → 原始 JWS 签名字节。version 是 Vault 验签元数据，对
/// provider-agnostic `diport::Signature` 无意义，因此剥离。
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
    let bytes = BASE64_URL.decode(b64).map_err(SignerError::new)?;
    Ok(Signature::new(bytes))
}

fn parse_vault_ciphertext_version(tagged: &str) -> Result<KeyVersion, MalformedCiphertext> {
    let rest = tagged.strip_prefix("vault:v").ok_or(MalformedCiphertext)?;
    let (version, b64) = rest.split_once(':').ok_or(MalformedCiphertext)?;
    if version.is_empty() || b64.is_empty() || !version.bytes().all(|b| b.is_ascii_digit()) {
        return Err(MalformedCiphertext);
    }
    BASE64.decode(b64).map_err(|_| MalformedCiphertext)?;
    KeyVersion::parse(version).map_err(|_| MalformedCiphertext)
}

fn ciphertext_to_str(ciphertext: &RedactedBytes) -> Result<(&str, KeyVersion), KeyProviderError> {
    std::str::from_utf8(ciphertext.as_bytes())
        .map_err(|_| KeyProviderError::new(KeyProviderErrorKind::Rejected, InvalidCiphertextUtf8))
        .and_then(|tagged| {
            let version = parse_vault_ciphertext_version(tagged)
                .map_err(|e| KeyProviderError::new(KeyProviderErrorKind::Rejected, e))?;
            Ok((tagged, version))
        })
}

fn ensure_ciphertext_matches_key_version(
    ciphertext_version: &KeyVersion,
    key_version: KeyVersion,
) -> Result<(), KeyProviderError> {
    if ciphertext_version.ct_eq(&key_version) {
        Ok(())
    } else {
        Err(KeyProviderError::new(
            KeyProviderErrorKind::Rejected,
            CiphertextVersionMismatch,
        ))
    }
}

fn ensure_response_versions_match(
    ciphertext_version: &KeyVersion,
    metadata_version: KeyVersion,
) -> Result<(), ResponseVersionMismatch> {
    if ciphertext_version.ct_eq(&metadata_version) {
        Ok(())
    } else {
        Err(ResponseVersionMismatch)
    }
}

/// 执行 Transit `sign`：`POST {base}/v1/{mount…}/sign/{key}`，header `X-Vault-Token`，请求级 `timeout`。
/// `base` 已在构造期校验 scheme（https / 显式 http）。`mount_segments`（构造期按 `/` 拆分校验）逐段 push、`key`
/// 单段 push——均经 `Url::path_segments_mut` percent-encode（杜绝路径段注入）。`token` / `message` 绝不进 span / 日志。
/// 请求固定发送 `marshaling_algorithm=jws`，响应签名固定按 URL-safe base64 解码。
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
    let payload = serde_json::to_vec(&build_sign_body(request.message.as_bytes()))
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
    parse_sign_response(&body)
}

#[tracing::instrument(
    name = "vault.transit.encrypt",
    skip_all,
    fields(resource = "vault", provider = "vault-transit", operation = "encrypt", key_name = key.as_str())
)]
pub(crate) async fn encrypt_impl(
    http: TransitHttp<'_>,
    key: KeyName,
    plaintext: Plaintext,
    aad: DerivedAad,
) -> Result<EncryptOutput, KeyProviderError> {
    let body = build_encrypt_body(&plaintext, &aad);
    let response =
        key_provider_request(http, KeyProviderOperation::Encrypt, key.as_str(), body).await?;
    parse_encrypt_response(&response, key)
}

#[tracing::instrument(
    name = "vault.transit.decrypt",
    skip_all,
    fields(
        resource = "vault",
        provider = "vault-transit",
        operation = "decrypt",
        key_name = key.name().as_str(),
        key_version = key.version().as_u32(),
        aad = ?aad.coordinates()
    )
)]
pub(crate) async fn decrypt_impl(
    http: TransitHttp<'_>,
    ciphertext: RedactedBytes,
    key: KeyRef,
    aad: DerivedAad,
) -> Result<Plaintext, KeyProviderError> {
    let (ciphertext, ciphertext_version) = ciphertext_to_str(&ciphertext)?;
    ensure_ciphertext_matches_key_version(&ciphertext_version, key.version())?;
    let body = build_decrypt_body(ciphertext, &aad);
    let response = key_provider_request(
        http,
        KeyProviderOperation::Decrypt,
        key.name().as_str(),
        body,
    )
    .await?;
    parse_decrypt_response(&response)
}

#[tracing::instrument(
    name = "vault.transit.rewrap",
    skip_all,
    fields(
        resource = "vault",
        provider = "vault-transit",
        operation = "rewrap",
        key_name = key.name().as_str(),
        old_key_version = key.version().as_u32()
    )
)]
pub(crate) async fn rewrap_impl(
    http: TransitHttp<'_>,
    ciphertext: RedactedBytes,
    key: KeyRef,
    aad: DerivedAad,
) -> Result<EncryptOutput, KeyProviderError> {
    let (ciphertext, ciphertext_version) = ciphertext_to_str(&ciphertext)?;
    ensure_ciphertext_matches_key_version(&ciphertext_version, key.version())?;
    let body = build_rewrap_body(ciphertext, &aad);
    let key_name = key.name().clone();
    let response = key_provider_request(
        http,
        KeyProviderOperation::Rewrap,
        key.name().as_str(),
        body,
    )
    .await?;
    parse_rewrap_response(&response, key_name)
}

async fn key_provider_request(
    http: TransitHttp<'_>,
    operation: KeyProviderOperation,
    key_name: &str,
    body: serde_json::Value,
) -> Result<Vec<u8>, KeyProviderError> {
    let url = http.endpoint_url(operation, key_name)?;
    let payload = serde_json::to_vec(&body).map_err(key_provider_unavailable)?;
    let response = http
        .client
        .post(url)
        .header(VAULT_TOKEN_HEADER, http.token)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .timeout(http.timeout)
        .body(payload)
        .send()
        .await
        .map_err(|e| key_provider_warn_and_wrap(OP_KEY_PROVIDER_SEND, operation, e))?;

    let status = response.status();
    if !status.is_success() {
        return Err(key_provider_status_error(operation, status.as_u16()));
    }

    response
        .bytes()
        .await
        .map(|body| body.to_vec())
        .map_err(|e| key_provider_warn_and_wrap(OP_KEY_PROVIDER_READ, operation, e))
}

fn key_provider_status_error(operation: KeyProviderOperation, code: u16) -> KeyProviderError {
    let (category, security_relevant) = classify_status(code);
    if security_relevant {
        log_key_provider_status_error(operation, code, category);
    } else {
        log_key_provider_status_warn(operation, code, category);
    }
    KeyProviderError::new(
        classify_key_provider_status(code),
        KeyProviderNonSuccessStatus(code),
    )
}

fn log_key_provider_status_error(operation: KeyProviderOperation, code: u16, category: &str) {
    tracing::error!(
        target: "vault",
        status = code,
        category,
        operation = operation.label(),
        "vault transit key provider returned non-success status"
    );
}

fn log_key_provider_status_warn(operation: KeyProviderOperation, code: u16, category: &str) {
    tracing::warn!(
        target: "vault",
        status = code,
        category,
        operation = operation.label(),
        "vault transit key provider returned non-success status"
    );
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

fn key_provider_warn_and_wrap(
    phase: &str,
    operation: KeyProviderOperation,
    err: reqwest::Error,
) -> KeyProviderError {
    let kind = if err.is_timeout() {
        KeyProviderErrorKind::Timeout
    } else {
        KeyProviderErrorKind::Unavailable
    };
    tracing::warn!(
        target: "vault",
        operation = operation.label(),
        phase = phase,
        category = classify_reqwest_error(&err),
        "vault transit key provider request failed"
    );
    KeyProviderError::new(kind, err)
}

fn key_provider_unavailable<E>(err: E) -> KeyProviderError
where
    E: std::error::Error + Send + Sync + 'static,
{
    KeyProviderError::new(KeyProviderErrorKind::Unavailable, err)
}

fn classify_key_provider_status(status: u16) -> KeyProviderErrorKind {
    match status {
        401 | 403 => KeyProviderErrorKind::Forbidden,
        404 => KeyProviderErrorKind::NotFound,
        408 => KeyProviderErrorKind::Timeout,
        429 => KeyProviderErrorKind::Unavailable,
        s if s >= 500 => KeyProviderErrorKind::Unavailable,
        _ => KeyProviderErrorKind::Rejected,
    }
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
    #![allow(clippy::expect_used)]

    use base64::Engine as _;
    use diport::KeyName;
    use diport::key_provider::KeyProviderErrorKind;
    use secure::{Plaintext, ProtectionContext};
    use vocab::tenant::TenantId;

    use super::{
        BASE64, BASE64_URL, build_decrypt_body, build_encrypt_body, build_rewrap_body,
        build_sign_body, parse_decrypt_response, parse_encrypt_response, parse_rewrap_response,
        parse_sign_response,
    };

    #[allow(clippy::expect_used)]
    fn sample_aad() -> secure::DerivedAad {
        let tenant =
            TenantId::parse("11111111-2222-4333-8444-555555555555").expect("canonical uuid");
        ProtectionContext::authenticated_request(tenant, "settings/db", "value", 7)
            .expect("valid protection context")
            .derive()
    }

    fn key_name() -> KeyName {
        KeyName::try_new("rss-field-key").expect("non-empty key")
    }

    fn assert_no_associated_data(body: &serde_json::Value) {
        assert!(
            body.get("associated_data").is_none(),
            "Vault KeyProvider must use context, not associated_data: {body}"
        );
    }

    #[test]
    fn build_sign_body_base64_encodes_input() {
        // base64("payload") == "cGF5bG9hZA=="（STANDARD，含 padding）。input 始终 STANDARD base64。
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
        // 签名消息可以包含任意二进制字节；Vault input 始终使用 STANDARD base64。
        let message: &[u8] = &[0x00, 0xFF, 0xAB];
        let expected = BASE64.encode(message); // 锚定期望 = 同一 STANDARD 引擎输出（"AP+r"）。
        assert_eq!(expected, "AP+r");
        assert_eq!(
            build_sign_body(message)["input"].as_str(),
            Some(expected.as_str())
        );
    }

    #[test]
    fn build_sign_body_includes_jws_marshaling() {
        let body = build_sign_body(b"msg");
        assert_eq!(
            body["marshaling_algorithm"].as_str(),
            Some("jws"),
            "Jws marshaling must send marshaling_algorithm=jws"
        );
    }

    #[test]
    fn build_sign_body_jws_input_is_still_standard_base64() {
        // JWS 模式下 input 仍为 STANDARD base64；只有响应签名段使用 URL-safe base64。
        let message: &[u8] = &[0xFB]; // STANDARD: "+w=="; URL_SAFE: "-w"。
        let body = build_sign_body(message);
        assert_eq!(
            body["input"].as_str(),
            Some("+w=="),
            "Vault sign input must use STANDARD base64"
        );
        assert_eq!(body["marshaling_algorithm"].as_str(), Some("jws"));
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
    fn parse_jws_decodes_url_safe_base64() {
        // anti-vacuity：0xFB 在 STANDARD base64 编码为 "+w=="，在 URL_SAFE（无 padding）编码为 "-w"。
        // `vault:v1:-w` 经固定 JWS 路径（BASE64_URL）解码 → [0xFB]。
        let url_safe_b64 = BASE64_URL.encode([0xFB_u8]); // "-w"（URL_SAFE，无 padding）
        assert_eq!(
            url_safe_b64, "-w",
            "0xFB must encode to '-w' in url-safe no-pad base64"
        );
        let body_str = format!(r#"{{"data":{{"signature":"vault:v1:{url_safe_b64}"}}}}"#);
        // Jws 路径：成功 decode → [0xFB]
        assert!(
            matches!(
                parse_sign_response(body_str.as_bytes()),
                Ok(sig) if sig.as_bytes() == [0xFB_u8]
            ),
            "Jws path must decode url-safe base64 '-w' to [0xFB]"
        );
        // anti-vacuity：相同值不能由 STANDARD base64 解码，证明使用了 URL-safe 引擎。
        assert!(
            BASE64.decode(url_safe_b64).is_err(),
            "STANDARD base64 must reject the URL-safe '-' character"
        );
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

    #[test]
    fn build_encrypt_body_uses_context_and_no_associated_data() {
        let aad = sample_aad();
        let plaintext = Plaintext::new(b"payload".to_vec());
        let body = build_encrypt_body(&plaintext, &aad);
        assert_eq!(body["plaintext"].as_str(), Some("cGF5bG9hZA=="));
        assert_eq!(
            body["context"].as_str(),
            Some(BASE64.encode(aad.as_canonical_bytes()).as_str())
        );
        assert_eq!(body["key_version"].as_u64(), Some(0));
        assert_no_associated_data(&body);
    }

    #[test]
    fn build_decrypt_body_uses_context_and_no_associated_data() {
        let aad = sample_aad();
        let body = build_decrypt_body("vault:v1:Y2lwaGVy", &aad);
        assert_eq!(body["ciphertext"].as_str(), Some("vault:v1:Y2lwaGVy"));
        assert_eq!(
            body["context"].as_str(),
            Some(BASE64.encode(aad.as_canonical_bytes()).as_str())
        );
        assert!(
            body.get("key_version").is_none(),
            "decrypt must rely on vault:vN + stored KeyRef, not override key_version"
        );
        assert_no_associated_data(&body);
    }

    #[test]
    fn build_rewrap_body_uses_context_and_no_associated_data() {
        let aad = sample_aad();
        let body = build_rewrap_body("vault:v1:Y2lwaGVy", &aad);
        assert_eq!(body["ciphertext"].as_str(), Some("vault:v1:Y2lwaGVy"));
        assert_eq!(
            body["context"].as_str(),
            Some(BASE64.encode(aad.as_canonical_bytes()).as_str())
        );
        assert_eq!(body["key_version"].as_u64(), Some(0));
        assert_no_associated_data(&body);
    }

    #[test]
    fn parse_encrypt_response_extracts_ciphertext_and_key_version() {
        let body = br#"{"data":{"ciphertext":"vault:v3:Y2lwaGVy","key_version":3}}"#;
        let out = parse_encrypt_response(body, key_name()).expect("valid response");
        assert_eq!(out.ciphertext(), b"vault:v3:Y2lwaGVy");
        assert_eq!(out.key().version().as_u32(), 3);
        assert_eq!(out.key().name().as_str(), "rss-field-key");
    }

    #[test]
    fn parse_rewrap_response_extracts_ciphertext_and_key_version() {
        let body = br#"{"data":{"ciphertext":"vault:v4:cmV3cmFwcGVk","key_version":4}}"#;
        let out = parse_rewrap_response(body, key_name()).expect("valid response");
        assert_eq!(out.ciphertext(), b"vault:v4:cmV3cmFwcGVk");
        assert_eq!(out.key().version().as_u32(), 4);
    }

    #[test]
    fn parse_encrypt_response_rejects_ciphertext_and_metadata_version_mismatch() {
        let body = br#"{"data":{"ciphertext":"vault:v7:Y2lwaGVy","key_version":8}}"#;
        let err = parse_encrypt_response(body, key_name()).expect_err("mismatched versions fail");
        assert_eq!(err.kind(), KeyProviderErrorKind::Unavailable);
        assert_eq!(err.to_string(), "key provider operation failed");
    }

    #[test]
    fn parse_decrypt_response_decodes_plaintext() {
        let body = br#"{"data":{"plaintext":"cGxhaW4="}}"#;
        let plaintext = parse_decrypt_response(body).expect("valid response");
        assert_eq!(plaintext.expose(), b"plain");
        assert!(!format!("{plaintext:?}").contains("plain"));
    }

    #[test]
    fn parse_key_provider_responses_reject_malformed_shapes() {
        let cases: &[&[u8]] = &[
            br#"{"data":null}"#,
            br#"{"errors":["permission denied"]}"#,
            br#"{"data":{}}"#,
            br#"{"data":{"ciphertext":"not-vault","key_version":1}}"#,
            br#"{"data":{"ciphertext":"vault:vX:Y2lwaGVy","key_version":1}}"#,
            br#"{"data":{"ciphertext":"vault:v1:!!!","key_version":1}}"#,
            br#"not json"#,
        ];
        for body in cases {
            let err = parse_encrypt_response(body, key_name()).expect_err("malformed response");
            assert_eq!(err.kind(), KeyProviderErrorKind::Unavailable);
            assert_eq!(err.to_string(), "key provider operation failed");
        }
        assert!(parse_decrypt_response(br#"{"data":{}}"#).is_err());
        assert!(parse_decrypt_response(br#"{"data":{"plaintext":"!!!"}}"#).is_err());
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

    // 固定 mount=["transit"] + timeout=200ms 调 sign_impl（直接传 http base Url；scheme 校验在 profile-specific VaultSigner 构造器，
    // 非 sign_impl 职责，故无需构造 VaultSigner）。OK_BODY 的值同时是合法 base64url，解码为 "rawsig"。
    async fn call(server: &MockServer, key: &str) -> Result<Signature, SignerError> {
        sign_impl(
            &reqwest::Client::new(),
            &base_url(server),
            TOKEN,
            &["transit".to_string()],
            Duration::from_millis(200),
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
            sign_request("k"),
        )
        .await;
        assert!(result.is_err());
    }
}

#[cfg(all(test, feature = "backend"))]
mod key_provider_impl_tests {
    //! KeyProvider HTTP 编排层测试：wiremock loopback + reqwest 真请求，覆盖路径分段、token header、
    //! AAD→context 单一 funnel、禁止 associated_data、非 2xx kind 映射。
    #![allow(clippy::expect_used)]

    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::Duration;

    use base64::Engine as _;
    use diport::key_provider::KeyProviderErrorKind;
    use diport::{KeyName, KeyRef, KeyVersion, RedactedBytes};
    use secure::{DerivedAad, Plaintext, ProtectionContext};
    use tracing::field::{Field, Visit};
    use tracing::span::Attributes;
    use tracing_subscriber::layer::{Context as LayerContext, Layer};
    use tracing_subscriber::prelude::*;
    use vocab::tenant::TenantId;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::{BASE64, TransitHttp, decrypt_impl, encrypt_impl, rewrap_impl};

    const TOKEN: &str = "test-token";

    #[allow(clippy::expect_used)]
    fn base_url(server: &MockServer) -> reqwest::Url {
        reqwest::Url::parse(&server.uri()).expect("mock server uri is a valid base url")
    }

    #[allow(clippy::expect_used)]
    fn key_name(raw: &str) -> KeyName {
        KeyName::try_new(raw).expect("non-empty key")
    }

    #[allow(clippy::expect_used)]
    fn key_ref(raw: &str, version: u32) -> KeyRef {
        KeyRef::new(key_name(raw), KeyVersion::new(version))
    }

    #[allow(clippy::expect_used)]
    fn aad(key: &str, field: &str, version: u32) -> DerivedAad {
        let tenant =
            TenantId::parse("11111111-2222-4333-8444-555555555555").expect("canonical uuid");
        ProtectionContext::authenticated_request(tenant, key, field, version)
            .expect("valid protection context")
            .derive()
    }

    #[allow(clippy::expect_used)]
    async fn single_request(server: &MockServer) -> wiremock::Request {
        let mut reqs = server
            .received_requests()
            .await
            .expect("wiremock request recording enabled by default");
        assert_eq!(reqs.len(), 1, "exactly one request expected");
        reqs.remove(0)
    }

    #[allow(clippy::expect_used)]
    fn request_json(req: &wiremock::Request) -> serde_json::Value {
        serde_json::from_slice(&req.body).expect("request body is json")
    }

    #[derive(Clone, Default)]
    struct SpanFieldRecorder {
        records: Arc<Mutex<Vec<String>>>,
    }

    impl SpanFieldRecorder {
        #[allow(clippy::expect_used)]
        fn records(&self) -> Vec<String> {
            self.records
                .lock()
                .expect("span field recorder mutex is not poisoned")
                .clone()
        }

        #[allow(clippy::expect_used)]
        fn clear(&self) {
            self.records
                .lock()
                .expect("span field recorder mutex is not poisoned")
                .clear();
        }
    }

    impl<S> Layer<S> for SpanFieldRecorder
    where
        S: tracing::Subscriber,
    {
        #[allow(clippy::expect_used)]
        fn on_new_span(
            &self,
            attrs: &Attributes<'_>,
            _id: &tracing::Id,
            _ctx: LayerContext<'_, S>,
        ) {
            let mut visitor = FieldRecorder::default();
            attrs.record(&mut visitor);
            let mut fields = vec![format!("name={}", attrs.metadata().name())];
            fields.extend(visitor.fields);
            self.records
                .lock()
                .expect("span field recorder mutex is not poisoned")
                .push(fields.join(" "));
        }
    }

    fn global_span_recorder() -> &'static SpanFieldRecorder {
        static RECORDER: OnceLock<SpanFieldRecorder> = OnceLock::new();
        RECORDER.get_or_init(|| {
            let recorder = SpanFieldRecorder::default();
            let subscriber = tracing_subscriber::registry().with(recorder.clone());
            let _ = tracing::subscriber::set_global_default(subscriber);
            recorder
        })
    }

    #[derive(Default)]
    struct FieldRecorder {
        fields: Vec<String>,
    }

    impl Visit for FieldRecorder {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.fields.push(format!("{}={value:?}", field.name()));
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            self.fields.push(format!("{}={value}", field.name()));
        }

        fn record_u64(&mut self, field: &Field, value: u64) {
            self.fields.push(format!("{}={value}", field.name()));
        }

        fn record_i64(&mut self, field: &Field, value: i64) {
            self.fields.push(format!("{}={value}", field.name()));
        }

        fn record_bool(&mut self, field: &Field, value: bool) {
            self.fields.push(format!("{}={value}", field.name()));
        }
    }

    #[tokio::test]
    async fn encrypt_sends_context_not_associated_data_and_encodes_key_path() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(
                    r#"{"data":{"ciphertext":"vault:v7:Y2lwaGVy","key_version":7}}"#,
                ),
            )
            .mount(&server)
            .await;
        let aad = aad("settings/db", "value", 7);
        let client = reqwest::Client::new();
        let base = base_url(&server);
        let mount = ["team".to_string(), "transit".to_string()];
        let out = encrypt_impl(
            TransitHttp::new(&client, &base, TOKEN, &mount, Duration::from_secs(5)),
            key_name("../field-key"),
            Plaintext::new(b"secret-value".to_vec()),
            aad.clone(),
        )
        .await
        .expect("encrypt ok");
        assert_eq!(out.ciphertext(), b"vault:v7:Y2lwaGVy");
        assert_eq!(out.key().version().as_u32(), 7);

        let req = single_request(&server).await;
        assert_eq!(req.url.path(), "/v1/team/transit/encrypt/..%2Ffield-key");
        assert_eq!(
            req.headers
                .get("X-Vault-Token")
                .and_then(|v| v.to_str().ok()),
            Some(TOKEN)
        );
        let body = request_json(&req);
        assert_eq!(body["plaintext"].as_str(), Some("c2VjcmV0LXZhbHVl"));
        assert_eq!(
            body["context"].as_str(),
            Some(BASE64.encode(aad.as_canonical_bytes()).as_str())
        );
        assert_eq!(body["key_version"].as_u64(), Some(0));
        assert!(body.get("associated_data").is_none());
    }

    #[allow(clippy::expect_used)]
    #[tokio::test]
    async fn decrypt_sends_context_and_returns_plaintext() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r#"{"data":{"plaintext":"cGxhaW4="}}"#),
            )
            .mount(&server)
            .await;
        let aad = aad("settings/db", "value", 7);
        let client = reqwest::Client::new();
        let base = base_url(&server);
        let mount = ["transit".to_string()];
        let plaintext = decrypt_impl(
            TransitHttp::new(&client, &base, TOKEN, &mount, Duration::from_secs(5)),
            RedactedBytes::new(b"vault:v7:Y2lwaGVy".to_vec()),
            key_ref("field-key", 7),
            aad.clone(),
        )
        .await
        .expect("decrypt ok");
        assert_eq!(plaintext.expose(), b"plain");

        let req = single_request(&server).await;
        assert_eq!(req.url.path(), "/v1/transit/decrypt/field-key");
        let body = request_json(&req);
        assert_eq!(body["ciphertext"].as_str(), Some("vault:v7:Y2lwaGVy"));
        assert_eq!(
            body["context"].as_str(),
            Some(BASE64.encode(aad.as_canonical_bytes()).as_str())
        );
        assert!(
            body.get("key_version").is_none(),
            "decrypt must not pin latest or override the ciphertext's previous-read version"
        );
        assert!(body.get("associated_data").is_none());
    }

    #[allow(clippy::expect_used)]
    #[tokio::test]
    async fn decrypt_span_records_aad_coordinates() {
        let recorder = global_span_recorder();
        recorder.clear();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_string(r#"{"errors":["x"]}"#))
            .mount(&server)
            .await;
        let client = reqwest::Client::new();
        let base = base_url(&server);
        let mount = ["transit".to_string()];
        let err = decrypt_impl(
            TransitHttp::new(&client, &base, TOKEN, &mount, Duration::from_secs(5)),
            RedactedBytes::new(b"vault:v7:Y2lwaGVy".to_vec()),
            key_ref("field-key", 7),
            aad("settings/db", "value", 7),
        )
        .await
        .expect_err("mocked Vault rejection should fail");
        assert_eq!(err.kind(), KeyProviderErrorKind::Rejected);

        let records = recorder.records().join("\n");
        assert!(
            records.contains("name=vault.transit.decrypt"),
            "decrypt span must be emitted: {records}"
        );
        assert!(
            records.contains("aad=ProtectionAad"),
            "decrypt span must include aad.coordinates(): {records}"
        );
        assert!(
            records.contains("settings/db") && records.contains("value"),
            "decrypt span must include AAD coordinate dimensions: {records}"
        );
    }

    #[allow(clippy::expect_used)]
    #[tokio::test]
    async fn rewrap_sends_context_and_returns_new_key_version_without_plaintext() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"ciphertext":"vault:v8:cmV3cmFwcGVk","key_version":8}}"#,
            ))
            .mount(&server)
            .await;
        let aad = aad("settings/db", "value", 7);
        let client = reqwest::Client::new();
        let base = base_url(&server);
        let mount = ["transit".to_string()];
        let out = rewrap_impl(
            TransitHttp::new(&client, &base, TOKEN, &mount, Duration::from_secs(5)),
            RedactedBytes::new(b"vault:v7:Y2lwaGVy".to_vec()),
            key_ref("field-key", 7),
            aad,
        )
        .await
        .expect("rewrap ok");
        assert_eq!(out.ciphertext(), b"vault:v8:cmV3cmFwcGVk");
        assert_eq!(out.key().version().as_u32(), 8);

        let req = single_request(&server).await;
        assert_eq!(req.url.path(), "/v1/transit/rewrap/field-key");
        let body = request_json(&req);
        assert_eq!(body["ciphertext"].as_str(), Some("vault:v7:Y2lwaGVy"));
        assert!(
            body.get("plaintext").is_none(),
            "rewrap must not send plaintext"
        );
        assert_eq!(body["key_version"].as_u64(), Some(0));
        assert!(body.get("associated_data").is_none());
    }

    #[tokio::test]
    async fn decrypt_and_rewrap_reject_key_version_mismatch_before_network() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let client = reqwest::Client::new();
        let base = base_url(&server);
        let mount = ["transit".to_string()];
        let decrypt_err = decrypt_impl(
            TransitHttp::new(&client, &base, TOKEN, &mount, Duration::from_secs(5)),
            RedactedBytes::new(b"vault:v6:Y2lwaGVy".to_vec()),
            key_ref("field-key", 7),
            aad("settings/db", "value", 7),
        )
        .await
        .expect_err("ciphertext/key version mismatch must fail");
        assert_eq!(decrypt_err.kind(), KeyProviderErrorKind::Rejected);

        let rewrap_err = rewrap_impl(
            TransitHttp::new(&client, &base, TOKEN, &mount, Duration::from_secs(5)),
            RedactedBytes::new(b"vault:v6:Y2lwaGVy".to_vec()),
            key_ref("field-key", 7),
            aad("settings/db", "value", 7),
        )
        .await
        .expect_err("ciphertext/key version mismatch must fail");
        assert_eq!(rewrap_err.kind(), KeyProviderErrorKind::Rejected);

        let reqs = server.received_requests().await.unwrap_or_default();
        assert_eq!(
            reqs.len(),
            0,
            "version mismatch must not hit Vault before fail-closed"
        );
    }

    #[tokio::test]
    async fn decrypt_non_success_statuses_map_to_key_provider_kinds() {
        let cases = [
            (400u16, KeyProviderErrorKind::Rejected),
            (401, KeyProviderErrorKind::Forbidden),
            (403, KeyProviderErrorKind::Forbidden),
            (404, KeyProviderErrorKind::NotFound),
            (408, KeyProviderErrorKind::Timeout),
            (429, KeyProviderErrorKind::Unavailable),
            (500, KeyProviderErrorKind::Unavailable),
        ];
        for (status, kind) in cases {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(status).set_body_string(r#"{"errors":["x"]}"#))
                .mount(&server)
                .await;
            let client = reqwest::Client::new();
            let base = base_url(&server);
            let mount = ["transit".to_string()];
            let err = decrypt_impl(
                TransitHttp::new(&client, &base, TOKEN, &mount, Duration::from_secs(5)),
                RedactedBytes::new(b"vault:v7:Y2lwaGVy".to_vec()),
                key_ref("field-key", 7),
                aad("settings/db", "value", 7),
            )
            .await
            .expect_err("non-success must fail");
            assert_eq!(err.kind(), kind, "status {status}");
            assert_eq!(err.to_string(), "key provider operation failed");
        }
    }

    #[tokio::test]
    async fn decrypt_after_previous_key_disabled_maps_to_rejected_without_detail() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_string(r#"{"errors":["ciphertext or key version is disallowed"]}"#),
            )
            .mount(&server)
            .await;
        let client = reqwest::Client::new();
        let base = base_url(&server);
        let mount = ["transit".to_string()];
        let err = decrypt_impl(
            TransitHttp::new(&client, &base, TOKEN, &mount, Duration::from_secs(5)),
            RedactedBytes::new(b"vault:v6:Y2lwaGVy".to_vec()),
            key_ref("field-key", 6),
            aad("settings/db", "value", 7),
        )
        .await
        .expect_err("Vault min_decryption_version should close the previous-read window");

        assert_eq!(err.kind(), KeyProviderErrorKind::Rejected);
        assert_eq!(err.to_string(), "key provider operation failed");
        assert!(
            !format!("{err:?}").contains("disallowed"),
            "Vault error body must not leak through KeyProviderError Debug"
        );
    }

    #[tokio::test]
    async fn decrypt_rejects_non_vault_ciphertext_before_network() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let client = reqwest::Client::new();
        let base = base_url(&server);
        let mount = ["transit".to_string()];
        let err = decrypt_impl(
            TransitHttp::new(&client, &base, TOKEN, &mount, Duration::from_secs(5)),
            RedactedBytes::new(b"not-vault".to_vec()),
            key_ref("field-key", 7),
            aad("settings/db", "value", 7),
        )
        .await
        .expect_err("malformed ciphertext must fail");
        assert_eq!(err.kind(), KeyProviderErrorKind::Rejected);
        let reqs = server.received_requests().await.unwrap_or_default();
        assert_eq!(reqs.len(), 0, "malformed ciphertext must not hit Vault");
    }
}
