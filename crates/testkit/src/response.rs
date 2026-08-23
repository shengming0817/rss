//! oneshot 收集后的契约响应 + 断言/解码 helper。

use axum::http::StatusCode;
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::TestkitError;

/// 完整收集的契约响应（状态码 + 全量 body 字节）。断言 helper 返回 `Result`（harness 不 panic），
/// 调用方在测试侧 `?` / `expect` 暴露。
#[derive(Debug, Clone)]
#[must_use]
pub struct ContractResponse {
    status: StatusCode,
    body: Vec<u8>,
}

impl ContractResponse {
    pub(crate) fn new(status: StatusCode, body: Vec<u8>) -> Self {
        Self { status, body }
    }

    /// HTTP 状态码。
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// 原始 body 字节。
    #[must_use]
    pub fn body_bytes(&self) -> &[u8] {
        &self.body
    }

    /// 反序列化 body 进 `T`。**典型传 generated wire 类型**（如 `IdentityLoginResponse`）做 schema 对齐
    /// 断言（#1136 验收「与 generated wire 类型对齐」）——序列化往返成立即证明响应形状匹配契约派生类型。
    pub fn json<T: DeserializeOwned>(&self) -> Result<T, TestkitError> {
        serde_json::from_slice(&self.body).map_err(TestkitError::Decode)
    }

    /// 解析统一 wire error envelope（`{"error":{"code","message","retryable","details","requestId"}}`，
    /// camelCase）。
    pub fn wire_error(&self) -> Result<WireError, TestkitError> {
        let env: ErrorEnvelope =
            serde_json::from_slice(&self.body).map_err(TestkitError::Decode)?;
        Ok(env.error)
    }

    /// 断言状态码；不匹配返回 [`TestkitError::Mismatch`]（含截断 body 便于定位）。返回 `&Self` 供链式。
    pub fn ensure_status(&self, expected: StatusCode) -> Result<&Self, TestkitError> {
        if self.status == expected {
            Ok(self)
        } else {
            Err(TestkitError::Mismatch(format!(
                "status {} != expected {}; body={}",
                self.status,
                expected,
                self.body_excerpt()
            )))
        }
    }

    /// 断言「状态码 + wire error code」（参数错误 / 鉴权边界维度）。返回 `&Self` 供链式。
    /// 不匹配的 [`TestkitError::Mismatch`] 同样附截断 body（与 [`Self::ensure_status`] 排障对称）。
    pub fn ensure_error(&self, status: StatusCode, code: &str) -> Result<&Self, TestkitError> {
        self.ensure_status(status)?;
        let err = self.wire_error()?;
        if err.code == code {
            Ok(self)
        } else {
            Err(TestkitError::Mismatch(format!(
                "error code {} != expected {}; body={}",
                err.code,
                code,
                self.body_excerpt()
            )))
        }
    }

    /// 断言失败排障用的 body 摘要：JSON body **递归脱敏敏感 key**（sessionId / token / authorization /
    /// password…）后序列化截断；非 JSON body 只示长度（不回显原文，整体可能即 token/凭据）。既够定位失败，
    /// 又不把 session/token 写进测试失败日志——测试诊断不绕过敏感值脱敏（安全：与仓库 redaction 取向一致）。
    fn body_excerpt(&self) -> String {
        match serde_json::from_slice::<serde_json::Value>(&self.body) {
            Ok(mut value) => {
                redact_sensitive(&mut value);
                truncate_excerpt(&value.to_string())
            }
            Err(_) => format!("<non-JSON body, {} bytes>", self.body.len()),
        }
    }
}

/// 断言失败信息里 body 摘要的字节上限（足够定位，避免全量 dump）。
const BODY_EXCERPT_LIMIT: usize = 512;

/// char-boundary 安全截断到 [`BODY_EXCERPT_LIMIT`]（裸字节切片在多字节字符中段会 panic——违反 harness 不 panic）。
fn truncate_excerpt(text: &str) -> String {
    if text.len() <= BODY_EXCERPT_LIMIT {
        return text.to_string();
    }
    let mut end = BODY_EXCERPT_LIMIT;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…<truncated {} bytes>", &text[..end], text.len())
}

/// 递归把敏感 key 的值替换为 `<redacted>`（不递归进被脱敏值）。防 sessionId / token / authorization 等进
/// 测试失败日志。over-redaction（如 `tokenCount`）在测试诊断里可接受——errs toward 不泄漏。
fn redact_sensitive(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map.iter_mut() {
                if is_sensitive_key(key) {
                    *val = serde_json::Value::String("<redacted>".to_string());
                } else {
                    redact_sensitive(val);
                }
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(redact_sensitive),
        _ => {}
    }
}

/// key 归一化（lowercase + 去 `_`/`-`）后是否含敏感子串。
fn is_sensitive_key(key: &str) -> bool {
    const SENSITIVE: &[&str] = &[
        "password",
        "token",
        "authorization",
        "bearer",
        "secret",
        "apikey",
        "cookie",
        "credential",
        "privatekey",
        "sessionid",
    ];
    let norm: String = key
        .chars()
        .filter(|c| *c != '_' && *c != '-')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    SENSITIVE.iter().any(|s| norm.contains(s))
}

/// 统一 wire error envelope 的 `error` 体。
///
/// 这是 testkit **测试侧 deserialize 镜像**——httpserve 的 serialize 侧 envelope 类型是私有的，
/// 测试断言只需 decode 形状（与 `httpserve/tests/runtime.rs` 直接索引 `json["error"]["code"]` 同精神）。
///
/// **严格镜像（契约对齐，不放宽）**：5 个字段 `code/message/retryable/details/requestId` 全 **required**（无
/// `serde(default)`）+ `deny_unknown_fields`——与 generated wire envelope 形状逐字段对齐。镜像比契约
/// 宽松（默认空值吞掉缺字段 / 容忍多余字段）会让域契约测试经 [`ContractResponse::ensure_error`] 漏测
/// envelope 形状回归：handler 漏 `message`/`details`/`requestId` 或多写字段时，反序列化即失败、`ensure_error`
/// 返回 `Err`（而非误绿）。anti-vacuity 见 `crates/testkit/tests/harness.rs` 的 incomplete/extra envelope 用例。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireError {
    /// 错误码（`ERR_*`）。
    pub code: String,
    /// 人读 message（const literal，无 PII）。
    pub message: String,
    /// 请求事实不变时客户端可否安全重试。
    pub retryable: bool,
    /// typed detail 列表（4xx 可下发；可空数组，但字段须在）。
    pub details: Vec<serde_json::Value>,
    /// 关联请求 id（框架注入）。
    #[serde(rename = "requestId")]
    pub request_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorEnvelope {
    error: WireError,
}
