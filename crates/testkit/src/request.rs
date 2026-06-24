//! 声明式契约请求 builder：method + uri + headers + body → `axum::http::Request<Body>`。

use axum::body::Body;
use axum::http::{Method, Request};
use serde::Serialize;

use crate::TestkitError;

/// JSON 媒体类型常量（content-type / accept；同义字符串重复，抽 const，rust-standards §工程护栏）。
const APPLICATION_JSON: &str = "application/json";
const CONTENT_TYPE: &str = "content-type";

/// 契约请求 builder。`json` / `raw_json` / `raw_body` 设 body（默认空 body）；header 透传 builder
/// 解析（非法名值在 [`Self::into_http`] 冒泡为 [`TestkitError::Build`]）。
#[derive(Debug)]
#[must_use = "ContractRequest 是 builder，需传给 testkit::call 才会发出"]
pub struct ContractRequest {
    method: Method,
    uri: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// [`Self::json`] 序列化失败时暂存，[`Self::into_http`] 冒泡（builder 链不返回 `Result`）。
    encode_error: Option<serde_json::Error>,
}

impl ContractRequest {
    fn new(method: Method, uri: impl Into<String>) -> Self {
        Self {
            method,
            uri: uri.into(),
            headers: Vec::new(),
            body: Vec::new(),
            encode_error: None,
        }
    }

    /// `GET <uri>`。
    pub fn get(uri: impl Into<String>) -> Self {
        Self::new(Method::GET, uri)
    }
    /// `POST <uri>`。
    pub fn post(uri: impl Into<String>) -> Self {
        Self::new(Method::POST, uri)
    }
    /// `PUT <uri>`。
    pub fn put(uri: impl Into<String>) -> Self {
        Self::new(Method::PUT, uri)
    }
    /// `PATCH <uri>`。
    pub fn patch(uri: impl Into<String>) -> Self {
        Self::new(Method::PATCH, uri)
    }
    /// `DELETE <uri>`。
    pub fn delete(uri: impl Into<String>) -> Self {
        Self::new(Method::DELETE, uri)
    }
    /// 任意 method `<method> <uri>`。
    pub fn method(method: Method, uri: impl Into<String>) -> Self {
        Self::new(method, uri)
    }

    /// 序列化 `body` 为 JSON 并设 `Content-Type: application/json`（正常请求路径）。
    pub fn json<T: Serialize>(mut self, body: &T) -> Self {
        match serde_json::to_vec(body) {
            Ok(bytes) => {
                self.body = bytes;
                self.headers
                    .push((CONTENT_TYPE.to_string(), APPLICATION_JSON.to_string()));
            }
            Err(e) => self.encode_error = Some(e),
        }
        self
    }

    /// 原样 JSON body（设 content-type，**不校验**合法性）——测「畸形 / 缺字段 body → 参数错误」用。
    pub fn raw_json(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self.headers
            .push((CONTENT_TYPE.to_string(), APPLICATION_JSON.to_string()));
        self
    }

    /// 原样字节 body（不设 content-type）。
    pub fn raw_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// 追加任意 header（名值经 `http` builder 解析，非法在 [`Self::into_http`] 冒泡）。
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// 设 `Authorization: Bearer <token>`（鉴权边界测试便捷入口）。
    pub fn bearer(self, token: &str) -> Self {
        self.header("authorization", format!("Bearer {token}"))
    }

    /// 组装为 `axum::http::Request<Body>`（序列化错误 / 非法 uri·header 冒泡为 [`TestkitError`]）。
    pub(crate) fn into_http(self) -> Result<Request<Body>, TestkitError> {
        if let Some(e) = self.encode_error {
            return Err(TestkitError::Encode(e));
        }
        let mut builder = Request::builder().method(self.method).uri(self.uri);
        for (name, value) in self.headers {
            builder = builder.header(name, value);
        }
        builder
            .body(Body::from(self.body))
            .map_err(|e| TestkitError::Build(e.to_string()))
    }
}
