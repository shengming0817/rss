//! aws-sdk-s3 操作映射（put / get / delete → `diport::ObjectStoreError`）。逻辑拆出 `lib.rs` 控制认知复杂度。
//!
//! 错误经 `rss_redact::redact_error` + `tracing::warn` 记录后包成不透明 [`ObjectStoreError`]（PII 边界：原始 SDK
//! 错误可能携 endpoint / bucket / 凭据签名，只进服务端日志且经脱敏，不入 wire——见 diport rustdoc）。**不**记录
//! 对象 key 原文（key 可能内嵌租户 / 用户标识，按 PII 保守处理；与 redis adapter 只记 `resource`/`operation` 一致）。

use aws_sdk_s3::Client;
use aws_sdk_s3::primitives::ByteStream;
use diport::{ObjectKey, ObjectPayload, ObjectStoreError};

/// 写入（覆盖）对象。S3 PUT 语义：已存在则覆盖。
pub(crate) async fn put_impl(
    client: &Client,
    bucket: &str,
    key: ObjectKey,
    body: Vec<u8>,
) -> Result<(), ObjectStoreError> {
    client
        .put_object()
        .bucket(bucket)
        .key(key.as_str())
        .body(ByteStream::from(body))
        .send()
        .await
        .map_err(|e| wrap("put", e))?;
    Ok(())
}

/// 读取对象。`NoSuchKey` → `Ok(None)`（不存在是正常态，非错误）；其余 SDK 错误 → `Err`。
///
/// **stream-first**：对象存在性 / 元数据由 GetObject 响应头先行解析（决定 `Some` / `None`），body 经
/// [`ObjectByteStream`](diport::ObjectByteStream) 逐块下行——**不**整对象一次性 `collect` 进内存（消除大对象
/// 内存风险）。消费域逐块处理或经 [`ObjectPayload::collect_limited`] 有界收集。aws `ByteStream` 经
/// [`futures::stream::unfold`] + 其 inherent `next()` 映射为 provider-agnostic 字节流。
pub(crate) async fn get_impl(
    client: &Client,
    bucket: &str,
    key: ObjectKey,
) -> Result<Option<ObjectPayload>, ObjectStoreError> {
    let output = match client
        .get_object()
        .bucket(bucket)
        .key(key.as_str())
        .send()
        .await
    {
        Ok(output) => output,
        Err(err) => {
            // NoSuchKey 是正常「不存在」，不是 provider 故障——映射为 Ok(None)。
            return match err.as_service_error() {
                Some(svc) if svc.is_no_such_key() => Ok(None),
                _ => Err(wrap("get", err)),
            };
        }
    };
    // 把 aws ByteStream 逐块映射为 ObjectByteStream（chunk → Vec<u8>，流内错误经 wrap 脱敏后冒泡）——
    // 不 collect 整对象进内存。
    let stream = futures::stream::unfold(output.body, |mut body| async move {
        match body.next().await {
            Some(Ok(chunk)) => Some((Ok(chunk.to_vec()), body)),
            Some(Err(err)) => Some((Err(wrap("get-stream", err)), body)),
            None => None,
        }
    });
    Ok(Some(ObjectPayload::new(Box::pin(stream))))
}

/// 删除对象。S3 DELETE **幂等**：删除不存在的对象返回 204，不报 404。
pub(crate) async fn delete_impl(
    client: &Client,
    bucket: &str,
    key: ObjectKey,
) -> Result<(), ObjectStoreError> {
    client
        .delete_object()
        .bucket(bucket)
        .key(key.as_str())
        .send()
        .await
        .map_err(|e| wrap("delete", e))?;
    Ok(())
}

/// 记录脱敏诊断后把 SDK 错误包成不透明 [`ObjectStoreError`]。`operation` 是闭值集低基数标签；
/// 错误经 `rss_redact::redact_error`（顶层 Display、不遍历 source 链）——不泄漏 endpoint / 凭据。
fn wrap<E>(operation: &str, err: E) -> ObjectStoreError
where
    E: std::error::Error + Send + Sync + 'static,
{
    tracing::warn!(
        target: "s3",
        resource = "s3",
        operation = operation,
        error = %rss_redact::redact_error(&err),
        "s3 object store operation failed"
    );
    ObjectStoreError::new(err)
}
