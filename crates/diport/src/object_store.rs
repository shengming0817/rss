//! `ObjectStore` —— 对象存储 provider DI port（可替换：aws-sdk-s3 / 未来 MinIO / GCS 等 S3-兼容后端）。
//!
//! provider-agnostic：bucket / endpoint / 凭据是 **adapter 构造配置**，不进 port——port 只认对象 key + 字节，
//! 故同一 port 可被任意 S3-兼容 provider 实现（与 cert-manager / SPIFFE 的 provider-agnostic 范式一致）。
//!
//! async 而非 sync：对象存储是网络 I/O；provider 互换要求统一最宽签名（与 [`crate::Signer`] /
//! 其它 async infrastructure ports 相同，区别于纯计算 helper。
//!
//! 读取 **stream-first**：[`ObjectStore::get_object`] 命中返回 [`ObjectPayload`]（provider 字节流），消费域逐块
//! 处理或经 [`ObjectPayload::collect_limited`] **显式有界**收集——port 不再固化「整对象进 `Vec<u8>`」，从类型层
//! 杜绝大对象一次性内存分配（对标 AWS SDK `ByteStream`、Apache `object_store::GetResult`：stream first，
//! collect opt-in）。
//!
//! 对标：**port 形状**照 [`crate::signer`] / [`crate::rate_limiter`]（ADR-003 dynosaur Send-变体范式，本 crate
//! 的 async DI port 单一对标）；**S3 操作语义**落地见 `adapters/s3`（aws-sdk-s3 `ref:` 在该 crate）。

use std::pin::Pin;

use dynosaur::dynosaur;
use futures::Stream;

use rss_redact::RedactedSource;

/// 对象存储操作失败。
///
/// PII 边界（**类型层 Hard**，与 [`crate::SignerError`] / [`crate::RateLimitError`] 同范式）：`Backend` 变体的
/// `source`（S3 provider 错误，可能携 endpoint / bucket / 凭据签名细节）经 [`RedactedSource`] 脱敏（`Debug`/`Display`
/// 固定 `<redacted>`、`Error::source()` 恒 `None`——原始错误不经任何 `Error` 接口暴露，fail-closed），`derive(Debug)`
/// 即安全。`Display` 仅 provider 无关安全摘要常量。`LimitExceeded` 的 `max_bytes` 是消费域设定的配置上界、**非 PII**，可观测。
/// 需要 source 诊断时走统一脱敏 funnel `rss_redact::redact_error`（顶层 `Display`、不遍历 source 链），**不**裸 `.source()`。
///
/// INVARIANT: DIPORT-ERR-SOURCE-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（source 经 `RedactedSource` 不暴露原始错误；回归见 `error_redaction` 单测）。
#[derive(Debug, thiserror::Error)]
pub enum ObjectStoreError {
    /// provider 后端故障（不可用 / 权限 / 网络等）。原始错误内部保留，不进 `Display` / wire / source 链。
    #[error("object store operation failed")]
    Backend {
        #[source]
        source: RedactedSource,
    },
    /// 对象字节超过 [`ObjectPayload::collect_limited`] 的有界上限——消费域据此拒绝过大对象（避免一次性内存
    /// 分配）。`max_bytes` 是配置上界、**非 PII**，安全可观测。
    #[error("object exceeds collect limit of {max_bytes} bytes")]
    LimitExceeded {
        /// 触发拒绝的字节上界（消费域配置值）。
        max_bytes: usize,
    },
}

impl ObjectStoreError {
    /// 把 adapter 内部错误包成 provider 后端故障（[`Self::Backend`]）。原始错误仅 owned 保留，不经任何
    /// `Error` 接口暴露（PII 边界）。
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Backend {
            source: RedactedSource::new(source),
        }
    }
}

/// 对象 key——配置 bucket 内的对象路径标识。newtype funnel（私有字段，单一构造入口），不裸传 `&str`。
/// opaque：key 命名 / 前缀策略随消费域派生，不在 DI-infra 层冻结。bucket **不**在此（是 adapter 构造配置）。
///
/// PII 边界（**类型层 Hard**，对标 [`crate::Message`] 的 `payload` / [`ObjectStoreError`]）：key 可能内嵌租户 /
/// 用户标识，`#[derive(rss_redact::Redact)]` 只输出 `ObjectKey(<redacted>)`，使任意消费方的 `?key` /
/// `{key:?}` 不泄漏原文（把 adapter 侧「不记录 key 原文」的 Soft 约定上移为通用类型层保证）。
/// INVARIANT: DIPORT-OBJECTKEY-DEBUG-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（回归见 `smoke::object_key_debug_redacts`）。
///
/// `Clone`：dynosaur `dyn(box)` 派发要求方法签名无生命周期参数，故 key 取所有权 move 进各操作。
#[derive(Clone, PartialEq, Eq, Hash, rss_redact::Redact)]
pub struct ObjectKey(#[redact(sensitivity = pii)] String);

impl ObjectKey {
    /// 由字符串构造对象 key。
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }
    /// 借出底层 key。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 对象字节流（chunked）——[`ObjectStore::get_object`] 命中时的 payload 载体。stream-first（对标 AWS SDK
/// `ByteStream` / Apache `object_store::GetResult.payload`）：provider 逐块下行，消费域逐块处理或经
/// [`ObjectPayload::collect_limited`] **显式有界**收集，**不**默认整对象进内存（消除大对象一次性分配风险）。
/// `Send`（非 `Sync`）：与其它 dynosaur Send DI port 返回流（[`crate::MessageStream`]）同形。
pub type ObjectByteStream = Pin<Box<dyn Stream<Item = Result<Vec<u8>, ObjectStoreError>> + Send>>;

/// [`ObjectStore::get_object`] 命中时的对象 payload（stream-first）。持有 provider 的字节流；消费域逐块读
/// （[`Self::into_stream`]）或经 [`Self::collect_limited`] 有界收集。**无**无界 collect——内存化只经显式上界
/// 路径，避免重新引入「整对象进 `Vec<u8>`」的内存风险（类型层 Hard：无返回 `Vec<u8>` 的便利方法）。
pub struct ObjectPayload {
    stream: ObjectByteStream,
}

impl ObjectPayload {
    /// 由 provider 字节流构造（adapter 侧）。
    pub fn new(stream: ObjectByteStream) -> Self {
        Self { stream }
    }

    /// 取出底层字节流逐块消费（流式路径，无内存上界——由消费方自行逐块处理）。
    pub fn into_stream(self) -> ObjectByteStream {
        self.stream
    }

    /// **有界**收集全部字节到内存：累积超过 `max_bytes` 即 [`ObjectStoreError::LimitExceeded`]（不静默截断、
    /// 不无界分配）。这是唯一的内存化便利路径（collect opt-in）；不设上界的逐块处理走 [`Self::into_stream`]。
    /// `max_bytes` 由消费域配置决定（DI-infra 层不预设业务上界）。
    pub async fn collect_limited(mut self, max_bytes: usize) -> Result<Vec<u8>, ObjectStoreError> {
        use futures::StreamExt;
        let mut buf = Vec::new();
        while let Some(chunk) = self.stream.next().await {
            let chunk = chunk?;
            if buf.len() + chunk.len() > max_bytes {
                return Err(ObjectStoreError::LimitExceeded { max_bytes });
            }
            buf.extend_from_slice(&chunk);
        }
        Ok(buf)
    }
}

/// 对象存储 provider DI port（async）。
///
/// 公开 [`ObjectStore`] 是 **Send 变体**（adapters `impl ObjectStore for ...`），[`DynObjectStore`] 是其
/// dyn-compatible wrapper（组合根经 `Box<DynObjectStore>` / `Arc<DynObjectStore>` 注入）。非 Send 基 trait
/// `ObjectStoreLocal` 不在 crate 根 re-export（见 crate rustdoc）。
///
/// dyn-safe 约束（ADR-003 §4.6）：方法 `&self`、参数 / 返回为具体类型（owned，无生命周期参数）、supertrait
/// 仅 Send、带 `async fn shutdown`（无 async Drop）。
#[trait_variant::make(ObjectStore: Send)]
#[dynosaur(pub DynObjectStore = dyn(box) ObjectStore, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `ObjectStore` 变体 +
// dynosaur `DynObjectStore` 承载（DI 注入走 Send wrapper）。这是 ADR-003 既定 dyn-port 范式。
pub trait ObjectStoreLocal {
    /// 写入（覆盖）对象。`key` 与 `body` 取**所有权**（async DI port 经 dynosaur `dyn(box)` 派发，dyn-compatible
    /// 要求方法签名无生命周期参数——引用参数会引入 `'_`，破坏 wrapper 生成；与 [`crate::Signer::sign`] 同范式）。
    /// 已存在则覆盖（S3 PUT 语义）。
    ///
    /// `body` 是**全量内存字节**——上传字节由消费域已持有（其自身内存），故 port 不对 put body 设上界。读取侧
    /// （[`Self::get_object`]）是 stream-first 以避免下行大对象一次性分配，二者不对称是因「上传字节归调用方所有、
    /// 下载字节由 port 分配」语义不同。
    async fn put_object(&self, key: ObjectKey, body: Vec<u8>) -> Result<(), ObjectStoreError>;

    /// 读取对象。`Ok(Some(payload))`=命中（payload 是 **stream-first** 字节流——消费域逐块读或经
    /// [`ObjectPayload::collect_limited`] 有界收集，**不**整对象进内存）；`Ok(None)`=对象不存在（**正常态**，
    /// 非错误，对标 S3 `NoSuchKey`）；`Err`=provider 后端故障。对标 AWS SDK `ByteStream` / Apache
    /// `object_store::GetResult`（stream first，collect opt-in）。
    async fn get_object(&self, key: ObjectKey) -> Result<Option<ObjectPayload>, ObjectStoreError>;

    /// 删除对象。**幂等**：删除不存在的对象返回 `Ok(())`（对标 S3 DELETE 语义，幂等不报 404）。
    async fn delete_object(&self, key: ObjectKey) -> Result<(), ObjectStoreError>;

    /// 异步释放 provider 资源（无 async Drop）。有 infra 资源的 adapter 应**同时** `impl ManagedResource`
    /// 由 `rss_runtime::ShutdownStack` 统一编排；本方法是 port-local 关闭路径（参 [`crate::Signer::shutdown`]）。
    async fn shutdown(&self) -> Result<(), ObjectStoreError>;
}

#[cfg(test)]
mod smoke {
    //! build smoke：证明 async DI port 可 native AFIT impl + 经 `Box<DynObjectStore>` 动态注入，
    //! 且 mockall mock（native-AFIT）可装入 `DynObjectStore` 跨 spawn（与 `rate_limiter.rs` 对称）。
    //! 另覆盖 [`ObjectPayload::collect_limited`] 的有界 / 超限 / 错误传播行为（stream-first 读取契约）。
    use super::{DynObjectStore, ObjectKey, ObjectPayload, ObjectStore, ObjectStoreError};

    fn _assert_redact<T: rss_redact::Redact>() {}

    fn obj_stream(bytes: &'static [u8]) -> ObjectPayload {
        ObjectPayload::new(Box::pin(futures::stream::once(async move {
            Ok::<Vec<u8>, ObjectStoreError>(bytes.to_vec())
        })))
    }

    struct InMem;
    impl ObjectStore for InMem {
        async fn put_object(
            &self,
            _key: ObjectKey,
            _body: Vec<u8>,
        ) -> Result<(), ObjectStoreError> {
            Ok(())
        }
        async fn get_object(
            &self,
            _key: ObjectKey,
        ) -> Result<Option<ObjectPayload>, ObjectStoreError> {
            Ok(Some(obj_stream(b"obj")))
        }
        async fn delete_object(&self, _key: ObjectKey) -> Result<(), ObjectStoreError> {
            Ok(())
        }
        async fn shutdown(&self) -> Result<(), ObjectStoreError> {
            Ok(())
        }
    }

    // multi_thread + spawn：boxed future 须 Send（trait_variant Send 变体）才能跨 worker 调度——
    // current-thread 不暴露 Send 违规，故用 multi_thread 真正验证 dyn 注入的 Send 语义。
    #[tokio::test(flavor = "multi_thread")]
    async fn object_store_is_dyn_injectable() {
        let store: Box<DynObjectStore> = DynObjectStore::new_box(InMem);
        let joined = tokio::spawn(async move {
            store
                .put_object(ObjectKey::new("k"), b"v".to_vec())
                .await
                .is_ok()
                && matches!(store.get_object(ObjectKey::new("k")).await, Ok(Some(_)))
                && store.delete_object(ObjectKey::new("k")).await.is_ok()
                && store.shutdown().await.is_ok()
        })
        .await;
        assert!(matches!(joined, Ok(true)));
    }

    // 与 rate_limiter.rs:mockall_mock_loads_into_dyn_rate_limiter 对称：mockall mock 是 native-AFIT trait
    // impl，可经 `new_box` 装入 dynosaur Send 变体 `DynObjectStore` 并跨 spawn（Send future）——
    // 预验证消费侧单测可 mock 本 port。
    mockall::mock! {
        TestObjectStore {}
        impl ObjectStore for TestObjectStore {
            async fn put_object(&self, key: ObjectKey, body: Vec<u8>) -> Result<(), ObjectStoreError>;
            async fn get_object(&self, key: ObjectKey) -> Result<Option<ObjectPayload>, ObjectStoreError>;
            async fn delete_object(&self, key: ObjectKey) -> Result<(), ObjectStoreError>;
            async fn shutdown(&self) -> Result<(), ObjectStoreError>;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mockall_mock_loads_into_dyn_object_store() {
        let mut mock = MockTestObjectStore::new();
        mock.expect_get_object()
            .returning(|_| Ok(Some(obj_stream(b"mocked"))));
        let store: Box<DynObjectStore> = DynObjectStore::new_box(mock);
        let joined = tokio::spawn(async move { store.get_object(ObjectKey::new("k")).await }).await;
        assert!(matches!(joined, Ok(Ok(Some(_)))));
    }

    // newtype funnel：`new` 收口 + `as_str` 借出（完整覆盖 ObjectKey 公开 API）。
    #[test]
    fn object_key_funnel_roundtrips() {
        let key = ObjectKey::new("tenant-a/blob.bin");
        assert_eq!(key.as_str(), "tenant-a/blob.bin");
    }

    // PII 边界回归（INVARIANT DIPORT-OBJECTKEY-DEBUG-REDACT-01）：key 原文不得经 Debug 泄漏。
    #[test]
    fn object_key_debug_redacts() {
        _assert_redact::<ObjectKey>();
        let key = ObjectKey::new("tenant-a/blob.bin");
        let dbg = format!("{key:?}");
        assert!(!dbg.contains("tenant-a"), "key 原文(tenant)泄漏: {dbg}");
        assert!(!dbg.contains("blob.bin"), "key 原文(object)泄漏: {dbg}");
        assert!(dbg.contains("<redacted>"), "缺 <redacted>: {dbg}");
    }

    // collect_limited：累积不超界 ⇒ 收齐全部字节。
    #[tokio::test]
    async fn collect_limited_within_bound_collects_all() {
        let payload = ObjectPayload::new(Box::pin(futures::stream::iter(vec![
            Ok::<Vec<u8>, ObjectStoreError>(b"ab".to_vec()),
            Ok(b"cd".to_vec()),
        ])));
        let got = payload.collect_limited(8).await;
        assert!(matches!(got, Ok(ref b) if b.as_slice() == b"abcd"));
    }

    // collect_limited：累积超界 ⇒ LimitExceeded（不静默截断、不无界分配）。
    #[tokio::test]
    async fn collect_limited_over_bound_errs() {
        let payload = ObjectPayload::new(Box::pin(futures::stream::iter(vec![
            Ok::<Vec<u8>, ObjectStoreError>(b"abc".to_vec()),
            Ok(b"def".to_vec()),
        ])));
        let got = payload.collect_limited(4).await;
        assert!(matches!(
            got,
            Err(ObjectStoreError::LimitExceeded { max_bytes: 4 })
        ));
    }

    // collect_limited：流内错误向上传播为 Backend（不被收集逻辑吞掉）。
    #[tokio::test]
    async fn collect_limited_propagates_stream_error() {
        let payload = ObjectPayload::new(Box::pin(futures::stream::iter(vec![
            Ok(b"ab".to_vec()),
            Err(ObjectStoreError::new(std::fmt::Error)),
        ])));
        let got = payload.collect_limited(64).await;
        assert!(matches!(got, Err(ObjectStoreError::Backend { .. })));
    }
}

#[cfg(test)]
mod error_redaction {
    //! PII 边界回归：[`ObjectStoreError`] 的 `Debug` 必须**不**展开 `Backend` 内部 `source`——source 携密（如
    //! S3 endpoint / bucket / 凭据签名）时 `{err:?}` 不得泄漏。原消费侧 Soft 日志约定已上移为类型层 Hard。
    //! `LimitExceeded`（`max_bytes` 非 PII）则可见。
    //! INVARIANT: DIPORT-OBJSTOREERR-DEBUG-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
    use super::ObjectStoreError;

    /// 模拟 S3 / network provider 错误：`Debug` 携 endpoint / 凭据（第三方 error 的 Debug 常含连接细节），
    /// 而 `Display` 仅安全摘要——正是 `ObjectStoreError::new` 包装后不得经 `Debug` 泄漏的内部错误形态。
    struct ProviderErr;
    impl std::fmt::Debug for ProviderErr {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(
                "ProviderErr { endpoint: \"https://AKIAEXAMPLE:secretkey@s3.internal/bkt\" }",
            )
        }
    }
    impl std::fmt::Display for ProviderErr {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("backend unavailable")
        }
    }
    impl std::error::Error for ProviderErr {}

    #[test]
    fn debug_does_not_expand_source_secret() {
        // anti-vacuity：内部 provider 错误自身 Debug 确实携密——故 wrapper 不展开 source 才有意义。
        assert!(
            format!("{ProviderErr:?}").contains("secretkey"),
            "前提失效：内部错误未携密，回归断言会空转"
        );
        let err = ObjectStoreError::new(ProviderErr);
        let rendered = format!("{err:?}");
        assert!(
            !rendered.contains("secretkey") && !rendered.contains("AKIAEXAMPLE"),
            "Debug 泄漏了 source 凭据: {rendered}"
        );
    }

    #[test]
    fn display_is_constant_safe_summary() {
        let err = ObjectStoreError::new(ProviderErr);
        assert_eq!(err.to_string(), "object store operation failed");
    }

    #[test]
    fn limit_exceeded_display_and_debug_show_bound() {
        // `max_bytes` 是配置上界、非 PII：Display / Debug 均可见（利于「对象超限」诊断）。
        let err = ObjectStoreError::LimitExceeded { max_bytes: 1024 };
        assert_eq!(
            err.to_string(),
            "object exceeds collect limit of 1024 bytes"
        );
        assert!(format!("{err:?}").contains("1024"));
    }
}
