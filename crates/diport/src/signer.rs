//! `Signer` —— 签名 provider DI port（可替换：prod HSM / softca / test in-mem）。

use dynosaur::dynosaur;

use rss_redact::RedactedBytes;
use rss_redact::RedactedSource;

/// 签名失败。
///
/// PII 边界（替代 `anyhow` 暴露在公共 port，与 [`crate::ShutdownError`] 同范式）：`Display` 仅输出
/// provider 无关的安全摘要常量（不含 runtime 数据）；source 经 [`RedactedSource`] 脱敏（`Debug`/`Display`
/// 固定 `<redacted>`、`Error::source()` 恒 `None`——原始错误不经任何 `Error` 接口暴露，fail-closed），
/// 见 INVARIANT: DIPORT-ERR-SOURCE-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }。`rss_redact::redact_error` funnel 取顶层 Display、不遍历 source 链。
#[derive(Debug, thiserror::Error)]
#[error("signing failed")]
pub struct SignerError {
    #[source]
    source: RedactedSource,
}

impl SignerError {
    /// 把 adapter 内部错误包成签名失败。原始错误仅作 internal source 保留，不经 `Display` 暴露（PII 边界）。
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: RedactedSource::new(source),
        }
    }
}

/// 签名 key 标识——provider 据此选 key + fail-closed 策略校验。newtype funnel（私有字段，单一构造入口）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyId(String);

impl KeyId {
    /// 由字符串构造 key 标识。
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
    /// 借出底层标识。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 签名用途——provider 据此 fail-closed 策略归因 + 审计。opaque newtype：值集随消费域（deviceloop 证书签发）
/// 细化，不在 DI-infra 层冻结闭值集。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningPurpose(String);

impl SigningPurpose {
    /// 由字符串构造用途标识。
    pub fn new(purpose: impl Into<String>) -> Self {
        Self(purpose.into())
    }
    /// 借出底层用途。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 签名结果字节。
///
/// PII 边界（类型层 Hard，对标 `primitives::crypto::{Mac,Digest}` opaque Debug）：字节经 [`RedactedBytes`] 持有
/// （`Debug` / `Display` 恒 `<redacted>`、不展开原始字节——密码学物料不进 Debug / tracing），故 struct
/// `derive(Debug)` 即安全：`Signature(<redacted>)`。
///
/// INVARIANT: DIPORT-DTO-BYTES-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（脱敏由 `RedactedBytes` 类型保证，回归见 `pii_debug` 单测）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature(RedactedBytes);

impl Signature {
    /// 由字节构造签名。
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(RedactedBytes::new(bytes))
    }
    /// 借出签名字节。
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// typed 签名请求（零信任边界）：provider 据 `key` / `purpose` 做 fail-closed 策略校验 + 审计归因，
/// **杜绝裸 message 盲签**。
///
/// **租户 / 调用者**经 ambient [`runctx::RequestCtx`] 解析（tenant / principal 是请求级 context 值，
/// 非 sign-request 字段；provider 从 ctx 取做 RLS / ABAC），不重复进本请求。字段集随消费域（deviceloop
/// 证书签发）细化——pre-GA 窗口可原地加字段（algorithm / correlation），是可演进接缝，非 production-final 冻结面。
#[derive(Debug, Clone)]
pub struct SignRequest {
    /// 目标签名 key。
    pub key: KeyId,
    /// 签名用途（fail-closed 归因）。
    pub purpose: SigningPurpose,
    /// 待签字节（[`RedactedBytes`] 持有：可能是 CSR / nonce / token 等敏感体，`Debug` 恒 `<redacted>`；
    /// `key` / `purpose` 是归因元数据，可观测）。
    pub message: RedactedBytes,
}

/// 签名 provider DI port（async）。
///
/// 公开 [`Signer`] 是 **Send 变体**（adapters `impl Signer for ...`），[`DynSigner`] 是其
/// dyn-compatible wrapper（组合根经 `Box<DynSigner>` / `Arc<DynSigner>` 注入）。非 Send 基 trait
/// `SignerLocal` 仅供静态分发窄场景，不在 crate 根 re-export（见 crate rustdoc）。
///
/// dyn-safe 约束（ADR-003 §4.6）：方法 `&self`、参数 / 返回为具体类型、supertrait 仅 Send、
/// 带 `async fn shutdown`（无 async Drop）。
#[trait_variant::make(Signer: Send)]
#[dynosaur(pub DynSigner = dyn(box) Signer, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `Signer` 变体 +
// dynosaur `DynSigner` 承载（DI 注入走 Send wrapper）。这是 ADR-003 既定 dyn-port 范式。
pub trait SignerLocal {
    /// 按 typed [`SignRequest`] 签名（provider 先据 key/purpose + ctx 租户 fail-closed 校验，再签 `message`）。
    async fn sign(&self, request: SignRequest) -> Result<Signature, SignerError>;

    /// 异步释放 provider 资源（无 async Drop；infra teardown 显式异步）。
    ///
    /// 与 [`crate::ManagedResource::shutdown`] 的关系：有 infra 资源（连接 / 句柄）的 signer adapter
    /// 应**同时** `impl ManagedResource`，由 `bootstrap::ShutdownStack` 统一逆序编排关闭；本方法是
    /// port-local 关闭路径（非 ShutdownStack 编排场景，或 provider 自身的轻量释放）。
    async fn shutdown(&self) -> Result<(), SignerError>;
}

#[cfg(test)]
mod smoke {
    //! build smoke：证明 async DI port 可 native AFIT impl + 经 `Box<DynSigner>` 动态注入。
    use super::{DynSigner, KeyId, SignRequest, Signature, Signer, SignerError, SigningPurpose};

    #[test]
    fn signer_error_wraps_source() {
        let err = SignerError::new(std::io::Error::other("leak-marker-sig"));
        assert_eq!(err.to_string(), "signing failed");
        assert!(std::error::Error::source(&err).is_some());
        // 端到端：derive(Debug) 经 RedactedSource 脱敏、不展开内层 source（anti-vacuity 前置）。
        assert!(
            format!("{:?}", std::io::Error::other("leak-marker-sig")).contains("leak-marker-sig"),
            "前提失效：内层 Debug 未携 marker"
        );
        assert!(
            !format!("{err:?}").contains("leak-marker-sig"),
            "wrapper Debug 泄漏 source: {err:?}"
        );
    }

    fn sample_request() -> SignRequest {
        SignRequest {
            key: KeyId::new("key-1"),
            purpose: SigningPurpose::new("device-cert"),
            message: b"payload".to_vec().into(),
        }
    }

    struct NoopSigner;
    impl Signer for NoopSigner {
        async fn sign(&self, _request: SignRequest) -> Result<Signature, SignerError> {
            Ok(Signature::new(Vec::new()))
        }
        async fn shutdown(&self) -> Result<(), SignerError> {
            Ok(())
        }
    }

    // multi_thread + spawn：boxed future 须 Send（trait_variant Send 变体）才能跨 worker 调度——
    // current-thread 不暴露 Send 违规，故用 multi_thread 真正验证 dyn 注入的 Send 语义。
    #[tokio::test(flavor = "multi_thread")]
    async fn signer_is_dyn_injectable() {
        let signer: Box<DynSigner> = DynSigner::new_box(NoopSigner);
        let joined = tokio::spawn(async move {
            signer.sign(sample_request()).await.is_ok() && signer.shutdown().await.is_ok()
        })
        .await;
        assert!(matches!(joined, Ok(true)));
    }

    // #1049 待决项 PORT-SHAPE：验证 mockall mock（native-AFIT，非 #[async_trait]）可装入 dynosaur
    // Send 变体的 `DynSigner` + 跨 spawn（Send future）。落实「mock 是 native trait impl，经 new_box 进 DynX」。
    mockall::mock! {
        TestSigner {}
        impl Signer for TestSigner {
            async fn sign(&self, request: SignRequest) -> Result<Signature, SignerError>;
            async fn shutdown(&self) -> Result<(), SignerError>;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mockall_mock_loads_into_dyn_signer() {
        let mut mock = MockTestSigner::new();
        mock.expect_sign()
            .returning(|_| Ok(Signature::new(vec![1, 2, 3])));
        let signer: Box<DynSigner> = DynSigner::new_box(mock);
        let joined = tokio::spawn(async move { signer.sign(sample_request()).await }).await;
        assert!(matches!(joined, Ok(Ok(ref sig)) if sig.as_bytes() == [1, 2, 3]));
    }
}

#[cfg(test)]
mod pii_debug {
    //! `SignRequest.message`（待签名体）/ `Signature`（密码学物料）字节 Debug 脱敏回归。
    //! INVARIANT: DIPORT-DTO-BYTES-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（字节经 `RedactedBytes` 脱敏，对标 `primitives::crypto::{Mac,Digest,MacKey}` opaque Debug）。
    use super::{KeyId, SignRequest, Signature, SigningPurpose};

    #[test]
    fn sign_request_debug_redacts_message() {
        // anti-vacuity：原始 Vec<u8> Debug 把 0xDE 渲染成 "222"，证明 "!contains(222)" 检测非空转。
        assert!(
            format!("{:?}", vec![0xDE_u8]).contains("222"),
            "前提失效：检测字节不在原始 Debug"
        );
        let req = SignRequest {
            key: KeyId::new("key-1"),
            purpose: SigningPurpose::new("device-cert"),
            message: vec![0xDE, 0xAD, 0xBE, 0xEF].into(),
        };
        let dbg = format!("{req:?}");
        assert!(!dbg.contains("222"), "message 字节泄漏(0xDE=222): {dbg}");
        assert!(!dbg.contains("173"), "message 字节泄漏(0xAD=173): {dbg}");
        assert!(dbg.contains("<redacted>"), "缺 <redacted>: {dbg}");
        assert!(dbg.contains("key-1"), "key 应可见: {dbg}");
        assert!(dbg.contains("device-cert"), "purpose 应可见: {dbg}");
    }

    #[test]
    fn signature_debug_is_opaque() {
        let sig = Signature::new(vec![0xDE, 0xAD]);
        assert_eq!(format!("{sig:?}"), "Signature(<redacted>)");
    }
}
