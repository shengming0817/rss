//! `Signer` —— 签名 provider DI port（可替换：prod HSM / softca / test in-mem）。

use dynosaur::dynosaur;

/// 签名失败。
///
/// PII 边界（替代 `anyhow` 暴露在公共 port，与 [`crate::ShutdownError`] 同范式）：`Display` 仅输出
/// provider 无关的安全摘要常量（不含 runtime 数据）；adapter 内部原始错误经 [`SignerError::new`] 包成
/// [`std::error::Error::source`] 内部保留，**不进默认日志**（待 `secure` redaction funnel 落地后清洗记录）。
#[derive(Debug, thiserror::Error)]
#[error("signing failed")]
pub struct SignerError {
    #[source]
    source: Box<dyn std::error::Error + Send + Sync + 'static>,
}

impl SignerError {
    /// 把 adapter 内部错误包成签名失败。原始错误仅作 internal source 保留，不经 `Display` 暴露（PII 边界）。
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: Box::new(source),
        }
    }
}

/// 签名 provider DI port（async）。
///
/// 公开 [`Signer`] 是 **Send 变体**（adapters `impl Signer for ...`），[`DynSigner`] 是其
/// dyn-compatible wrapper（组合根经 `Box<DynSigner>` / `Arc<DynSigner>` 注入）。非 Send 基 trait
/// `SignerLocal` 仅供静态分发窄场景，不在 crate 根 re-export（见 crate rustdoc）。
///
/// dyn-safe 约束（ADR-003 §4.6）：方法 `&self`、参数 / 返回为具体类型、supertrait 仅 Send、
/// 带 `async fn shutdown`（无 async Drop）。
///
/// ⚠ **代表性最小 port（feasibility 范式，非 production-final）**：本 PR（PR-diport）冻结 Signer 仅为
/// 验证 async crypto port 的 dynosaur Send 派发范式。当前 `sign(&[u8])` 是**裸签**——production 签名 port
/// 须改 typed request（key/tenant/purpose/algorithm/caller，供 provider fail-closed 策略校验 + 审计归因，
/// 零信任边界），随**证书签发域（deviceloop）**落地设计，跟踪 **issue #1061**。**禁止** adapter 按当前裸
/// 形态落 production impl。（pre-GA wire 窗口允许届时原地收紧，见 api-versioning §兼容窗口。）
#[trait_variant::make(Signer: Send)]
#[dynosaur(pub DynSigner = dyn(box) Signer, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `Signer` 变体 +
// dynosaur `DynSigner` 承载（DI 注入走 Send wrapper）。这是 ADR-003 既定 dyn-port 范式。
pub trait SignerLocal {
    /// 对 `message` 签名，返回签名字节。
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError>;

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
    use super::{DynSigner, Signer, SignerError};

    struct NoopSigner;
    impl Signer for NoopSigner {
        async fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, SignerError> {
            Ok(Vec::new())
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
            signer.sign(b"payload").await.is_ok() && signer.shutdown().await.is_ok()
        })
        .await;
        assert!(matches!(joined, Ok(true)));
    }

    // #1049 待决项 PORT-SHAPE：验证 mockall mock（native-AFIT，非 #[async_trait]）可装入 dynosaur
    // Send 变体的 `DynSigner` + 跨 spawn（Send future）。落实「mock 是 native trait impl，经 new_box 进 DynX」。
    mockall::mock! {
        TestSigner {}
        impl Signer for TestSigner {
            async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError>;
            async fn shutdown(&self) -> Result<(), SignerError>;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mockall_mock_loads_into_dyn_signer() {
        let mut mock = MockTestSigner::new();
        mock.expect_sign().returning(|_| Ok(vec![1, 2, 3]));
        let signer: Box<DynSigner> = DynSigner::new_box(mock);
        let joined = tokio::spawn(async move { signer.sign(b"x").await }).await;
        assert!(matches!(joined, Ok(Ok(ref sig)) if sig == &[1, 2, 3]));
    }
}
