//! `Signer` —— 签名 provider DI port（可替换：prod HSM / softca / test in-mem）。

use dynosaur::dynosaur;

/// 签名失败。
///
/// PII 边界（替代 `anyhow` 暴露在公共 port）：`Display` 仅输出 provider 无关的安全摘要常量；
/// adapter 内部原始错误待行为 PR 经 `#[source]` 内部保留、不进默认日志（参 [`crate::ShutdownError`]）。
#[derive(Debug, thiserror::Error)]
#[error("signing failed")]
pub struct SignerError;

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
    /// 对 `message` 签名，返回签名字节。
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError>;

    /// 异步释放 provider 资源（无 async Drop；infra teardown 显式异步）。
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

    #[tokio::test]
    async fn signer_is_dyn_injectable() {
        let signer: Box<DynSigner> = DynSigner::new_box(NoopSigner);
        assert!(signer.sign(b"payload").await.is_ok());
        assert!(signer.shutdown().await.is_ok());
    }
}
