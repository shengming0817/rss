//! `FencedWriter` —— 防护写 provider DI port（可替换：prod Redis/Postgres / test in-mem）。
//!
//! 跨副本写路径正确性原语：reconciler 从 `Context::epoch()` 取当前任期 [`vocab::Epoch`]，写**某个被保护
//! 资源**（[`FencedWriteKey`]）时携该 epoch；provider 维护**每个 key 各自**的已接受 epoch 高水位，
//! **fence 掉 epoch `<` 该 key 高水位的写**（旧 leader stale 写被挡）。**同/新 epoch 放行**——lease epoch
//! 在一个任期内**稳定不变**，同任期对同一/不同 key 的多次写都合法；同 epoch 重放的幂等由消费方
//! idempotency 负责，**不**由 fencing 拒（fencing 只挡跨任期 stale，不挡同任期重写）。
//! 「leader ≠ fencing」：仅靠 lease 选举不保正确性——跨副本一致性靠此 per-key CAS + 消费方幂等
//! （`consistency::Reconciler`、`diport::FencedWriter` 与 provider conformance）。
//!
//! ref: Martin Kleppmann《DDIA》§8.3 fencing token（storage 拒绝 token 低于已见高水位的写，**按被保护资源**）；
//! kube-rs/controller-runtime `Request` 以 `ObjectRef`/`NamespacedName` 识别对象（非全局单 token）；
//! etcd `concurrency.Mutex` 持锁后保存 revision 作 owner/version 上下文。
//! INVARIANT: RECONCILE-FENCE-MONO-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（**per-key** 单调：跨任期 stale（epoch `<` 该 key 高水位）拒、
//! 同/新任期受。回归见 `adapters/memory` per-key CAS 测试）。
//! 该不变式是 **Medium（运行期 `#[test]`）固有**：单调性是对**运行期** epoch 值的比较（高水位在运行期才知），
//! 无法上移编译期类型系统；故守卫是 adapter 行为测试 + anti-vacuity（write(key,e2)→write(key,e1<e2) 必 Fenced），非 Hard。

use dynosaur::dynosaur;

use rss_redact::RedactedBytes;
use rss_redact::RedactedSource;

/// 防护写结论（typed outcome，非 error——fence 是预期控制流）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WriteOutcome {
    /// 写已提交（epoch `≥` 该 key 已接受高水位，high-water 推进到本 epoch）。
    Committed,
    /// 写被 fence（epoch `<` 该 key 已接受高水位）——本实例已失任期 / 旧 leader stale 写；调用方应停写、重选举。
    Fenced,
}

/// 被保护资源标识（fencing 维度）。provider 按 key **各自**维护 epoch 高水位——同任期对不同 key 的写互不
/// fence、对同一 key 的 stale 写被挡。对标 kube `ObjectRef` / etcd key。newtype funnel（私有字段，单一构造入口）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FencedWriteKey(String);

impl FencedWriteKey {
    /// 由资源标识构造（如 `tenant-42/cert-3`、设备 id）。
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }
    /// 借出底层 key。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// typed 防护写请求：`key` 被保护资源 + `epoch` 当前任期 token + `data` payload。
///
/// PII 边界（类型层 Hard，同 [`crate::SignRequest`]）：`data`（待写 payload，可能含敏感设备状态 / 凭据）经
/// [`RedactedBytes`] 持有（`Debug` 恒 `<redacted>`），故 `derive(Debug)` 即安全；`key` / `epoch` 是路由 / 版本元数据，可观测。
///
/// INVARIANT: DIPORT-DTO-BYTES-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }。
#[derive(Debug, Clone)]
pub struct FencedWriteRequest {
    /// 被保护资源（fencing 高水位按 key 隔离）。
    pub key: FencedWriteKey,
    /// 当前任期 epoch（来自 `LeaseToken.epoch` / `Context::epoch()`）；provider 按 key CAS 比对高水位。
    pub epoch: vocab::Epoch,
    /// 待写 payload（provider-agnostic 字节，[`RedactedBytes`] 持有）。
    pub data: RedactedBytes,
}

/// 防护写失败（infra 故障，**非** fence——fence 是 [`WriteOutcome::Fenced`] 的 `Ok`）。
///
/// PII 边界（与 [`crate::SignerError`] 同范式）：source 经 [`RedactedSource`] 脱敏。
/// 见 INVARIANT: DIPORT-ERR-SOURCE-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }。
#[derive(Debug, thiserror::Error)]
#[error("fenced write failed")]
pub struct FencedWriterError {
    #[source]
    source: RedactedSource,
}

impl FencedWriterError {
    /// 把 adapter 内部错误包成防护写失败。原始错误仅作 internal source 保留，不经 `Display` 暴露（PII 边界）。
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: RedactedSource::new(source),
        }
    }
}

/// 防护写 provider DI port（async）。
///
/// 公开 [`FencedWriter`] 是 **Send 变体**（adapters `impl FencedWriter for ...`），
/// [`DynFencedWriter`] 是其 dyn-compatible wrapper（组合根经 `Box<DynFencedWriter>` 注入）。
/// 非 Send 基 trait `FencedWriterLocal` 不在 crate 根 re-export。
#[trait_variant::make(FencedWriter: Send)]
#[dynosaur(pub DynFencedWriter = dyn(box) FencedWriter, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `FencedWriter` 变体 +
// dynosaur `DynFencedWriter` 承载（DI 注入走 Send wrapper）。这是 ADR-003 既定 dyn-port 范式。
pub trait FencedWriterLocal {
    /// 按 [`FencedWriteRequest`] 防护写：`request.epoch` `≥` 该 `request.key` 已接受高水位 ⇒
    /// [`WriteOutcome::Committed`]（高水位推进到本 epoch）；`<` ⇒ [`WriteOutcome::Fenced`]（旧 leader stale
    /// 写被挡）。**同/新 epoch 放行**（同任期多写合法，幂等由消费方负责）；`Err` 仅表 infra 故障。
    async fn write(&self, request: FencedWriteRequest) -> Result<WriteOutcome, FencedWriterError>;

    /// 异步释放 provider 资源（无 async Drop）。有 infra 资源的 adapter 应同时 `impl ManagedResource`
    /// 由 `rss_runtime::ShutdownStack` 统一编排；本方法是 port-local 关闭路径。
    async fn shutdown(&self) -> Result<(), FencedWriterError>;
}

#[cfg(test)]
mod smoke {
    //! build smoke：证明 async DI port 可 native AFIT impl + 经 `Box<DynFencedWriter>` 跨 spawn（Send）动态注入。
    use super::{
        DynFencedWriter, FencedWriteKey, FencedWriteRequest, FencedWriter, FencedWriterError,
        WriteOutcome,
    };

    #[test]
    fn fenced_writer_error_redacts_source() {
        let err = FencedWriterError::new(std::io::Error::other("leak-marker-fence"));
        assert_eq!(err.to_string(), "fenced write failed");
        assert!(std::error::Error::source(&err).is_some());
        assert!(
            !format!("{err:?}").contains("leak-marker-fence"),
            "source 泄漏: {err:?}"
        );
    }

    #[test]
    fn fenced_write_request_debug_redacts_data() {
        // anti-vacuity：原始 Vec<u8> Debug 把 0xDE 渲染成 "222"。
        assert!(format!("{:?}", vec![0xDE_u8]).contains("222"));
        let req = FencedWriteRequest {
            key: FencedWriteKey::new("cert-3"),
            epoch: vocab::Epoch::new(3),
            data: vec![0xDE, 0xAD].into(),
        };
        let dbg = format!("{req:?}");
        assert!(!dbg.contains("222"), "data 字节泄漏: {dbg}");
        assert!(dbg.contains("<redacted>"), "缺 <redacted>: {dbg}");
        assert!(dbg.contains('3'), "epoch 应可见: {dbg}");
        assert!(dbg.contains("cert-3"), "key 应可见: {dbg}");
    }

    struct NoopWriter;
    impl FencedWriter for NoopWriter {
        async fn write(
            &self,
            _request: FencedWriteRequest,
        ) -> Result<WriteOutcome, FencedWriterError> {
            Ok(WriteOutcome::Committed)
        }
        async fn shutdown(&self) -> Result<(), FencedWriterError> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fenced_writer_is_dyn_injectable() {
        let writer: Box<DynFencedWriter> = DynFencedWriter::new_box(NoopWriter);
        let joined = tokio::spawn(async move {
            let outcome = writer
                .write(FencedWriteRequest {
                    key: FencedWriteKey::new("res-1"),
                    epoch: vocab::Epoch::new(1),
                    data: b"x".to_vec().into(),
                })
                .await;
            matches!(outcome, Ok(WriteOutcome::Committed)) && writer.shutdown().await.is_ok()
        })
        .await;
        assert!(matches!(joined, Ok(true)));
    }
}
