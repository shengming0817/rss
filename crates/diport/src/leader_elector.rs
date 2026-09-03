//! `LeaderElector` —— 分布式 leader 选举 provider DI port（可替换：prod Redis/Postgres / test in-mem）。
//!
//! 单进程模式不注入本 port（harness `ReconcileLoop::run`，always leader、`Context::epoch()` 为 `None`、无 fencing）；
//! 多副本模式经 `ReconcileLoop::run_with_leader(Arc<L>, ..)` 注入（泛型静态分发，非 `Box<DynLeaderElector>`——
//! dyn 变体 Send 非 Sync，DIPORT-ASYNC-ARC-SEND-01），整环 leader-gated：仅 lease holder dispatch（`consistency::Reconciler`、`diport::FencedWriter` 与 provider conformance）。
//!
//! ref: kubernetes/client-go tools/leaderelection/leaderelection.go@master（`tryAcquireOrRenew` 单一争夺/续租
//! 入口 + holder identity + 单调 `LeaderTransitions`）；RSS 把 `LeaderElectionRecord` 收敛成 typed [`LeaseToken`]，
//! 单调 epoch 落 `vocab::Epoch` 供 `FencedWriter` 写路径 CAS。

use std::time::Duration;

use dynosaur::dynosaur;

use rss_redact::RedactedSource;

/// leader 选举失败（infra 故障，**非**「未当选」——未当选是 [`LeaderElectorLocal::acquire`] 的 `Ok(None)`）。
///
/// PII 边界（与 [`crate::SignerError`] 同范式）：`Display` 仅安全摘要常量；source 经 [`RedactedSource`]
/// 脱敏（`Debug`/`Display` 固定 `<redacted>`、`Error::source()` 恒 `None`）。见 INVARIANT: DIPORT-ERR-SOURCE-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }。
#[derive(Debug, thiserror::Error)]
#[error("leader election failed")]
pub struct LeaderElectorError {
    #[source]
    source: RedactedSource,
}

impl LeaderElectorError {
    /// 把 adapter 内部错误包成选举失败。原始错误仅作 internal source 保留，不经 `Display` 暴露（PII 边界）。
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: RedactedSource::new(source),
        }
    }
}

/// `LeaderId` 解析错误（canonical funnel fail-closed，照 `consistency::EntityId`）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LeaderIdError {
    /// holder identity 为空。
    #[error("leader id is empty")]
    Empty,
    /// holder identity 纯空白或含控制字符。
    #[error("leader id is blank or contains control characters")]
    NotCanonical,
}

/// leader 实例标识（holder identity）。sealed newtype funnel（私有字段，唯一构造入口 [`LeaderId::parse`]，
/// fail-closed）——空 / 非 canonical holder 拒绝（防静默 leadership 漂移 / 日志注入）。
///
/// 对标 client-go `LeaderElectionRecord.HolderIdentity`：标识当前持 lease 的实例（pod / 进程）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaderId(String);

impl LeaderId {
    /// 解析 holder identity；非空 + canonical（fail-closed）。空 → [`LeaderIdError::Empty`]；纯空白 /
    /// 含控制字符 → [`LeaderIdError::NotCanonical`]。其余形态（pod 名 / uuid / host:pid）保持 opaque。
    pub fn parse(raw: &str) -> Result<Self, LeaderIdError> {
        if raw.is_empty() {
            return Err(LeaderIdError::Empty);
        }
        if raw.trim().is_empty() || raw.chars().any(char::is_control) {
            return Err(LeaderIdError::NotCanonical);
        }
        Ok(Self(raw.to_string()))
    }
    /// 借出底层标识。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 当选凭据：当前持 leadership 的实例 + 该**任期**单调 [`vocab::Epoch`]。
///
/// 任期语义（fencing 单源）：同一持有者续租 ⇒ `epoch` 不变（同任期）；leadership 易手（旧 holder lease
/// 失效后他者接管）⇒ `epoch` 单调递增（新任期）。`epoch` 注入 `FencedWriter` 写路径做 CAS——旧任期 stale 写被挡。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseToken {
    /// 当前任期持有者。
    pub holder: LeaderId,
    /// 当前任期单调 epoch（fencing token）。
    pub epoch: vocab::Epoch,
}

/// 分布式 leader 选举 provider DI port（async）。
///
/// 公开 [`LeaderElector`] 是 **Send 变体**（adapters `impl LeaderElector for ...`），
/// [`DynLeaderElector`] 是其 dyn-compatible wrapper（组合根经 `Box<DynLeaderElector>` 注入）。
/// 非 Send 基 trait `LeaderElectorLocal` 不在 crate 根 re-export。
#[trait_variant::make(LeaderElector: Send)]
#[dynosaur(pub DynLeaderElector = dyn(box) LeaderElector, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `LeaderElector` 变体 +
// dynosaur `DynLeaderElector` 承载（DI 注入走 Send wrapper）。这是 ADR-003 既定 dyn-port 范式。
pub trait LeaderElectorLocal {
    /// 争夺或续租 leadership（client-go `tryAcquireOrRenew` 范式，harness 每 renew-interval 轮询一次）。
    ///
    /// - `Ok(Some(token))`：本实例当前持有 leadership（`token.epoch` = 当前任期单调 epoch，注入 `FencedWriter`）。
    /// - `Ok(None)`：他实例持有 lease，本实例**非** leader——harness 据此停 dispatch、取消 lease-scoped token。
    /// - `Err(..)`：infra 故障（连接 / 后端不可用），harness 退避后重试。
    ///
    /// `lease` 是 lease TTL（holder 须在过期前再次 `acquire` 续租；超时未续 ⇒ 他实例可接管，epoch 递增）。
    async fn acquire(&self, lease: Duration) -> Result<Option<LeaseToken>, LeaderElectorError>;

    /// 主动让出 leadership（优雅退出：清当前 lease，使他实例即时接管，无需等 TTL）。
    ///
    /// **impl 契约**：仅当 `token` 是**当前任期**持有者（`holder` **且** `epoch` 均匹配存储的当前 lease）时
    /// 生效；已易手或旧任期 stale token 则 no-op（幂等）。**仅校验 `holder` 不够**——同 holder 重启后持旧
    /// epoch token 调 `release` 会误让出其续租后的新任期 lease，故 production adapter 必须同时校验 epoch。
    async fn release(&self, token: LeaseToken) -> Result<(), LeaderElectorError>;

    /// 异步释放 provider 资源（无 async Drop）。有 infra 资源的 adapter 应同时 `impl ManagedResource`
    /// 由 `bootstrap::ShutdownStack` 统一编排；本方法是 port-local 关闭路径。
    async fn shutdown(&self) -> Result<(), LeaderElectorError>;
}

#[cfg(test)]
mod smoke {
    //! build smoke：证明 async DI port 可 native AFIT impl + 经 `Box<DynLeaderElector>` 跨 spawn（Send）动态注入。
    use super::{DynLeaderElector, LeaderElector, LeaderElectorError, LeaderId, LeaseToken};
    use std::time::Duration;

    #[allow(clippy::expect_used)]
    // reason: 测试桩用 canonical literal 构造 LeaderId，item-level carve-out。
    fn test_leader_id() -> LeaderId {
        LeaderId::parse("noop").expect("canonical literal")
    }

    // LeaderId::parse 拒空 / 纯空白 / 控制字符（fail-closed funnel，照 EntityId）。
    #[test]
    fn leader_id_parse_rejects_non_canonical() {
        use super::LeaderIdError;
        assert!(matches!(LeaderId::parse(""), Err(LeaderIdError::Empty)));
        for raw in [" ", "\t", "a\nb", "x\0y"] {
            assert!(
                matches!(LeaderId::parse(raw), Err(LeaderIdError::NotCanonical)),
                "raw={raw:?}"
            );
        }
        assert_eq!(test_leader_id().as_str(), "noop");
    }

    #[test]
    fn leader_elector_error_redacts_source() {
        let err = LeaderElectorError::new(std::io::Error::other("leak-marker-elect"));
        assert_eq!(err.to_string(), "leader election failed");
        assert!(std::error::Error::source(&err).is_some());
        // anti-vacuity：内层自身 Debug 携 marker，wrapper Debug 经 RedactedSource 脱敏不泄漏。
        assert!(
            format!("{:?}", std::io::Error::other("leak-marker-elect"))
                .contains("leak-marker-elect")
        );
        assert!(
            !format!("{err:?}").contains("leak-marker-elect"),
            "source 泄漏: {err:?}"
        );
    }

    struct NoopElector;
    impl LeaderElector for NoopElector {
        async fn acquire(
            &self,
            _lease: Duration,
        ) -> Result<Option<LeaseToken>, LeaderElectorError> {
            Ok(Some(LeaseToken {
                holder: test_leader_id(),
                epoch: vocab::Epoch::new(0),
            }))
        }
        async fn release(&self, _token: LeaseToken) -> Result<(), LeaderElectorError> {
            Ok(())
        }
        async fn shutdown(&self) -> Result<(), LeaderElectorError> {
            Ok(())
        }
    }

    // multi_thread + spawn：boxed future 须 Send（trait_variant Send 变体）才能跨 worker 调度。
    #[tokio::test(flavor = "multi_thread")]
    async fn leader_elector_is_dyn_injectable() {
        let elector: Box<DynLeaderElector> = DynLeaderElector::new_box(NoopElector);
        let joined = tokio::spawn(async move {
            let acquired = elector.acquire(Duration::from_secs(30)).await;
            matches!(acquired, Ok(Some(_))) && elector.shutdown().await.is_ok()
        })
        .await;
        assert!(matches!(joined, Ok(true)));
    }
}
