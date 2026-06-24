//! Reconcile 控制环接缝（L4）—— desired↔actual 收敛，函数式接缝（对标 kube-rs）。
//!
//! `Reconciler` 是 L4 引擎策略 trait（native AFIT；reconcile.md §Reconciler 实现要点冻结此方法集）。
//! `Request::default()` = resync pulse（re-observe 你拥有的全部，level-triggered）；
//! transient error → Loop 退避重试（per-entity 指数退避）。
//! ref: kube-rs kube-runtime/src/controller/mod.rs@main（`Action::requeue`/`await_change`、`reconcile`；
//! RSS 用 trait method + 泛型消费替 kube 裸 fn，非 `Box<dyn>`）。

use std::time::Duration;

/// reconcile 目标实体标识（sealed newtype；私有字段，构造经 fallible funnel）。
///
/// 非空、canonical（fail-closed）；空/非法 key 拒绝。替换冻结期的裸 `String` 占位
/// （codex F2：裸 String 冻进 baseline → 后续换 newtype 是破坏式变更）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EntityId(String);

/// `EntityId` 解析错误。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EntityIdError {
    #[error("entity id is empty")]
    Empty,
    #[error("entity id is blank or contains control characters")]
    NotCanonical,
}

impl EntityId {
    /// 解析实体 key；非空 + canonical（fail-closed，对齐 struct rustdoc + spec.md AC）。
    ///
    /// canonical floor：拒纯空白与控制字符——二者作 reconcile 实体 key 会致静默 key 漂移 / 日志注入；
    /// 其余形态（uuid / 路径形 `tenant/cert` 等）保持 opaque（无固定 charset 承诺）。
    pub fn parse(raw: &str) -> Result<Self, EntityIdError> {
        if raw.is_empty() {
            return Err(EntityIdError::Empty);
        }
        if raw.trim().is_empty() || raw.chars().any(char::is_control) {
            return Err(EntityIdError::NotCanonical);
        }
        Ok(Self(raw.to_string()))
    }

    /// 借出底层字符串视图。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// reconcile 运行上下文（Loop harness 提供；opaque sealed——私有字段，消费域 crate 不能伪造）。
///
/// 承载取消信号 / lease epoch / 租户命名空间句柄等运行期接缝（行为 PR 兑现字段）。
/// reason: reconciler 在 system 身份下跑，ctx 由 harness 注入而非业务构造（reconcile.md §Builder 强制）。
#[derive(Debug)]
pub struct Context {
    #[allow(dead_code)]
    // reason: 冻结期 opaque sealed 字段，harness 注入，行为 PR 兑现访问器实现后移除。
    _sealed: (),
}

/// reconcile 请求（私有字段；`default()`（`None` entity）= resync pulse「re-observe 全部」，level-triggered）。
///
/// `for_entity` = 定向单实体 reconcile。engine 类型不 derive serde（ADR-004 C6）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Request {
    entity: Option<EntityId>,
}

impl Request {
    /// 定向单实体 reconcile。
    pub fn for_entity(entity: EntityId) -> Self {
        Self {
            entity: Some(entity),
        }
    }

    /// 目标实体；`None` ⇒ resync pulse（fan out 到每个拥有的实体）。
    pub fn entity(&self) -> Option<&EntityId> {
        self.entity.as_ref()
    }
}

/// reconcile 成功结果（私有字段；`requeue_after` 表达健康态稍后复检 —— reconcile.md / kube `Action`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    requeue_after: Option<Duration>,
}

impl Outcome {
    /// 已收敛，等下个外部事件/resync tick（对标 kube `Action::await_change`）。
    pub fn settled() -> Self {
        Self {
            requeue_after: None,
        }
    }

    /// 已收敛但需 `after` 后主动复检（对标 kube `Action::requeue`）。
    pub fn requeue_after(after: Duration) -> Self {
        Self {
            requeue_after: Some(after),
        }
    }

    /// fallback 复检间隔；`None` ⇒ 纯 level-triggered。
    pub fn requeue_interval(&self) -> Option<Duration> {
        self.requeue_after
    }
}

/// reconcile 失败（私有字段；`is_permanent` 仅不可重试分类，**不**自动改放弃下一步 —— reconcile.md）。
#[derive(Debug, thiserror::Error)]
#[error("{}", .kind.message())]
pub struct ReconcileError {
    kind: crate::error::EngineErrorKind,
}

impl ReconcileError {
    /// 由引擎错误种类构造。
    pub fn new(kind: crate::error::EngineErrorKind) -> Self {
        Self { kind }
    }

    /// 是否不可重试（permanent 分类；不触发自动放弃，reconcile.md）。
    pub fn is_permanent(&self) -> bool {
        self.kind == crate::error::EngineErrorKind::Permanent
    }

    /// 是否可重试（`Transient`）。Loop harness 据此决定指数退避重试（reconcile.md）。
    pub fn is_transient(&self) -> bool {
        self.kind == crate::error::EngineErrorKind::Transient
    }
}

/// 域 reconciler 策略（L4 引擎策略 trait，native AFIT）。
///
/// 签名冻结对齐 `docs/rules/reconcile.md`：`reconcile(&self, ctx: &Context, req: Request)`。
/// native AFIT ⇒ 非 object-safe，Loop harness 泛型 `<R: Reconciler>` 消费，禁 `Box<dyn>`。
/// 退避分类由 [`ReconcileError::is_transient`]/`is_permanent` 驱动（Loop 读，不走 trait 方法）。
#[allow(async_fn_in_trait)]
// reason: native AFIT 引擎策略，仅泛型静态分发消费（ADR-003 既定范式）。
pub trait Reconciler {
    /// 把 `req` 指向的实体（或 resync 全部）从 actual 驱动趋向 desired。
    async fn reconcile(&self, ctx: &Context, req: Request) -> Result<Outcome, ReconcileError>;
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{EntityId, EntityIdError, Outcome, ReconcileError, Request};
    use crate::error::EngineErrorKind;

    // EntityId 接受非空 canonical key（uuid / 路径形 `tenant/cert` 等 opaque 形态；内部空格仍 opaque）+ as_str 往返。
    #[test]
    #[allow(clippy::unwrap_used)]
    // reason: 测试 happy-path 断言已 is_ok 的 parse 结果，item-level carve-out（error-handling.md §Carve-out）。
    fn entity_id_parse_accepts_canonical_and_round_trips() {
        let cases: &[&str] = &[
            "device-1",
            "f47ac10b-58cc-4372-a567-0e02b2c3d479",
            "tenant-42/cert-3",
            "a b", // 内部空格仍 opaque（非纯空白、无控制字符）
        ];
        for &raw in cases {
            assert!(EntityId::parse(raw).is_ok(), "expected Ok for raw={raw:?}");
            assert_eq!(EntityId::parse(raw).unwrap().as_str(), raw, "raw={raw:?}");
        }
    }

    // 空 → Empty（fail-closed）。
    #[test]
    fn entity_id_parse_rejects_empty() {
        assert!(matches!(EntityId::parse(""), Err(EntityIdError::Empty)));
    }

    // 纯空白 / 含控制字符 → NotCanonical（fail-closed，对齐 spec：防静默 key 漂移 / 日志注入）。
    #[test]
    fn entity_id_parse_rejects_non_canonical() {
        for raw in [" ", "\t", "  ", "a\tb", "a\nb", "x\0y"] {
            assert!(
                matches!(EntityId::parse(raw), Err(EntityIdError::NotCanonical)),
                "expected NotCanonical for raw={raw:?}"
            );
        }
    }

    // Request::default() = resync pulse（entity None）；for_entity = 定向单实体（entity Some）。
    #[test]
    #[allow(clippy::unwrap_used)]
    // reason: 测试 happy-path 断言已 is_ok 的 parse 结果，item-level carve-out（error-handling.md §Carve-out）。
    fn request_default_is_resync_for_entity_is_targeted() {
        let resync = Request::default();
        assert_eq!(resync.entity(), None);

        let eid = EntityId::parse("device-7").unwrap();
        let targeted = Request::for_entity(eid.clone());
        assert_eq!(targeted.entity(), Some(&eid));

        // PartialEq：同 entity 相等，resync ≠ targeted。
        assert_eq!(targeted, Request::for_entity(eid));
        assert_ne!(resync, targeted);
    }

    // Outcome::settled() = 纯 level-triggered（requeue_interval None）；
    // requeue_after(d) = 健康态稍后复检（requeue_interval Some(d)，含 0 边界）。
    #[test]
    fn outcome_settled_vs_requeue_after() {
        assert_eq!(Outcome::settled().requeue_interval(), None);

        let cases: &[Duration] = &[
            Duration::from_secs(0),
            Duration::from_secs(30),
            Duration::from_millis(1500),
        ];
        for &d in cases {
            assert_eq!(
                Outcome::requeue_after(d).requeue_interval(),
                Some(d),
                "after={d:?}"
            );
        }
    }

    // ReconcileError::new + is_permanent/is_transient 真值表（三 kind）+ Display == kind.message()
    // （分类 ≠ 放弃；Display 不拼 runtime 数据，避免 PII）。
    #[test]
    fn reconcile_error_classification_and_display() {
        let cases: &[(EngineErrorKind, bool, bool)] = &[
            (EngineErrorKind::Transient, false, true),
            (EngineErrorKind::Permanent, true, false),
            (EngineErrorKind::Invariant, false, false),
        ];
        for &(kind, permanent, transient) in cases {
            let e = ReconcileError::new(kind);
            assert_eq!(e.is_permanent(), permanent, "is_permanent kind={kind:?}");
            assert_eq!(e.is_transient(), transient, "is_transient kind={kind:?}");
            assert_eq!(e.to_string(), kind.message(), "display kind={kind:?}");
        }
    }
}
