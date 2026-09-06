//! Pure comparison extracted from baseline 5b63e10:consistency/src/reconcile.rs.
use core::fmt;
/// 域拥有的 desired snapshot（私有字段；只经 [`DesiredState::present`] / [`DesiredState::missing`] 构造）。
///
/// `T` 是域 reconciler 映射后的纯比较值，不是 DB row、adapter handle、generated DTO 或 transport payload。
#[derive(Clone, PartialEq, Eq)]
pub struct DesiredState<T> {
    value: Option<T>,
}

impl<T> fmt::Debug for DesiredState<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DesiredState")
            .field("present", &self.value.is_some())
            .finish()
    }
}

impl<T> DesiredState<T> {
    /// desired 存在：域期望该实体以 `value` 形态存在。
    pub fn present(value: T) -> Self {
        Self { value: Some(value) }
    }

    /// desired 缺失：域期望该实体不存在。
    pub fn missing() -> Self {
        Self { value: None }
    }

    /// 借出 desired snapshot。
    pub fn as_ref(&self) -> Option<&T> {
        self.value.as_ref()
    }
}

/// 域观察到的 actual snapshot（私有字段；只经 [`ActualState::present`] / [`ActualState::missing`] 构造）。
///
/// `T` 是域 reconciler 映射后的纯比较值，不是 DB row、adapter handle、generated DTO 或 transport payload。
#[derive(Clone, PartialEq, Eq)]
pub struct ActualState<T> {
    value: Option<T>,
}

impl<T> fmt::Debug for ActualState<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActualState")
            .field("present", &self.value.is_some())
            .finish()
    }
}

impl<T> ActualState<T> {
    /// actual 存在：观察侧当前有该实体 snapshot。
    pub fn present(value: T) -> Self {
        Self { value: Some(value) }
    }

    /// actual 缺失：观察侧当前不存在该实体。
    pub fn missing() -> Self {
        Self { value: None }
    }

    /// 借出 actual snapshot。
    pub fn as_ref(&self) -> Option<&T> {
        self.value.as_ref()
    }
}

/// desired/actual drift 闭值集（metrics/log label 单源）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftKind {
    /// desired 与 actual 同为缺失，或同为存在且 snapshot 相等。
    Converged,
    /// desired 存在但 actual 缺失，需要创建 / 发起建立。
    MissingActual,
    /// desired 缺失但 actual 存在，需要删除 / 发起撤销。
    UnexpectedActual,
    /// desired 与 actual 都存在但 snapshot 不相等，需要更新。
    Changed,
}

impl DriftKind {
    /// 稳定低基数 label（crate-owned 闭映射）。
    pub fn as_label(self) -> &'static str {
        match self {
            DriftKind::Converged => "converged",
            DriftKind::MissingActual => "missing_actual",
            DriftKind::UnexpectedActual => "unexpected_actual",
            DriftKind::Changed => "changed",
        }
    }
}

/// drift 对应的纯收敛下一步分类；不是 adapter action，也不执行 I/O。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConvergeAction {
    /// 已收敛，无动作。
    Noop,
    /// actual 缺失，下一步应创建。
    Create,
    /// actual 存在但不匹配，下一步应更新。
    Update,
    /// actual 不应存在，下一步应删除。
    Delete,
}

impl ConvergeAction {
    /// 由 drift 闭集映射到最小下一步分类。
    pub fn for_drift(drift: DriftKind) -> Self {
        match drift {
            DriftKind::Converged => ConvergeAction::Noop,
            DriftKind::MissingActual => ConvergeAction::Create,
            DriftKind::UnexpectedActual => ConvergeAction::Delete,
            DriftKind::Changed => ConvergeAction::Update,
        }
    }

    /// 稳定低基数 label（crate-owned 闭映射）。
    pub fn as_label(self) -> &'static str {
        match self {
            ConvergeAction::Noop => "noop",
            ConvergeAction::Create => "create",
            ConvergeAction::Update => "update",
            ConvergeAction::Delete => "delete",
        }
    }
}

/// desired/actual 比较结果（私有字段；只经 [`ReconcileDiff::between`] 分类）。
#[derive(Clone, PartialEq, Eq)]
pub struct ReconcileDiff<T> {
    desired: DesiredState<T>,
    actual: ActualState<T>,
    drift: DriftKind,
}

impl<T> fmt::Debug for ReconcileDiff<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReconcileDiff")
            .field("desired_present", &self.desired.as_ref().is_some())
            .field("actual_present", &self.actual.as_ref().is_some())
            .field("drift", &self.drift)
            .field("converge_action", &self.converge_action())
            .finish()
    }
}

impl<T: PartialEq> ReconcileDiff<T> {
    /// 比较 desired/actual presence + snapshot equality，生成闭集 drift。
    pub fn between(desired: DesiredState<T>, actual: ActualState<T>) -> Self {
        let drift = match (desired.as_ref(), actual.as_ref()) {
            (None, None) => DriftKind::Converged,
            (Some(_), None) => DriftKind::MissingActual,
            (None, Some(_)) => DriftKind::UnexpectedActual,
            (Some(desired), Some(actual)) if desired == actual => DriftKind::Converged,
            (Some(_), Some(_)) => DriftKind::Changed,
        };
        Self {
            desired,
            actual,
            drift,
        }
    }
}

impl<T> ReconcileDiff<T> {
    /// desired snapshot。
    pub fn desired(&self) -> &DesiredState<T> {
        &self.desired
    }

    /// actual snapshot。
    pub fn actual(&self) -> &ActualState<T> {
        &self.actual
    }

    /// drift 闭集分类。
    pub fn drift(&self) -> DriftKind {
        self.drift
    }

    /// 由 drift 得出的纯下一步分类。
    pub fn converge_action(&self) -> ConvergeAction {
        ConvergeAction::for_drift(self.drift)
    }
}
