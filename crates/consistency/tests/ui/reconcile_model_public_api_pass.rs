//! compile-pass：reconcile desired/actual/diff/converge 模型经 consistency crate root 公开。

use consistency::{
    ActualState, ConvergeAction, DesiredState, DriftKind, ReconcileDiff, ReconcileResultLabel,
};

fn main() {
    let desired = DesiredState::present("spec-v2");
    let actual = ActualState::present("spec-v1");
    let diff = ReconcileDiff::between(desired, actual);

    assert_eq!(diff.desired().as_ref(), Some(&"spec-v2"));
    assert_eq!(diff.actual().as_ref(), Some(&"spec-v1"));
    assert_eq!(diff.drift(), DriftKind::Changed);
    assert_eq!(diff.converge_action(), ConvergeAction::Update);
    assert_eq!(diff.drift().as_label(), "changed");
    assert_eq!(diff.converge_action().as_label(), "update");
    assert_eq!(ReconcileResultLabel::from_panic().as_label(), "transient");
}
