// rss_dlq_operator_callsite UI fixture（disallowed caller）。
#![allow(unused, unknown_lints)]

fn main() {
    let _cap = eventexec::OperatorDlqCapability::issue_for_authorized_operator();

    let issue = eventexec::OperatorDlqCapability::issue_for_authorized_operator;
    let _cap2 = issue();

    allowed_by_attr();
}

#[allow(rss_dlq_operator_callsite)] // reason: UI fixture 验证逃生门
fn allowed_by_attr() {
    let _cap = eventexec::OperatorDlqCapability::issue_for_authorized_operator();
}
