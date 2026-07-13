// rss_dlq_operator_callsite UI fixture（allowed caller）。example target 名 `httpserve`。
#![allow(unused)]

fn main() {
    let _cap = eventexec::OperatorDlqCapability::issue_for_authorized_operator();
    let _subject = eventexec::VerifiedOperatorSubject::from_verified("operator:alice");
}
