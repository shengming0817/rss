use consistency::ConsumerGroup;
use eventexec::InboxBacklogSelection;

fn main() {
    let raw = ConsumerGroup::parse("operator.supplied.group").unwrap();
    let _forged = InboxBacklogSelection { groups: vec![raw] };
}
