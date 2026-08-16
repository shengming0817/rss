use eventing_composition::BridgedSubscriptions;

fn main() {
    let _forged = BridgedSubscriptions {
        subscriptions: Vec::new(),
        inbox_backlog: eventexec::InboxBacklogSelection::from_generated(&[]).unwrap(),
    };
}
