use rss_audit_core::ActorId;

fn main() {
    let actor = ActorId::parse("sensitive-actor").unwrap();
    let _ = serde_json::to_vec(&actor);
}
