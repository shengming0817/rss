use rss_transactional_messaging::transaction::{SettlementDecision, SettlementKind};

fn main() {
    let _forged = SettlementDecision(SettlementKind::Acknowledge);
}
