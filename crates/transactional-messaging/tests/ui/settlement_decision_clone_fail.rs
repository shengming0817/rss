use rss_transactional_messaging::transaction::SettlementDecision;

fn clone_decision(decision: SettlementDecision) {
    let _duplicate = decision.clone();
}

fn main() {}
