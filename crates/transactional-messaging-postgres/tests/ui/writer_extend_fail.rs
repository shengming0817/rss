#![allow(unused_imports, unused_variables)]
use rss_transactional_messaging_postgres as adapter;
use rss_transactional_messaging::{outbox::OutboxRelayStore, policy::OperationDeadline};
fn denied(writer: &adapter::PgOutboxWriter, deadline: OperationDeadline, claim: &adapter::PgOutboxClaim) {
    let _ = writer.extend(claim, deadline);
}
fn main() {}
