use rss_transactional_messaging_postgres::PgInboxClaim;

fn duplicate(claim: PgInboxClaim) {
    let _replay = claim.clone();
}

fn main() {}
