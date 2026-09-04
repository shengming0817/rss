use rss_transactional_messaging::transaction::VerifiedConsumerBinding;

fn main() {
    let _forged = VerifiedConsumerBinding {
        identity: panic!(),
        fingerprint: panic!(),
    };
}
