use rss_transactional_messaging::transaction::EnvelopeValidationFailure;

fn main() {
    let _forged = EnvelopeValidationFailure::MalformedIdentity.into_settlement();
}
