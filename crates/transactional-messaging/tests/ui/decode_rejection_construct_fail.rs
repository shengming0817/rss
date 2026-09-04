use rss_transactional_messaging::transaction::{
    DecodeRejection, EnvelopeValidationFailure,
};

fn main() {
    let _forged = DecodeRejection {
        reason: EnvelopeValidationFailure::MalformedMetadata,
    };
}
