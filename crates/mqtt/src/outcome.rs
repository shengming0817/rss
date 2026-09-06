use rss_transactional_messaging::transport::{
    PublishFailure, PublishFailureKind as Kind, PublishFailureReason as Reason,
    PublishFailureStage as Stage, PublishOutcome,
};
use rumqttc::mqttbytes::v5::PubAckReason;
use rumqttc::{ClientError, PublishNoticeError, PublishResult};

pub(crate) fn definite(kind: Kind, stage: Stage, reason: Reason) -> PublishOutcome<()> {
    PublishOutcome::DefinitelyNotPublished(PublishFailure::new(kind, stage, reason))
}
pub(crate) fn ambiguous(reason: Reason) -> PublishOutcome<()> {
    PublishOutcome::Ambiguous(PublishFailure::new(Kind::Transient, Stage::Confirm, reason))
}
pub(crate) fn admission(error: ClientError) -> PublishOutcome<()> {
    match error {
        ClientError::InvalidRequest(_) => {
            definite(Kind::Permanent, Stage::Encode, Reason::InvalidMessage)
        }
        ClientError::RequestChannelFull(_)
        | ClientError::RequestChannelDisconnected(_)
        | ClientError::TrackingUnavailable => definite(
            Kind::Transient,
            Stage::Admission,
            Reason::TransportUnavailable,
        ),
        _ => ambiguous(Reason::TransportUnavailable),
    }
}
pub(crate) fn notice(result: Result<PublishResult, PublishNoticeError>) -> PublishOutcome<()> {
    match result {
        Ok(PublishResult::Qos1(ack)) => puback(ack.reason),
        Err(PublishNoticeError::RetainNotSupported) => {
            definite(Kind::Permanent, Stage::Send, Reason::ProviderRejected)
        }
        Err(PublishNoticeError::BrokerOnlySessionResume) => definite(
            Kind::Transient,
            Stage::Admission,
            Reason::TransportUnavailable,
        ),
        _ => ambiguous(Reason::TransportUnavailable),
    }
}
fn puback(reason: PubAckReason) -> PublishOutcome<()> {
    use PubAckReason::*;
    match reason {
        Success | NoMatchingSubscribers => PublishOutcome::Confirmed(()),
        NotAuthorized | TopicNameInvalid | PayloadFormatInvalid => {
            definite(Kind::Permanent, Stage::Confirm, Reason::ProviderRejected)
        }
        UnspecifiedError | ImplementationSpecificError | PacketIdentifierInUse | QuotaExceeded => {
            definite(Kind::Transient, Stage::Confirm, Reason::ProviderRejected)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejection_is_not_success_and_uncertainty_never_dead_letters() {
        assert!(matches!(
            puback(PubAckReason::Success),
            PublishOutcome::Confirmed(())
        ));
        assert!(matches!(
            puback(PubAckReason::NoMatchingSubscribers),
            PublishOutcome::Confirmed(())
        ));
        for reason in [
            PubAckReason::NotAuthorized,
            PubAckReason::TopicNameInvalid,
            PubAckReason::PayloadFormatInvalid,
        ] {
            assert!(
                matches!(puback(reason), PublishOutcome::DefinitelyNotPublished(f) if f.kind() == Kind::Permanent)
            );
        }
        for reason in [
            PubAckReason::UnspecifiedError,
            PubAckReason::ImplementationSpecificError,
            PubAckReason::PacketIdentifierInUse,
            PubAckReason::QuotaExceeded,
        ] {
            assert!(
                matches!(puback(reason), PublishOutcome::DefinitelyNotPublished(f) if f.kind() == Kind::Transient)
            );
        }
        for error in [
            PublishNoticeError::SessionReset,
            PublishNoticeError::Recv,
            PublishNoticeError::SessionPersistence("private".into()),
        ] {
            assert!(notice(Err(error)).is_ambiguous());
        }
    }
}
