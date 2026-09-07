mod support;
use rss_transactional_messaging::{
    message::{MessageRoute, MessagingDomain},
    transport::{PublishFailureReason, PublishOutcome, Publisher},
};
use rss_transactional_messaging_kafka::*;
use std::time::Duration;
use support::*;

#[derive(Clone, Copy)]
enum Case {
    MutualTls,
    WrongCa,
    WrongHostname,
    WrongClient,
    Scram,
    WrongPassword,
}
impl Case {
    fn id(self) -> &'static str {
        match self {
            Self::MutualTls => "auth-mtls",
            Self::WrongCa => "auth-wrong-ca",
            Self::WrongHostname => "auth-wrong-host",
            Self::WrongClient => "auth-wrong-client",
            Self::Scram => "auth-scram",
            Self::WrongPassword => "auth-wrong-password",
        }
    }
    fn accepted(self) -> bool {
        matches!(self, Self::MutualTls | Self::Scram)
    }
}
fn configured(f: &testkit::KafkaTlsFixture, case: Case) -> anyhow::Result<KafkaConfig> {
    if matches!(case, Case::MutualTls) {
        return config(f);
    }
    let brokers = match case {
        Case::Scram | Case::WrongPassword => f.scram_brokers().to_owned(),
        _ => f.brokers().to_owned(),
    };
    let credentials = match case {
        Case::Scram => {
            KafkaCredentials::scram_sha512(f.scram_username().into(), f.scram_password().into())?
        }
        Case::WrongPassword => KafkaCredentials::scram_sha512(
            f.scram_username().into(),
            "wrong-fixture-password".into(),
        )?,
        Case::WrongClient => KafkaCredentials::mutual_tls(
            f.untrusted_client_certificate_pem().into(),
            f.client_key_pem().into(),
        )?,
        _ => KafkaCredentials::mutual_tls(
            f.client_certificate_pem().into(),
            f.client_key_pem().into(),
        )?,
    };
    Ok(KafkaConfig::new(
        KafkaClientId::parse(&format!("{}-{}", f.topic(), case.id()))?,
        brokers,
        if matches!(case, Case::WrongCa) {
            f.wrong_ca_pem()
        } else {
            f.ca_pem()
        }
        .into(),
        credentials,
        MessagingDomain::parse("events")?,
        [(MessageRoute::parse("event:v1")?, f.topic().into())],
        KafkaLimits::new(1, 1, 4096, Duration::from_secs(2))?,
    )?)
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_kafka_real_authentication_matrix() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(110), async {
        let fixture = testkit::shared_kafka_tls().await?;
        for case in [
            Case::MutualTls,
            Case::WrongCa,
            Case::WrongClient,
            Case::Scram,
            Case::WrongPassword,
        ] {
            let (publisher, resource) =
                KafkaPublisher::create(configured(&fixture, case)?, Duration::from_secs(5)).await?;
            let outcome = publisher
                .publish(&message(case.id())?, deadline(Duration::from_secs(5))?)
                .await;
            drained(&publisher).await?;
            if case.accepted() {
                assert!(
                    matches!(outcome, PublishOutcome::Confirmed(_)),
                    "{} did not authenticate",
                    case.id()
                );
                assert_record(&read_records(&fixture, case.id(), 1).await?[0], case.id());
            } else {
                assert!(
                    !matches!(outcome, PublishOutcome::Confirmed(_)),
                    "{} bypassed authentication",
                    case.id()
                );
                assert_ne!(
                    outcome.failure().map(|f| f.reason()),
                    Some(PublishFailureReason::DeadlineElapsed),
                    "native rejection must arrive before the caller deadline"
                );
                assert!(read_records(&fixture, case.id(), 0).await?.is_empty());
            }
            let closed = resource.shutdown(Duration::from_secs(5)).await;
            assert!(matches!(closed, Ok(()) | Err(KafkaError::OwnerFailed)));
        }
        let mismatch =
            testkit::exclusive_kafka_tls(testkit::KafkaTlsServerIdentity::UnmatchedHost).await?;
        let (publisher, resource) = KafkaPublisher::create(
            configured(&mismatch, Case::WrongHostname)?,
            Duration::from_secs(5),
        )
        .await?;
        let outcome = publisher
            .publish(
                &message(Case::WrongHostname.id())?,
                deadline(Duration::from_secs(5))?,
            )
            .await;
        assert!(!matches!(outcome, PublishOutcome::Confirmed(_)));
        assert_ne!(
            outcome.failure().map(|f| f.reason()),
            Some(PublishFailureReason::DeadlineElapsed)
        );
        drained(&publisher).await?;
        assert_eq!(mismatch.topic_end_offset().await?, 0);
        resource.shutdown(Duration::from_secs(5)).await?;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}
