use consistency::{Disposition, EngineError, OutboxMetricSubject, OutboxRelay};

mod provider {
    use super::*;

    pub struct Claim {
        subject: OutboxMetricSubject,
        lease_token: String,
        deadline_epoch_micros: i64,
    }

    pub struct Store {
        domain: vocab::DomainName,
    }

    impl OutboxRelay for Store {
        type Claim = Claim;

        fn claim_subject(claim: &Self::Claim) -> &OutboxMetricSubject {
            &claim.subject
        }

        fn claim_domain(&self) -> &vocab::DomainName {
            &self.domain
        }

        async fn claim_batch(&self, _limit: usize) -> Result<Vec<Self::Claim>, EngineError> {
            Ok(Vec::new())
        }

        async fn relay(&self, _claim: Self::Claim) -> Result<Disposition, EngineError> {
            Ok(Disposition::Ack)
        }
    }
}

fn main() {
    let tenant = rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap();
    let subject = consistency::OutboxMetricSubject::new(
        tenant,
        consistency::OutboxContractId::parse("runtime.fact-recorded").unwrap(),
    );
    let _ = provider::Claim {
        subject,
        lease_token: "forged".into(),
        deadline_epoch_micros: 1,
    };
}
