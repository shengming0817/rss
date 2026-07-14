use consistency::{Disposition, EngineError, OutboxMetricSubject, OutboxRelay};

mod provider {
    use super::*;

    pub struct Claim {
        subject: OutboxMetricSubject,
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

async fn drives_claimed<S: OutboxRelay>(store: &S) -> Result<(), EngineError> {
    let _: &vocab::DomainName = store.claim_domain();
    for claim in store.claim_batch(10).await? {
        let _ = S::claim_subject(&claim);
        let _ = store.relay(claim).await?;
    }
    Ok(())
}

fn main() {}
