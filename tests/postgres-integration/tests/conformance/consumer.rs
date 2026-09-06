use super::*;
use rss_transactional_messaging::observability::{
    TransactionalMessagingEmitter, TransactionalMessagingObservation,
};
use rss_transactional_messaging::transport::Delivery;
use rss_transactional_messaging_runtime::consumer::{
    ConsumerExecution, ProcessingDisposition, consume_once,
};
use rss_transactional_messaging_testkit::{
    consumer::ConsumerTxDriver, memory::RecordingSettlement,
};

#[derive(Default)]
struct Emitter(Mutex<Vec<TransactionalMessagingObservation>>);
impl TransactionalMessagingEmitter for Emitter {
    fn emit(&self, observation: TransactionalMessagingObservation) {
        self.0.lock().expect("observations").push(observation);
    }
}
struct FaultTransaction<'a> {
    inner: PgConsumerTx<Effect>,
    runtime: &'a PgRuntime,
    owner: &'a sqlx::PgPool,
    fault: u8,
}
impl ConsumerTx<Vec<u8>> for FaultTransaction<'_> {
    type Claim = PgInboxClaim;
    type CommitProof = <PgConsumerTx<Effect> as ConsumerTx<Vec<u8>>>::CommitProof;
    async fn execute(
        &self,
        claim: &Self::Claim,
        message: &MessageEnvelope<Vec<u8>>,
        intent: ReceiptIntent,
        deadline: OperationDeadline,
    ) -> TransactionOutcome<Self::CommitProof> {
        match self.fault {
            1 => self
                .runtime
                .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck),
            2 => {
                sqlx::query("UPDATE rss_transactional_messaging.inbox SET lease_until=clock_timestamp()-interval '1 second' WHERE message_id=$1")
                .bind(message.id().as_str()).execute(self.owner).await.expect("expire claim before effect");
            }
            _ => {}
        }
        self.inner.execute(claim, message, intent, deadline).await
    }
}
impl Harness {
    async fn consume(
        &self,
        fault: u8,
    ) -> Result<
        (
            ProcessingDisposition,
            Vec<TransactionalMessagingObservation>,
            usize,
        ),
        ConformanceError,
    > {
        let message = message(&self.id());
        let m = message.metadata();
        let subscription =
            SubscriptionIdentity::new(m.domain().clone(), m.route().clone(), m.contract().clone());
        let timer = Timer::new();
        let emitter = Emitter::default();
        let execution = ConsumerExecution::new(
            ConsumerGroup::parse("suite").expect("group"),
            &Validator,
            &subscription,
            &timer,
            ConsumerExecutionPolicy::new(RetryPolicy::STANDARD, ExecutionBudget::STANDARD),
            &emitter,
        );
        let transaction = FaultTransaction {
            inner: PgConsumerTx::new(self.runtime.clone(), Effect(TerminalDisposition::Succeeded)),
            runtime: &self.runtime,
            owner: &self.owner,
            fault,
        };
        let actions = Arc::new(Mutex::new(Vec::new()));
        let abandons = Arc::new(AtomicUsize::new(0));
        // Keep the concrete provider future off the conformance runner stack.
        let result = Box::pin(consume_once(
            &self.inbox(),
            &transaction,
            &execution,
            Delivery::new(
                message,
                RecordingSettlement::observing(actions, abandons.clone()),
            ),
        ))
        .await
        .map_err(conformance)?;
        let observations = std::mem::take(&mut *emitter.0.lock().expect("observations"));
        Ok((result, observations, abandons.load(Ordering::SeqCst)))
    }
}
impl ConsumerTxDriver for Harness {
    fn reset(&self) {
        self.reset_case();
    }
    async fn committed_delivery(
        &self,
    ) -> Result<Vec<TransactionalMessagingObservation>, ConformanceError> {
        let (_, observations, _) = self.consume(0).await?;
        assert_eq!(self.count().await, 1);
        Ok(observations)
    }
    async fn duplicate_delivery(
        &self,
    ) -> Result<(TerminalDisposition, Vec<TransactionalMessagingObservation>), ConformanceError>
    {
        self.consume(0).await?;
        let (result, observations, _) = self.consume(0).await?;
        assert_eq!(self.count().await, 1);
        match result {
            ProcessingDisposition::Duplicate(value) => Ok((value, observations)),
            _ => Err(ConformanceError::delivery(MessagingErrorKind::Invariant)),
        }
    }
    async fn commit_unknown_delivery(
        &self,
    ) -> Result<(Vec<TransactionalMessagingObservation>, usize), ConformanceError> {
        let (_, observations, abandons) = self.consume(1).await?;
        assert_eq!(
            self.count().await,
            1,
            "ACK uncertainty does not erase a real commit"
        );
        Ok((observations, abandons))
    }
    async fn lease_lost_delivery(
        &self,
    ) -> Result<(Vec<TransactionalMessagingObservation>, usize), ConformanceError> {
        let (_, observations, abandons) = self.consume(2).await?;
        assert_eq!(self.count().await, 0);
        Ok((observations, abandons))
    }
}
