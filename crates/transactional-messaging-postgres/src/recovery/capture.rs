use super::PgRecoveryCapture;
use crate::{ConsumerRecoveryMode, PgConsumerEffectFailure, PgInboxClaim, PgTransaction};
use rss_data_protection::Aead;
use rss_transactional_messaging::{
    message::MessageEnvelope,
    transaction::{ReceiptIntent, TerminalDisposition},
};
use rss_transactional_messaging_recovery::{
    DeadLetterId,
    protection::{CaptureContext, seal},
};
impl<K> crate::consumer::sealed::Mode for PgRecoveryCapture<K> {}
impl<P: AsRef<[u8]> + Sync, K: Aead + Send + Sync> ConsumerRecoveryMode<P>
    for PgRecoveryCapture<K>
{
    async fn record(
        &self,
        tx: &mut PgTransaction<'_>,
        claim: &PgInboxClaim,
        message: &MessageEnvelope<P>,
        intent: &ReceiptIntent,
        disposition: TerminalDisposition,
    ) -> Result<(), PgConsumerEffectFailure> {
        if !tx.belongs_to(&self.runtime) {
            return Err(PgConsumerEffectFailure::infrastructure(
                crate::PgError::invariant(),
            ));
        }
        let id = DeadLetterId::new();
        let context =
            CaptureContext::from_provider(id, claim.identity.clone(), intent.fingerprint());
        let capsule = seal(self.key.as_ref(), &context, message)
            .map_err(PgConsumerEffectFailure::infrastructure)?;
        let identity = context.consumer();
        let contract = identity.contract();
        let result = sqlx::query("INSERT INTO rss_transactional_messaging.consumer_dead_letter (tenant_id,id,message_id,consumer_group,contract,contract_version,schema_digest,fingerprint,capsule,reason) VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (tenant_id,message_id,consumer_group) DO NOTHING")
            .bind(identity.tenant_id().to_string()).bind(id.to_string()).bind(identity.message_id().as_str()).bind(identity.group().as_str()).bind(contract.id().as_str()).bind(contract.version().to_string()).bind(contract.schema_digest().as_str()).bind(intent.fingerprint().as_bytes().as_slice()).bind(capsule.bytes()).bind(disposition.as_label()).execute(&mut *tx.connection).await.map_err(PgConsumerEffectFailure::infrastructure)?;
        // An extant row while the Inbox is still nonterminal violates the atomic capture contract.
        if result.rows_affected() != 1 {
            return Err(PgConsumerEffectFailure::infrastructure(
                crate::PgError::invariant(),
            ));
        }
        Ok(())
    }
}
