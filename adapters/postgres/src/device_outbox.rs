//! Exact PostgreSQL DeviceLatent MQTT outbox boundary.
//!
//! The generic identity outbox contains more contracts than the device transport may publish.
//! This adapter therefore claims the two MQTT contracts in SQL, returns a closed move-only claim,
//! and consumes that claim when a broker PUBACK is durably settled. It deliberately owns no
//! generic [`diport::Publisher`] and does not implement [`consistency::OutboxRelay`].

use consistency::{EngineError, EngineErrorKind, IdemKey};
use diport::BrokerAccepted;
use eventing::delivery::DeliveryBudget;
use ids::DeviceId;

use crate::cotx::eventing::{DeviceMqttPubackMutation, OutboxSettlementFence};
use crate::cotx::{ServingWriteLane, TenantDb, infra_tenant_scope, io_deadline_after};
use crate::outbox::OutboxLease;

const DEVICE_OUTBOX_CLAIM_BATCH_MAX: usize = 10_000;
const APPLY_DEVICE_CERTIFICATE: &str = "identity.apply-device-certificate";
const DEVICE_INGRESS_RECEIPTED: &str = "identity.device-ingress-receipted";

/// Exact raw claim lane for the cross-tenant device relay funnel. Tenant table operations remain
/// behind [`TenantDb`]; this capability can execute only the fixed SECURITY DEFINER claim entry.
#[derive(Clone)]
pub(crate) struct PgDeviceOutboxClaimPool(sqlx::PgPool);

impl PgDeviceOutboxClaimPool {
    pub(crate) fn new(pool: sqlx::PgPool) -> Self {
        Self(pool)
    }
}

#[derive(sqlx::FromRow)]
struct ClaimedDeviceOutboxRow {
    tenant_id: String,
    device_id: String,
    contract_id: String,
    event_id: String,
    payload: Vec<u8>,
    expected_command_version: Option<i64>,
    lease_token: String,
    deadline_epoch_micros: i64,
}

/// Stable tenant/device routing coordinate returned by the exact PostgreSQL claim.
///
/// The MQTT adapter resolves its configured credential generation for this device; storage never
/// accepts a caller-provided topic or credential scope while classifying an outbox row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PgDeviceOutboxScope {
    tenant: rss_request_context::TenantId,
    device: DeviceId,
}

impl PgDeviceOutboxScope {
    #[must_use]
    pub const fn tenant(&self) -> rss_request_context::TenantId {
        self.tenant
    }

    #[must_use]
    pub const fn device(&self) -> DeviceId {
        self.device
    }
}

struct DeviceOutboxClaim {
    scope: PgDeviceOutboxScope,
    message_id: IdemKey,
    payload: Vec<u8>,
    expected_command_version: Option<deviceloop::CommandVersion>,
    lease: OutboxLease,
}

impl std::fmt::Debug for DeviceOutboxClaim {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceOutboxClaim")
            .field("scope", &self.scope)
            .field("message_id", &"<redacted>")
            .field("payload", &"<redacted>")
            .field("expected_command_version", &self.expected_command_version)
            .field("lease", &self.lease)
            .finish()
    }
}

/// Move-only claim for `identity.apply-device-certificate`.
pub struct PgClaimedDeviceCommand(DeviceOutboxClaim);

/// Move-only claim for `identity.device-ingress-receipted`.
pub struct PgClaimedDeviceIngressReceipt(DeviceOutboxClaim);

macro_rules! impl_claim_accessors {
    ($claim:ty) => {
        impl $claim {
            #[must_use]
            pub const fn scope(&self) -> PgDeviceOutboxScope {
                self.0.scope
            }

            #[must_use]
            pub fn message_id(&self) -> &str {
                self.0.message_id.as_str()
            }

            #[must_use]
            pub fn payload(&self) -> &[u8] {
                &self.0.payload
            }
        }
    };
}

impl_claim_accessors!(PgClaimedDeviceCommand);
impl_claim_accessors!(PgClaimedDeviceIngressReceipt);

impl std::fmt::Debug for PgClaimedDeviceCommand {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("PgClaimedDeviceCommand")
            .field(&self.0)
            .finish()
    }
}

impl std::fmt::Debug for PgClaimedDeviceIngressReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("PgClaimedDeviceIngressReceipt")
            .field(&self.0)
            .finish()
    }
}

/// Closed, SQL-classified set of device MQTT outbox claims.
///
/// Neither this enum nor either variant payload implements `Clone`; settlement consumes it by
/// value so one process cannot reuse a PUBACK capability for two durable mutations.
#[derive(Debug)]
pub enum PgClaimedDeviceOutbox {
    ApplyDeviceCertificate(PgClaimedDeviceCommand),
    DeviceIngressReceipted(PgClaimedDeviceIngressReceipt),
}

impl PgClaimedDeviceOutbox {
    #[must_use]
    pub const fn scope(&self) -> PgDeviceOutboxScope {
        self.claim().scope
    }

    #[must_use]
    pub fn message_id(&self) -> &str {
        self.claim().message_id.as_str()
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.claim().payload
    }

    const fn claim(&self) -> &DeviceOutboxClaim {
        match self {
            Self::ApplyDeviceCertificate(claim) => &claim.0,
            Self::DeviceIngressReceipted(claim) => &claim.0,
        }
    }

    /// Bind this durable, move-only claim to the exact broker PUBACK proof.
    ///
    /// The returned settlement capability owns both values, so neither the claim nor the broker
    /// proof can be reused for a second durable mutation.
    #[must_use]
    pub fn broker_accepted(self, accepted: BrokerAccepted) -> PgBrokerAcceptedDeviceOutbox {
        PgBrokerAcceptedDeviceOutbox {
            claimed: self,
            _accepted: accepted,
        }
    }

    fn into_claim(self) -> Result<(DeviceOutboxClaim, DeviceMqttPubackMutation), EngineError> {
        match self {
            Self::ApplyDeviceCertificate(claim) => {
                let expected_version = claim
                    .0
                    .expected_command_version
                    .ok_or_else(|| EngineError::new(EngineErrorKind::Invariant))?
                    .get();
                Ok((
                    claim.0,
                    DeviceMqttPubackMutation::Command { expected_version },
                ))
            }
            Self::DeviceIngressReceipted(claim) => Ok((claim.0, DeviceMqttPubackMutation::Receipt)),
        }
    }
}

impl From<PgClaimedDeviceCommand> for PgClaimedDeviceOutbox {
    fn from(claim: PgClaimedDeviceCommand) -> Self {
        Self::ApplyDeviceCertificate(claim)
    }
}

impl From<PgClaimedDeviceIngressReceipt> for PgClaimedDeviceOutbox {
    fn from(claim: PgClaimedDeviceIngressReceipt) -> Self {
        Self::DeviceIngressReceipted(claim)
    }
}

/// One-shot settlement capability coupling a durable PostgreSQL claim to broker acceptance.
///
/// Fields are private and the type is move-only. It can be minted only by consuming both a
/// [`PgClaimedDeviceOutbox`] and provider-owned [`BrokerAccepted`] evidence.
pub struct PgBrokerAcceptedDeviceOutbox {
    claimed: PgClaimedDeviceOutbox,
    _accepted: BrokerAccepted,
}

impl std::fmt::Debug for PgBrokerAcceptedDeviceOutbox {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PgBrokerAcceptedDeviceOutbox")
            .field("claimed", &self.claimed)
            .field("broker_accepted", &"<move-only-proof>")
            .finish()
    }
}

/// Closed durable result of consuming one move-only broker PUBACK claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgDeviceOutboxSettlement {
    Settled,
    Expired,
    LostLease,
}

/// Narrow device MQTT outbox derived from the combined PostgreSQL command/outbox provider.
pub struct PgDeviceOutbox {
    claim_pool: PgDeviceOutboxClaimPool,
    tenant_pool: TenantDb<ServingWriteLane>,
    relay_budget: DeliveryBudget,
}

impl PgDeviceOutbox {
    pub(crate) fn from_command_store(
        claim_pool: PgDeviceOutboxClaimPool,
        tenant_pool: TenantDb<ServingWriteLane>,
        relay_budget: DeliveryBudget,
    ) -> Self {
        Self {
            claim_pool,
            tenant_pool,
            relay_budget,
        }
    }

    /// Atomically lease only draft `identity.apply-device-certificate` rows.
    ///
    /// A stale `publishing` lease is reclaimed with the same message id, scope and payload. A crash
    /// after broker PUBACK but before [`Self::settle_puback`] therefore remains at-least-once and
    /// recoverable without advancing command state prematurely.
    pub async fn claim_commands(
        &self,
        limit: usize,
    ) -> Result<Vec<PgClaimedDeviceCommand>, EngineError> {
        self.claim_kind(ClaimKind::Command, limit)
            .await?
            .into_iter()
            .map(|claim| match claim {
                PgClaimedDeviceOutbox::ApplyDeviceCertificate(claim) => Ok(claim),
                PgClaimedDeviceOutbox::DeviceIngressReceipted(_) => {
                    Err(EngineError::new(EngineErrorKind::Invariant))
                }
            })
            .collect()
    }

    /// Atomically lease only `identity.device-ingress-receipted` rows.
    pub async fn claim_receipts(
        &self,
        limit: usize,
    ) -> Result<Vec<PgClaimedDeviceIngressReceipt>, EngineError> {
        self.claim_kind(ClaimKind::Receipt, limit)
            .await?
            .into_iter()
            .map(|claim| match claim {
                PgClaimedDeviceOutbox::DeviceIngressReceipted(claim) => Ok(claim),
                PgClaimedDeviceOutbox::ApplyDeviceCertificate(_) => {
                    Err(EngineError::new(EngineErrorKind::Invariant))
                }
            })
            .collect()
    }

    async fn claim_kind(
        &self,
        kind: ClaimKind,
        limit: usize,
    ) -> Result<Vec<PgClaimedDeviceOutbox>, EngineError> {
        if !(1..=DEVICE_OUTBOX_CLAIM_BATCH_MAX).contains(&limit) {
            return Err(EngineError::new(EngineErrorKind::Invariant));
        }
        let limit =
            i64::try_from(limit).map_err(|_| EngineError::new(EngineErrorKind::Invariant))?;
        let mut tx = self
            .claim_pool
            .0
            .begin()
            .await
            .map_err(|error| map_storage(error, "device_outbox_claim_begin"))?;
        let monotonic_deadline = io_deadline_after(self.relay_budget.lease_ttl());
        let rows: Vec<ClaimedDeviceOutboxRow> = sqlx::query_as(
            "SELECT tenant_id,device_id,contract_id,event_id,payload, \
             expected_command_version, \
             lease_token,deadline_epoch_micros \
             FROM public.rss_claim_device_mqtt_outbox($1,$2,$3,$4)",
        )
        .bind(kind.as_sql())
        .bind(limit)
        .bind(self.relay_budget.lease_ttl().as_millis() as i64)
        .bind(self.relay_budget.required_budget().as_millis() as i64)
        .fetch_all(&mut *tx)
        .await
        .map_err(|error| map_storage(error, "device_outbox_claim"))?;

        let claims = rows
            .into_iter()
            .map(|row| hydrate_claim(row, monotonic_deadline))
            .collect::<Result<Vec<_>, _>>()?;
        tx.commit()
            .await
            .map_err(|error| map_storage(error, "device_outbox_claim_commit"))?;
        Ok(claims)
    }

    /// Consume a broker-accepted claim capability and durably settle its exact claim.
    ///
    /// Command settlement advances `Queued -> Published` and the outbox row atomically. Receipt
    /// settlement touches only its outbox row. Every non-settled outcome consumes the stale claim;
    /// the SQL lease remains authoritative for later reclaim.
    pub async fn settle_puback(
        &self,
        accepted: PgBrokerAcceptedDeviceOutbox,
    ) -> Result<PgDeviceOutboxSettlement, EngineError> {
        self.settle_accepted(accepted).await
    }

    async fn settle_accepted(
        &self,
        accepted: PgBrokerAcceptedDeviceOutbox,
    ) -> Result<PgDeviceOutboxSettlement, EngineError> {
        let PgBrokerAcceptedDeviceOutbox {
            claimed,
            _accepted: broker_accepted,
        } = accepted;
        let _consumed_broker_acceptance = broker_accepted;
        let (claimed, mutation) = claimed.into_claim()?;
        let now = io_deadline_after(std::time::Duration::ZERO);
        if now >= claimed.lease.monotonic_deadline() {
            return Ok(PgDeviceOutboxSettlement::Expired);
        }
        let deadline = claimed
            .lease
            .monotonic_deadline()
            .min(io_deadline_after(self.relay_budget.settle_timeout()));
        let tenant = claimed.scope.tenant;
        let event_id = claimed.message_id.as_str().to_owned();
        let lease_token = claimed.lease.token().to_owned();
        let lease_deadline_epoch_micros = claimed.lease.deadline_epoch_micros();
        let raw = self
            .tenant_pool
            .outbox_deadline_write(
                infra_tenant_scope(tenant),
                deadline,
                move |mut tx| {
                    Box::pin(async move {
                        tx.outbox_settle_device_mqtt_puback(
                            OutboxSettlementFence {
                                event_id: &event_id,
                                lease_token: &lease_token,
                                lease_deadline_epoch_micros,
                            },
                            mutation,
                        )
                        .await
                        .map_err(|error| map_storage(error, "device_outbox_settle"))
                    })
                },
                |error| map_storage(error, "device_outbox_settle_transaction"),
                || EngineError::new(EngineErrorKind::Transient),
            )
            .await?;
        parse_settlement(&raw)
    }
}

#[derive(Clone, Copy)]
enum ClaimKind {
    Command,
    Receipt,
}

impl ClaimKind {
    const fn as_sql(self) -> i16 {
        match self {
            Self::Command => 1,
            Self::Receipt => 2,
        }
    }
}

fn hydrate_claim(
    row: ClaimedDeviceOutboxRow,
    monotonic_deadline: tokio::time::Instant,
) -> Result<PgClaimedDeviceOutbox, EngineError> {
    let tenant = rss_request_context::TenantId::parse(&row.tenant_id)
        .map_err(|_| EngineError::new(EngineErrorKind::Invariant))?;
    let device = DeviceId::parse(&row.device_id)
        .map_err(|_| EngineError::new(EngineErrorKind::Invariant))?;
    let message_id =
        IdemKey::parse(&row.event_id).map_err(|_| EngineError::new(EngineErrorKind::Invariant))?;
    let lease = OutboxLease::hydrate(
        row.lease_token,
        row.deadline_epoch_micros,
        monotonic_deadline,
    )
    .map_err(|_| EngineError::new(EngineErrorKind::Invariant))?;
    let scope = PgDeviceOutboxScope { tenant, device };

    match (row.contract_id.as_str(), row.expected_command_version) {
        (APPLY_DEVICE_CERTIFICATE, Some(version)) => {
            let expected_command_version = deviceloop::CommandVersion::restore(version)
                .map_err(|_| EngineError::new(EngineErrorKind::Invariant))?;
            Ok(PgClaimedDeviceOutbox::ApplyDeviceCertificate(
                PgClaimedDeviceCommand(DeviceOutboxClaim {
                    scope,
                    message_id,
                    payload: row.payload,
                    expected_command_version: Some(expected_command_version),
                    lease,
                }),
            ))
        }
        (DEVICE_INGRESS_RECEIPTED, None) => Ok(PgClaimedDeviceOutbox::DeviceIngressReceipted(
            PgClaimedDeviceIngressReceipt(DeviceOutboxClaim {
                scope,
                message_id,
                payload: row.payload,
                expected_command_version: None,
                lease,
            }),
        )),
        _ => Err(EngineError::new(EngineErrorKind::Invariant)),
    }
}

fn parse_settlement(raw: &str) -> Result<PgDeviceOutboxSettlement, EngineError> {
    match raw {
        "settled" => Ok(PgDeviceOutboxSettlement::Settled),
        "expired" => Ok(PgDeviceOutboxSettlement::Expired),
        "lost_lease" => Ok(PgDeviceOutboxSettlement::LostLease),
        _ => Err(EngineError::new(EngineErrorKind::Invariant)),
    }
}

fn map_storage(error: sqlx::Error, phase: &'static str) -> EngineError {
    tracing::warn!(
        target: "postgres",
        phase,
        error = %secure::redact_error(&error),
        "device mqtt outbox operation failed"
    );
    EngineError::new(EngineErrorKind::Transient)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(contract_id: &str, expected_command_version: Option<i64>) -> ClaimedDeviceOutboxRow {
        ClaimedDeviceOutboxRow {
            tenant_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            device_id: "22222222-2222-4222-8222-222222222222".to_owned(),
            contract_id: contract_id.to_owned(),
            event_id: "device-message-1".to_owned(),
            payload: vec![1, 2, 3],
            expected_command_version,
            lease_token: "33333333-3333-4333-8333-333333333333".to_owned(),
            deadline_epoch_micros: 1,
        }
    }

    #[test]
    fn hydration_returns_the_closed_contract_variants() {
        let deadline = io_deadline_after(std::time::Duration::from_secs(1));
        let command = hydrate_claim(row(APPLY_DEVICE_CERTIFICATE, Some(1)), deadline)
            .expect("valid command claim");
        assert!(matches!(
            command,
            PgClaimedDeviceOutbox::ApplyDeviceCertificate(_)
        ));

        let receipt = hydrate_claim(row(DEVICE_INGRESS_RECEIPTED, None), deadline)
            .expect("valid receipt claim");
        assert!(matches!(
            receipt,
            PgClaimedDeviceOutbox::DeviceIngressReceipted(_)
        ));
    }

    #[test]
    fn hydration_rejects_contract_or_command_version_shape_drift() {
        let deadline = io_deadline_after(std::time::Duration::from_secs(1));
        assert!(hydrate_claim(row("identity.some-other-fact", None), deadline).is_err());
        assert!(hydrate_claim(row(APPLY_DEVICE_CERTIFICATE, None), deadline).is_err());
        assert!(hydrate_claim(row(DEVICE_INGRESS_RECEIPTED, Some(1)), deadline).is_err());
    }

    #[test]
    fn public_claim_accessors_keep_stable_transport_coordinates() {
        let claim = hydrate_claim(
            row(APPLY_DEVICE_CERTIFICATE, Some(1)),
            io_deadline_after(std::time::Duration::from_secs(1)),
        )
        .expect("valid claim");
        assert_eq!(claim.message_id(), "device-message-1");
        assert_eq!(claim.payload(), [1, 2, 3]);
        assert_eq!(
            claim.scope().device().as_uuid().hyphenated().to_string(),
            "22222222-2222-4222-8222-222222222222"
        );
    }

    #[cfg(feature = "integration")]
    fn relay_budget() -> Result<DeliveryBudget, eventing::delivery::DeliveryBudgetError> {
        DeliveryBudget::new(
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(40),
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
        )
    }

    #[cfg(feature = "integration")]
    #[tokio::test(flavor = "multi_thread")]
    async fn real_postgres_reclaims_stable_command_and_atomically_settles_pubacks()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use diport::ManagedResource as _;

        const TENANT: &str = "11111111-1111-4111-8111-111111111111";
        const DEVICE: &str = "22222222-2222-4222-8222-222222222222";
        const COMMAND_ID: &str = "device-command-outbox-1";
        const RECEIPT_ID: &str = "device-receipt-outbox-1";
        const OTHER_ID: &str = "identity-other-outbox-1";
        const SCHEMA_HASH: &str =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let (fixture, owner) = crate::test_pg::connect_pg().await?;
        owner.run_migrations().await?;
        let privilege_shape: (bool, bool, bool, bool, bool) = sqlx::query_as(
            "SELECT \
             pg_catalog.has_table_privilege( \
               'rss_outbox_maintenance','public.device_commands','SELECT'), \
             pg_catalog.has_table_privilege( \
               'rss_device_mqtt_outbox_owner','public.device_commands','SELECT'), \
             pg_catalog.has_column_privilege( \
               'rss_device_mqtt_outbox_owner','public.device_commands','generation','SELECT'), \
             pg_catalog.has_column_privilege( \
               'rss_device_mqtt_outbox_owner','public.device_commands','intent_digest','SELECT'), \
             pg_catalog.has_function_privilege( \
               'rss_app', \
               'public.rss_load_draft_device_mqtt_command_claim(uuid,text)', \
               'EXECUTE')",
        )
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(privilege_shape, (false, false, true, false, false));
        let command_metadata = serde_json::json!({
            "tenantId": TENANT,
            "schemaVersion": "v1",
            "schemaHash": SCHEMA_HASH,
            "subjectId": DEVICE,
        });
        let receipt_metadata = serde_json::json!({
            "tenantId": TENANT,
            "schemaVersion": "v1",
            "schemaHash": SCHEMA_HASH,
            "subjectId": DEVICE,
            "credentialGeneration": 7,
        });

        crate::integration_tests::support::DevicePolicyLineageFixture::new(&owner, TENANT, DEVICE)?
            .with_policy(3_600, 300, true, false, &[])
            .seed(7)
            .await?;
        sqlx::raw_sql(
            "INSERT INTO public.reconcile_targets \
               (tenant_id,target_id,reconciler_id,resource_kind,resource_id) \
             VALUES \
               ('11111111-1111-4111-8111-111111111111', \
                '44444444-4444-4444-8444-444444444444', \
                'identity.device-certificate','device-certificate', \
                '22222222-2222-4222-8222-222222222222'); \
             INSERT INTO public.reconcile_leases (tenant_id,target_id,state,epoch) \
             VALUES \
               ('11111111-1111-4111-8111-111111111111', \
                '44444444-4444-4444-8444-444444444444','free',1);",
        )
        .execute(&owner.pool)
        .await?;
        sqlx::query(
            "INSERT INTO public.device_commands \
               (tenant_id,command_id,device_id,generation,fence_epoch,artifact_eligibility, \
                intent_digest,deadline,state,version,queued_at) \
             VALUES ($1::uuid,$2,$3::uuid,7,1,'draft',decode(repeat('22',32),'hex'), \
                     clock_timestamp()+interval '1 hour','queued',1,clock_timestamp())",
        )
        .bind(TENANT)
        .bind(COMMAND_ID)
        .bind(DEVICE)
        .execute(&owner.pool)
        .await?;
        for (event_id, contract_id, metadata, payload) in [
            (
                COMMAND_ID,
                APPLY_DEVICE_CERTIFICATE,
                command_metadata.to_string(),
                b"command-payload".as_slice(),
            ),
            (
                RECEIPT_ID,
                DEVICE_INGRESS_RECEIPTED,
                receipt_metadata.to_string(),
                b"receipt-payload".as_slice(),
            ),
            (
                OTHER_ID,
                "identity.some-other-fact",
                command_metadata.to_string(),
                b"other-payload".as_slice(),
            ),
        ] {
            sqlx::query(
                "INSERT INTO public.outbox \
                   (event_id,tenant_id,domain,topic,contract_id,contract_version,schema_hash, \
                    payload,metadata,partition_key,causation_id) \
                 VALUES ($1,$2::uuid,'identity',$3,$4,'v1',$5,$6,$7::jsonb,NULL,NULL)",
            )
            .bind(event_id)
            .bind(TENANT)
            .bind(contract_id)
            .bind(contract_id)
            .bind(SCHEMA_HASH)
            .bind(payload)
            .bind(metadata)
            .execute(&owner.pool)
            .await?;
        }

        let app = crate::test_pg::connect_pg_rss_app_role(&fixture, &owner).await?;
        let store = crate::PgDeviceCommandStore::<
            identity::ports::device_certificate::DraftEligibility,
        >::from_unverified_stores_for_test(&app, &app);
        let outbox = store.device_outbox(relay_budget()?);

        let mut command_claims = outbox.claim_commands(10).await?;
        if command_claims.len() != 1 {
            return Err(std::io::Error::other("expected one command claim").into());
        }
        let command = command_claims
            .pop()
            .ok_or_else(|| std::io::Error::other("missing command claim"))?;
        let stable_message_id = command.message_id().to_owned();
        let stable_scope = command.scope();
        let stable_payload = command.payload().to_vec();
        assert_eq!(
            stable_scope.tenant(),
            rss_request_context::TenantId::parse(TENANT)?
        );
        assert_eq!(stable_scope.device(), DeviceId::parse(DEVICE)?);

        let receipt_status: String =
            sqlx::query_scalar("SELECT status FROM outbox WHERE event_id=$1")
                .bind(RECEIPT_ID)
                .fetch_one(&owner.pool)
                .await?;
        assert_eq!(
            receipt_status, "pending",
            "command claim must not lease receipt"
        );

        // Model a process crash after broker PUBACK and before settlement by expiring only the
        // persisted lease. The command remains queued until the reclaimed claim is settled.
        sqlx::query(
            "UPDATE outbox SET updated_at=clock_timestamp()-interval '2 minutes', \
                    lease_until=clock_timestamp()-interval '1 minute' WHERE event_id=$1",
        )
        .bind(COMMAND_ID)
        .execute(&owner.pool)
        .await?;
        drop(command);

        let mut receipt_claims = outbox.claim_receipts(10).await?;
        if receipt_claims.len() != 1 {
            return Err(std::io::Error::other("expected one receipt claim").into());
        }
        let receipt = receipt_claims
            .pop()
            .ok_or_else(|| std::io::Error::other("missing receipt claim"))?;
        assert_eq!(receipt.scope(), stable_scope);
        let receipt = PgClaimedDeviceOutbox::from(receipt)
            .broker_accepted(diport::test_support::broker_accepted());
        assert_eq!(
            outbox.settle_accepted(receipt).await?,
            PgDeviceOutboxSettlement::Settled
        );

        let mut reclaimed = outbox.claim_commands(10).await?;
        if reclaimed.len() != 1 {
            return Err(std::io::Error::other("expected one reclaimed command").into());
        }
        let reclaimed = reclaimed
            .pop()
            .ok_or_else(|| std::io::Error::other("missing reclaimed command"))?;
        assert_eq!(reclaimed.message_id(), stable_message_id);
        assert_eq!(reclaimed.scope(), stable_scope);
        assert_eq!(reclaimed.payload(), stable_payload);
        let before: (String, i64) = sqlx::query_as(
            "SELECT state,version FROM device_commands WHERE tenant_id=$1::uuid AND command_id=$2",
        )
        .bind(TENANT)
        .bind(COMMAND_ID)
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(before, ("queued".to_owned(), 1));
        let reclaimed = PgClaimedDeviceOutbox::from(reclaimed)
            .broker_accepted(diport::test_support::broker_accepted());
        assert_eq!(
            outbox.settle_accepted(reclaimed).await?,
            PgDeviceOutboxSettlement::Settled
        );

        let after: (String, i64, String, String, String) = sqlx::query_as(
            "SELECT command.state,command.version,command_outbox.status,receipt_outbox.status, \
                    other_outbox.status \
             FROM device_commands AS command \
             JOIN outbox AS command_outbox ON command_outbox.event_id=command.command_id \
             JOIN outbox AS receipt_outbox ON receipt_outbox.event_id=$3 \
             JOIN outbox AS other_outbox ON other_outbox.event_id=$4 \
             WHERE command.tenant_id=$1::uuid AND command.command_id=$2",
        )
        .bind(TENANT)
        .bind(COMMAND_ID)
        .bind(RECEIPT_ID)
        .bind(OTHER_ID)
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(
            after,
            (
                "published".to_owned(),
                2,
                "published".to_owned(),
                "published".to_owned(),
                "pending".to_owned(),
            )
        );

        app.shutdown().await?;
        owner.shutdown().await?;
        drop(fixture);
        Ok(())
    }
}
