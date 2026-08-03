//! Closed MQTT downlink routing for DeviceLatent workers.

use std::sync::Arc;

use diport::MessageId;
use mqtt::{MqttSession, MqttSessionError};
use postgres::{PgBrokerAcceptedDeviceOutbox, PgClaimedDeviceOutbox};

/// Assembly-private two-contract routing request.
///
/// Callers cannot construct this from an arbitrary contract or topic. The only constructor below
/// derives it from PostgreSQL's SQL-classified, move-only claim.
enum DeviceMqttPublishRequest {
    ApplyDeviceCertificate {
        tenant: vocab::TenantId,
        device: ids::DeviceId,
        message_id: MessageId,
        payload: Vec<u8>,
    },
    ApplicationReceipt {
        tenant: vocab::TenantId,
        device: ids::DeviceId,
        message_id: MessageId,
        payload: Vec<u8>,
    },
}

impl DeviceMqttPublishRequest {
    fn from_claim(claim: &PgClaimedDeviceOutbox) -> Self {
        let persistent_scope = claim.scope();
        let tenant = persistent_scope.tenant();
        let device = persistent_scope.device();
        let message_id = MessageId::new(claim.message_id());
        let payload = claim.payload().to_vec();
        match claim {
            PgClaimedDeviceOutbox::ApplyDeviceCertificate(_) => Self::ApplyDeviceCertificate {
                tenant,
                device,
                message_id,
                payload,
            },
            PgClaimedDeviceOutbox::DeviceIngressReceipted(_) => Self::ApplicationReceipt {
                tenant,
                device,
                message_id,
                payload,
            },
        }
    }
}

/// Private publisher sharing the pilot's one managed [`MqttSession`] and one driver.
///
/// Publishing consumes a durable claim and can return only the corresponding broker-accepted
/// settlement capability. Raw requests and bare [`diport::BrokerAccepted`] values never leave this
/// boundary.
#[derive(Clone)]
pub(crate) struct DeviceMqttPublisher {
    session: Arc<MqttSession>,
}

impl std::fmt::Debug for DeviceMqttPublisher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DeviceMqttPublisher(<shared-session>)")
    }
}

impl DeviceMqttPublisher {
    #[must_use]
    pub(crate) fn new(session: Arc<MqttSession>) -> Self {
        Self { session }
    }

    pub(crate) async fn publish(
        &self,
        claim: PgClaimedDeviceOutbox,
    ) -> Result<PgBrokerAcceptedDeviceOutbox, MqttSessionError> {
        let request = DeviceMqttPublishRequest::from_claim(&claim);
        let accepted = match request {
            DeviceMqttPublishRequest::ApplyDeviceCertificate {
                tenant,
                device,
                message_id,
                payload,
            } => {
                self.session
                    .send_command(tenant, device, &message_id, payload)
                    .await?
            }
            DeviceMqttPublishRequest::ApplicationReceipt {
                tenant,
                device,
                message_id,
                payload,
            } => {
                self.session
                    .send_application_receipt(tenant, device, &message_id, payload)
                    .await?
            }
        };
        Ok(claim.broker_accepted(accepted))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diport::Publisher;
    use static_assertions::{assert_not_impl_any, assert_type_eq_all};

    assert_not_impl_any!(DeviceMqttPublisher: Publisher);
    assert_not_impl_any!(PgBrokerAcceptedDeviceOutbox: Clone, Copy);
    assert_type_eq_all!(
        PgBrokerAcceptedDeviceOutbox,
        postgres::PgBrokerAcceptedDeviceOutbox
    );

    fn publish_consumes_claim_and_returns_settlement_capability<'a>(
        publisher: &'a DeviceMqttPublisher,
        claim: PgClaimedDeviceOutbox,
    ) -> impl Future<Output = Result<PgBrokerAcceptedDeviceOutbox, MqttSessionError>> + 'a {
        publisher.publish(claim)
    }

    #[test]
    fn publisher_surface_is_claim_bound_and_move_only() {
        let _ = publish_consumes_claim_and_returns_settlement_capability;
    }
}
