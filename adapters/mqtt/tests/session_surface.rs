use diport::{ManagedResource, MessageId, Publisher, Subscriber};
use mqtt::{
    AuthenticatedDeviceDelivery, BrokerAccepted, MqttReadiness, MqttSession, MqttSessionError,
};
use static_assertions::{assert_impl_all, assert_not_impl_any};

assert_impl_all!(MqttSession: ManagedResource, Send, Sync);
assert_not_impl_any!(MqttSession: Publisher, Subscriber, Clone);
assert_not_impl_any!(AuthenticatedDeviceDelivery: Clone, Copy);
assert_not_impl_any!(BrokerAccepted: Clone, Copy);

fn application_receipt_publish_is_transport_only<'a>(
    session: &'a MqttSession,
    tenant: vocab::TenantId,
    device: ids::DeviceId,
    message_id: &'a MessageId,
    payload: Vec<u8>,
) -> impl Future<Output = Result<BrokerAccepted, MqttSessionError>> + 'a {
    session.send_application_receipt(tenant, device, message_id, payload)
}

#[test]
fn application_receipt_publish_returns_only_broker_acceptance() {
    let _ = application_receipt_publish_is_transport_only;
}

/// ```compile_fail
/// # async fn bypass(delivery: mqtt::AuthenticatedDeviceDelivery) {
/// delivery.ack().await.unwrap();
/// # }
/// ```
pub struct DirectAckMustNotCompile;

/// A generic repository receipt is domain data, not authority to settle a transport delivery.
///
/// ```compile_fail
/// # async fn bypass<D, R>(delivery: D, repository: &R) {
/// let _ = identity::ports::device_certificate::run_device_ingress(delivery, repository).await;
/// # }
/// ```
pub struct GenericRepositoryCannotAuthorizePuback;

/// ```compile_fail
/// # fn bypass(delivery: &mqtt::AuthenticatedDeviceDelivery) {
/// let _ = delivery.to_message("event-1");
/// # }
/// ```
pub struct GenericMessageEscapeMustNotCompile;

#[test]
fn readiness_is_a_closed_non_sensitive_state() {
    let states = [
        MqttReadiness::Starting,
        MqttReadiness::Ready {
            session_present: false,
            credential_revision: 1,
        },
        MqttReadiness::Ready {
            session_present: true,
            credential_revision: 2,
        },
        MqttReadiness::Reloading {
            from_revision: 1,
            to_revision: 2,
        },
        MqttReadiness::Degraded {
            credential_revision: 2,
        },
        MqttReadiness::Stopped,
    ];
    for state in states {
        let rendered = format!("{state:?}");
        assert!(!rendered.contains("BEGIN CERTIFICATE"));
        assert!(!rendered.contains("PRIVATE KEY"));
        assert!(!rendered.contains("mqtts://"));
    }
}
