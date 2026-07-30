use diport::{ManagedResource, Publisher, Subscriber};
use mqtt::{AuthenticatedDeviceDelivery, BrokerAccepted, MqttReadiness, MqttSession};
use static_assertions::{assert_impl_all, assert_not_impl_any};

assert_impl_all!(MqttSession: ManagedResource, Send, Sync);
assert_not_impl_any!(MqttSession: Publisher, Subscriber, Clone);
assert_not_impl_any!(AuthenticatedDeviceDelivery: Clone, Copy);
assert_not_impl_any!(BrokerAccepted: Clone, Copy);

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
