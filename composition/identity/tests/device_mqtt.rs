#![cfg(feature = "device-mqtt")]

use identity::ports::device_certificate::{DeviceIngressDomainOutcome, PendingDeviceIngress};
use identity_composition::{
    PostgresDeviceIngressSettlementError, acknowledge_postgres_device_ingress,
};
use mqtt::AuthenticatedDeviceDelivery;
use postgres::{PgBrokerAcceptedDeviceOutbox, PgDeviceIngressCommit};
use static_assertions::assert_not_impl_any;

assert_not_impl_any!(PgBrokerAcceptedDeviceOutbox: Clone, Copy);

fn durable_puback_requires_the_exact_postgres_commit<'a>(
    delivery: AuthenticatedDeviceDelivery,
    pending: PendingDeviceIngress,
    committed: PgDeviceIngressCommit<identity::ports::device_certificate::DraftEligibility>,
) -> impl Future<Output = Result<DeviceIngressDomainOutcome, PostgresDeviceIngressSettlementError>> + 'a
{
    acknowledge_postgres_device_ingress(delivery, pending, committed)
}

#[test]
fn device_mqtt_surface_is_closed_and_postgres_commit_gated() {
    let _ = durable_puback_requires_the_exact_postgres_commit;
}
