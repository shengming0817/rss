# MQTT Uplink Admission Observability

This is the minimal operations contract for #1903's bounded authenticated-uplink queue. It does
not add the broader device metrics owned by #1905.

## Metric schema

| Metric | Type | Labels | Closed values | Meaning |
|---|---|---|---|---|
| `mqtt_uplink_admission_failures_total` | Counter | `reason`, `contract` | `reason=queue_full`; `contract=ack\|report` | A verified delivery could not enter the bounded in-memory ingress queue. It remains unacknowledged and the persistent MQTT session may redeliver it. |

The executable schema is owned by `adapters/mqtt`: `MqttUplinkAdmissionFailureReason::as_label()`
owns `reason`, and `MqttUplinkContract::as_label()` owns `contract`. Tenant, device, topic,
correlation data, payload, packet id and error text are forbidden labels.

`DeliveryClosed` is a terminal session/lifecycle error and is intentionally not relabelled as queue
saturation. The metric is emitted only when the adapter-private bounded `DeliveryQueue` rejects a
push at capacity and returns `DeliverySaturated`; neither branch emits an application receipt or
success PUBACK. Only `DeliverySaturated` rejects that admission attempt without tearing down a
healthy transport candidate. Pre-authentication assertion/topic rejection is instead consumed by
an adapter-private carrier and sent as an MQTT v5 negative PUBACK (`>=0x80`): this terminates broker
redelivery without minting delivery, commit, receipt, or acceptance authority. If the transport
fails before that negative ACK is observed outgoing, the session stops fail-closed instead of
reconnecting into an ambiguous poison replay.

The uplink path uses a strictly bounded short-lock `VecDeque` + `Notify` + closed queue with a
single driver producer and single ingress consumer, and `RECEIVE_MAXIMUM == DELIVERY_CAPACITY` as a
compile-time hard const. Invalidation has one funnel under the settlement short barrier: checked
atomic epoch bump, then synchronous clear of not-yet-popped prior-generation pending (no PUBACK),
and only then any async disconnect, drain, backoff, or connect. Popped / in-flight deliveries rely
on epoch settlement. Settlement shares that barrier with begin/invalidate so current-epoch check,
`try_ack` enqueue, and same-generation error classification are linearized: epoch mismatch returns
`MqttSessionError::StaleTransportEpoch`; same-generation failure remains `AckUnavailable`. The pilot
keeps the recovered session and waits for broker same-envelope persistent-session replay only on
terminal settlement `StaleTransportEpoch` (durable post-commit or bounded unaddressable poison
terminal); `AckUnavailable`, receipt mismatch, and commit failure remain fail-closed and shut the
session down. The pilot records the continue path as
`component=deviceidentity_ingress, reason=stale_terminal_settlement`; it is not a settlement-failure
event and does not imply successful PUBACK. This contract does not add metric labels, dashboard
panels, or alerts.

## Dashboard

Use one diagnostic panel:

```promql
sum by (contract, reason) (rate(mqtt_uplink_admission_failures_total[5m]))
```

Show the two closed contract series without tenant/device variables. Correlate a sustained rate
with MQTT session readiness, ingress worker throughput and PostgreSQL availability. A missing
series means no failure has yet been observed; it is not a queue-depth gauge and must not be shown
as proof that ingress is healthy.

## Rules and response

The corresponding Prometheus file is `docs/ops/mqtt-uplink-admission.rules.yaml`. It intentionally
defines no paging or recording rule: #1903 has no measured saturation SLO or independently
actionable threshold, and paging on a diagnostic counter would duplicate session/readiness and
database availability signals. Deployments may visualize the direct dashboard query but must not
invent a global page without a measured SLO and a distinct operator action.

Operational response is documented in
`docs/runbooks/202608012100-1903-mqtt-uplink-admission.md`.
