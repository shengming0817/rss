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
saturation. The metric is emitted only by the `TrySendError::Full` branch, which also returns
`DeliverySaturated`; neither branch emits an application receipt or PUBACK.

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
