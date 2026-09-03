# MQTT Uplink Admission Saturation Runbook

Use this runbook when the dashboard shows sustained growth in
`mqtt_uplink_admission_failures_total{reason="queue_full"}`. The signal is diagnostic-only and does
not page by itself.

## Confirm the failure mode

1. Record deployment identity, first-seen time and the closed `contract=ack|report` label.
2. Confirm matching `mqtt uplink admission rejected` WARN events with `reason=queue_full`.
3. Check MQTT readiness/reconnect state, ingress worker throughput and PostgreSQL availability.
   If readiness transitions directly from Degraded to Stopped, confirm the closed
   `reason=negative_puback_outcome_unknown` error marker before treating it as terminal poison
   disposition rather than ordinary transport recovery.
4. Do not add tenant, device, topic, correlation, packet id or payload to metric labels. Use
   access-controlled traces or broker/database tooling when instance-level diagnosis is required.

## Safe response

- Preserve manual ACK and the bounded adapter-private `DeliveryQueue`. Do not switch to auto-ACK,
  unbounded buffering or a drop-and-ack path to clear pressure. Invalidation clears not-yet-popped
  prior-generation pending synchronously without PUBACK before any reconnect/backoff window.
- Restore the stalled ingress consumer or database dependency first. A saturated attempt has no
  application receipt and remains eligible for persistent-session redelivery.
  Only `DeliverySaturated` must not tear down a healthy transport. Assertion/topic rejection uses
  MQTT v5 negative PUBACK and keeps the same Ready session after the ACK is observed outgoing; it
  does not mint authenticated delivery or durable acceptance. A transport failure while that ACK
  outcome is unknown is terminal (`Degraded → Stopped`) and must not enter automatic poison
  reconnect.
- After recovery, verify the counter rate returns to zero and that the same stable envelope reaches
  one durable receipt/application receipt before settlement. Broker same-envelope persistent replay
  on the same endpoint with `session_present=true` after the old session closes is the only continue
  path when terminal settlement (durable post-commit or bounded unaddressable poison terminal)
  returns `StaleTransportEpoch`. Treat `AckUnavailable`, receipt mismatch, and commit failure as
  fail-closed shutdown signals, not replay-continue cases. Correlate adapter
  `reason=stale_transport_epoch` with the pilot INFO event
  `component=deviceidentity_ingress, reason=stale_terminal_settlement`; the latter means the
  recovered session remains live while awaiting same-envelope replay, not that settlement succeeded.
- If pressure is legitimate sustained load, collect queue service time and capacity evidence before
  changing the bound. #1903 does not authorize a generic MQTT DLT/requeue platform, and this runbook
  does not add metric labels, dashboard panels, or paging alerts.

## Escalation

Escalate when saturation continues after the ingress worker and PostgreSQL are healthy, or when
broker redelivery does not repair the same envelope. Preserve broker/session and database evidence;
never infer durable commit or positive PUBACK solely from this counter. A negative PUBACK means
terminal rejection, not application acceptance.
Escalate the `negative_puback_outcome_unknown` marker separately: automatic reconnect is
intentionally disabled until an operator has established broker/session state. This marker is an
independent runbook trigger even when `queue_full` is zero. Freeze automated restarts, record the
deployment and broker instance, and inspect the stable RSS client session plus inflight/persistent
queue state without deleting or expiring it. Restore broker transport, then recreate the stopped
RSS session through the deployment's normal process restart. Recovery is complete only after the
same client reaches Ready, the marker does not recur, and a new valid QoS1 probe is delivered. If
the marker repeats, stop restart automation and escalate with the preserved broker/session evidence;
do not clear the persistent session, synthesize a positive PUBACK, or claim application receipt.
