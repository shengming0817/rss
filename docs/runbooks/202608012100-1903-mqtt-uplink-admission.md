# MQTT Uplink Admission Saturation Runbook

Use this runbook when the dashboard shows sustained growth in
`mqtt_uplink_admission_failures_total{reason="queue_full"}`. The signal is diagnostic-only and does
not page by itself.

## Confirm the failure mode

1. Record deployment identity, first-seen time and the closed `contract=ack|report` label.
2. Confirm matching `mqtt uplink admission rejected` WARN events with `reason=queue_full`.
3. Check MQTT readiness/reconnect state, ingress worker throughput and PostgreSQL availability.
4. Do not add tenant, device, topic, correlation, packet id or payload to metric labels. Use
   access-controlled traces or broker/database tooling when instance-level diagnosis is required.

## Safe response

- Preserve manual ACK and the bounded adapter-private `DeliveryQueue`. Do not switch to auto-ACK,
  unbounded buffering or a drop-and-ack path to clear pressure. Invalidation clears not-yet-popped
  prior-generation pending synchronously without PUBACK before any reconnect/backoff window.
- Restore the stalled ingress consumer or database dependency first. A saturated attempt has no
  application receipt and remains eligible for persistent-session redelivery.
  Only `DeliverySaturated` must not tear down a healthy transport; `AssertionRejected` is a
  trust-boundary failure and still enters recovery.
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
  does not add metric labels, dashboard panels, or paging alerts. #1908 H2 observes adapter queue /
  receive-window capacity via test-support; it does not claim this counter or `TrySendError::Full`.

## Escalation

Escalate when saturation continues after the ingress worker and PostgreSQL are healthy, or when
broker redelivery does not repair the same envelope. Preserve broker/session and database evidence;
never infer durable commit or PUBACK solely from this counter.
