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

- Preserve manual ACK and the bounded queue. Do not switch to auto-ACK, unbounded buffering or a
  drop-and-ack path to clear pressure.
- Restore the stalled ingress consumer or database dependency first. A saturated attempt has no
  application receipt and remains eligible for persistent-session redelivery.
- After recovery, verify the counter rate returns to zero and that the same stable envelope reaches
  one durable receipt/application receipt before settlement.
- If pressure is legitimate sustained load, collect queue service time and capacity evidence before
  changing the bound. #1903 does not authorize a generic MQTT DLT/requeue platform.

## Escalation

Escalate when saturation continues after the ingress worker and PostgreSQL are healthy, or when
broker redelivery does not repair the same envelope. Preserve broker/session and database evidence;
never infer durable commit or PUBACK solely from this counter.
