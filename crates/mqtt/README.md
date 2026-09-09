# rss-mqtt

Experimental MQTT v5 / QoS 1 transport with bounded admission, broker-confirmed publication,
move-only receive settlement and restart-safe protocol sessions. `rss-runtime` is not required.
The provider is `rumqttc-v5-next =0.34.0`, with default features disabled and the Rustls ring backend.
There is no legacy MQTT API, device topic, assertion, schema or compatibility layer.

## Temporary upstream logging restriction (#2308)

**Consumer requirement:** disable `rumqttc` and `rumqttc_core` and their child targets in the
application logger/collector. Upstream 0.34.0 logs complete packets on some failure paths; the
adapter's redacted errors do not intercept those log calls. This is an explicitly accepted temporary
risk, tracked in [PBI #2308](https://dev.azure.com/shengming0923/rss/_workitems/edit/2308), not an upstream fix.
Do not enable upstream tracing/logging or override child targets through `RUST_LOG` until that issue
is resolved. The library never installs/replaces a global logger or disables other application logs.

For a tracing/log bridge, use the tested application-owned policy from `examples/support/logging.rs`:

```rust,ignore
tracing_subscriber::fmt()
    .with_env_filter(tracing_subscriber::EnvFilter::new("info,rumqttc=off,rumqttc_core=off"))
    .try_init()?;
```

Equivalent target exclusions are mandatory for other logging backends. The regression exercises a
real upstream retained-publication rejection and an illegal inbound packet with secret fields, and
checks that application logs still work. Upgrade to an upstream release with safe packet/error
logging, rerun those tests without the exclusions, then remove this temporary restriction.

## Ownership and construction

`connect(config, clock, session_store)` starts one driver on the caller's Tokio runtime and returns
`(MqttPublisher, MqttReceiver, MqttResource)`. The publisher is cloneable; the receiver and resource
are unique. Keep all three alive. Dropping the receiver stops the connection; dropping the resource
cancels and aborts its driver. Call `resource.shutdown(total_budget).await` to drain protocol-admitted
outbound work and join the driver. Admission closes before shutdown; its total budget also bounds
blocked storage and connection work. No public handle exposes the underlying client or event loop.

Supply a `Clock` as a constructor argument, an explicit `Limits`, and a preconfigured Rustls
`ClientConfig` with the desired trust roots and optional client certificate. Credentials are supplied
by the caller through the fallible `credentials(...)` builder, which rejects invalid MQTT fields. TLS is mandatory; there is no plaintext or verification-bypass option in this adapter.
The caller owns authentication, authorization, credential rotation and the contents of its TLS config.
Default keepalive/connect timeout are 10 seconds; reconnection uses exponential backoff with jitter, initially 100–200 milliseconds and capped at 30 seconds.
`ReconnectPolicy` configures the initial and maximum waits. The delay resets only after connection and
subscriptions are validated. Backoff continues processing queued commands, including graceful
shutdown; handling commands does not restart the timer. Forced cancellation remains separate.
Session expiry defaults to the upstream persistent-session setting and can be set explicitly.
`Reconnecting { cause, generation }` retains a closed diagnostic; transient broker busy/quota
responses recover automatically, while authentication, storage and session mismatch failures remain terminal.
Per-operation `OperationDeadline` values come from the existing transactional messaging clock API.

Each `(session store scope, client ID)` must have exactly one active driver, including across
processes. The store is caller-provided and must implement upstream `SessionStore` crash consistency
and exclusivity; the adapter does not supply distributed leases. Use upstream `PersistedSession`
encoding directly. Checkpoints contain payloads and protocol state, so the caller must protect them
at rest and isolate broker/tenant/environment scopes. A fixed subscription set belongs to that
identity: change the identity or explicitly reset the broker session before changing that set.

Both live reconnection and reconstructed EventLoops restore upstream packet identifiers and in-flight
protocol state. Missing, invalid or mismatched local state is not replaced with broker-only compatibility
mode. Storage/restore errors are terminal and visible through `connection_state()` and `wait_ready()`.
`Ready { session_present: false, .. }` makes loss of the previous broker session visible; offline inbound
messages may have been lost. Desired filters are reasserted and their QoS 1 SUBACKs validated before
readiness. Broker persistence/retention itself remains an external deployment responsibility.

## Publication and Outbox

`PublishRequest` carries authored topic, payload, retain, Message Expiry Interval, correlation data
and user properties. The caller owns their business meaning. QoS is always 1. Topic aliases and QoS 2
are not exposed. Application metadata is not synthesized or regenerated during protocol retries.

`MqttPublisher::publish` returns the existing `PublishOutcome<()>`:

- `Confirmed`: a matching successful PUBACK, including NoMatchingSubscribers. This means broker
  acceptance, not subscriber existence, consumer processing, business authentication or an application receipt.
- `DefinitelyNotPublished`: evidence of pre-admission failure or explicit broker rejection. Invalid
  topics/payload formats and authorization rejection are permanent; quota/unspecified broker errors are transient.
- `Ambiguous`: confirmation loss, timeout, session reset, storage uncertainty or unknown upstream failure.

A cancelled/timed-out caller does **not** cancel an already admitted upstream request. It may still be
sent or replayed. Preserve the original message identity, content and properties on any application
retry, and design consumers for duplicate delivery. Only the canonical relay maps these outcomes to
Outbox Published/Retry/DeadLetter. Protocol checkpoints do not replace the application Outbox.

`MqttOutboxPublisher::new(publisher, plan)` implements `Publisher<Vec<u8>>`. Encode business
payloads before appending to the Outbox. `MqttOutboxPlan` binds one domain and a nonempty immutable
map of typed routes to `MqttOutboxTopic` destinations/options. The adapter sends persisted payload
bytes unchanged and exclusively writes canonical user properties; there is no encoding callback.
Wrong domain, unbound route and oversized/invalid metadata fail before protocol admission.
Both raw and Outbox publication fix one monotonic cutoff on entry: metadata encoding, size
validation, queue admission and broker confirmation consume the same budget. Expiration before
command submission is definitely-not-published; expiration after submission remains ambiguous.

The RSS MQTT envelope uses `messageId`, `tenantId`, `domain`, `route`, `contractId`, `schemaVersion`,
`schemaHash`, `occurredAt`, optional `partitionKey`, `correlation`, `causationId`, `trace` and
`tenantAuthority`. Application attributes use `attribute.` prefixes, including attributes whose
names equal reserved fields. The reader rejects duplicate, missing required and unknown fields.
These metadata names align with the Kafka adapter; they are not a business authentication claim.

This replaces the experimental mapper API and its caller-defined wire format, including the former
example's `message-id`. There is no legacy fallback. Switch producers and consumers together;
existing protocol checkpoints/queued publications encoded in the old format need an explicit drain
and session/consumer cutover. A route/topic option change between deployments is also an explicit
routing migration; immutable per-instance configuration does not prove cross-deployment equality.
The generic `MqttPublisher` still accepts application-owned raw MQTT packets independently.

## Transactional receive (`consumer` feature)

`MqttDeliverySource::new(receiver, subscription)` consumes the exclusive receiver. Its connection
must have exactly one configured MQTT filter; each broker topic must match it and each decoded
RSS envelope must match the exact logical domain/route/contract subscription. A filter may contain
MQTT wildcards; topic membership does not authenticate tenant authority.

The source implements core `DeliverySource<Vec<u8>>`. Feed it to the existing `ConsumerWorker`
with a trusted ingress validator, Inbox and `ConsumerTx`. Only one managed stream can be active;
there is no raw receiver or settlement extraction from the transactional source. Business handlers
receive only their normal typed context/repositories. The `MqttTransactionSettlement` wrapper can
consume core-issued decisions, but cannot mint ACK/Reject or expose its raw protocol authority.

Successful transaction/duplicate receipt verification grants ACK. Decode/ingress or durable terminal
rejection grants a terminal negative PUBACK. Requeue/abandon sends no PUBACK and requests retirement
of the connection: all other unacknowledged deliveries on that session may also replay. Returning
from that synchronous request does not prove broker redelivery. Commit unknown and rollback failure
never grant success ACK. Old-generation settlement remains invalid after reconnect.

Temporary reconnects run inside the same stream. Cancelling a pending `next()` does not discard
unyielded deliveries. Graceful worker cancellation lets its current transaction finish; forcibly
dropping the stream retires the current connection without implicit ACK and returns the receiver
to its source. A replacement stream waits for a newer Ready generation; concurrent stream creation
is rejected. This supports the worker's resubscription after transient settlement failures. Dropping
the last source/stream owner closes the receiver/driver. Terminal failures remain observable through
`connection_state()` and fail subsequent subscription attempts; construct a new resource/source
for terminal recovery. Requeue/abandon rejects elapsed budgets and stale/closed ownership, while
Drop still requests conservative retirement on failure.
The `consumer` feature adds no runtime, SQLx or product authentication implementation to this crate.

## Receive settlement

`receiver.next()` is a cancellation-safe admission wait. `Delivery` exposes unverified MQTT data and
can be split into the upstream publish packet and a private, non-cloneable `Settlement`:

- `ack_after_durable_handoff(deadline)` consumes the permission. The caller must first complete its
  durable transaction/handoff; this call does not prove an arbitrary external transaction committed.
- `reject_terminal(reason, deadline)` sends a terminal negative PUBACK. It is not AMQP requeue.
- `abandon()` or dropping an unsettled permission retires the connection without ACK, allowing the
  broker's retained session to redeliver. Other unacknowledged deliveries on the connection also replay.

Settlement success means the driver observed the current connection's outgoing PUBACK after local
write/flush. MQTT does not acknowledge a PUBACK, so broker receipt cannot be guaranteed. A timeout or
connection failure yields an unknown result; the permission cannot be reused for another decision.
Any reconnect/retirement invalidates old permissions even if the packet ID is reused. Receive capacity
counts deliveries held by the caller as well as the queued deliveries. QoS 0/2 ingress is an explicit
unsupported-QoS error, never a reliable delivery with fabricated ACK authority.

## Validation and sources

`cargo test -p rss-mqtt` covers value/error boundaries. `make ci CI_PART=tests CI_FILTER='package(=mqtt-integration)'` covers
real private-CA/mTLS Mosquitto, PostgreSQL Outbox/relay, ACK-loss proxy, durable session reconstruction,
backpressure, and scripted TLS protocol failure windows. The integration package owns test-only
storage and fault endpoints; no production broker/backend is included here.
`python3 hack/mqtt-package-proof.py` checks isolated consumption of packaged artifacts.

Historical extraction source: `baseline/pre-community-core-20260902`, commit
`5b63e10a1b396b0ff70b7d1e6e55db296cd7a891:adapters/mqtt`.
Primary implementation reference: `thehouseisonfire/rumqtt`, commit
`aa7a694f9b76b17d4c31200cf73d79616acae9b3`, `rumqttc-v5/src/{client,eventloop,state,notice,session}.rs`.
