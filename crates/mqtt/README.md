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
subscriptions are validated; cancellation interrupts the wait.
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

`MqttOutboxPublisher::new(publisher, mapper)` implements `Publisher<P>`. The mapper is a trusted infrastructure, caller-owned
`Fn(&MessageEnvelope<P>) -> Result<PublishRequest, MqttError>`; it must deterministically preserve the
message ID and authored content in the caller's chosen encoding. The adapter imposes no topic or
wire envelope format. Mapper failure is an Encode/InvalidMessage permanent non-publication.

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

`cargo test -p rss-mqtt` covers value/error boundaries. `cargo nextest run -p mqtt-integration` covers
real private-CA/mTLS Mosquitto, PostgreSQL Outbox/relay, ACK-loss proxy, durable session reconstruction,
backpressure, and scripted TLS protocol failure windows. The integration package owns test-only
storage and fault endpoints; no production broker/backend is included here.
`python3 hack/mqtt-package-proof.py` checks isolated consumption of packaged artifacts.

Historical extraction source: `baseline/pre-community-core-20260902`, commit
`5b63e10a1b396b0ff70b7d1e6e55db296cd7a891:adapters/mqtt`.
Primary implementation reference: `thehouseisonfire/rumqtt`, commit
`aa7a694f9b76b17d4c31200cf73d79616acae9b3`, `rumqttc-v5/src/{client,eventloop,state,notice,session}.rs`.

The Outbox mapper performs pure encoding and returns only `EncodeError` for permanent invalid content.
Transport, storage, authentication and other fallible I/O belong outside that function. The caller
composition owns canonical metadata encoding and durable-handoff proof; the generic MQTT crate does
not grant business handlers access to its publisher or settlement capabilities.
