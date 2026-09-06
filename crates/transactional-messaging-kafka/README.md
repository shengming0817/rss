# rss-transactional-messaging-kafka

An independently consumable Kafka **publisher-only** adapter implementing
`rss_transactional_messaging::transport::Publisher<Vec<u8>>`. PostgreSQL Outbox and the existing
relay provide durable at-least-once publication. This crate contains no consumer, Kafka transaction,
projection source, application host, schema registry, or deployment machinery.

## Create, publish, close

```rust,no_run
use std::time::Duration;
use rss_transactional_messaging_kafka::{KafkaConfig, KafkaPublisher, KafkaError};

async fn run(config: KafkaConfig) -> Result<(), KafkaError> {
    let (publisher, resource) = KafkaPublisher::create(config, Duration::from_secs(5)).await?;
    // Give publisher clones to a caller-owned relay using PgOutboxStore<KafkaPublishReceipt>.
    // Stop and drain the relay before closing the unique transport owner.
    resource.shutdown(Duration::from_secs(5)).await
}
```

`KafkaConfig::new` takes a mandatory `KafkaClientId`, bootstrap servers, an explicit private CA PEM, `KafkaCredentials`, a
`MessagingDomain`, immutable `(MessageRoute, String)` topic mappings, and `KafkaLimits`. Provide
mTLS certificate/key PEM using `mutual_tls`, or SCRAM-SHA-512 credentials using `scram_sha512`.
Client identity is caller-owned stable, non-secret operational metadata (1..=128 ASCII letters,
digits, dots, underscores or hyphens); it controls Kafka client-id quotas and accompanies the
validated domain in safe native event diagnostics. Production always verifies certificates and hostnames. There is no plaintext constructor, raw
client accessor or arbitrary configuration override. PEM validation completes during native
initialization; successful `create` does not prove broker availability or permissions.

`KafkaLimits::new(queued, in_flight, record_bytes, delivery_timeout)` independently bounds the
command queue and native pending attempts. Counts are 1..=100,000, record bytes 1..=100,000,000;
each count times record bytes must fit 2 GB. The integral-millisecond delivery timeout is 10 ms
through 24 hours. These are configurable safety ceilings, not recommended production sizing.
Authored-byte accounting includes payload, key, topic and headers with a per-header charge.
Native bookkeeping, temporary serialization copies and host-owned inputs consume additional memory.
A full queue returns a definite transient refusal immediately; the library adds no local retry loop.

Reliability settings are fixed: `acks=all`, `enable.idempotence=true`, retries=2147483647,
max-in-flight per connection=5, linger=0, finite native queue limits and message timeout. Request and
socket timeouts are capped by the native message timeout and 10 seconds. Topic auto-creation is off.
Callers provision topics, replication, ISR, ACLs, credentials and stable routing. Tenant metadata is
an authored assertion, not authentication; broker/product authorization remains necessary.

## Evidence and wire representation

A synchronous native enqueue failure proves non-publication. Local queue admission never proves
Kafka acceptance. Only a successful delivery report creates `KafkaPublishReceipt`, with topic,
partition and offset accessors. It proves broker acceptance under the configured acknowledgements,
not consumer processing, indefinite retention, or exactly-once execution. PostgreSQL uses the
receipt to select its existing published transition; it does not persist Kafka coordinates.

All delivery-report errors and lost results after admission remain `Ambiguous`; the safe Rust API
does not expose sufficient persistence evidence to narrow them. Definite invalid authored input
is permanent; capacity/closed admission is transient. Diagnostics use the core's closed failure
kind, stage and reason. `DeadlineElapsed` is reserved for the core-owned operation watchdog;
native message/request timeouts are `TransportUnavailable`. Provider text, credentials and payload never enter error chains or Debug.

The Kafka value is the original payload bytes (including an empty, non-null value). The Kafka key
is the original UTF-8 partition key, or null when absent; no synthetic key or partition number is
introduced. Keep caller-authored keys globally unique or tenant-scoped, and topic mappings and
partition counts stable when ordering matters. Kafka idempotence deduplicates native retries;
a new Outbox attempt can still append a duplicate with the original message ID.

The sole writer emits UTF-8 headers `messageId`, `tenantId`, `domain`, `route`, `contractId`,
`schemaVersion` (full version), `schemaHash`, and `occurredAt` (original Unix seconds). Optional
headers are `partitionKey`, `correlation`, `causationId`, `trace`, and `tenantAuthority`.
Attributes use `attribute.<original-key>`; embedded NUL in a key is rejected before native calls.
Attributes cannot shadow reserved headers. Kafka's broker timestamp is separate from the preserved
`occurredAt`; applications supply the payload schema and serialization.

## Cancellation and ownership

One dedicated OS thread exclusively owns `BaseProducer`. Publisher handles contain no native
handle or connection credentials; startup consumes those separately from routing and record limits. The thread processes bounded commands and delivery reports; its private bounded pending
map owns reply senders. Native opaque values are monotonically increasing numeric tokens and own
no Rust allocations. Late or missing reports cannot leak boxed senders. Native destruction is
completed before unresolved entries are reclaimed as ambiguous; tokens are never reused.

`OperationDeadline` starts a monotonic watchdog immediately at publish entry. Queued commands are
checked again before native send. Dropping the caller future only stops waiting: an already sent
record can still arrive, and remains pending until its report or transport teardown. Native
message timeout bounds native retries independently; it does not reset the caller's deadline.

`shutdown(self, timeout)` immediately seals admission, even if its returned future is never polled.
It drains accepted commands and native deliveries within one total budget. Forced retirement and
nonblocking native admission share the same lock, so a dequeued but unsent command cannot cross
an already-effective forced close. Dropping the resource,
cancelling shutdown or exceeding its budget requests forced retirement. Native purge cannot prove
in-flight non-acceptance. The owner thread performs native teardown and then sends completion directly through a oneshot;
no Tokio blocking worker waits for its lifetime. A successful shutdown means graceful drain and native cleanup;
a timeout means cleanup may still be running. librdkafka destruction has no hard time limit, and
the host must allow cleanup to finish. No synchronous native destruction occurs on a Tokio worker.
A fatal callback or the native client fatal flag seals admission and terminates the owner with
`OwnerFailed`; pending attempts remain ambiguous through cleanup. A caller may construct a new
resource explicitly; an old handle never recovers or reopens itself. Startup cancellation uses the same owner cleanup path. Invalid startup/shutdown duration values
return `InvalidLifecycleTimeout`, independently of record/queue `InvalidLimits`. Surviving publisher clones cannot reopen it.

`test-support` exposes deterministic pre-send/post-send gates and a pending-count observation.
It does not enable a fake backend, plaintext transport or weaker acceptance semantics.

## Build and verification

This repository pins rust-rdkafka 0.39.0; its current Cargo.lock resolves librdkafka 2.12.1.
The build statically compiles bundled librdkafka with vendored OpenSSL through `ssl-vendored`; default features and dynamic linking are disabled. A C/C++
toolchain, make, Perl and pkg-config are required (macOS and Linux). No system librdkafka is needed.
The repository Cargo.lock fixes native sources for this revision; external consumers resolve their own
compatible transitive versions and do not inherit this lockfile. The #2306 OpenSSL exception is confined with cargo-deny
parent constraints; unrelated OpenSSL/native TLS providers remain banned. This exception accepts
no security advisory. Consumer applications control their own resolved feature/build environment.

Run `cargo test -p rss-transactional-messaging-kafka --all-features` for component and independent
consumer checks, and `cargo nextest run -p kafka-integration --all-features` for the real mTLS Kafka
and PostgreSQL closure. The real authentication matrix proves mTLS/SCRAM success, wrong CA,
trusted-CA hostname mismatch, untrusted client certificate and incorrect SCRAM password rejection.
Tests compare receipt coordinates with broker records and preserve actual duplicates after ambiguity.

ref: rust-rdkafka src/producer/base_producer.rs@598ac4ba1f714852bdf4e5685fe10cf5a66e947c
ref: rust-rdkafka src/util.rs@598ac4ba1f714852bdf4e5685fe10cf5a66e947c
