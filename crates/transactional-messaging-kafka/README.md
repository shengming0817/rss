# rss-transactional-messaging-kafka

An independently consumable Kafka **publisher-only** adapter implementing
`rss_transactional_messaging::transport::Publisher<Vec<u8>>`. PostgreSQL Outbox and the existing
relay provide durable at-least-once publication. This crate contains no consumer, Kafka transaction,
projection source, application host, schema registry, or deployment machinery.

## Create, publish, close

```rust,no_run
use std::time::Duration;
use rss_transactional_messaging_kafka::{
    KafkaConfig, KafkaPublisher, KafkaError, KafkaLimits, KafkaTimeouts,
};

fn limits() -> Result<KafkaLimits, KafkaError> {
    KafkaLimits::new(64, 32, 128 * 1024, 32_000_000,
        KafkaTimeouts::low_latency(Duration::from_secs(5))?)
}

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
Client identity is caller-owned stable, non-secret operational metadata (1..=255 ASCII letters,
digits, dots, underscores or hyphens); it controls Kafka client-id quotas and accompanies the
validated domain in safe native event diagnostics. Production always verifies certificates and hostnames. There is no plaintext constructor, raw
client accessor or arbitrary configuration override. PEM validation completes during native
initialization; successful `create` does not prove broker availability or permissions.

`KafkaLimits::new(queued, in_flight, record_bytes, total_budget_bytes, timeouts)` requires positive,
finite counts and bytes. The counts are capacity ceilings, not recommended deployment sizes. The
native pending count must fit `i32`; the Rust queue's slot storage must fit the platform. Counts,
record bytes and queue byte products may exceed the old 100,000 / 100 MB / 2 GB policy ceilings
when the explicit aggregate budget and native representations permit them.

The static record-accounting budget is checked before allocating queues or record bodies:

- Each of the `queued` slots covers one record and up to one record of encoding scratch.
  One more record is charged to the worker after dequeue: `(2 * queued + 1) * record_bytes`.
- Native records are charged `ceil(in_flight * record_bytes / 1024) * 1024`.
- The preallocated channel and concurrent candidates each charge `queued * size_of::<QueuedCommand>()`.
  The worker charges one `Command`; the pending map charges `in_flight * size_of::<(token, reply)>()`.

All arithmetic and conversions are checked; construction rejects an insufficient aggregate budget.
`record_bytes` retains the adapter's accounting of payload, key, topic and headers, including the
existing per-header charges (64 bytes for ordinary headers; 128 plus the attribute prefix for
attributes). Native admission may briefly overlap Rust payload/key with the native copy. Headers
transfer to native on successful send; pending replies remain owned until delivery or native
teardown, even after caller cancellation. The static reservation does not depend on caller waiters
still being present and adds no runtime byte-accounting mechanism.

This is a **record-accounting model, not a process RSS guarantee**. Allocator/container spare
capacity and control data, oneshot allocations, native message bookkeeping, metadata, socket and
protocol/batch buffers, credentials and caller-owned envelopes/futures consume additional memory.
Command and pending counts bound their respective owners; host concurrency and input ownership
remain caller-controlled. Native `queue.buffering.max.kbytes` itself charges **payload only**;
key/header-heavy or empty-payload records are covered by the adapter's record/count model instead.
The integration load probe reports the actual client process RSS (Rust and native together), with
its sampling interval, alongside throughput/latency and full-queue/teardown observations. Broker
JVM memory is outside that client measurement.

`KafkaTimeouts::new(socket, request, linger, delivery)` independently configures transport timing.
Socket uses integral milliseconds in 10..=300,000; request in 1..=900,000; delivery in
1..=2,147,483,647. Linger accepts integral microseconds in 0..=900 seconds. Finer precision is
rejected, and delivery must be strictly greater than linger. `KafkaTimeouts::low_latency(delivery)`
chooses 10-second socket/request values and zero linger without clipping the supplied delivery
value or deriving the other values from it. Native Produce requests still use the lesser of socket
timeout and remaining delivery time. Request timeout is the broker's ack timeout; this native
client imposes no Java-style delivery >= request + linger constraint. Caller operation deadlines
remain independent watchdogs.

`message.max.bytes` is derived from the record ceiling plus librdkafka 2.12.1's 36-byte maximum
per-record framing (at least the native minimum of 1000). Values beyond its 1 GB native limit are
rejected. This conservative local admission setting excludes full batch/ProduceRequest framing
and does **not** guarantee broker acceptance: brokers enforce topic `max.message.bytes` and their
own limits. A synchronous native rejection is definite; a broker rejection delivered after native
acceptance remains ambiguous with a classified failure.

Reliability settings stay fixed: `acks=all`, `enable.idempotence=true`, retries=2147483647,
max-in-flight per connection=5, finite native queue limits and delivery timeout. A publish reserves one slot before encoding. Its command owns the slot until dequeue, including
when the caller stops waiting. Concurrent calls enter FIFO order at successful enqueue. A full queue returns
a definite transient refusal immediately; the library adds no local retry loop. Topic auto-creation is off.
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
consumer checks, and `make ci CI_PART=tests CI_FILTER='package(=kafka-integration)'` for the real mTLS Kafka
and PostgreSQL closure. The real authentication matrix proves mTLS/SCRAM success, wrong CA,
trusted-CA hostname mismatch, untrusted client certificate and incorrect SCRAM password rejection.
Tests compare receipt coordinates with broker records and preserve actual duplicates after ambiguity.

ref: rust-rdkafka src/producer/base_producer.rs@598ac4ba1f714852bdf4e5685fe10cf5a66e947c
ref: rust-rdkafka src/util.rs@598ac4ba1f714852bdf4e5685fe10cf5a66e947c

ref: librdkafka src/rdkafka_conf.c@e1db7eaa517f0a6438bc846a9c49ede73b9ea211
ref: librdkafka src/rdkafka_msg.h@e1db7eaa517f0a6438bc846a9c49ede73b9ea211
