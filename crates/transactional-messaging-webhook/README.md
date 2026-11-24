# RSS HTTPS Webhook publisher

`WebhookPublisher` implements `Publisher<Vec<u8>>`. Pair it with
`PgOutboxStore<WebhookPublishReceipt>` and the existing relay. Business changes and
`pending_message` append belong in the same caller-owned transaction. No new schema,
queue, scheduler, broker or runtime is required.

## Host inputs and durable binding

`pending_message` adds `webhookTargetId` and `webhookTargetVersion` to authored
metadata, preserving correlation, partition and causation. The canonical message
fingerprint protects those fields and the exact body. Reserved-field collisions
are rejected. Direct SQL writers must author the same fields. Delivery IDs must
not contain `.`; `webhook-id` is the unchanged MessageId, separate from any business
eventId in the payload. Each fanout target requires its own MessageId.

Every attempt calls `TargetAuthorizer` with the complete metadata, MessageId and
fingerprint. The trusted host checks current tenant/resource/subscription authority
and returns an `AuthorizedTarget` bound to the exact tenant/target/version. Endpoint
versions must be immutable; never route an old version to a new URL. The adapter
checks bindings but cannot authenticate a tenant or validate a host's authorization
implementation. Revocation does not retract a request already sent.

The host owns DNS, network policy, CA trust and keys. Supply a bounded address
snapshot and explicit IP/CIDR allowlist through `NetworkAccess`; there is no implicit
private-network ban, so enterprise networks can be explicitly permitted. The
adapter normalizes mapped IPv4, validates ports and connects only to approved IPs,
while validating the original hostname with the supplied CA roots. No redirects,
environment proxies, DNS fallback or insecure certificate verifier are available.
Host authorization/resolution futures must be nonblocking and cancellation-safe;
wrapping blocking system DNS in a timeout does not terminate that work.

## Signature and outcomes

The Standard Webhooks V1 signature is HMAC-SHA256 over
`MessageId.attempt_unix_seconds.raw_body`. Headers are `webhook-id`,
`webhook-timestamp`, and `webhook-signature: v1,<standard-base64>`; two signatures
separated by a space support overlapping key rotation. The host injects a UTC
`WallClock` and supplies endpoint-specific 24–64 byte secrets. Body bytes are sent
unchanged with `application/octet-stream`; the adapter does not interpret JSON.

Only final 2xx headers mint a private, move-only receipt. This proves HTTP receipt,
not receiver processing or exactly-once delivery. All non-2xx responses and failures
after sending begins are ambiguous. Known pre-send permanent failures can dead-letter;
transient failures retry. The existing relay owns same-ID retries, leases, delivery
windows and recovery. No HTTP retry extends those limits.

## Resource ownership

Pass an `ExecutionTimer`, UTC clock and explicit `Limits` at construction. One
cutoff covers authorization, connection attempts, TLS, signature, send and headers.
Capacity is fail-fast. Dialing follows the authorized snapshot in order and divides
the remaining time among the remaining distinct addresses. Each slice includes TCP,
the actual peer check, TLS for the URL hostname and HTTP/1 readiness. A request
is sent only once per publish call.

The final argument to `Limits::new` selects connection reuse. Pass `None` to close
after every request, or `Some(IdlePoolLimits::new(max_idle, idle_timeout)?)` to set a
publisher-wide idle cap and retention time. Each checkout requires fresh authorization,
an exact tenant, target version, URL, CA set and current/retiring signing keys, and
a peer still present in the allowed address snapshot. The publisher signs with the
current attempt's keys. Each active publish exclusively owns the socket and Hyper
driver; cancellation releases both.

The final 2xx headers determine acceptance. The publisher can reuse a connection
after an empty response or an immediately complete body (up to 8 KiB and 16 frames).
A slow or incomplete body releases the connection immediately. The driver handles
HTTP framing; the adapter does not collect or decompress bodies.

While the host Tokio runtime is active, one lazy cleanup task expires idle sockets
even without further publications. Retain the runtime through shutdown. Call
`publisher.close(deadline).await` to stop admission, drop idle sockets and await
in-flight publishes and the cleanup task. A timeout leaves admission closed and the
wait can be resumed. Dropping the publisher releases idle sockets and aborts its cleaner.

Upstream references: Standard Webhooks
`spec/standard-webhooks.md@bece768d960f09e242f5cd5686d859e475d6b478`;
Hyper HTTP/1 client and response persistence rules in `src/client/conn/http1.rs` and
`src/proto/h1/role.rs@7f67699ce32d717081deb7018b4da7d679277ac0`;
rustls `rustls/src/webpki/server_verifier.rs@f04804fa13341a9b1dc02b5d1dd8a746f2c4b7fb`.
