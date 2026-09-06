# rss-device-command

A provider-neutral device command lifecycle, authority model and borrowed-transaction port.
Version 0.1.0 is experimental. There is one public owner and no historical API or schema adapter.
The core depends on public messaging vocabulary for transactional dispatch, never on PostgreSQL,
global DI, Reconcile, Saga, device authentication or product protocols.

## Identity and transitions

`CommandSpec` binds a tenant, UUID device, tenant-local command ID, independent positive generation
and authority epoch, expected 32-byte state digest and Unix-microsecond deadline. Command IDs are
1–255 ASCII alphanumeric/`_.:-` bytes. Multiple commands can be active for one device. Products
supply authenticated identities and define state normalization/digest semantics; these values do
not authenticate their source. Every device report names its exact command and authority.

```rust
use rss_device_command::*;
use rss_request_context::TenantId;
# fn example() -> Result<(), Box<dyn std::error::Error>> {
let scope = Scope::new(
    TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?,
    DeviceId::parse("550e8400-e29b-41d4-a716-446655440000")?,
);
let coordinate = Coordinate::new(1, 1)?;
let spec = CommandSpec::new(scope, CommandId::parse("set-mode")?, coordinate,
    StateDigest::from_bytes([7; 32]), 1_000_000);
let command = Command::queue(spec, 10)?;
assert_eq!(command.status(), Status::Queued);
# Ok(()) }
```

Only durable publication confirmation reaches Published; device ACK reaches Received; an exact
actual-state match after Received reaches Applied. A device may reject after either Published
or Received. Expiry, cancellation and supersession are terminal server decisions. They never
prove that the device did not execute an old command. Gateway/device replay protection is a
separate product responsibility.

Generation describes desired version; epoch describes authority. `next.supersedes(current)`
requires generation not to decrease and epoch to strictly increase. A generation update therefore
also increases epoch; takeover can keep generation. Neither coordinate is a command version.
Changing authority supersedes its active commands in the same transaction.

Every real transition increments version once. Repeated milestones are no-ops; terminal states
absorb late input. Conflicting reports fail without mutation. An operation reaching the command
deadline records TimedOut instead of advancing success. Explicit cancellation, supersession
and device rejection retain their actual terminal reason even after that deadline. Server timestamps must be monotonic per
command. `Command::restore` validates all persisted milestones and the exact lifecycle version.
`Event` drives the pure reducer; it is not a credential or a proof that an external fact occurred.
The store accepts only `DeviceReport` for device-originated input.

## Transactions and recovery

`Store` borrows its provider transaction. Queue binds the complete immutable command and dispatch
fingerprint, stages one outbox entry, and never commits. No returned snapshot or `Transition`
authorizes transport ACK before the enclosing transaction's confirmed settlement. Exact create
replay returns the existing snapshot; changed immutable facts conflict. Products own authored
message contracts, routes and protocol payloads and must bind them to the same command intent.

An early ACK or actual-state report returns OutOfOrder. The consumer must roll back/release and
persistently redeliver that original ingress; it must not write a terminal Inbox receipt. This
library does not keep another ingress journal, queue, receipt database or transport sequence.
See the PostgreSQL package for composition with the existing Inbox transaction.

`recover` inspects at most `BatchLimit` (1–64) active commands using an explicit command-ID cursor.
Each inspected no-op counts toward the limit. Commit the page before advancing its cursor; after
a complete sweep restart from None for newly published or newly expired commands. The provider
uses the enclosing transaction's original deadline. Cancellation drops that transaction future
and invokes its owner's isolation policy; it does not prove rollback. No thread, timer task or
infinite retry loop is spawned. Uncertain settlement requires exact durable readback first.

## Extraction

The fixed source is `baseline/pre-community-core-20260902` at
`5b63e10a1b396b0ff70b7d1e6e55db296cd7a891`: deviceloop command/generation/store and durable tests.
Only lifecycle, identity, fencing and recovery semantics are extracted. Per-device singleton
commands, generic device-state containers, certificates and old ingress receipts are not restored.
Private test fixtures and the exhaustive state/event matrix validate the new owner.

ref: mdeloof/statig statig/src/awaitable/state_machine.rs@3780eecdbcf4326051c38676d592c6c2b4a3bab5
