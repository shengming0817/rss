# Runtime Production Acceptance

This runbook records the current release evidence for the full `runtime` assembly. Markdown is not
an enforcement carrier: the canonical static verdict comes from `cargo xtask assembly validate`,
the generated artifacts and lock, while runtime evidence comes from strict smoke and the container
journeys described below.

## Profile transition status

The bare release smoke in this runbook is transition-era legacy runtime evidence, not the Core
profile carrier. [ADR-024](../architecture/202608012034-024-enterprise-framework-product-surface.md)
authorizes the stable product-profile evidence ownership, and Azure PBI
[#2124](https://dev.azure.com/shengming0923/rss/_workitems/edit/2124) is the single source for the
Core lifecycle evidence plan. This runbook intentionally does not duplicate that plan's selector,
receipt contract or future carrier details.

Until the authorized Core evidence set is green on one exact closure and the whole profile is
activated atomically, the bare release smoke remains the canonical legacy runtime evidence. At
activation it is demoted to a packaging regression covering image build, entrypoint, configuration
load and process start only; it no longer proves profile readiness, drain or outage behavior.

## Release identity

Archive one evidence bundle containing the Git SHA, immutable image digest, `assembly.lock.json`
digest, RuntimePlan fingerprint, configuration/JWKS/allowlist generation, command lines, UTC
timestamps, exit codes and redacted logs. The accepted assembly is exactly `profile = "production"`;
changing the profile, provider lifecycle or provider durability rotates the governed artifacts.

The executable RuntimePlan contains exactly the manifest's active provider declarations. Draft
providers are not executable alternatives and are forbidden in the production manifest. Every
production provider is persistent; listener rate limiting uses the assembly's existing Redis pool
and is cluster-global.

## Legacy runtime evidence during profile transition

1. Run the assembly validation, generated-file checks, AssemblyLock check and runtime
   baseline verification on the release commit.
2. Run `RSS_SMOKE_MODE=release ./deploy/smoke.sh` without `KEEP_UP=1`. Release mode cannot skip a
   missing fixture, retain the stack or tolerate an unavailable dependency. A successful run emits
   the exact machine receipt `RELEASE IMAGE ON DEMO INFRA EVIDENCE`; this proves the release image
   completed the demo compose dependency/readiness/outage closure, not that production TLS, secret
   manager configuration or production infrastructure has been validated. Only
   `RSS_SMOKE_MODE=developer RSS_SMOKE_ALLOW_SKIP=1` may skip an incomplete Remote/SPIFFE fixture,
   and it emits the sole `NOT PRODUCTION EVIDENCE` receipt with every missing variable named.
3. On a fresh, project-scoped database, run the sealed release's independent migration operator and
   verify `_sqlx_migrations` has exactly one successful row with the expected checksum for every
   embedded version. After that job completes, start two containers from the same image and
   configuration generation concurrently and require both replicas to become ready. Serving
   processes never own or execute migration capability.
4. Pause Vault and require both replicas to become unready through the exact unhealthy Vault-backed
   probes. Resume Vault and require those probes to become healthy with overall readiness 200 and no
   fallback provider. The strict single-image smoke applies the same exact unhealthy/healthy closure
   to Vault, Vault KV, S3 and Redis; Redis is restored and proven healthy unconditionally.
5. Remove replica A from traffic and send SIGTERM. During its entire drain window, continuously
   require replica B's HTTP readiness and critical worker probes to remain healthy. A must exit zero
   and log `all runtime resources drained; exiting`; then start a replacement and recover two ready
   replicas.

The two-replica journey proves per-process move-only lifecycle ownership, surviving-replica
continuity under the existing active/standby coordination, and replacement within one release
generation. It does not prove a new global leader transfer protocol, old/new binary compatibility,
or mixed-generation rolling deployment.

## Production cutover

Migrations 0072 and 0073 are forward-only hard cutovers. Before the new generation serves traffic:

1. Quiesce login, refresh, revocation and authenticated ingress; disable every old workload, job and
   controller restart path, then prove the old process inventory is zero.
2. Record the required static PostgreSQL lane snapshot and migration preconditions. Run the sealed
   release's independent operator Job while every serving Deployment remains stopped. A serving
   process never contains or executes migration capability.
3. Require the operator Job to complete and verify the ledger exactly matches the release's embedded
   migration head. Only then start replicas from the same sealed image/configuration generation and
   restore traffic after the complete readiness set is healthy.

Do not mix old and new generations. Once ledger 0073 is present, an old audit writer is forbidden.
Once a persistent certificate revocation has been accepted, an in-memory revocation binary is
forbidden. When any forward-only fence has fired, keep traffic stopped and roll forward with a fixed
release rather than installing a compatibility reader, alias or fallback.

## Outage and recovery boundary

| Dependency | Evidence in this change | Permitted recovery |
|------------|-------------------------|--------------------|
| Vault Transit / Vault KV | strict smoke and two-replica readiness down/up | in-process recovery |
| S3 | strict smoke readiness down/up | in-process recovery |
| Redis | strict smoke plus active/standby coordination evidence | in-process recovery when the exercised path recovers |
| PostgreSQL | independent migration ledger and initial two-replica readiness only | restore service, then restart replicas if readiness does not recover |
| RabbitMQ | initial readiness only | rolling process restart; automatic consumer re-subscription is not claimed |
| SPIFFE / JWKS | startup and static production gates | restore source and restart when the exercised runtime path does not self-heal |

An outage never authorizes switching to a draft, memory, noop or fail-open provider. Uncovered
recovery behavior is a release limitation, not implicit evidence.

## Legacy runtime commands during profile transition

```bash
./hack/cargo.sh xtask assembly validate
./hack/cargo.sh xtask assembly artifacts check
./hack/cargo.sh xtask assembly generate-modules --check
./hack/cargo.sh xtask assembly generate-providers --check
./hack/cargo.sh xtask assembly lock check
./hack/cargo.sh xtask verify --only runtime-assembly-residual
./hack/cargo.sh test -p journeys --test production_runtime
./hack/cargo.sh test -p journeys --features integration --test two_replica_runtime -- --test-threads=1
RSS_SMOKE_MODE=release ./deploy/smoke.sh
./hack/cargo.sh xtask verify --fast
```
