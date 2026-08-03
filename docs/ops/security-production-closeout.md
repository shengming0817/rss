# Security Production Closeout

This runbook records the gates that the full runtime must continue satisfying after switching to
`profile = "production"`. The switch is a ratchet: validation rejects a downgrade and the governed
manifest, RuntimePlan, generated artifacts and lock rotate together.

## Blockers

| Area | Blocker | Production gate |
|------|---------|-----------------|
| Token profiles / JWKS | Each listener is fixed to one typed token profile. RSS Access is User-only and requires the complete grant quartet; its kind is not configurable. Federated Access owns the non-User allowlist. The profiles have separate issuer, audience, ES256 JWKS source and readiness; Service Token has separate issuer, audience, HS256 key and cluster-global replay. No generic/mixed provider is deployable. | `cargo xtask assembly validate` requires profile-specific typed providers plus `run()`-reachable JWKS load/watch, `rss_access_token_jwks_ready` / `federated_access_token_jwks_ready`, managed-resource, binding and anti-bait evidence. |
| RSS User grant currency | Every protected RSS request verifies the JWT first, then checks the exact signed grant/User/tenant/auth-time/epoch against one tenant-scoped durable grant/account snapshot. | Missing, terminal, expired or mismatched state returns 401 before the handler; store failure returns 503 and never falls back to JWT-only evidence. |
| Vault | Access-token signing, settings ConfigValue encryption, and settings secret resolution must use active persistent Vault providers. Secret resolution additionally requires one strict, non-empty tenant/store allowlist. | `cargo xtask assembly validate` requires active/persistent/backend `vault::VaultSigner`, `vault::VaultKeyProvider`, and `vault::VaultSecretResolver`; startup rejects a missing, malformed, empty, duplicate or cross-tenant-overlapping `RSS_VAULT_TENANT_STORE_ALLOWLIST_JSON`, while a KV-only failure lowers `vault_secret_resolver_ready`. |
| SPIFFE / mTLS | Internal non-loopback traffic must use SPIFFE/mTLS. `service-token` is loopback local-test only. | `cargo xtask assembly validate` requires `run()`-reachable AST evidence for `MtlsServerConfig::from_spire`, `DomainHttpTransport::from_spire`, and `domain_transport_ready`; legacy Internal service-token migration env constants are rejected. |
| Egress TLS (AMQP/Redis/S3/PG) | **Scope = `assemblies/runtime` only** (`profile=production`). Runtime egress always Deny + VerifyFull. `RSS_AMQP_ALLOW_PLAINTEXT` / `RSS_REDIS_ALLOW_PLAINTEXT` / `RSS_S3_ALLOW_PLAINTEXT` / `RSS_PG_SSL_MODE` are banned (fail-fast if present). Required private CA paths: `RSS_AMQP_CA_CERT_PEM_PATH`, `RSS_REDIS_CA_CERT_PEM_PATH`, `RSS_S3_CA_CERT_PEM_PATH`, `RSS_PG_SSL_ROOT_CERT_PATH`. Bundle URLs must use `amqps://` / `rediss://` / `https://`. Ingress-only exception: `RSS_LISTENER_ALLOW_PLAINTEXT=dev-container` for compose port mapping (#1649). Other production assemblies (e.g. `identityaudit` WebPki AMQP/Redis) are explicitly deferred outside this closeout gate. | `cargo xtask assembly validate` applies the egress-tls AST gate only when `manifest.name == "runtime"`; startup rejects banned knobs and missing CA paths; demo compose serves TLS via `deploy/demo-tls/generate-demo-cas.sh`. |
| Device certificate revocation | Runtime assembly uses the persistent PostgreSQL provider with exact tenant/device/serial scope, logical expiry, fail-closed reads and fixed bounded retention. No SoftCA fallback is deployable. | Startup must mint the private revocation capability receipt only after table/RLS/ACL/maintenance-role/function verification; `device-revocation-store` is active/persistent and produces its real probe + worker. |

## Triggers

- Flip an assembly to `profile = "production"` only in the same PR that proves the above gates.
- Production provider posture is closed: declarations are active and persistent except the exact
  replica-local `GovernorLimiter`; the executable RuntimePlan contains active declarations only.
  Draft, noop, memory and fail-open alternatives are not outage recovery mechanisms.
- Rotate each access profile's JWKS independently and atomically; failed refresh must keep last-good keys and lower only that profile's readyz signal.
- For Vault Transit RSS Access signing, `export-vault-transit` must merge **Active + Retiring (and optional
  Next)** public keys into `RSS_ACCESS_TOKEN_JWKS_PATH` before starting server. When Retiring is configured,
  do not single-key or Active-only whole-file overwrite.
- Reject deployment if active RSS/Federated issuer, audience or canonical JWKS path overlaps, if Service issuer/audience overlaps either access profile, or if an unselected profile namespace is present.
- Remove `RSS_ACCESS_TOKEN_TRUSTED_KINDS` from every release bundle. It is no longer a supported RSS key; configure non-User kinds only through `RSS_FEDERATED_ACCESS_TOKEN_TRUSTED_KINDS` on a Federated listener.
- Remove any deployment use of `RSS_INTERNAL_SERVICE_TOKEN_MIGRATION_TICKET` or `RSS_INTERNAL_SERVICE_TOKEN_MIGRATION_EXPIRES_AT_UNIX`; they are no longer supported.
- Publish the Vault tenant/store allowlist only as the strict `{"bindings":[{"tenantId":"<uuid>","storeId":"<id>","mount":"<kv-v2-mount>","kvPathPrefix":"<prefix>"}]}` shape. Root/binding unknown fields, empty bindings, duplicate `(tenantId, storeId)`, invalid paths and cross-tenant physical namespace overlap are fatal; no alias or fallback is supported.
- Provision `<kvPathPrefix>/.rss-readiness` for every binding and grant the runtime token read access to the binding namespace. The canary key is reserved for capability health and must not contain business material.
- Treat migration `0072` as a non-rolling, forward-only cutover. Apply the additive migration with
  revocation traffic disabled, quiesce the revocation entry points, disable every old
  workload/controller/job restart path, and prove the old generation process inventory is zero.
  Before any new binary starts, save one PostgreSQL snapshot proving the five static
  `rss-postgres-{writer,reader,audit-admin,maintenance,migrator}` lanes have zero total connections;
  only then start the new binary and reopen traffic. After startup those lane names identify duties,
  not generations, so continue proving old-generation zero only from deployment process inventory.
  After the new binary accepts its first certificate revocation, never roll back to a binary that
  reads an in-memory ledger; keep traffic stopped and roll forward with a corrected migration/runtime
  instead.
- Treat the #1842 identity credential-security writer switch as a non-rolling application cutover,
  even though it adds no migration. First stop ingress for password change, account status
  restriction, logout and any internal reactivation caller; then drain every in-flight
  old-generation identity writer and scale the old serving generation to zero. Prove both the old
  process inventory and its PostgreSQL writer connections are zero before starting the new
  generation and reopening traffic. Never mix the old password-only CAS writer with the new
  `PgIdentitySecurityLifecycle`: the old path cannot atomically bump account epoch, revoke
  grant/family and append `identity.security-event`. There is no dual-write, compatibility helper or
  rolling rollback. If startup or verification fails, keep these writes quiesced and roll forward.
  Reactivation after cutover remains eventless and must not revive any revoked/compromised grant or
  refresh family.

## Atomic Vault Allowlist Cutover

Treat the serving binary and `RSS_VAULT_TENANT_STORE_ALLOWLIST_JSON` as one sealed generation.
Validate the strict JSON with the same binary before any provider/runtime preparation:

```bash
rss vault-allowlist validate --file /run/rss-config/vault-allowlist.json
```

The validator accepts only `--file <path>` or `--stdin`, needs no Vault provider configuration or
network, and emits only a static success/error category. After validation, stop routing to the old
generation, and atomically publish the new binary plus its exact config bundle. Invalid allowlist
state is a startup failure before listeners;
an unmapped tenant/store is a request-level `Forbidden` rejected before Vault I/O and cannot write
readiness. Vault Transit failure is represented by `keyprovider_ready`; KV mount/ACL/canary failure is
represented independently by `vault_secret_resolver_ready`. Either provider-down state yields 503,
and neither may be collapsed into `Forbidden`.

Rollback restores the exact previous binary and previous allowlist/config bundle together, waits for
the complete readiness set, and only then restores traffic. This cutover changes neither database
schema nor persisted data/ciphertext format, so it requires no database or persistence rollback.
Never deploy only one half of the pair, and never add a legacy variable alias, dual reader, default
allowlist or compatibility fallback.

## RSS Access Signing Key Rotation

Planned rotation keeps verify overlap so in-flight access tokens remain valid while JWKS propagates.
Mint is always Active-only: Next and Retiring never sign. Coordinate Vault Transit key provisioning,
JWKS publication, and runtime env as one audited change set per replica generation.

### Environment

| Variable | Required | Meaning |
|----------|----------|---------|
| `RSS_ACCESS_TOKEN_SIGNING_ACTIVE_KEY_ID` | ✔ (rss-access) | Sole mint `kid` (Active). |
| `RSS_ACCESS_TOKEN_SIGNING_NEXT_KEY_ID` | optional | Staged Next `kid` (not used for mint). Publish its public key to JWKS before promoting. |
| `RSS_ACCESS_TOKEN_SIGNING_RETIRING` | optional | Comma-separated `kid=unixSeconds` entries. Each `unixSeconds` is `verify_until` for that Retiring kid. |
| `RSS_ACCESS_TOKEN_SIGNING_ROTATED_AT` | required when Retiring is set | Unix seconds when Active/Retiring cutover started; overlap is measured from this instant. |
| `RSS_ACCESS_TOKEN_TTL_SECS` | ✔ (rss-access) | Max access-token TTL (`1..=900`). Feeds planned overlap as `ttl`. |
| `RSS_ACCESS_TOKEN_ROTATION_CLOCK_SKEW_SECS` | optional | Clock skew budget (default `60`, max `86400`). |
| `RSS_ACCESS_TOKEN_ROTATION_JWKS_PROPAGATION_SLO_SECS` | optional | JWKS propagation SLO (default `300`, max `86400`). |
| `RSS_ACCESS_TOKEN_ROTATION_MARGIN_SECS` | optional | Extra safety margin (default `60`, max `86400`). |
| `RSS_ACCESS_TOKEN_ROTATION_MODE` | optional | Exactly `planned` (default) or `emergency`. |

### Overlap (planned)

Startup rejects planned rotation when any Retiring entry fails:

```text
verify_until - rotated_at >= ttl + clock_skew + jwks_propagation_slo + margin
```

Exact equality passes; one second short fails. Defaults with `ttl=900` yield a minimum overlap of
`900 + 60 + 300 + 60 = 1320` seconds unless operators raise the policy knobs.

### Planned steps

1. **Prepare Next** — Create the new Vault Transit signing key (or new version / key name). Set
   `RSS_ACCESS_TOKEN_SIGNING_NEXT_KEY_ID` to that `kid`. Do not promote Active yet.
2. **Publish public key to JWKS** — Run `export-vault-transit` to merge Active + Retiring (if any) + Next
   into `RSS_ACCESS_TOKEN_JWKS_PATH` (atomic rename / Secret projection). Ensure the Next `kid` is included
   before promotion. Wait until every verifier replica has refreshed and `rss_access_token_jwks_ready` stays
   healthy with the Next `kid` present.
3. **Switch Active / Retiring** — Promote Next → Active. Move the previous Active into
   `RSS_ACCESS_TOKEN_SIGNING_RETIRING` as `oldKid=verifyUntilUnix`. Clear or leave Next empty / set
   the following staged key. Set `RSS_ACCESS_TOKEN_SIGNING_ROTATED_AT` to the cutover unix time and
   `RSS_ACCESS_TOKEN_ROTATION_MODE=planned`. Choose `verify_until` so the overlap formula holds.
4. **Wait overlap** — Keep Retiring keys in the merged JWKS export and in `SIGNING_RETIRING` until
   `now >= verify_until` for every entry. Do not remove public keys early; clients may still present
   tokens signed by Retiring kids. After any Retiring `verify_until` passes,
   `rss_access_token_signing_rotation` reports **Degraded** (readyz still 200; operator cleanup debt;
   traffic continues). During overlap, a Retiring kid missing from JWKS makes the probe **Unhealthy**
   (503) under `planned` mode or **Degraded** (200) under `emergency` mode.
5. **Remove Retired** — After every Retiring deadline, re-run `export-vault-transit` without retired kids
   (Active + any remaining Retiring/Next only) and clear them from `RSS_ACCESS_TOKEN_SIGNING_RETIRING`
   (and `SIGNING_ROTATED_AT` when no Retiring remains). Confirm `rss_access_token_jwks_ready` and
   `rss_access_token_signing_rotation` return to **Healthy**.

### Emergency mode

Set `RSS_ACCESS_TOKEN_ROTATION_MODE=emergency` only under incident approval when the Active private
key is compromised or must be abandoned immediately.

- Overlap validation is **exempt**: startup does not require `verify_until - rotated_at >= min_overlap`.
- Immediately retire the compromised Active: mint only on the replacement Active; do **not** keep the
  old kid in Retiring for a long verify window unless incident policy explicitly requires brief
  forensic acceptance.
- Expect abrupt invalidation of in-flight tokens signed by the abandoned key; force re-auth /
  refresh as needed and record the blast radius.
- Still publish the replacement public key to JWKS **before** traffic trusts the new Active, and keep
  `rss_access_token_jwks_ready` / `rss_access_token_signing_rotation` healthy on the replacement set.
- Return to `planned` for the next routine rotation; do not leave production permanently in emergency.

### Readiness

| Probe | Role during rotation |
|-------|----------------------|
| `rss_access_token_jwks_ready` | Profile JWKS load/watch healthy (last-good retained on refresh failure). |
| `federated_access_token_jwks_ready` | Federated JWKS only; independent of RSS Access signing rotation. |
| `rss_access_token_signing_rotation` | Active `kid` present in JWKS. Retiring past `verify_until` → **Degraded** (readyz still 200; operator cleanup debt; traffic continues). In overlap window, Retiring kid missing from JWKS → **Unhealthy** (503) in `planned` mode or **Degraded** (200) in `emergency` mode. Next missing from JWKS remains **Healthy** with detail `next signing key not yet in jwks`. |

Keep new replicas out of the serving pool until selected JWKS ready probes and
`rss_access_token_signing_rotation` are **not Unhealthy** (HTTP 200). **Degraded** cleanup debt
(Retiring past `verify_until`) does **not** block traffic—only Unhealthy (503) must keep a replica out of
the pool. Metric `authn_rotation_verify_until_timestamp` exposes the nearest Retiring `verify_until` as a
**unix timestamp gauge** (not remaining seconds); alerts may derive `(timestamp - now)` for time-to-deadline.

## Atomic Token Profile Cutover

This is a breaking, stop-the-world authentication cutover. Do not place old and new binaries in the
same serving pool, do not canary them behind a shared listener, and do not let a load balancer route
traffic to both generations. Old and new token/config semantics are mutually incompatible; a mixed
pool would make authentication depend on which replica receives the request.

1. Render and validate one sealed release bundle containing the new binary, all three listener
   selectors, only the selected profile namespaces, profile-exclusive JWKS files, and the Service
   Token key when selected. Reject the release if any legacy/generic token variable is present, if
   an unselected namespace is present, or if issuer/audience/JWKS isolation validation fails.
2. Quiesce login, refresh and authenticated API ingress, then scale the old serving pool to zero.
   Record the time at which the final old replica stopped; no old process may mint or accept a token
   after this point. From issuance evidence, record `last_issue_exp` as the greatest `exp` of any
   token the old generation could have issued. If that evidence is unavailable, conservatively set
   it to the final old replica stop time plus the greatest configured old-profile token lifetime
   (currently 900 seconds).
3. In one audited DBA maintenance transaction, revoke every active durable refresh token and every
   active AuthGrant. The runtime role is intentionally not a bulk-revocation authority; use the
   approved database-owner maintenance path and record affected row counts:

   ```sql
   BEGIN;
   UPDATE refresh_tokens SET status = 'revoked' WHERE status = 'active';
   UPDATE auth_grants
      SET status = 'revoked', closed_at = clock_timestamp(), close_reason = 'logout_all'
    WHERE status = 'active';
   COMMIT;
   ```

4. Calculate and record one absolute drain deadline using the deployed values and an explicit,
   positive operational safety margin:

   ```text
   drain_until = last_issue_exp
               + verifier_leeway
               + issuer_clock_skew
               + safety_margin
   ```

   Use the greatest verifier expiry leeway and issuer clock-skew bound across every old/new profile
   involved in the cutover. Keep ingress closed until a trusted clock is **strictly later** than
   `drain_until`. Waiting only 900 seconds is insufficient: 900 seconds is only the conservative
   lifetime used to derive `last_issue_exp`, before leeway, clock skew and the safety margin are
   added. Record every input, its source and the resulting deadline in the change evidence.
5. Start only the new binary with the sealed new configuration. Keep it out of the serving pool
   until `rss_access_token_jwks_ready` and/or `federated_access_token_jwks_ready` (as selected) and
   all other required readiness probes are healthy. Then open ingress and require every user,
   device and operator to authenticate again; no refresh/AuthGrant state survives the cutover.
6. Verify the correct profile succeeds only on its fixed listener. Verify every active cross-profile
   token/listener pairing, duplicate `Authorization`, duplicate Service `X-Tenant-ID`, missing
   required Service challenger header, claim/header mismatch, missing signed `tenant_id` (service
   profile), and bad signature all return 401 — using only current-protocol fixtures; do **not**
   archive or present pre-cutover private-MAC / legacy token samples as canary evidence. Confirm
   `/readyz` names only selected profile probes and logs/metrics/error bodies contain no token,
   subject, tenant, `kid`, `sid`, `jti`, `auth_time`, or `authn_epoch`.

Rollback is also whole-generation only: close ingress, scale the new pool to zero, revoke any
refresh/AuthGrant records minted by the new generation using the same audited transaction, restore
the exact previous binary **and** its exact previous configuration/key bundle, wait for its complete
readiness set, then reopen ingress and require authentication again. Never roll back only the
binary, only configuration, only one listener, or one key source; never add aliases, dual reads or a
mixed old/new pool to reduce downtime. If the previous bundle cannot be restored as a unit, keep
ingress closed and roll forward with a corrected new bundle.

## Atomic Service Token Standard JWS Cutover

This is the #1997 amendment to Service Token: standard compact JWS HS256 with signed canonical
`tenant_id`, exact-one `X-Tenant-ID` challenger equality, and removal of the private MAC path.
It does **not** add configuration keys, dual-read, or a T3/Soft gate. Ops drain is not a code
compatibility window. The final tree and this runbook **do not** keep or require archived old /
private-MAC token samples as negative evidence.

1. Stop every old-generation mint path and quiesce service-token traffic (Internal service-token
   listeners, operator maintenance callers, and any local-test mint still on the pre-cutover
   generation). Record the time the final old replica stopped issuing or accepting tokens.
2. From issuance evidence, record `last_issue_exp` as the greatest `exp` of any service token the
   old generation could have issued. If that evidence is unavailable, set it conservatively to
   final stop time plus the Service Token maximum lifetime (300 seconds).
3. Calculate one absolute drain deadline with existing verifier/issuer bounds and an explicit
   positive operational safety margin — reuse deployed values; do not invent new knobs:

   ```text
   drain_until = last_issue_exp
               + verifier_leeway
               + issuer_clock_skew
               + safety_margin
   ```

   Keep ingress and mint closed until a trusted clock is **strictly later** than `drain_until`.
   Waiting only 300 seconds is insufficient: 300 seconds derives `last_issue_exp`, before leeway,
   skew and margin. Record every input, source and the resulting deadline in the change evidence.
4. Deploy mint, verify and runtime as **one** sealed generation (same binary + same Service Token
   issuer/audience/HS256 bundle). Do not split mint-only or verify-only rollout; do not place
   pre-cutover and standard-JWS replicas in the same serving pool; do not dual-read both
   signing-input shapes.
5. Keep the new generation out of the pool until required readiness probes are healthy. Reopen
   traffic only after canary proves **current-protocol** boundaries: matching signed `tenant_id` +
   exact-one challenger header succeeds; missing header, duplicate header, claim/header mismatch,
   missing `tenant_id` claim, and bad signature all return 401; mTLS still establishes no ambient
   tenant. Do **not** keep, mint, or present archived private-MAC / legacy tokens for this check.
6. Sync deployment consumers of OIDC verify closed-set `reason` labels with the new generation
   (scrapers, log filters, runbooks that match exact strings). This is a label-map cutover only —
   not a dashboard/alert product change:

   | Transition | Label |
   |------------|-------|
   | Retire | `service_tenant_claim_forbidden` |
   | Retain / verify | `missing_tenant_binding` (missing exact-one challenger header) |
   | Enable / verify | `tenant_claim_header_mismatch` (claim/header equality fail) |
   | Enable / verify | `scoped_principal_missing_tenant` (missing signed `tenant_id` claim) |
   | Enable / verify | `tenant_not_canonical` (non-canonical tenant claim) |

   Duplicate `X-Tenant-ID` is rejected at the httpserve exact-one header boundary before OIDC verify
   and therefore has **no** OIDC closed-set `reason` label — canary it only as HTTP 401; do **not**
   invent a scraper label for that path. Do **not** keep a reason, alias, or canary for the retired
   private-MAC / “tenant claim forbidden” protocol, and do **not** archive old tokens solely to
   exercise a retired label.

Rollback is whole-generation only: close traffic, scale the new pool to zero, restore the exact
previous binary **and** its exact previous Service Token config/key bundle together, wait for
readiness, then reopen. Never reintroduce a non-standard signing-input path in a new binary, never
add an alias or dual reader to shorten downtime, and never introduce a temporary Soft/T3 gate for
mixed semantics. If the previous bundle cannot be restored as a unit, keep traffic closed and roll
forward.

## Acceptance Commands

```bash
cargo test -p xtask assembly
cargo test -p runtime oidc_jwks
cargo xtask assembly validate
cargo xtask verify --fast
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

`cargo xtask assembly validate` is the machine gate. Markdown text is descriptive only and must not be treated as production evidence.
