# Security Production Closeout

This runbook tracks the remaining gates before any runtime assembly may switch to `profile = "production"`.
The current `assemblies/runtime/assembly.toml` remains `profile = "demo"` until every blocker below is closed.

## Blockers

| Area | Blocker | Production gate |
|------|---------|-----------------|
| Token profiles / JWKS | Each listener is fixed to one typed token profile. RSS Access and Federated Access have separate issuer, audience, ES256 JWKS source and readiness; Service Token has separate issuer, audience, HS256 key and cluster-global replay. No generic/mixed provider is deployable. | `cargo xtask assembly validate` requires profile-specific typed providers plus `run()`-reachable JWKS load/watch, `rss_access_token_jwks_ready` / `federated_access_token_jwks_ready`, managed-resource, binding and anti-bait evidence. |
| Vault | Access-token signing and settings ConfigValue encryption must use active persistent Vault providers. | `cargo xtask assembly validate` requires active/persistent/backend `vault::VaultSigner` and `vault::VaultKeyProvider`. |
| SPIFFE / mTLS | Internal non-loopback traffic must use SPIFFE/mTLS. `service-token` is loopback local-test only. | `cargo xtask assembly validate` requires `run()`-reachable AST evidence for `MtlsServerConfig::from_spire`, `DomainHttpTransport::from_spire`, and `domain_transport_ready`; legacy Internal service-token migration env constants are rejected. |

## Triggers

- Flip an assembly to `profile = "production"` only in the same PR that proves the above gates.
- Rotate each access profile's JWKS independently and atomically; failed refresh must keep last-good keys and lower only that profile's readyz signal.
- For Vault Transit RSS Access signing, `export-vault-transit` must merge **Active + Retiring (and optional
  Next)** public keys into `RSS_ACCESS_TOKEN_JWKS_PATH` before starting server. When Retiring is configured,
  do not single-key or Active-only whole-file overwrite.
- Reject deployment if active RSS/Federated issuer, audience or canonical JWKS path overlaps, if Service issuer/audience overlaps either access profile, or if an unselected profile namespace is present.
- Remove any deployment use of `RSS_INTERNAL_SERVICE_TOKEN_MIGRATION_TICKET` or `RSS_INTERNAL_SERVICE_TOKEN_MIGRATION_EXPIRES_AT_UNIX`; they are no longer supported.

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
   after this point.
3. In one audited DBA maintenance transaction, revoke every active durable refresh token and every
   non-revoked session. The runtime role is intentionally not a bulk-revocation authority; use the
   approved database-owner maintenance path and record affected row counts:

   ```sql
   BEGIN;
   UPDATE refresh_tokens SET status = 'revoked' WHERE status = 'active';
   UPDATE sessions SET revoked = true WHERE revoked = false;
   COMMIT;
   ```

4. Keep ingress closed for **900 seconds from the final old replica stop**. This is the longest
   profile lifetime (RSS/Federated Access 900s; Service Token 300s) and prevents an in-flight old
   credential from straddling the trust-chain switch. Do not shorten this window based on the
   Service Token lifetime.
5. Start only the new binary with the sealed new configuration. Keep it out of the serving pool
   until `rss_access_token_jwks_ready` and/or `federated_access_token_jwks_ready` (as selected) and
   all other required readiness probes are healthy. Then open ingress and require every user,
   device and operator to authenticate again; no refresh/session state survives the cutover.
6. Verify the correct profile succeeds only on its fixed listener. Verify an archived old token,
   every active cross-profile token/listener pairing, duplicate `Authorization`, and duplicate
   Service `X-Tenant-ID` all return 401. Confirm `/readyz` names only selected profile probes and
   logs/metrics/error bodies contain no token, subject, tenant, `kid`, or `jti`.

Rollback is also whole-generation only: close ingress, scale the new pool to zero, revoke any
refresh/session records minted by the new generation using the same audited transaction, restore
the exact previous binary **and** its exact previous configuration/key bundle, wait for its complete
readiness set, then reopen ingress and require authentication again. Never roll back only the
binary, only configuration, only one listener, or one key source; never add aliases, dual reads or a
mixed old/new pool to reduce downtime. If the previous bundle cannot be restored as a unit, keep
ingress closed and roll forward with a corrected new bundle.

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
