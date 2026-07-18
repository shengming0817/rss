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
- For Vault Transit RSS Access signing, export the current public key for `RSS_ACCESS_TOKEN_ES256_KEY_ID` into `RSS_ACCESS_TOKEN_JWKS_PATH` before starting server.
- Reject deployment if active RSS/Federated issuer, audience or canonical JWKS path overlaps, if Service issuer/audience overlaps either access profile, or if an unselected profile namespace is present.
- Remove any deployment use of `RSS_INTERNAL_SERVICE_TOKEN_MIGRATION_TICKET` or `RSS_INTERNAL_SERVICE_TOKEN_MIGRATION_EXPIRES_AT_UNIX`; they are no longer supported.

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
