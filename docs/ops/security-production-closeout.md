# Security Production Closeout

This runbook tracks the remaining gates before any runtime assembly may switch to `profile = "production"`.
The current `assemblies/runtime/assembly.toml` remains `profile = "demo"` until every blocker below is closed.

## Blockers

| Area | Blocker | Production gate |
|------|---------|-----------------|
| OIDC / JWKS | Serving runtime must verify JWTs from a local JWKS file source, not static env keys. The file must be rotated by infra and expose `oidc_jwks_ready`. Access-token signing key `kid` and verifier JWKS must be same-source. | `cargo xtask assembly validate` requires `oidc::OidcProvider` active/persistent/backend plus `run()`-reachable AST evidence for `JwksKeySource::load_and_watch`, `keys_jwks`, `OidcJwksReadyProbe`, probe registration, and OIDC managed-resource wiring. |
| Vault | Access-token signing and settings ConfigValue encryption must use active persistent Vault providers. | `cargo xtask assembly validate` requires active/persistent/backend `vault::VaultSigner` and `vault::VaultKeyProvider`. |
| SPIFFE / mTLS | Internal non-loopback traffic must use SPIFFE/mTLS. `service-token` is loopback local-test only. | `cargo xtask assembly validate` requires `run()`-reachable AST evidence for `MtlsServerConfig::from_spire`, `DomainHttpTransport::from_spire`, and `domain_transport_ready`; legacy Internal service-token migration env constants are rejected. |

## Triggers

- Flip an assembly to `profile = "production"` only in the same PR that proves the above gates.
- Rotate OIDC keys by updating the JWKS file atomically; failed refresh must keep last-good keys and make readyz unhealthy.
- For Vault Transit access JWT signing, export the current public key for `RSS_JWT_ES256_KEY_ID` into the JWKS file before starting server.
- Remove any deployment use of `RSS_INTERNAL_SERVICE_TOKEN_MIGRATION_TICKET` or `RSS_INTERNAL_SERVICE_TOKEN_MIGRATION_EXPIRES_AT_UNIX`; they are no longer supported.

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
