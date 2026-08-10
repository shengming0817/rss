# rss-platform

`rss-platform` is the provider-free, typed in-process Platform Public application kernel. It owns
static ES256 access verification, typed dispatch, bounded drain, and closed diagnostics; it does
not own HTTP listeners, runtime providers, or a service locator.

The lifecycle is deliberately linear:

```rust,ignore
let issuer = TrustedIssuer::from_jwks_json(issuer_url, audience, jwks_json)?;
let application = ApplicationBuilder::new(ApplicationName::parse("inventory_app")?)
    .trusted_issuer(issuer)
    .module(
        ApplicationModule::new(ModuleName::parse("runtime")?)
            .handler::<contracts::RuntimeInventory, _>(inventory_handler),
    )
    .build()?;
let handle = application.start();
let dispatcher = handle.dispatcher();
let access = dispatcher.verify(&AccessToken::parse(encoded_token)?, now)?;
let response = dispatcher.dispatch::<contracts::RuntimeInventory>(
    &access,
    RequestId::parse("request-1")?,
    contracts::RuntimeInventoryRequest,
)?;
let conditions = handle.conditions();
let diagnostics = handle.diagnostics();
let report = handle.shutdown(std::time::Duration::from_secs(5))?;
```

`Contract` is sealed: only generated markers can reach dispatch. `AccessToken` and verified
authority views cannot be cloned, formatted, serialized, or constructed by consumers. A cloned
`Dispatcher` rechecks the private authority time window on every call, rejects new work during
drain, and fails closed after stop. `TrustedIssuer::verify` uses the standard `kind` and
`tenant_id` claims with zero skew; integrations that already own bounded profile configuration can
pass an immutable `VerificationPolicy` to `verify_with_policy` without creating a second signature
or claims decision path. Stage errors expose only
typed diagnostic codes; their text and source chain never contain token, subject, tenant, key, or
provider configuration data.

Collection-valued `runtime.inventory` builders reject duplicate or non-canonically ordered values.
Inspect `InventoryValueError::code` for a closed, non-sensitive reason.
