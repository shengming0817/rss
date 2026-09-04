# rss-platform

`rss-platform` is the provider-free asynchronous application waist for RSS. Applications author
typed `Contract` markers and async `Handler` implementations; the host supplies a read-only
`HostView`, while authenticated request values arrive as `rss-request-context` views.

The crate deliberately contains no JWT/JWKS verification, provider catalog, process lifecycle,
runtime plan, cancellation authority, or inventory publisher. Those remain owned by official
integrations and the composition root.
Building an application yields a dispatcher and an instance-bound `TrustedContextMinter`. The
integration keeps that non-cloneable minter private and uses it only after validating input. Dispatch
requires the resulting move-only `AdmittedRequest`; callers cannot enter dispatch by assembling an
authority-free `RequestContextView`, and a capability minted for another application is rejected.

```rust
use rss_platform::{ApplicationModule, ModuleName};

let module = ApplicationModule::new(ModuleName::parse("inventory")?);
assert_eq!(module.name().as_str(), "inventory");
# Ok::<(), rss_platform::NameError>(())
```
