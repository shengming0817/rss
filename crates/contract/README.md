# rss-contract

`rss-contract` provides canonical, authority-free values used by RSS public APIs: contract
identities, absolute timepoints, opaque pagination cursors, data classification, and redact-safe
errors, and the protocol-neutral `Contract` trait.

`Contract` binds associated Request/Response types to one ContractDescriptor. It is the sole
owner previously located in rss-platform; consumers import it directly from rss-contract.
The trait does not prove schema/DTO equivalence or authorize execution. No old export remains.

Values can be parsed at runtime or authored as validated constants. The package deliberately does
not contain a registry, generated catalog, runtime binding, or admission authority.
Parsing errors distinguish empty, overlong, malformed, and zero-version identities without
echoing rejected input.

`ContractId` is at most 255 ASCII bytes and contains at least two dot-separated segments.
Each segment starts with a lowercase letter, followed by lowercase letters, digits, or single
hyphens between letters/digits. For example, `a.b` and `a-b.c1.d-2` are valid; `foo`, `foo-.bar`,
and `foo--bar.baz` are rejected. Runtime parsing and all static identity/descriptor constructors
share one validator; invalid static construction panics (a compile error in a constant).
Identifiers are never normalized, aliased, or accepted through a legacy parser.

The #2325 correction tightens the previously over-permissive parser. The owner confirmed there
are no persisted or external noncanonical identities to retain. Canonical IDs retain their exact
bytes, versions, routing keys and fingerprints. Message headers, PostgreSQL decoding, recovery
and archive readers apply the same validation and reject noncanonical identities through their
existing errors. This confirmation does not authorize changes to other persisted identities.

`Timepoint` is a non-negative Unix `int64` seconds value with total ordering and fallible
conversions. It does not provide a clock, `now`, deadlines, or scheduling authority.

`PageCursor` stores at most 4096 bytes of canonical unpadded base64url. Its contents stay opaque to
Foundation: consumers classify a well-formed token as `Stale` when it no longer matches their
tenant, query, version, or provider state. Cursor diagnostics never echo the token.

`DataClass` is the sole closed vocabulary for public, internal, PII, and secret data. It does not
contain redaction engines or policy. `SafeError` stores only a closed `SafeErrorCode`; its category
and message are fixed by that code, and it cannot carry provider sources, arbitrary messages,
payloads, or details.

```rust
use rss_contract::{
    ContractDescriptor, ContractId, ContractVersion, DataClass, PageCursor, SafeError,
    SafeErrorCode, Timepoint,
};

let id = ContractId::parse("runtime.inventory")?;
let version = ContractVersion::parse("v1")?;
assert_eq!(id.as_str(), "runtime.inventory");
assert_eq!(version.major(), 1);
assert_eq!(Timepoint::try_from(42)?.unix_seconds(), 42);
assert_eq!(PageCursor::parse("AQ")?.as_str(), "AQ");
assert_eq!(DataClass::Pii.as_str(), "pii");
assert_eq!(
    SafeError::new(SafeErrorCode::Unavailable).to_string(),
    "service unavailable"
);

const INVENTORY: ContractDescriptor = ContractDescriptor::from_static(
    "runtime.inventory",
    1,
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
);
assert_eq!(INVENTORY.id(), "runtime.inventory");
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Independent consumption proof

From the RSS checkout, run:

```sh
cargo test -p rss-contract --locked
python3 -m unittest discover -s hack/tests -p test_contract_package_proof.py
python3 hack/contract-package-proof.py --source
python3 hack/contract-package-proof.py --artifacts /path/to/candidate --revision <full-commit-sha>
```

The candidate directory uses the existing `packages.tsv`, `SHA256SUMS` and `.crate` format.
The revision must match the proof checkout and the archive’s `.cargo_vcs_info.json`; its origin
must be the clean `crates/contract` path. Both consumers run the same `tests/public_values.rs`
and `tests/safe_semantics.rs`; the artifact consumer reads them from the verified archive itself.
Missing, empty, ignored or failed suites cannot satisfy the proof. The package currently has no
Cargo dependencies; any additional resolved package fails the proof until its consumption is
explicitly designed. Each run uses a temporary independent workspace, lock and target directory,
an empty Cargo home and the checkout's pinned Rust toolchain. Before running tests, rustc dep-info
must place every transitive source input (including `include!` and `include_str!`) within the
consumer or exact Contract package; checking only Cargo target roots is insufficient.

The candidate workflow saves `contract-proof.json` with the revision, version, archive SHA-256,
lock digest and executed test counts; commands and test results are in the job log. This proves
behavior of that candidate artifact, not registry publication or product acceptance. Full private
boundary tests and compile-fail documentation remain component tests, without a second copy.

Licensed under the MIT License.
