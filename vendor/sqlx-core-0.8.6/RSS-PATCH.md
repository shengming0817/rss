# RSS downstream patch: exclusive explicit TLS roots

This directory is the published `sqlx-core` 0.8.6 crate, vendored for RSS issue #1954.

- Upstream tag: `v0.8.6`
- Upstream commit: `bab1b022bd56a64f9a08b46b36b97c5cff19d77e`
- crates.io archive checksum: `ee6798b1838b6a0f69c007c133b8df5866302197e404e8b6ee8ed3e3a5e68dc6`
- Upstream licenses: MIT OR Apache-2.0; both license files are retained here.

The `rss-exclusive-explicit-roots` feature changes only rustls server-root initialization. When a
caller supplies `root_cert_path`, the store starts empty and receives only certificates from that
bundle. Without an explicit bundle, upstream WebPKI-root behavior is unchanged. The public
`ExclusiveExplicitRoots` marker makes downstream production consumers fail to compile if the
capability is removed or disabled.
Combining it with SQLx's native-tls backend is also a compile error because that backend retains
ambient system roots.

The crate root also allows the compiler's newer `mismatched_lifetime_syntaxes` lint. Cargo caps that
lint for the crates.io dependency but not for a local path dependency; the allow keeps the upstream
0.8.6 signatures unchanged under RSS's `clippy -D warnings` policy.

The canonical affected carrier verifies the crates.io archive checksum, the exact five-file delta,
all unchanged-file hashes, the exclusive-root unit tests, and the forbidden native-tls feature
union. Run it from the repository root with:

```bash
./hack/cargo.sh test -p postgres --test feature_manifest \
  exclusive_root_vendor -- --nocapture
```

The patch may be removed only when a released SQLx API supplies the same exclusive-root semantics,
the adapter consumes that API without a compatibility path, and the existing T1/T2 proofs pass.
