# rss-redact-derive

This is the procedural-macro implementation used by `rss-redact`.

Application and library code should depend on `rss-redact`, which re-exports `#[derive(Redact)]`.
Keeping the macro in a dedicated `proc-macro` package is required by Rust, while the re-export keeps
one user-facing redaction dependency.
