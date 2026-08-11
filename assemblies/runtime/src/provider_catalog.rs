//! Compile-link proof for the generated provider catalog.

const _: () = assert!(!crate::providers_gen::PROVIDER_CATALOG.is_empty());
