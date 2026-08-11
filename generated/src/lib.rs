//! generated — 契约派生 wire 类型（committed，一等审查材料）。
//! 由 `cargo xtask codegen` 生成；勿手改。漂移由 `cargo xtask codegen --check` 守（CI 门）。

/// Field-level at-rest protection metadata generated from schema `x-protection`.
///
/// This is declarative metadata only. It does not perform encryption/decryption and intentionally
/// does not depend on runtime protection types such as `KeyProvider`, `ProtectionContext`, or AAD
/// constructors.
pub trait FieldProtectionMetadata {
    /// Field protection declarations for this DTO, expressed in wire field paths.
    const FIELD_PROTECTIONS: &'static [FieldProtectionSpec];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldProtectionSpec {
    /// Dotted wire path from the DTO root, for example `value` or `profile.secret`.
    ///
    /// Rust field names produced by codegen, such as `store_id`, are never used here.
    pub field_path: &'static str,
    /// At-rest declaration. `Plain` is emitted only when schema explicitly says `atRest: plain`.
    pub at_rest: ProtectionAtRest,
    /// Encryption mode for encrypted fields. `None` means `at_rest` is `Plain`.
    pub mode: Option<ProtectionMode>,
    /// Wire key scope from schema, currently for example `tenant`.
    pub key_scope: Option<&'static str>,
    /// AAD dimensions declared by schema, preserved in declaration order.
    pub aad: &'static [ProtectionAadDim],
    /// Required rationale for equality-revealing modes.
    pub reason: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionAtRest {
    /// The field is explicitly declared as not encrypted at rest.
    Plain,
    /// The field is declared as encrypted at rest.
    Encrypt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionMode {
    /// Randomized encryption: same plaintext may produce different ciphertext.
    Randomized,
    /// Deterministic encryption: exposes plaintext equality by design.
    Deterministic,
    /// Blind index: exposes a stable lookup token by design.
    BlindIndex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionAadDim {
    /// Tenant boundary dimension.
    Tenant,
    /// Settings/config key dimension.
    ConfigKey,
    /// Field path dimension.
    Field,
    /// Schema version dimension.
    SchemaVersion,
}
pub mod command;
pub mod device_certificate;
pub mod event;
pub mod http;
pub mod projection;
pub mod saga;
