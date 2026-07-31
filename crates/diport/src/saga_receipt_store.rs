//! Protected Saga receipt DI port.
//!
//! `commit_completed` is the only public Completed transition funnel: providers must persist the
//! protected receipt and the matching journal row in one fenced local transaction. A plain
//! receipt `put` API intentionally does not exist.
//!
//! ref: oxidecomputer/steno src/saga_log.rs@b47f830210ed26b9b0bc0aa03f5ba1708333c30c

use dynosaur::dynosaur;

use consistency::{SagaAttempt, SagaLease, SagaReceiptFormatVersion, SagaReceiptScope};
use secure::Plaintext;

use crate::RedactedSource;

/// One exact receipt and its matching Completed journal sequence.
pub struct SagaStepCompletion {
    scope: SagaReceiptScope,
    attempt: SagaAttempt,
    format: SagaReceiptFormatVersion,
    plaintext: Plaintext,
    completed_seq: u64,
}

impl std::fmt::Debug for SagaStepCompletion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SagaStepCompletion(<redacted>)")
    }
}

impl SagaStepCompletion {
    /// Build the single composite completion command accepted by receipt providers.
    pub fn new(
        scope: SagaReceiptScope,
        attempt: SagaAttempt,
        format: SagaReceiptFormatVersion,
        plaintext: Plaintext,
        completed_seq: u64,
    ) -> Self {
        Self {
            scope,
            attempt,
            format,
            plaintext,
            completed_seq,
        }
    }

    /// Borrow the exact durable receipt scope without exposing plaintext.
    pub const fn scope(&self) -> &SagaReceiptScope {
        &self.scope
    }

    /// Return the positive attempt recorded for this completion.
    pub const fn attempt(&self) -> SagaAttempt {
        self.attempt
    }

    /// Return the closed receipt wire-format version.
    pub const fn format(&self) -> SagaReceiptFormatVersion {
        self.format
    }

    /// Return the journal sequence that must commit atomically with the receipt.
    pub const fn completed_seq(&self) -> u64 {
        self.completed_seq
    }

    /// Explicitly expose protected plaintext to the provider encryption boundary.
    pub const fn plaintext(&self) -> &Plaintext {
        &self.plaintext
    }

    /// Move the complete command into adapter-owned encryption and transaction preparation.
    ///
    /// The returned [`Plaintext`] is exposed only for immediate encryption; it must not be logged,
    /// cloned into diagnostics, or persisted outside the protected transaction.
    pub fn into_parts(
        self,
    ) -> (
        SagaReceiptScope,
        SagaAttempt,
        SagaReceiptFormatVersion,
        Plaintext,
        u64,
    ) {
        (
            self.scope,
            self.attempt,
            self.format,
            self.plaintext,
            self.completed_seq,
        )
    }
}

/// Exact durable receipt returned by `load_exact`.
pub struct StoredSagaReceipt {
    scope: SagaReceiptScope,
    attempt: SagaAttempt,
    format: SagaReceiptFormatVersion,
    plaintext: Plaintext,
    completed_seq: u64,
}

impl std::fmt::Debug for StoredSagaReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("StoredSagaReceipt(<redacted>)")
    }
}

impl StoredSagaReceipt {
    /// Hydrate a provider-verified exact receipt after all durable invariants have passed.
    ///
    /// Providers must verify trusted AAD, keyed integrity, scope, format, attempt and completion
    /// sequence before constructing this value. `plaintext` is the decrypted sensitive payload.
    pub fn new(
        scope: SagaReceiptScope,
        attempt: SagaAttempt,
        format: SagaReceiptFormatVersion,
        plaintext: Plaintext,
        completed_seq: u64,
    ) -> Self {
        Self {
            scope,
            attempt,
            format,
            plaintext,
            completed_seq,
        }
    }

    /// Borrow the trusted durable scope associated with the decrypted payload.
    pub const fn scope(&self) -> &SagaReceiptScope {
        &self.scope
    }

    /// Return the positive attempt stored with the receipt.
    pub const fn attempt(&self) -> SagaAttempt {
        self.attempt
    }

    /// Return the validated closed receipt wire-format version.
    pub const fn format(&self) -> SagaReceiptFormatVersion {
        self.format
    }

    /// Return the matching Completed journal sequence.
    pub const fn completed_seq(&self) -> u64 {
        self.completed_seq
    }

    /// Explicitly expose decrypted plaintext to the trusted receipt consumer.
    ///
    /// The returned reference must not be logged or retained beyond receipt processing.
    pub const fn plaintext(&self) -> &Plaintext {
        &self.plaintext
    }

    /// Consume the stored receipt and expose its decrypted plaintext to the trusted consumer.
    ///
    /// The returned value must not be logged or persisted without re-entering a protection
    /// boundary.
    pub fn into_plaintext(self) -> Plaintext {
        self.plaintext
    }
}

/// Closed result of a composite receipt + Completed commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaReceiptCommitOutcome {
    /// A new exact receipt/journal pair committed.
    Committed,
    /// The exact pair was already committed.
    IdempotentDuplicate,
    /// The durable receipt or journal pair conflicts with this completion.
    Conflict,
    /// The Saga lease token/epoch/expiry fence rejected the write.
    LeaseLost,
}

/// Safe in-process classification of receipt store failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaReceiptStoreErrorKind {
    /// Encryption, decryption or keyed-fingerprint operation failed.
    Protection,
    /// Provider/backend operation failed before a commit was attempted.
    Storage,
    /// The server may have committed but the caller did not receive a definitive acknowledgement.
    CommitUnknown,
    /// Stored metadata, HMAC, AAD or pair invariants are invalid.
    Integrity,
    /// Stored envelope format is not supported by this binary.
    UnsupportedFormat,
}

/// Redacted Saga receipt provider error.
#[derive(Debug, thiserror::Error)]
#[error("saga receipt store operation failed")]
pub struct SagaReceiptStoreError {
    kind: SagaReceiptStoreErrorKind,
    #[source]
    source: RedactedSource,
}

impl SagaReceiptStoreError {
    /// Wrap an adapter error without exposing its source through `Display`.
    pub fn new<E>(kind: SagaReceiptStoreErrorKind, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            kind,
            source: RedactedSource::new(source),
        }
    }

    /// Closed safe classification used by executor control flow.
    pub const fn kind(&self) -> SagaReceiptStoreErrorKind {
        self.kind
    }
}

/// Protected Saga receipt store.
///
/// The store is shared by concurrent Saga executor futures, so both the static and erased port
/// forms require `Send + Sync`.
#[trait_variant::make(SagaReceiptStore: Send)]
#[dynosaur(pub DynSagaReceiptStore = dyn(box) SagaReceiptStore, bridge(dyn))]
#[allow(async_fn_in_trait)]
pub trait SagaReceiptStoreLocal: Send + Sync {
    /// Atomically commit the protected receipt and matching Completed journal transition.
    async fn commit_completed(
        &self,
        lease: &SagaLease,
        completion: SagaStepCompletion,
    ) -> Result<SagaReceiptCommitOutcome, SagaReceiptStoreError>;

    /// Load only the exact trusted scope. Providers must decrypt with re-derived trusted AAD.
    async fn load_exact(
        &self,
        scope: &SagaReceiptScope,
    ) -> Result<Option<StoredSagaReceipt>, SagaReceiptStoreError>;

    /// Release provider resources.
    async fn shutdown(&self) -> Result<(), SagaReceiptStoreError>;
}
