use crate::{DecodedAuditV1, Error, EventId, PreparedAuditV1, SourceId, codec};
use rss_ledger::{
    AppendRequest, ChainId, Entry, LedgerId, RecordId, Sequence, Verification, VerifiedWindow,
};
use rss_request_context::TenantId;

/// Fixed Audit V1 chain identity. Every tenant has one V1 audit sequence.
pub const AUDIT_CHAIN_ID: &str = "rss.audit.v1";

pub(crate) fn audit_record_id(source: &SourceId, event: &EventId) -> Result<RecordId, Error> {
    Ok(RecordId::parse(&format!(
        "v1:{}:{}",
        source.as_str(),
        event.as_str()
    ))?)
}

/// One authenticated Audit record and its ledger sequence.
///
/// Authentication is limited to the supplied window and does not prove durable commit or absence
/// of truncation.
pub struct VerifiedAuditEntryV1 {
    sequence: Sequence,
    record: DecodedAuditV1,
}

impl VerifiedAuditEntryV1 {
    /// Ledger position in the verified window.
    #[must_use]
    pub const fn sequence(&self) -> Sequence {
        self.sequence
    }

    /// Decoded authenticated record.
    #[must_use]
    pub const fn record(&self) -> &DecodedAuditV1 {
        &self.record
    }
}

impl std::fmt::Debug for VerifiedAuditEntryV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedAuditEntryV1")
            .field("sequence", &self.sequence)
            .finish_non_exhaustive()
    }
}

/// Authenticated Audit records for exactly one supplied ledger window.
pub struct VerifiedAuditWindow {
    ledger: Verification,
    records: Vec<VerifiedAuditEntryV1>,
}

/// Audit records decoded from an authenticated Ledger window, up to the first malformed record.
/// Storage adapters can check the associations of this prefix before reporting a later decode error.
pub struct DecodedAuditWindow<'a> {
    window: &'a VerifiedWindow,
    records: Vec<VerifiedAuditEntryV1>,
    decode_error: Option<Error>,
}

impl<'a> DecodedAuditWindow<'a> {
    /// Check the expected ledger scope and decode each body once, in sequence order.
    pub fn from_ledger(tenant: TenantId, window: &'a VerifiedWindow) -> Result<Self, Error> {
        if window.ledger().tenant() != tenant || window.ledger().chain().as_str() != AUDIT_CHAIN_ID
        {
            return Err(Error::IdentityMismatch);
        }
        let mut records = Vec::with_capacity(window.entries().len());
        let decode_error = window
            .entries()
            .iter()
            .try_for_each(|entry| {
                records.push(VerifiedAuditEntryV1 {
                    sequence: entry.sequence(),
                    record: codec::decode_untrusted(entry.payload())?,
                });
                Ok(())
            })
            .err();
        Ok(Self {
            window,
            records,
            decode_error,
        })
    }

    /// Pair each structurally decoded record with its exact authenticated bytes for association checks.
    pub fn decoded(&self) -> impl Iterator<Item = (&Entry, &DecodedAuditV1)> {
        self.window
            .entries()
            .iter()
            .zip(self.records.iter().map(|row| &row.record))
    }

    /// Report any structural failure after an adapter has checked the decoded prefix.
    pub fn check_complete(&self) -> Result<(), Error> {
        self.decode_error.map_or(Ok(()), Err)
    }

    /// Verify identities in record order, then report any decode error following that prefix.
    pub fn verify_identities(self) -> Result<VerifiedAuditWindow, Error> {
        for (entry, record) in self.decoded() {
            let id = record.event().identity();
            if id.tenant() != self.window.ledger().tenant()
                || entry.record_id() != &audit_record_id(id.source().source_id(), id.event_id())?
            {
                return Err(Error::IdentityMismatch);
            }
        }
        self.check_complete()?;
        Ok(VerifiedAuditWindow {
            ledger: self.window.verification().clone(),
            records: self.records,
        })
    }
}

impl VerifiedAuditWindow {
    /// Underlying limited ledger verification result.
    #[must_use]
    pub const fn ledger_verification(&self) -> &Verification {
        &self.ledger
    }

    /// Audit records corresponding to the verified entries.
    #[must_use]
    pub fn records(&self) -> &[VerifiedAuditEntryV1] {
        &self.records
    }
}

impl std::fmt::Debug for VerifiedAuditWindow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedAuditWindow")
            .field("ledger", &self.ledger)
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl PreparedAuditV1 {
    /// Map this exact Audit record to its optional integrity chain. Not commit evidence.
    pub fn append_request(&self) -> Result<AppendRequest, Error> {
        let identity = self.identity();
        Ok(AppendRequest::from_bytes(
            LedgerId::new(identity.tenant(), ChainId::parse(AUDIT_CHAIN_ID)?),
            audit_record_id(identity.source().source_id(), identity.event_id())?,
            self.shared_bytes(),
        )?)
    }
    /// Compare an authenticated entry with the exact audit bytes and identity.
    pub fn matches_entry(&self, entry: &Entry) -> bool {
        self.append_request()
            .is_ok_and(|request| entry.matches(&request))
    }
}
