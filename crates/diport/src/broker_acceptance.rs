//! Provider-neutral, move-only evidence that a broker accepted one publication.
//!
//! The mint capability is deliberately separate from the receipt. Production ownership of
//! [`BrokerAcceptanceMint::mqtt_session_boundary`] is enforced by the MQTT AST gate; consumers can
//! carry and consume [`BrokerAccepted`] but cannot construct either tuple field directly.

/// Move-only evidence minted after the broker acknowledges a QoS publication.
pub struct BrokerAccepted(());

impl BrokerAccepted {
    /// Mint broker acceptance at the provider boundary holding the dedicated mint capability.
    #[doc(hidden)]
    #[must_use]
    pub const fn from_provider(_mint: BrokerAcceptanceMint) -> Self {
        Self(())
    }
}

impl std::fmt::Debug for BrokerAccepted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BrokerAccepted")
    }
}

/// Move-only authority for the exact managed MQTT session boundary to mint broker acceptance.
///
/// This is public only because the provider lives in a separate crate. The always-on
/// `mqtt::ownership_gate` AST test rejects every production callsite except the exact session
/// PUBACK boundary.
pub struct BrokerAcceptanceMint(());

impl BrokerAcceptanceMint {
    /// Obtain the production mint at the managed MQTT session PUBACK boundary.
    #[doc(hidden)]
    #[must_use]
    pub const fn mqtt_session_boundary() -> Self {
        Self(())
    }
}

#[cfg(feature = "test-support")]
pub(crate) const fn accepted_for_test() -> BrokerAccepted {
    BrokerAccepted(())
}
