//! Deterministic draft-only MQTT v5 device peer for the certificate convergence and MQTT
//! backpressure join journeys.
//!
//! This crate is test support, not a production device SDK. It exposes only the closed path used
//! by those journeys: prime a persistent session, go offline, restore that session, accept the
//! expected latest command, acknowledge it (optionally replaying the exact pending ACK frame under
//! a typed bounded budget), then report the matching persisted draft state.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use rumqttc::v5::mqttbytes::QoS;
use rumqttc::v5::mqttbytes::v5::{
    ConnectReturnCode, Filter, Packet, PubAckReason, Publish, PublishProperties,
    SubscribeReasonCode,
};
use rumqttc::v5::{AsyncClient, Event, EventLoop, MqttOptions};
use rumqttc::{Outgoing, TlsConfiguration, Transport};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

const REQUEST_CAPACITY: usize = 16;
const KEEP_ALIVE: Duration = Duration::from_secs(30);
const SESSION_EXPIRY_SECONDS: u32 = 3_600;
const MAX_TOPIC_LEN: usize = 1_024;
const MAX_IDENTIFIER_LEN: usize = 256;
const MAX_DEADLINE_EPOCH_SECONDS: i64 = 9_223_372_036_854;
const SHA256_PREFIX: &str = "sha256:";
const DRAFT_ELIGIBILITY: &str = "draft";

/// Closed errors emitted by the deterministic draft peer.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DraftSimulatorError {
    /// A caller-provided configuration value is outside the closed journey contract.
    #[error("invalid draft simulator configuration field: {field}")]
    InvalidConfiguration { field: &'static str },
    /// A caller-provided same-envelope replay budget is zero or above the closed upper bound.
    #[error("same-envelope ACK replay attempts outside closed non-zero bound, got {attempts}")]
    InvalidReplayAttempts { attempts: u8 },
    /// TLS trust or client identity PEM could not be prepared.
    #[error("invalid draft simulator TLS material")]
    InvalidTlsMaterial,
    /// The broker connection or event loop failed.
    #[error("draft simulator MQTT connection failed")]
    MqttConnection,
    /// A client request could not be admitted to the event loop.
    #[error("draft simulator MQTT request failed")]
    MqttRequest,
    /// A bounded operation did not complete before its configured deadline.
    #[error("draft simulator operation `{operation}` exceeded its {waited:?} deadline")]
    DeadlineExceeded {
        operation: &'static str,
        waited: Duration,
    },
    /// A broker rejected the MQTT connection.
    #[error("draft simulator MQTT connection was rejected: {code:?}")]
    ConnectionRejected { code: ConnectReturnCode },
    /// Initial session priming unexpectedly reused a broker session.
    #[error("clean-start session priming unexpectedly restored an existing session")]
    UnexpectedPrimedSession,
    /// Reconnect did not restore the previously primed persistent session.
    #[error("persistent MQTT session was not restored")]
    SessionNotPresent,
    /// One of the two exact subscriptions was rejected.
    #[error("draft simulator MQTT subscription was rejected")]
    SubscriptionRejected,
    /// Broker settlement rejected an ACK or reported-state uplink.
    #[error("draft simulator MQTT publish was rejected: {reason:?}")]
    PublishRejected { reason: PubAckReason },
    /// A command payload or its correlation identity is invalid.
    #[error("invalid draft command field: {field}")]
    InvalidCommand { field: &'static str },
    /// A downlink newer than the journey-provided durable coordinate was observed.
    #[error(
        "observed command coordinate generation={observed_generation}, epoch={observed_epoch} newer than expected generation={expected_generation}, epoch={expected_epoch}"
    )]
    UnexpectedCommandCoordinate {
        expected_generation: u64,
        expected_epoch: u64,
        observed_generation: u64,
        observed_epoch: u64,
    },
    /// Persisted artifact evidence is not an exact draft match for the command.
    #[error("invalid persisted draft artifact field: {field}")]
    InvalidDraftArtifact { field: &'static str },
    /// An application receipt is malformed or does not match the pending ingress.
    #[error("invalid draft application receipt field: {field}")]
    InvalidReceipt { field: &'static str },
    /// JSON encoding or decoding failed.
    #[error("draft simulator JSON failed")]
    Json(#[from] serde_json::Error),
}

/// Exact four MQTT topics used by the canonical flow.
pub struct DraftTopics {
    command: String,
    ack: String,
    report: String,
    receipt: String,
}

impl DraftTopics {
    /// Validate four distinct concrete topics. Wildcards are never accepted.
    pub fn new(
        command: String,
        ack: String,
        report: String,
        receipt: String,
    ) -> Result<Self, DraftSimulatorError> {
        validate_topic("command_topic", &command)?;
        validate_topic("ack_topic", &ack)?;
        validate_topic("report_topic", &report)?;
        validate_topic("receipt_topic", &receipt)?;
        if command == ack
            || command == report
            || command == receipt
            || ack == report
            || ack == receipt
            || report == receipt
        {
            return Err(DraftSimulatorError::InvalidConfiguration {
                field: "distinct_topics",
            });
        }
        Ok(Self {
            command,
            ack,
            report,
            receipt,
        })
    }
}

/// Owned client trust and mTLS identity. Secret PEM is never exposed again after construction.
pub struct DraftTlsMaterial {
    ca_pem: String,
    certificate_pem: String,
    private_key_pem: String,
}

impl DraftTlsMaterial {
    /// Construct owned TLS material for both the prime and reconnect handshakes.
    pub fn new(
        ca_pem: String,
        certificate_pem: String,
        private_key_pem: String,
    ) -> Result<Self, DraftSimulatorError> {
        validate_pem_material("ca_pem", &ca_pem)?;
        validate_pem_material("certificate_pem", &certificate_pem)?;
        validate_pem_material("private_key_pem", &private_key_pem)?;
        Ok(Self {
            ca_pem,
            certificate_pem,
            private_key_pem,
        })
    }
}

impl std::fmt::Debug for DraftTlsMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DraftTlsMaterial(<redacted>)")
    }
}

/// Complete, immutable connection configuration for one draft device peer.
pub struct DraftSimulatorConfig {
    endpoint: Url,
    stable_client_id: String,
    credential_generation: u64,
    tls: DraftTlsMaterial,
    topics: DraftTopics,
    wait_deadline: Duration,
}

impl DraftSimulatorConfig {
    /// Build the only configuration accepted by the journey peer.
    pub fn new(
        endpoint: Url,
        stable_client_id: String,
        credential_generation: u64,
        tls: DraftTlsMaterial,
        topics: DraftTopics,
        wait_deadline: Duration,
    ) -> Result<Self, DraftSimulatorError> {
        if endpoint.scheme() != "mqtts" {
            return Err(DraftSimulatorError::InvalidConfiguration { field: "endpoint" });
        }
        if endpoint.host_str().is_none()
            || endpoint.port().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || !matches!(endpoint.path(), "" | "/")
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(DraftSimulatorError::InvalidConfiguration { field: "endpoint" });
        }
        validate_nonempty("stable_client_id", &stable_client_id, MAX_IDENTIFIER_LEN)?;
        if credential_generation == 0 || credential_generation > i64::MAX as u64 {
            return Err(DraftSimulatorError::InvalidConfiguration {
                field: "credential_generation",
            });
        }
        if wait_deadline.is_zero() {
            return Err(DraftSimulatorError::InvalidConfiguration {
                field: "wait_deadline",
            });
        }
        Ok(Self {
            endpoint,
            stable_client_id,
            credential_generation,
            tls,
            topics,
            wait_deadline,
        })
    }
}

/// Exact desired generation and fence epoch supplied from durable journey evidence.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct DraftCommandCoordinate {
    generation: u64,
    fence_epoch: u64,
}

impl DraftCommandCoordinate {
    /// Reject zero and values that cannot be represented by the frozen int64 wire contract.
    pub fn new(generation: u64, fence_epoch: u64) -> Result<Self, DraftSimulatorError> {
        if generation == 0 || generation > i64::MAX as u64 {
            return Err(DraftSimulatorError::InvalidCommand {
                field: "desiredGeneration",
            });
        }
        if fence_epoch == 0 || fence_epoch > i64::MAX as u64 {
            return Err(DraftSimulatorError::InvalidCommand {
                field: "fenceEpoch",
            });
        }
        Ok(Self {
            generation,
            fence_epoch,
        })
    }

    /// Desired generation carried by the selected command.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Fence epoch carried by the selected command.
    #[must_use]
    pub const fn fence_epoch(self) -> u64 {
        self.fence_epoch
    }
}

/// One exact latest command selected after reconnect. Its fields cannot be forged or mutated.
pub struct DraftCommand {
    command_id: String,
    device_id: String,
    coordinate: DraftCommandCoordinate,
    artifact_digest: String,
}

impl DraftCommand {
    /// Stable command identity carried in MQTT correlation data.
    #[must_use]
    pub fn command_id(&self) -> &str {
        &self.command_id
    }

    /// Selected desired generation and fence epoch.
    #[must_use]
    pub const fn coordinate(&self) -> DraftCommandCoordinate {
        self.coordinate
    }

    /// Opaque digest of the persisted draft artifact authorized by the command.
    #[must_use]
    pub fn artifact_digest(&self) -> &str {
        &self.artifact_digest
    }

    fn decode(payload: &[u8], correlation: &[u8]) -> Result<Self, DraftSimulatorError> {
        let command_id = std::str::from_utf8(correlation)
            .map_err(|_| DraftSimulatorError::InvalidCommand {
                field: "correlationData",
            })?
            .to_owned();
        validate_command_text("correlationData", &command_id, 1, MAX_IDENTIFIER_LEN)?;
        let wire: CommandWire = serde_json::from_slice(payload)?;
        validate_command_text("deviceId", &wire.device_id, 1, MAX_IDENTIFIER_LEN)?;
        validate_command_text(
            "authorizationReceiptId",
            &wire.authorization_receipt_id,
            1,
            MAX_IDENTIFIER_LEN,
        )?;
        validate_command_text("artifactId", &wire.artifact_id, 16, MAX_IDENTIFIER_LEN)?;
        validate_command_digest("intentDigest", &wire.intent_digest)?;
        validate_command_digest("policyHash", &wire.policy_hash)?;
        validate_command_digest("artifactDigest", &wire.artifact_digest)?;
        if !(1..=MAX_DEADLINE_EPOCH_SECONDS).contains(&wire.deadline_epoch_seconds) {
            return Err(DraftSimulatorError::InvalidCommand {
                field: "deadlineEpochSeconds",
            });
        }
        Ok(Self {
            command_id,
            device_id: wire.device_id,
            coordinate: DraftCommandCoordinate::new(wire.desired_generation, wire.fence_epoch)?,
            artifact_digest: wire.artifact_digest,
        })
    }

    fn ack_payload(
        &self,
        credential_generation: u64,
        device_sequence: u64,
        observed_at: i64,
    ) -> Result<(String, Vec<u8>), DraftSimulatorError> {
        validate_device_sequence(device_sequence)?;
        let ingress_id = format!(
            "draft-credential-g{credential_generation}-ack-g{}-e{}-s{device_sequence}",
            self.coordinate.generation, self.coordinate.fence_epoch
        );
        let payload = serde_json::to_vec(&CommandAckWire {
            device_id: &self.device_id,
            command_id: &self.command_id,
            desired_generation: self.coordinate.generation,
            fence_epoch: self.coordinate.fence_epoch,
            device_sequence,
            result: "received",
            reason: "None",
            observed_at,
        })?;
        Ok((ingress_id, payload))
    }

    fn report_payload(
        &self,
        credential_generation: u64,
        artifact: DraftAppliedArtifact,
        device_sequence: u64,
        observed_at: i64,
    ) -> Result<(String, Vec<u8>), DraftSimulatorError> {
        validate_device_sequence(device_sequence)?;
        if artifact.artifact_digest != self.artifact_digest {
            return Err(DraftSimulatorError::InvalidDraftArtifact {
                field: "artifactDigest",
            });
        }
        let ingress_id = format!(
            "draft-credential-g{credential_generation}-report-g{}-e{}-s{device_sequence}",
            self.coordinate.generation, self.coordinate.fence_epoch
        );
        let payload = serde_json::to_vec(&CertificateReportWire {
            device_id: &self.device_id,
            observed_generation: self.coordinate.generation,
            fence_epoch: self.coordinate.fence_epoch,
            device_sequence,
            state_hash: &artifact.state_hash,
            artifact_digest: &artifact.artifact_digest,
            observed_at,
        })?;
        Ok((ingress_id, payload))
    }
}

/// Draft artifact evidence read from durable storage by the journey.
pub struct DraftAppliedArtifact {
    artifact_digest: String,
    state_hash: String,
}

impl DraftAppliedArtifact {
    /// Admit only a persisted `draft` row with exact SHA-256 digest encodings.
    pub fn from_persisted(
        eligibility: &str,
        artifact_digest: &str,
        state_hash: &str,
    ) -> Result<Self, DraftSimulatorError> {
        if eligibility != DRAFT_ELIGIBILITY {
            return Err(DraftSimulatorError::InvalidDraftArtifact {
                field: "eligibility",
            });
        }
        validate_artifact_digest("artifactDigest", artifact_digest)?;
        validate_artifact_digest("stateHash", state_hash)?;
        Ok(Self {
            artifact_digest: artifact_digest.to_owned(),
            state_hash: state_hash.to_owned(),
        })
    }
}

/// ACK publication accepted by the broker and awaiting its canonical application receipt.
///
/// Privately retains the exact settled ACK publish frame so the journey can request a typed,
/// bounded same-envelope replay without exposing raw topic or payload surfaces.
pub struct PendingDraftAck {
    command: DraftCommand,
    ingress_id: String,
    topic: String,
    payload: Vec<u8>,
}

/// Non-zero same-envelope ACK republish budget with a closed upper bound.
///
/// The bound is intentionally small and fixed so join tests can fill a bounded subscriber without
/// growing into a general burst or fault-script API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SameEnvelopeReplayAttempts {
    attempts: u8,
}

impl SameEnvelopeReplayAttempts {
    /// Inclusive upper bound for same-envelope ACK republish attempts.
    pub const MAX: u8 = 40;

    /// Admit only a non-zero attempt count within [`Self::MAX`].
    pub fn new(attempts: u8) -> Result<Self, DraftSimulatorError> {
        if attempts == 0 || attempts > Self::MAX {
            return Err(DraftSimulatorError::InvalidReplayAttempts { attempts });
        }
        Ok(Self { attempts })
    }

    /// Admitted attempt count.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.attempts
    }
}

impl PendingDraftAck {
    /// Deterministic ingress envelope ID used to query durable commit evidence.
    #[must_use]
    pub fn ingress_id(&self) -> &str {
        &self.ingress_id
    }
}

/// Command capability minted only after its ACK application receipt is observed.
pub struct AcknowledgedDraftCommand {
    command: DraftCommand,
}

/// Matching report accepted by the broker and awaiting its canonical application receipt.
pub struct PendingDraftReport {
    ingress_id: String,
    device_id: String,
    desired_generation: u64,
}

impl PendingDraftReport {
    /// Deterministic ingress envelope ID used to query durable commit evidence.
    #[must_use]
    pub fn ingress_id(&self) -> &str {
        &self.ingress_id
    }
}

/// One committed application receipt matched to an exact pending ingress.
pub struct DraftApplicationReceipt {
    ingress_id: String,
    correlation: Vec<u8>,
    committed_at: i64,
}

impl DraftApplicationReceipt {
    /// Ingress envelope ID matched by this receipt.
    #[must_use]
    pub fn ingress_id(&self) -> &str {
        &self.ingress_id
    }

    /// Stable receipt event identity carried in MQTT correlation data.
    #[must_use]
    pub fn correlation(&self) -> &[u8] {
        &self.correlation
    }

    /// Durable commit timestamp carried by the frozen receipt contract.
    #[must_use]
    pub const fn committed_at(&self) -> i64 {
        self.committed_at
    }

    fn decode(
        payload: &[u8],
        correlation: &[u8],
        expected_ingress: &str,
        expected_device: &str,
        expected_generation: u64,
    ) -> Result<Self, DraftSimulatorError> {
        if correlation.is_empty() {
            return Err(DraftSimulatorError::InvalidReceipt {
                field: "correlationData",
            });
        }
        let wire: ReceiptWire = serde_json::from_slice(payload)?;
        if wire.ingress_envelope_id != expected_ingress {
            return Err(DraftSimulatorError::InvalidReceipt {
                field: "ingressEnvelopeId",
            });
        }
        if wire.device_id != expected_device {
            return Err(DraftSimulatorError::InvalidReceipt { field: "deviceId" });
        }
        if wire.desired_generation != expected_generation {
            return Err(DraftSimulatorError::InvalidReceipt {
                field: "desiredGeneration",
            });
        }
        if wire.authorization_receipt_id.is_empty()
            || wire.authorization_receipt_id.len() > MAX_IDENTIFIER_LEN
            || wire
                .authorization_receipt_id
                .chars()
                .any(char::is_whitespace)
        {
            return Err(DraftSimulatorError::InvalidReceipt {
                field: "authorizationReceiptId",
            });
        }
        if wire.outcome != "committed" {
            return Err(DraftSimulatorError::InvalidReceipt { field: "outcome" });
        }
        if wire.reason != "None" {
            return Err(DraftSimulatorError::InvalidReceipt { field: "reason" });
        }
        Ok(Self {
            ingress_id: wire.ingress_envelope_id,
            correlation: correlation.to_vec(),
            committed_at: wire.committed_at,
        })
    }
}

/// A clean-start device whose exact downlink subscriptions have been persisted at the broker.
pub struct PrimedDraftDevice {
    config: DraftSimulatorConfig,
    client: AsyncClient,
    events: EventLoop,
}

impl PrimedDraftDevice {
    /// Gracefully disconnect while preserving the non-zero MQTT session expiry.
    pub async fn go_offline(self) -> Result<OfflineDraftDevice, DraftSimulatorError> {
        let Self {
            config,
            client,
            events,
        } = self;
        disconnect_preserving_session(config, client, events).await
    }
}

/// Offline ownership of one previously primed persistent broker session.
pub struct OfflineDraftDevice {
    config: DraftSimulatorConfig,
}

impl OfflineDraftDevice {
    /// Reconnect with `clean_start=false` and reject any ConnAck without `session_present`.
    pub async fn reconnect(self) -> Result<DraftDeviceSimulator, DraftSimulatorError> {
        let (client, mut events) = mqtt_client(&self.config, false)?;
        let session_present = within_deadline(
            self.config.wait_deadline,
            "persistent session reconnect",
            wait_for_connack(&mut events),
        )
        .await?;
        if !session_present {
            return Err(DraftSimulatorError::SessionNotPresent);
        }
        Ok(DraftDeviceSimulator {
            config: self.config,
            client,
            events,
            buffered: VecDeque::new(),
        })
    }
}

/// Restored persistent device peer ready for the closed ACK/report convergence flow.
pub struct DraftDeviceSimulator {
    config: DraftSimulatorConfig,
    client: AsyncClient,
    events: EventLoop,
    buffered: VecDeque<BufferedDownlink>,
}

impl DraftDeviceSimulator {
    /// Establish a clean persistent session and subscribe the two exact downlink topics.
    pub async fn prime(
        config: DraftSimulatorConfig,
    ) -> Result<PrimedDraftDevice, DraftSimulatorError> {
        let (client, mut events) = mqtt_client(&config, true)?;
        let session_present = within_deadline(
            config.wait_deadline,
            "persistent session prime",
            wait_for_connack(&mut events),
        )
        .await?;
        if session_present {
            return Err(DraftSimulatorError::UnexpectedPrimedSession);
        }
        within_deadline(
            config.wait_deadline,
            "exact downlink subscriptions",
            async {
                client
                    .subscribe_many([
                        Filter::new(config.topics.command.as_str(), QoS::AtLeastOnce),
                        Filter::new(config.topics.receipt.as_str(), QoS::AtLeastOnce),
                    ])
                    .await
                    .map_err(client_error)?;
                wait_for_suback(&mut events).await
            },
        )
        .await?;
        Ok(PrimedDraftDevice {
            config,
            client,
            events,
        })
    }

    /// Gracefully disconnect while preserving the non-zero MQTT session expiry.
    pub async fn go_offline(self) -> Result<OfflineDraftDevice, DraftSimulatorError> {
        let Self {
            config,
            client,
            events,
            buffered: _,
        } = self;
        disconnect_preserving_session(config, client, events).await
    }

    /// Receive until the journey-provided latest durable coordinate is observed.
    ///
    /// Older queued commands receive only their MQTT broker ACK. No application ACK is emitted.
    pub async fn receive_latest(
        &mut self,
        expected: DraftCommandCoordinate,
    ) -> Result<DraftCommand, DraftSimulatorError> {
        let wait = self.config.wait_deadline;
        within_deadline(wait, "expected latest command", async {
            let selector = LatestCommandSelector::new(expected);
            loop {
                let downlink = self.next_downlink().await?;
                if downlink.topic != self.config.topics.command {
                    continue;
                }
                let correlation =
                    downlink
                        .correlation
                        .as_deref()
                        .ok_or(DraftSimulatorError::InvalidCommand {
                            field: "correlationData",
                        })?;
                if let Some(command) = selector.observe(&downlink.payload, correlation)? {
                    return Ok(command);
                }
            }
        })
        .await
    }

    /// Consume the selected command, publish its received ACK, and return pending receipt state.
    pub async fn send_ack(
        &mut self,
        command: DraftCommand,
        device_sequence: u64,
        observed_at: i64,
    ) -> Result<PendingDraftAck, DraftSimulatorError> {
        let (ingress_id, payload) = command.ack_payload(
            self.config.credential_generation,
            device_sequence,
            observed_at,
        )?;
        let topic = self.config.topics.ack.clone();
        self.publish_settled(&topic, payload.clone(), &ingress_id)
            .await?;
        Ok(PendingDraftAck {
            command,
            ingress_id,
            topic,
            payload,
        })
    }

    /// Republish only the exact pending ACK frame for a typed, bounded same-envelope budget.
    ///
    /// Each attempt waits for broker PUBACK. This does not expose topic or payload and does not
    /// accept arbitrary publish scripts.
    pub async fn replay_pending_ack(
        &mut self,
        pending: &PendingDraftAck,
        attempts: SameEnvelopeReplayAttempts,
    ) -> Result<(), DraftSimulatorError> {
        for _ in 0..attempts.get() {
            self.publish_settled(&pending.topic, pending.payload.clone(), &pending.ingress_id)
                .await?;
        }
        Ok(())
    }

    /// Consume pending ACK state and wait for its exact committed application receipt.
    pub async fn wait_ack_receipt(
        &mut self,
        pending: PendingDraftAck,
    ) -> Result<(AcknowledgedDraftCommand, DraftApplicationReceipt), DraftSimulatorError> {
        let receipt = self
            .wait_receipt(
                &pending.ingress_id,
                &pending.command.device_id,
                pending.command.coordinate.generation,
            )
            .await?;
        Ok((
            AcknowledgedDraftCommand {
                command: pending.command,
            },
            receipt,
        ))
    }

    /// Consume the acknowledged command and verified draft artifact, then publish a matching report.
    pub async fn send_matching_report(
        &mut self,
        acknowledged: AcknowledgedDraftCommand,
        artifact: DraftAppliedArtifact,
        device_sequence: u64,
        observed_at: i64,
    ) -> Result<PendingDraftReport, DraftSimulatorError> {
        let command = acknowledged.command;
        let (ingress_id, payload) = command.report_payload(
            self.config.credential_generation,
            artifact,
            device_sequence,
            observed_at,
        )?;
        let topic = self.config.topics.report.clone();
        self.publish_settled(&topic, payload, &ingress_id).await?;
        Ok(PendingDraftReport {
            ingress_id,
            device_id: command.device_id,
            desired_generation: command.coordinate.generation,
        })
    }

    /// Consume pending report state and wait for its exact committed application receipt.
    pub async fn wait_report_receipt(
        &mut self,
        pending: PendingDraftReport,
    ) -> Result<DraftApplicationReceipt, DraftSimulatorError> {
        self.wait_receipt(
            &pending.ingress_id,
            &pending.device_id,
            pending.desired_generation,
        )
        .await
    }

    async fn publish_settled(
        &mut self,
        topic: &str,
        payload: Vec<u8>,
        ingress_id: &str,
    ) -> Result<(), DraftSimulatorError> {
        let wait = self.config.wait_deadline;
        within_deadline(wait, "uplink broker PUBACK", async {
            self.client
                .publish_with_properties(
                    topic,
                    QoS::AtLeastOnce,
                    false,
                    payload,
                    PublishProperties {
                        correlation_data: Some(ingress_id.as_bytes().to_vec().into()),
                        ..PublishProperties::default()
                    },
                )
                .await
                .map_err(client_error)?;
            let mut packet_id = None;
            loop {
                match self.events.poll().await.map_err(connection_error)? {
                    Event::Outgoing(Outgoing::Publish(observed)) if packet_id.is_none() => {
                        packet_id = Some(observed);
                    }
                    Event::Incoming(Packet::PubAck(ack)) if packet_id == Some(ack.pkid) => {
                        return match ack.reason {
                            PubAckReason::Success | PubAckReason::NoMatchingSubscribers => Ok(()),
                            reason => Err(DraftSimulatorError::PublishRejected { reason }),
                        };
                    }
                    Event::Incoming(Packet::Publish(publish)) => {
                        self.buffer_publish(publish).await?;
                    }
                    Event::Incoming(_) | Event::Outgoing(_) => {}
                }
            }
        })
        .await
    }

    async fn wait_receipt(
        &mut self,
        expected_ingress: &str,
        expected_device: &str,
        expected_generation: u64,
    ) -> Result<DraftApplicationReceipt, DraftSimulatorError> {
        let wait = self.config.wait_deadline;
        within_deadline(wait, "matching application receipt", async {
            loop {
                let downlink = self.next_downlink().await?;
                if downlink.topic != self.config.topics.receipt {
                    continue;
                }
                let correlation =
                    downlink
                        .correlation
                        .as_deref()
                        .ok_or(DraftSimulatorError::InvalidReceipt {
                            field: "correlationData",
                        })?;
                let wire: ReceiptWire = serde_json::from_slice(&downlink.payload)?;
                if wire.ingress_envelope_id != expected_ingress {
                    continue;
                }
                return DraftApplicationReceipt::decode(
                    &downlink.payload,
                    correlation,
                    expected_ingress,
                    expected_device,
                    expected_generation,
                );
            }
        })
        .await
    }

    async fn next_downlink(&mut self) -> Result<BufferedDownlink, DraftSimulatorError> {
        if let Some(buffered) = self.buffered.pop_front() {
            return Ok(buffered);
        }
        loop {
            match self.events.poll().await.map_err(connection_error)? {
                Event::Incoming(Packet::Publish(publish)) => {
                    return self.acknowledge_downlink(publish).await;
                }
                Event::Incoming(_) | Event::Outgoing(_) => {}
            }
        }
    }

    async fn buffer_publish(&mut self, publish: Publish) -> Result<(), DraftSimulatorError> {
        let downlink = self.acknowledge_downlink(publish).await?;
        self.buffered.push_back(downlink);
        Ok(())
    }

    async fn acknowledge_downlink(
        &self,
        publish: Publish,
    ) -> Result<BufferedDownlink, DraftSimulatorError> {
        self.client.ack(&publish).await.map_err(client_error)?;
        let topic = std::str::from_utf8(publish.topic.as_ref())
            .map_err(|_| DraftSimulatorError::InvalidConfiguration {
                field: "downlink_topic",
            })?
            .to_owned();
        Ok(BufferedDownlink {
            topic,
            payload: publish.payload.to_vec(),
            correlation: publish
                .properties
                .as_ref()
                .and_then(|properties| properties.correlation_data.as_deref())
                .map(<[u8]>::to_vec),
        })
    }
}

struct LatestCommandSelector {
    expected: DraftCommandCoordinate,
}

impl LatestCommandSelector {
    const fn new(expected: DraftCommandCoordinate) -> Self {
        Self { expected }
    }

    fn observe(
        &self,
        payload: &[u8],
        correlation: &[u8],
    ) -> Result<Option<DraftCommand>, DraftSimulatorError> {
        let command = DraftCommand::decode(payload, correlation)?;
        match command.coordinate.cmp(&self.expected) {
            std::cmp::Ordering::Less => Ok(None),
            std::cmp::Ordering::Equal => Ok(Some(command)),
            std::cmp::Ordering::Greater => Err(DraftSimulatorError::UnexpectedCommandCoordinate {
                expected_generation: self.expected.generation,
                expected_epoch: self.expected.fence_epoch,
                observed_generation: command.coordinate.generation,
                observed_epoch: command.coordinate.fence_epoch,
            }),
        }
    }
}

struct BufferedDownlink {
    topic: String,
    payload: Vec<u8>,
    correlation: Option<Vec<u8>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CommandWire {
    device_id: String,
    authorization_receipt_id: String,
    desired_generation: u64,
    fence_epoch: u64,
    intent_digest: String,
    policy_hash: String,
    artifact_id: String,
    artifact_digest: String,
    deadline_epoch_seconds: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CommandAckWire<'a> {
    device_id: &'a str,
    command_id: &'a str,
    desired_generation: u64,
    fence_epoch: u64,
    device_sequence: u64,
    result: &'static str,
    reason: &'static str,
    observed_at: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CertificateReportWire<'a> {
    device_id: &'a str,
    observed_generation: u64,
    fence_epoch: u64,
    device_sequence: u64,
    state_hash: &'a str,
    artifact_digest: &'a str,
    observed_at: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReceiptWire {
    ingress_envelope_id: String,
    authorization_receipt_id: String,
    desired_generation: u64,
    device_id: String,
    outcome: String,
    reason: String,
    committed_at: i64,
}

fn mqtt_client(
    config: &DraftSimulatorConfig,
    clean_start: bool,
) -> Result<(AsyncClient, EventLoop), DraftSimulatorError> {
    let host = config
        .endpoint
        .host_str()
        .ok_or(DraftSimulatorError::InvalidConfiguration { field: "endpoint" })?;
    let port = config
        .endpoint
        .port()
        .ok_or(DraftSimulatorError::InvalidConfiguration { field: "endpoint" })?;
    let mut options = MqttOptions::new(&config.stable_client_id, host, port);
    options
        .set_transport(Transport::tls_with_config(TlsConfiguration::Rustls(
            tls_client(&config.tls)?,
        )))
        .set_keep_alive(KEEP_ALIVE)
        .set_clean_start(clean_start)
        .set_session_expiry_interval(Some(SESSION_EXPIRY_SECONDS))
        .set_manual_acks(true);
    Ok(AsyncClient::new(options, REQUEST_CAPACITY))
}

fn tls_client(tls: &DraftTlsMaterial) -> Result<Arc<ClientConfig>, DraftSimulatorError> {
    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(tls.ca_pem.as_bytes()) {
        roots
            .add(certificate.map_err(|_| DraftSimulatorError::InvalidTlsMaterial)?)
            .map_err(|_| DraftSimulatorError::InvalidTlsMaterial)?;
    }
    let certificates = CertificateDer::pem_slice_iter(tls.certificate_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| DraftSimulatorError::InvalidTlsMaterial)?;
    if certificates.is_empty() {
        return Err(DraftSimulatorError::InvalidTlsMaterial);
    }
    let key = PrivateKeyDer::from_pem_slice(tls.private_key_pem.as_bytes())
        .map_err(|_| DraftSimulatorError::InvalidTlsMaterial)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| DraftSimulatorError::InvalidTlsMaterial)?
        .with_root_certificates(roots)
        .with_client_auth_cert(certificates, key)
        .map_err(|_| DraftSimulatorError::InvalidTlsMaterial)?;
    Ok(Arc::new(config))
}

async fn wait_for_connack(events: &mut EventLoop) -> Result<bool, DraftSimulatorError> {
    loop {
        match events.poll().await.map_err(connection_error)? {
            Event::Incoming(Packet::ConnAck(ack)) => {
                if ack.code != ConnectReturnCode::Success {
                    return Err(DraftSimulatorError::ConnectionRejected { code: ack.code });
                }
                return Ok(ack.session_present);
            }
            Event::Incoming(_) | Event::Outgoing(_) => {}
        }
    }
}

async fn disconnect_preserving_session(
    config: DraftSimulatorConfig,
    client: AsyncClient,
    mut events: EventLoop,
) -> Result<OfflineDraftDevice, DraftSimulatorError> {
    within_deadline(
        config.wait_deadline,
        "persistent session disconnect",
        async {
            client.disconnect().await.map_err(client_error)?;
            loop {
                match events.poll().await.map_err(connection_error)? {
                    Event::Outgoing(Outgoing::Disconnect) => return Ok(()),
                    Event::Incoming(_) | Event::Outgoing(_) => {}
                }
            }
        },
    )
    .await?;
    drop(client);
    drop(events);
    Ok(OfflineDraftDevice { config })
}

async fn wait_for_suback(events: &mut EventLoop) -> Result<(), DraftSimulatorError> {
    loop {
        match events.poll().await.map_err(connection_error)? {
            Event::Incoming(Packet::SubAck(ack)) => {
                if ack.return_codes
                    == [
                        SubscribeReasonCode::Success(QoS::AtLeastOnce),
                        SubscribeReasonCode::Success(QoS::AtLeastOnce),
                    ]
                {
                    return Ok(());
                }
                return Err(DraftSimulatorError::SubscriptionRejected);
            }
            Event::Incoming(_) | Event::Outgoing(_) => {}
        }
    }
}

async fn within_deadline<T>(
    waited: Duration,
    operation: &'static str,
    future: impl Future<Output = Result<T, DraftSimulatorError>>,
) -> Result<T, DraftSimulatorError> {
    tokio::time::timeout(waited, future)
        .await
        .map_err(|_| DraftSimulatorError::DeadlineExceeded { operation, waited })?
}

fn client_error(_: rumqttc::v5::ClientError) -> DraftSimulatorError {
    DraftSimulatorError::MqttRequest
}

fn connection_error(_: rumqttc::v5::ConnectionError) -> DraftSimulatorError {
    DraftSimulatorError::MqttConnection
}

fn validate_topic(field: &'static str, topic: &str) -> Result<(), DraftSimulatorError> {
    validate_nonempty(field, topic, MAX_TOPIC_LEN)?;
    if topic.contains(['#', '+']) {
        return Err(DraftSimulatorError::InvalidConfiguration { field });
    }
    Ok(())
}

fn validate_nonempty(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), DraftSimulatorError> {
    if value.is_empty()
        || value.len() > maximum
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(DraftSimulatorError::InvalidConfiguration { field });
    }
    Ok(())
}

fn validate_pem_material(field: &'static str, value: &str) -> Result<(), DraftSimulatorError> {
    let bytes = value.as_bytes();
    let invalid_control = value
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r'));
    let invalid_carriage_return = bytes
        .iter()
        .enumerate()
        .any(|(index, byte)| *byte == b'\r' && bytes.get(index + 1) != Some(&b'\n'));
    if value.trim().is_empty() || invalid_control || invalid_carriage_return {
        return Err(DraftSimulatorError::InvalidConfiguration { field });
    }
    Ok(())
}

fn validate_command_text(
    field: &'static str,
    value: &str,
    minimum: usize,
    maximum: usize,
) -> Result<(), DraftSimulatorError> {
    if value.len() < minimum
        || value.len() > maximum
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(DraftSimulatorError::InvalidCommand { field });
    }
    Ok(())
}

fn validate_command_digest(field: &'static str, digest: &str) -> Result<(), DraftSimulatorError> {
    if is_sha256_digest(digest) {
        Ok(())
    } else {
        Err(DraftSimulatorError::InvalidCommand { field })
    }
}

fn validate_device_sequence(device_sequence: u64) -> Result<(), DraftSimulatorError> {
    if device_sequence > i64::MAX as u64 {
        Err(DraftSimulatorError::InvalidCommand {
            field: "deviceSequence",
        })
    } else {
        Ok(())
    }
}

fn validate_artifact_digest(field: &'static str, digest: &str) -> Result<(), DraftSimulatorError> {
    if is_sha256_digest(digest) {
        Ok(())
    } else {
        Err(DraftSimulatorError::InvalidDraftArtifact { field })
    }
}

fn is_sha256_digest(value: &str) -> bool {
    value.strip_prefix(SHA256_PREFIX).is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rumqttc::v5::Request;
    use static_assertions::assert_not_impl_any;

    const COMMAND_TOPIC: &str = "tenants/t1/devices/d1/commands/apply-certificate";
    const ACK_TOPIC: &str = "tenants/t1/devices/d1/events/command-acked";
    const REPORT_TOPIC: &str = "tenants/t1/devices/d1/events/certificate-reported";
    const RECEIPT_TOPIC: &str = "tenants/t1/devices/d1/receipts/application";
    const ARTIFACT_DIGEST: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const STALE_DIGEST: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const STATE_HASH: &str =
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    #[test]
    fn same_envelope_replay_attempts_admit_nonzero_within_max() -> Result<(), DraftSimulatorError> {
        assert_eq!(SameEnvelopeReplayAttempts::new(1)?.get(), 1);
        assert_eq!(
            SameEnvelopeReplayAttempts::new(SameEnvelopeReplayAttempts::MAX)?.get(),
            SameEnvelopeReplayAttempts::MAX
        );
        assert!(matches!(
            SameEnvelopeReplayAttempts::new(0),
            Err(DraftSimulatorError::InvalidReplayAttempts { attempts: 0 })
        ));
        assert!(matches!(
            SameEnvelopeReplayAttempts::new(SameEnvelopeReplayAttempts::MAX + 1),
            Err(DraftSimulatorError::InvalidReplayAttempts { attempts: 41 })
        ));
        Ok(())
    }

    #[test]
    fn pending_ack_is_move_only_and_replay_budget_is_closed() {
        assert_not_impl_any!(PendingDraftAck: Clone, Copy);
        assert_eq!(SameEnvelopeReplayAttempts::MAX, 40);
        assert!(SameEnvelopeReplayAttempts::new(33).is_ok());
    }

    #[test]
    fn coordinate_requires_nonzero_int64_generation_and_epoch() {
        assert!(DraftCommandCoordinate::new(0, 1).is_err());
        assert!(DraftCommandCoordinate::new(1, 0).is_err());
        assert!(DraftCommandCoordinate::new(i64::MAX as u64 + 1, 1).is_err());
        assert!(DraftCommandCoordinate::new(2, 3).is_ok());
    }

    #[test]
    fn exact_topics_reject_duplicates_and_wildcards() {
        assert!(
            DraftTopics::new(
                COMMAND_TOPIC.to_owned(),
                ACK_TOPIC.to_owned(),
                REPORT_TOPIC.to_owned(),
                COMMAND_TOPIC.to_owned(),
            )
            .is_err()
        );
        assert!(
            DraftTopics::new(
                "tenants/+/devices/d1/commands/apply-certificate".to_owned(),
                ACK_TOPIC.to_owned(),
                REPORT_TOPIC.to_owned(),
                RECEIPT_TOPIC.to_owned(),
            )
            .is_err()
        );
    }

    #[test]
    fn configuration_requires_mqtts_explicit_port_generation_and_deadline() {
        let config = |endpoint: &str, generation, deadline| {
            DraftSimulatorConfig::new(
                Url::parse(endpoint).ok()?,
                "stable-device".to_owned(),
                generation,
                DraftTlsMaterial::new("ca".into(), "cert".into(), "key".into()).ok()?,
                topics().ok()?,
                deadline,
            )
            .ok()
        };
        assert!(config("mqtt://localhost:1883", 2, Duration::from_secs(1)).is_none());
        assert!(config("mqtts://localhost", 2, Duration::from_secs(1)).is_none());
        assert!(
            config(
                "mqtts://user:password@localhost:8883/path",
                2,
                Duration::from_secs(1),
            )
            .is_none()
        );
        assert!(config("mqtts://localhost:8883", 0, Duration::from_secs(1)).is_none());
        assert!(config("mqtts://localhost:8883", 2, Duration::ZERO).is_none());
        assert!(config("mqtts://localhost:8883", 2, Duration::from_secs(1)).is_some());
    }

    #[test]
    fn tls_material_accepts_canonical_pem_line_endings_and_rejects_unsafe_text() {
        let lf = "-----BEGIN CERTIFICATE-----\nY2E=\n-----END CERTIFICATE-----\n";
        let crlf = "-----BEGIN PRIVATE KEY-----\r\naw==\r\n-----END PRIVATE KEY-----\r\n";
        assert!(DraftTlsMaterial::new(lf.into(), lf.into(), crlf.into()).is_ok());

        for invalid in [
            "",
            " \r\n\t",
            "pem\0material",
            "pem\tmaterial",
            "pem\rmaterial",
        ] {
            assert!(
                DraftTlsMaterial::new(invalid.into(), lf.into(), crlf.into()).is_err(),
                "unsafe PEM text must be rejected: {invalid:?}"
            );
        }
    }

    #[test]
    fn latest_selector_discards_older_coordinates() -> Result<(), DraftSimulatorError> {
        let expected = DraftCommandCoordinate::new(2, 4)?;
        let stale = command_json(1, 3, STALE_DIGEST)?;
        let latest = command_json(2, 4, ARTIFACT_DIGEST)?;
        let selector = LatestCommandSelector::new(expected);

        assert!(selector.observe(&stale, b"old")?.is_none());
        let selected = selector.observe(&latest, b"latest")?;
        assert_eq!(
            selected.as_ref().map(DraftCommand::command_id),
            Some("latest")
        );
        assert_eq!(
            selected.as_ref().map(DraftCommand::artifact_digest),
            Some(ARTIFACT_DIGEST)
        );
        Ok(())
    }

    #[test]
    fn selector_rejects_a_command_newer_than_durable_expectation() -> Result<(), DraftSimulatorError>
    {
        let selector = LatestCommandSelector::new(DraftCommandCoordinate::new(2, 4)?);
        assert!(
            selector
                .observe(&command_json(3, 5, ARTIFACT_DIGEST)?, b"future")
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn ack_and_report_wire_fields_are_camel_case() -> Result<(), DraftSimulatorError> {
        let command = DraftCommand::decode(&command_json(2, 4, ARTIFACT_DIGEST)?, b"command-2")?;
        let (ack_id, ack) = command.ack_payload(2, 7, 1_700_000_000_000_007)?;
        let ack: serde_json::Value = serde_json::from_slice(&ack)?;
        assert_eq!(ack["commandId"], "command-2");
        assert_eq!(ack["desiredGeneration"], 2);
        assert_eq!(ack["fenceEpoch"], 4);
        assert_eq!(ack["deviceSequence"], 7);
        assert!(ack.get("command_id").is_none());

        let artifact = DraftAppliedArtifact::from_persisted("draft", ARTIFACT_DIGEST, STATE_HASH)?;
        let (report_id, report) = command.report_payload(2, artifact, 8, 1_700_000_000_000_008)?;
        let report: serde_json::Value = serde_json::from_slice(&report)?;
        assert_eq!(report["observedGeneration"], 2);
        assert_eq!(report["fenceEpoch"], 4);
        assert_eq!(report["stateHash"], STATE_HASH);
        assert_eq!(report["artifactDigest"], ARTIFACT_DIGEST);
        assert!(report.get("state_hash").is_none());
        assert_ne!(ack_id, report_id);
        Ok(())
    }

    #[test]
    fn applied_artifact_is_draft_only_and_digest_bound() -> Result<(), DraftSimulatorError> {
        assert!(
            DraftAppliedArtifact::from_persisted("production", ARTIFACT_DIGEST, STATE_HASH)
                .is_err()
        );
        assert!(DraftAppliedArtifact::from_persisted("draft", "artifact", STATE_HASH).is_err());

        let command = DraftCommand::decode(&command_json(2, 4, ARTIFACT_DIGEST)?, b"command-2")?;
        let wrong = DraftAppliedArtifact::from_persisted("draft", STALE_DIGEST, STATE_HASH)?;
        assert!(
            command
                .report_payload(2, wrong, 8, 1_700_000_000_000_008)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn receipt_requires_matching_ingress_device_and_correlation() -> Result<(), DraftSimulatorError>
    {
        let receipt = br#"{
            "ingressEnvelopeId":"draft-ack-g2-e4-s7",
            "authorizationReceiptId":"0191f7d4-34d7-7b42-9fcb-9e85b92f42a1",
            "desiredGeneration":2,
            "deviceId":"device-1",
            "outcome":"committed",
            "reason":"None",
            "committedAt":1700000000000007
        }"#;
        let parsed = DraftApplicationReceipt::decode(
            receipt,
            b"receipt-event-1",
            "draft-ack-g2-e4-s7",
            "device-1",
            2,
        )?;
        assert_eq!(parsed.ingress_id(), "draft-ack-g2-e4-s7");
        assert_eq!(parsed.correlation(), b"receipt-event-1");
        assert_eq!(parsed.committed_at(), 1_700_000_000_000_007);
        assert!(
            DraftApplicationReceipt::decode(receipt, b"", "draft-ack-g2-e4-s7", "device-1", 2)
                .is_err()
        );
        assert!(
            DraftApplicationReceipt::decode(receipt, b"event", "other-ingress", "device-1", 2)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn mqtt_failures_drop_sensitive_transport_sources() {
        const SENTINEL_TOPIC: &str = "tenants/sentinel/devices/secret/topic";
        const SENTINEL_PAYLOAD: &[u8] = b"sentinel-payload-secret";

        let publish = Publish::new(SENTINEL_TOPIC, QoS::AtLeastOnce, SENTINEL_PAYLOAD, None);
        let errors = [
            client_error(rumqttc::v5::ClientError::Request(Request::Publish(
                publish.clone(),
            ))),
            connection_error(rumqttc::v5::ConnectionError::NotConnAck(Box::new(
                Packet::Publish(publish),
            ))),
        ];

        for error in errors {
            let rendered = format!("{error}\n{error:?}");
            assert!(!rendered.contains(SENTINEL_TOPIC));
            assert!(!rendered.contains(std::str::from_utf8(SENTINEL_PAYLOAD).unwrap_or_default()));
            assert!(std::error::Error::source(&error).is_none());
        }
    }

    #[test]
    fn lifecycle_capabilities_are_move_only() {
        assert_not_impl_any!(DraftSimulatorConfig: Clone, Copy);
        assert_not_impl_any!(PrimedDraftDevice: Clone, Copy);
        assert_not_impl_any!(OfflineDraftDevice: Clone, Copy);
        assert_not_impl_any!(DraftDeviceSimulator: Clone, Copy);
        assert_not_impl_any!(DraftCommand: Clone, Copy);
        assert_not_impl_any!(DraftAppliedArtifact: Clone, Copy);
        assert_not_impl_any!(PendingDraftAck: Clone, Copy);
        assert_not_impl_any!(AcknowledgedDraftCommand: Clone, Copy);
        assert_not_impl_any!(PendingDraftReport: Clone, Copy);
        assert_not_impl_any!(DraftApplicationReceipt: Clone, Copy);
    }

    fn topics() -> Result<DraftTopics, DraftSimulatorError> {
        DraftTopics::new(
            COMMAND_TOPIC.to_owned(),
            ACK_TOPIC.to_owned(),
            REPORT_TOPIC.to_owned(),
            RECEIPT_TOPIC.to_owned(),
        )
    }

    fn command_json(
        generation: u64,
        fence_epoch: u64,
        artifact_digest: &str,
    ) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&serde_json::json!({
            "deviceId": "device-1",
            "authorizationReceiptId": "0191f7d4-34d7-7b42-9fcb-9e85b92f42a1",
            "desiredGeneration": generation,
            "fenceEpoch": fence_epoch,
            "intentDigest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "policyHash": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "artifactId": "draft-artifact-0001",
            "artifactDigest": artifact_digest,
            "deadlineEpochSeconds": 1_800_000_000_i64,
        }))
    }
}
