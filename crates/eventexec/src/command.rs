//! 命令分发 runtime —— reviewed capability + 幂等消费（P12，#1124）。
//!
//! **producer**：generated wrapper 只能调用 [`DirectCommandDispatcher`] 或
//! [`JournaledCommandDispatcher`]。两者在本 crate 内构造 reviewed DTO，再交 provider store；事件
//! `OutboxEmitter` 的 [`consistency::EventTopic`] 会拒绝 command namespace，因此不存在 raw command
//! event authoring 旁路。
//!
//! **consumer**：[`register_command_handler`] 复用 [`run_consumer`] + [`InboxStore`] claimer 两阶段
//! 去重（同 canonical command id 已 durable done 后二次投递 → `Message.id` 同键 → `try_claim` 返 `Duplicate` → handler 不调、幂等短路 =
//! claimer 拒）；零新去重原语。
//!
//! INVARIANT: COMMAND-ALIAS-PROBE-SEAL-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary", facet = "alias-probe-type" }—— raw business key 只在本模块内进入 mandatory keyed blind-index keyring；
//! provider 只能收到私有构造的 [`CommandAliasProbeSet`]，无法取得 raw key 或伪造 alias probes。
//!
//! ref: debezium outbox SMT（producer 业务事实 → outbox 行 durable 落库）
//! ref: eventuate-tram-core io.eventuate.tram.consumer.common.DuplicateMessageDetector@master
//!      （message-id 作幂等键，对应 canonical command id 的 consumer 侧 claimer）

use std::sync::Arc;

use consistency::outbox::{EventTopic, EventTopicError, PermanentError, PermanentErrorKind};
use consistency::{
    CommandIdempotencyKey, CommandJournalOutcome, CommandRequestFingerprint, CommandResultSummary,
    HandleResult, InboxStore,
};
use diport::dead_letter_store::DynDeadLetterStore;
use diport::{
    EnvelopeSubjectId, Message, MessageStream, OutboxActor, OutboxEnvelopeParts, RedactedSource,
};
use secure::{BlindIndex, BlindIndexKey, FilterBits, IndexScope};
use sha2::{Digest as _, Sha256};

use crate::consumer::{ConsumerMeta, LeaseConfig, run_consumer};
use crate::tenant_authority::TenantAuthority;

/// One independently keyed command-alias generation.
pub struct CommandAliasKey {
    key_id: String,
    key: BlindIndexKey,
}

impl std::fmt::Debug for CommandAliasKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CommandAliasKey(<redacted>)")
    }
}

impl CommandAliasKey {
    /// Build a key generation from a non-secret identifier and at least 256 bits of key material.
    pub fn new(
        key_id: impl Into<String>,
        key: impl Into<Vec<u8>>,
    ) -> Result<Self, CommandIdempotencyKeyringError> {
        let key_id = key_id.into();
        if key_id.is_empty()
            || key_id.len() > 64
            || !key_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(CommandIdempotencyKeyringError::InvalidKeyId);
        }
        let key = BlindIndexKey::from_bytes(key)
            .map_err(|_| CommandIdempotencyKeyringError::InvalidKeyMaterial)?;
        Ok(Self { key_id, key })
    }
}

/// Command alias keyring configuration failure.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommandIdempotencyKeyringError {
    /// Key identifiers must be short canonical labels.
    #[error("command idempotency key id is invalid")]
    InvalidKeyId,
    /// Key material must contain at least 256 bits.
    #[error("command idempotency key material is invalid")]
    InvalidKeyMaterial,
    /// Current and previous generations must have unique identifiers.
    #[error("command idempotency key ids must be unique")]
    DuplicateKeyId,
}

/// Required current key plus the explicit lookup window used during key rotation.
pub struct CommandIdempotencyKeyring {
    current: CommandAliasKey,
    previous: Vec<CommandAliasKey>,
}

impl std::fmt::Debug for CommandIdempotencyKeyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CommandIdempotencyKeyring(<redacted>)")
    }
}

impl CommandIdempotencyKeyring {
    /// Build a fail-closed rotation window. Key identifiers may not repeat.
    pub fn new(
        current: CommandAliasKey,
        previous: Vec<CommandAliasKey>,
    ) -> Result<Self, CommandIdempotencyKeyringError> {
        let mut ids = std::collections::BTreeSet::new();
        if !ids.insert(current.key_id.as_str())
            || previous.iter().any(|key| !ids.insert(key.key_id.as_str()))
        {
            return Err(CommandIdempotencyKeyringError::DuplicateKeyId);
        }
        Ok(Self { current, previous })
    }

    fn probes(
        &self,
        tenant: vocab::TenantId,
        topic: &str,
        raw: &CommandIdempotencyKey,
    ) -> Result<CommandAliasProbeSet, ()> {
        let scope = IndexScope::new(tenant, topic, "idempotency_key", "command_alias_v2")
            .map_err(|_| ())?;
        let index = BlindIndex::new(scope, &[], FilterBits::DEFAULT);
        let current = command_alias_probe(&index, &self.current, raw)?;
        let previous = self
            .previous
            .iter()
            .map(|key| command_alias_probe(&index, key, raw))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(CommandAliasProbeSet {
            current: Some(current),
            previous,
        })
    }
}

fn command_alias_probe(
    index: &BlindIndex<'_>,
    key: &CommandAliasKey,
    raw: &CommandIdempotencyKey,
) -> Result<CommandAliasProbe, ()> {
    let digest = index.index(&key.key, raw.as_str()).map_err(|_| ())?;
    Ok(CommandAliasProbe {
        key_id: key.key_id.clone(),
        digest: digest.as_bytes().to_vec(),
    })
}

/// One sealed keyed lookup alias. The digest is safe for equality lookup but redacted from Debug.
pub struct CommandAliasProbe {
    key_id: String,
    digest: Vec<u8>,
}

impl std::fmt::Debug for CommandAliasProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CommandAliasProbe(<redacted>)")
    }
}

impl CommandAliasProbe {
    /// Rotation key identifier.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Full 256-bit keyed alias digest.
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }

    /// Consume into provider storage values.
    pub fn into_parts(self) -> (String, Vec<u8>) {
        (self.key_id, self.digest)
    }
}

/// Current and previous keyed aliases for one reviewed command intent.
pub struct CommandAliasProbeSet {
    current: Option<CommandAliasProbe>,
    previous: Vec<CommandAliasProbe>,
}

impl std::fmt::Debug for CommandAliasProbeSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CommandAliasProbeSet(<redacted>)")
    }
}

impl CommandAliasProbeSet {
    const fn none() -> Self {
        Self {
            current: None,
            previous: Vec::new(),
        }
    }

    /// Current write alias, or `None` for a direct command without a business key.
    pub fn current(&self) -> Option<&CommandAliasProbe> {
        self.current.as_ref()
    }

    /// Previous-key lookup aliases in configured order.
    pub fn previous(&self) -> &[CommandAliasProbe] {
        &self.previous
    }

    /// Consume into provider-owned alias values.
    pub fn into_parts(self) -> (Option<CommandAliasProbe>, Vec<CommandAliasProbe>) {
        (self.current, self.previous)
    }
}

/// Provider storage failure shared by direct and journaled command stores.
#[derive(Debug, thiserror::Error)]
#[error("command store operation failed")]
pub struct CommandStoreError {
    kind: CommandStoreErrorKind,
    #[source]
    source: RedactedSource,
}

/// Caller-actionable command persistence failure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommandStoreErrorKind {
    /// The same idempotency alias names a semantically different command.
    Conflict,
    /// The persistence provider is temporarily unavailable.
    Unavailable,
    /// The provider detected an internal or invariant failure.
    Internal,
}

impl CommandStoreError {
    fn with_kind<E>(kind: CommandStoreErrorKind, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            kind,
            source: RedactedSource::new(source),
        }
    }

    /// Build a deterministic semantic conflict.
    pub fn conflict<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::with_kind(CommandStoreErrorKind::Conflict, source)
    }

    /// Build a transient provider availability failure.
    pub fn unavailable<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::with_kind(CommandStoreErrorKind::Unavailable, source)
    }

    /// Build an invariant or unexpected internal provider failure.
    pub fn internal<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::with_kind(CommandStoreErrorKind::Internal, source)
    }

    /// Stable failure class; provider text remains redacted.
    pub const fn kind(&self) -> CommandStoreErrorKind {
        self.kind
    }
}

/// Direct command dispatch failure. All messages are stable and contain no request data.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CommandEmitError {
    /// 命令 topic 非 canonical dotted（routing key 形态非法）。
    #[error("command topic is not a canonical dotted name")]
    Topic,
    /// Caller supplied an invalid idempotency key.
    #[error("command idempotency key is invalid")]
    IdempotencyKey,
    /// Scoped actor tenant differs from the command tenant.
    #[error("command actor tenant does not match command tenant")]
    ActorTenant,
    /// Typed request serialization failed.
    #[error("command request serialization failed")]
    Serialization,
    /// The same scoped key was reused for a different request.
    #[error("command idempotency conflict")]
    Conflict,
    /// The persistence provider is temporarily unavailable.
    #[error("command dispatch store is unavailable")]
    Unavailable,
    /// Provider rejected the reviewed command with an internal failure.
    #[error("command dispatch store failed")]
    Store(#[source] CommandStoreError),
}

/// Journaled command dispatch failure with stable outcome classification.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CommandJournalError {
    /// Generated command topic is not a canonical command namespace.
    #[error("command topic is invalid")]
    Topic,
    /// Caller supplied an empty or invalid idempotency key.
    #[error("command idempotency key is invalid")]
    IdempotencyKey,
    /// Request fingerprint derivation failed.
    #[error("command request fingerprint is invalid")]
    Fingerprint,
    /// Scoped actor tenant differs from the command tenant.
    #[error("command actor tenant does not match command tenant")]
    ActorTenant,
    /// Typed request serialization failed.
    #[error("command request serialization failed")]
    Serialization,
    /// Provider operation failed.
    #[error("command journal store failed")]
    Store(#[source] CommandStoreError),
    /// The persistence provider is temporarily unavailable.
    #[error("command journal store is unavailable")]
    Unavailable,
    /// An equivalent request is currently in flight.
    #[error("command is already in flight")]
    InFlight,
    /// An equivalent request previously failed.
    #[error("command previously failed")]
    Failed,
    /// The same scoped key was reused for a different request.
    #[error("command idempotency conflict")]
    Conflict,
    /// Provider returned a completed result other than the enqueue acknowledgement.
    #[error("command journal returned an unexpected completed result")]
    UnexpectedCompleted,
    /// Provider returned an outcome unknown to this runtime version.
    #[error("command journal returned an unexpected outcome")]
    UnexpectedOutcome,
}

/// Successful journal dispatch classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandJournalDispatchOutcome {
    /// This request created the journal/outbox write.
    Recorded,
    /// An equivalent request had already enqueued the command.
    AlreadyEnqueued,
}

/// Provider-agnostic direct command store. It never accepts an event entry.
pub trait CommandDispatchStore: Send + Sync {
    /// Persist one reviewed direct command.
    fn dispatch_command(
        &self,
        command: ReviewedCommandDispatch,
    ) -> impl std::future::Future<Output = Result<(), CommandStoreError>> + Send;
}

/// Provider-agnostic durable command journal seam.
pub trait CommandJournalStore: Send + Sync {
    /// Record command intent and enqueue its outbox command atomically in the provider.
    fn record_command(
        &self,
        command: ReviewedCommandJournal,
        result_summary: CommandResultSummary,
    ) -> impl std::future::Future<Output = Result<CommandJournalOutcome, CommandStoreError>> + Send;
}

/// Provider-neutral reviewed command intent. Raw idempotency keys are absent by construction.
pub struct ReviewedCommandIntent {
    topic: &'static str,
    payload: Vec<u8>,
    aliases: CommandAliasProbeSet,
    request_fingerprint: CommandRequestFingerprint,
}

impl ReviewedCommandIntent {
    /// Validated command topic.
    pub const fn topic(&self) -> &'static str {
        self.topic
    }

    /// Serialized typed request payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Keyed current/previous alias probes.
    pub const fn aliases(&self) -> &CommandAliasProbeSet {
        &self.aliases
    }

    /// Fingerprint of command semantics, explicitly excluding the raw idempotency key.
    pub const fn request_fingerprint(&self) -> &CommandRequestFingerprint {
        &self.request_fingerprint
    }

    /// Consume into provider-owned values.
    pub fn into_parts(
        self,
    ) -> (
        &'static str,
        Vec<u8>,
        CommandAliasProbeSet,
        CommandRequestFingerprint,
    ) {
        (
            self.topic,
            self.payload,
            self.aliases,
            self.request_fingerprint,
        )
    }
}

/// Reviewed direct command write. External crates can consume but cannot construct it.
pub struct ReviewedCommandDispatch {
    intent: ReviewedCommandIntent,
    envelope: OutboxEnvelopeParts,
}

impl ReviewedCommandDispatch {
    fn new(
        spec: generated::command::CommandSpec,
        tenant: vocab::TenantId,
        payload: Vec<u8>,
        subject_id: EnvelopeSubjectId,
        actor: OutboxActor,
        aliases: CommandAliasProbeSet,
    ) -> Result<Self, CommandEmitError> {
        let (intent, envelope) = reviewed_intent(spec, tenant, payload, subject_id, actor, aliases)
            .map_err(CommandEmitError::from)?;
        Ok(Self { intent, envelope })
    }

    /// Borrow the reviewed intent.
    pub const fn intent(&self) -> &ReviewedCommandIntent {
        &self.intent
    }

    /// Borrow the reviewed envelope.
    pub const fn envelope(&self) -> &OutboxEnvelopeParts {
        &self.envelope
    }

    /// Consume into provider-owned primitives.
    pub fn into_parts(self) -> (ReviewedCommandIntent, OutboxEnvelopeParts) {
        (self.intent, self.envelope)
    }
}

/// Reviewed journal command write. External crates can consume but cannot construct it.
pub struct ReviewedCommandJournal {
    intent: ReviewedCommandIntent,
    envelope: OutboxEnvelopeParts,
}

impl ReviewedCommandJournal {
    fn new(
        spec: generated::command::CommandSpec,
        tenant: vocab::TenantId,
        payload: Vec<u8>,
        subject_id: EnvelopeSubjectId,
        actor: OutboxActor,
        aliases: CommandAliasProbeSet,
    ) -> Result<Self, CommandJournalError> {
        if aliases.current().is_none() {
            return Err(CommandJournalError::IdempotencyKey);
        }
        let (intent, envelope) = reviewed_intent(spec, tenant, payload, subject_id, actor, aliases)
            .map_err(CommandJournalError::from)?;
        Ok(Self { intent, envelope })
    }

    /// Borrow the reviewed intent.
    pub const fn intent(&self) -> &ReviewedCommandIntent {
        &self.intent
    }

    /// Consume into provider-owned primitives.
    pub fn into_parts(self) -> (ReviewedCommandIntent, OutboxEnvelopeParts) {
        (self.intent, self.envelope)
    }
}

#[derive(Debug, Clone, Copy)]
enum ReviewedIntentError {
    Topic,
    Fingerprint,
    ActorTenant,
}

impl From<ReviewedIntentError> for CommandEmitError {
    fn from(error: ReviewedIntentError) -> Self {
        match error {
            ReviewedIntentError::Topic => Self::Topic,
            ReviewedIntentError::Fingerprint => Self::Serialization,
            ReviewedIntentError::ActorTenant => Self::ActorTenant,
        }
    }
}

impl From<ReviewedIntentError> for CommandJournalError {
    fn from(error: ReviewedIntentError) -> Self {
        match error {
            ReviewedIntentError::Topic => Self::Topic,
            ReviewedIntentError::Fingerprint => Self::Fingerprint,
            ReviewedIntentError::ActorTenant => Self::ActorTenant,
        }
    }
}

fn reviewed_intent(
    spec: generated::command::CommandSpec,
    tenant: vocab::TenantId,
    payload: Vec<u8>,
    subject_id: EnvelopeSubjectId,
    actor: OutboxActor,
    aliases: CommandAliasProbeSet,
) -> Result<(ReviewedCommandIntent, OutboxEnvelopeParts), ReviewedIntentError> {
    validate_command_topic(spec.topic()).map_err(|()| ReviewedIntentError::Topic)?;
    validate_actor_tenant(tenant, &actor).map_err(|()| ReviewedIntentError::ActorTenant)?;
    let request_fingerprint = command_request_fingerprint(
        tenant,
        spec.topic(),
        spec.contract(),
        &payload,
        &subject_id,
        &actor,
    )
    .map_err(|()| ReviewedIntentError::Fingerprint)?;
    Ok((
        ReviewedCommandIntent {
            topic: spec.topic(),
            payload,
            aliases,
            request_fingerprint,
        },
        OutboxEnvelopeParts::new(spec.contract(), tenant, subject_id, actor),
    ))
}

pub(crate) fn reviewed_keyed_intent(
    keyring: &CommandIdempotencyKeyring,
    spec: generated::command::CommandSpec,
    tenant: vocab::TenantId,
    payload: Vec<u8>,
    subject_id: EnvelopeSubjectId,
    actor: OutboxActor,
    raw_idempotency_key: &str,
) -> Result<(ReviewedCommandIntent, OutboxEnvelopeParts), CommandEmitError> {
    let key = CommandIdempotencyKey::parse(raw_idempotency_key)
        .map_err(|_| CommandEmitError::IdempotencyKey)?;
    let aliases = keyring
        .probes(tenant, spec.topic(), &key)
        .map_err(|()| CommandEmitError::IdempotencyKey)?;
    reviewed_intent(spec, tenant, payload, subject_id, actor, aliases)
        .map_err(CommandEmitError::from)
}

fn command_request_fingerprint(
    tenant: vocab::TenantId,
    topic: &str,
    contract: vocab::ContractBinding,
    payload: &[u8],
    subject_id: &EnvelopeSubjectId,
    actor: &OutboxActor,
) -> Result<CommandRequestFingerprint, ()> {
    let mut hasher = Sha256::new();
    hash_component(&mut hasher, "rss-command-request-v2");
    hash_component(&mut hasher, contract.domain());
    hash_component(&mut hasher, contract.contract_id());
    hash_component(&mut hasher, contract.version());
    hash_component(&mut hasher, contract.schema_hash());
    hash_component(&mut hasher, &tenant.to_string());
    hash_component(&mut hasher, topic);
    hash_component(&mut hasher, subject_id.as_str());
    hash_component(&mut hasher, actor.kind().as_actor_metadata_label());
    hash_component(&mut hasher, actor.actor_id().as_str());
    match actor.tenant() {
        Some(actor_tenant) => hash_component(&mut hasher, &actor_tenant.to_string()),
        None => hash_component(&mut hasher, ""),
    }
    hash_component(&mut hasher, actor.scope().as_label());
    hash_bytes_component(&mut hasher, payload);
    CommandRequestFingerprint::parse(format!("sha256:{}", lower_hex(&hasher.finalize())))
        .map_err(|_| ())
}

pub(crate) fn validate_actor_tenant(
    tenant: vocab::TenantId,
    actor: &OutboxActor,
) -> Result<(), ()> {
    match actor.tenant() {
        Some(actor_tenant) if actor_tenant != tenant => Err(()),
        Some(_) | None => Ok(()),
    }
}

fn hash_component(hasher: &mut Sha256, value: &str) {
    hasher.update(value.len().to_string().as_bytes());
    hasher.update(b":");
    hasher.update(value.as_bytes());
    hasher.update(b"\0");
}

fn hash_bytes_component(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(value.len().to_string().as_bytes());
    hasher.update(b":");
    hasher.update(value);
    hasher.update(b"\0");
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn validate_command_topic(topic: &str) -> Result<(), ()> {
    match EventTopic::parse(topic) {
        Err(EventTopicError::CommandNamespace) => Ok(()),
        _ => Err(()),
    }
}

/// Generic direct-command bridge generated wrappers can call.
pub struct DirectCommandDispatcher<S> {
    store: S,
    keyring: Arc<CommandIdempotencyKeyring>,
}

impl<S> DirectCommandDispatcher<S> {
    /// Bind a provider store and the mandatory independent idempotency keyring.
    pub fn new(store: S, keyring: Arc<CommandIdempotencyKeyring>) -> Self {
        Self { store, keyring }
    }
}

impl<S: CommandDispatchStore> DirectCommandDispatcher<S> {
    #[allow(clippy::too_many_arguments)]
    async fn dispatch_reviewed<C>(
        &self,
        request: &C::Request,
        tenant: vocab::TenantId,
        subject_id: EnvelopeSubjectId,
        actor: OutboxActor,
        idempotency_key: Option<&str>,
    ) -> Result<(), CommandEmitError>
    where
        C: generated::command::DirectCommandContract,
        C::Request: Send + Sync,
    {
        let spec = C::SPEC;
        let payload = serde_json::to_vec(request).map_err(|_| CommandEmitError::Serialization)?;
        let aliases = match idempotency_key {
            Some(raw) => {
                let key = CommandIdempotencyKey::parse(raw)
                    .map_err(|_| CommandEmitError::IdempotencyKey)?;
                self.keyring
                    .probes(tenant, spec.topic(), &key)
                    .map_err(|()| CommandEmitError::IdempotencyKey)?
            }
            None => CommandAliasProbeSet::none(),
        };
        let command =
            ReviewedCommandDispatch::new(spec, tenant, payload, subject_id, actor, aliases)?;
        CommandDispatchStore::dispatch_command(&self.store, command)
            .await
            .map_err(map_emit_store_error)
    }
}

impl<S: CommandDispatchStore> generated::command::CommandEmit for DirectCommandDispatcher<S> {
    type Error = CommandEmitError;
    type SubjectId = EnvelopeSubjectId;
    type Actor = OutboxActor;

    async fn emit<C>(
        &self,
        request: &C::Request,
        tenant: vocab::TenantId,
        subject_id: Self::SubjectId,
        actor: Self::Actor,
        idempotency_key: Option<&str>,
    ) -> Result<(), Self::Error>
    where
        C: generated::command::DirectCommandContract,
        C::Request: Send + Sync,
    {
        self.dispatch_reviewed::<C>(request, tenant, subject_id, actor, idempotency_key)
            .await
    }
}

/// Generic journal-required command bridge generated wrappers can call.
pub struct JournaledCommandDispatcher<S> {
    store: S,
    keyring: Arc<CommandIdempotencyKeyring>,
}

impl<S> JournaledCommandDispatcher<S> {
    /// Bind a provider journal store and the mandatory independent idempotency keyring.
    pub fn new(store: S, keyring: Arc<CommandIdempotencyKeyring>) -> Self {
        Self { store, keyring }
    }
}

impl<S: CommandJournalStore> generated::command::CommandJournal for JournaledCommandDispatcher<S> {
    type Error = CommandJournalError;
    type Outcome = CommandJournalDispatchOutcome;
    type SubjectId = EnvelopeSubjectId;
    type Actor = OutboxActor;

    async fn journal<C>(
        &self,
        request: &C::Request,
        tenant: vocab::TenantId,
        subject_id: Self::SubjectId,
        actor: Self::Actor,
        idempotency_key: &str,
    ) -> Result<Self::Outcome, Self::Error>
    where
        C: generated::command::JournaledCommandContract,
        C::Request: Send + Sync,
    {
        let spec = C::SPEC;
        let key = CommandIdempotencyKey::parse(idempotency_key)
            .map_err(|_| CommandJournalError::IdempotencyKey)?;
        let aliases = self
            .keyring
            .probes(tenant, spec.topic(), &key)
            .map_err(|()| CommandJournalError::IdempotencyKey)?;
        let payload =
            serde_json::to_vec(request).map_err(|_| CommandJournalError::Serialization)?;
        let command =
            ReviewedCommandJournal::new(spec, tenant, payload, subject_id, actor, aliases)?;
        match CommandJournalStore::record_command(
            &self.store,
            command,
            CommandResultSummary::ENQUEUED,
        )
        .await
        .map_err(map_journal_store_error)?
        {
            CommandJournalOutcome::Recorded => Ok(CommandJournalDispatchOutcome::Recorded),
            CommandJournalOutcome::AlreadyCompleted(summary)
                if summary == CommandResultSummary::ENQUEUED =>
            {
                Ok(CommandJournalDispatchOutcome::AlreadyEnqueued)
            }
            CommandJournalOutcome::AlreadyCompleted(_) => {
                Err(CommandJournalError::UnexpectedCompleted)
            }
            CommandJournalOutcome::AlreadyInFlight => Err(CommandJournalError::InFlight),
            CommandJournalOutcome::AlreadyFailed(_) => Err(CommandJournalError::Failed),
            CommandJournalOutcome::Conflict => Err(CommandJournalError::Conflict),
            _ => Err(CommandJournalError::UnexpectedOutcome),
        }
    }
}

fn map_emit_store_error(error: CommandStoreError) -> CommandEmitError {
    match error.kind() {
        CommandStoreErrorKind::Conflict => CommandEmitError::Conflict,
        CommandStoreErrorKind::Unavailable => CommandEmitError::Unavailable,
        CommandStoreErrorKind::Internal => CommandEmitError::Store(error),
    }
}

fn map_journal_store_error(error: CommandStoreError) -> CommandJournalError {
    match error.kind() {
        CommandStoreErrorKind::Conflict => CommandJournalError::Conflict,
        CommandStoreErrorKind::Unavailable => CommandJournalError::Unavailable,
        CommandStoreErrorKind::Internal => CommandJournalError::Store(error),
    }
}

/// Runtime 命令消费注册 —— 复用 [`run_consumer`] 驱动 + [`InboxStore`] claimer 两阶段去重。
///
/// 消息 `payload` 经 `serde_json` 解码为 typed `R` 后交 `handler`；解码失败 = 永久 `reject`（坏 wire 不可
/// 恢复 → DLX，不 Requeue 无限重投）。同 canonical command id（`Message.id` = dispatch key）二次投递 → claimer
/// durable done 时 `try_claim` 返 `Duplicate` → handler 不调、幂等短路；active claim 返
/// transient 并 Requeue。claim→handle→commit/dlx 全复用
/// `run_consumer`，零新去重原语。`contract` 同时提供 contract id 与 expected schema fingerprint，命令路径
/// 与事件订阅路径共享同一 envelope header gate。
///
/// **生命周期接线（调用方必须遵守）**：本函数 `.await` 后进入无限消费循环（持续驱动 `stream`）；
/// 调用方**必须**将其 spawn 到组合根的 `ManagedResource` / `ShutdownStack` 可取消任务栈，以保证
/// 关闭信号能中断循环。直接 `.await` 会阻塞当前 task 且无法接收 shutdown，属组合根接线错误。
/// 组合根 spawn 接线（ManagedResource / ShutdownStack）随首个真实命令消费者落地。
///
/// 组合根 registrar（impl `generated::command::CommandRegister`）经 spawn 调用本 async 驱动；generated
/// `<cmd>::register_handler` wrapper 锁 typed `R` + baked CONTRACT_ID/TOPIC。
#[allow(clippy::too_many_arguments)]
// reason: 8 参数是命令消费注册的最小必要集（stream/idempotency/dlx/domain/contract_id/topic/handler/lease_cfg
// 各自语义独立）；聚合 struct 增间接层且无复用，item-level carve-out（error-handling.md §Carve-out）。
pub async fn register_command_handler<S, R, H, Fut>(
    stream: MessageStream,
    idempotency: Arc<S>,
    dlx: Box<DynDeadLetterStore<'static>>,
    domain: impl Into<String>,
    contract: vocab::ContractBinding,
    topic: impl Into<String>,
    consumer_group: impl Into<String>,
    tenant_authority: Arc<TenantAuthority>,
    handler: H,
    lease_cfg: LeaseConfig,
) where
    S: InboxStore + Send + Sync + 'static,
    R: for<'de> serde::Deserialize<'de> + Send + 'static,
    H: Fn(R) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = HandleResult> + Send + 'static,
{
    let contract_id_s: Arc<str> = contract.contract_id().into();
    let topic_s: Arc<str> = topic.into().into();
    let meta = ConsumerMeta::new(
        domain.into(),
        topic_owner(&topic_s),
        &*contract_id_s,
        &*topic_s,
        consumer_group,
        tenant_authority,
    )
    .with_expected_schema(contract.version(), contract.schema_hash());
    let handler = Arc::new(handler);
    run_consumer(
        stream,
        idempotency,
        dlx,
        meta,
        move |msg: Message| {
            let handler = Arc::clone(&handler);
            let contract_id_s = Arc::clone(&contract_id_s);
            let topic_s = Arc::clone(&topic_s);
            Box::pin(async move {
                match serde_json::from_slice::<R>(msg.payload.as_bytes()) {
                    Ok(req) => handler(req).await,
                    Err(_) => {
                        // 坏 wire = 永久 reject（不可恢复 → DLX）；warn 记录解码失败原因（无 payload 字节，PII 边界）。
                        log_decode_failed(msg.id.as_str(), &contract_id_s, &topic_s);
                        HandleResult::reject(PermanentError::new(PermanentErrorKind::Permanent))
                    }
                }
            })
        },
        lease_cfg,
    )
    .await;
}

fn topic_owner(topic: &str) -> &str {
    topic.split('.').next().unwrap_or(topic)
}

/// 命令 payload 解码失败结构化 warn（contract_id/topic/message_id 归因；无 payload 字节，PII 边界同 DLX log）。
fn log_decode_failed(message_id: &str, contract_id: &str, topic: &str) {
    tracing::warn!(
        message_id,
        contract_id,
        topic,
        "command: payload decode failed, permanent reject to DLX"
    );
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    use consistency::idempotency::{IdemKey, LeaseOutcome, LeaseToken, SeenState};
    use consistency::{
        CommandIdempotencyKey, CommandJournalOutcome, CommandResultSummary, HandleResult,
    };
    use consistency::{InboxReceiptContext, InboxStore};
    use diport::dead_letter_store::{
        DeadLetterRecord, DeadLetterStore, DeadLetterStoreError, DynDeadLetterStore,
    };
    use diport::{
        EnvelopeMetadata, EnvelopeSubjectId, KEY_SCHEMA_HASH, KEY_SCHEMA_VERSION,
        KEY_TENANT_AUTHORITY, KEY_TENANT_ID, Message, OpaqueActorId, OutboxActor,
    };
    use primitives::{Mac, MacAlgorithm, MacKey, MacVerifier};

    use super::{
        CommandAliasKey, CommandAliasProbeSet, CommandEmitError, CommandIdempotencyKeyring,
        CommandJournalDispatchOutcome, CommandJournalError, CommandJournalStore, CommandStoreError,
        CommandStoreErrorKind, JournaledCommandDispatcher, LeaseConfig, ReviewedCommandDispatch,
        ReviewedCommandJournal, map_emit_store_error, map_journal_store_error,
        register_command_handler,
    };
    use crate::MAX_REDELIVERY;
    use crate::TenantAuthority;
    use crate::tenant_authority::TenantAuthorityBinding;

    const HASH: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn command_store_error_keeps_stable_message_and_redacts_provider_source() {
        let error = CommandStoreError::internal(std::io::Error::other("provider-secret-marker"));
        assert_eq!(error.to_string(), "command store operation failed");
        assert_eq!(error.kind(), CommandStoreErrorKind::Internal);
        assert!(std::error::Error::source(&error).is_some());
        assert!(!format!("{error:?}").contains("provider-secret-marker"));
    }

    /// 测试用 lease 配置（续租间隔大，命令消费测试中续租不触发）。
    fn lease_cfg() -> LeaseConfig {
        LeaseConfig::from_ttl(std::time::Duration::from_secs(60))
    }

    #[allow(clippy::expect_used)]
    fn tenant() -> vocab::TenantId {
        vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant")
    }

    fn command_contract() -> vocab::ContractBinding {
        vocab::ContractBinding::from_static("seed", "seed.do-thing", "v1", HASH)
    }

    #[allow(clippy::expect_used)]
    fn subject(raw: &str) -> EnvelopeSubjectId {
        EnvelopeSubjectId::from_opaque(raw).expect("opaque subject")
    }

    #[allow(clippy::expect_used)]
    fn actor() -> OutboxActor {
        OutboxActor::service(OpaqueActorId::from_opaque("command-test-service").expect("actor"))
    }

    #[allow(clippy::expect_used)]
    fn other_tenant_actor() -> OutboxActor {
        let other = vocab::TenantId::parse("11111111-1111-1111-1111-111111111111")
            .expect("canonical tenant");
        OutboxActor::scoped(
            vocab::PrincipalKind::Admin,
            OpaqueActorId::from_opaque("other-tenant-actor").expect("actor"),
            other,
            vocab::ScopedTenant::Tenant,
        )
    }

    #[allow(clippy::expect_used)]
    fn idem(raw: &str) -> CommandIdempotencyKey {
        CommandIdempotencyKey::parse(raw).expect("idempotency key")
    }

    #[allow(clippy::expect_used)]
    fn command_keyring() -> Arc<CommandIdempotencyKeyring> {
        Arc::new(
            CommandIdempotencyKeyring::new(
                CommandAliasKey::new("k2", vec![0x42; 32]).expect("key"),
                vec![CommandAliasKey::new("k1", vec![0x24; 32]).expect("key")],
            )
            .expect("keyring"),
        )
    }

    #[derive(Debug)]
    struct TestMac;

    impl MacVerifier for TestMac {
        fn sign(&self, key: &MacKey, _algorithm: MacAlgorithm, message: &[u8]) -> Mac {
            let mut tag = Vec::from(key.as_bytes());
            tag.extend_from_slice(message);
            Mac::from_bytes(tag)
        }

        fn verify(&self, key: &MacKey, algorithm: MacAlgorithm, message: &[u8], tag: &Mac) -> bool {
            self.sign(key, algorithm, message).as_bytes() == tag.as_bytes()
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: fixed valid keyring fixtures must produce a complete current/previous alias set.
    fn keyed_aliases_are_stable_rotatable_and_tenant_scoped() {
        let keys = command_keyring();
        let raw = idem("customer@example.test/retry-42");
        let first = keys
            .probes(tenant(), "seed.commands.do-thing", &raw)
            .expect("aliases");
        let repeated = keys
            .probes(tenant(), "seed.commands.do-thing", &raw)
            .expect("aliases");
        let other = keys
            .probes(
                vocab::TenantId::parse("11111111-1111-1111-1111-111111111111").expect("tenant"),
                "seed.commands.do-thing",
                &raw,
            )
            .expect("aliases");
        assert_eq!(first.current().expect("current").key_id(), "k2");
        assert_eq!(first.previous()[0].key_id(), "k1");
        assert_eq!(
            first.current().expect("current").digest(),
            repeated.current().expect("current").digest()
        );
        assert_ne!(
            first.current().expect("current").digest(),
            other.current().expect("current").digest()
        );
        assert_eq!(format!("{first:?}"), "CommandAliasProbeSet(<redacted>)");
    }

    #[test]
    fn reviewed_direct_command_rejects_scoped_actor_from_other_tenant() {
        let result = ReviewedCommandDispatch::new(
            generated::command::_seed_v1::SPEC,
            tenant(),
            br#"{"op":"one"}"#.to_vec(),
            subject("subject-1"),
            other_tenant_actor(),
            CommandAliasProbeSet::none(),
        );
        assert!(matches!(result, Err(CommandEmitError::ActorTenant)));
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: fixed valid generated inputs exercise fingerprint equality and inequality.
    fn fingerprint_excludes_idempotency_key_but_includes_payload() {
        let keys = command_keyring();
        let build = |raw: &str, payload: &[u8]| {
            ReviewedCommandJournal::new(
                generated::command::_seed_v1::SPEC,
                tenant(),
                payload.to_vec(),
                subject("subject-1"),
                actor(),
                keys.probes(tenant(), generated::command::_seed_v1::TOPIC, &idem(raw))
                    .expect("aliases"),
            )
            .expect("reviewed")
        };
        let first = build("first-key", br#"{"op":"one"}"#);
        let changed_key = build("second-key", br#"{"op":"one"}"#);
        let changed_payload = build("first-key", br#"{"op":"two"}"#);
        assert_eq!(
            first.intent().request_fingerprint(),
            changed_key.intent().request_fingerprint()
        );
        assert_ne!(
            first.intent().request_fingerprint(),
            changed_payload.intent().request_fingerprint()
        );
    }

    #[test]
    fn store_error_kind_maps_to_public_dispatcher_outcomes() {
        assert!(matches!(
            map_emit_store_error(CommandStoreError::conflict(std::io::Error::other("x"))),
            CommandEmitError::Conflict
        ));
        assert!(matches!(
            map_emit_store_error(CommandStoreError::unavailable(std::io::Error::other("x"))),
            CommandEmitError::Unavailable
        ));
        assert!(matches!(
            map_journal_store_error(CommandStoreError::conflict(std::io::Error::other("x"))),
            CommandJournalError::Conflict
        ));
        assert!(matches!(
            map_journal_store_error(CommandStoreError::unavailable(std::io::Error::other("x"))),
            CommandJournalError::Unavailable
        ));
    }

    #[allow(clippy::expect_used)]
    fn tenant_authority() -> Arc<TenantAuthority> {
        Arc::new(
            TenantAuthority::new(
                Arc::new(TestMac),
                MacKey::from_bytes(vec![0x42; 32]),
                60,
                5,
                Arc::new(|| 1_700_000_000),
            )
            .expect("valid tenant authority"),
        )
    }

    struct FakeJournalStore {
        outcome: Mutex<Option<CommandJournalOutcome>>,
    }

    impl FakeJournalStore {
        fn new(outcome: CommandJournalOutcome) -> Self {
            Self {
                outcome: Mutex::new(Some(outcome)),
            }
        }
    }

    impl CommandJournalStore for FakeJournalStore {
        #[allow(clippy::expect_used)]
        // reason: generated journal wrapper must always supply a current keyed alias.
        fn record_command(
            &self,
            command: ReviewedCommandJournal,
            result_summary: CommandResultSummary,
        ) -> impl std::future::Future<Output = Result<CommandJournalOutcome, CommandStoreError>> + Send
        {
            assert_eq!(result_summary, CommandResultSummary::ENQUEUED);
            let (intent, envelope) = command.into_parts();
            assert_eq!(intent.topic(), "seed.commands.do-thing");
            assert_eq!(intent.payload(), br#"{"amount":7,"targetId":"target-1"}"#);
            assert_eq!(*envelope.contract(), generated::command::_seed_v1::CONTRACT);
            assert_eq!(envelope.tenant(), tenant());
            assert_eq!(intent.aliases().current().expect("current").key_id(), "k2");
            #[allow(clippy::unwrap_used)]
            let outcome = self.outcome.lock().unwrap().take().unwrap();
            async move { Ok(outcome) }
        }
    }

    async fn journal_seed(
        outcome: CommandJournalOutcome,
        key: &str,
    ) -> Result<CommandJournalDispatchOutcome, CommandJournalError> {
        let dispatcher =
            JournaledCommandDispatcher::new(FakeJournalStore::new(outcome), command_keyring());
        generated::command::_seed_v1::journal_async(
            &dispatcher,
            generated::command::_seed_v1::SeedDoThingRequest {
                amount: 7,
                target_id: "target-1".to_string(),
            },
            tenant(),
            subject("subject-opaque"),
            actor(),
            key.to_string(),
        )
        .await
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: known provider outcomes are asserted as successful canary cases.
    async fn seed_journal_maps_all_provider_outcomes() {
        assert_eq!(
            journal_seed(CommandJournalOutcome::Recorded, "stable-key")
                .await
                .expect("recorded"),
            CommandJournalDispatchOutcome::Recorded
        );
        assert_eq!(
            journal_seed(
                CommandJournalOutcome::AlreadyCompleted(CommandResultSummary::ENQUEUED),
                "stable-key"
            )
            .await
            .expect("already enqueued"),
            CommandJournalDispatchOutcome::AlreadyEnqueued
        );
        assert!(matches!(
            journal_seed(CommandJournalOutcome::AlreadyInFlight, "stable-key").await,
            Err(CommandJournalError::InFlight)
        ));
        assert!(matches!(
            journal_seed(
                CommandJournalOutcome::AlreadyFailed(consistency::CommandErrorSummary::FAILED),
                "stable-key"
            )
            .await,
            Err(CommandJournalError::Failed)
        ));
        assert!(matches!(
            journal_seed(CommandJournalOutcome::Conflict, "stable-key").await,
            Err(CommandJournalError::Conflict)
        ));
        assert!(matches!(
            journal_seed(CommandJournalOutcome::Recorded, "").await,
            Err(CommandJournalError::IdempotencyKey)
        ));
    }

    // ── consumer 侧 fakes ───────────────────────────────────────────────────────

    enum CheckResult {
        Fresh,
        Duplicate,
    }

    struct FakeStore {
        result: CheckResult,
        commit_count: AtomicU32,
    }

    impl FakeStore {
        fn fresh() -> Arc<Self> {
            Arc::new(Self {
                result: CheckResult::Fresh,
                commit_count: AtomicU32::new(0),
            })
        }
        fn duplicate() -> Arc<Self> {
            Arc::new(Self {
                result: CheckResult::Duplicate,
                commit_count: AtomicU32::new(0),
            })
        }
        fn commits(&self) -> u32 {
            self.commit_count.load(Ordering::Acquire)
        }
    }

    impl InboxStore for FakeStore {
        async fn try_claim(
            &self,
            _ctx: &InboxReceiptContext,
            _key: &IdemKey,
            _lease: &LeaseToken,
        ) -> Result<SeenState, consistency::error::EngineError> {
            match self.result {
                CheckResult::Fresh => Ok(SeenState::Fresh),
                CheckResult::Duplicate => Ok(SeenState::Duplicate),
            }
        }
        async fn extend(
            &self,
            _ctx: &InboxReceiptContext,
            _key: &IdemKey,
            _lease: &LeaseToken,
        ) -> Result<LeaseOutcome, consistency::error::EngineError> {
            // 命令消费测试不模拟租约丢失：恒 Held。
            Ok(LeaseOutcome::Held)
        }
        async fn commit(
            &self,
            _ctx: &InboxReceiptContext,
            _key: &IdemKey,
            _lease: &LeaseToken,
        ) -> Result<LeaseOutcome, consistency::error::EngineError> {
            self.commit_count.fetch_add(1, Ordering::Release);
            Ok(LeaseOutcome::Held)
        }
        async fn release(
            &self,
            _ctx: &InboxReceiptContext,
            _key: &IdemKey,
            _lease: &LeaseToken,
        ) -> Result<(), consistency::error::EngineError> {
            Ok(())
        }
    }

    struct FakeDlx {
        writes: Mutex<u32>,
    }
    impl FakeDlx {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                writes: Mutex::new(0),
            })
        }
        fn write_count(&self) -> u32 {
            #[allow(clippy::unwrap_used)]
            // reason: 测试 Mutex，item-level carve-out
            *self.writes.lock().unwrap()
        }
    }
    impl DeadLetterStore for FakeDlx {
        async fn write_dead_letter(
            &self,
            _record: DeadLetterRecord,
        ) -> Result<(), DeadLetterStoreError> {
            #[allow(clippy::unwrap_used)]
            // reason: 测试 Mutex，item-level carve-out
            {
                *self.writes.lock().unwrap() += 1;
            }
            Ok(())
        }
        async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
            Ok(())
        }
    }

    fn box_dlx(store: Arc<FakeDlx>) -> Box<DynDeadLetterStore<'static>> {
        struct ArcProxy(Arc<FakeDlx>);
        impl DeadLetterStore for ArcProxy {
            async fn write_dead_letter(
                &self,
                record: DeadLetterRecord,
            ) -> Result<(), DeadLetterStoreError> {
                self.0.write_dead_letter(record).await
            }
            async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
                Ok(())
            }
        }
        DynDeadLetterStore::new_box(ArcProxy(store))
    }

    #[allow(clippy::expect_used)]
    fn stream_of_with_schema(
        items: &[(&str, &[u8])],
        schema_version: &str,
        schema_hash: &str,
    ) -> diport::MessageStream {
        let msgs: Vec<Message> = items
            .iter()
            .map(|(id, p)| {
                let mut md = EnvelopeMetadata::empty();
                let token = tenant_authority()
                    .sign(TenantAuthorityBinding::new(
                        tenant(),
                        "seed",
                        "seed.do-thing",
                        "seed.commands.do-thing",
                        id,
                    ))
                    .expect("tenant authority test signing cannot fail");
                md.insert_wire_pair(KEY_TENANT_ID, tenant().to_string());
                md.insert_wire_pair(KEY_TENANT_AUTHORITY, token);
                md.insert_wire_pair(KEY_SCHEMA_VERSION, schema_version);
                md.insert_wire_pair(KEY_SCHEMA_HASH, schema_hash);
                Message::new_with_metadata(*id, p.to_vec(), md)
            })
            .collect();
        Box::pin(futures::stream::iter(msgs))
    }

    fn stream_of(items: &[(&str, &[u8])]) -> diport::MessageStream {
        stream_of_with_schema(items, "v1", HASH)
    }

    #[derive(serde::Deserialize)]
    struct DoThing {
        amount: i64,
    }

    /// 合法 wire → typed decode → handler 收到 typed Request；Ack → commit 1 次、无 DLX。
    #[tokio::test]
    async fn register_decodes_typed_and_acks() {
        let idem = FakeStore::fresh();
        let dlx = FakeDlx::new();
        let seen = Arc::new(Mutex::new(Vec::<i64>::new()));
        let seen2 = seen.clone();
        register_command_handler::<_, DoThing, _, _>(
            stream_of(&[("dispatch-1", b"{\"amount\":9}")]),
            idem.clone(),
            box_dlx(dlx.clone()),
            "seed",
            command_contract(),
            "seed.commands.do-thing",
            "seed.do-thing.consumer",
            tenant_authority(),
            move |req: DoThing| {
                let seen2 = seen2.clone();
                async move {
                    #[allow(clippy::unwrap_used)]
                    // reason: 测试 Mutex，item-level carve-out
                    seen2.lock().unwrap().push(req.amount);
                    HandleResult::ack()
                }
            },
            lease_cfg(),
        )
        .await;
        #[allow(clippy::unwrap_used)]
        // reason: 测试断言，item-level carve-out
        let amounts = seen.lock().unwrap().clone();
        assert_eq!(amounts, vec![9], "handler 应收到 typed decode 的 amount");
        assert_eq!(idem.commits(), 1, "Ack → commit 1 次");
        assert_eq!(dlx.write_count(), 0, "无 DLX");
    }

    #[tokio::test]
    async fn register_rejects_schema_hash_mismatch_before_claim() {
        const OTHER_HASH: &str =
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let idem = FakeStore::fresh();
        let dlx = FakeDlx::new();
        let calls = Arc::new(AtomicU32::new(0));
        let calls2 = calls.clone();

        register_command_handler::<_, DoThing, _, _>(
            stream_of_with_schema(
                &[("dispatch-wrong-schema", b"{\"amount\":9}")],
                "v1",
                OTHER_HASH,
            ),
            idem.clone(),
            box_dlx(dlx.clone()),
            "seed",
            command_contract(),
            "seed.commands.do-thing",
            "seed.do-thing.consumer",
            tenant_authority(),
            move |_req: DoThing| {
                let calls2 = calls2.clone();
                async move {
                    calls2.fetch_add(1, Ordering::Relaxed);
                    HandleResult::ack()
                }
            },
            lease_cfg(),
        )
        .await;

        assert_eq!(
            calls.load(Ordering::Relaxed),
            0,
            "schema mismatch must be rejected before typed handler"
        );
        assert_eq!(idem.commits(), 0, "schema mismatch must not claim/commit");
        assert_eq!(dlx.write_count(), 0, "header gate must skip app DLX");
    }

    /// 同 canonical command id 二次（claimer 返 Duplicate）→ handler 不调、不 commit（= claimer 拒，两阶段去重）。
    #[tokio::test]
    async fn register_duplicate_dispatch_id_rejected_by_claimer() {
        let idem = FakeStore::duplicate();
        let dlx = FakeDlx::new();
        let calls = Arc::new(AtomicU32::new(0));
        let calls2 = calls.clone();
        register_command_handler::<_, DoThing, _, _>(
            stream_of(&[("dispatch-dup", b"{\"amount\":1}")]),
            idem.clone(),
            box_dlx(dlx.clone()),
            "seed",
            command_contract(),
            "seed.commands.do-thing",
            "seed.do-thing.consumer",
            tenant_authority(),
            move |_req: DoThing| {
                let calls2 = calls2.clone();
                async move {
                    calls2.fetch_add(1, Ordering::Relaxed);
                    HandleResult::ack()
                }
            },
            lease_cfg(),
        )
        .await;
        assert_eq!(
            calls.load(Ordering::Relaxed),
            0,
            "Duplicate → handler 不调（claimer 拒）"
        );
        assert_eq!(idem.commits(), 0, "Duplicate → 不 commit");
    }

    /// 坏 wire（非法 JSON）→ 永久 reject → DLX 写 1 次（坏消息不 Requeue 无限重投）。
    #[tokio::test]
    async fn register_bad_wire_rejected_to_dlx() {
        let idem = FakeStore::fresh();
        let dlx = FakeDlx::new();
        register_command_handler::<_, DoThing, _, _>(
            stream_of(&[("dispatch-bad", b"not json")]),
            idem.clone(),
            box_dlx(dlx.clone()),
            "seed",
            command_contract(),
            "seed.commands.do-thing",
            "seed.do-thing.consumer",
            tenant_authority(),
            move |_req: DoThing| async move { HandleResult::ack() },
            lease_cfg(),
        )
        .await;
        assert_eq!(dlx.write_count(), 1, "坏 wire → 永久 reject → DLX");
    }

    // ── TC-F5c：requeue 路径 → MAX_REDELIVERY 耗尽 → DLX ────────────────────

    /// TC-F5c：handler 恒 Requeue → MAX_REDELIVERY 次后进 DLX（镜像 consumer.rs TC2，经命令 wrapper）。
    #[tokio::test]
    async fn register_requeue_exhausted_to_dlx() {
        let idem = FakeStore::fresh();
        let dlx = FakeDlx::new();
        let calls = Arc::new(AtomicU32::new(0));
        let calls2 = calls.clone();
        register_command_handler::<_, DoThing, _, _>(
            stream_of(&[("dispatch-rq", b"{\"amount\":1}")]),
            idem.clone(),
            box_dlx(dlx.clone()),
            "seed",
            command_contract(),
            "seed.commands.do-thing",
            "seed.do-thing.consumer",
            tenant_authority(),
            move |_req: DoThing| {
                let calls2 = calls2.clone();
                async move {
                    calls2.fetch_add(1, Ordering::Relaxed);
                    HandleResult::requeue(consistency::error::EngineError::new(
                        consistency::error::EngineErrorKind::Transient,
                    ))
                }
            },
            lease_cfg(),
        )
        .await;
        assert_eq!(
            calls.load(Ordering::Relaxed),
            MAX_REDELIVERY,
            "requeue handler 应调 MAX_REDELIVERY 次"
        );
        assert_eq!(dlx.write_count(), 1, "requeue 耗尽 → DLX 写 1 次");
    }
}
