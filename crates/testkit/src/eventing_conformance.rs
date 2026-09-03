//! Eventing conformance helpers（#1435）。
//!
//! 本模块只表达 provider-agnostic 的 eventing 行为断言：outbox relay / sampler / sweeper、
//! inbox claim / lease CAS，以及 consumer settlement / DLX 语义。调用方用闭包适配具体 adapter
//! 类型和探针；本模块不依赖任何 RSS domain 类型，
//! 不替代生产 API 的类型层 Hard 约束。
//!
//! ref: serverlesstechnology/cqrs persistence/postgres-es/src/event_repository.rs@d6bc03ca1cd7a6538fedb51fd4c592126527a3c0

use std::future::Future;
use std::pin::Pin;

type CaseFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, String>> + 'a>>;
type OutboxSeedFn<'a> = Box<dyn FnMut(OutboxSeedArgs) -> CaseFuture<'a, ()> + 'a>;
type OutboxRelayFn<'a> = Box<dyn FnMut(OutboxRelayArgs) -> CaseFuture<'a, RelayObservation> + 'a>;
type OutboxClaimFn<'a> = Box<dyn FnMut(DomainArgs) -> CaseFuture<'a, Vec<String>> + 'a>;
type OutboxStateFn<'a> = Box<dyn FnMut(EventIdArgs) -> CaseFuture<'a, OutboxState> + 'a>;
type OutboxBackdateFn<'a> = Box<dyn FnMut(EventIdArgs) -> CaseFuture<'a, ()> + 'a>;
type OutboxSampleFn<'a> = Box<dyn FnMut(DomainArgs) -> CaseFuture<'a, BacklogSample> + 'a>;
type OutboxSweepFn<'a> = Box<dyn FnMut(u64) -> CaseFuture<'a, u64> + 'a>;
type OutboxTerminalFn<'a> = Box<dyn FnMut(OutboxTerminalArgs) -> CaseFuture<'a, ()> + 'a>;

type InboxClaimFn<'a> = Box<dyn FnMut(InboxLeaseArgs) -> CaseFuture<'a, InboxSeen> + 'a>;
type InboxLeaseFn<'a> = Box<dyn FnMut(InboxLeaseArgs) -> CaseFuture<'a, LeaseOutcome> + 'a>;
type InboxReleaseFn<'a> = Box<dyn FnMut(InboxLeaseArgs) -> CaseFuture<'a, ()> + 'a>;
type InboxBackdateFn<'a> = Box<dyn FnMut(InboxKeyArgs) -> CaseFuture<'a, ()> + 'a>;

type ConsumerScenarioFn<'a> = Box<dyn FnMut() -> CaseFuture<'a, ConsumerObservation> + 'a>;

/// Eventing conformance 断言失败。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EventingConformanceError {
    /// Provider operation failed.
    #[error("{0}")]
    Provider(Box<ProviderFailure>),
    /// Observed value did not match the expected value.
    #[error("{0}")]
    Mismatch(Box<MismatchFailure>),
    /// DLX observation did not match the expected value.
    #[error("{0}")]
    DlxMismatch(Box<DlxFailure>),
}

#[derive(Debug, thiserror::Error)]
#[error("eventing conformance: provider op failed during {stage}: {error}")]
pub struct ProviderFailure {
    pub stage: &'static str,
    pub error: String,
}

#[derive(thiserror::Error)]
#[error(
    "eventing conformance: {stage} mismatch for event_id={event_id} inbox_key={inbox_key} consumer_group={consumer_group} lease_token=<redacted>; expected {expected}, got {actual}"
)]
pub struct MismatchFailure {
    pub stage: &'static str,
    pub event_id: String,
    pub inbox_key: String,
    pub consumer_group: String,
    pub lease_token_alias: String,
    pub expected: String,
    pub actual: String,
}

impl std::fmt::Debug for MismatchFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MismatchFailure")
            .field("stage", &self.stage)
            .field("event_id", &self.event_id)
            .field("inbox_key", &self.inbox_key)
            .field("consumer_group", &self.consumer_group)
            .field("lease_token_alias", &"<redacted>")
            .field("expected", &self.expected)
            .field("actual", &self.actual)
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
#[error(
    "eventing conformance: {stage} dlx mismatch for event_id={event_id} source_kind={source_kind} domain={domain} contract_id={contract_id} topic={topic} num_attempts={num_attempts}; expected {expected}, got {actual}"
)]
pub struct DlxFailure {
    pub stage: &'static str,
    pub event_id: String,
    pub source_kind: String,
    pub domain: String,
    pub contract_id: String,
    pub topic: String,
    pub num_attempts: u32,
    pub expected: String,
    pub actual: String,
}

fn provider(stage: &'static str, error: String) -> EventingConformanceError {
    EventingConformanceError::Provider(Box::new(ProviderFailure {
        stage,
        error: safe_error(error),
    }))
}

fn safe_error(error: String) -> String {
    let error = redact_secret_values(redact_url_userinfo(&error).replace(['\r', '\n'], " "));
    const MAX_SAFE_ERROR_LEN: usize = 240;
    if error.len() <= MAX_SAFE_ERROR_LEN {
        error
    } else {
        let end = error
            .char_indices()
            .take_while(|(idx, _)| *idx <= MAX_SAFE_ERROR_LEN)
            .map(|(idx, _)| idx)
            .last()
            .unwrap_or(0);
        format!("{}...", &error[..end])
    }
}

fn redact_url_userinfo(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0;
    while let Some(rel_scheme) = input[cursor..].find("://") {
        let scheme_end = cursor + rel_scheme + 3;
        out.push_str(&input[cursor..scheme_end]);
        let authority_end = input[scheme_end..]
            .find(['/', '?', '#', ' '])
            .map_or(input.len(), |idx| scheme_end + idx);
        if let Some(at_rel) = input[scheme_end..authority_end].find('@') {
            out.push_str("<redacted>@");
            cursor = scheme_end + at_rel + 1;
        } else {
            cursor = scheme_end;
        }
    }
    out.push_str(&input[cursor..]);
    out
}

fn redact_secret_values(input: String) -> String {
    let mut redacted = input;
    for key in [
        "password", "passwd", "pwd", "token", "secret", "apikey", "api_key", "key",
    ] {
        redacted = redact_key_value(&redacted, key);
    }
    redacted
}

fn redact_key_value(input: &str, key: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0;
    while let Some(rel) = lower[cursor..].find(key) {
        let key_start = cursor + rel;
        let key_end = key_start + key.len();
        let prev_is_word = key_start > 0
            && (lower.as_bytes()[key_start - 1].is_ascii_alphanumeric()
                || lower.as_bytes()[key_start - 1] == b'_');
        let mut sep = key_end;
        while sep < input.len() && input.as_bytes()[sep].is_ascii_whitespace() {
            sep += 1;
        }
        let has_sep = sep < input.len() && matches!(input.as_bytes()[sep], b'=' | b':');
        if prev_is_word || !has_sep {
            out.push_str(&input[cursor..key_end]);
            cursor = key_end;
            continue;
        }
        let value_start = sep + 1;
        let value_end = input[value_start..]
            .find(['&', ';', ',', ' '])
            .map_or(input.len(), |idx| value_start + idx);
        out.push_str(&input[cursor..value_start]);
        out.push_str("<redacted>");
        cursor = value_end;
    }
    out.push_str(&input[cursor..]);
    out
}

fn mismatch(
    stage: &'static str,
    ids: &EventingIds,
    expected: impl Into<String>,
    actual: impl Into<String>,
) -> EventingConformanceError {
    EventingConformanceError::Mismatch(Box::new(MismatchFailure {
        stage,
        event_id: ids.event_id.clone(),
        inbox_key: ids.inbox_key.clone(),
        consumer_group: ids.consumer_group.clone(),
        lease_token_alias: ids.lease_token.clone(),
        expected: expected.into(),
        actual: actual.into(),
    }))
}

fn dlx_mismatch(
    stage: &'static str,
    ids: &EventingIds,
    dlx: &DlxFields,
    expected: impl Into<String>,
    actual: impl Into<String>,
) -> EventingConformanceError {
    EventingConformanceError::DlxMismatch(Box::new(DlxFailure {
        stage,
        event_id: ids.event_id.clone(),
        source_kind: dlx.source_kind.clone(),
        domain: dlx.domain.clone(),
        contract_id: dlx.contract_id.clone(),
        topic: dlx.topic.clone(),
        num_attempts: dlx.num_attempts,
        expected: expected.into(),
        actual: actual.into(),
    }))
}

fn expect_eq<T>(
    stage: &'static str,
    ids: &EventingIds,
    actual: T,
    expected: T,
) -> Result<(), EventingConformanceError>
where
    T: std::fmt::Debug + PartialEq,
{
    if actual == expected {
        Ok(())
    } else {
        Err(mismatch(
            stage,
            ids,
            format!("{expected:?}"),
            format!("{actual:?}"),
        ))
    }
}

fn expect(
    stage: &'static str,
    ids: &EventingIds,
    ok: bool,
    expected: &str,
    actual: impl Into<String>,
) -> Result<(), EventingConformanceError> {
    if ok {
        Ok(())
    } else {
        Err(mismatch(stage, ids, expected, actual))
    }
}

/// Stable ids used in conformance failure messages.
#[derive(Clone)]
pub struct EventingIds {
    pub event_id: String,
    pub inbox_key: String,
    pub consumer_group: String,
    /// Test lease alias; callers may map this to a provider-specific secret token.
    pub lease_token: String,
}

impl std::fmt::Debug for EventingIds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventingIds")
            .field("event_id", &self.event_id)
            .field("inbox_key", &self.inbox_key)
            .field("consumer_group", &self.consumer_group)
            .field("lease_token", &"<redacted>")
            .finish()
    }
}

impl EventingIds {
    pub fn new(
        event_id: impl Into<String>,
        inbox_key: impl Into<String>,
        consumer_group: impl Into<String>,
        lease_token: impl Into<String>,
    ) -> Self {
        Self {
            event_id: event_id.into(),
            inbox_key: inbox_key.into(),
            consumer_group: consumer_group.into(),
            lease_token: lease_token.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct OutboxSeedArgs {
    pub event_id: String,
    pub domain: String,
}

#[derive(Debug, Clone)]
pub struct OutboxRelayArgs {
    pub event_id: String,
    pub mode: PublishMode,
}

#[derive(Debug, Clone)]
pub struct DomainArgs {
    pub domain: String,
}

#[derive(Debug, Clone)]
pub struct EventIdArgs {
    pub event_id: String,
}

#[derive(Debug, Clone)]
pub struct OutboxTerminalArgs {
    pub event_id: String,
    pub domain: String,
    pub status: TerminalStatus,
}

#[derive(Clone)]
pub struct InboxLeaseArgs {
    pub inbox_key: String,
    pub consumer_group: String,
    /// Test-only lease alias. Do not put provider secret tokens here.
    pub lease_alias: String,
}

impl std::fmt::Debug for InboxLeaseArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboxLeaseArgs")
            .field("inbox_key", &self.inbox_key)
            .field("consumer_group", &self.consumer_group)
            .field("lease_alias", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct InboxKeyArgs {
    pub inbox_key: String,
    pub consumer_group: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishMode {
    Ok,
    Transient,
    Permanent,
    Ambiguous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RelayDisposition {
    Ack,
    Requeue,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayObservation {
    pub disposition: RelayDisposition,
    /// Broker-visible message id. This should equal the outbox event id.
    pub message_id: Option<String>,
    pub publish_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxState {
    pub exists: bool,
    pub status: OutboxStatus,
    pub retry_count: i64,
    pub retry_after_set: bool,
    pub dlx_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OutboxStatus {
    Absent,
    Pending,
    Publishing,
    Published,
    Dlx,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BacklogSample {
    pub depth: u64,
    pub oldest_age_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TerminalStatus {
    PublishedOld,
    DlxOld,
}

pub struct OutboxRelayCase<'a> {
    pub ids: EventingIds,
    pub domain: String,
    pub other_domain: String,
    pub max_attempts: u32,
    pub seed_pending: OutboxSeedFn<'a>,
    pub relay: OutboxRelayFn<'a>,
    pub claim_batch: OutboxClaimFn<'a>,
    pub state: OutboxStateFn<'a>,
    pub backdate_publishing: OutboxBackdateFn<'a>,
    pub sample_backlog: OutboxSampleFn<'a>,
    pub sweep: OutboxSweepFn<'a>,
    pub seed_terminal: OutboxTerminalFn<'a>,
}

/// Assert provider outbox relay, retry/DLX, stale reclaim, sampler, and sweeper semantics.
pub async fn assert_outbox_relay_conformance(
    mut case: OutboxRelayCase<'_>,
) -> Result<(), EventingConformanceError> {
    if case.max_attempts < 2 {
        return Err(mismatch(
            "outbox.config.max-attempts",
            &case.ids,
            "max_attempts >= 2",
            format!("max_attempts={}", case.max_attempts),
        ));
    }
    let retry_id = format!("{}-retry", case.ids.event_id);
    let ambiguous_id = format!("{}-ambiguous", case.ids.event_id);
    let permanent_id = format!("{}-permanent", case.ids.event_id);
    let stale_id = format!("{}-stale", case.ids.event_id);
    let other_id = format!("{}-other", case.ids.event_id);
    let old_published_id = format!("{}-old-published", case.ids.event_id);
    let old_dlx_id = format!("{}-old-dlx", case.ids.event_id);

    assert_outbox_claim_and_ack(&mut case, other_id).await?;
    assert_outbox_transient_retry(&mut case, retry_id).await?;
    assert_outbox_ambiguous_retry(&mut case, ambiguous_id).await?;
    assert_outbox_permanent_dlx(&mut case, permanent_id).await?;
    assert_outbox_stale_and_sample(&mut case, stale_id).await?;
    assert_outbox_sweeper(&mut case, old_published_id, old_dlx_id).await
}

async fn assert_outbox_claim_and_ack(
    case: &mut OutboxRelayCase<'_>,
    other_id: String,
) -> Result<(), EventingConformanceError> {
    (case.seed_pending)(OutboxSeedArgs {
        event_id: case.ids.event_id.clone(),
        domain: case.domain.clone(),
    })
    .await
    .map_err(|e| provider("outbox.seed.pending", e))?;
    (case.seed_pending)(OutboxSeedArgs {
        event_id: other_id.clone(),
        domain: case.other_domain.clone(),
    })
    .await
    .map_err(|e| provider("outbox.seed.other-domain", e))?;

    let claimed = (case.claim_batch)(DomainArgs {
        domain: case.domain.clone(),
    })
    .await
    .map_err(|e| provider("outbox.claim", e))?;
    expect(
        "outbox.claim.domain",
        &case.ids,
        claimed.contains(&case.ids.event_id) && !claimed.contains(&other_id),
        "target event present and other-domain event absent",
        format!("{claimed:?}"),
    )?;

    let ok = (case.relay)(OutboxRelayArgs {
        event_id: case.ids.event_id.clone(),
        mode: PublishMode::Ok,
    })
    .await
    .map_err(|e| provider("outbox.relay.ok", e))?;
    expect_eq(
        "outbox.relay.ok.disposition",
        &case.ids,
        ok.disposition,
        RelayDisposition::Ack,
    )?;
    expect_eq(
        "outbox.relay.ok.message_id",
        &case.ids,
        ok.message_id.as_deref(),
        Some(case.ids.event_id.as_str()),
    )?;
    expect_eq(
        "outbox.relay.ok.publish-count",
        &case.ids,
        ok.publish_count,
        1,
    )?;
    let state = (case.state)(EventIdArgs {
        event_id: case.ids.event_id.clone(),
    })
    .await
    .map_err(|e| provider("outbox.state.published", e))?;
    expect_eq(
        "outbox.writeback.published",
        &case.ids,
        state.status,
        OutboxStatus::Published,
    )
}

async fn assert_outbox_transient_retry(
    case: &mut OutboxRelayCase<'_>,
    retry_id: String,
) -> Result<(), EventingConformanceError> {
    (case.seed_pending)(OutboxSeedArgs {
        event_id: retry_id.clone(),
        domain: case.domain.clone(),
    })
    .await
    .map_err(|e| provider("outbox.seed.retry", e))?;
    for attempt in 1..=case.max_attempts {
        let ids = EventingIds::new(
            retry_id.clone(),
            retry_id.clone(),
            case.ids.consumer_group.clone(),
            case.ids.lease_token.clone(),
        );
        let obs = (case.relay)(OutboxRelayArgs {
            event_id: retry_id.clone(),
            mode: PublishMode::Transient,
        })
        .await
        .map_err(|e| provider("outbox.relay.transient", e))?;
        let expected_disposition = if attempt == case.max_attempts {
            RelayDisposition::Reject
        } else {
            RelayDisposition::Requeue
        };
        expect_eq(
            "outbox.relay.transient.disposition",
            &ids,
            obs.disposition,
            expected_disposition,
        )?;
        expect_eq(
            "outbox.relay.transient.message_id",
            &ids,
            obs.message_id.as_deref(),
            Some(retry_id.as_str()),
        )?;
        expect_eq(
            "outbox.relay.transient.publish-count",
            &ids,
            obs.publish_count,
            1,
        )?;
        let state = (case.state)(EventIdArgs {
            event_id: retry_id.clone(),
        })
        .await
        .map_err(|e| provider("outbox.state.retry", e))?;
        assert_outbox_retry_state(&ids, &state, attempt, expected_disposition)?;
    }
    Ok(())
}

async fn assert_outbox_ambiguous_retry(
    case: &mut OutboxRelayCase<'_>,
    retry_id: String,
) -> Result<(), EventingConformanceError> {
    (case.seed_pending)(OutboxSeedArgs {
        event_id: retry_id.clone(),
        domain: case.domain.clone(),
    })
    .await
    .map_err(|e| provider("outbox.seed.ambiguous", e))?;
    for attempt in 1..=case.max_attempts {
        let ids = EventingIds::new(
            retry_id.clone(),
            retry_id.clone(),
            case.ids.consumer_group.clone(),
            case.ids.lease_token.clone(),
        );
        let obs = (case.relay)(OutboxRelayArgs {
            event_id: retry_id.clone(),
            mode: PublishMode::Ambiguous,
        })
        .await
        .map_err(|e| provider("outbox.relay.ambiguous", e))?;
        let expected_disposition = if attempt == case.max_attempts {
            RelayDisposition::Reject
        } else {
            RelayDisposition::Requeue
        };
        expect_eq(
            "outbox.relay.ambiguous.disposition",
            &ids,
            obs.disposition,
            expected_disposition,
        )?;
        expect_eq(
            "outbox.relay.ambiguous.message-id",
            &ids,
            obs.message_id.as_deref(),
            Some(retry_id.as_str()),
        )?;
        expect_eq(
            "outbox.relay.ambiguous.publish-count",
            &ids,
            obs.publish_count,
            1,
        )?;
        let state = (case.state)(EventIdArgs {
            event_id: retry_id.clone(),
        })
        .await
        .map_err(|e| provider("outbox.state.ambiguous", e))?;
        assert_outbox_retry_state(&ids, &state, attempt, expected_disposition)?;
    }
    Ok(())
}

fn assert_outbox_retry_state(
    ids: &EventingIds,
    state: &OutboxState,
    attempt: u32,
    expected_disposition: RelayDisposition,
) -> Result<(), EventingConformanceError> {
    expect_eq(
        "outbox.retry.count",
        ids,
        state.retry_count,
        i64::from(attempt),
    )?;
    if expected_disposition == RelayDisposition::Requeue {
        expect_eq(
            "outbox.retry.status",
            ids,
            state.status,
            OutboxStatus::Pending,
        )?;
        expect(
            "outbox.retry.retry_after",
            ids,
            state.retry_after_set,
            "retry_after set",
            format!("retry_after_set={}", state.retry_after_set),
        )
    } else {
        expect_eq(
            "outbox.retry.dlx.status",
            ids,
            state.status,
            OutboxStatus::Dlx,
        )?;
        expect(
            "outbox.retry.dlx.row",
            ids,
            state.dlx_count >= 1,
            "dlx_count >= 1",
            format!("dlx_count={}", state.dlx_count),
        )
    }
}

async fn assert_outbox_permanent_dlx(
    case: &mut OutboxRelayCase<'_>,
    permanent_id: String,
) -> Result<(), EventingConformanceError> {
    (case.seed_pending)(OutboxSeedArgs {
        event_id: permanent_id.clone(),
        domain: case.domain.clone(),
    })
    .await
    .map_err(|e| provider("outbox.seed.permanent", e))?;
    let ids = EventingIds::new(
        permanent_id.clone(),
        permanent_id.clone(),
        case.ids.consumer_group.clone(),
        case.ids.lease_token.clone(),
    );
    let obs = (case.relay)(OutboxRelayArgs {
        event_id: permanent_id.clone(),
        mode: PublishMode::Permanent,
    })
    .await
    .map_err(|e| provider("outbox.relay.permanent", e))?;
    expect_eq(
        "outbox.relay.permanent.disposition",
        &ids,
        obs.disposition,
        RelayDisposition::Reject,
    )?;
    expect_eq(
        "outbox.relay.permanent.publish-count",
        &ids,
        obs.publish_count,
        1,
    )?;
    let state = (case.state)(EventIdArgs {
        event_id: permanent_id,
    })
    .await
    .map_err(|e| provider("outbox.state.permanent", e))?;
    expect_eq(
        "outbox.permanent.status",
        &ids,
        state.status,
        OutboxStatus::Dlx,
    )?;
    expect_eq("outbox.permanent.retry_count", &ids, state.retry_count, 1)
}

async fn assert_outbox_stale_and_sample(
    case: &mut OutboxRelayCase<'_>,
    stale_id: String,
) -> Result<(), EventingConformanceError> {
    (case.seed_pending)(OutboxSeedArgs {
        event_id: stale_id.clone(),
        domain: case.domain.clone(),
    })
    .await
    .map_err(|e| provider("outbox.seed.stale", e))?;
    (case.backdate_publishing)(EventIdArgs {
        event_id: stale_id.clone(),
    })
    .await
    .map_err(|e| provider("outbox.backdate.stale", e))?;
    let sample = (case.sample_backlog)(DomainArgs {
        domain: case.domain.clone(),
    })
    .await
    .map_err(|e| provider("outbox.sample", e))?;
    expect(
        "outbox.sample.depth",
        &case.ids,
        sample.depth >= 1,
        "depth >= 1",
        format!("depth={}", sample.depth),
    )?;
    expect(
        "outbox.sample.oldest-age",
        &case.ids,
        sample.oldest_age_seconds >= 1,
        "oldest_age_seconds >= 1",
        format!("oldest_age_seconds={}", sample.oldest_age_seconds),
    )?;

    let claimed = (case.claim_batch)(DomainArgs {
        domain: case.domain.clone(),
    })
    .await
    .map_err(|e| provider("outbox.claim.stale", e))?;
    expect(
        "outbox.stale.reclaim",
        &case.ids,
        claimed.contains(&stale_id),
        "stale publishing event present",
        format!("{claimed:?}"),
    )
}

async fn assert_outbox_sweeper(
    case: &mut OutboxRelayCase<'_>,
    old_published_id: String,
    old_dlx_id: String,
) -> Result<(), EventingConformanceError> {
    (case.seed_terminal)(OutboxTerminalArgs {
        event_id: old_published_id.clone(),
        domain: case.domain.clone(),
        status: TerminalStatus::PublishedOld,
    })
    .await
    .map_err(|e| provider("outbox.seed.old-published", e))?;
    (case.seed_terminal)(OutboxTerminalArgs {
        event_id: old_dlx_id.clone(),
        domain: case.domain.clone(),
        status: TerminalStatus::DlxOld,
    })
    .await
    .map_err(|e| provider("outbox.seed.old-dlx", e))?;
    let _ = (case.sweep)(3600)
        .await
        .map_err(|e| provider("outbox.sweep", e))?;
    let published = (case.state)(EventIdArgs {
        event_id: old_published_id,
    })
    .await
    .map_err(|e| provider("outbox.state.old-published", e))?;
    let dlx = (case.state)(EventIdArgs {
        event_id: old_dlx_id,
    })
    .await
    .map_err(|e| provider("outbox.state.old-dlx", e))?;
    expect(
        "outbox.sweep.old-published",
        &case.ids,
        !published.exists,
        "old published row removed",
        format!("{published:?}"),
    )?;
    expect(
        "outbox.sweep.keeps-dlx",
        &case.ids,
        dlx.exists && dlx.status == OutboxStatus::Dlx,
        "old dlx row retained",
        format!("{dlx:?}"),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InboxSeen {
    Fresh,
    InProgress,
    Duplicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeaseOutcome {
    Held,
    Lost,
}

pub struct InboxConformanceCase<'a> {
    pub ids: EventingIds,
    pub second_group: String,
    pub try_claim: InboxClaimFn<'a>,
    pub extend: InboxLeaseFn<'a>,
    pub commit: InboxLeaseFn<'a>,
    pub release: InboxReleaseFn<'a>,
    pub backdate_claim: InboxBackdateFn<'a>,
}

/// Assert provider inbox duplicate and lease-CAS semantics.
pub async fn assert_inbox_conformance(
    mut case: InboxConformanceCase<'_>,
) -> Result<(), EventingConformanceError> {
    let release_key = format!("{}-release", case.ids.inbox_key);
    let stale_key = format!("{}-stale", case.ids.inbox_key);
    let lease_a = case.ids.lease_token.clone();
    let lease_b = format!("{lease_a}-b");

    let first = (case.try_claim)(InboxLeaseArgs {
        inbox_key: case.ids.inbox_key.clone(),
        consumer_group: case.ids.consumer_group.clone(),
        lease_alias: lease_a.clone(),
    })
    .await
    .map_err(|e| provider("inbox.try_claim.first", e))?;
    expect_eq("inbox.first.fresh", &case.ids, first, InboxSeen::Fresh)?;

    let in_progress = (case.try_claim)(InboxLeaseArgs {
        inbox_key: case.ids.inbox_key.clone(),
        consumer_group: case.ids.consumer_group.clone(),
        lease_alias: lease_b.clone(),
    })
    .await
    .map_err(|e| provider("inbox.try_claim.in-progress", e))?;
    expect_eq(
        "inbox.in-progress",
        &case.ids,
        in_progress,
        InboxSeen::InProgress,
    )?;

    let other_group = (case.try_claim)(InboxLeaseArgs {
        inbox_key: case.ids.inbox_key.clone(),
        consumer_group: case.second_group.clone(),
        lease_alias: lease_b.clone(),
    })
    .await
    .map_err(|e| provider("inbox.try_claim.group", e))?;
    expect_eq(
        "inbox.group-isolation",
        &case.ids,
        other_group,
        InboxSeen::Fresh,
    )?;

    let extended = (case.extend)(InboxLeaseArgs {
        inbox_key: case.ids.inbox_key.clone(),
        consumer_group: case.ids.consumer_group.clone(),
        lease_alias: lease_a.clone(),
    })
    .await
    .map_err(|e| provider("inbox.extend.held", e))?;
    expect_eq("inbox.extend.held", &case.ids, extended, LeaseOutcome::Held)?;

    let committed = (case.commit)(InboxLeaseArgs {
        inbox_key: case.ids.inbox_key.clone(),
        consumer_group: case.ids.consumer_group.clone(),
        lease_alias: lease_a.clone(),
    })
    .await
    .map_err(|e| provider("inbox.commit.held", e))?;
    expect_eq(
        "inbox.commit.held",
        &case.ids,
        committed,
        LeaseOutcome::Held,
    )?;

    let after_done = (case.try_claim)(InboxLeaseArgs {
        inbox_key: case.ids.inbox_key.clone(),
        consumer_group: case.ids.consumer_group.clone(),
        lease_alias: lease_b.clone(),
    })
    .await
    .map_err(|e| provider("inbox.try_claim.done", e))?;
    expect_eq(
        "inbox.done.duplicate",
        &case.ids,
        after_done,
        InboxSeen::Duplicate,
    )?;

    let release_first = (case.try_claim)(InboxLeaseArgs {
        inbox_key: release_key.clone(),
        consumer_group: case.ids.consumer_group.clone(),
        lease_alias: lease_a.clone(),
    })
    .await
    .map_err(|e| provider("inbox.release.claim", e))?;
    expect_eq(
        "inbox.release.claim",
        &case.ids,
        release_first,
        InboxSeen::Fresh,
    )?;
    (case.release)(InboxLeaseArgs {
        inbox_key: release_key.clone(),
        consumer_group: case.ids.consumer_group.clone(),
        lease_alias: lease_a.clone(),
    })
    .await
    .map_err(|e| provider("inbox.release", e))?;
    let reclaimed = (case.try_claim)(InboxLeaseArgs {
        inbox_key: release_key.clone(),
        consumer_group: case.ids.consumer_group.clone(),
        lease_alias: lease_b.clone(),
    })
    .await
    .map_err(|e| provider("inbox.release.reclaim", e))?;
    expect_eq(
        "inbox.release.reclaim",
        &case.ids,
        reclaimed,
        InboxSeen::Fresh,
    )?;

    let stale_first = (case.try_claim)(InboxLeaseArgs {
        inbox_key: stale_key.clone(),
        consumer_group: case.ids.consumer_group.clone(),
        lease_alias: lease_a.clone(),
    })
    .await
    .map_err(|e| provider("inbox.stale.claim", e))?;
    expect_eq(
        "inbox.stale.claim",
        &case.ids,
        stale_first,
        InboxSeen::Fresh,
    )?;
    (case.backdate_claim)(InboxKeyArgs {
        inbox_key: stale_key.clone(),
        consumer_group: case.ids.consumer_group.clone(),
    })
    .await
    .map_err(|e| provider("inbox.stale.backdate", e))?;
    let stale_reclaim = (case.try_claim)(InboxLeaseArgs {
        inbox_key: stale_key.clone(),
        consumer_group: case.ids.consumer_group.clone(),
        lease_alias: lease_b.clone(),
    })
    .await
    .map_err(|e| provider("inbox.stale.reclaim", e))?;
    expect_eq(
        "inbox.stale.reclaim",
        &case.ids,
        stale_reclaim,
        InboxSeen::Fresh,
    )?;
    let stale_old_commit = (case.commit)(InboxLeaseArgs {
        inbox_key: stale_key.clone(),
        consumer_group: case.ids.consumer_group.clone(),
        lease_alias: lease_a.clone(),
    })
    .await
    .map_err(|e| provider("inbox.stale.old-commit", e))?;
    expect_eq(
        "inbox.stale.old-commit-lost",
        &case.ids,
        stale_old_commit,
        LeaseOutcome::Lost,
    )?;
    let stale_new_commit = (case.commit)(InboxLeaseArgs {
        inbox_key: stale_key,
        consumer_group: case.ids.consumer_group.clone(),
        lease_alias: lease_b,
    })
    .await
    .map_err(|e| provider("inbox.stale.new-commit", e))?;
    expect_eq(
        "inbox.stale.new-commit-held",
        &case.ids,
        stale_new_commit,
        LeaseOutcome::Held,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SettleAction {
    Ack,
    Requeue,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlxFields {
    pub source_kind: String,
    pub domain: String,
    pub contract_id: String,
    pub topic: String,
    pub num_attempts: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumerObservation {
    pub handler_calls: u32,
    pub claim_attempts: u32,
    pub committed: bool,
    pub released: bool,
    pub dlx_count: u64,
    pub settle: SettleAction,
    pub num_attempts: u32,
    pub source_kind: String,
    pub domain: String,
    pub contract_id: String,
    pub topic: String,
}

/// Provider-neutral evidence for consuming both deliveries of a same-id duplicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumerDuplicateEffectObservation {
    /// Number of committed business mutations caused by both deliveries.
    pub business_mutations: u64,
    /// Number of done inbox receipts left for the stable event and consumer group.
    pub inbox_done_rows: u64,
    /// Broker settlement applied to the duplicate delivery.
    pub duplicate_settle: SettleAction,
}

/// Unforgeable evidence that duplicate delivery preserved exactly one database effect.
#[derive(Debug)]
pub struct ConsumerDuplicateEffectConformancePassed {
    _private: (),
}

/// Assert a duplicate is acknowledged without repeating its transactional database effect.
pub fn assert_consumer_duplicate_effect_conformance(
    ids: &EventingIds,
    observation: &ConsumerDuplicateEffectObservation,
) -> Result<ConsumerDuplicateEffectConformancePassed, EventingConformanceError> {
    expect_eq(
        "consumer.duplicate-effect.business-mutations",
        ids,
        observation.business_mutations,
        1,
    )?;
    expect_eq(
        "consumer.duplicate-effect.inbox-done",
        ids,
        observation.inbox_done_rows,
        1,
    )?;
    expect_eq(
        "consumer.duplicate-effect.ack",
        ids,
        observation.duplicate_settle,
        SettleAction::Ack,
    )?;
    Ok(ConsumerDuplicateEffectConformancePassed { _private: () })
}

pub struct ConsumerConformanceCase<'a> {
    pub ids: EventingIds,
    pub expected_dlx: DlxFields,
    pub duplicate_delivery: ConsumerScenarioFn<'a>,
    pub poison_delivery: ConsumerScenarioFn<'a>,
    pub dlx_failure: ConsumerScenarioFn<'a>,
    pub malformed_message_id: ConsumerScenarioFn<'a>,
}

/// Assert consumer duplicate, poison-DLX, DLX failure, and malformed-id behavior.
pub async fn assert_consumer_conformance(
    mut case: ConsumerConformanceCase<'_>,
) -> Result<(), EventingConformanceError> {
    let duplicate = (case.duplicate_delivery)()
        .await
        .map_err(|e| provider("consumer.duplicate", e))?;
    expect_eq(
        "consumer.duplicate.handler-calls",
        &case.ids,
        duplicate.handler_calls,
        0,
    )?;
    expect_eq(
        "consumer.duplicate.settle",
        &case.ids,
        duplicate.settle,
        SettleAction::Ack,
    )?;
    expect(
        "consumer.duplicate.no-commit",
        &case.ids,
        !duplicate.committed,
        "not committed",
        format!("committed={}", duplicate.committed),
    )?;

    let poison = (case.poison_delivery)()
        .await
        .map_err(|e| provider("consumer.poison", e))?;
    assert_dlx_fields(
        "consumer.poison.dlx-fields",
        &case.ids,
        &case.expected_dlx,
        &poison,
    )?;
    expect(
        "consumer.poison.dlx-written",
        &case.ids,
        poison.dlx_count >= 1,
        "dlx_count >= 1",
        format!("dlx_count={}", poison.dlx_count),
    )?;
    expect_eq(
        "consumer.poison.handler-calls",
        &case.ids,
        poison.handler_calls,
        case.expected_dlx.num_attempts,
    )?;
    expect_eq(
        "consumer.poison.settle",
        &case.ids,
        poison.settle,
        SettleAction::Ack,
    )?;
    expect(
        "consumer.poison.commit",
        &case.ids,
        poison.committed,
        "committed",
        format!("committed={}", poison.committed),
    )?;

    let failed = (case.dlx_failure)()
        .await
        .map_err(|e| provider("consumer.dlx-failure", e))?;
    assert_dlx_fields(
        "consumer.dlx-failure.dlx-fields",
        &case.ids,
        &case.expected_dlx,
        &failed,
    )?;
    expect_eq(
        "consumer.dlx-failure.settle",
        &case.ids,
        failed.settle,
        SettleAction::Requeue,
    )?;
    expect_eq(
        "consumer.dlx-failure.handler-calls",
        &case.ids,
        failed.handler_calls,
        case.expected_dlx.num_attempts,
    )?;
    expect(
        "consumer.dlx-failure.release",
        &case.ids,
        failed.released,
        "released",
        format!("released={}", failed.released),
    )?;

    let malformed = (case.malformed_message_id)()
        .await
        .map_err(|e| provider("consumer.malformed", e))?;
    expect_eq(
        "consumer.malformed.settle",
        &case.ids,
        malformed.settle,
        SettleAction::Reject,
    )?;
    expect_eq(
        "consumer.malformed.no-claim",
        &case.ids,
        malformed.claim_attempts,
        0,
    )?;
    expect_eq(
        "consumer.malformed.handler-calls",
        &case.ids,
        malformed.handler_calls,
        0,
    )
}

fn assert_dlx_fields(
    stage: &'static str,
    ids: &EventingIds,
    expected: &DlxFields,
    actual: &ConsumerObservation,
) -> Result<(), EventingConformanceError> {
    let actual_fields = DlxFields {
        source_kind: actual.source_kind.clone(),
        domain: actual.domain.clone(),
        contract_id: actual.contract_id.clone(),
        topic: actual.topic.clone(),
        num_attempts: actual.num_attempts,
    };
    if &actual_fields == expected {
        Ok(())
    } else {
        Err(dlx_mismatch(
            stage,
            ids,
            &actual_fields,
            format!("{expected:?}"),
            format!("{actual_fields:?}"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use super::{
        BacklogSample, ConsumerConformanceCase, ConsumerDuplicateEffectObservation,
        ConsumerObservation, DlxFields, DomainArgs, EventIdArgs, EventingConformanceError,
        EventingIds, InboxLeaseArgs, MismatchFailure, OutboxRelayArgs, OutboxRelayCase,
        OutboxSeedArgs, OutboxState, OutboxStatus, OutboxTerminalArgs, PublishMode,
        RelayDisposition, RelayObservation, SettleAction, TerminalStatus,
        assert_consumer_conformance, assert_consumer_duplicate_effect_conformance,
        assert_outbox_relay_conformance,
    };

    fn ids() -> EventingIds {
        EventingIds::new("evt-1", "evt-1", "group-a", "lease-a")
    }

    fn ok_observation(settle: SettleAction) -> ConsumerObservation {
        ConsumerObservation {
            handler_calls: 3,
            claim_attempts: 1,
            committed: settle == SettleAction::Ack,
            released: false,
            dlx_count: 1,
            settle,
            num_attempts: 3,
            source_kind: "consumer".to_string(),
            domain: "test".to_string(),
            contract_id: "contract".to_string(),
            topic: "test.event".to_string(),
        }
    }

    fn expected_dlx() -> DlxFields {
        DlxFields {
            source_kind: "consumer".to_string(),
            domain: "test".to_string(),
            contract_id: "contract".to_string(),
            topic: "test.event".to_string(),
            num_attempts: 3,
        }
    }

    fn outbox_ids() -> EventingIds {
        EventingIds::new("evt-outbox", "evt-outbox", "group-a", "lease-a")
    }

    fn outbox_state(status: OutboxStatus, retry_count: i64, dlx_count: u64) -> OutboxState {
        OutboxState {
            exists: true,
            status,
            retry_count,
            retry_after_set: status == OutboxStatus::Pending,
            dlx_count,
        }
    }

    fn stateful_outbox_case(
        publish_count: u64,
        ambiguous_immediate_dlx: bool,
    ) -> OutboxRelayCase<'static> {
        let attempts = Arc::new(Mutex::new(HashMap::<String, u32>::new()));
        let relay_attempts = Arc::clone(&attempts);
        let state_attempts = Arc::clone(&attempts);
        OutboxRelayCase {
            ids: outbox_ids(),
            domain: "domain-a".to_string(),
            other_domain: "domain-b".to_string(),
            max_attempts: 2,
            seed_pending: Box::new(|OutboxSeedArgs { .. }| Box::pin(async { Ok(()) })),
            relay: Box::new(move |OutboxRelayArgs { event_id, mode }| {
                let attempt = {
                    let mut attempts = relay_attempts
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let attempt = attempts.entry(event_id.clone()).or_default();
                    *attempt += 1;
                    *attempt
                };
                Box::pin(async move {
                    let disposition = match mode {
                        PublishMode::Ok => RelayDisposition::Ack,
                        PublishMode::Permanent => RelayDisposition::Reject,
                        PublishMode::Transient => {
                            if attempt < 2 {
                                RelayDisposition::Requeue
                            } else {
                                RelayDisposition::Reject
                            }
                        }
                        PublishMode::Ambiguous if ambiguous_immediate_dlx => {
                            RelayDisposition::Reject
                        }
                        PublishMode::Ambiguous => {
                            if attempt < 2 {
                                RelayDisposition::Requeue
                            } else {
                                RelayDisposition::Reject
                            }
                        }
                    };
                    Ok(RelayObservation {
                        disposition,
                        message_id: Some(event_id),
                        publish_count,
                    })
                })
            }),
            claim_batch: Box::new(|DomainArgs { .. }| {
                Box::pin(async {
                    Ok(vec![
                        "evt-outbox".to_string(),
                        "evt-outbox-stale".to_string(),
                    ])
                })
            }),
            state: Box::new(move |EventIdArgs { event_id }| {
                let attempt = state_attempts
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(&event_id)
                    .copied()
                    .unwrap_or_default();
                Box::pin(async move {
                    if event_id.ends_with("-old-published") {
                        return Ok(OutboxState {
                            exists: false,
                            status: OutboxStatus::Absent,
                            retry_count: 0,
                            retry_after_set: false,
                            dlx_count: 0,
                        });
                    }
                    if event_id.ends_with("-old-dlx") {
                        return Ok(outbox_state(OutboxStatus::Dlx, 0, 1));
                    }
                    if event_id.ends_with("-permanent") {
                        return Ok(outbox_state(OutboxStatus::Dlx, 1, 1));
                    }
                    if event_id.ends_with("-retry") || event_id.ends_with("-ambiguous") {
                        let terminal = attempt >= 2
                            || (ambiguous_immediate_dlx && event_id.ends_with("-ambiguous"));
                        return Ok(if terminal {
                            outbox_state(OutboxStatus::Dlx, i64::from(attempt), 1)
                        } else {
                            outbox_state(OutboxStatus::Pending, i64::from(attempt), 0)
                        });
                    }
                    Ok(outbox_state(OutboxStatus::Published, 0, 0))
                })
            }),
            backdate_publishing: Box::new(|EventIdArgs { .. }| Box::pin(async { Ok(()) })),
            sample_backlog: Box::new(|DomainArgs { .. }| {
                Box::pin(async {
                    Ok(BacklogSample {
                        depth: 1,
                        oldest_age_seconds: 1,
                    })
                })
            }),
            sweep: Box::new(|_| Box::pin(async { Ok(1) })),
            seed_terminal: Box::new(|OutboxTerminalArgs { status, .. }| {
                Box::pin(async move {
                    match status {
                        TerminalStatus::PublishedOld | TerminalStatus::DlxOld => Ok(()),
                    }
                })
            }),
        }
    }

    #[tokio::test]
    async fn outbox_conformance_catches_missing_publish() {
        let result = assert_outbox_relay_conformance(stateful_outbox_case(0, false)).await;
        assert!(
            matches!(
                result,
                Err(EventingConformanceError::Mismatch(ref detail))
                    if detail.stage == "outbox.relay.ok.publish-count"
            ),
            "broken relay fake must fail, got {result:?}"
        );
    }

    #[tokio::test]
    async fn outbox_conformance_covers_ambiguous_pending_same_id_until_budget_dlx()
    -> Result<(), EventingConformanceError> {
        assert_outbox_relay_conformance(stateful_outbox_case(1, false)).await
    }

    #[tokio::test]
    async fn outbox_conformance_rejects_ambiguous_immediate_dlx() {
        let result = assert_outbox_relay_conformance(stateful_outbox_case(1, true)).await;
        assert!(
            matches!(
                result,
                Err(EventingConformanceError::Mismatch(ref detail))
                    if detail.stage == "outbox.relay.ambiguous.disposition"
            ),
            "Ambiguous treated as Permanent must fail, got {result:?}"
        );
    }

    fn consumer_duplicate_effect_observation() -> ConsumerDuplicateEffectObservation {
        ConsumerDuplicateEffectObservation {
            business_mutations: 1,
            inbox_done_rows: 1,
            duplicate_settle: SettleAction::Ack,
        }
    }

    #[test]
    fn consumer_duplicate_effect_conformance_accepts_single_effect()
    -> Result<(), EventingConformanceError> {
        assert_consumer_duplicate_effect_conformance(
            &ids(),
            &consumer_duplicate_effect_observation(),
        )?;
        Ok(())
    }

    #[test]
    fn consumer_duplicate_effect_conformance_catches_duplicate_business_mutation() {
        let mut observation = consumer_duplicate_effect_observation();
        observation.business_mutations = 2;

        let result = assert_consumer_duplicate_effect_conformance(&ids(), &observation);

        assert!(
            matches!(
                result,
                Err(EventingConformanceError::Mismatch(ref detail))
                    if detail.stage == "consumer.duplicate-effect.business-mutations"
            ),
            "duplicate business mutation must fail, got {result:?}"
        );
    }

    #[test]
    fn consumer_duplicate_effect_conformance_catches_wrong_inbox_done_count() {
        for inbox_done_rows in [0, 2] {
            let mut observation = consumer_duplicate_effect_observation();
            observation.inbox_done_rows = inbox_done_rows;

            let result = assert_consumer_duplicate_effect_conformance(&ids(), &observation);

            assert!(
                matches!(
                    result,
                    Err(EventingConformanceError::Mismatch(ref detail))
                        if detail.stage == "consumer.duplicate-effect.inbox-done"
                ),
                "inbox_done_rows={inbox_done_rows} must fail, got {result:?}"
            );
        }
    }

    #[test]
    fn consumer_duplicate_effect_conformance_catches_unacked_duplicate() {
        for duplicate_settle in [SettleAction::Requeue, SettleAction::Reject] {
            let mut observation = consumer_duplicate_effect_observation();
            observation.duplicate_settle = duplicate_settle;

            let result = assert_consumer_duplicate_effect_conformance(&ids(), &observation);

            assert!(
                matches!(
                    result,
                    Err(EventingConformanceError::Mismatch(ref detail))
                        if detail.stage == "consumer.duplicate-effect.ack"
                ),
                "duplicate_settle={duplicate_settle:?} must fail, got {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn consumer_conformance_passes_happy_path() -> Result<(), EventingConformanceError> {
        assert_consumer_conformance(ConsumerConformanceCase {
            ids: ids(),
            expected_dlx: expected_dlx(),
            duplicate_delivery: Box::new(|| {
                Box::pin(async {
                    let mut o = ok_observation(SettleAction::Ack);
                    o.handler_calls = 0;
                    o.committed = false;
                    Ok(o)
                })
            }),
            poison_delivery: Box::new(|| Box::pin(async { Ok(ok_observation(SettleAction::Ack)) })),
            dlx_failure: Box::new(|| {
                Box::pin(async {
                    let mut o = ok_observation(SettleAction::Requeue);
                    o.committed = false;
                    o.released = true;
                    o.dlx_count = 0;
                    Ok(o)
                })
            }),
            malformed_message_id: Box::new(|| {
                Box::pin(async {
                    let mut o = ok_observation(SettleAction::Reject);
                    o.handler_calls = 0;
                    o.claim_attempts = 0;
                    o.committed = false;
                    Ok(o)
                })
            }),
        })
        .await
    }

    #[tokio::test]
    async fn consumer_conformance_catches_duplicate_handler_call() {
        let result = assert_consumer_conformance(ConsumerConformanceCase {
            ids: ids(),
            expected_dlx: expected_dlx(),
            duplicate_delivery: Box::new(|| {
                Box::pin(async { Ok(ok_observation(SettleAction::Ack)) })
            }),
            poison_delivery: Box::new(|| Box::pin(async { Ok(ok_observation(SettleAction::Ack)) })),
            dlx_failure: Box::new(|| {
                Box::pin(async {
                    let mut o = ok_observation(SettleAction::Requeue);
                    o.released = true;
                    o.committed = false;
                    Ok(o)
                })
            }),
            malformed_message_id: Box::new(|| {
                Box::pin(async {
                    let mut o = ok_observation(SettleAction::Reject);
                    o.claim_attempts = 0;
                    o.committed = false;
                    Ok(o)
                })
            }),
        })
        .await;
        assert!(
            matches!(
                result,
                Err(EventingConformanceError::Mismatch(ref detail))
                    if detail.stage == "consumer.duplicate.handler-calls"
            ),
            "broken duplicate fake must fail, got {result:?}"
        );
    }

    #[tokio::test]
    async fn consumer_conformance_catches_wrong_dlx_metadata() {
        let result = assert_consumer_conformance(ConsumerConformanceCase {
            ids: ids(),
            expected_dlx: expected_dlx(),
            duplicate_delivery: Box::new(|| {
                Box::pin(async {
                    let mut o = ok_observation(SettleAction::Ack);
                    o.handler_calls = 0;
                    o.committed = false;
                    Ok(o)
                })
            }),
            poison_delivery: Box::new(|| {
                Box::pin(async {
                    let mut o = ok_observation(SettleAction::Ack);
                    o.topic = "wrong.topic".to_string();
                    Ok(o)
                })
            }),
            dlx_failure: Box::new(|| {
                Box::pin(async {
                    let mut o = ok_observation(SettleAction::Requeue);
                    o.released = true;
                    o.committed = false;
                    Ok(o)
                })
            }),
            malformed_message_id: Box::new(|| {
                Box::pin(async {
                    let mut o = ok_observation(SettleAction::Reject);
                    o.claim_attempts = 0;
                    o.committed = false;
                    Ok(o)
                })
            }),
        })
        .await;
        assert!(
            matches!(
                result,
                Err(EventingConformanceError::DlxMismatch(ref detail))
                    if detail.stage == "consumer.poison.dlx-fields"
            ),
            "broken dlx metadata fake must fail, got {result:?}"
        );
    }

    #[tokio::test]
    async fn consumer_conformance_catches_poison_handler_count() {
        let result = assert_consumer_conformance(ConsumerConformanceCase {
            ids: ids(),
            expected_dlx: expected_dlx(),
            duplicate_delivery: Box::new(|| {
                Box::pin(async {
                    let mut o = ok_observation(SettleAction::Ack);
                    o.handler_calls = 0;
                    o.committed = false;
                    Ok(o)
                })
            }),
            poison_delivery: Box::new(|| {
                Box::pin(async {
                    let mut o = ok_observation(SettleAction::Ack);
                    o.handler_calls = 1;
                    Ok(o)
                })
            }),
            dlx_failure: Box::new(|| {
                Box::pin(async {
                    let mut o = ok_observation(SettleAction::Requeue);
                    o.handler_calls = 3;
                    o.released = true;
                    o.committed = false;
                    Ok(o)
                })
            }),
            malformed_message_id: Box::new(|| {
                Box::pin(async {
                    let mut o = ok_observation(SettleAction::Reject);
                    o.handler_calls = 0;
                    o.claim_attempts = 0;
                    o.committed = false;
                    Ok(o)
                })
            }),
        })
        .await;
        assert!(
            matches!(
                result,
                Err(EventingConformanceError::Mismatch(ref detail))
                    if detail.stage == "consumer.poison.handler-calls"
            ),
            "broken poison fake must fail, got {result:?}"
        );
    }

    #[tokio::test]
    async fn consumer_conformance_catches_malformed_handler_call() {
        let result = assert_consumer_conformance(ConsumerConformanceCase {
            ids: ids(),
            expected_dlx: expected_dlx(),
            duplicate_delivery: Box::new(|| {
                Box::pin(async {
                    let mut o = ok_observation(SettleAction::Ack);
                    o.handler_calls = 0;
                    o.committed = false;
                    Ok(o)
                })
            }),
            poison_delivery: Box::new(|| {
                Box::pin(async {
                    let mut o = ok_observation(SettleAction::Ack);
                    o.handler_calls = 3;
                    Ok(o)
                })
            }),
            dlx_failure: Box::new(|| {
                Box::pin(async {
                    let mut o = ok_observation(SettleAction::Requeue);
                    o.handler_calls = 3;
                    o.released = true;
                    o.committed = false;
                    Ok(o)
                })
            }),
            malformed_message_id: Box::new(|| {
                Box::pin(async {
                    let mut o = ok_observation(SettleAction::Reject);
                    o.handler_calls = 1;
                    o.claim_attempts = 0;
                    o.committed = false;
                    Ok(o)
                })
            }),
        })
        .await;
        assert!(
            matches!(
                result,
                Err(EventingConformanceError::Mismatch(ref detail))
                    if detail.stage == "consumer.malformed.handler-calls"
            ),
            "broken malformed fake must fail, got {result:?}"
        );
    }

    #[test]
    fn provider_error_sanitizer_redacts_and_truncates_safely() {
        let err = super::safe_error(
            "postgres://user:password@localhost/db?token=abc\npassword=secret 中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文"
                .to_string(),
        );
        assert!(!err.contains("password@"));
        assert!(!err.contains("token=abc"));
        assert!(!err.contains("password=secret"));
        assert!(!err.contains('\n'));
        assert!(err.len() <= 243);
    }

    #[test]
    fn mismatch_failure_debug_redacts_lease_token_alias() {
        const SECRET: &str = "super-secret-lease-token";
        let err = EventingConformanceError::Mismatch(Box::new(MismatchFailure {
            stage: "inbox.extend.held",
            event_id: "evt-1".into(),
            inbox_key: "evt-1".into(),
            consumer_group: "group-a".into(),
            lease_token_alias: SECRET.into(),
            expected: "Held".into(),
            actual: "Lost".into(),
        }));
        let dbg = format!("{err:?}");
        assert!(
            dbg.contains("<redacted>"),
            "Debug must include redaction marker, got {dbg}"
        );
        assert!(
            !dbg.contains(SECRET),
            "Debug must not leak lease token alias, got {dbg}"
        );
        let display = err.to_string();
        assert!(
            display.contains("lease_token=<redacted>"),
            "Display must keep redacted lease token, got {display}"
        );
        assert!(
            !display.contains(SECRET),
            "Display must not leak lease token alias, got {display}"
        );
    }

    #[test]
    fn eventing_ids_debug_redacts_lease_token() {
        const SECRET: &str = "super-secret-lease-token";
        let ids = EventingIds::new("evt-1", "evt-1", "group-a", SECRET);
        let dbg = format!("{ids:?}");
        assert!(
            dbg.contains("<redacted>"),
            "Debug must include redaction marker, got {dbg}"
        );
        assert!(
            !dbg.contains(SECRET),
            "Debug must not leak lease token, got {dbg}"
        );
    }

    #[test]
    fn inbox_lease_args_debug_redacts_lease_alias() {
        const SECRET: &str = "super-secret-lease-token";
        let args = InboxLeaseArgs {
            inbox_key: "evt-1".into(),
            consumer_group: "group-a".into(),
            lease_alias: SECRET.into(),
        };
        let dbg = format!("{args:?}");
        assert!(
            dbg.contains("<redacted>"),
            "Debug must include redaction marker, got {dbg}"
        );
        assert!(
            !dbg.contains(SECRET),
            "Debug must not leak lease alias, got {dbg}"
        );
    }
}
