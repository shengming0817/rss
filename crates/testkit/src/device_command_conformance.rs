//! Provider-neutral conformance assertions for durable device commands and ingress evidence.
//!
//! Provider tests map their domain outcomes into the closed observations below and supply async
//! closures. This crate intentionally knows no device-loop, identity, or adapter type. The
//! assertions are Medium behavioural evidence complementing the production port's Hard type and
//! database constraints; they are not an in-memory store implementation.

use std::fmt::Debug;
use std::future::Future;

/// Failure reported by the device-command conformance harness.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DeviceCommandConformanceError {
    /// A provider operation failed before its result could be classified.
    #[error("device-command conformance: provider op failed during {stage}: {error}")]
    Provider { stage: &'static str, error: String },
    /// A provider returned the wrong closed outcome.
    #[error("device-command conformance: {stage} returned {actual}; expected {expected}")]
    UnexpectedOutcome {
        stage: &'static str,
        expected: &'static str,
        actual: &'static str,
    },
    /// A persisted value differed from its canonical value.
    #[error(
        "device-command conformance: {stage} value mismatch; expected {expected:?}, got {actual:?}"
    )]
    ValueMismatch {
        stage: &'static str,
        expected: String,
        actual: String,
    },
    /// A durable value expected after a write was absent.
    #[error("device-command conformance: {stage} returned no durable value")]
    MissingValue { stage: &'static str },
    /// Tenant-local ingress identities collided across tenant scopes.
    #[error("device-command conformance: tenant-local ingress identity was not isolated")]
    TenantIsolationViolation,
}

fn provider<E: Debug>(stage: &'static str, error: E) -> DeviceCommandConformanceError {
    DeviceCommandConformanceError::Provider {
        stage,
        error: format!("{error:?}"),
    }
}

fn value_mismatch<T: Debug>(
    stage: &'static str,
    expected: &T,
    actual: &T,
) -> DeviceCommandConformanceError {
    DeviceCommandConformanceError::ValueMismatch {
        stage,
        expected: format!("{expected:?}"),
        actual: format!("{actual:?}"),
    }
}

fn expect_value<T: Debug + PartialEq>(
    stage: &'static str,
    actual: &T,
    expected: &T,
) -> Result<(), DeviceCommandConformanceError> {
    if actual == expected {
        Ok(())
    } else {
        Err(value_mismatch(stage, expected, actual))
    }
}

/// Provider-neutral classification of command creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceCommandCreateObservation<S, I> {
    /// A new queued aggregate was persisted.
    Created(S),
    /// Exact immutable input replayed the already-persisted aggregate.
    Replay(S),
    /// The command identity was reused with different immutable input.
    IdentityConflict,
    /// Another command already owns the active coordinate and intent.
    ActiveConflict { command_id: I },
}

impl<S, I> DeviceCommandCreateObservation<S, I> {
    const fn label(&self) -> &'static str {
        match self {
            Self::Created(_) => "created",
            Self::Replay(_) => "replay",
            Self::IdentityConflict => "identity-conflict",
            Self::ActiveConflict { .. } => "active-conflict",
        }
    }
}

/// Inputs and provider operation for the command-creation conformance sequence.
pub struct DeviceCommandCreateCase<Q, S, I, C> {
    /// First canonical creation input.
    pub first_input: Q,
    /// Exact replay of the first immutable input.
    pub replay_input: Q,
    /// Same command identity with different immutable input.
    pub identity_conflict_input: Q,
    /// Different command identity with the same active coordinate and intent.
    pub active_conflict_input: Q,
    /// Canonical queued snapshot, including provider-owned timestamps.
    pub expected_snapshot: S,
    /// Identity which must be named by the active conflict.
    pub expected_active_command_id: I,
    /// Provider creation operation.
    pub create: C,
}

/// Assert first create, exact replay, identity conflict, and active uniqueness conflict.
pub async fn assert_device_command_create<Q, S, I, C, CF, E>(
    mut case: DeviceCommandCreateCase<Q, S, I, C>,
) -> Result<(), DeviceCommandConformanceError>
where
    S: Debug + PartialEq,
    I: Debug + PartialEq,
    C: FnMut(Q) -> CF,
    CF: Future<Output = Result<DeviceCommandCreateObservation<S, I>, E>>,
    E: Debug,
{
    match (case.create)(case.first_input)
        .await
        .map_err(|error| provider("first create", error))?
    {
        DeviceCommandCreateObservation::Created(snapshot) => {
            expect_value("first create", &snapshot, &case.expected_snapshot)?;
        }
        outcome => {
            return Err(DeviceCommandConformanceError::UnexpectedOutcome {
                stage: "first create",
                expected: "created",
                actual: outcome.label(),
            });
        }
    }

    match (case.create)(case.replay_input)
        .await
        .map_err(|error| provider("exact create replay", error))?
    {
        DeviceCommandCreateObservation::Replay(snapshot) => {
            expect_value("exact create replay", &snapshot, &case.expected_snapshot)?;
        }
        outcome => {
            return Err(DeviceCommandConformanceError::UnexpectedOutcome {
                stage: "exact create replay",
                expected: "replay",
                actual: outcome.label(),
            });
        }
    }

    let identity_conflict = (case.create)(case.identity_conflict_input)
        .await
        .map_err(|error| provider("identity conflict", error))?;
    if !matches!(
        identity_conflict,
        DeviceCommandCreateObservation::IdentityConflict
    ) {
        return Err(DeviceCommandConformanceError::UnexpectedOutcome {
            stage: "identity conflict",
            expected: "identity-conflict",
            actual: identity_conflict.label(),
        });
    }

    match (case.create)(case.active_conflict_input)
        .await
        .map_err(|error| provider("active conflict", error))?
    {
        DeviceCommandCreateObservation::ActiveConflict { command_id } => expect_value(
            "active conflict command id",
            &command_id,
            &case.expected_active_command_id,
        ),
        outcome => Err(DeviceCommandConformanceError::UnexpectedOutcome {
            stage: "active conflict",
            expected: "active-conflict",
            actual: outcome.label(),
        }),
    }
}

/// Assert that a fresh provider/repository instance restores the exact durable snapshot.
///
/// The supplied closure must cross the provider's normal restart/reconstruction boundary rather
/// than reuse an aggregate already resident in memory.
pub async fn assert_device_command_restart_equivalence<K, S, L, LF, E>(
    command_key: K,
    expected_snapshot: S,
    restart_load: L,
) -> Result<S, DeviceCommandConformanceError>
where
    S: Debug + PartialEq,
    L: FnOnce(K) -> LF,
    LF: Future<Output = Result<Option<S>, E>>,
    E: Debug,
{
    let actual = restart_load(command_key)
        .await
        .map_err(|error| provider("restart load", error))?
        .ok_or(DeviceCommandConformanceError::MissingValue {
            stage: "restart load",
        })?;
    expect_value("restart load", &actual, &expected_snapshot)?;
    Ok(actual)
}

/// Provider-neutral classification of an optimistic command transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceCommandCasObservation<S, V> {
    /// State and version advanced.
    Advanced(S),
    /// The caller's expected version was stale or ahead.
    VersionConflict { actual: V },
    /// The canonical state machine classified a zero-write semantic no-op.
    NoChange,
    /// No aggregate exists in the authorized scope.
    Missing,
}

impl<S, V> DeviceCommandCasObservation<S, V> {
    const fn label(&self) -> &'static str {
        match self {
            Self::Advanced(_) => "advanced",
            Self::VersionConflict { .. } => "version-conflict",
            Self::NoChange => "no-change",
            Self::Missing => "missing",
        }
    }
}

/// Inputs and provider operations for optimistic-CAS conformance.
pub struct DeviceCommandCasCase<Q, V, C, L, M> {
    /// First concurrent mutation using the same expected version.
    pub contender_a_input: Q,
    /// Second concurrent mutation using the same expected version.
    pub contender_b_input: Q,
    /// A later retry which still uses the now-stale version.
    pub stale_input: Q,
    /// A mutation which the canonical state machine must classify as a semantic no-op.
    pub no_change_input: Q,
    /// A mutation targeting an aggregate absent from the authorized scope.
    pub missing_input: Q,
    /// Version which both losing operations must report.
    pub expected_actual_version: V,
    /// Provider transition operation. It is `Fn`, allowing two calls to be in flight together.
    pub transition: C,
    /// Load the currently persisted snapshot.
    pub load: L,
    /// Load the aggregate targeted by `missing_input`; it must remain absent.
    pub load_missing: M,
}

/// Assert the complete CAS outcome vocabulary and zero-write losing/no-op behavior.
pub async fn assert_device_command_cas<Q, S, V, C, L, M, CF, LF, MF, E>(
    mut case: DeviceCommandCasCase<Q, V, C, L, M>,
) -> Result<S, DeviceCommandConformanceError>
where
    S: Debug + PartialEq,
    V: Debug + PartialEq,
    C: Fn(Q) -> CF,
    L: FnMut() -> LF,
    M: FnOnce() -> MF,
    CF: Future<Output = Result<DeviceCommandCasObservation<S, V>, E>>,
    LF: Future<Output = Result<Option<S>, E>>,
    MF: Future<Output = Result<Option<S>, E>>,
    E: Debug,
{
    let contender_a = (case.transition)(case.contender_a_input);
    let contender_b = (case.transition)(case.contender_b_input);
    let (outcome_a, outcome_b) = futures::join!(contender_a, contender_b);
    let outcome_a = outcome_a.map_err(|error| provider("CAS contender A", error))?;
    let outcome_b = outcome_b.map_err(|error| provider("CAS contender B", error))?;

    let (winner, losing_actual) = match (outcome_a, outcome_b) {
        (
            DeviceCommandCasObservation::Advanced(snapshot),
            DeviceCommandCasObservation::VersionConflict { actual },
        )
        | (
            DeviceCommandCasObservation::VersionConflict { actual },
            DeviceCommandCasObservation::Advanced(snapshot),
        ) => (snapshot, actual),
        (left, right) => {
            return Err(DeviceCommandConformanceError::UnexpectedOutcome {
                stage: "concurrent CAS",
                expected: "one advanced and one version-conflict",
                actual: match (left.label(), right.label()) {
                    ("advanced", "advanced") => "two advanced",
                    ("version-conflict", "version-conflict") => "two version-conflicts",
                    _ => "non-CAS outcome",
                },
            });
        }
    };
    expect_value(
        "losing CAS actual version",
        &losing_actual,
        &case.expected_actual_version,
    )?;

    let after_race = (case.load)()
        .await
        .map_err(|error| provider("load after CAS race", error))?
        .ok_or(DeviceCommandConformanceError::MissingValue {
            stage: "load after CAS race",
        })?;
    expect_value("load after CAS race", &after_race, &winner)?;

    match (case.transition)(case.stale_input)
        .await
        .map_err(|error| provider("stale CAS retry", error))?
    {
        DeviceCommandCasObservation::VersionConflict { actual } => {
            expect_value(
                "stale CAS actual version",
                &actual,
                &case.expected_actual_version,
            )?;
        }
        outcome => {
            return Err(DeviceCommandConformanceError::UnexpectedOutcome {
                stage: "stale CAS retry",
                expected: "version-conflict",
                actual: outcome.label(),
            });
        }
    }

    let after_stale = (case.load)()
        .await
        .map_err(|error| provider("load after stale CAS", error))?
        .ok_or(DeviceCommandConformanceError::MissingValue {
            stage: "load after stale CAS",
        })?;
    expect_value("stale CAS zero-write", &after_stale, &winner)?;

    match (case.transition)(case.no_change_input)
        .await
        .map_err(|error| provider("semantic no-change", error))?
    {
        DeviceCommandCasObservation::NoChange => {}
        outcome => {
            return Err(DeviceCommandConformanceError::UnexpectedOutcome {
                stage: "semantic no-change",
                expected: "no-change",
                actual: outcome.label(),
            });
        }
    }

    let after_no_change = (case.load)()
        .await
        .map_err(|error| provider("load after semantic no-change", error))?
        .ok_or(DeviceCommandConformanceError::MissingValue {
            stage: "load after semantic no-change",
        })?;
    expect_value("semantic no-change zero-write", &after_no_change, &winner)?;

    match (case.transition)(case.missing_input)
        .await
        .map_err(|error| provider("missing CAS", error))?
    {
        DeviceCommandCasObservation::Missing => {}
        outcome => {
            return Err(DeviceCommandConformanceError::UnexpectedOutcome {
                stage: "missing CAS",
                expected: "missing",
                actual: outcome.label(),
            });
        }
    }

    let after_missing = (case.load_missing)()
        .await
        .map_err(|error| provider("load after missing CAS", error))?;
    if let Some(actual) = after_missing {
        return Err(DeviceCommandConformanceError::ValueMismatch {
            stage: "missing CAS zero-write",
            expected: "None".to_owned(),
            actual: format!("Some({actual:?})"),
        });
    }
    Ok(winner)
}

/// Provider-neutral classification of append-once ingress evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceIngressConformanceObservation<R> {
    /// Evidence was appended for the first time.
    Appended(R),
    /// Exact immutable evidence replayed its original receipt.
    Replay(R),
    /// A tenant-local event identity was reused with different immutable evidence.
    Conflict,
}

impl<R> DeviceIngressConformanceObservation<R> {
    const fn label(&self) -> &'static str {
        match self {
            Self::Appended(_) => "appended",
            Self::Replay(_) => "replay",
            Self::Conflict => "conflict",
        }
    }
}

/// Inputs and provider operations for append-once ingress conformance.
pub struct DeviceIngressConformanceCase<T, K, Q, A, L> {
    /// First tenant fixture used to mint provider scope capabilities.
    pub tenant_a: T,
    /// Isolated tenant fixture which reuses the same event identity.
    pub tenant_b: T,
    /// Tenant-local event identity used by both tenants.
    pub event_id: K,
    /// First append input for tenant A.
    pub first_input: Q,
    /// Exact immutable replay input for tenant A.
    pub replay_input: Q,
    /// Same event identity with changed immutable evidence for tenant A.
    pub conflict_input: Q,
    /// First input for tenant B, reusing the event identity with distinct evidence.
    pub tenant_b_input: Q,
    /// Provider append operation.
    pub append: A,
    /// Provider receipt load operation.
    pub load: L,
}

/// Assert exact replay, immutable conflict, zero overwrite, and tenant-local ID isolation.
pub async fn assert_device_ingress_conformance<T, K, Q, R, A, L, AF, LF, E>(
    mut case: DeviceIngressConformanceCase<T, K, Q, A, L>,
) -> Result<(), DeviceCommandConformanceError>
where
    T: Clone,
    K: Clone,
    R: Debug + PartialEq,
    A: FnMut(T, Q) -> AF,
    L: FnMut(T, K) -> LF,
    AF: Future<Output = Result<DeviceIngressConformanceObservation<R>, E>>,
    LF: Future<Output = Result<Option<R>, E>>,
    E: Debug,
{
    let receipt_a = match (case.append)(case.tenant_a.clone(), case.first_input)
        .await
        .map_err(|error| provider("first ingress append", error))?
    {
        DeviceIngressConformanceObservation::Appended(receipt) => receipt,
        outcome => {
            return Err(DeviceCommandConformanceError::UnexpectedOutcome {
                stage: "first ingress append",
                expected: "appended",
                actual: outcome.label(),
            });
        }
    };

    match (case.append)(case.tenant_a.clone(), case.replay_input)
        .await
        .map_err(|error| provider("exact ingress replay", error))?
    {
        DeviceIngressConformanceObservation::Replay(receipt) => {
            expect_value("exact ingress replay", &receipt, &receipt_a)?;
        }
        outcome => {
            return Err(DeviceCommandConformanceError::UnexpectedOutcome {
                stage: "exact ingress replay",
                expected: "replay",
                actual: outcome.label(),
            });
        }
    }

    let conflict = (case.append)(case.tenant_a.clone(), case.conflict_input)
        .await
        .map_err(|error| provider("ingress identity conflict", error))?;
    if !matches!(conflict, DeviceIngressConformanceObservation::Conflict) {
        return Err(DeviceCommandConformanceError::UnexpectedOutcome {
            stage: "ingress identity conflict",
            expected: "conflict",
            actual: conflict.label(),
        });
    }

    let tenant_a_after_conflict = (case.load)(case.tenant_a.clone(), case.event_id.clone())
        .await
        .map_err(|error| provider("load after ingress conflict", error))?
        .ok_or(DeviceCommandConformanceError::MissingValue {
            stage: "load after ingress conflict",
        })?;
    expect_value(
        "ingress conflict zero-write",
        &tenant_a_after_conflict,
        &receipt_a,
    )?;

    let receipt_b = match (case.append)(case.tenant_b.clone(), case.tenant_b_input)
        .await
        .map_err(|error| provider("isolated tenant ingress append", error))?
    {
        DeviceIngressConformanceObservation::Appended(receipt) => receipt,
        outcome => {
            return Err(DeviceCommandConformanceError::UnexpectedOutcome {
                stage: "isolated tenant ingress append",
                expected: "appended",
                actual: outcome.label(),
            });
        }
    };
    if receipt_a == receipt_b {
        return Err(DeviceCommandConformanceError::TenantIsolationViolation);
    }

    let tenant_a_final = (case.load)(case.tenant_a, case.event_id.clone())
        .await
        .map_err(|error| provider("tenant A final ingress load", error))?
        .ok_or(DeviceCommandConformanceError::MissingValue {
            stage: "tenant A final ingress load",
        })?;
    expect_value("tenant A final ingress load", &tenant_a_final, &receipt_a)?;

    let tenant_b_final = (case.load)(case.tenant_b, case.event_id)
        .await
        .map_err(|error| provider("tenant B ingress load", error))?
        .ok_or(DeviceCommandConformanceError::MissingValue {
            stage: "tenant B ingress load",
        })?;
    expect_value("tenant B ingress load", &tenant_b_final, &receipt_b)
}
