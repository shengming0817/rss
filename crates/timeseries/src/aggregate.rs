//! Shared arithmetic and sufficient statistics; providers own scanning and persistence.
// ref: timescale/timescaledb-toolkit crates/stats-agg/src/stats1d.rs@1.21.0
use crate::*;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, num::NonZeroU64};
mod numeric;
mod ordered;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "Spec", into = "Spec")]
pub struct SummarySpec(Spec);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Spec {
    stream: Stream,
    series: Series,
    resolution: NonZeroU64,
    coverage: CoveragePolicy,
    max_gap: Option<NonZeroU64>,
}
impl TryFrom<Spec> for SummarySpec {
    type Error = Error;
    fn try_from(value: Spec) -> Result<Self, Error> {
        let s = Self(value);
        s.validate()?;
        Ok(s)
    }
}
impl From<SummarySpec> for Spec {
    fn from(v: SummarySpec) -> Self {
        v.0
    }
}
impl SummarySpec {
    pub fn new(
        stream: Stream,
        series: Series,
        resolution: NonZeroU64,
        coverage: CoveragePolicy,
        max_gap: Option<NonZeroU64>,
    ) -> Result<Self, Error> {
        Self::try_from(Spec {
            stream,
            series,
            resolution,
            coverage,
            max_gap,
        })
    }
    pub fn validate(&self) -> Result<(), Error> {
        self.selection().validate()?;
        if self.0.resolution.get() > i64::MAX as u64 {
            return Err(Error::NumericRange);
        }
        let counter = matches!(
            self.0.series.definition().spec().metric,
            Metric::Counter { .. }
        );
        let state = matches!(
            self.0.series.definition().spec().metric,
            Metric::Bool | Metric::State { .. }
        );
        if counter != self.0.max_gap.is_some()
            || (!state && self.0.coverage != CoveragePolicy::ObservedOnly)
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
    pub const fn stream(&self) -> &Stream {
        &self.0.stream
    }
    pub const fn series(&self) -> &Series {
        &self.0.series
    }
    pub const fn resolution_micros(&self) -> NonZeroU64 {
        self.0.resolution
    }
    pub const fn coverage(&self) -> CoveragePolicy {
        self.0.coverage
    }
    pub const fn max_gap(&self) -> Option<NonZeroU64> {
        self.0.max_gap
    }
    pub fn selection(&self) -> Selection {
        Selection::Exact {
            stream: self.0.stream.clone(),
            series: self.0.series.clone(),
        }
    }
    pub fn binding(&self) -> Result<Digest, Error> {
        digest(b"summary-spec", self)
    }
    /// Policy identity excludes resolution: only aligned compatible summaries may roll up.
    pub fn semantics(&self) -> Result<Digest, Error> {
        digest(
            b"summary-semantics",
            &(
                &self.0.stream,
                &self.0.series,
                self.0.coverage,
                self.0.max_gap,
            ),
        )
    }
    pub fn bucket(&self, at: Timestamp) -> Result<Interval, Error> {
        let r = self.0.resolution.get() as i64;
        let start = at.micros() / r * r;
        Interval::new(
            Timestamp::new(start)?,
            Timestamp::new(start.saturating_add(r))?,
        )
    }
    pub fn lookback(&self) -> u64 {
        match self.coverage() {
            CoveragePolicy::HoldLast(n) => n.get(),
            CoveragePolicy::ObservedOnly => self.max_gap().map_or(0, NonZeroU64::get),
        }
    }
}

/// Serialized provider-owned summary format. No producer identity is derived from it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Summary {
    pub window: Interval,
    semantics: Digest,
    valid: u64,
    defects: BTreeSet<Completeness>,
    data: Statistics,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
enum Statistics {
    Numeric(numeric::Numeric),
    Counter {
        kind: NumberKind,
        contributions: Vec<ordered::Contribution>,
    },
    State {
        segments: Vec<StateSegment>,
        transitions: Vec<Transition>,
    },
}
impl Summary {
    /// Input is unique and ordered by the canonical observation tuple. It may include
    /// one predecessor for Counter/state boundary semantics. Providers enforce scan budgets.
    pub fn compute(
        spec: &SummarySpec,
        window: Interval,
        samples: &[Sample],
        max_items: usize,
    ) -> Result<Self, Error> {
        if samples.len() > max_items || window.width_micros() == 0 {
            return Err(Error::BudgetExceeded);
        }
        let selection = spec.selection();
        let mut previous = None;
        let mut ids = BTreeSet::new();
        for sample in samples {
            if !selection.matches(sample) {
                return Err(Error::InvalidInput);
            }
            let i = sample.input();
            let key = (i.observed_at, i.sequence, &i.id);
            if previous.is_some_and(|p| p >= key) || !ids.insert(&i.id) {
                return Err(Error::Conflict);
            }
            previous = Some(key);
        }
        let mut defects = BTreeSet::new();
        let valid = samples
            .iter()
            .filter(|s| {
                inside(s.input().observed_at, window)
                    && matches!(s.input().reading, Reading::Valid(_))
            })
            .count() as u64;
        if samples.iter().any(|s| {
            inside(s.input().observed_at, window) && !matches!(s.input().reading, Reading::Valid(_))
        }) {
            defects.insert(Completeness::Gaps);
        }
        let data = match spec.series().definition().spec().metric {
            Metric::Gauge { number } => {
                Statistics::Numeric(numeric::Numeric::compute(number, window, samples)?)
            }
            Metric::Counter {
                number,
                temporality,
            } => Statistics::Counter {
                kind: number,
                contributions: ordered::counter(spec, window, samples, temporality, &mut defects)?,
            },
            Metric::Bool | Metric::State { .. } => {
                let (segments, transitions) = ordered::state(spec, window, samples)?;
                Statistics::State {
                    segments,
                    transitions,
                }
            }
        };
        let result = Self {
            window,
            semantics: spec.semantics()?,
            valid,
            defects,
            data,
        };
        result.check_size(max_items)?;
        Ok(result)
    }
    fn check_size(&self, max: usize) -> Result<(), Error> {
        let n = match &self.data {
            Statistics::Numeric(_) => 1,
            Statistics::Counter { contributions, .. } => contributions.len(),
            Statistics::State {
                segments,
                transitions,
            } => segments.len().saturating_add(transitions.len()),
        };
        if n > max {
            Err(Error::BudgetExceeded)
        } else {
            Ok(())
        }
    }
    /// Exact ordered union. No averaging means, proportional splitting or policy coercion.
    pub fn merge(mut self, other: Self, max_items: usize) -> Result<Self, Error> {
        if self.window.end() != other.window.start() || self.semantics != other.semantics {
            return Err(Error::InvalidInput);
        }
        self.window = Interval::new(self.window.start(), other.window.end())?;
        self.valid = self
            .valid
            .checked_add(other.valid)
            .ok_or(Error::NumericRange)?;
        self.defects.extend(other.defects);
        match (&mut self.data, other.data) {
            (Statistics::Numeric(a), Statistics::Numeric(b)) => a.merge(b)?,
            (
                Statistics::Counter {
                    kind: a,
                    contributions: x,
                },
                Statistics::Counter {
                    kind: b,
                    contributions: y,
                },
            ) if *a == b => x.extend(y),
            (
                Statistics::State {
                    segments: a,
                    transitions: x,
                },
                Statistics::State {
                    segments: b,
                    transitions: y,
                },
            ) => {
                a.extend(b);
                x.extend(y);
            }
            _ => return Err(Error::InvalidInput),
        }
        self.check_size(max_items)?;
        Ok(self)
    }
    pub fn project(&self, operation: AggregateOp) -> Result<AggregateBucket, Error> {
        let mut defects = self.defects.clone();
        let (value, covered) = match &self.data {
            Statistics::Numeric(n) => (n.project(operation)?, 0),
            Statistics::Counter {
                kind,
                contributions,
            } => ordered::project_counter(
                *kind,
                contributions,
                self.window,
                operation,
                &mut defects,
            )?,
            Statistics::State {
                segments,
                transitions,
            } => ordered::project_state(segments, transitions, operation)?,
        };
        if !matches!(self.data, Statistics::Numeric(_)) && covered < self.window.width_micros() {
            defects.insert(Completeness::Gaps);
        }
        Ok(AggregateBucket {
            window: self.window,
            value,
            valid_samples: self.valid,
            covered_micros: covered,
            completeness: defects,
        })
    }
}
fn inside(at: Timestamp, w: Interval) -> bool {
    at >= w.start() && at < w.end()
}
