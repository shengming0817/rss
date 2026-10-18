use super::*;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Contribution {
    window: Interval,
    increase: Sum,
}
fn number(s: &Sample) -> Option<Number> {
    if let Reading::Valid(Value::Number(n)) = s.input().reading {
        Some(n)
    } else {
        None
    }
}
fn difference(a: Number, b: Number) -> Result<Sum, Error> {
    match (a, b) {
        (Number::I64(a), Number::I64(b)) => Ok(Sum::I128(i128::from(b) - i128::from(a))),
        (Number::U64(a), Number::U64(b)) => Ok(Sum::U128(
            u128::from(b)
                .checked_sub(u128::from(a))
                .ok_or(Error::NumericRange)?,
        )),
        (Number::F64(a), Number::F64(b)) => Ok(Sum::F64(FiniteF64::new(b.get() - a.get())?)),
        _ => Err(Error::InvalidInput),
    }
}
/// For ordered semantics, the greatest sequence/id wins at a shared timestamp.
fn points(samples: &[Sample]) -> Vec<&Sample> {
    let mut out: Vec<&Sample> = Vec::new();
    for s in samples {
        if out
            .last()
            .is_some_and(|p| p.input().observed_at == s.input().observed_at)
        {
            out.pop();
        }
        out.push(s);
    }
    out
}
fn cumulative(
    a: &Sample,
    b: &Sample,
    max_gap: u64,
    defects: &mut BTreeSet<Completeness>,
) -> Result<Option<Contribution>, Error> {
    let (Some(x), Some(y)) = (number(a), number(b)) else {
        defects.insert(Completeness::Gaps);
        return Ok(None);
    };
    let ai = a.input().interval.ok_or(Error::Invariant)?;
    let bi = b.input().interval.ok_or(Error::Invariant)?;
    if ai.start() != bi.start() || bi.width_micros() == 0 || numeric::compare(y, x)?.is_lt() {
        defects.insert(Completeness::ResetBoundary);
        return Ok(None);
    }
    let window = Interval::new(a.input().observed_at, b.input().observed_at)?;
    if window.width_micros() > max_gap {
        defects.insert(Completeness::Gaps);
        return Ok(None);
    }
    Ok(Some(Contribution {
        window,
        increase: difference(x, y)?,
    }))
}
pub(super) fn counter(
    spec: &SummarySpec,
    window: Interval,
    samples: &[Sample],
    temporality: Temporality,
    defects: &mut BTreeSet<Completeness>,
) -> Result<Vec<Contribution>, Error> {
    let mut out = Vec::new();
    let max_gap = spec.max_gap().ok_or(Error::Invariant)?.get();
    if temporality == Temporality::Delta {
        for s in samples
            .iter()
            .filter(|s| inside(s.input().observed_at, window))
        {
            if let Some(n) = number(s) {
                let w = s.input().interval.ok_or(Error::Invariant)?;
                if w.width_micros() > max_gap {
                    defects.insert(Completeness::Gaps);
                } else {
                    out.push(Contribution {
                        window: w,
                        increase: numeric::as_sum(n),
                    });
                }
            }
        }
    } else {
        let ordered = points(samples);
        for pair in ordered.windows(2) {
            if inside(pair[1].input().observed_at, window)
                && let Some(c) = cumulative(pair[0], pair[1], max_gap, defects)?
            {
                out.push(c);
            }
        }
    }
    Ok(out)
}
pub(super) fn project_counter(
    kind: NumberKind,
    items: &[Contribution],
    window: Interval,
    op: AggregateOp,
    defects: &mut BTreeSet<Completeness>,
) -> Result<(AggregateValue, u64), Error> {
    let mut sum = Sum::zero(kind)?;
    let mut covered = 0u64;
    let mut last = None;
    let mut overlap = false;
    let mut ordered: Vec<_> = items.iter().collect();
    ordered.sort_by_key(|c| (c.window.start(), c.window.end()));
    for c in ordered {
        if c.window.start() < window.start() || c.window.end() > window.end() {
            defects.insert(Completeness::Boundary);
            continue;
        }
        if last.is_some_and(|end| c.window.start() < end) {
            overlap = true;
        }
        last = Some(last.map_or(c.window.end(), |end: Timestamp| end.max(c.window.end())));
        sum = sum.checked_add(c.increase)?;
        covered = covered
            .checked_add(c.window.width_micros())
            .ok_or(Error::NumericRange)?;
    }
    if overlap {
        defects.insert(Completeness::Overlap);
        return Ok((AggregateValue::Missing, 0));
    }
    let Some(duration_micros) = NonZeroU64::new(covered) else {
        return Ok((AggregateValue::Missing, 0));
    };
    let value = match op {
        AggregateOp::Sum | AggregateOp::Increase => AggregateValue::Sum(sum),
        AggregateOp::Rate => AggregateValue::Rate {
            increase: sum,
            duration_micros,
        },
        _ => return Err(Error::Unsupported),
    };
    Ok((value, covered))
}
fn state_value(s: &Sample) -> Option<StateValue> {
    match &s.input().reading {
        Reading::Valid(Value::Bool(v)) => Some(StateValue::Bool(*v)),
        Reading::Valid(Value::State(v)) => Some(StateValue::State(v.clone())),
        _ => None,
    }
}
pub(super) fn state(
    spec: &SummarySpec,
    window: Interval,
    samples: &[Sample],
) -> Result<(Vec<StateSegment>, Vec<Transition>), Error> {
    let ordered = points(samples);
    let mut segments = Vec::new();
    let mut transitions = Vec::new();
    for (idx, s) in ordered.iter().enumerate() {
        let Some(value) = state_value(s) else {
            continue;
        };
        let at = s.input().observed_at;
        if at >= window.end() {
            break;
        }
        if let Some(prev) = idx.checked_sub(1).and_then(|i| ordered.get(i))
            && inside(at, window)
            && let Some(from) = state_value(prev)
        {
            let continuous = match spec.coverage() {
                CoveragePolicy::ObservedOnly => true,
                CoveragePolicy::HoldLast(n) => {
                    (at.micros() - prev.input().observed_at.micros()) as u64 <= n.get()
                }
            };
            if continuous && from != value {
                transitions.push(Transition {
                    at,
                    from,
                    to: value.clone(),
                });
            }
        }
        let end = match spec.coverage() {
            CoveragePolicy::ObservedOnly => at,
            CoveragePolicy::HoldLast(n) => Timestamp::new(
                at.micros()
                    .saturating_add(i64::try_from(n.get()).unwrap_or(i64::MAX)),
            )?
            .min(
                ordered
                    .get(idx + 1)
                    .map_or(window.end(), |s| s.input().observed_at),
            )
            .min(window.end()),
        };
        let start = at.max(window.start());
        if end >= start {
            segments.push(StateSegment {
                value,
                window: Interval::new(start, end)?,
            });
        }
    }
    Ok((segments, transitions))
}
pub(super) fn project_state(
    segments: &[StateSegment],
    transitions: &[Transition],
    op: AggregateOp,
) -> Result<(AggregateValue, u64), Error> {
    let mut durations: Vec<StateDuration> = Vec::new();
    let mut compact: Vec<StateSegment> = Vec::new();
    let mut covered = 0u64;
    for s in segments {
        let micros = s.window.width_micros();
        covered = covered.checked_add(micros).ok_or(Error::NumericRange)?;
        if let Some(d) = durations.iter_mut().find(|d| d.value == s.value) {
            d.micros = d.micros.checked_add(micros).ok_or(Error::NumericRange)?;
        } else {
            durations.push(StateDuration {
                value: s.value.clone(),
                micros,
            });
        }
        if let Some(last) = compact.last_mut()
            && last.value == s.value
            && last.window.end() == s.window.start()
        {
            last.window = Interval::new(last.window.start(), s.window.end())?;
        } else {
            compact.push(s.clone());
        }
    }
    if segments.is_empty() {
        return Ok((AggregateValue::Missing, 0));
    }
    let value = match op {
        AggregateOp::Timeline => AggregateValue::StateSegments(compact),
        AggregateOp::Transitions => AggregateValue::Transitions(transitions.to_vec()),
        AggregateOp::Coverage => AggregateValue::StateCoverage(durations),
        _ => return Err(Error::Unsupported),
    };
    Ok((value, covered))
}
