use super::*;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Numeric {
    sum: Sum,
    count: u64,
    min: Option<Number>,
    max: Option<Number>,
}
pub(super) fn as_sum(n: Number) -> Sum {
    match n {
        Number::I64(v) => Sum::I128(v.into()),
        Number::U64(v) => Sum::U128(v.into()),
        Number::F64(v) => Sum::F64(v),
    }
}
pub(super) fn compare(a: Number, b: Number) -> Result<std::cmp::Ordering, Error> {
    match (a, b) {
        (Number::I64(a), Number::I64(b)) => Ok(a.cmp(&b)),
        (Number::U64(a), Number::U64(b)) => Ok(a.cmp(&b)),
        (Number::F64(a), Number::F64(b)) => {
            a.get().partial_cmp(&b.get()).ok_or(Error::NumericRange)
        }
        _ => Err(Error::InvalidInput),
    }
}
impl Numeric {
    pub(super) fn compute(
        kind: NumberKind,
        window: Interval,
        samples: &[Sample],
    ) -> Result<Self, Error> {
        let mut s = Self {
            sum: Sum::zero(kind)?,
            count: 0,
            min: None,
            max: None,
        };
        for sample in samples {
            if let Reading::Valid(Value::Number(n)) = sample.input().reading
                && inside(sample.input().observed_at, window)
            {
                s.add(n)?;
            }
        }
        Ok(s)
    }
    fn extrema(&mut self, n: Number) -> Result<(), Error> {
        if self
            .min
            .map(|v| compare(n, v))
            .transpose()?
            .is_none_or(|v| v.is_lt())
        {
            self.min = Some(n);
        }
        if self
            .max
            .map(|v| compare(n, v))
            .transpose()?
            .is_none_or(|v| v.is_gt())
        {
            self.max = Some(n);
        }
        Ok(())
    }
    pub(super) fn add(&mut self, n: Number) -> Result<(), Error> {
        self.sum = self.sum.checked_add(as_sum(n))?;
        self.count = self.count.checked_add(1).ok_or(Error::NumericRange)?;
        self.extrema(n)
    }
    pub(super) fn merge(&mut self, b: Self) -> Result<(), Error> {
        self.sum = self.sum.checked_add(b.sum)?;
        self.count = self.count.checked_add(b.count).ok_or(Error::NumericRange)?;
        if let Some(n) = b.min {
            self.extrema(n)?;
        }
        if let Some(n) = b.max {
            self.extrema(n)?;
        }
        Ok(())
    }
    pub(super) fn project(&self, op: AggregateOp) -> Result<AggregateValue, Error> {
        let Some(count) = NonZeroU64::new(self.count) else {
            return Ok(AggregateValue::Missing);
        };
        Ok(match op {
            AggregateOp::Sum => AggregateValue::Sum(self.sum),
            AggregateOp::Count => AggregateValue::Count(self.count),
            AggregateOp::Mean => AggregateValue::Mean {
                sum: self.sum,
                count,
            },
            AggregateOp::Min => AggregateValue::Number(self.min.ok_or(Error::Invariant)?),
            AggregateOp::Max => AggregateValue::Number(self.max.ok_or(Error::Invariant)?),
            _ => return Err(Error::Unsupported),
        })
    }
}
