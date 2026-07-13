//! Outbox relay/sweeper 驱动配置护栏（#1209）——构造期 fail-fast 下限/上限校验。
//!
//! 范式同 [`crate::reconcile`] 的 `Trigger::interval` / `BackoffPolicy::new`（fail-fast `new()` +
//! `#[non_exhaustive]` thiserror + 私有字段 + accessor）；这些是**构造期配置校验**错误，非 wire 错误，
//! 故不进 `vocab` ERR_ 命名空间。
//!
//! # INVARIANT: RELAY-CONFIG-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
//!
//! `relay_loop` 只接 [`RelayConfig`]（非裸 `Duration`/`usize`）；私有字段 + 唯一
//! [`RelayConfig::new`] funnel ⇒ **未校验的 config 不可表达**（构造器 funnel +
//! input-struct-field-exclusion，Hard）。误配 `poll_interval=0`（`tokio::time::interval` 立即连发 → DB
//! 热轮询打爆连接池）、`max_in_flight=0`（claim 恒空 → relay 永不推进、静默积压）或并发上限过大，
//! 均在构造点即拒。relay domain 由 provider 绑定，不进入 config，避免双输入错插。
//!
//! # INVARIANT: SAMPLER-CONFIG-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
//!
//! `backlog_sampler_loop` 只接 [`SamplerConfig`]；`domains` 数量上限 + 经 `vocab::DomainName`
//! （crate-name 形 `[a-z][a-z0-9_]*`，grammar 单源）逐个校验 + 去重，同时限制 metrics `domain`
//! label 基数（#1076 对齐：domain 是 runtime 配置，故由 typed funnel 而非编译期枚举封边）。
//!
//! # INVARIANT: SWEEPER-CONFIG-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
//!
//! `sweeper_loop` 只接 [`SweeperConfig`]；同 funnel 拒 `sweep_interval=0`（同热轮询风险）与
//! `retain_seconds=0`（删除 just-published 行）。

use std::time::Duration;

use vocab::DomainName;

// ── relay 护栏边界（≥3 处或语义常量抽 const）──────────────────────────────────

/// relay poll 间隔下限：`tokio::time::interval` 非零 + 防 sub-100ms 热轮询打爆 DB。
const MIN_POLL_INTERVAL: Duration = Duration::from_millis(100);
/// relay poll 间隔上限：超 5min 则 backlog 投递延迟 SLO 失去意义。
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(300);
/// relay 单轮并发 claim/publish 下限：0 ⇒ claim 恒空、relay 永不推进（静默积压）。
const MIN_MAX_IN_FLIGHT: usize = 1;
/// relay 单轮并发 claim/publish 上限：限制在途 I/O、内存与 lease 到期前无法完成的风险。
const MAX_MAX_IN_FLIGHT: usize = 64;
/// backlog 采样间隔下限：非零 + 防热轮询聚合查询。
const MIN_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
/// backlog 采样间隔上限：≤60s 保证 5min oldest-age SLO 窗口内多次采样。
const MAX_SAMPLE_INTERVAL: Duration = Duration::from_secs(60);
/// sampler 扫描 domain 数上限（metrics `domain` label 基数闸）。
const MAX_DOMAINS: usize = 64;

/// sweeper 扫描间隔下限：非零 + 防热轮询 DELETE。
const MIN_SWEEP_INTERVAL: Duration = Duration::from_secs(1);

// ── RelayConfig ───────────────────────────────────────────────────────────────

/// [`RelayConfig`] 构造校验错误（构造期，非 wire；`#[non_exhaustive]` thiserror）。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum RelayConfigError {
    /// poll 间隔越界。
    #[error("relay poll_interval {got:?} out of range [{min:?}, {max:?}]")]
    PollIntervalOutOfRange {
        got: Duration,
        min: Duration,
        max: Duration,
    },
    /// 最大在途数越界。
    #[error("relay max_in_flight {got} out of range [{min}, {max}]")]
    MaxInFlightOutOfRange { got: usize, min: usize, max: usize },
}

/// relay 驱动配置；domain 由实现 [`consistency::OutboxSource`] 的 provider 自身绑定。
///
/// 私有字段 + 唯一 [`RelayConfig::new`] funnel（RELAY-CONFIG-01）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayConfig {
    poll_interval: Duration,
    max_in_flight: usize,
}

impl RelayConfig {
    /// 构造并 fail-fast 校验（poll 间隔、最大在途数越界即拒）。
    pub fn new(poll_interval: Duration, max_in_flight: usize) -> Result<Self, RelayConfigError> {
        if poll_interval < MIN_POLL_INTERVAL || poll_interval > MAX_POLL_INTERVAL {
            return Err(RelayConfigError::PollIntervalOutOfRange {
                got: poll_interval,
                min: MIN_POLL_INTERVAL,
                max: MAX_POLL_INTERVAL,
            });
        }
        if !(MIN_MAX_IN_FLIGHT..=MAX_MAX_IN_FLIGHT).contains(&max_in_flight) {
            return Err(RelayConfigError::MaxInFlightOutOfRange {
                got: max_in_flight,
                min: MIN_MAX_IN_FLIGHT,
                max: MAX_MAX_IN_FLIGHT,
            });
        }
        Ok(Self {
            poll_interval,
            max_in_flight,
        })
    }

    /// relay poll 间隔。
    pub fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    /// relay 单轮最大在途 claim/publish 数。
    pub fn max_in_flight(&self) -> usize {
        self.max_in_flight
    }
}

// ── SamplerConfig ─────────────────────────────────────────────────────────────

/// [`SamplerConfig`] 构造校验错误（构造期，非 wire；`#[non_exhaustive]` thiserror）。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SamplerConfigError {
    /// domain 数为空或超 [`MAX_DOMAINS`]。
    #[error("sampler domains count {got} out of range [1, {max}]")]
    DomainCount { got: usize, max: usize },
    /// 某 domain 非合法 [`DomainName`]（crate-name 形 `[a-z][a-z0-9_]*`，单源 vocab）。
    #[error(
        "sampler domain {domain:?} is not a valid DomainName (crate-name form [a-z][a-z0-9_]*)"
    )]
    DomainInvalid { domain: String },
    /// domain 集含重复（重复会双发 gauge，构造期拒）。
    #[error("sampler domains contain duplicate {domain:?}")]
    DomainDuplicate { domain: String },
    /// 采样间隔越界。
    #[error("sampler sample_interval {got:?} out of range [{min:?}, {max:?}]")]
    SampleIntervalOutOfRange {
        got: Duration,
        min: Duration,
        max: Duration,
    },
}

/// backlog sampler 驱动配置（SAMPLER-CONFIG-01）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamplerConfig {
    domains: Vec<DomainName>,
    sample_interval: Duration,
}

impl SamplerConfig {
    /// 构造并 fail-fast 校验（域数量、`DomainName` grammar、去重、采样间隔越界即拒）。
    pub fn new(
        domains: Vec<String>,
        sample_interval: Duration,
    ) -> Result<Self, SamplerConfigError> {
        if domains.is_empty() || domains.len() > MAX_DOMAINS {
            return Err(SamplerConfigError::DomainCount {
                got: domains.len(),
                max: MAX_DOMAINS,
            });
        }
        let mut parsed = Vec::with_capacity(domains.len());
        for raw in domains {
            let domain =
                DomainName::parse(&raw).map_err(|_| SamplerConfigError::DomainInvalid {
                    domain: raw.clone(),
                })?;
            if parsed.contains(&domain) {
                return Err(SamplerConfigError::DomainDuplicate { domain: raw });
            }
            parsed.push(domain);
        }
        if sample_interval < MIN_SAMPLE_INTERVAL || sample_interval > MAX_SAMPLE_INTERVAL {
            return Err(SamplerConfigError::SampleIntervalOutOfRange {
                got: sample_interval,
                min: MIN_SAMPLE_INTERVAL,
                max: MAX_SAMPLE_INTERVAL,
            });
        }
        Ok(Self {
            domains: parsed,
            sample_interval,
        })
    }

    /// 扫描的 domain 集（已校验数量、grammar、去重）。
    pub fn domains(&self) -> &[DomainName] {
        &self.domains
    }

    /// backlog 采样间隔。
    pub fn sample_interval(&self) -> Duration {
        self.sample_interval
    }
}

// ── SweeperConfig ─────────────────────────────────────────────────────────────

/// [`SweeperConfig`] 构造校验错误（构造期，非 wire）。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SweeperConfigError {
    /// `retain_seconds == 0`（会删除 just-published 行）。
    #[error("sweeper retain_seconds must be non-zero")]
    RetainZero,
    /// sweep 间隔低于下限（热轮询 DELETE 防护）。
    #[error("sweeper sweep_interval {got:?} below minimum {min:?}")]
    SweepIntervalTooSmall { got: Duration, min: Duration },
}

/// sweeper 驱动配置（私有字段 + 唯一 [`SweeperConfig::new`] funnel，SWEEPER-CONFIG-01）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweeperConfig {
    retain_seconds: u64,
    sweep_interval: Duration,
}

impl SweeperConfig {
    /// 构造并 fail-fast 校验（`retain_seconds` 非零、`sweep_interval` ≥ 下限）。
    pub fn new(retain_seconds: u64, sweep_interval: Duration) -> Result<Self, SweeperConfigError> {
        if retain_seconds == 0 {
            return Err(SweeperConfigError::RetainZero);
        }
        if sweep_interval < MIN_SWEEP_INTERVAL {
            return Err(SweeperConfigError::SweepIntervalTooSmall {
                got: sweep_interval,
                min: MIN_SWEEP_INTERVAL,
            });
        }
        Ok(Self {
            retain_seconds,
            sweep_interval,
        })
    }

    /// 已投递行保留秒数。
    pub fn retain_seconds(&self) -> u64 {
        self.retain_seconds
    }

    /// sweep 扫描间隔。
    pub fn sweep_interval(&self) -> Duration {
        self.sweep_interval
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── RelayConfig：表驱动越界拒绝 + happy 边界放行 ──────────────────────────
    #[test]
    fn relay_config_rejects_out_of_range_poll_interval() {
        let cases: &[(Duration, bool)] = &[
            (Duration::ZERO, false),
            (Duration::from_millis(50), false),
            (Duration::from_millis(99), false),
            (Duration::from_millis(100), true),
            (Duration::from_secs(300), true),
            (Duration::from_secs(301), false),
        ];
        for &(poll, ok) in cases {
            let got = RelayConfig::new(poll, 10);
            assert_eq!(got.is_ok(), ok, "poll_interval={poll:?}");
            if !ok {
                assert!(matches!(
                    got,
                    Err(RelayConfigError::PollIntervalOutOfRange { .. })
                ));
            }
        }
    }

    #[test]
    fn relay_config_rejects_out_of_range_max_in_flight() {
        let cases: &[(usize, bool)] = &[(0, false), (1, true), (64, true), (65, false)];
        for &(max_in_flight, ok) in cases {
            let got = RelayConfig::new(Duration::from_millis(100), max_in_flight);
            assert_eq!(got.is_ok(), ok, "max_in_flight={max_in_flight}");
            if !ok {
                assert!(matches!(
                    got,
                    Err(RelayConfigError::MaxInFlightOutOfRange { .. })
                ));
            }
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: 测试 happy-path 断言已知合法 config，item-level carve-out（error-handling.md §Carve-out）。
    fn relay_config_accessors_round_trip() {
        let cfg = RelayConfig::new(Duration::from_millis(250), 32).expect("valid config");
        assert_eq!(cfg.poll_interval(), Duration::from_millis(250));
        assert_eq!(cfg.max_in_flight(), 32);
    }

    // ── SamplerConfig：domain funnel + sample interval ───────────────────────
    #[test]
    fn sampler_config_rejects_out_of_range_sample_interval() {
        let cases: &[(Duration, bool)] = &[
            (Duration::ZERO, false),
            (Duration::from_millis(999), false),
            (Duration::from_secs(1), true),
            (Duration::from_secs(60), true),
            (Duration::from_secs(61), false),
        ];
        for &(sample, ok) in cases {
            let got = SamplerConfig::new(vec!["dom".into()], sample);
            assert_eq!(got.is_ok(), ok, "sample_interval={sample:?}");
            if !ok {
                assert!(matches!(
                    got,
                    Err(SamplerConfigError::SampleIntervalOutOfRange { .. })
                ));
            }
        }
    }

    #[test]
    fn sampler_config_rejects_domain_count() {
        assert_eq!(
            SamplerConfig::new(vec![], Duration::from_secs(15)),
            Err(SamplerConfigError::DomainCount { got: 0, max: 64 })
        );
        let many: Vec<String> = (0..65).map(|i| format!("dom_{i}")).collect();
        assert!(matches!(
            SamplerConfig::new(many, Duration::from_secs(15)),
            Err(SamplerConfigError::DomainCount { got: 65, max: 64 })
        ));
        assert!(SamplerConfig::new(vec!["dom".into()], Duration::from_secs(15)).is_ok());
        let exactly_64: Vec<String> = (0..64).map(|i| format!("dom_{i}")).collect();
        assert!(
            SamplerConfig::new(exactly_64, Duration::from_secs(15)).is_ok(),
            "exactly MAX_DOMAINS=64 must be accepted"
        );
    }

    #[test]
    fn sampler_config_rejects_invalid_domain() {
        let bad: &[&str] = &["Dom", "1dom", "-dom", "do-main", "do main", "do.main", ""];
        for &domain in bad {
            assert!(
                matches!(
                    SamplerConfig::new(vec![domain.into()], Duration::from_secs(15)),
                    Err(SamplerConfigError::DomainInvalid { .. })
                ),
                "expected DomainInvalid for {domain:?}"
            );
        }
        for &domain in &["dom", "test_domain", "identity", "domain1", "a_b_c2"] {
            assert!(
                SamplerConfig::new(vec![domain.into()], Duration::from_secs(15)).is_ok(),
                "expected Ok for {domain:?}"
            );
        }
    }

    #[test]
    fn sampler_config_rejects_duplicate_domain() {
        assert!(matches!(
            SamplerConfig::new(
                vec!["identity".into(), "settings".into(), "identity".into()],
                Duration::from_secs(15)
            ),
            Err(SamplerConfigError::DomainDuplicate { .. })
        ));
        assert!(
            SamplerConfig::new(
                vec!["identity".into(), "settings".into()],
                Duration::from_secs(15)
            )
            .is_ok()
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: 测试 happy-path 断言已知合法 config，item-level carve-out（error-handling.md §Carve-out）。
    fn sampler_config_accessors_round_trip() {
        let cfg = SamplerConfig::new(
            vec!["identity".into(), "settings".into()],
            Duration::from_secs(30),
        )
        .expect("valid config");
        let domain_strs: Vec<&str> = cfg.domains().iter().map(DomainName::as_str).collect();
        assert_eq!(domain_strs, vec!["identity", "settings"]);
        assert_eq!(cfg.sample_interval(), Duration::from_secs(30));
    }

    // ── SweeperConfig ────────────────────────────────────────────────────────
    #[test]
    fn sweeper_config_rejects_zero_retain() {
        assert_eq!(
            SweeperConfig::new(0, Duration::from_secs(60)),
            Err(SweeperConfigError::RetainZero)
        );
    }

    #[test]
    fn sweeper_config_rejects_small_sweep_interval() {
        let cases: &[(Duration, bool)] = &[
            (Duration::ZERO, false),
            (Duration::from_millis(999), false),
            (Duration::from_secs(1), true),
            (Duration::from_secs(3600), true), // 无上限：retention 周期可长
        ];
        for &(sweep, ok) in cases {
            let got = SweeperConfig::new(86_400, sweep);
            assert_eq!(got.is_ok(), ok, "sweep_interval={sweep:?}");
            if !ok {
                assert!(matches!(
                    got,
                    Err(SweeperConfigError::SweepIntervalTooSmall { .. })
                ));
            }
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: 测试 happy-path 断言已知合法 config，item-level carve-out（error-handling.md §Carve-out）。
    fn sweeper_config_accessors_round_trip() {
        let cfg = SweeperConfig::new(86_400, Duration::from_secs(120)).expect("valid");
        assert_eq!(cfg.retain_seconds(), 86_400);
        assert_eq!(cfg.sweep_interval(), Duration::from_secs(120));
    }
}
