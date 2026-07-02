//! Outbox relay/sampler 可观测性发射端口（#1209，service-internal seam）。
//!
//! [`OutboxMetrics`] 是 relay/sampler loop 注入式发射接缝：生产传 [`MetricsOutboxMetrics`]
//! （`metrics` facade 硬依赖、无 feature 门），测试传 counting fake 做确定性断言。**定义在本服务
//! crate**（签名引 `consistency::Disposition` / `consistency::BacklogSample` 引擎类型）——按 ADR-005
//! category line 非 provider-agnostic infra port，不归 `diport`；且 `eventexec`（Service 层）依层矩阵
//! `allows(Service,Service)=false` 不能依赖 `observ`，故 label 闭值集经 crate 自有 `as_label()` 闭映射
//! （status=`Disposition::as_label()`、phase=[`RelayPhase::as_label`]），domain 由
//! [`crate::relay_config::RelayConfig`] 构造期数量/格式校验 515 住基数（#1076 对齐），tenant/contract
//! 由 `consistency::OutboxMetricSubject` typed scope 收口。
//!
//! metric 名（bare，对齐 `observability.md` §Metrics Label 的 `reconcile_total` / `idempotency_requests_total`）：
//! - `outbox_publish_total{domain,contract_id,tenant_id,status}`（Counter）—— relay 单条结算处置。
//! - `outbox_dlx_total{domain,contract_id,tenant_id}`（Counter）—— `Reject`（永久失败进 DLX）。
//! - `outbox_pending_depth{domain,contract_id,tenant_id}` /
//!   `outbox_oldest_pending_age_seconds{domain,contract_id,tenant_id}`（Gauge）—— 采样器。
//! - `outbox_relay_tick_duration_seconds{phase}`（Histogram，phase=poll|publish）—— relay tick 分相耗时。
//!
//! # INVARIANT: OUTBOX-METRICS-PORT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
//!
//! [`OutboxMetrics`] 归属 `eventexec`（Service 层）**不可迁 `diport`**：签名引 `consistency::Disposition` /
//! `consistency::BacklogSample`（Engine 类型），按 ADR-005 category line 判据「此 port 能否在 `diport` 内
//! 编译而不让 diport 依赖引擎？」→ 不能 → 归定义域（同 `consistency::outbox` 的 OUTBOX-ENGINE-PORT-01）。
//! 它是 service-internal 发射接缝、非 provider-agnostic DI infra port。

use consistency::{BacklogSample, Disposition, OutboxMetricSubject};
use vocab::DomainName;

/// relay tick 计时相位闭值集（histogram `phase` label）。
///
/// settle（CAS 落库）是 adapter 内部、对 eventexec 不可见，故 `Publish` 相涵盖 `relay()` 端到端
/// （publish + adapter 内 settle）；只分 poll/publish 两相。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayPhase {
    /// `poll_pending` 扫描相。
    Poll,
    /// 逐条 `relay()`（含 adapter 内 settle）相。
    Publish,
}

impl RelayPhase {
    /// 稳定低基数 label（crate-owned 闭映射）。
    pub fn as_label(self) -> &'static str {
        match self {
            RelayPhase::Poll => "poll",
            RelayPhase::Publish => "publish",
        }
    }
}

/// Outbox metric scope：domain + tenant + contract 三维标签的唯一 typed 入口。
#[derive(Debug, Clone, Copy)]
pub struct OutboxMetricScope<'a> {
    domain: &'a DomainName,
    subject: &'a OutboxMetricSubject,
}

impl<'a> OutboxMetricScope<'a> {
    /// 组合 config domain 与 outbox row subject。
    pub fn new(domain: &'a DomainName, subject: &'a OutboxMetricSubject) -> Self {
        Self { domain, subject }
    }

    /// metric `domain` label。
    pub fn domain_label(&self) -> &'a str {
        self.domain.as_str()
    }

    /// metric `contract_id` label。
    pub fn contract_id_label(&self) -> &'a str {
        self.subject.contract_id().as_str()
    }

    /// metric `tenant_id` label。
    pub fn tenant_id_label(&self) -> String {
        self.subject.tenant_id().to_string()
    }
}

/// Outbox relay/sampler 发射端口（注入式；`Send + Sync` 供 spawned worker task 跨线程持有）。
///
/// label scope 收 typed [`OutboxMetricScope`]（**非** raw triple）——把低基数 label 闭值集封在 public port
/// 边界（外部调用方无法绕过 `DomainName` / `OutboxContractId` / `TenantId` funnel 传任意串）；发射处才降级。
pub trait OutboxMetrics: Send + Sync {
    /// relay 单条结算：按 `disposition` 记 `outbox_publish_total`；`Reject` 同时记 `outbox_dlx_total`。
    fn record_publish(&self, scope: &OutboxMetricScope<'_>, disposition: Disposition);

    /// 采样器：set `outbox_pending_depth` / `outbox_oldest_pending_age_seconds` gauge。
    fn record_backlog(&self, scope: &OutboxMetricScope<'_>, sample: BacklogSample);

    /// relay tick 分相耗时：observe `outbox_relay_tick_duration_seconds{phase}` histogram。
    fn record_tick_duration(&self, phase: RelayPhase, seconds: f64);
}

/// `metrics` facade-backed 生产发射端口（**唯一** `OutboxMetrics` production 实现）。
///
/// 经进程级 global recorder 发射（`metrics::counter!/gauge!/histogram!`）；组合根注入
/// `Arc::new(MetricsOutboxMetrics)`，并自行决定是否装 recorder（`adapters/prometheus` `PromExporter`）——
/// 装则导出 `/metrics`，不装则 `metrics` facade 自身 no-op（idiomatic：库无条件发射，executable 选 recorder）。
/// **不提供 public no-op 实现**：杜绝生产误注入 no-op 致告警静默（#1209 review F3 fail-closed）。测试用
/// counting fake 做确定性断言。动态 label 经 macro runtime arm 传 `String`——基数已由 typed scope 封边。
pub struct MetricsOutboxMetrics;

impl OutboxMetrics for MetricsOutboxMetrics {
    fn record_publish(&self, scope: &OutboxMetricScope<'_>, disposition: Disposition) {
        // 在发射处才降到 owned String（macro runtime label arm）；typed 边界已封基数。
        let domain = scope.domain_label().to_owned();
        let contract_id = scope.contract_id_label().to_owned();
        let tenant_id = scope.tenant_id_label();
        metrics::counter!(
            "outbox_publish_total",
            "domain" => domain.clone(),
            "contract_id" => contract_id.clone(),
            "tenant_id" => tenant_id.clone(),
            "status" => disposition.as_label(),
        )
        .increment(1);
        if disposition == Disposition::Reject {
            metrics::counter!(
                "outbox_dlx_total",
                "domain" => domain,
                "contract_id" => contract_id,
                "tenant_id" => tenant_id,
            )
            .increment(1);
        }
    }

    fn record_backlog(&self, scope: &OutboxMetricScope<'_>, sample: BacklogSample) {
        let domain = scope.domain_label().to_owned();
        let contract_id = scope.contract_id_label().to_owned();
        let tenant_id = scope.tenant_id_label();
        metrics::gauge!(
            "outbox_pending_depth",
            "domain" => domain.clone(),
            "contract_id" => contract_id.clone(),
            "tenant_id" => tenant_id.clone(),
        )
        .set(sample.depth() as f64);
        metrics::gauge!(
            "outbox_oldest_pending_age_seconds",
            "domain" => domain,
            "contract_id" => contract_id,
            "tenant_id" => tenant_id,
        )
        .set(sample.oldest_age_seconds() as f64);
    }

    fn record_tick_duration(&self, phase: RelayPhase, seconds: f64) {
        metrics::histogram!("outbox_relay_tick_duration_seconds", "phase" => phase.as_label())
            .record(seconds);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consistency::OutboxContractId;

    /// 解析测试 domain（合法 DomainName）。
    #[allow(clippy::expect_used)]
    // reason: 测试 happy-path 已知合法 domain，item-level carve-out（error-handling.md §Carve-out）。
    fn dn(s: &str) -> DomainName {
        DomainName::parse(s).expect("valid test domain")
    }

    #[allow(clippy::expect_used)]
    // reason: 测试 happy-path 已知合法 subject。
    fn subject() -> OutboxMetricSubject {
        OutboxMetricSubject::new(
            vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
                .expect("valid test tenant"),
            OutboxContractId::parse("identity.session-created").expect("valid test contract"),
        )
    }

    #[test]
    fn relay_phase_as_label_distinct() {
        assert_eq!(RelayPhase::Poll.as_label(), "poll");
        assert_eq!(RelayPhase::Publish.as_label(), "publish");
        assert_ne!(RelayPhase::Poll.as_label(), RelayPhase::Publish.as_label());
    }

    // facade 发射：同线程 with_local_recorder 断言 metric 名/label 出现（含 Reject → publish+dlx 双记）。
    #[test]
    fn metrics_facade_emits_publish_and_dlx_on_reject() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            let m = MetricsOutboxMetrics;
            let domain = dn("identity");
            let subject = subject();
            let scope = OutboxMetricScope::new(&domain, &subject);
            m.record_publish(&scope, Disposition::Reject);
            m.record_backlog(&scope, BacklogSample::new(7, 305));
            m.record_tick_duration(RelayPhase::Publish, 0.25);
        });
        let rendered = handle.render();
        assert!(rendered.contains("outbox_publish_total"), "{rendered}");
        assert!(rendered.contains("outbox_dlx_total"), "{rendered}");
        assert!(rendered.contains("contract_id"), "{rendered}");
        assert!(rendered.contains("identity.session-created"), "{rendered}");
        assert!(rendered.contains("tenant_id"), "{rendered}");
        assert!(
            rendered.contains("f47ac10b-58cc-4372-a567-0e02b2c3d479"),
            "{rendered}"
        );
        assert!(rendered.contains("reject"), "{rendered}");
        assert!(rendered.contains("outbox_pending_depth"), "{rendered}");
        assert!(
            rendered.contains("outbox_oldest_pending_age_seconds"),
            "{rendered}"
        );
        assert!(
            rendered.contains("outbox_relay_tick_duration_seconds"),
            "{rendered}"
        );
    }

    // facade：Ack/Requeue 不记 dlx（dlx 仅 Reject）——逐非-Reject 处置覆盖 if 分支假路径。
    #[test]
    fn metrics_facade_non_reject_does_not_emit_dlx() {
        for disposition in [Disposition::Ack, Disposition::Requeue] {
            let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
            let handle = recorder.handle();
            metrics::with_local_recorder(&recorder, || {
                let domain = dn("settings");
                let subject = subject();
                let scope = OutboxMetricScope::new(&domain, &subject);
                MetricsOutboxMetrics.record_publish(&scope, disposition);
            });
            let rendered = handle.render();
            assert!(rendered.contains("outbox_publish_total"), "{rendered}");
            assert!(
                !rendered.contains("outbox_dlx_total"),
                "non-reject {} must not emit dlx: {rendered}",
                disposition.as_label()
            );
        }
    }
}
