//! 域 crate 装配单元。
//!
//! [`DomainBinding`] 是一个域 crate 在组合根层的单一所有权装配单元：域服务实例与其生命周期
//! 输出一同构造完成。组合根把 bindings 交给 [`compose_bindings`]；只有 [`Domain::init`] 全部成功后，
//! 受控出口才按值排空并返回聚合 output。
//!
//! [`Domain::init`]: crate::domain::Domain::init
//!
//! [`DomainModuleResult`] 是域能力的标准装配出口（ADR-010 §2.2）：`module()` / `wire_X` 的可聚合产物，
//! 组合根经 [`DomainModuleResult::merge`] / [`Extend`] 聚合各域 result 后排空到 sink。

use diport::DynManagedResource;
use primitives::ProbeName;
use tokio_util::sync::CancellationToken;

use crate::domain::Domain;
use crate::registry::HealthProbe;

/// 一个域 crate 的单一所有权装配单元。
///
/// `domain` 已持有构造好的域实例（所有必填依赖经构造器注入，缺失即编译错误），`output` 是该域
/// 唯一的生命周期输出。bootstrap 先按 binding 顺序借用 `domain` 完成声明聚合，再消费 `output`；
/// compose 失败不会提前转移 output 所有权。
///
/// ```compile_fail
/// use bootstrap::{Domain, DomainBinding, DomainModuleResult, KernelError, Registry};
///
/// struct NoopDomain;
/// impl Domain for NoopDomain {
///     fn init(&self, _registry: &mut Registry) -> Result<(), KernelError> {
///         Ok(())
///     }
/// }
///
/// let binding = DomainBinding::new(
///     "noop",
///     Box::new(NoopDomain),
///     DomainModuleResult::default(),
/// );
/// let _output = binding.output;
/// ```
pub struct DomainBinding {
    /// 域 crate 的标识名（用于日志 / 诊断，不作路由前缀）。
    name: &'static str,
    /// 已构造完成的域实例。
    domain: Box<dyn Domain>,
    /// 本域的生命周期输出；只含 probes / resources / workers，不承载 domain service 或 routes。
    output: DomainModuleResult,
}

impl DomainBinding {
    /// 建立一个尚未 compose 的 domain binding。
    pub fn new(name: &'static str, domain: Box<dyn Domain>, output: DomainModuleResult) -> Self {
        Self {
            name,
            domain,
            output,
        }
    }

    /// 域 crate 的静态诊断名。
    pub fn name(&self) -> &'static str {
        self.name
    }
}

/// 需要 per-stack cancel token 的后台 worker；组合根排空进 [`ShutdownStack::register_with_token`]。
///
/// [`ShutdownStack::register_with_token`]: crate::shutdown::ShutdownStack::register_with_token
pub type WorkerSpec = Box<dyn FnOnce(CancellationToken) -> Box<DynManagedResource<'static>> + Send>;

/// 域能力的标准装配出口（ADR-010 §2.2）：`module()` / `wire_X` 的可聚合产物，组合根经
/// [`DomainModuleResult::merge`] 聚合各域 result 后逐 `Vec` 排空到 sink，不再逐项手工接线。
///
/// 只携框架擦除的生命周期三出口 probes / resources / workers。`name` / `domain` 归 [`DomainBinding`]；
/// domain service 与 routes 不进入通用输出袋。域 service 留在 `wire_X` 内部经 typed route 闭包捕获——配合
/// `assemblies/runtime` 的 `wire_X(deps: &SharedRuntimeDeps) -> Result<DomainModuleResult>` 签名
/// （INVARIANT WIRING-DEPS-NO-HANDOFF-01，Hard）杜绝跨 module value handoff。
///
/// # provider 单源装配（#1498 / #1676）
///
/// Redis / S3 / Vault capability bundle 经 `runtime_resources(&self) ->
/// Vec<Box<DynManagedResource>>`（仅 `diport` 类型）单源派生受管资源；adapter **不依赖 bootstrap**。
/// 组合根以 crate-private `ProviderOutput` 把这些原语转换为本结构，再经
/// [`DomainModuleResult::merge`] 进入统一生命周期路径，避免暴露裸 channel 或逐项手写
/// `register_detached`（GoCell D5 多通道漂移根因）。PG readiness 还需要 interval / cancel token，不适用
/// 此 seam；#1677 已由 runtime-private、单次消费的显式 PG output 收口，且不实现通用 `ProviderOutput`。
/// AMQP 归 event-infra 生命周期，不把异质输出塞进宽泛 provider trait。
#[derive(Default)]
pub struct DomainModuleResult {
    /// readiness / liveness 探针，组合根排空进 [`Registry::probe`]（须先于 `take_health_reporter`，readyz 才聚合）。
    ///
    /// [`Registry::probe`]: crate::registry::Registry::probe
    pub probes: Vec<(ProbeName, Box<dyn HealthProbe>)>,
    /// 无后台任务的 detached 受管资源，排空进 [`ShutdownStack::register_detached`]。
    ///
    /// [`ShutdownStack::register_detached`]: crate::shutdown::ShutdownStack::register_detached
    pub resources: Vec<Box<DynManagedResource<'static>>>,
    /// 需 cancel token 的后台 worker，排空进 [`ShutdownStack::register_with_token`]。
    ///
    /// [`ShutdownStack::register_with_token`]: crate::shutdown::ShutdownStack::register_with_token
    pub workers: Vec<WorkerSpec>,
}

impl DomainModuleResult {
    /// 把另一个域的产物聚合进来（跨域统一 fold；组合根只聚合 result，ADR-010 §2.2）。
    ///
    /// 这是契约唯一聚合原语——未来域只需多一行 `module.merge(wire_X(&deps).await?)`，组合根形态恒定。
    pub fn merge(&mut self, other: DomainModuleResult) {
        self.probes.extend(other.probes);
        self.resources.extend(other.resources);
        self.workers.extend(other.workers);
    }
}

impl Extend<DomainModuleResult> for DomainModuleResult {
    fn extend<T: IntoIterator<Item = DomainModuleResult>>(&mut self, iter: T) {
        for result in iter {
            self.merge(result);
        }
    }
}

/// 按 binding 顺序 fail-fast compose，并仅在成功后返回聚合生命周期输出。
///
/// `bindings` 是未 compose 状态的唯一 owner。字段私有使调用方无法提前取得 output；compose 成功后
/// 本函数按值排空全部 bindings 并保序聚合 output，失败则在 drain 前返回，bindings 与 outputs 原样保留。
pub fn compose_bindings(
    bindings: &mut Vec<DomainBinding>,
) -> Result<(crate::registry::Registry, DomainModuleResult), crate::domain::KernelError> {
    let registry = {
        let domains: Vec<&dyn Domain> = bindings
            .iter()
            .map(|binding| binding.domain.as_ref())
            .collect();
        crate::domain::compose(&domains)?
    };

    let mut output = DomainModuleResult::default();
    output.extend(bindings.drain(..).map(|binding| binding.output));
    Ok((registry, output))
}

#[cfg(test)]
mod result_tests {
    use super::*;

    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use diport::{ManagedResource as _, ShutdownError};
    use primitives::{HealthCheck, HealthStatus};

    use crate::domain::KernelError;

    /// 测试探针替身（impl `HealthProbe`；`check` 固定 Healthy，仅供聚合计数断言）。
    struct NoopProbe;
    impl HealthProbe for NoopProbe {
        fn check(&self) -> HealthCheck {
            // reason: 测试常量名；ProbeName::parse 仅失败于非法字符集，此处恒合法。
            #[allow(clippy::expect_used)]
            let name = ProbeName::parse("noop").expect("valid probe name");
            HealthCheck::new(name, HealthStatus::Healthy, "noop")
        }
    }

    /// 测试受管资源替身（impl `ManagedResource`；shutdown 永不被测试调用）。
    struct NoopResource;
    impl diport::ManagedResource for NoopResource {
        fn name(&self) -> &str {
            "noop-resource"
        }
        async fn shutdown(&self) -> Result<(), ShutdownError> {
            // reason: 仅供 merge 计数断言构造 Box；测试不 await shutdown。
            Ok(())
        }
    }

    #[allow(clippy::expect_used)]
    fn probe_entry() -> (ProbeName, Box<dyn HealthProbe>) {
        (
            ProbeName::parse("noop").expect("valid probe name"),
            Box::new(NoopProbe),
        )
    }

    fn resource_entry() -> Box<DynManagedResource<'static>> {
        DynManagedResource::new_box(NoopResource)
    }

    fn worker_entry() -> WorkerSpec {
        Box::new(|_token| DynManagedResource::new_box(NoopResource))
    }

    struct DeclaringDomain(&'static str);

    impl Domain for DeclaringDomain {
        fn init(&self, reg: &mut crate::Registry) -> Result<(), KernelError> {
            reg.probe(probe_name(self.0), Box::new(LabeledProbe(self.0)))
        }
    }

    struct FailingDomain;

    impl Domain for FailingDomain {
        fn init(&self, _reg: &mut crate::Registry) -> Result<(), KernelError> {
            Err(KernelError::Invariant)
        }
    }

    struct LabeledProbe(&'static str);

    impl HealthProbe for LabeledProbe {
        fn check(&self) -> HealthCheck {
            HealthCheck::new(probe_name(self.0), HealthStatus::Healthy, "test")
        }
    }

    struct LabeledResource(&'static str);

    impl diport::ManagedResource for LabeledResource {
        fn name(&self) -> &str {
            self.0
        }

        async fn shutdown(&self) -> Result<(), ShutdownError> {
            Ok(())
        }
    }

    #[allow(clippy::expect_used)]
    fn probe_name(label: &str) -> ProbeName {
        ProbeName::parse(label).expect("test probe name must be valid")
    }

    fn labeled_probe(label: &'static str) -> (ProbeName, Box<dyn HealthProbe>) {
        (probe_name(label), Box::new(LabeledProbe(label)))
    }

    fn labeled_resource(label: &'static str) -> Box<DynManagedResource<'static>> {
        DynManagedResource::new_box(LabeledResource(label))
    }

    fn labeled_worker(label: &'static str) -> WorkerSpec {
        Box::new(move |_token| labeled_resource(label))
    }

    fn labeled_result(label: &'static str) -> DomainModuleResult {
        DomainModuleResult {
            probes: vec![labeled_probe(label)],
            resources: vec![labeled_resource(label)],
            workers: vec![labeled_worker(label)],
        }
    }

    /// `Default` 产出空结果（三 Vec 皆空）。
    #[test]
    fn default_is_empty() {
        let r = DomainModuleResult::default();
        assert!(r.probes.is_empty());
        assert!(r.resources.is_empty());
        assert!(r.workers.is_empty());
    }

    /// `merge` 把另一结果的三类产物全部 extend 进来（跨域聚合）。
    #[test]
    fn merge_extends_all_vecs() {
        let mut base = DomainModuleResult {
            probes: vec![probe_entry()],
            resources: vec![resource_entry()],
            workers: vec![worker_entry()],
        };
        let other = DomainModuleResult {
            probes: vec![probe_entry(), probe_entry()],
            resources: vec![resource_entry()],
            workers: vec![worker_entry(), worker_entry()],
        };

        base.merge(other);

        assert_eq!(base.probes.len(), 3, "probes 累加");
        assert_eq!(base.resources.len(), 2, "resources 累加");
        assert_eq!(base.workers.len(), 3, "workers 累加");
    }

    /// `DomainModuleResult` 必须 `Send`（组合根 `merge` / drain 跨 await 持有）。
    #[test]
    fn domain_module_result_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<DomainModuleResult>();
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn compose_bindings_returns_outputs_only_after_success() {
        let mut bindings = vec![
            DomainBinding::new(
                "first",
                Box::new(DeclaringDomain("first.init")),
                labeled_result("first.output"),
            ),
            DomainBinding::new(
                "second",
                Box::new(DeclaringDomain("second.init")),
                labeled_result("second.output"),
            ),
        ];

        let (registry, output) =
            compose_bindings(&mut bindings).expect("domain declarations must compose");
        assert!(
            bindings.is_empty(),
            "success must consume all bindings once"
        );
        let report = registry.readyz_report();
        let init_order: Vec<&str> = report
            .checks()
            .iter()
            .map(|check| check.name().as_str())
            .collect();
        assert_eq!(init_order, ["first.init", "second.init"]);

        let output_order: Vec<&str> = output
            .probes
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        assert_eq!(output_order, ["first.output", "second.output"]);
    }

    #[test]
    fn compose_failure_does_not_consume_binding_output() {
        let mut bindings = vec![DomainBinding::new(
            "failing",
            Box::new(FailingDomain),
            labeled_result("still-owned"),
        )];

        assert!(compose_bindings(&mut bindings).is_err());
        assert_eq!(bindings.len(), 1, "failure must not drain bindings");
        assert_eq!(bindings[0].name(), "failing");

        let output = std::mem::take(&mut bindings[0].output);
        assert_eq!(output.probes[0].0.as_str(), "still-owned");
        assert_eq!(output.resources[0].name(), "still-owned");
        assert_eq!(
            output.workers.into_iter().next().map(|worker| {
                let resource = worker(CancellationToken::new());
                resource.name().to_owned()
            }),
            Some("still-owned".to_owned())
        );
    }

    #[test]
    fn extend_preserves_channel_order_empty_results_and_duplicates() {
        let results = vec![
            labeled_result("first"),
            DomainModuleResult::default(),
            labeled_result("duplicate"),
            labeled_result("duplicate"),
            DomainModuleResult::default(),
            labeled_result("last"),
        ];

        let mut output = DomainModuleResult::default();
        output.extend(results);
        let expected = ["first", "duplicate", "duplicate", "last"];
        let probe_order: Vec<&str> = output
            .probes
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        let resource_order: Vec<&str> = output
            .resources
            .iter()
            .map(|resource| resource.name())
            .collect();
        let worker_order: Vec<String> = output
            .workers
            .into_iter()
            .map(|worker| worker(CancellationToken::new()).name().to_owned())
            .collect();

        assert_eq!(probe_order, expected);
        assert_eq!(resource_order, expected);
        assert_eq!(
            worker_order,
            expected.map(str::to_owned),
            "FnOnce workers must move in input order"
        );

        let mut identity = DomainModuleResult::default();
        identity.extend([DomainModuleResult::default()]);
        assert!(identity.probes.is_empty());
        assert!(identity.resources.is_empty());
        assert!(identity.workers.is_empty());
    }

    #[test]
    fn extend_preserves_single_non_empty_result() {
        let mut output = DomainModuleResult::default();
        output.extend([labeled_result("only")]);

        assert_eq!(output.probes.len(), 1);
        assert_eq!(output.probes[0].0.as_str(), "only");
        assert_eq!(output.resources.len(), 1);
        assert_eq!(output.resources[0].name(), "only");
        assert_eq!(output.workers.len(), 1);
        let worker_labels: Vec<String> = output
            .workers
            .into_iter()
            .map(|worker| worker(CancellationToken::new()).name().to_owned())
            .collect();
        assert_eq!(worker_labels, ["only"]);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn worker_is_moved_and_invoked_once() {
        let calls = Arc::new(AtomicUsize::new(0));
        let worker_calls = Arc::clone(&calls);
        let worker: WorkerSpec = Box::new(move |_token| {
            worker_calls.fetch_add(1, Ordering::SeqCst);
            labeled_resource("single-use")
        });
        let mut output = DomainModuleResult {
            workers: vec![worker],
            ..DomainModuleResult::default()
        };

        let worker = output.workers.pop().expect("worker must be present");
        let resource = worker(CancellationToken::new());

        assert_eq!(resource.name(), "single-use");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(output.workers.is_empty());
    }

    #[test]
    fn binding_concurrency_contracts_are_explicit() {
        fn assert_send<T: Send>() {}
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<Box<dyn Domain>>();
        assert_send::<DomainModuleResult>();
        assert_send::<DomainBinding>();
    }
}
