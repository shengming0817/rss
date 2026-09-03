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

use diport::{DynManagedResource, ManagedTaskRegistration};
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

/// 带闭合 admission shutdown policy 的后台 worker。
///
/// 生产构造点必须显式选择 phase-one 广播或自身 LIFO 相位取消；无默认 variant、裸 factory alias
/// 或动态 policy 字符串。runtime sink 对本枚举穷尽 match，把两种 policy 分别送入唯一 token funnel。
pub enum WorkerSpec {
    /// shutdown phase-one 立即取消，适用于 readiness、sampler、sweeper 等不接收业务事务的 task。
    PhaseOne(WorkerRegistration),
    /// 等后注册资源完成 LIFO drain 后，到本 worker 自身相位才取消并 join。
    Deferred(WorkerRegistration),
}

pub struct WorkerRegistration {
    descriptor: WorkerDescriptor,
    make: WorkerFactory,
}

enum WorkerFactory {
    Resource(Box<dyn FnOnce(CancellationToken) -> Box<DynManagedResource<'static>> + Send>),
    ManagedTask(Box<dyn FnOnce(CancellationToken) -> ManagedTaskRegistration + Send>),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WorkerAdmissionLane {
    Observational,
    Relay,
    Consumer,
    Writes,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WorkerDescriptor {
    pub lane: WorkerAdmissionLane,
    pub identity: String,
}

impl WorkerRegistration {
    pub fn descriptor(&self) -> WorkerDescriptor {
        self.descriptor.clone()
    }
    fn register_phase_one(
        self,
        stack: &mut crate::shutdown::ShutdownStack,
    ) -> Option<diport::TaskStatus> {
        match self.make {
            WorkerFactory::Resource(make) => {
                stack.register_with_token(make);
                None
            }
            WorkerFactory::ManagedTask(make) => Some(stack.register_managed_task_with_token(make)),
        }
    }

    fn register_deferred(
        self,
        stack: &mut crate::shutdown::ShutdownStack,
    ) -> Option<diport::TaskStatus> {
        match self.make {
            WorkerFactory::Resource(make) => {
                stack.register_deferred_with_token(make);
                None
            }
            WorkerFactory::ManagedTask(make) => {
                Some(stack.register_deferred_managed_task_with_token(make))
            }
        }
    }
}

impl WorkerSpec {
    fn registration<F>(
        identity: impl Into<String>,
        lane: WorkerAdmissionLane,
        make: F,
    ) -> WorkerRegistration
    where
        F: FnOnce(CancellationToken) -> Box<DynManagedResource<'static>> + Send + 'static,
    {
        let identity = identity.into();
        assert!(!identity.is_empty(), "worker identity must not be empty");
        WorkerRegistration {
            descriptor: WorkerDescriptor { lane, identity },
            make: WorkerFactory::Resource(Box::new(make)),
        }
    }

    fn managed_registration<F>(
        identity: impl Into<String>,
        lane: WorkerAdmissionLane,
        make: F,
    ) -> WorkerRegistration
    where
        F: FnOnce(CancellationToken) -> ManagedTaskRegistration + Send + 'static,
    {
        let identity = identity.into();
        assert!(!identity.is_empty(), "worker identity must not be empty");
        WorkerRegistration {
            descriptor: WorkerDescriptor { lane, identity },
            make: WorkerFactory::ManagedTask(Box::new(make)),
        }
    }

    #[track_caller]
    pub fn managed_observational_phase_one<F>(identity: impl Into<String>, make: F) -> Self
    where
        F: FnOnce(CancellationToken) -> ManagedTaskRegistration + Send + 'static,
    {
        Self::PhaseOne(Self::managed_registration(
            identity,
            WorkerAdmissionLane::Observational,
            make,
        ))
    }

    #[track_caller]
    pub fn managed_observational_deferred<F>(identity: impl Into<String>, make: F) -> Self
    where
        F: FnOnce(CancellationToken) -> ManagedTaskRegistration + Send + 'static,
    {
        Self::Deferred(Self::managed_registration(
            identity,
            WorkerAdmissionLane::Observational,
            make,
        ))
    }

    #[track_caller]
    pub fn observational_phase_one<F>(identity: impl Into<String>, make: F) -> Self
    where
        F: FnOnce(CancellationToken) -> Box<DynManagedResource<'static>> + Send + 'static,
    {
        Self::PhaseOne(Self::registration(
            identity,
            WorkerAdmissionLane::Observational,
            make,
        ))
    }

    #[track_caller]
    pub fn observational_deferred<F>(identity: impl Into<String>, make: F) -> Self
    where
        F: FnOnce(CancellationToken) -> Box<DynManagedResource<'static>> + Send + 'static,
    {
        Self::Deferred(Self::registration(
            identity,
            WorkerAdmissionLane::Observational,
            make,
        ))
    }

    #[track_caller]
    pub fn relay_deferred<F>(
        identity: impl Into<String>,
        gate: &primitives::RelayAdmission,
        make: F,
    ) -> Self
    where
        F: FnOnce(
                CancellationToken,
                primitives::RelayAdmission,
            ) -> Box<DynManagedResource<'static>>
            + Send
            + 'static,
    {
        let gate = gate.clone();
        Self::Deferred(Self::registration(
            identity,
            WorkerAdmissionLane::Relay,
            move |token| make(token, gate),
        ))
    }

    #[track_caller]
    pub fn relay_phase_one<F>(
        identity: impl Into<String>,
        gate: &primitives::RelayAdmission,
        make: F,
    ) -> Self
    where
        F: FnOnce(
                CancellationToken,
                primitives::RelayAdmission,
            ) -> Box<DynManagedResource<'static>>
            + Send
            + 'static,
    {
        let gate = gate.clone();
        Self::PhaseOne(Self::registration(
            identity,
            WorkerAdmissionLane::Relay,
            move |token| make(token, gate),
        ))
    }

    #[track_caller]
    pub fn consumer_phase_one<F>(
        identity: impl Into<String>,
        gate: &primitives::ConsumerAdmission,
        make: F,
    ) -> Self
    where
        F: FnOnce(
                CancellationToken,
                primitives::ConsumerAdmission,
            ) -> Box<DynManagedResource<'static>>
            + Send
            + 'static,
    {
        let gate = gate.clone();
        Self::PhaseOne(Self::registration(
            identity,
            WorkerAdmissionLane::Consumer,
            move |token| make(token, gate),
        ))
    }

    #[track_caller]
    pub fn consumer_deferred<F>(
        identity: impl Into<String>,
        gate: &primitives::ConsumerAdmission,
        make: F,
    ) -> Self
    where
        F: FnOnce(
                CancellationToken,
                primitives::ConsumerAdmission,
            ) -> Box<DynManagedResource<'static>>
            + Send
            + 'static,
    {
        let gate = gate.clone();
        Self::Deferred(Self::registration(
            identity,
            WorkerAdmissionLane::Consumer,
            move |token| make(token, gate),
        ))
    }

    #[track_caller]
    pub fn writes_phase_one<F>(
        identity: impl Into<String>,
        gate: &primitives::WriteAdmission,
        make: F,
    ) -> Self
    where
        F: FnOnce(
                CancellationToken,
                primitives::WriteAdmission,
            ) -> Box<DynManagedResource<'static>>
            + Send
            + 'static,
    {
        let gate = gate.clone();
        Self::PhaseOne(Self::registration(
            identity,
            WorkerAdmissionLane::Writes,
            move |token| make(token, gate),
        ))
    }

    #[track_caller]
    pub fn writes_deferred<F>(
        identity: impl Into<String>,
        gate: &primitives::WriteAdmission,
        make: F,
    ) -> Self
    where
        F: FnOnce(
                CancellationToken,
                primitives::WriteAdmission,
            ) -> Box<DynManagedResource<'static>>
            + Send
            + 'static,
    {
        let gate = gate.clone();
        Self::Deferred(Self::registration(
            identity,
            WorkerAdmissionLane::Writes,
            move |token| make(token, gate),
        ))
    }

    pub fn descriptor(&self) -> WorkerDescriptor {
        match self {
            Self::PhaseOne(r) | Self::Deferred(r) => r.descriptor(),
        }
    }

    /// Consume this closed worker policy into the sole shutdown owner.
    #[must_use = "managed worker status must be supervised by the runtime executor"]
    pub fn register_into(
        self,
        stack: &mut crate::shutdown::ShutdownStack,
    ) -> Option<diport::TaskStatus> {
        match self {
            Self::PhaseOne(registration) => registration.register_phase_one(stack),
            Self::Deferred(registration) => registration.register_deferred(stack),
        }
    }
}

/// Stable, startup-time proof of the exact worker set about to be spawned.
pub fn validate_worker_inventory<'a>(
    workers: impl IntoIterator<Item = &'a WorkerSpec>,
) -> Result<WorkerInventory, WorkerInventoryError> {
    let mut descriptors: Vec<_> = workers.into_iter().map(WorkerSpec::descriptor).collect();
    descriptors.sort_unstable();
    let mut digest = 0xcbf29ce484222325_u64;
    for descriptor in &descriptors {
        for byte in format!("{:?}:{}\n", descriptor.lane, descriptor.identity).bytes() {
            digest ^= u64::from(byte);
            digest = digest.wrapping_mul(0x100000001b3);
        }
    }
    if let Some(pair) = descriptors
        .windows(2)
        .find(|pair| pair[0].identity == pair[1].identity)
    {
        return Err(WorkerInventoryError::DuplicateIdentity(
            pair[0].identity.clone(),
        ));
    }
    Ok(WorkerInventory {
        descriptors,
        digest,
    })
}

pub fn validate_worker_inventory_exact<'a>(
    workers: impl IntoIterator<Item = &'a WorkerSpec>,
    expected: &ExpectedWorkerInventory,
) -> Result<WorkerInventory, WorkerInventoryError> {
    let inventory = validate_worker_inventory(workers)?;
    let mutating =
        |descriptor: &&WorkerDescriptor| descriptor.lane != WorkerAdmissionLane::Observational;
    for descriptor in inventory.descriptors.iter().filter(mutating) {
        match expected
            .descriptors
            .iter()
            .find(|candidate| candidate.identity == descriptor.identity)
        {
            None => return Err(WorkerInventoryError::Unexpected(descriptor.clone())),
            Some(candidate) if candidate.lane != descriptor.lane => {
                return Err(WorkerInventoryError::WrongLane {
                    identity: descriptor.identity.clone(),
                    expected: candidate.lane,
                    actual: descriptor.lane,
                });
            }
            Some(_) => {}
        }
    }
    if let Some(missing) = expected.descriptors.iter().find(|candidate| {
        candidate.lane != WorkerAdmissionLane::Observational
            && !inventory
                .descriptors
                .iter()
                .filter(mutating)
                .any(|descriptor| descriptor.identity == candidate.identity)
    }) {
        return Err(WorkerInventoryError::Missing(missing.clone()));
    }
    Ok(inventory)
}

/// Validate the complete worker set, including observational workers.
pub fn validate_worker_inventory_closed<'a>(
    workers: impl IntoIterator<Item = &'a WorkerSpec>,
    expected: &ExpectedWorkerInventory,
) -> Result<WorkerInventory, WorkerInventoryError> {
    let inventory = validate_worker_inventory(workers)?;
    if let Some(unexpected) = inventory
        .descriptors
        .iter()
        .find(|descriptor| !expected.descriptors.contains(descriptor))
    {
        return Err(WorkerInventoryError::Unexpected(unexpected.clone()));
    }
    if let Some(missing) = expected
        .descriptors
        .iter()
        .find(|descriptor| !inventory.descriptors.contains(descriptor))
    {
        return Err(WorkerInventoryError::Missing(missing.clone()));
    }
    Ok(inventory)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedWorkerInventory {
    descriptors: Vec<WorkerDescriptor>,
}

impl ExpectedWorkerInventory {
    pub fn closed(
        descriptors: impl IntoIterator<Item = WorkerDescriptor>,
    ) -> Result<Self, WorkerInventoryError> {
        let mut descriptors: Vec<_> = descriptors.into_iter().collect();
        descriptors.sort_unstable();
        if let Some(pair) = descriptors
            .windows(2)
            .find(|pair| pair[0].identity == pair[1].identity)
        {
            return Err(WorkerInventoryError::DuplicateExpectedIdentity(
                pair[0].identity.clone(),
            ));
        }
        Ok(Self { descriptors })
    }
}

impl WorkerDescriptor {
    pub fn expected(identity: impl Into<String>, lane: WorkerAdmissionLane) -> Self {
        Self {
            identity: identity.into(),
            lane,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct WorkerInventory {
    pub descriptors: Vec<WorkerDescriptor>,
    pub digest: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum WorkerInventoryError {
    #[error("duplicate worker identity: {0}")]
    DuplicateIdentity(String),
    #[error("duplicate expected worker identity: {0}")]
    DuplicateExpectedIdentity(String),
    #[error("unexpected worker: {0:?}")]
    Unexpected(WorkerDescriptor),
    #[error("missing worker: {0:?}")]
    Missing(WorkerDescriptor),
    #[error("worker {identity} has wrong lane: expected {expected:?}, actual {actual:?}")]
    WrongLane {
        identity: String,
        expected: WorkerAdmissionLane,
        actual: WorkerAdmissionLane,
    },
}

/// 单一生命周期输出通道。
///
/// 闭枚举让新增通道必须同时更新 runtime sink 的穷尽匹配；[`DomainModuleResult`] 不再维护
/// 三个可能独立漂移的公开集合。
pub enum DomainLifecycleOutput {
    /// 具名健康探针。
    Probe(ProbeName, Box<dyn HealthProbe>),
    /// 由 shutdown stack 单次消费的受管资源。
    Resource(Box<DynManagedResource<'static>>),
    /// 由 runtime executor 启动并关闭的 worker 规格。
    Worker(WorkerSpec),
}

/// 域能力的标准装配出口（ADR-010 §2.2）。
///
/// `module()` / `wire_X` 产出的 probes、resources 与 workers 进入同一个闭合、保序的生命周期
/// 集合。组合根通过 [`DomainModuleResult::merge`] 聚合，再由 runtime sink 穷尽消费；domain service
/// 与 routes 不进入此通用输出载体。
#[derive(Default)]
pub struct DomainModuleResult {
    outputs: Vec<DomainLifecycleOutput>,
}

impl DomainModuleResult {
    /// 按 probes、resources、workers 的分组顺序构造输出，并保留各输入迭代器的顺序。
    pub fn from_parts(
        probes: impl IntoIterator<Item = (ProbeName, Box<dyn HealthProbe>)>,
        resources: impl IntoIterator<Item = Box<DynManagedResource<'static>>>,
        workers: impl IntoIterator<Item = WorkerSpec>,
    ) -> Self {
        let mut result = Self::default();
        result.extend_probes(probes);
        result.extend_resources(resources);
        result.extend_workers(workers);
        result
    }

    /// 在输出尾部追加一个 probe。
    pub fn push_probe(&mut self, probe: (ProbeName, Box<dyn HealthProbe>)) {
        self.outputs
            .push(DomainLifecycleOutput::Probe(probe.0, probe.1));
    }

    /// 在输出尾部追加一个 resource。
    pub fn push_resource(&mut self, resource: Box<DynManagedResource<'static>>) {
        self.outputs.push(DomainLifecycleOutput::Resource(resource));
    }

    /// 在输出尾部追加一个 worker。
    pub fn push_worker(&mut self, worker: WorkerSpec) {
        self.outputs.push(DomainLifecycleOutput::Worker(worker));
    }

    /// 按输入顺序在输出尾部追加 probes。
    pub fn extend_probes(
        &mut self,
        probes: impl IntoIterator<Item = (ProbeName, Box<dyn HealthProbe>)>,
    ) {
        self.outputs.extend(
            probes
                .into_iter()
                .map(|(name, probe)| DomainLifecycleOutput::Probe(name, probe)),
        );
    }

    /// 按输入顺序在输出尾部追加 resources。
    pub fn extend_resources(
        &mut self,
        resources: impl IntoIterator<Item = Box<DynManagedResource<'static>>>,
    ) {
        self.outputs
            .extend(resources.into_iter().map(DomainLifecycleOutput::Resource));
    }

    /// 按输入顺序在输出尾部追加 workers。
    pub fn extend_workers(&mut self, workers: impl IntoIterator<Item = WorkerSpec>) {
        self.outputs
            .extend(workers.into_iter().map(DomainLifecycleOutput::Worker));
    }

    /// 按相对插入顺序借用所有 probes。
    pub fn probes(&self) -> impl Iterator<Item = (&ProbeName, &Box<dyn HealthProbe>)> {
        self.outputs.iter().filter_map(|output| match output {
            DomainLifecycleOutput::Probe(name, probe) => Some((name, probe)),
            DomainLifecycleOutput::Resource(_) | DomainLifecycleOutput::Worker(_) => None,
        })
    }

    /// 按相对插入顺序借用所有 resources。
    pub fn resources(&self) -> impl Iterator<Item = &Box<DynManagedResource<'static>>> {
        self.outputs.iter().filter_map(|output| match output {
            DomainLifecycleOutput::Resource(resource) => Some(resource),
            DomainLifecycleOutput::Probe(_, _) | DomainLifecycleOutput::Worker(_) => None,
        })
    }

    /// 按相对插入顺序借用所有 workers。
    pub fn workers(&self) -> impl Iterator<Item = &WorkerSpec> {
        self.outputs.iter().filter_map(|output| match output {
            DomainLifecycleOutput::Worker(worker) => Some(worker),
            DomainLifecycleOutput::Probe(_, _) | DomainLifecycleOutput::Resource(_) => None,
        })
    }

    /// 返回 probe 数量。
    pub fn probe_count(&self) -> usize {
        self.probes().count()
    }

    /// 返回 resource 数量。
    pub fn resource_count(&self) -> usize {
        self.resources().count()
    }

    /// 返回 worker 数量。
    pub fn worker_count(&self) -> usize {
        self.workers().count()
    }

    /// 排空当前输出并按原始插入顺序返回；调用方必须穷尽匹配闭枚举。
    pub fn drain_outputs(&mut self) -> std::vec::IntoIter<DomainLifecycleOutput> {
        std::mem::take(&mut self.outputs).into_iter()
    }

    /// 按原始插入顺序消费全部闭合生命周期输出。
    pub fn into_outputs(self) -> impl Iterator<Item = DomainLifecycleOutput> {
        self.outputs.into_iter()
    }

    /// 把另一个闭合生命周期载体保序搬入当前载体（domain fold；provider transaction 也可内部复用）。
    ///
    /// `merge` 不改变 lifecycle output 的 semantic owner；owner 由调用方所在的 typed transaction
    /// 决定。未来域只需多一行 `module.merge(wire_X(&deps).await?)`，组合根形态恒定。
    pub fn merge(&mut self, other: DomainModuleResult) {
        self.outputs.extend(other.outputs);
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
    let mut registry = crate::registry::Registry::new();
    for binding in bindings.iter() {
        registry.init_domain(binding.name, binding.domain.as_ref())?;
    }

    let output = drain_binding_outputs(bindings);
    Ok((registry, output))
}

/// Reclaim lifecycle outputs from bindings that could not be composed.
///
/// This is the failure-side counterpart of [`compose_bindings`]. Generated assembly glue retains
/// every successfully built binding when a later domain constructor fails; the composition root
/// drains those outputs into its startup transaction so managed resources are closed
/// asynchronously instead of being synchronously dropped. The binding internals remain private,
/// so this is the only pre-compose lifecycle escape hatch.
pub fn drain_binding_outputs(bindings: &mut Vec<DomainBinding>) -> DomainModuleResult {
    let mut output = DomainModuleResult::default();
    output.extend(bindings.drain(..).map(|binding| binding.output));
    output
}

#[cfg(test)]
mod result_tests {
    use super::*;

    fn drain_workers(output: &mut DomainModuleResult) -> Vec<WorkerSpec> {
        let mut workers = Vec::new();
        let mut retained = DomainModuleResult::default();
        for output in output.drain_outputs() {
            match output {
                DomainLifecycleOutput::Probe(name, probe) => retained.push_probe((name, probe)),
                DomainLifecycleOutput::Resource(resource) => retained.push_resource(resource),
                DomainLifecycleOutput::Worker(worker) => workers.push(worker),
            }
        }
        *output = retained;
        workers
    }

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
        WorkerSpec::observational_phase_one("crates.bootstrap.src.module.01", |_token| {
            DynManagedResource::new_box(NoopResource)
        })
    }

    #[test]
    fn worker_inventory_is_order_independent_and_lane_exact() -> Result<(), WorkerInventoryError> {
        let (_, relay, _, _) = primitives::prepare_dr_admission_controls().into_parts();
        let first = WorkerSpec::observational_phase_one("crates.bootstrap.src.module.02", |_| {
            DynManagedResource::new_box(NoopResource)
        });
        let second =
            WorkerSpec::relay_deferred("crates.bootstrap.src.module.03", &relay, |_, _| {
                DynManagedResource::new_box(NoopResource)
            });
        let expected = ExpectedWorkerInventory::closed([
            WorkerDescriptor::expected(
                "crates.bootstrap.src.module.02",
                WorkerAdmissionLane::Observational,
            ),
            WorkerDescriptor::expected(
                "crates.bootstrap.src.module.03",
                WorkerAdmissionLane::Relay,
            ),
        ])?;
        let forward = validate_worker_inventory_exact([&first, &second], &expected)?;
        let reverse = validate_worker_inventory_exact([&second, &first], &expected)?;
        assert_eq!(forward.digest, reverse.digest);
        assert_eq!(
            forward
                .descriptors
                .iter()
                .map(|descriptor| descriptor.lane)
                .collect::<Vec<_>>(),
            vec![
                WorkerAdmissionLane::Observational,
                WorkerAdmissionLane::Relay
            ]
        );
        Ok(())
    }

    #[test]
    fn worker_inventory_rejects_duplicate_identity() -> Result<(), WorkerInventoryError> {
        let first = WorkerSpec::observational_phase_one("duplicate", |_| {
            DynManagedResource::new_box(NoopResource)
        });
        let second = WorkerSpec::observational_deferred("duplicate", |_| {
            DynManagedResource::new_box(NoopResource)
        });
        let expected = ExpectedWorkerInventory::closed([WorkerDescriptor::expected(
            "duplicate",
            WorkerAdmissionLane::Observational,
        )])?;
        assert!(matches!(
            validate_worker_inventory_exact([&first, &second], &expected),
            Err(WorkerInventoryError::DuplicateIdentity(identity)) if identity == "duplicate"
        ));
        Ok(())
    }

    #[test]
    fn closed_worker_inventory_rejects_extra_observational_worker()
    -> Result<(), WorkerInventoryError> {
        let worker = WorkerSpec::observational_phase_one("observe", |_| {
            DynManagedResource::new_box(NoopResource)
        });
        let expected = ExpectedWorkerInventory::closed([WorkerDescriptor::expected(
            "observe",
            WorkerAdmissionLane::Observational,
        )])?;
        assert!(validate_worker_inventory_closed([&worker], &expected).is_ok());
        let empty = ExpectedWorkerInventory::closed([])?;
        assert!(matches!(
            validate_worker_inventory_closed([&worker], &empty),
            Err(WorkerInventoryError::Unexpected(_))
        ));
        Ok(())
    }

    #[test]
    fn worker_inventory_rejects_missing_extra_and_wrong_lane() -> Result<(), WorkerInventoryError> {
        let (_, relay, _, _) = primitives::prepare_dr_admission_controls().into_parts();
        let actual = WorkerSpec::relay_deferred("actual", &relay, |_, _| {
            DynManagedResource::new_box(NoopResource)
        });
        let expected = ExpectedWorkerInventory::closed([WorkerDescriptor::expected(
            "expected",
            WorkerAdmissionLane::Relay,
        )])?;
        assert!(matches!(
            validate_worker_inventory_exact([&actual], &expected),
            Err(WorkerInventoryError::Unexpected(_))
        ));

        let missing = ExpectedWorkerInventory::closed([
            WorkerDescriptor::expected("actual", WorkerAdmissionLane::Relay),
            WorkerDescriptor::expected("missing", WorkerAdmissionLane::Writes),
        ])?;
        assert!(matches!(
            validate_worker_inventory_exact([&actual], &missing),
            Err(WorkerInventoryError::Missing(_))
        ));

        let wrong_lane = ExpectedWorkerInventory::closed([WorkerDescriptor::expected(
            "actual",
            WorkerAdmissionLane::Consumer,
        )])?;
        assert!(matches!(
            validate_worker_inventory_exact([&actual], &wrong_lane),
            Err(WorkerInventoryError::WrongLane { .. })
        ));
        Ok(())
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
        WorkerSpec::observational_phase_one(label, move |_token| labeled_resource(label))
    }

    fn worker_identity(worker: WorkerSpec) -> String {
        worker.descriptor().identity
    }

    fn labeled_result(label: &'static str) -> DomainModuleResult {
        DomainModuleResult::from_parts(
            [labeled_probe(label)],
            [labeled_resource(label)],
            [labeled_worker(label)],
        )
    }

    /// `Default` 产出空结果（单一 lifecycle output 集合为空）。
    #[test]
    fn default_is_empty() {
        let r = DomainModuleResult::default();
        assert_eq!(r.probe_count(), 0);
        assert_eq!(r.resource_count(), 0);
        assert_eq!(r.worker_count(), 0);
    }

    /// `merge` 把另一结果的三类产物全部 extend 进来（跨域聚合）。
    #[test]
    fn merge_extends_all_vecs() {
        let mut base =
            DomainModuleResult::from_parts([probe_entry()], [resource_entry()], [worker_entry()]);
        let other = DomainModuleResult::from_parts(
            [probe_entry(), probe_entry()],
            [resource_entry()],
            [worker_entry(), worker_entry()],
        );

        base.merge(other);

        assert_eq!(base.probe_count(), 3, "probes 累加");
        assert_eq!(base.resource_count(), 2, "resources 累加");
        assert_eq!(base.worker_count(), 3, "workers 累加");
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

        let output_order: Vec<&str> = output.probes().map(|(name, _)| name.as_str()).collect();
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

        let mut output = drain_binding_outputs(&mut bindings);
        assert!(
            bindings.is_empty(),
            "recovery must consume all bindings once"
        );
        assert_eq!(
            output.probes().next().map(|(name, _)| name.as_str()),
            Some("still-owned")
        );
        assert_eq!(
            output.resources().next().map(|resource| resource.name()),
            Some("still-owned")
        );
        assert_eq!(
            drain_workers(&mut output)
                .into_iter()
                .next()
                .map(worker_identity),
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
        let probe_order: Vec<String> = output
            .probes()
            .map(|(name, _)| name.as_str().to_owned())
            .collect();
        let resource_order: Vec<String> = output
            .resources()
            .map(|resource| resource.name().to_owned())
            .collect();
        let worker_order: Vec<String> = drain_workers(&mut output)
            .into_iter()
            .map(worker_identity)
            .collect();

        assert_eq!(probe_order, expected.map(str::to_owned));
        assert_eq!(resource_order, expected.map(str::to_owned));
        assert_eq!(
            worker_order,
            expected.map(str::to_owned),
            "FnOnce workers must move in input order"
        );

        let mut identity = DomainModuleResult::default();
        identity.extend([DomainModuleResult::default()]);
        assert_eq!(identity.probe_count(), 0);
        assert_eq!(identity.resource_count(), 0);
        assert_eq!(identity.worker_count(), 0);
    }

    #[test]
    fn extend_preserves_single_non_empty_result() {
        let mut output = DomainModuleResult::default();
        output.extend([labeled_result("only")]);

        assert_eq!(output.probe_count(), 1);
        assert_eq!(
            output.probes().next().map(|(name, _)| name.as_str()),
            Some("only")
        );
        assert_eq!(output.resource_count(), 1);
        assert_eq!(
            output.resources().next().map(|resource| resource.name()),
            Some("only")
        );
        assert_eq!(output.worker_count(), 1);
        let worker_labels: Vec<String> = drain_workers(&mut output)
            .into_iter()
            .map(worker_identity)
            .collect();
        assert_eq!(worker_labels, ["only"]);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn worker_is_moved_and_invoked_once() {
        let calls = Arc::new(AtomicUsize::new(0));
        let worker_calls = Arc::clone(&calls);
        let worker =
            WorkerSpec::observational_deferred("crates.bootstrap.src.module.05", move |_token| {
                worker_calls.fetch_add(1, Ordering::SeqCst);
                labeled_resource("single-use")
            });
        let mut output = DomainModuleResult::default();
        output.push_worker(worker);

        let worker = drain_workers(&mut output)
            .pop()
            .expect("worker must be present");
        let root = CancellationToken::new();
        let mut stack = crate::shutdown::ShutdownStack::new(root);
        let _status = worker.register_into(&mut stack);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(output.worker_count(), 0);
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
