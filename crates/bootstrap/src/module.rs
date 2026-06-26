//! 域 crate 装配单元。
//!
//! [`DomainModule`] 是一个域 crate 在组合根层的装配单元：域服务实例已构造完成
//! （所有必填依赖经构造器注入），bootstrap 只需拿到它并调 [`Domain::init`]。
//!
//! [`ModuleFactory`] 是域 crate 暴露给组合根的工厂约定：组合根收集各域
//! `module()` 返回的 [`DomainModule`]，交 bootstrap 驱动 init + shutdown。
//!
//! [`Domain::init`]: crate::domain::Domain::init
//!
//! [`DomainModuleResult`] 是域能力的标准装配出口（ADR-010 §2.2）：`module()` / `wire_X` 的可聚合产物，
//! 组合根经 [`DomainModuleResult::merge`] 聚合各域 result 后排空到 sink。

use diport::DynManagedResource;
use primitives::ProbeName;
use tokio_util::sync::CancellationToken;

use crate::domain::Domain;
use crate::registry::HealthProbe;

/// 一个域 crate 的装配单元（域服务实例已构造完成）。
///
/// `domain` 字段已持有构造好的域实例（所有必填依赖经构造器注入，缺失即编译错误）。
/// bootstrap 拿到所有 [`DomainModule`] 后，按注册顺序逐个调 `domain.init(reg)`。
pub struct DomainModule {
    /// 域 crate 的标识名（用于日志 / 诊断，不作路由前缀）。
    pub name: &'static str,
    /// 已构造完成的域实例。
    pub domain: Box<dyn Domain>,
}

/// 域 crate 暴露的工厂约定。
///
/// 组合根（assembly / bin crate）为每个域 crate 声明一个 `ModuleFactory`
/// 函数指针，收集后交 bootstrap 统一驱动 init + shutdown：
///
/// ```ignore
/// // 在组合根中：
/// let modules: Vec<DomainModule> = vec![
///     identity::module(),
///     settings::module(),
/// ];
/// ```
///
/// 工厂函数内部完成依赖注入（构造器注入），返回已就绪的 [`DomainModule`]。
///
/// # 适用场景与限制
///
/// `ModuleFactory` 是 `fn()` 裸函数指针（无捕获、零大小），仅适用于**零运行时依赖**的
/// 工厂场景——域 crate 的所有依赖在编译期已硬编码（如常量配置、无外部 I/O 的纯计算域）。
///
/// 若工厂需要在运行时注入依赖（如 DB pool、`Clock`、`Publisher` 等），
/// 应改用闭包形式：
///
/// ```ignore
/// // 参数化构造（注入运行时依赖）的组合根应使用 Box<dyn Fn() -> DomainModule + Send + Sync>
/// // 或在 module() 内经构造器位置参注入：
/// fn identity_module(pool: Arc<PgPool>, clock: Box<DynClock<'static>>) -> DomainModule {
///     DomainModule {
///         name: "identity",
///         domain: Box::new(IdentityDomain::new(pool, clock)),
///     }
/// }
/// ```
///
/// `ModuleFactory` 仅用于零依赖工厂场景，不适合做通用的依赖注入入口。
pub type ModuleFactory = fn() -> DomainModule;

/// 需要 per-stack cancel token 的后台 worker；组合根排空进 [`ShutdownStack::register_with_token`]。
///
/// [`ShutdownStack::register_with_token`]: crate::shutdown::ShutdownStack::register_with_token
pub type WorkerSpec = Box<dyn FnOnce(CancellationToken) -> Box<DynManagedResource<'static>> + Send>;

/// 域能力的标准装配出口（ADR-010 §2.2）：`module()` / `wire_X` 的可聚合产物，组合根经
/// [`DomainModuleResult::merge`] 聚合各域 result 后逐 `Vec` 排空到 sink，不再逐项手工接线。
///
/// # 字段随 PERSIST 自底向上落地（ADR-010 §2.6，不冻字段）
///
/// **首切（#1422 / ADR step 2）只携框架擦除类型** probes / resources / workers——`services` / `routes` /
/// `name` / `domain` 字段随 #1421 settings 闭环（ADR step 5）补。域 service **不经**此结构出向（留 `wire_X`
/// 内部经 route 闭包捕获）——配合 `assemblies/runtime` 的 `wire_X(deps: &SharedRuntimeDeps) -> Result<DomainModuleResult>`
/// 签名（INVARIANT WIRING-DEPS-NO-HANDOFF-01，Hard）杜绝跨 module value handoff。
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

#[cfg(test)]
mod result_tests {
    use super::*;

    use diport::ShutdownError;
    use primitives::{HealthCheck, HealthStatus};

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
}
