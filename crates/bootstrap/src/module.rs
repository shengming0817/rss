//! 域 crate 装配单元。
//!
//! [`DomainModule`] 是一个域 crate 在组合根层的装配单元：域服务实例已构造完成
//! （所有必填依赖经构造器注入），bootstrap 只需拿到它并调 [`Domain::init`]。
//!
//! [`ModuleFactory`] 是域 crate 暴露给组合根的工厂约定：组合根收集各域
//! `module()` 返回的 [`DomainModule`]，交 bootstrap 驱动 init + shutdown。
//!
//! [`Domain::init`]: crate::domain::Domain::init

use crate::domain::Domain;

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
