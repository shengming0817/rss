//! grpc — RSS workspace crate (signature-frozen; RW-G0.2 PR-5). See docs/rules/architecture.md.
//!
//! 签名冻结（ADR-004 C7）：sealed-marker 以 **native AFIT** impl diport 已冻 DI port trait，body=`todo!()`。
//! raw client 字段待 W 阶段接后端时填入（届时保持 `pub(crate)`）；crate 保持 forbid(unsafe_code)（继承 workspace lints，不 invoke dynosaur 宏）。

use diport::{ManagedResource, ShutdownError};

/// gRPC 传输 adapter（sealed-marker）。raw client（server / listener 句柄）字段待 W 阶段填入，保持 `pub(crate)`。
pub struct GrpcServer;

impl ManagedResource for GrpcServer {
    fn name(&self) -> &str {
        todo!()
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        todo!()
    }
}

#[cfg(test)]
mod smoke {
    //! build smoke：编译期断言 sealed-marker 已 impl 冻结的 diport DI port trait
    //! （PhantomData 绑定检查，不构造、不执行 `todo!()` body）。
    //! INVARIANT: ADAPTER-PORT-FREEZE-02 —— sealed-marker impl 冻结的 diport DI port trait；去掉任一 impl 即编译失败（anti-vacuity）。
    use core::marker::PhantomData;

    fn assert_managed_resource<T: diport::ManagedResource>(_: PhantomData<T>) {}

    #[test]
    fn impls_frozen_ports() {
        assert_managed_resource(PhantomData::<super::GrpcServer>);
    }
}
