//! vault — RSS workspace crate (signature-frozen; RW-G0.2 PR-5). See docs/rules/architecture.md.
//!
//! 签名冻结（ADR-004 C7）：sealed-marker 以 **native AFIT** impl diport 已冻 DI port trait，body=`todo!()`。
//! raw client 字段待 W 阶段接后端时填入（届时保持 `pub(crate)`）；crate 保持 forbid(unsafe_code)（继承 workspace lints，不 invoke dynosaur 宏）。

use diport::{ManagedResource, ShutdownError, SignRequest, Signature, Signer, SignerError};

/// HashiCorp Vault 签名 adapter（sealed-marker）。raw client（vault 连接 / 句柄）字段待 W 阶段填入，保持 `pub(crate)`。
/// 同时 impl `Signer` 与 `ManagedResource`（各有 `shutdown`）；消费经 `DynSigner`/`Box<DynManagedResource>` 无歧义，直接操作 raw struct 时用 UFCS 消歧。
pub struct VaultSigner;

impl Signer for VaultSigner {
    async fn sign(&self, _request: SignRequest) -> Result<Signature, SignerError> {
        todo!()
    }

    async fn shutdown(&self) -> Result<(), SignerError> {
        todo!()
    }
}

impl ManagedResource for VaultSigner {
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
    //! INVARIANT: ADAPTER-PORT-FREEZE-12 —— sealed-marker impl 冻结的 diport DI port trait；去掉任一 impl 即编译失败（anti-vacuity）。
    use core::marker::PhantomData;

    fn assert_managed_resource<T: diport::ManagedResource>(_: PhantomData<T>) {}
    fn assert_signer<T: diport::Signer>(_: PhantomData<T>) {}

    #[test]
    fn impls_frozen_ports() {
        assert_managed_resource(PhantomData::<super::VaultSigner>);
        assert_signer(PhantomData::<super::VaultSigner>);
    }
}
