//! pass：dynosaur Send DI port 可 native AFIT impl + 经 `Box<DynX>` / `Arc<DynX>` 注入。
//! 覆盖全部 async DI port（DIPORT-DYN-COMPAT-01 回归锁随新增端口同步扩展）：Signer / AuditSink / Subscriber / RateLimiter。
use diport::{
    AuditSink, AuditSinkError, DynAuditSink, DynRateLimiter, DynSigner, DynSubscriber, KeyId,
    MessageStream, RateLimitDecision, RateLimitError, RateLimitKey, RateLimiter, SignRequest,
    Signature, Signer, SignerError, SigningPurpose, Subscriber, SubscriberError, Topic,
};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

struct OkSigner;

impl Signer for OkSigner {
    async fn sign(&self, _request: SignRequest) -> Result<Signature, SignerError> {
        Ok(Signature::new(Vec::new()))
    }
    async fn shutdown(&self) -> Result<(), SignerError> {
        Ok(())
    }
}

struct OkAuditSink;

impl AuditSink for OkAuditSink {
    async fn record(
        &self,
        _event: diport::AuditEvent,
    ) -> Result<(), AuditSinkError> {
        Ok(())
    }
    async fn shutdown(&self) -> Result<(), AuditSinkError> {
        Ok(())
    }
}

struct OkSubscriber;

impl Subscriber for OkSubscriber {
    async fn subscribe(
        &self,
        _topic: Topic,
        _token: CancellationToken,
    ) -> Result<MessageStream, SubscriberError> {
        Ok(Box::pin(futures::stream::empty()))
    }
    async fn shutdown(&self) -> Result<(), SubscriberError> {
        Ok(())
    }
}

struct OkRateLimiter;

impl RateLimiter for OkRateLimiter {
    async fn check(&self, _key: RateLimitKey) -> Result<RateLimitDecision, RateLimitError> {
        Ok(RateLimitDecision::Allowed)
    }
    async fn shutdown(&self) -> Result<(), RateLimitError> {
        Ok(())
    }
}

fn main() {
    let _boxed: Box<DynSigner> = DynSigner::new_box(OkSigner);
    let _arced: Arc<DynSigner> = DynSigner::new_arc(OkSigner);
    let _req = SignRequest {
        key: KeyId::new("k"),
        purpose: SigningPurpose::new("p"),
        message: Vec::new(),
    };

    // AuditSink：async DI port，dyn(box) wrapper 可 Box/Arc 注入。
    let _audit_boxed: Box<DynAuditSink> = DynAuditSink::new_box(OkAuditSink);
    let _audit_arced: Arc<DynAuditSink> = DynAuditSink::new_arc(OkAuditSink);

    // Subscriber：async DI port，返回 MessageStream（Pin<Box<dyn Stream + Send>>）仍 dyn-compatible。
    let _sub_boxed: Box<DynSubscriber> = DynSubscriber::new_box(OkSubscriber);
    let _sub_arced: Arc<DynSubscriber> = DynSubscriber::new_arc(OkSubscriber);

    // RateLimiter：async DI port（#1011），dyn(box) wrapper 可 Box/Arc 注入。
    let _rl_boxed: Box<DynRateLimiter> = DynRateLimiter::new_box(OkRateLimiter);
    let _rl_arced: Arc<DynRateLimiter> = DynRateLimiter::new_arc(OkRateLimiter);
    let _key = RateLimitKey::new("k");
}
