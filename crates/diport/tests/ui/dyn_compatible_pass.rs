//! pass：dynosaur Send DI port 可 native AFIT impl + 经 `Box<DynX>` / `Arc<DynX>` 注入。
//! 覆盖 async DI port（DIPORT-DYN-COMPAT-01 回归锁随新增端口同步扩展）。
use consistency::{EventEntry, EventTopic, IdemKey};
use diport::{
    AuditSink, AuditSinkError, CasStore, CasStoreError, CasStoreOutcome, CasStoreRequest, CertScope,
    CertSerial, DynAuditSink, DynCasStore, DynLockStore, DynManagedResource, DynObjectStore,
    DynOutboxEmitter, DynPdp, DynPublisher, DynRateLimiter, DynRevocationStore, DynSigner,
    DynServiceTokenReplayStore, DynSubscriber, KeyId, LockAcquireOutcome, LockRenewOutcome,
    LockStore, LockStoreError, LockStoreKey, ManagedResource, MessageStream, ObjectKey,
    ObjectPayload, ObjectStore, ObjectStoreError, OutboxEmitError, OutboxEmitter,
    OutboxEnvelopeParts, Pdp, PdpError, PublishRequest, Publisher, PublisherError,
    RateLimitDecision, RateLimitError, RateLimitKey, RateLimiter, RawCredential, RevocationStore,
    RevocationStoreError, ServiceTokenReplayDeadline, ServiceTokenReplayDisposition,
    ServiceTokenReplayKey, ServiceTokenReplayStore, ServiceTokenReplayStoreError, ShutdownError,
    SignRequest, Signature, Signer, SignerError, SigningPurpose, Subscriber, SubscriberError, Topic,
    VerifiedClaims,
};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio_util::sync::CancellationToken;

fn assert_send_sync<T: Send + Sync>() {}

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

struct OkPublisher;

impl Publisher for OkPublisher {
    async fn publish(&self, _request: PublishRequest) -> Result<(), PublisherError> {
        Ok(())
    }
    async fn shutdown(&self) -> Result<(), PublisherError> {
        Ok(())
    }
}

struct OkManagedResource;

impl ManagedResource for OkManagedResource {
    fn name(&self) -> &str {
        "ok"
    }
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        Ok(())
    }
}

struct OkObjectStore;

impl ObjectStore for OkObjectStore {
    async fn put_object(&self, _key: ObjectKey, _body: Vec<u8>) -> Result<(), ObjectStoreError> {
        Ok(())
    }
    async fn get_object(&self, _key: ObjectKey) -> Result<Option<ObjectPayload>, ObjectStoreError> {
        Ok(None)
    }
    async fn delete_object(&self, _key: ObjectKey) -> Result<(), ObjectStoreError> {
        Ok(())
    }
    async fn shutdown(&self) -> Result<(), ObjectStoreError> {
        Ok(())
    }
}

struct OkPdp;

impl Pdp for OkPdp {
    async fn verify(&self, _raw: &RawCredential) -> Result<VerifiedClaims, PdpError> {
        Ok(VerifiedClaims::new("sub", None, None))
    }
}

struct OkServiceTokenReplayStore;

impl ServiceTokenReplayStore for OkServiceTokenReplayStore {
    async fn check_and_record(
        &self,
        _key: &ServiceTokenReplayKey,
        _expires_at: SystemTime,
        _deadline: ServiceTokenReplayDeadline,
    ) -> Result<ServiceTokenReplayDisposition, ServiceTokenReplayStoreError> {
        Ok(ServiceTokenReplayDisposition::Recorded)
    }
}

struct OkOutboxEmitter;

impl OutboxEmitter for OkOutboxEmitter {
    async fn emit(
        &self,
        _entry: EventEntry,
        _env: OutboxEnvelopeParts,
    ) -> Result<(), OutboxEmitError> {
        Ok(())
    }
}

struct OkRevocationStore;

impl RevocationStore for OkRevocationStore {
    async fn revoke(
        &self,
        _serial: CertSerial,
        _scope: CertScope,
    ) -> Result<(), RevocationStoreError> {
        Ok(())
    }
    async fn is_revoked(
        &self,
        _serial: CertSerial,
        _scope: CertScope,
    ) -> Result<bool, RevocationStoreError> {
        Ok(false)
    }
    async fn shutdown(&self) -> Result<(), RevocationStoreError> {
        Ok(())
    }
}

struct OkCasStore;

impl CasStore for OkCasStore {
    async fn compare_and_swap(
        &self,
        _request: CasStoreRequest,
    ) -> Result<CasStoreOutcome, CasStoreError> {
        Ok(CasStoreOutcome::Conflict { current: None })
    }
    async fn shutdown(&self) -> Result<(), CasStoreError> {
        Ok(())
    }
}

struct OkLockStore;

impl LockStore for OkLockStore {
    async fn acquire(
        &self,
        _key: LockStoreKey,
        _ttl: Duration,
    ) -> Result<LockAcquireOutcome, LockStoreError> {
        Ok(LockAcquireOutcome::Held)
    }
    async fn renew(
        &self,
        _key: LockStoreKey,
        _token: vocab::Epoch,
        _ttl: Duration,
    ) -> Result<LockRenewOutcome, LockStoreError> {
        Ok(LockRenewOutcome::Lost)
    }
    async fn release(&self, _key: LockStoreKey, _token: vocab::Epoch) -> Result<(), LockStoreError> {
        Ok(())
    }
    async fn shutdown(&self) -> Result<(), LockStoreError> {
        Ok(())
    }
}

fn main() {
    let _boxed: Box<DynSigner> = DynSigner::new_box(OkSigner);
    let _arced: Arc<DynSigner> = DynSigner::new_arc(OkSigner);
    let _req = SignRequest {
        key: KeyId::new("k"),
        purpose: SigningPurpose::new("p"),
        message: Vec::new().into(),
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

    // Publisher：async DI port，dyn(box) wrapper 可 Box/Arc 注入。
    let _pub_boxed: Box<DynPublisher> = DynPublisher::new_box(OkPublisher);
    let _pub_arced: Arc<DynPublisher> = DynPublisher::new_arc(OkPublisher);

    // ManagedResource：async DI port（shutdown 编排），dyn(box) wrapper 可 Box/Arc 注入。
    let _mr_boxed: Box<DynManagedResource> = DynManagedResource::new_box(OkManagedResource);
    let _mr_arced: Arc<DynManagedResource> = DynManagedResource::new_arc(OkManagedResource);

    // ObjectStore：async DI port（#1011），dyn(box) wrapper 可 Box/Arc 注入。
    let _obj_boxed: Box<DynObjectStore> = DynObjectStore::new_box(OkObjectStore);
    let _obj_arced: Arc<DynObjectStore> = DynObjectStore::new_arc(OkObjectStore);

    // Pdp：async DI port（#1109 验签 provider），dyn(box) wrapper 可 Box/Arc 注入。
    let _pdp_boxed: Box<DynPdp> = DynPdp::new_box(OkPdp);
    let _pdp_arced: Arc<DynPdp> = DynPdp::new_arc(OkPdp);
    assert_send_sync::<Arc<DynPdp<'static>>>();

    let _replay_boxed: Box<DynServiceTokenReplayStore> =
        DynServiceTokenReplayStore::new_box(OkServiceTokenReplayStore);
    let _replay_arced: Arc<DynServiceTokenReplayStore> =
        DynServiceTokenReplayStore::new_arc(OkServiceTokenReplayStore);
    assert_send_sync::<Arc<DynServiceTokenReplayStore<'static>>>();

    // OutboxEmitter：async DI port（#1100 durable outbox 发射），dyn(box) wrapper 可 Box/Arc 注入。
    let _oe_boxed: Box<DynOutboxEmitter> = DynOutboxEmitter::new_box(OkOutboxEmitter);
    let _oe_arced: Arc<DynOutboxEmitter> = DynOutboxEmitter::new_arc(OkOutboxEmitter);

    // RevocationStore：async DI port（#1260 证书撤销 provider），dyn(box) wrapper 可 Box/Arc 注入。
    let _rev_boxed: Box<DynRevocationStore> = DynRevocationStore::new_box(OkRevocationStore);
    let _rev_arced: Arc<DynRevocationStore> = DynRevocationStore::new_arc(OkRevocationStore);

    // CasStore：async DI port（#1007 state-CAS provider），dyn(box) wrapper 可 Box/Arc 注入。
    let _cas_boxed: Box<DynCasStore> = DynCasStore::new_box(OkCasStore);
    let _cas_arced: Arc<DynCasStore> = DynCasStore::new_arc(OkCasStore);

    // LockStore：async DI port（#1007 distlock provider），dyn(box) wrapper 可 Box/Arc 注入。
    let _lock_boxed: Box<DynLockStore> = DynLockStore::new_box(OkLockStore);
    let _lock_arced: Arc<DynLockStore> = DynLockStore::new_arc(OkLockStore);

    let _ = EventTopic::parse("events.t");
    let _ = IdemKey::parse("k");
}
