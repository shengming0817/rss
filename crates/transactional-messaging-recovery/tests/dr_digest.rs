use rss_request_context::TenantId;
use rss_transactional_messaging::{
    fence::{Epoch, StorageIdentity},
    inbox::{ConsumerGroup, ConsumerIdentity},
    message::{ContractIdentity, MessageFingerprint, MessageId},
};
use rss_transactional_messaging_recovery::{
    OperationId, Version,
    dr::{Member, Plan, RestoreEvidence},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
#[derive(Clone)]
struct Facts {
    tenant: TenantId,
    operation: OperationId,
    storage: StorageIdentity,
    epoch: Epoch,
    evidence: RestoreEvidence,
    members: Vec<Member>,
}
impl Facts {
    fn digest(self) -> Result<[u8; 32]> {
        Ok(Plan::new(
            self.tenant,
            self.operation,
            self.storage,
            self.epoch,
            self.evidence,
            self.members,
        )?
        .digest())
    }
}
fn tenant() -> Result<TenantId> {
    Ok(TenantId::parse("11111111-1111-1111-1111-111111111111")?)
}
fn outbox(fingerprint: u8, version: i64) -> Result<Member> {
    Ok(Member::Outbox {
        message: MessageId::parse("message")?,
        fingerprint: MessageFingerprint::from_bytes([fingerprint; 32]),
        version: Version::new(version)?,
    })
}
#[test]
fn every_plan_coordinate_changes_authorization_digest() -> Result<()> {
    let base = Facts {
        tenant: tenant()?,
        operation: OperationId::new(),
        storage: StorageIdentity::new([1; 16], [2; 16])?,
        epoch: Epoch::new(1)?,
        evidence: RestoreEvidence::new([3; 32], [4; 32])?,
        members: vec![outbox(5, 1)?],
    };
    let digest = base.clone().digest()?;
    type Mutation = fn(&mut Facts) -> Result<()>;
    let cases: [(&str, Mutation); 9] = [
        ("tenant", |f| {
            f.tenant = TenantId::parse("22222222-2222-2222-2222-222222222222")?;
            Ok(())
        }),
        ("operation", |f| {
            f.operation = OperationId::new();
            Ok(())
        }),
        ("target", |f| {
            f.storage = StorageIdentity::new([9; 16], [2; 16])?;
            Ok(())
        }),
        ("lineage", |f| {
            f.storage = StorageIdentity::new([1; 16], [9; 16])?;
            Ok(())
        }),
        ("epoch", |f| {
            f.epoch = Epoch::new(2)?;
            Ok(())
        }),
        ("database evidence", |f| {
            f.evidence = RestoreEvidence::new([9; 32], [4; 32])?;
            Ok(())
        }),
        ("broker evidence", |f| {
            f.evidence = RestoreEvidence::new([3; 32], [9; 32])?;
            Ok(())
        }),
        ("fingerprint", |f| {
            f.members = vec![outbox(9, 1)?];
            Ok(())
        }),
        ("version", |f| {
            f.members = vec![outbox(5, 2)?];
            Ok(())
        }),
    ];
    for (name, mutate) in cases {
        let mut changed = base.clone();
        mutate(&mut changed)?;
        assert_ne!(digest, changed.digest()?, "{name}");
    }
    Ok(())
}
fn consumer(
    id: &str,
    group: &str,
    contract: &'static str,
    version: u32,
    schema: &'static str,
    fp: u8,
) -> Result<Member> {
    Ok(Member::Consumer {
        identity: ConsumerIdentity::new(
            tenant()?,
            ConsumerGroup::parse(group)?,
            MessageId::parse(id)?,
            ContractIdentity::new(
                rss_contract::ContractId::from_static(contract),
                rss_contract::ContractVersion::from_static_major(version),
                rss_contract::SchemaDigest::from_static(schema),
            ),
        ),
        fingerprint: MessageFingerprint::from_bytes([fp; 32]),
    })
}
#[test]
fn full_consumer_identity_and_direction_are_digest_inputs() -> Result<()> {
    const A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let base = Facts {
        tenant: tenant()?,
        operation: OperationId::new(),
        storage: StorageIdentity::new([1; 16], [2; 16])?,
        epoch: Epoch::new(1)?,
        evidence: RestoreEvidence::new([3; 32], [4; 32])?,
        members: vec![consumer("message", "group", "orders.created", 1, A, 5)?],
    };
    let digest = base.clone().digest()?;
    let cases = [
        consumer("other", "group", "orders.created", 1, A, 5)?,
        consumer("message", "other", "orders.created", 1, A, 5)?,
        consumer("message", "group", "orders.updated", 1, A, 5)?,
        consumer("message", "group", "orders.created", 2, A, 5)?,
        consumer("message", "group", "orders.created", 1, B, 5)?,
        consumer("message", "group", "orders.created", 1, A, 9)?,
        outbox(5, 1)?,
    ];
    for member in cases {
        let mut changed = base.clone();
        changed.members = vec![member];
        assert_ne!(digest, changed.digest()?);
    }
    Ok(())
}

#[test]
fn termination_binds_the_exact_prior_operation_and_all_execution_coordinates() -> Result<()> {
    let op = OperationId::new();
    let prior = OperationId::new();
    let storage = StorageIdentity::new([1; 16], [2; 16])?;
    let make = |tenant, op, storage, epoch, prior, digest| {
        Plan::terminate(tenant, op, storage, epoch, prior, digest)
    };
    let baseline = make(tenant()?, op, storage, Epoch::new(2)?, prior, [3; 32])?;
    assert!(baseline.members().is_empty());
    assert!(
        matches!(baseline.action(), rss_transactional_messaging_recovery::dr::PlanAction::Terminate { operation, digest } if *operation==prior && *digest==[3;32])
    );
    for changed in [
        make(
            TenantId::parse("22222222-2222-2222-2222-222222222222")?,
            op,
            storage,
            Epoch::new(2)?,
            prior,
            [3; 32],
        )?,
        make(
            tenant()?,
            OperationId::new(),
            storage,
            Epoch::new(2)?,
            prior,
            [3; 32],
        )?,
        make(
            tenant()?,
            op,
            StorageIdentity::new([9; 16], [2; 16])?,
            Epoch::new(2)?,
            prior,
            [3; 32],
        )?,
        make(
            tenant()?,
            op,
            StorageIdentity::new([1; 16], [9; 16])?,
            Epoch::new(2)?,
            prior,
            [3; 32],
        )?,
        make(tenant()?, op, storage, Epoch::new(3)?, prior, [3; 32])?,
        make(
            tenant()?,
            op,
            storage,
            Epoch::new(2)?,
            OperationId::new(),
            [3; 32],
        )?,
        make(tenant()?, op, storage, Epoch::new(2)?, prior, [4; 32])?,
    ] {
        assert_ne!(baseline.digest(), changed.digest());
    }
    assert!(make(tenant()?, op, storage, Epoch::new(2)?, op, [3; 32]).is_err());
    assert!(make(tenant()?, op, storage, Epoch::new(2)?, prior, [0; 32]).is_err());
    assert!(
        make(
            tenant()?,
            op,
            storage,
            Epoch::new(i64::MAX)?,
            prior,
            [3; 32]
        )
        .is_err()
    );
    Ok(())
}
