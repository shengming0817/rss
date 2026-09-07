use rss_request_context::TenantId;
use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};

#[test]
fn execution_binding_rejects_ambiguous_or_missing_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = TenantId::parse("00000000-0000-0000-0000-000000000001")?;
    let storage = StorageIdentity::new([1; 16], [2; 16])?;
    let epoch = Epoch::new(1)?;
    assert!(Epoch::new(0).is_err());
    assert!(StorageIdentity::new([0; 16], [2; 16]).is_err());
    assert!(ExecutionBinding::new(storage, vec![]).is_err());
    assert!(ExecutionBinding::new(storage, vec![(tenant, epoch), (tenant, epoch)]).is_err());
    let binding = ExecutionBinding::new(storage, vec![(tenant, epoch)])?;
    assert_eq!(binding.epoch(tenant), Some(epoch));
    assert_eq!(
        binding.epoch(TenantId::parse("00000000-0000-0000-0000-000000000002")?),
        None
    );
    assert!(format!("{binding:?}").contains("ExecutionBinding"));
    assert!(!format!("{binding:?}").contains(&tenant.to_string()));
    Ok(())
}
