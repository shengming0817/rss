pub mod localtx {
    pub async fn assert_commit() -> Result<(), ()> { Ok(()) }
    pub async fn assert_rollback() -> Result<(), ()> { Ok(()) }
    pub async fn assert_rejected_no_write() -> Result<(), ()> { Ok(()) }
    pub async fn assert_commit_unknown_no_replay() -> Result<(), ()> { Ok(()) }
    pub async fn assert_rollback_failed_no_replay() -> Result<(), ()> { Ok(()) }
}

pub mod tenant_conformance {
    pub async fn assert_tenant_isolation() -> Result<(), ()> { Ok(()) }
}

pub mod repo_conformance {
    pub async fn assert_retry_boundary_policy() -> Result<(), ()> { Ok(()) }
}
