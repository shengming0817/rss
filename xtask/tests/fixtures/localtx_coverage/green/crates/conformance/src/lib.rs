pub mod localtx {
    macro_rules! case {
        ($name:ident) => {
            pub struct $name<A>(A);
            impl<A> $name<A> {
                pub fn new(action: A) -> Self { Self(action) }
            }
        };
    }
    case!(CommitCase);
    case!(RollbackCase);
    case!(RejectedNoWriteCase);
    case!(CommitUnknownCase);
    case!(RollbackFailedCase);
    pub async fn assert_commit<A>(_: CommitCase<A>) -> Result<(), ()> { Ok(()) }
    pub async fn assert_rollback<A>(_: RollbackCase<A>) -> Result<(), ()> { Ok(()) }
    pub async fn assert_rejected_no_write<A>(_: RejectedNoWriteCase<A>) -> Result<(), ()> { Ok(()) }
    pub async fn assert_commit_unknown_no_replay<A>(_: CommitUnknownCase<A>) -> Result<(), ()> { Ok(()) }
    pub async fn assert_rollback_failed_no_replay<A>(_: RollbackFailedCase<A>) -> Result<(), ()> { Ok(()) }
}
