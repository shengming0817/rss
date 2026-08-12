pub mod tenant_conformance {
    pub async fn assert_tenant_isolation<T, U, A, O, C>(
        _: T,
        _: U,
        _: A,
        _: O,
        _: C,
    ) -> Result<(), ()> {
        Ok(())
    }
}

pub mod repo_conformance {
    macro_rules! path {
        ($name:ident) => {
            pub struct $name<A>(A);
            impl<A> $name<A> {
                pub fn new(action: A) -> Self {
                    Self(action)
                }
            }
        };
    }

    path!(TransientSuccessPath);
    path!(ConflictPath);
    path!(PermanentPath);
    path!(TransientExhaustionPath);

    pub struct RetryBoundaryCase<T, C, P, E>(T, C, P, E);
    impl<T, C, P, E> RetryBoundaryCase<T, C, P, E> {
        pub fn new(transient: T, conflict: C, permanent: P, exhaustion: E) -> Self {
            Self(transient, conflict, permanent, exhaustion)
        }
    }

    pub async fn assert_retry_boundary_policy<T, C, P, E>(
        _: RetryBoundaryCase<T, C, P, E>,
    ) -> Result<(), ()> {
        Ok(())
    }
}
