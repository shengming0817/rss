#[cfg(test)]
mod tests {
    struct DemoProviderFixture;

    impl DemoProviderFixture {
        const fn new() -> Self {
            Self
        }

        async fn execute(&self) -> Result<(), ()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn tenant_scoped_uow_profile() -> Result<(), ()> {
        const LOCALTX_BACKEND_PROFILE_DEMO_WRITE: ::vocab::HttpRouteBinding<
            ::generated::http::demo_v1::write::RouteMarker,
            ::vocab::http::LocalTx,
        > = ::generated::http::demo_v1::write::ROUTE;
        const LOCALTX_BACKEND_PROVIDER_DEMO_WRITE: ::std::marker::PhantomData<(
            ::generated::http::demo_v1::write::RouteMarker,
            DemoProviderFixture,
        )> = ::std::marker::PhantomData;
        let _typed_enrollment = LOCALTX_BACKEND_PROFILE_DEMO_WRITE;
        let provider = DemoProviderFixture::new();
        ::rss_conformance::localtx::assert_commit(::rss_conformance::localtx::CommitCase::new(|| async {
            provider.execute().await
        }))
        .await?;
        ::rss_conformance::localtx::assert_rollback(::rss_conformance::localtx::RollbackCase::new(|| async {
            provider.execute().await
        }))
        .await?;
        ::rss_conformance::localtx::assert_rejected_no_write(::rss_conformance::localtx::RejectedNoWriteCase::new(
            || async { provider.execute().await },
        ))
        .await?;
        ::rss_conformance::localtx::assert_rejected_no_write(::rss_conformance::localtx::RejectedNoWriteCase::new(
            || async { provider.execute().await },
        ))
        .await?;
        ::testkit::tenant_conformance::assert_tenant_isolation(
            (),
            (),
            || async { provider.execute().await },
            || async { Ok::<(), ()>(()) },
            |_: ()| (),
        )
        .await?;
        ::testkit::repo_conformance::assert_retry_boundary_policy(
            ::testkit::repo_conformance::RetryBoundaryCase::new(
                ::testkit::repo_conformance::TransientSuccessPath::new(|| async {
                    provider.execute().await
                }),
                ::testkit::repo_conformance::ConflictPath::new(|| async {
                    provider.execute().await
                }),
                ::testkit::repo_conformance::PermanentPath::new(|| async {
                    provider.execute().await
                }),
                ::testkit::repo_conformance::TransientExhaustionPath::new(|| async {
                    provider.execute().await
                }),
            ),
        )
        .await?;
        ::rss_conformance::localtx::assert_commit_unknown_no_replay(
            ::rss_conformance::localtx::CommitUnknownCase::new(|| async {
                provider.execute().await
            }),
        )
        .await?;
        ::rss_conformance::localtx::assert_rollback_failed_no_replay(
            ::rss_conformance::localtx::RollbackFailedCase::new(|| async {
                provider.execute().await
            }),
        )
        .await?;
        Ok(())
    }
}
