#[cfg(test)]
mod tests {
    struct DemoProviderFixture;

    impl DemoProviderFixture {
        const fn new() -> Self {
            Self
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
        let _provider = DemoProviderFixture::new();
        ::testkit::localtx::assert_commit().await?;
        ::testkit::localtx::assert_rollback().await?;
        ::testkit::localtx::assert_rejected_no_write().await?;
        ::testkit::localtx::assert_rejected_no_write().await?;
        ::testkit::tenant_conformance::assert_tenant_isolation().await?;
        ::testkit::repo_conformance::assert_retry_boundary_policy().await?;
        ::testkit::localtx::assert_commit_unknown_no_replay().await?;
        ::testkit::localtx::assert_rollback_failed_no_replay().await?;
        Ok(())
    }
}
