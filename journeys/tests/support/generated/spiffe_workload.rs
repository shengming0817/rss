// @generated from proto/spiffe/workload.proto (spiffe crate 0.16.0).
// Source SHA-256: 8be0c3cb2bb9a42f446170ef027bd8f432dcf4fb347c1c37964738087287db74

#[derive(Clone, Copy, PartialEq, Eq, Hash, ::prost::Message)]
pub struct X509svidRequest {}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct X509svidResponse {
    #[prost(message, repeated, tag = "1")]
    pub svids: ::prost::alloc::vec::Vec<X509svid>,
    #[prost(bytes = "bytes", repeated, tag = "2")]
    pub crl: ::prost::alloc::vec::Vec<::prost::bytes::Bytes>,
    #[prost(map = "string, bytes", tag = "3")]
    pub federated_bundles:
        ::std::collections::HashMap<::prost::alloc::string::String, ::prost::bytes::Bytes>,
}

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct X509svid {
    #[prost(string, tag = "1")]
    pub spiffe_id: ::prost::alloc::string::String,
    #[prost(bytes = "bytes", tag = "2")]
    pub x509_svid: ::prost::bytes::Bytes,
    #[prost(bytes = "bytes", tag = "3")]
    pub x509_svid_key: ::prost::bytes::Bytes,
    #[prost(bytes = "bytes", tag = "4")]
    pub bundle: ::prost::bytes::Bytes,
    #[prost(string, tag = "5")]
    pub hint: ::prost::alloc::string::String,
}

/// Generated server implementations.
pub mod spiffe_workload_api_server {
    #![allow(
        unused_variables,
        dead_code,
        missing_docs,
        clippy::wildcard_imports,
        clippy::let_unit_value,
        reason = "tonic generated server surface"
    )]

    use tonic::codegen::*;

    #[async_trait]
    pub trait SpiffeWorkloadApi: std::marker::Send + std::marker::Sync + 'static {
        type FetchX509svidStream: tonic::codegen::tokio_stream::Stream<
                Item = std::result::Result<super::X509svidResponse, tonic::Status>,
            > + std::marker::Send
            + 'static;

        async fn fetch_x509svid(
            &self,
            request: tonic::Request<super::X509svidRequest>,
        ) -> std::result::Result<tonic::Response<Self::FetchX509svidStream>, tonic::Status>;
    }

    #[derive(Debug)]
    pub struct SpiffeWorkloadApiServer<T> {
        inner: Arc<T>,
    }

    impl<T> SpiffeWorkloadApiServer<T> {
        pub fn new(inner: T) -> Self {
            Self {
                inner: Arc::new(inner),
            }
        }
    }

    impl<T, B> tonic::codegen::Service<http::Request<B>> for SpiffeWorkloadApiServer<T>
    where
        T: SpiffeWorkloadApi,
        B: Body + std::marker::Send + 'static,
        B::Error: Into<StdError> + std::marker::Send + 'static,
    {
        type Response = http::Response<tonic::body::Body>;
        type Error = std::convert::Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;

        fn poll_ready(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<std::result::Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: http::Request<B>) -> Self::Future {
            match request.uri().path() {
                "/SpiffeWorkloadAPI/FetchX509SVID" => {
                    #[allow(non_camel_case_types)]
                    struct FetchX509SVIDSvc<T: SpiffeWorkloadApi>(pub Arc<T>);
                    impl<T: SpiffeWorkloadApi>
                        tonic::server::ServerStreamingService<super::X509svidRequest>
                        for FetchX509SVIDSvc<T>
                    {
                        type Response = super::X509svidResponse;
                        type ResponseStream = T::FetchX509svidStream;
                        type Future =
                            BoxFuture<tonic::Response<Self::ResponseStream>, tonic::Status>;

                        fn call(
                            &mut self,
                            request: tonic::Request<super::X509svidRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            Box::pin(async move {
                                <T as SpiffeWorkloadApi>::fetch_x509svid(&inner, request).await
                            })
                        }
                    }

                    let inner = Arc::clone(&self.inner);
                    Box::pin(async move {
                        let method = FetchX509SVIDSvc(inner);
                        let codec = tonic_prost::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec);
                        Ok(grpc.server_streaming(method, request).await)
                    })
                }
                _ => Box::pin(async move {
                    let mut response = http::Response::new(tonic::body::Body::default());
                    let headers = response.headers_mut();
                    headers.insert(
                        tonic::Status::GRPC_STATUS,
                        (tonic::Code::Unimplemented as i32).into(),
                    );
                    headers.insert(
                        http::header::CONTENT_TYPE,
                        tonic::metadata::GRPC_CONTENT_TYPE,
                    );
                    Ok(response)
                }),
            }
        }
    }

    impl<T> Clone for SpiffeWorkloadApiServer<T> {
        fn clone(&self) -> Self {
            Self {
                inner: Arc::clone(&self.inner),
            }
        }
    }

    pub const SERVICE_NAME: &str = "SpiffeWorkloadAPI";

    impl<T> tonic::server::NamedService for SpiffeWorkloadApiServer<T> {
        const NAME: &'static str = SERVICE_NAME;
    }
}
