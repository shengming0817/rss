//! Closed private-CA client construction for S3 general and DLX archive providers.
//!
//! The adapter owns the AWS SDK HTTP/TLS assembly so production and live conformance cannot drift
//! into separate trust-store implementations.

use std::sync::Arc;

use aws_sdk_s3::config::{Credentials, ProvideCredentials, Region, SharedHttpClient};
use aws_smithy_http_client::tls::{self, TrustStore};
use diport::Clock;
use secure::S3Endpoint;

use crate::{S3DlxArchiveStore, VerifiedS3DlxArchiveStore};

/// Typed factory for an S3 client that trusts exactly one caller-supplied private CA bundle.
#[derive(Clone)]
pub struct PrivateCaS3ClientFactory {
    endpoint: S3Endpoint,
    region: String,
    credentials: Credentials,
    force_path_style: bool,
    ca_cert_pem: Vec<u8>,
}

impl PrivateCaS3ClientFactory {
    /// Captures every input that affects the production S3 SDK client.
    pub fn new(
        endpoint: S3Endpoint,
        region: impl Into<String>,
        credentials: Credentials,
        force_path_style: bool,
        ca_cert_pem: Vec<u8>,
    ) -> Self {
        Self {
            endpoint,
            region: region.into(),
            credentials,
            force_path_style,
            ca_cert_pem,
        }
    }

    /// Shared private-CA HTTPS client used by general and DLX SDK construction.
    pub fn build_https_client(&self) -> Result<SharedHttpClient, PrivateCaS3BuildError> {
        build_private_ca_https_client(&self.ca_cert_pem)
    }

    /// Builds an AWS SDK client through the canonical private-CA TLS funnel.
    pub fn build_client(&self) -> Result<aws_sdk_s3::Client, PrivateCaS3BuildError> {
        self.build_client_with_credentials_provider(self.credentials.clone())
    }

    /// Builds an AWS SDK client with a caller-supplied credentials provider and the shared TLS funnel.
    pub fn build_client_with_credentials_provider(
        &self,
        credentials_provider: impl ProvideCredentials + 'static,
    ) -> Result<aws_sdk_s3::Client, PrivateCaS3BuildError> {
        let http = self.build_https_client()?;
        let sdk = aws_sdk_s3::config::Builder::new()
            .behavior_version_latest()
            .region(Region::new(self.region.clone()))
            .credentials_provider(credentials_provider)
            .endpoint_url(self.endpoint.expose())
            .force_path_style(self.force_path_style)
            .http_client(http)
            .build();
        Ok(aws_sdk_s3::Client::from_conf(sdk))
    }

    /// Builds a DLX archive store through the shared TLS funnel and a caller-owned credentials provider.
    pub fn build_dlx_archive_store(
        &self,
        bucket: impl Into<String>,
        clock: Arc<dyn Clock>,
        credentials_provider: impl ProvideCredentials + 'static,
    ) -> Result<S3DlxArchiveStore, PrivateCaS3BuildError> {
        Ok(S3DlxArchiveStore::new(
            self.build_client_with_credentials_provider(credentials_provider)?,
            bucket,
            clock,
        )?)
    }

    /// Builds and verifies the dedicated DLX archive store through the same client funnel.
    pub async fn build_verified_dlx_archive_store(
        &self,
        bucket: impl Into<String>,
        clock: Arc<dyn Clock>,
    ) -> Result<VerifiedS3DlxArchiveStore, PrivateCaS3BuildError> {
        Ok(self
            .build_dlx_archive_store(bucket, clock, self.credentials.clone())?
            .verify()
            .await?)
    }
}

/// Builds the canonical private-CA HTTPS client from a PEM trust-anchor bundle.
///
/// Crate-private on purpose: production and conformance must enter only through
/// [`PrivateCaS3ClientFactory`] (single TLS funnel).
pub(crate) fn build_private_ca_https_client(
    ca_cert_pem: &[u8],
) -> Result<SharedHttpClient, PrivateCaS3BuildError> {
    let trust = TrustStore::empty().with_pem_certificate(ca_cert_pem.to_vec());
    let tls = tls::TlsContext::builder()
        .with_trust_store(trust)
        .build()
        .map_err(PrivateCaS3BuildError::TlsContext)?;
    Ok(aws_smithy_http_client::Builder::new()
        .tls_provider(tls::Provider::Rustls(
            tls::rustls_provider::CryptoMode::Ring,
        ))
        .tls_context(tls)
        .build_https())
}

/// Fail-closed construction error for the canonical private-CA S3 archive funnel.
#[derive(Debug, thiserror::Error)]
pub enum PrivateCaS3BuildError {
    /// The private trust store could not be converted into an HTTPS client context.
    #[error("build S3 private-CA TLS context")]
    TlsContext(#[source] aws_smithy_http_client::HttpClientError),
    /// The archive bucket input was invalid.
    #[error("construct S3 DLX archive store")]
    ArchiveConfig(#[from] crate::S3DlxArchiveConfigError),
    /// The live provider did not satisfy the required WORM capabilities.
    #[error("verify S3 DLX archive capability")]
    ArchiveCapability(#[from] crate::S3DlxArchiveCapabilityError),
}
