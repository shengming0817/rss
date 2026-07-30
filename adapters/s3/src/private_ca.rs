//! Closed private-CA client construction for the SettingsOnly S3 archive provider.
//!
//! The adapter owns the AWS SDK HTTP/TLS assembly so production and live conformance cannot drift
//! into separate trust-store implementations.

use std::sync::Arc;

use aws_sdk_s3::config::{Credentials, Region};
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

    /// Builds an AWS SDK client through the canonical private-CA TLS funnel.
    pub fn build_client(&self) -> Result<aws_sdk_s3::Client, PrivateCaS3BuildError> {
        let trust = TrustStore::empty().with_pem_certificate(self.ca_cert_pem.clone());
        let tls = tls::TlsContext::builder()
            .with_trust_store(trust)
            .build()
            .map_err(PrivateCaS3BuildError::TlsContext)?;
        let http = aws_smithy_http_client::Builder::new()
            .tls_provider(tls::Provider::Rustls(
                tls::rustls_provider::CryptoMode::Ring,
            ))
            .tls_context(tls)
            .build_https();
        let sdk = aws_sdk_s3::config::Builder::new()
            .behavior_version_latest()
            .region(Region::new(self.region.clone()))
            .credentials_provider(self.credentials.clone())
            .endpoint_url(self.endpoint.expose())
            .force_path_style(self.force_path_style)
            .http_client(http)
            .build();
        Ok(aws_sdk_s3::Client::from_conf(sdk))
    }

    /// Builds and verifies the dedicated DLX archive store through the same client funnel.
    pub async fn build_verified_dlx_archive_store(
        &self,
        bucket: impl Into<String>,
        clock: Arc<dyn Clock>,
    ) -> Result<VerifiedS3DlxArchiveStore, PrivateCaS3BuildError> {
        Ok(S3DlxArchiveStore::new(self.build_client()?, bucket, clock)?
            .verify()
            .await?)
    }
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
