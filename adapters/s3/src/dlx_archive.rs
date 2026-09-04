//! Dedicated S3 WORM capability for dead-letter cold archives.
//!
//! This module intentionally does not reuse [`crate::S3Store`]: a DLX archive credential must not
//! acquire the generic object's destructive or enumeration capabilities. Only the verified wrapper
//! is allowed to implement the lifecycle archive port.

use std::sync::Arc;
use std::time::SystemTime;

use aws_sdk_s3::Client;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{
    BucketVersioningStatus, ChecksumMode, ExpirationStatus, LifecycleRule, ObjectLockEnabled,
    ObjectLockMode as S3ObjectLockMode, ObjectLockRetentionMode,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use diport::{
    ArchiveChecksum, ArchiveVersionId, DLX_MAX_ARCHIVE_CIPHERTEXT_BYTES, DlxArchiveCiphertext,
    DlxArchiveHeadOutcome, DlxArchiveObjectMetadata, DlxArchivePutOutcome, DlxArchivePutRequest,
    DlxArchiveStore, DlxLifecycleError, DlxLifecycleOperation, DlxLifecycleReason, KeyRef,
};
use eventexec::DLX_HOT_RETENTION_SECONDS;
use rss_redact::RedactedBytes;

const SECONDS_PER_DAY: i64 = 24 * 60 * 60;
const CANARY_GENERATION_SECS: i64 = SECONDS_PER_DAY;
const CANARY_KEY_PREFIX: &str = "__rss_capability_probe/dlx-worm-v2";
const CANARY_BODY: &[u8] = b"rss-dlx-worm-capability-v2";
const ARCHIVE_KEY_REF_METADATA: &str = "rss-dlx-key-ref";

pub trait ArchiveClock: Send + Sync {
    fn now(&self) -> SystemTime;
}

/// Invalid construction parameters for the dedicated DLX archive provider.
#[derive(Debug, thiserror::Error)]
pub enum S3DlxArchiveConfigError {
    /// Bucket names are mandatory; there is no shared-bucket fallback.
    #[error("dlx archive bucket must not be empty")]
    EmptyBucket,
}

/// Fail-closed startup capability gate error.
#[derive(Debug, thiserror::Error)]
pub enum S3DlxArchiveCapabilityError {
    /// The provider call failed; details are emitted only through the redacted diagnostic funnel.
    #[error("dlx archive S3 capability probe failed")]
    Provider,
    /// Bucket versioning is not enabled.
    #[error("dlx archive bucket versioning must be enabled")]
    VersioningRequired,
    /// Object Lock is absent or disabled.
    #[error("dlx archive bucket Object Lock must be enabled")]
    ObjectLockRequired,
    /// Default retention is not COMPLIANCE.
    #[error("dlx archive bucket default Object Lock mode must be COMPLIANCE")]
    ComplianceRequired,
    /// The configured default retention is not strictly longer than the 30-day hot window.
    #[error("dlx archive bucket default retention must be strictly longer than 30 days")]
    RetentionTooShort,
    /// No enabled, bucket-wide lifecycle rule bounds both current and noncurrent archive versions.
    #[error(
        "dlx archive bucket lifecycle must expire current and noncurrent versions strictly after 30 days"
    )]
    LifecycleRequired,
    /// The provider did not preserve create-only, checksum, or WORM metadata semantics.
    #[error("dlx archive S3 canary semantics are invalid")]
    CanaryInvariant,
}

#[derive(Clone)]
struct ArchiveCore {
    client: Client,
    bucket: String,
    clock: Arc<dyn ArchiveClock>,
}

/// Unverified S3 DLX archive provider.
///
/// This type deliberately does **not** implement `diport::DlxArchiveStore`. Call [`Self::verify`]
/// at startup and inject only the resulting [`VerifiedS3DlxArchiveStore`].
///
/// ```compile_fail
/// fn requires_verified<T: diport::DlxArchiveStore>() {}
/// requires_verified::<s3::S3DlxArchiveStore>();
/// ```
pub struct S3DlxArchiveStore {
    core: ArchiveCore,
}

/// S3 DLX archive provider whose bucket passed the versioning, Object Lock, retention, conditional
/// create, checksum, and HEAD startup probe.
///
/// It intentionally cannot be substituted for the generic object-store provider, keeping its
/// capability surface free of destructive generic operations:
///
/// ```compile_fail
/// fn requires_generic_store<T: diport::ObjectStore>() {}
/// requires_generic_store::<s3::VerifiedS3DlxArchiveStore>();
/// ```
#[derive(Clone)]
pub struct VerifiedS3DlxArchiveStore {
    core: ArchiveCore,
}

impl S3DlxArchiveStore {
    /// Builds the unverified provider. Endpoint, region, credentials, and TLS remain composition-root
    /// concerns; the dedicated bucket and clock are mandatory positional dependencies.
    pub fn new(
        client: Client,
        bucket: impl Into<String>,
        clock: Arc<dyn ArchiveClock>,
    ) -> Result<Self, S3DlxArchiveConfigError> {
        let bucket = bucket.into();
        if bucket.trim().is_empty() {
            return Err(S3DlxArchiveConfigError::EmptyBucket);
        }
        Ok(Self {
            core: ArchiveCore {
                client,
                bucket,
                clock,
            },
        })
    }

    /// Executes the fail-closed WORM capability gate and returns the only type that can implement the
    /// archive port.
    pub async fn verify(self) -> Result<VerifiedS3DlxArchiveStore, S3DlxArchiveCapabilityError> {
        verify_read_only_capabilities(&self.core).await?;
        self.verify_canary().await?;
        Ok(VerifiedS3DlxArchiveStore { core: self.core })
    }

    async fn verify_canary(&self) -> Result<(), S3DlxArchiveCapabilityError> {
        let now = now_epoch(&self.core)?;
        let canary_key = canary_key_for_epoch(now);
        let checksum = sha256(CANARY_BODY);
        let first = put_if_absent_raw(&self.core, &canary_key, CANARY_BODY, checksum, None)
            .await
            .map_err(capability_operation_error)?;
        let first_metadata = metadata_after_put(&self.core, &canary_key, first)
            .await
            .map_err(capability_operation_error)?;
        let second = put_if_absent_raw(&self.core, &canary_key, CANARY_BODY, checksum, None)
            .await
            .map_err(capability_operation_error)?;
        if !matches!(second, RawPutOutcome::AlreadyExists) {
            return Err(S3DlxArchiveCapabilityError::CanaryInvariant);
        }
        let head = head_current_raw(&self.core, &canary_key)
            .await
            .map_err(capability_operation_error)?;
        let RawHeadOutcome::Present(metadata) = head else {
            return Err(S3DlxArchiveCapabilityError::CanaryInvariant);
        };
        if metadata.version_id != first_metadata.version_id
            || metadata.checksum != checksum
            || !retention_is_active(now, &metadata)
        {
            return Err(S3DlxArchiveCapabilityError::CanaryInvariant);
        }
        Ok(())
    }
}

impl VerifiedS3DlxArchiveStore {
    /// Re-checks the read-only bucket capabilities used by the runtime readiness probe.
    ///
    /// This intentionally does not create an object: the startup gate proves conditional-create,
    /// checksum and HEAD semantics once, while the periodic probe detects provider outages and
    /// versioning/Object-Lock/lifecycle drift with the narrow read-only IAM surface.
    pub async fn probe_readiness(&self) -> Result<(), S3DlxArchiveCapabilityError> {
        verify_read_only_capabilities(&self.core).await
    }
}

async fn verify_read_only_capabilities(
    core: &ArchiveCore,
) -> Result<(), S3DlxArchiveCapabilityError> {
    verify_versioning(core).await?;
    let minimum_retention_seconds = verify_default_object_lock(core).await?;
    verify_lifecycle(core, minimum_retention_seconds).await
}

async fn verify_versioning(core: &ArchiveCore) -> Result<(), S3DlxArchiveCapabilityError> {
    let output = core
        .client
        .get_bucket_versioning()
        .bucket(&core.bucket)
        .send()
        .await
        .map_err(capability_provider_error)?;
    if output.status() != Some(&BucketVersioningStatus::Enabled) {
        return Err(S3DlxArchiveCapabilityError::VersioningRequired);
    }
    Ok(())
}

async fn verify_default_object_lock(
    core: &ArchiveCore,
) -> Result<i64, S3DlxArchiveCapabilityError> {
    let output = core
        .client
        .get_object_lock_configuration()
        .bucket(&core.bucket)
        .send()
        .await
        .map_err(capability_provider_error)?;
    let configuration = output
        .object_lock_configuration()
        .ok_or(S3DlxArchiveCapabilityError::ObjectLockRequired)?;
    if configuration.object_lock_enabled() != Some(&ObjectLockEnabled::Enabled) {
        return Err(S3DlxArchiveCapabilityError::ObjectLockRequired);
    }
    let retention = configuration
        .rule()
        .and_then(|rule| rule.default_retention())
        .ok_or(S3DlxArchiveCapabilityError::RetentionTooShort)?;
    if retention.mode() != Some(&ObjectLockRetentionMode::Compliance) {
        return Err(S3DlxArchiveCapabilityError::ComplianceRequired);
    }
    let retention_seconds = retention_seconds(retention.days(), retention.years())
        .ok_or(S3DlxArchiveCapabilityError::RetentionTooShort)?;
    if retention_seconds <= DLX_HOT_RETENTION_SECONDS {
        return Err(S3DlxArchiveCapabilityError::RetentionTooShort);
    }
    Ok(retention_seconds)
}

async fn verify_lifecycle(
    core: &ArchiveCore,
    minimum_retention_seconds: i64,
) -> Result<(), S3DlxArchiveCapabilityError> {
    use aws_sdk_s3::error::ProvideErrorMetadata as _;

    let output = core
        .client
        .get_bucket_lifecycle_configuration()
        .bucket(&core.bucket)
        .send()
        .await
        .map_err(|error| {
            if error.as_service_error().and_then(|service| service.code())
                == Some("NoSuchLifecycleConfiguration")
            {
                S3DlxArchiveCapabilityError::LifecycleRequired
            } else {
                capability_provider_error(error)
            }
        })?;
    if output
        .rules()
        .iter()
        .any(|rule| lifecycle_rule_is_safe(rule, minimum_retention_seconds))
    {
        Ok(())
    } else {
        Err(S3DlxArchiveCapabilityError::LifecycleRequired)
    }
}

fn lifecycle_rule_is_safe(rule: &LifecycleRule, minimum_retention_seconds: i64) -> bool {
    rule.status() == &ExpirationStatus::Enabled
        && lifecycle_rule_applies_to_all_objects(rule)
        && rule
            .expiration()
            .and_then(|expiration| expiration.days())
            .is_some_and(|days| expiration_exceeds_retention(days, minimum_retention_seconds))
        && rule
            .noncurrent_version_expiration()
            .and_then(|expiration| expiration.noncurrent_days())
            .is_some_and(|days| expiration_exceeds_retention(days, minimum_retention_seconds))
}

fn lifecycle_rule_applies_to_all_objects(rule: &LifecycleRule) -> bool {
    rule.filter().is_some_and(|filter| {
        filter.prefix().is_none_or(str::is_empty)
            && filter.tag().is_none()
            && filter.object_size_greater_than().is_none()
            && filter.object_size_less_than().is_none()
            && filter.and().is_none()
    })
}

impl DlxArchiveStore for VerifiedS3DlxArchiveStore {
    type ObjectKey = eventexec::DlxArchiveObjectKey;

    async fn put_if_absent(
        &self,
        request: DlxArchivePutRequest<Self::ObjectKey>,
    ) -> Result<DlxArchivePutOutcome, DlxLifecycleError> {
        let checksum = *request.checksum().as_bytes();
        let key_ref = request.ciphertext().key_ref().to_token();
        let outcome = put_if_absent_raw(
            &self.core,
            request.object_key().as_str(),
            request.ciphertext().ciphertext().as_bytes(),
            checksum,
            Some(&key_ref),
        )
        .await
        .map_err(|error| lifecycle_operation_error(DlxLifecycleOperation::PutArchive, error))?;
        match outcome {
            RawPutOutcome::AlreadyExists => {
                let RawHeadOutcome::Present(raw) =
                    head_current_raw(&self.core, request.object_key().as_str())
                        .await
                        .map_err(|error| {
                            lifecycle_operation_error(DlxLifecycleOperation::HeadArchive, error)
                        })?
                else {
                    return Err(DlxLifecycleError::new(
                        DlxLifecycleOperation::HeadArchive,
                        DlxLifecycleReason::ObjectMissing,
                    ));
                };
                Ok(DlxArchivePutOutcome::AlreadyExists(lifecycle_metadata(raw)))
            }
            RawPutOutcome::Created(version_id) => {
                let metadata = require_active_created_head(
                    &self.core,
                    request.object_key().as_str(),
                    &version_id,
                    checksum,
                    &key_ref,
                )
                .await?;
                Ok(DlxArchivePutOutcome::Created(metadata))
            }
        }
    }

    async fn get_ciphertext(
        &self,
        key: &eventexec::DlxArchiveObjectKey,
        version_id: &ArchiveVersionId,
    ) -> Result<Option<DlxArchiveCiphertext>, DlxLifecycleError> {
        let ciphertext = get_raw(&self.core, key.as_str(), version_id)
            .await
            .map_err(|error| lifecycle_operation_error(DlxLifecycleOperation::GetArchive, error))?;
        ciphertext
            .map(|raw| {
                KeyRef::parse(&raw.key_ref)
                    .map(|key_ref| {
                        DlxArchiveCiphertext::new(RedactedBytes::new(raw.bytes), key_ref)
                    })
                    .map_err(|_| {
                        DlxLifecycleError::new(
                            DlxLifecycleOperation::GetArchive,
                            DlxLifecycleReason::InvalidArchiveFormat,
                        )
                    })
            })
            .transpose()
    }

    async fn head(
        &self,
        key: &eventexec::DlxArchiveObjectKey,
        version_id: &ArchiveVersionId,
    ) -> Result<DlxArchiveHeadOutcome, DlxLifecycleError> {
        match head_version_raw(&self.core, key.as_str(), version_id)
            .await
            .map_err(|error| lifecycle_operation_error(DlxLifecycleOperation::HeadArchive, error))?
        {
            RawHeadOutcome::Missing => Ok(DlxArchiveHeadOutcome::Missing),
            RawHeadOutcome::Present(raw) => {
                Ok(DlxArchiveHeadOutcome::Present(lifecycle_metadata(raw)))
            }
        }
    }
}

async fn require_active_created_head(
    core: &ArchiveCore,
    key: &str,
    version_id: &ArchiveVersionId,
    expected_checksum: [u8; 32],
    expected_key_ref: &str,
) -> Result<DlxArchiveObjectMetadata, DlxLifecycleError> {
    let head = head_version_raw(core, key, version_id)
        .await
        .map_err(|error| lifecycle_operation_error(DlxLifecycleOperation::HeadArchive, error))?;
    let RawHeadOutcome::Present(raw) = head else {
        return Err(DlxLifecycleError::new(
            DlxLifecycleOperation::HeadArchive,
            DlxLifecycleReason::ObjectMissing,
        ));
    };
    let now = epoch_secs(core.clock.now()).ok_or_else(|| {
        DlxLifecycleError::new(
            DlxLifecycleOperation::VerifyArchive,
            DlxLifecycleReason::ArithmeticOverflow,
        )
    })?;
    if raw.checksum != expected_checksum {
        return Err(DlxLifecycleError::new(
            DlxLifecycleOperation::VerifyArchive,
            DlxLifecycleReason::ChecksumMismatch,
        ));
    }
    if raw.key_ref.as_deref() != Some(expected_key_ref) {
        return Err(DlxLifecycleError::new(
            DlxLifecycleOperation::VerifyArchive,
            DlxLifecycleReason::KeyMismatch,
        ));
    }
    if !retention_is_active(now, &raw) {
        return Err(DlxLifecycleError::new(
            DlxLifecycleOperation::VerifyArchive,
            DlxLifecycleReason::RetentionInvalid,
        ));
    }
    Ok(lifecycle_metadata(raw))
}

fn lifecycle_metadata(raw: RawObjectMetadata) -> DlxArchiveObjectMetadata {
    DlxArchiveObjectMetadata::new(
        ArchiveChecksum::from_sha256_bytes(raw.checksum),
        raw.version_id,
        raw.retain_until_epoch_secs,
    )
}

fn lifecycle_operation_error(
    operation: DlxLifecycleOperation,
    error: RawOperationError,
) -> DlxLifecycleError {
    let reason = match error {
        RawOperationError::Provider => DlxLifecycleReason::ProviderUnavailable,
        RawOperationError::VersionDrift => DlxLifecycleReason::VersionDrift,
        RawOperationError::Invariant => DlxLifecycleReason::UnexpectedProviderResponse,
    };
    DlxLifecycleError::new(operation, reason)
}

fn retention_seconds(days: Option<i32>, years: Option<i32>) -> Option<i64> {
    match (days, years) {
        (Some(days), None) => i64::from(days).checked_mul(SECONDS_PER_DAY),
        (None, Some(years)) => i64::from(years)
            .checked_mul(365)
            .and_then(|days| days.checked_mul(SECONDS_PER_DAY)),
        _ => None,
    }
}

fn expiration_exceeds_retention(days: i32, minimum_retention_seconds: i64) -> bool {
    i64::from(days)
        .checked_mul(SECONDS_PER_DAY)
        .is_some_and(|seconds| seconds > minimum_retention_seconds)
}

fn retention_is_active(now_epoch_secs: i64, metadata: &RawObjectMetadata) -> bool {
    now_epoch_secs
        .checked_add(DLX_HOT_RETENTION_SECONDS)
        .is_some_and(|minimum| metadata.retain_until_epoch_secs > minimum)
}

fn canary_key_for_epoch(now_epoch_secs: i64) -> String {
    let generation = now_epoch_secs.div_euclid(CANARY_GENERATION_SECS);
    format!("{CANARY_KEY_PREFIX}/{generation}")
}

fn now_epoch(core: &ArchiveCore) -> Result<i64, S3DlxArchiveCapabilityError> {
    epoch_secs(core.clock.now()).ok_or(S3DlxArchiveCapabilityError::CanaryInvariant)
}

fn epoch_secs(value: SystemTime) -> Option<i64> {
    value
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RawPutOutcome {
    Created(ArchiveVersionId),
    AlreadyExists,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawObjectMetadata {
    checksum: [u8; 32],
    version_id: ArchiveVersionId,
    retain_until_epoch_secs: i64,
    key_ref: Option<String>,
}

enum RawHeadOutcome {
    Present(RawObjectMetadata),
    Missing,
}

struct RawCiphertext {
    bytes: Vec<u8>,
    key_ref: String,
}

#[derive(Debug, thiserror::Error)]
enum RawOperationError {
    #[error("dlx archive S3 provider operation failed")]
    Provider,
    #[error("dlx archive S3 object invariant failed")]
    Invariant,
    #[error("dlx archive S3 version observation changed during verification")]
    VersionDrift,
}

async fn put_if_absent_raw(
    core: &ArchiveCore,
    key: &str,
    body: &[u8],
    checksum: [u8; 32],
    key_ref: Option<&str>,
) -> Result<RawPutOutcome, RawOperationError> {
    if !ciphertext_size_allowed(body.len()) {
        return Err(RawOperationError::Invariant);
    }
    let checksum_header = BASE64_STANDARD.encode(checksum);
    let mut request = core
        .client
        .put_object()
        .bucket(&core.bucket)
        .key(key)
        .if_none_match("*")
        .checksum_sha256(&checksum_header)
        .body(ByteStream::from(body.to_vec()));
    if let Some(key_ref) = key_ref {
        request = request.metadata(ARCHIVE_KEY_REF_METADATA, key_ref);
    }
    match request.send().await {
        Ok(output) => {
            if output.checksum_sha256() != Some(checksum_header.as_str()) {
                return Err(RawOperationError::Invariant);
            }
            let version_id = output
                .version_id()
                .ok_or(RawOperationError::Invariant)
                .and_then(parse_version_id)?;
            Ok(RawPutOutcome::Created(version_id))
        }
        Err(error) if put_precondition_failed(&error) => Ok(RawPutOutcome::AlreadyExists),
        Err(error) => Err(operation_provider_error("put-if-absent", error)),
    }
}

fn put_precondition_failed(
    error: &aws_sdk_s3::error::SdkError<aws_sdk_s3::operation::put_object::PutObjectError>,
) -> bool {
    use aws_sdk_s3::error::ProvideErrorMetadata as _;

    error
        .as_service_error()
        .and_then(|service| service.code())
        .is_some_and(|code| code == "PreconditionFailed")
        || error
            .raw_response()
            .is_some_and(|response| response.status().as_u16() == 412)
}

async fn head_current_raw(
    core: &ArchiveCore,
    key: &str,
) -> Result<RawHeadOutcome, RawOperationError> {
    head_raw(core, key, None).await
}

async fn head_version_raw(
    core: &ArchiveCore,
    key: &str,
    version_id: &ArchiveVersionId,
) -> Result<RawHeadOutcome, RawOperationError> {
    head_raw(core, key, Some(version_id)).await
}

async fn head_raw(
    core: &ArchiveCore,
    key: &str,
    expected_version_id: Option<&ArchiveVersionId>,
) -> Result<RawHeadOutcome, RawOperationError> {
    let mut request = core.client.head_object().bucket(&core.bucket).key(key);
    if let Some(version_id) = expected_version_id {
        request = request.version_id(version_id.as_str());
    }
    let output = match request.checksum_mode(ChecksumMode::Enabled).send().await {
        Ok(output) => output,
        Err(error) if head_not_found(&error) => return Ok(RawHeadOutcome::Missing),
        Err(error) => return Err(operation_provider_error("head", error)),
    };
    let version_id = output
        .version_id()
        .ok_or(RawOperationError::VersionDrift)
        .and_then(parse_version_id)?;
    if expected_version_id.is_some_and(|expected| expected != &version_id) {
        return Err(RawOperationError::VersionDrift);
    }
    if output.object_lock_mode() != Some(&S3ObjectLockMode::Compliance) {
        return Err(RawOperationError::Invariant);
    }
    let checksum = output
        .checksum_sha256()
        .and_then(parse_checksum)
        .ok_or(RawOperationError::Invariant)?;
    let retain_until_epoch_secs = output
        .object_lock_retain_until_date()
        .map(aws_sdk_s3::primitives::DateTime::secs)
        .ok_or(RawOperationError::Invariant)?;
    let key_ref = output
        .metadata()
        .and_then(|metadata| metadata.get(ARCHIVE_KEY_REF_METADATA))
        .cloned();
    Ok(RawHeadOutcome::Present(RawObjectMetadata {
        checksum,
        version_id,
        retain_until_epoch_secs,
        key_ref,
    }))
}

fn head_not_found(
    error: &aws_sdk_s3::error::SdkError<aws_sdk_s3::operation::head_object::HeadObjectError>,
) -> bool {
    error
        .as_service_error()
        .is_some_and(aws_sdk_s3::operation::head_object::HeadObjectError::is_not_found)
        || error
            .raw_response()
            .is_some_and(|response| response.status().as_u16() == 404)
}

async fn get_raw(
    core: &ArchiveCore,
    key: &str,
    version_id: &ArchiveVersionId,
) -> Result<Option<RawCiphertext>, RawOperationError> {
    let output = match core
        .client
        .get_object()
        .bucket(&core.bucket)
        .key(key)
        .version_id(version_id.as_str())
        .checksum_mode(ChecksumMode::Enabled)
        .send()
        .await
    {
        Ok(output) => output,
        Err(error) if get_not_found(&error) => return Ok(None),
        Err(error) => return Err(operation_provider_error("get", error)),
    };
    let observed_version_id = output
        .version_id()
        .ok_or(RawOperationError::VersionDrift)
        .and_then(parse_version_id)?;
    if &observed_version_id != version_id {
        return Err(RawOperationError::VersionDrift);
    }
    let expected_checksum = output
        .checksum_sha256()
        .and_then(parse_checksum)
        .ok_or(RawOperationError::Invariant)?;
    let key_ref = output
        .metadata()
        .and_then(|metadata| metadata.get(ARCHIVE_KEY_REF_METADATA))
        .cloned()
        .ok_or(RawOperationError::Invariant)?;
    let bytes = collect_ciphertext(output.body).await?;
    if sha256(&bytes) != expected_checksum {
        return Err(RawOperationError::Invariant);
    }
    Ok(Some(RawCiphertext { bytes, key_ref }))
}

fn get_not_found(
    error: &aws_sdk_s3::error::SdkError<aws_sdk_s3::operation::get_object::GetObjectError>,
) -> bool {
    error
        .as_service_error()
        .is_some_and(aws_sdk_s3::operation::get_object::GetObjectError::is_no_such_key)
        || error
            .raw_response()
            .is_some_and(|response| response.status().as_u16() == 404)
}

async fn collect_ciphertext(mut body: ByteStream) -> Result<Vec<u8>, RawOperationError> {
    let mut bytes = Vec::new();
    while let Some(next) = body.next().await {
        let chunk = next.map_err(|error| operation_provider_error("get-stream", error))?;
        let next_len = bytes
            .len()
            .checked_add(chunk.len())
            .ok_or(RawOperationError::Invariant)?;
        if !ciphertext_size_allowed(next_len) {
            return Err(RawOperationError::Invariant);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn ciphertext_size_allowed(len: usize) -> bool {
    len <= DLX_MAX_ARCHIVE_CIPHERTEXT_BYTES
}

fn parse_version_id(raw: &str) -> Result<ArchiveVersionId, RawOperationError> {
    ArchiveVersionId::try_from_provider(raw).map_err(|_| RawOperationError::Invariant)
}

async fn metadata_after_put(
    core: &ArchiveCore,
    key: &str,
    outcome: RawPutOutcome,
) -> Result<RawObjectMetadata, RawOperationError> {
    let head = match outcome {
        RawPutOutcome::Created(version_id) => head_version_raw(core, key, &version_id).await?,
        RawPutOutcome::AlreadyExists => head_current_raw(core, key).await?,
    };
    match head {
        RawHeadOutcome::Present(metadata) => Ok(metadata),
        RawHeadOutcome::Missing => Err(RawOperationError::VersionDrift),
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    *ArchiveChecksum::sha256(bytes).as_bytes()
}

fn parse_checksum(value: &str) -> Option<[u8; 32]> {
    let decoded = BASE64_STANDARD.decode(value).ok()?;
    decoded.try_into().ok()
}

fn capability_operation_error(error: RawOperationError) -> S3DlxArchiveCapabilityError {
    match error {
        RawOperationError::Provider => S3DlxArchiveCapabilityError::Provider,
        RawOperationError::Invariant | RawOperationError::VersionDrift => {
            S3DlxArchiveCapabilityError::CanaryInvariant
        }
    }
}

fn capability_provider_error<E>(error: E) -> S3DlxArchiveCapabilityError
where
    E: std::error::Error,
{
    tracing::warn!(
        target: "s3",
        resource = "dlx_archive",
        operation = "capability-probe",
        error = %rss_redact::redact_error(&error),
        "dlx archive S3 capability probe failed"
    );
    S3DlxArchiveCapabilityError::Provider
}

fn operation_provider_error<E>(operation: &'static str, error: E) -> RawOperationError
where
    E: std::error::Error,
{
    tracing::warn!(
        target: "s3",
        resource = "dlx_archive",
        operation,
        error = %rss_redact::redact_error(&error),
        "dlx archive S3 operation failed"
    );
    RawOperationError::Provider
}

#[cfg(test)]
mod tests {
    use super::{
        ciphertext_size_allowed, expiration_exceeds_retention, parse_checksum, retention_seconds,
        sha256,
    };
    use base64::Engine as _;
    use diport::DLX_MAX_ARCHIVE_CIPHERTEXT_BYTES;

    #[test]
    fn retention_must_be_strictly_longer_than_hot_window() {
        let thirty_days = 30 * 24 * 60 * 60;
        assert_eq!(retention_seconds(Some(30), None), Some(thirty_days));
        assert!(expiration_exceeds_retention(31, thirty_days));
        assert_eq!(retention_seconds(None, Some(1)), Some(365 * 24 * 60 * 60));
        assert_eq!(retention_seconds(None, None), None);
        assert_eq!(retention_seconds(Some(31), Some(1)), None);
    }

    #[test]
    fn checksum_parser_requires_exact_sha256_width() {
        let checksum = sha256(b"dlx");
        let encoded = base64::engine::general_purpose::STANDARD.encode(checksum);
        assert_eq!(parse_checksum(&encoded), Some(checksum));
        assert_eq!(parse_checksum("AQ=="), None);
        assert_eq!(parse_checksum("not-base64"), None);
    }

    #[test]
    fn archive_ciphertext_size_is_bounded_symmetrically() {
        assert!(ciphertext_size_allowed(DLX_MAX_ARCHIVE_CIPHERTEXT_BYTES));
        assert!(!ciphertext_size_allowed(
            DLX_MAX_ARCHIVE_CIPHERTEXT_BYTES.saturating_add(1)
        ));
    }
}
