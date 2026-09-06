#![doc=include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
use aws_sdk_s3::{
    Client,
    primitives::{ByteStream, DateTime},
    types::{BucketVersioningStatus, ChecksumMode, ObjectLockEnabled, ObjectLockMode},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_transactional_messaging::policy::OperationDeadline;
use rss_transactional_messaging_recovery::archive::{
    ArchiveObjectStore, Error, MAX_OBJECT_BYTES, Object, Observation, Prepared,
};
use sha2::{Digest, Sha256};
/// Product-owned wall clock, used only for startup canary retention.
pub trait Clock {
    /// UTC epoch seconds.
    fn unix_seconds(&self) -> i64;
}
/// Unverified client; deliberately does not implement the archive port.
/// ```compile_fail
/// use rss_transactional_messaging_recovery::archive::ArchiveObjectStore;
/// fn needs_verified<T: ArchiveObjectStore>() {}
/// needs_verified::<rss_transactional_messaging_recovery_s3::Unverified>();
/// ```
pub struct Unverified {
    client: Client,
    bucket: String,
}
/// Capability produced only after a real bucket and conditional-write probe.
pub struct S3ArchiveStore {
    client: Client,
    bucket: String,
}
impl Unverified {
    /// The supplied SDK client owns TLS, endpoint, identity and encryption configuration.
    pub fn new(client: Client, bucket: String) -> Result<Self, Error> {
        if bucket.is_empty() || bucket.len() > 255 {
            return Err(Error::Invalid);
        }
        Ok(Self { client, bucket })
    }
    /// Probe actual versioning, Object Lock, checksum and conditional-create behavior under one budget.
    pub async fn verify<C: Clock>(
        self,
        clock: &C,
        deadline: OperationDeadline,
    ) -> Result<S3ArchiveStore, Error> {
        let retain = clock
            .unix_seconds()
            .checked_add(60)
            .ok_or(Error::Retention)?;
        // SDK request futures are large; keep the public capability future bounded in stack size.
        tokio::time::timeout(
            deadline.timeout(),
            Box::pin(async move {
                let version = self
                    .client
                    .get_bucket_versioning()
                    .bucket(&self.bucket)
                    .send()
                    .await
                    .map_err(sdk_error)?;
                if version.status() != Some(&BucketVersioningStatus::Enabled) {
                    return Err(Error::StorageContract);
                }
                let lock = self
                    .client
                    .get_object_lock_configuration()
                    .bucket(&self.bucket)
                    .send()
                    .await
                    .map_err(sdk_error)?;
                if lock
                    .object_lock_configuration()
                    .and_then(|c| c.object_lock_enabled())
                    != Some(&ObjectLockEnabled::Enabled)
                {
                    return Err(Error::StorageContract);
                }
                let store = S3ArchiveStore {
                    client: self.client,
                    bucket: self.bucket,
                };
                let bytes = uuid::Uuid::new_v4().as_bytes().to_vec();
                let p = Prepared {
                    object: Object {
                        key: format!(".rss-archive-probe/{}", uuid::Uuid::new_v4()),
                        checksum: Sha256::digest(&bytes).into(),
                        length: bytes.len() as u64,
                        version: None,
                        retain_until: retain,
                    },
                    bytes,
                };
                let first = store.put_inner(&p).await?;
                let second = store.put_inner(&p).await?;
                if first != second {
                    return Err(Error::StorageContract);
                }
                let observed = store
                    .inspect_inner(&first, true)
                    .await?
                    .ok_or(Error::Evidence)?;
                if observed.bytes.as_deref() != Some(p.bytes.as_slice()) || !observed.compliance {
                    return Err(Error::Evidence);
                }
                Ok(store)
            }),
        )
        .await
        .map_err(|_| Error::Deadline)?
    }
}
impl S3ArchiveStore {
    async fn put_inner(&self, p: &Prepared) -> Result<Object, Error> {
        if p.bytes.is_empty()
            || p.bytes.len() > MAX_OBJECT_BYTES
            || p.object.length != p.bytes.len() as u64
            || p.object.checksum != <[u8; 32]>::from(Sha256::digest(&p.bytes))
            || p.object.version.is_some()
        {
            return Err(Error::Invalid);
        }
        // ref: awslabs/aws-sdk-rust sdk/s3/src/operation/put_object/builders.rs@653085fbbc4a50138cf955445b65431bea3599d4
        let result = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(&p.object.key)
            .if_none_match("*")
            .checksum_sha256(STANDARD.encode(p.object.checksum))
            .object_lock_mode(ObjectLockMode::Compliance)
            .object_lock_retain_until_date(DateTime::from_secs(p.object.retain_until))
            .body(ByteStream::from(p.bytes.clone()))
            .send()
            .await;
        let version = match result {
            Ok(output) => Some(output.version_id().ok_or(Error::Evidence)?.to_owned()),
            Err(e) if e.raw_response().is_some_and(|r| r.status().as_u16() == 412) => None,
            // Includes 409 and transport errors: prepared bytes survive for a later bounded retry.
            Err(error) => return Err(sdk_error(error)),
        };
        let mut expected = p.object.clone();
        expected.version = version;
        let actual = self.head(&expected).await?.ok_or(Error::Evidence)?;
        if !actual.compliance
            || actual.object.key != expected.key
            || actual.object.checksum != expected.checksum
            || actual.object.length != expected.length
            || actual.object.retain_until < expected.retain_until
        {
            return Err(Error::Evidence);
        }
        if expected.version.is_some() && expected.version != actual.object.version {
            return Err(Error::Evidence);
        }
        Ok(actual.object)
    }
    async fn head(&self, object: &Object) -> Result<Option<Observation>, Error> {
        let response = self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(&object.key)
            .set_version_id(object.version.clone())
            .checksum_mode(ChecksumMode::Enabled)
            .send()
            .await;
        let output = match response {
            Ok(v) => v,
            Err(e) if e.as_service_error().is_some_and(|e| e.is_not_found()) => return Ok(None),
            Err(error) => return Err(sdk_error(error)),
        };
        let version = output
            .version_id()
            .filter(|s| !s.is_empty() && *s != "null")
            .ok_or(Error::Evidence)?
            .to_owned();
        let checksum: [u8; 32] = STANDARD
            .decode(output.checksum_sha256().ok_or(Error::Evidence)?)
            .map_err(|_| Error::Evidence)?
            .try_into()
            .map_err(|_| Error::Evidence)?;
        let length = u64::try_from(output.content_length().ok_or(Error::Evidence)?)
            .map_err(|_| Error::Evidence)?;
        if length > MAX_OBJECT_BYTES as u64 {
            return Err(Error::Evidence);
        }
        Ok(Some(Observation {
            object: Object {
                key: object.key.clone(),
                checksum,
                length,
                version: Some(version),
                retain_until: output
                    .object_lock_retain_until_date()
                    .ok_or(Error::Evidence)?
                    .secs(),
            },
            compliance: output.object_lock_mode() == Some(&ObjectLockMode::Compliance),
            bytes: None,
        }))
    }
    async fn inspect_inner(
        &self,
        object: &Object,
        body: bool,
    ) -> Result<Option<Observation>, Error> {
        let Some(mut result) = self.head(object).await? else {
            return Ok(None);
        };
        if object.version.is_some() && result.object.version != object.version {
            return Err(Error::Evidence);
        }
        if body {
            let mut response = self
                .client
                .get_object()
                .bucket(&self.bucket)
                .key(&object.key)
                .set_version_id(result.object.version.clone())
                .send()
                .await
                .map_err(sdk_error)?;
            if response.version_id() != result.object.version.as_deref() {
                return Err(Error::Evidence);
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response
                .body
                .try_next()
                .await
                .map_err(|_| Error::Unavailable)?
            {
                if bytes
                    .len()
                    .checked_add(chunk.len())
                    .is_none_or(|n| n > MAX_OBJECT_BYTES || n as u64 > result.object.length)
                {
                    return Err(Error::Evidence);
                }
                bytes.extend_from_slice(&chunk);
            }
            if bytes.len() as u64 != result.object.length
                || <[u8; 32]>::from(Sha256::digest(&bytes)) != result.object.checksum
            {
                return Err(Error::Evidence);
            }
            result.bytes = Some(bytes);
        }
        Ok(Some(result))
    }
}
impl ArchiveObjectStore for S3ArchiveStore {
    async fn put(&self, p: &Prepared, d: OperationDeadline) -> Result<Object, Error> {
        tokio::time::timeout(d.timeout(), Box::pin(self.put_inner(p)))
            .await
            .map_err(|_| Error::Deadline)?
    }
    async fn inspect(
        &self,
        o: &Object,
        body: bool,
        d: OperationDeadline,
    ) -> Result<Option<Observation>, Error> {
        tokio::time::timeout(d.timeout(), Box::pin(self.inspect_inner(o, body)))
            .await
            .map_err(|_| Error::Deadline)?
    }
}

/// Classify structured SDK variants/statuses without exposing provider diagnostics.
/// PUT callers still preserve settlement uncertainty independently of this error category.
fn sdk_error<E>(error: aws_sdk_s3::error::SdkError<E>) -> Error {
    use aws_sdk_s3::error::SdkError;
    if matches!(error, SdkError::ConstructionFailure(_)) {
        return Error::StorageContract;
    }
    match error
        .raw_response()
        .map(|response| response.status().as_u16())
    {
        Some(408 | 409 | 429 | 500..=599) | None => Error::Unavailable,
        Some(400..=499) => Error::StorageContract,
        _ => Error::Evidence,
    }
}
