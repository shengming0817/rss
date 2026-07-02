//! s3 adapter —— RSS workspace（W 阶段真身，#1011 对象存储切片）。
//!
//! 单一 `S3Store`：
//! - 始终 `impl diport::ManagedResource`（已冻结，ADAPTER-PORT-FREEZE-10）。
//! - `backend` feature 开时增补 `impl diport::ObjectStore`（aws-sdk-s3 put/get/delete）。
//!
//! feature-off（default build）：空壳编译、freeze smoke 类型断言仍有效；不引入 aws-sdk 依赖。
//! feature-on（`--features backend`）：持有 `aws_sdk_s3::Client` + 目标 bucket；client 由组合根 / 测试注入
//! （endpoint / region / 凭据 / 连接器在构造侧决定）——adapter **不**内建 HTTPS 连接器（`default-https-client`
//! 关，避开 aws-lc-rs / ring 的 license 收口，见 Cargo.toml；与 redis/amqp adapter 的 TLS 收口同范式）。
//! 测试用 `aws-smithy-mocks` 注入 canned 响应（确定性，无 live 后端、不拉 TLS）；live MinIO 集成测试显式
//! 注入 HTTP/TLS connector。
//! crate 保持 `forbid(unsafe_code)`（继承 workspace lints；只 import diport trait + aws-sdk，不 invoke dynosaur 宏）。

#[cfg(feature = "backend")]
mod store;

#[cfg(feature = "backend")]
use std::sync::Arc;

use diport::{DynManagedResource, ManagedResource, ShutdownError};

/// S3 对象存储 adapter（sealed-marker）。
///
/// `backend` feature 关时为空壳（仅供 freeze smoke 类型断言）；开时持有 aws-sdk-s3 `Client` + 目标 bucket。
pub struct S3Store {
    #[cfg(feature = "backend")]
    client: aws_sdk_s3::Client,
    #[cfg(feature = "backend")]
    bucket: String,
}

/// 空 bucket（构造期 fail-fast，不静默接受空 bucket 在运行期每次操作失败）。
#[cfg(feature = "backend")]
#[derive(Debug, thiserror::Error)]
#[error("s3 bucket must not be empty")]
pub struct EmptyBucket;

#[cfg(feature = "backend")]
impl S3Store {
    /// 由 aws-sdk-s3 `Client` + 目标 bucket 构造。
    ///
    /// **fail-fast**：拒绝空 bucket（误配在组合根接线期即暴露，不在运行期静默失败）。`client` 由组合根 /
    /// 测试构造（endpoint / region / 凭据 / 连接器在构造侧决定）——adapter 不内建 HTTPS 连接器（见 crate / Cargo.toml）。
    pub fn new(client: aws_sdk_s3::Client, bucket: impl Into<String>) -> Result<Self, EmptyBucket> {
        let bucket = bucket.into();
        if bucket.is_empty() {
            return Err(EmptyBucket);
        }
        Ok(Self { client, bucket })
    }
}

impl ManagedResource for S3Store {
    fn name(&self) -> &str {
        "s3"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        // reason: aws-sdk-s3 Client 无显式 close（无连接池句柄需释放——连接器在构造侧持有，随 drop 回收），
        // 关闭无需显式动作。
        Ok(())
    }
}

/// 组合根级 S3 能力包：私有持 `Arc<S3Store>`，派发真实对象存储句柄并产出 shutdown resource。
#[cfg(feature = "backend")]
#[derive(Clone)]
pub struct S3RuntimeDeps {
    store: Arc<S3Store>,
}

#[cfg(feature = "backend")]
impl S3RuntimeDeps {
    /// 由组合根注入已构造的 [`S3Store`]。endpoint/credentials/TLS provider 均不在 adapter 内解析。
    #[must_use]
    pub fn new(store: S3Store) -> Self {
        Self {
            store: Arc::new(store),
        }
    }

    /// 派发真实 object-store 句柄。返回 concrete `Arc<S3Store>`，避免 `Arc<DynObjectStore>` 的 Send/Sync 限制。
    #[must_use]
    pub fn object_store(&self) -> Arc<S3Store> {
        Arc::clone(&self.store)
    }

    /// 单源 managed-resource/rollback 派生：当前仅 S3 store guard。
    #[must_use]
    pub fn runtime_resources(&self) -> Vec<Box<DynManagedResource<'static>>> {
        vec![DynManagedResource::new_box(S3StoreGuard(Arc::clone(
            &self.store,
        )))]
    }
}

#[cfg(feature = "backend")]
struct S3StoreGuard(Arc<S3Store>);

#[cfg(feature = "backend")]
impl ManagedResource for S3StoreGuard {
    fn name(&self) -> &str {
        ManagedResource::name(&*self.0)
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        ManagedResource::shutdown(&*self.0).await
    }
}

#[cfg(feature = "backend")]
impl diport::ObjectStore for S3Store {
    async fn put_object(
        &self,
        key: diport::ObjectKey,
        body: Vec<u8>,
    ) -> Result<(), diport::ObjectStoreError> {
        store::put_impl(&self.client, &self.bucket, key, body).await
    }

    async fn get_object(
        &self,
        key: diport::ObjectKey,
    ) -> Result<Option<diport::ObjectPayload>, diport::ObjectStoreError> {
        store::get_impl(&self.client, &self.bucket, key).await
    }

    async fn delete_object(&self, key: diport::ObjectKey) -> Result<(), diport::ObjectStoreError> {
        store::delete_impl(&self.client, &self.bucket, key).await
    }

    async fn shutdown(&self) -> Result<(), diport::ObjectStoreError> {
        // reason: 同 ManagedResource::shutdown——无 infra 句柄需释放。port-local 关闭路径（参 diport rustdoc）。
        Ok(())
    }
}

#[cfg(test)]
mod smoke {
    //! build smoke：编译期断言 sealed-marker 已 impl 冻结的 diport DI port trait（PhantomData 绑定检查，
    //! 不构造、不执行 body）。
    //! INVARIANT: ADAPTER-PORT-FREEZE-10 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }—— sealed-marker impl 冻结的 diport DI port trait（ManagedResource
    //! 始终；ObjectStore 于 backend）；去掉任一 impl 即编译失败（anti-vacuity）。
    use core::marker::PhantomData;

    fn assert_managed_resource<T: diport::ManagedResource>(_: PhantomData<T>) {}

    #[test]
    fn impls_managed_resource() {
        assert_managed_resource(PhantomData::<super::S3Store>);
    }

    #[cfg(feature = "backend")]
    fn assert_object_store<T: diport::ObjectStore>(_: PhantomData<T>) {}

    #[cfg(feature = "backend")]
    #[test]
    fn impls_object_store() {
        assert_object_store(PhantomData::<super::S3Store>);
    }
}

#[cfg(all(test, feature = "backend"))]
mod backend_tests {
    //! 对象存储行为矩阵（aws-smithy-mocks canned 响应，确定性、无 live 后端）：
    //! put 成功 / get→Some / get NoSuchKey→None / get 其它错误→Err / delete 幂等成功 / 构造期 fail-fast /
    //! 生命周期 name+shutdown。
    use super::{S3RuntimeDeps, S3Store};
    use aws_sdk_s3::operation::delete_object::DeleteObjectOutput;
    use aws_sdk_s3::operation::get_object::{GetObjectError, GetObjectOutput};
    use aws_sdk_s3::operation::put_object::PutObjectOutput;
    use aws_sdk_s3::primitives::ByteStream;
    use aws_sdk_s3::types::error::{InvalidObjectState, NoSuchKey};
    use aws_smithy_mocks::{mock, mock_client};
    use diport::{ManagedResource, ObjectKey, ObjectPayload, ObjectStore};

    const BUCKET: &str = "test-bucket";

    // 构造 helper：mock_client + S3Store::new。expect 的 item-level carve-out 集中于此一处
    // （error-handling.md §Carve-out 要求 item-level），测试体不再散落 `expect`。
    #[allow(clippy::expect_used)]
    fn store_with(client: aws_sdk_s3::Client) -> S3Store {
        S3Store::new(client, BUCKET).expect("non-empty bucket")
    }

    // get helper：解出命中的 ObjectPayload（stream-first 读取的命中分支）。item-level expect carve-out 集中
    // 于此一处，测试体不散落 `expect`。
    #[allow(clippy::expect_used)]
    async fn get_hit(store: &S3Store, key: &str) -> ObjectPayload {
        store
            .get_object(ObjectKey::new(key))
            .await
            .expect("get_object should succeed")
            .expect("object should be present")
    }

    #[tokio::test]
    async fn put_object_succeeds() {
        let rule = mock!(aws_sdk_s3::Client::put_object)
            .then_output(|| PutObjectOutput::builder().build());
        let store = store_with(mock_client!(aws_sdk_s3, &[&rule]));
        assert!(
            store
                .put_object(ObjectKey::new("k"), b"hello".to_vec())
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn get_object_streams_and_collects_within_limit() {
        let rule = mock!(aws_sdk_s3::Client::get_object).then_output(|| {
            GetObjectOutput::builder()
                .body(ByteStream::from_static(b"hello"))
                .build()
        });
        let store = store_with(mock_client!(aws_sdk_s3, &[&rule]));
        // 命中 → stream-first payload → 有界 collect 收齐字节。
        let collected = get_hit(&store, "k").await.collect_limited(64).await;
        assert!(matches!(collected, Ok(ref b) if b.as_slice() == b"hello"));
    }

    #[tokio::test]
    async fn get_object_collect_exceeds_limit_errs() {
        // 有界 collect：对象 5 字节、上界 2 ⇒ Err（LimitExceeded，不无界分配）——锁 stream-first 内存上界契约。
        let rule = mock!(aws_sdk_s3::Client::get_object).then_output(|| {
            GetObjectOutput::builder()
                .body(ByteStream::from_static(b"hello"))
                .build()
        });
        let store = store_with(mock_client!(aws_sdk_s3, &[&rule]));
        assert!(get_hit(&store, "k").await.collect_limited(2).await.is_err());
    }

    #[tokio::test]
    async fn get_object_no_such_key_is_none() {
        let rule = mock!(aws_sdk_s3::Client::get_object)
            .then_error(|| GetObjectError::NoSuchKey(NoSuchKey::builder().build()));
        let store = store_with(mock_client!(aws_sdk_s3, &[&rule]));
        assert!(matches!(
            store.get_object(ObjectKey::new("missing")).await,
            Ok(None)
        ));
    }

    #[tokio::test]
    async fn get_object_other_error_is_err() {
        // 非 NoSuchKey 的 service 错误 → Err（不误判为「不存在」）。
        let rule = mock!(aws_sdk_s3::Client::get_object).then_error(|| {
            GetObjectError::InvalidObjectState(InvalidObjectState::builder().build())
        });
        let store = store_with(mock_client!(aws_sdk_s3, &[&rule]));
        assert!(store.get_object(ObjectKey::new("k")).await.is_err());
    }

    #[tokio::test]
    async fn delete_object_succeeds() {
        let rule = mock!(aws_sdk_s3::Client::delete_object)
            .then_output(|| DeleteObjectOutput::builder().build());
        let store = store_with(mock_client!(aws_sdk_s3, &[&rule]));
        assert!(store.delete_object(ObjectKey::new("k")).await.is_ok());
    }

    #[tokio::test]
    async fn delete_object_on_missing_key_is_ok() {
        // 幂等契约锁定：S3 DELETE 对不存在的 key 仍返回成功（204，不报 404）——消费侧据此契约
        // 重复删除安全。mock 返回成功输出即模拟该幂等语义。
        let rule = mock!(aws_sdk_s3::Client::delete_object)
            .then_output(|| DeleteObjectOutput::builder().build());
        let store = store_with(mock_client!(aws_sdk_s3, &[&rule]));
        assert!(
            store
                .delete_object(ObjectKey::new("never-existed"))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn put_object_empty_body_succeeds() {
        // 边界：零字节对象（合法 S3 PUT，如空占位对象）。
        let rule = mock!(aws_sdk_s3::Client::put_object)
            .then_output(|| PutObjectOutput::builder().build());
        let store = store_with(mock_client!(aws_sdk_s3, &[&rule]));
        assert!(
            store
                .put_object(ObjectKey::new("empty"), Vec::new())
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn new_rejects_empty_bucket() {
        let rule = mock!(aws_sdk_s3::Client::put_object)
            .then_output(|| PutObjectOutput::builder().build());
        let client = mock_client!(aws_sdk_s3, &[&rule]);
        assert!(S3Store::new(client, "").is_err());
    }

    #[tokio::test]
    async fn lifecycle_name_and_shutdowns() {
        let rule = mock!(aws_sdk_s3::Client::put_object)
            .then_output(|| PutObjectOutput::builder().build());
        let store = store_with(mock_client!(aws_sdk_s3, &[&rule]));
        assert_eq!(ManagedResource::name(&store), "s3");
        assert!(ManagedResource::shutdown(&store).await.is_ok());
        assert!(ObjectStore::shutdown(&store).await.is_ok());
    }

    #[tokio::test]
    async fn runtime_deps_single_sources_store_and_resource_guard() {
        let rule = mock!(aws_sdk_s3::Client::put_object)
            .then_output(|| PutObjectOutput::builder().build());
        let deps = S3RuntimeDeps::new(store_with(mock_client!(aws_sdk_s3, &[&rule])));
        let store = deps.object_store();
        assert!(
            store
                .put_object(ObjectKey::new("runtime-deps"), b"ok".to_vec())
                .await
                .is_ok()
        );

        let resources = deps.runtime_resources();
        assert_eq!(resources.len(), 1, "s3 bundle emits one store guard");
        assert_eq!(resources[0].name(), "s3");
    }
}
