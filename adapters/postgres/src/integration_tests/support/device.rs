use super::*;

use crate::cotx::{ServingWriteLane, TenantDb};

pub(crate) struct DevicePolicyLineageFixture<'a> {
    store: &'a PgStore,
    scope: DeviceCertificateScope,
    tenant: String,
    device: String,
    validity_seconds: i32,
    renew_before_seconds: i32,
    client_auth: bool,
    server_auth: bool,
    sans: Vec<String>,
}

impl<'a> DevicePolicyLineageFixture<'a> {
    pub(crate) fn new(store: &'a PgStore, tenant: &str, device: &str) -> Result<Self, sqlx::Error> {
        let tenant_id = rss_request_context::TenantId::parse(tenant)
            .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
        let device_id = ids::DeviceId::new(
            uuid::Uuid::parse_str(device)
                .map_err(|error| sqlx::Error::Protocol(error.to_string()))?,
        );
        Ok(Self {
            store,
            scope: DeviceCertificateScope::for_test(tenant_id, device_id),
            tenant: tenant.to_owned(),
            device: device.to_owned(),
            validity_seconds: 3_600,
            renew_before_seconds: 600,
            client_auth: true,
            server_auth: false,
            sans: Vec::new(),
        })
    }

    pub(crate) fn with_policy(
        mut self,
        validity_seconds: i32,
        renew_before_seconds: i32,
        client_auth: bool,
        server_auth: bool,
        sans: &[String],
    ) -> Self {
        self.validity_seconds = validity_seconds;
        self.renew_before_seconds = renew_before_seconds;
        self.client_auth = client_auth;
        self.server_auth = server_auth;
        self.sans = sans.to_vec();
        self
    }

    async fn run<T>(
        &self,
        write: impl for<'conn> FnOnce(
            &'conn mut sqlx::PgConnection,
        ) -> BoxFuture<'conn, Result<T, sqlx::Error>>
        + Send
        + 'static,
    ) -> Result<T, sqlx::Error>
    where
        T: Send + 'static,
    {
        TenantDb::<ServingWriteLane>::from_unverified_for_test(self.store)
            .identity_write(
                self.scope,
                move |mut tx| {
                    Box::pin(async move {
                        let mut identity = tx.identity();
                        let mut policy = identity.device_policy();
                        write(policy.connection_for_lineage_fixture()).await
                    })
                },
                std::convert::identity,
            )
            .await
    }

    pub(crate) async fn seed(&self, generation: i64) -> Result<(), sqlx::Error> {
        let tenant = self.tenant.clone();
        let device = self.device.clone();
        let sans = self.sans.clone();
        let validity_seconds = self.validity_seconds;
        let renew_before_seconds = self.renew_before_seconds;
        let client_auth = self.client_auth;
        let server_auth = self.server_auth;
        self.run(move |conn| Box::pin(async move {
            let seeded = sqlx::query(
                "WITH receipt AS (SELECT pg_catalog.gen_random_uuid() AS receipt_id), \
                 operation AS ( \
                   INSERT INTO device_certificate_policy_operations ( \
                     tenant_id,device_id,idempotency_key,request_digest,accepted_generation, \
                     accepted_condition,authorization_receipt_id,principal_kind,principal_id, \
                     contract_id,permission,obligation_fingerprint,evaluated_at) \
                   SELECT $1::uuid,$2::uuid,pg_catalog.gen_random_uuid(), \
                     pg_catalog.decode(repeat('11',32),'hex'),1,'reconciling',receipt_id, \
                     'service','integration-fixture','identity.device-certificate-policy-put', \
                     'identity:device-certificate-policy:write', \
                     pg_catalog.decode(repeat('22',32),'hex'),TIMESTAMPTZ 'epoch' \
                   FROM receipt RETURNING authorization_receipt_id \
                 ), policy_basis AS ( \
                   INSERT INTO device_certificate_policy_authorization_policies ( \
                     tenant_id,device_id,authorization_receipt_id,policy_ordinal,policy_id,policy_version) \
                   SELECT $1::uuid,$2::uuid,authorization_receipt_id,1,'integration-fixture-policy',1 \
                   FROM operation \
                 ), lineage AS ( \
                   INSERT INTO device_certificate_desired_generation_lineage ( \
                     tenant_id,device_id,generation,authorization_receipt_id) \
                   SELECT $1::uuid,$2::uuid,series.generation,operation.authorization_receipt_id \
                   FROM operation CROSS JOIN pg_catalog.generate_series(1,$3) AS series(generation) \
                   RETURNING generation,authorization_receipt_id \
                 ) \
                 INSERT INTO device_certificate_desired_states ( \
                   tenant_id,device_id,generation,authorization_receipt_id,validity_seconds, \
                   renew_before_seconds,client_auth,server_auth,sans) \
                 SELECT $1::uuid,$2::uuid,$3,authorization_receipt_id,$4,$5,$6,$7,$8 \
                 FROM lineage WHERE generation=$3",
            )
            .bind(&tenant)
            .bind(&device)
            .bind(generation)
            .bind(validity_seconds)
            .bind(renew_before_seconds)
            .bind(client_auth)
            .bind(server_auth)
            .bind(&sans)
            .execute(conn)
            .await?;
            if seeded.rows_affected() != 1 {
                return Err(sqlx::Error::Protocol(
                    "device-policy lineage seed did not create exactly one desired row".to_owned(),
                ));
            }
            Ok(())
        })).await
    }

    pub(crate) async fn advance(&self, next_generation: i64) -> Result<(), sqlx::Error> {
        let tenant = self.tenant.clone();
        let device = self.device.clone();
        self.run(move |conn| {
            Box::pin(async move {
                let advanced = sqlx::query(
                    "WITH lineage AS ( \
                   INSERT INTO device_certificate_desired_generation_lineage \
                     (tenant_id,device_id,generation,authorization_receipt_id) \
                   SELECT tenant_id,device_id,$3,authorization_receipt_id \
                   FROM device_certificate_desired_states \
                   WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND generation=$3-1 \
                   RETURNING authorization_receipt_id \
                 ) \
                 UPDATE device_certificate_desired_states desired SET generation=$3 \
                 FROM lineage WHERE desired.tenant_id=$1::uuid AND desired.device_id=$2::uuid \
                   AND desired.generation=$3-1",
                )
                .bind(&tenant)
                .bind(&device)
                .bind(next_generation)
                .execute(conn)
                .await?;
                if advanced.rows_affected() != 1 {
                    return Err(sqlx::Error::Protocol(
                        "device-policy lineage advance did not update exactly one desired row"
                            .to_owned(),
                    ));
                }
                Ok(())
            })
        })
        .await
    }

    pub(crate) async fn accept(&self, next_generation: i64) -> Result<(), sqlx::Error> {
        let tenant = self.tenant.clone();
        let device = self.device.clone();
        let sans = self.sans.clone();
        let validity_seconds = self.validity_seconds;
        let renew_before_seconds = self.renew_before_seconds;
        let client_auth = self.client_auth;
        let server_auth = self.server_auth;
        self.run(move |conn| Box::pin(async move {
            let accepted = sqlx::query(
                "WITH receipt AS (SELECT pg_catalog.gen_random_uuid() AS receipt_id), \
                 operation AS ( \
                   INSERT INTO device_certificate_policy_operations ( \
                     tenant_id,device_id,idempotency_key,request_digest,accepted_generation, \
                     accepted_condition,authorization_receipt_id,principal_kind,principal_id, \
                     contract_id,permission,obligation_fingerprint,evaluated_at) \
                   SELECT $1::uuid,$2::uuid,pg_catalog.gen_random_uuid(), \
                     pg_catalog.decode(repeat('33',32),'hex'),$3,'reconciling',receipt_id, \
                     'service','integration-fixture','identity.device-certificate-policy-put', \
                     'identity:device-certificate-policy:write', \
                     pg_catalog.decode(repeat('44',32),'hex'),TIMESTAMPTZ 'epoch' \
                   FROM receipt RETURNING authorization_receipt_id \
                 ), policy_basis AS ( \
                   INSERT INTO device_certificate_policy_authorization_policies ( \
                     tenant_id,device_id,authorization_receipt_id,policy_ordinal,policy_id,policy_version) \
                   SELECT $1::uuid,$2::uuid,authorization_receipt_id,1,'integration-fixture-policy-v2',1 \
                   FROM operation \
                 ), lineage AS ( \
                   INSERT INTO device_certificate_desired_generation_lineage ( \
                     tenant_id,device_id,generation,authorization_receipt_id) \
                   SELECT $1::uuid,$2::uuid,$3,authorization_receipt_id FROM operation \
                   RETURNING authorization_receipt_id \
                 ) \
                 UPDATE device_certificate_desired_states desired SET \
                   generation=$3,authorization_receipt_id=lineage.authorization_receipt_id, \
                   validity_seconds=$4,renew_before_seconds=$5,client_auth=$6,server_auth=$7,sans=$8 \
                 FROM lineage WHERE desired.tenant_id=$1::uuid AND desired.device_id=$2::uuid \
                   AND desired.generation=$3-1",
            )
            .bind(&tenant)
            .bind(&device)
            .bind(next_generation)
            .bind(validity_seconds)
            .bind(renew_before_seconds)
            .bind(client_auth)
            .bind(server_auth)
            .bind(&sans)
            .execute(conn)
            .await?;
            if accepted.rows_affected() != 1 {
                return Err(sqlx::Error::Protocol(
                    "device-policy lineage acceptance did not update exactly one desired row".to_owned(),
                ));
            }
            Ok(())
        })).await
    }
}

// ── Device certificate desired/reported/condition authority (#1896) ──────────────

pub(in super::super) fn device_certificate_policy_hash(
    validity_seconds: i32,
    renew_before_seconds: i32,
    client_auth: bool,
    server_auth: bool,
    sans: &[String],
) -> Vec<u8> {
    use deviceloop::CertificatePolicy;
    use sha2::{Digest as _, Sha256};

    let key_usages = [
        client_auth.then_some("clientAuth"),
        server_auth.then_some("serverAuth"),
    ]
    .into_iter()
    .flatten()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    let policy = CertificatePolicy::restore(
        validity_seconds as u64,
        renew_before_seconds as u64,
        key_usages,
        sans.to_vec(),
    )
    .expect("test policy must be accepted by the production domain constructor");
    Sha256::digest(policy.canonical_bytes()).to_vec()
}

pub(in super::super) async fn insert_device_certificate_desired(
    store: &PgStore,
    tenant: &str,
    device: &str,
    client_auth: bool,
    server_auth: bool,
    sans: &[String],
) -> Result<(), sqlx::Error> {
    DevicePolicyLineageFixture::new(store, tenant, device)?
        .with_policy(3_600, 600, client_auth, server_auth, sans)
        .seed(1)
        .await
}

pub(in super::super) fn reconcile_limit(value: usize) -> ReconcileMaxInFlight {
    let Ok(limit) = ReconcileMaxInFlight::try_new(value) else {
        unreachable!("fixed integration concurrency is valid");
    };
    limit
}

pub(in super::super) fn operator_repair_authorization(
    caller: vocab::ServiceCallerDomain,
    identity: diport::SagaWorkerIdentity,
    instance: consistency::SagaInstanceRef,
    reason: consistency::SagaOperatorReason,
    change_ticket: diport::SagaOperatorChangeTicket,
    start_audit_id: diport::SagaOperatorStartAuditId,
) -> Result<
    diport::SagaOperatorAuthorization<diport::saga_operator_action::Repair>,
    diport::SagaOperatorRepairReasonError,
> {
    let evidence = diport::SagaOperatorRepairExpectation::new(
        diport::SagaOperatorRepairReason::try_from(reason)?,
        diport::SagaOperatorReasonText::parse("provider evidence reviewed")
            .map_err(|_| diport::SagaOperatorRepairReasonError)?,
        change_ticket,
    );
    Ok(diport::test_support::saga_operator_authorization(
        caller,
        identity,
        instance,
        evidence,
        start_audit_id,
    ))
}

pub(in super::super) fn settings_operator_execution(
    tenant: rss_request_context::TenantId,
) -> eventexec::ProjectionExecutionContext {
    let projection = eventexec::ProjectionId::parse(SETTINGS_PROJECTION_ID)
        .expect("generated Settings projection id");
    eventexec::WorkflowRuntimePlan::generated_projection_operator_execution_fixture(
        &projection,
        tenant,
    )
    .expect("plan-issued Settings operator execution")
}
