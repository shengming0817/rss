use eventexec::{ProjectionId, ProjectionSourceScope};

fn main() {
    let tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap();
    let projection = ProjectionId::parse("projection").unwrap();
    let digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let _new = ProjectionSourceScope::new(tenant, projection.clone(), "v1", digest, digest);
    let _parts = ProjectionSourceScope::from_parts(
        tenant,
        projection.clone(),
        "v1",
        digest,
        digest,
    );
    let _raw = ProjectionSourceScope::from_raw(tenant, projection.clone(), "v1", digest, digest);
    let _test = ProjectionSourceScope::for_test(tenant, projection, "v1", digest, digest);
}
