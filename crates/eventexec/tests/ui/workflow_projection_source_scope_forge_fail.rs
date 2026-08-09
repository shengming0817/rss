use eventexec::{ProjectionId, ProjectionSourceScope};

fn main() {
    let _forged = ProjectionSourceScope {
        tenant: vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap(),
        projection: ProjectionId::parse("projection").unwrap(),
        definition_version: "v1".into(),
        definition_schema_digest:
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        input_generation:
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .into(),
    };
}
