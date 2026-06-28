//! generated field-protection metadata is declarative review material only.
//! It exposes contract `x-protection` policy without pulling in runtime crypto ports.

use generated::{
    FieldProtectionMetadata, ProtectionAadDim, ProtectionAtRest, ProtectionMode,
    http::settings_v1::SettingsConfigPublishRequest,
};

#[test]
fn settings_config_publish_value_exposes_protection_metadata() {
    let protections = SettingsConfigPublishRequest::FIELD_PROTECTIONS;
    assert_eq!(protections.len(), 1);

    let value = protections[0];
    assert_eq!(value.field_path, "value");
    assert_eq!(value.at_rest, ProtectionAtRest::Encrypt);
    assert_eq!(value.mode, Some(ProtectionMode::Randomized));
    assert_eq!(value.key_scope, Some("tenant"));
    assert_eq!(
        value.aad,
        &[
            ProtectionAadDim::Tenant,
            ProtectionAadDim::ConfigKey,
            ProtectionAadDim::Field,
            ProtectionAadDim::SchemaVersion,
        ]
    );
    assert_eq!(value.reason, None);
}
