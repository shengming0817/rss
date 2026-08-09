//! Executable-artifact contract for the identityaudit runtime image.
//!
//! Gated by Cargo `required-features = ["artifact-acceptance"]`. Missing or
//! illegal `RSS_IDENTITYAUDIT_ACCEPTANCE_IMAGE` fails closed (no harness ignore).

#![allow(clippy::expect_used, clippy::unwrap_used)] // reason: deterministic validator contract fixtures fail loudly when a fixed case changes polarity.

mod support;

use anyhow::Context;
use support::{
    ACCEPTANCE_IMAGE_ENV, Artifact, assert_executable_contract, validate_acceptance_image,
};

const IMAGE_ENV: &str = ACCEPTANCE_IMAGE_ENV;

#[test]
fn identityaudit_runtime_image_is_an_executable_artifact() -> anyhow::Result<()> {
    let image = std::env::var(IMAGE_ENV).with_context(|| format!("{IMAGE_ENV} must be set"))?;
    let image = validate_acceptance_image(IMAGE_ENV, &image)?;
    assert_executable_contract(Artifact::Image(&image))
}

#[test]
fn acceptance_image_rejects_empty_dash_prefix_and_whitespace() {
    assert!(
        validate_acceptance_image(IMAGE_ENV, "")
            .unwrap_err()
            .to_string()
            .contains(IMAGE_ENV)
    );
    assert!(
        validate_acceptance_image(IMAGE_ENV, "-evil")
            .unwrap_err()
            .to_string()
            .contains(IMAGE_ENV)
    );
    for bad in ["has space", "has\ttab", " has-leading", "trailing "] {
        let err = validate_acceptance_image(IMAGE_ENV, bad)
            .expect_err("whitespace must be rejected")
            .to_string();
        assert!(
            err.contains(IMAGE_ENV),
            "illegal image diagnostic must name {IMAGE_ENV}: {err}"
        );
    }
    assert_eq!(
        validate_acceptance_image(IMAGE_ENV, "rss-identityaudit:artifact-acceptance").unwrap(),
        "rss-identityaudit:artifact-acceptance"
    );
}
