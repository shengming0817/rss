//! Minimal executable-artifact contract for the identityaudit binary.

mod support;

use support::{Artifact, assert_executable_contract};

#[test]
fn identityaudit_server_binary_is_an_executable_artifact() -> anyhow::Result<()> {
    assert_executable_contract(Artifact::Binary(env!("CARGO_BIN_EXE_identityaudit-server")))
}
