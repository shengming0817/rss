//! LocalOnly HTTP effect profile gate.
//!
//! Active LocalOnly HTTP contracts are pure local reads/projections. Their closed effect
//! vocabulary may therefore contain only `auth`, `read`, and `projection`; write, transaction,
//! asynchronous, worker, or cross-tenant audit effects require a higher consistency level.
//!
//! INVARIANT: LOCAL-ONLY-EFFECTS-01 { level = "Medium", exec = "verify", source = "code" } -- active LocalOnly HTTP contracts may declare only auth/read/projection effects; synthetic green/red fixtures and the verify/ci plan make the cross-field rule blocking.

use crate::contract::DiscoveredContract;
use crate::contract::manifest::{
    ConsistencyLevel, ContractKind, EffectKind, HttpMethod, Lifecycle,
};
use crate::diagnostic::{self, GovernanceCheck, finding};
use anyhow::{Result, anyhow, bail};
use std::collections::BTreeSet;
use std::path::Path;

pub(crate) type Finding = diagnostic::Finding<Rule>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    ForbiddenEffect,
}

pub(crate) struct LocalOnlyEffects;

impl GovernanceCheck for LocalOnlyEffects {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "consistency local-only-effects"
    }

    fn check(&self) -> Result<(String, Vec<Finding>)> {
        check_root(&crate::workspace_root()?)
    }
}

fn check_root(root: &Path) -> Result<(String, Vec<Finding>)> {
    let contracts = discover_without_absolute_paths(root)?;
    findings_for(root, &contracts)
}

fn discover_without_absolute_paths(root: &Path) -> Result<Vec<DiscoveredContract>> {
    crate::contract::discover(&root.join("contracts")).map_err(|error| {
        let root_text = root.to_string_lossy();
        anyhow!(format!("{error:#}").replace(root_text.as_ref(), "."))
    })
}

/// Collect findings independently from discovery order. The BTreeSet key is the externally
/// promised stable diagnostic order and also de-duplicates repeated effects in one profile.
fn findings_for(root: &Path, contracts: &[DiscoveredContract]) -> Result<(String, Vec<Finding>)> {
    type FindingKey = (String, String, String, String, String);

    let mut checked = 0usize;
    let mut forbidden: BTreeSet<FindingKey> = BTreeSet::new();
    for contract in contracts {
        let manifest = &contract.manifest;
        if manifest.lifecycle != Lifecycle::Active
            || manifest.kind != ContractKind::Http
            || manifest.consistency_level != ConsistencyLevel::LocalOnly
        {
            continue;
        }
        checked += 1;

        let subject = relative_manifest_path(root, contract)?;
        let path = required_path(manifest.path.as_deref(), &subject, &manifest.id)?;
        let method = required_method(manifest.method, &subject, &manifest.id)?;
        let profile = manifest.effect_profile.as_ref().ok_or_else(|| {
            anyhow!(
                "{subject}: active LocalOnly HTTP contract `{}` missing `effectProfile`",
                manifest.id
            )
        })?;

        for &effect in &profile.effects {
            let Some(effect_wire) = forbidden_effect_wire(effect) else {
                continue;
            };
            forbidden.insert((
                manifest.id.clone(),
                path.to_string(),
                method.as_wire().to_string(),
                effect_wire.to_string(),
                subject.clone(),
            ));
        }
    }

    let findings = forbidden
        .into_iter()
        .map(|(contract_id, path, method, effect, subject)| {
            finding(
                Rule::ForbiddenEffect,
                subject,
                format!(
                    "contract `{contract_id}` {method} {path} declares forbidden LocalOnly effect `{effect}`"
                ),
            )
        })
        .collect();
    Ok((
        format!("{checked} active LocalOnly HTTP contract(s) checked"),
        findings,
    ))
}

fn relative_manifest_path(root: &Path, contract: &DiscoveredContract) -> Result<String> {
    let manifest_path = contract.dir.join("contract.toml");
    let relative = manifest_path.strip_prefix(root).map_err(|_| {
        anyhow!("discovered contract manifest is outside the workspace root: contract.toml")
    })?;
    let relative = relative
        .to_str()
        .ok_or_else(|| anyhow!("contract manifest path is not valid UTF-8"))?;
    Ok(relative.replace('\\', "/"))
}

fn required_path<'a>(path: Option<&'a str>, subject: &str, contract_id: &str) -> Result<&'a str> {
    match path {
        Some(path) => Ok(path),
        None => bail!("{subject}: active LocalOnly HTTP contract `{contract_id}` missing `path`"),
    }
}

fn required_method(
    method: Option<HttpMethod>,
    subject: &str,
    contract_id: &str,
) -> Result<HttpMethod> {
    match method {
        Some(method) => Ok(method),
        None => bail!("{subject}: active LocalOnly HTTP contract `{contract_id}` missing `method`"),
    }
}

/// Closed, exhaustive classification. Adding an `EffectKind` variant fails compilation until its
/// LocalOnly policy has been decided explicitly.
fn forbidden_effect_wire(effect: EffectKind) -> Option<&'static str> {
    match effect {
        EffectKind::Auth | EffectKind::Read | EffectKind::Projection => None,
        EffectKind::Write => Some("write"),
        EffectKind::Transaction => Some("transaction"),
        EffectKind::Outbox => Some("outbox"),
        EffectKind::Publish => Some("publish"),
        EffectKind::Workflow => Some("workflow"),
        EffectKind::Saga => Some("saga"),
        EffectKind::Reconcile => Some("reconcile"),
        EffectKind::Worker => Some("worker"),
        EffectKind::CrossTenantAudit => Some("cross-tenant-audit"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract;
    use std::path::{Path, PathBuf};

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/consistency_effects")
            .join(name)
    }

    #[test]
    fn safe_effects_pass_and_non_active_or_non_local_only_are_ignored() -> anyhow::Result<()> {
        let (summary, findings) = check_root(&fixture("green"))?;
        assert_eq!(summary, "1 active LocalOnly HTTP contract(s) checked");
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    #[test]
    fn every_forbidden_effect_is_reported_once_in_stable_wire_order() -> anyhow::Result<()> {
        let (_, findings) = check_root(&fixture("all_forbidden"))?;
        let actual: Vec<_> = findings
            .iter()
            .map(|f| (f.subject.as_str(), f.detail.as_str()))
            .collect();
        assert_eq!(
            actual,
            vec![
                (
                    "contracts/http/demo/v1/unsafe/contract.toml",
                    "contract `demo.unsafe` GET /api/v1/demo/unsafe declares forbidden LocalOnly effect `cross-tenant-audit`"
                ),
                (
                    "contracts/http/demo/v1/unsafe/contract.toml",
                    "contract `demo.unsafe` GET /api/v1/demo/unsafe declares forbidden LocalOnly effect `outbox`"
                ),
                (
                    "contracts/http/demo/v1/unsafe/contract.toml",
                    "contract `demo.unsafe` GET /api/v1/demo/unsafe declares forbidden LocalOnly effect `publish`"
                ),
                (
                    "contracts/http/demo/v1/unsafe/contract.toml",
                    "contract `demo.unsafe` GET /api/v1/demo/unsafe declares forbidden LocalOnly effect `reconcile`"
                ),
                (
                    "contracts/http/demo/v1/unsafe/contract.toml",
                    "contract `demo.unsafe` GET /api/v1/demo/unsafe declares forbidden LocalOnly effect `saga`"
                ),
                (
                    "contracts/http/demo/v1/unsafe/contract.toml",
                    "contract `demo.unsafe` GET /api/v1/demo/unsafe declares forbidden LocalOnly effect `transaction`"
                ),
                (
                    "contracts/http/demo/v1/unsafe/contract.toml",
                    "contract `demo.unsafe` GET /api/v1/demo/unsafe declares forbidden LocalOnly effect `worker`"
                ),
                (
                    "contracts/http/demo/v1/unsafe/contract.toml",
                    "contract `demo.unsafe` GET /api/v1/demo/unsafe declares forbidden LocalOnly effect `workflow`"
                ),
                (
                    "contracts/http/demo/v1/unsafe/contract.toml",
                    "contract `demo.unsafe` GET /api/v1/demo/unsafe declares forbidden LocalOnly effect `write`"
                ),
            ]
        );
        assert!(findings.iter().all(|f| f.rule == Rule::ForbiddenEffect));
        Ok(())
    }

    #[test]
    fn findings_are_stable_when_discovery_input_is_reversed() -> anyhow::Result<()> {
        let root = fixture("stable_order");
        let contracts_root = root.join("contracts");
        let discovered = contract::discover(&contracts_root)?;
        let mut reversed = discovered.clone();
        reversed.reverse();
        assert_eq!(
            findings_for(&root, &discovered)?.1,
            findings_for(&root, &reversed)?.1
        );
        assert_eq!(findings_for(&root, &discovered)?.1.len(), 2);
        Ok(())
    }

    #[test]
    fn duplicate_contract_identity_reports_each_subject_in_stable_order() -> anyhow::Result<()> {
        let root = fixture("stable_order");
        let contracts_root = root.join("contracts");
        let mut colliding = contract::discover(&contracts_root)?;
        let identity = (
            colliding[0].manifest.id.clone(),
            colliding[0].manifest.path.clone(),
            colliding[0].manifest.method,
            colliding[0].manifest.effect_profile.clone(),
        );
        colliding[1].manifest.id = identity.0;
        colliding[1].manifest.path = identity.1;
        colliding[1].manifest.method = identity.2;
        colliding[1].manifest.effect_profile = identity.3;

        let forward = findings_for(&root, &colliding)?.1;
        colliding.reverse();
        let reversed = findings_for(&root, &colliding)?.1;

        assert_eq!(forward, reversed);
        assert_eq!(forward.len(), 2);
        assert_eq!(
            forward
                .iter()
                .map(|finding| finding.subject.as_str())
                .collect::<Vec<_>>(),
            vec![
                "contracts/http/demo/v1/alpha/contract.toml",
                "contracts/http/demo/v1/zeta/contract.toml",
            ]
        );
        Ok(())
    }

    #[test]
    fn incomplete_active_local_only_metadata_is_a_hard_error() -> anyhow::Result<()> {
        for name in [
            "missing_kind",
            "missing_path",
            "missing_method",
            "missing_profile",
        ] {
            let error = match check_root(&fixture(name)) {
                Ok(result) => return Err(anyhow!("{name} unexpectedly passed: {result:?}")),
                Err(error) => error,
            };
            let message = format!("{error:#}");
            assert!(
                message.contains("contract.toml") || message.contains("demo.incomplete"),
                "{name}: {message}"
            );
            assert!(
                !message.contains(fixture(name).to_string_lossy().as_ref()),
                "hard error must not leak absolute fixture path: {message}"
            );
        }
        Ok(())
    }
}
