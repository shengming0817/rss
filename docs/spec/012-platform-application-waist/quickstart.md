# Quickstart: validate the Platform vNext decision

The vNext implementation is pending #2107/#2108. These commands validate the decision package and existing carriers;
they do not imply that planned vNext carriers are active.

```bash
set -euo pipefail

git diff --check origin/develop...HEAD
git diff --check

cargo test -p xtask release_surface::tests::closure_planner_is_dependency_first_and_dev_edges_do_not_expand_it -- --exact
cargo test -p xtask package_proof::tests::release_proof_plans_are_derived_from_the_complete_release_surface -- --exact
cargo test -p xtask publicapi::tests::nonempty_release_surface_green_and_forbidden_workspace_type_red -- --exact
cargo test -p xtask layerdeps::tests::runtimeinventorymint_wrapper_exact_green -- --exact
cargo test -p runtimeexec inventory::tests::inventory_reader_is_unavailable_before_exact_listener_publication -- --exact
```

The canonical cross-repository receipt and artifact lifecycle are defined by
[`ADR-026`](../../architecture/202608111253-026-rss-incubator-ownership-migration.md); `plan.md` only records this
cutover's exact-check additions. These commands reverify existing code carriers and diff hygiene. They do not inspect
Markdown wording, enforce document anchors or activate planned vNext carriers. Human review owns semantic consistency.
