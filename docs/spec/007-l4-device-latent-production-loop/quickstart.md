# DeviceLatent specification quickstart

Run these commands from the repository worktree containing this specification. This file owns commands only; architecture, requirements, dependencies, and proof ownership live in the linked specification documents.

## Validate this documentation change

Confirm that all eight JSON proposal documents are present and parseable (this does not claim JSON Schema meta-schema validation):

```bash
(
  set -euo pipefail
  set -- docs/spec/007-l4-device-latent-production-loop/contracts/*.schema.json
  test "$#" -eq 8
  jq empty "$@"
)
```

Run the one-time, non-committed specification smoke for file inventory, requirement exact-set, PBI coverage, and local links:

```bash
(
  set -euo pipefail
  spec_dir=docs/spec/007-l4-device-latent-production-loop

  spec_ids=$(mktemp)
  trace_ids=$(mktemp)
  trap 'rm -f "$spec_ids" "$trace_ids"' EXIT HUP INT TERM

  test "$(find "$spec_dir" -type f | wc -l | tr -d ' ')" -eq 20
  test -f docs/architecture/202607291724-022-l4-device-latent-production-loop.md
  test -f docs/architecture/202608120423-028-device-security-candidate-scope.md

  rg -o '^- \*\*(N?FR-[0-9]{3}[a-z]?):' "$spec_dir/spec.md" |
    sed -E 's/^- \*\*([^:]+):/\1/' | sort >"$spec_ids"
  rg -o '^\| (N?FR-[0-9]{3}[a-z]?) \|' "$spec_dir/traceability.md" |
    sed -E 's/^\| ([^ ]+) \|/\1/' | sort >"$trace_ids"
  test -s "$spec_ids"
  test "$(uniq -d "$spec_ids" | wc -l | tr -d ' ')" -eq 0
  test "$(uniq -d "$trace_ids" | wc -l | tr -d ' ')" -eq 0
  cmp "$spec_ids" "$trace_ids"
  for pbi in $(seq 1893 1909); do
    rg -q "#$pbi" "$spec_dir/tasks.md"
  done

  find "$spec_dir" -type f -name '*.md' -print0 |
    xargs -0 perl -ne 'while (/\[[^]]+\]\((?!https?:|#)([^)#]+)(?:#[^)]+)?\)/g) { $p=$1; $p=~s/%20/ /g; $base=$ARGV; $base=~s{/[^/]+$}{}; $path=$p=~m{^/}?$p:"$base/$p"; die "$ARGV: missing $p\n" unless -e $path }'
)
```

Finish the fast repository checks:

```sh
/usr/bin/git diff --check
make verify-fast
```

After all documentation is committed, run the bounded affected preflight once:

```sh
make ci CI_BASE=origin/develop
```

If that complete run fails, collect the full failure set, repair it as one batch, and then perform one unified revalidation.

## Current repository contract commands

These canonical commands validate the live Draft contracts and generated output. They prove repository closure only; they do not activate a production path.

```sh
cargo xtask contract validate
cargo xtask codegen --check

# #1909 existing verification-path closure: six Draft candidates plus typed evidence/impact joins
./hack/cargo.sh xtask public-api internal --layer curated --check
./hack/cargo.sh xtask verify --only contract-validate --only codegen-check --only contract-binding-guard

# #1902 standalone broker T2: always hermetic Docker, no RSS_MQTT_TEST_URL fallback
./hack/cargo.sh test -p mqtt --features broker-tests --test integration

# #2117 production candidate: exact manifest/provider/runtime artifact closure
./hack/cargo.sh test -p assembly-schema deviceidentity_pilot_roles_are_active_persistent_and_exact
./hack/cargo.sh test -p xtask deviceidentity_pilot_capability_closure_is_exact_and_non_vacuous
./hack/cargo.sh test -p deviceidentity --lib
./hack/cargo.sh test -p identity-composition --features device-mqtt --lib
cargo xtask assembly validate
cargo xtask assembly artifacts check
cargo xtask assembly generate-modules --check
cargo xtask assembly generate-providers --check
cargo test -p deviceidentity --bin deviceidentity-server
# Immutable image acceptance (requires a pre-built content address):
# RSS_DEVICEIDENTITY_ACCEPTANCE_IMAGE='registry/name@sha256:<64-lower-hex>' \
#   cargo test -p deviceidentity --features artifact-acceptance --test runtime_image_acceptance \
#   deviceidentity_runtime_image_is_a_content_addressed_candidate

# #1907 T2 PostgreSQL/worker join hazards (authorized-artifact return vs lease takeover; postcommit crash/reclaim)
./hack/cargo.sh nextest run -p postgres --features integration -E 'test(authorized_artifact_return_loses_to_lease_takeover_without_stale_command) | test(postcommit_worker_crash_reclaim_keeps_command_singular_and_exposes_interrupted_attempt)' --retries 0
```

The #2117 target is a production candidate, not a supported artifact or activated profile. Its six proposal contracts remain Draft. The image test proves only a caller-supplied content address, nonroot user, fixed ENTRYPOINT, bundled schema and `--help`; it does not launch the service or prove registry provenance. The #1907 command retains its existing T2 ownership and does not become T3.

## No activation command

The current `deviceidentity` artifact is candidate-only. A binary, image target and required provider wiring now exist, but there is deliberately no T3 selector, supported/canonical promotion or activation command. `deviceidentity-server --config <path>` is the candidate runtime entrypoint, not an official-profile activation command.
