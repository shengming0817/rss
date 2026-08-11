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

  rg -o '^- \*\*(N?FR-[0-9]{3}[a-z]?):' "$spec_dir/spec.md" |
    sed -E 's/^- \*\*([^:]+):/\1/' | sort >"$spec_ids"
  rg -o '^\| (N?FR-[0-9]{3}[a-z]?) \|' "$spec_dir/traceability.md" |
    sed -E 's/^\| ([^ ]+) \|/\1/' | sort >"$trace_ids"
  test -s "$spec_ids"
  test "$(uniq -d "$spec_ids" | wc -l | tr -d ' ')" -eq 0
  test "$(uniq -d "$trace_ids" | wc -l | tr -d ' ')" -eq 0
  cmp "$spec_ids" "$trace_ids"
  for pbi in $(seq 1893 1910); do
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

# #1904 library-only draft pilot: exact Demo + Identity + Demo and five-provider closure
./hack/cargo.sh test -p assembly-schema deviceidentity_pilot_roles_are_active_persistent_and_exact
./hack/cargo.sh test -p xtask deviceidentity_pilot_capability_closure_is_exact_and_non_vacuous
./hack/cargo.sh test -p deviceidentity --lib
./hack/cargo.sh test -p identity-composition --features device-mqtt --lib
cargo xtask assembly validate
cargo xtask assembly artifacts check
cargo xtask assembly generate-modules --check
cargo xtask assembly generate-providers --check

# #1906 T2 programmable simulator convergence journey (production-ineligible draft artifacts)
./hack/cargo.sh nextest run -p journeys --features integration --test device_certificate_convergence_journey

# #1907 T2 PostgreSQL/worker join hazards (authorized-artifact return vs lease takeover; postcommit crash/reclaim)
./hack/cargo.sh nextest run -p postgres --features integration -E 'test(authorized_artifact_return_loses_to_lease_takeover_without_stale_command) | test(postcommit_worker_crash_reclaim_keeps_command_singular_and_exposes_interrupted_attempt)' --retries 0

# #1908 T2 MQTT broker/backpressure plus durable-ingress join journey
# ReleaseCheck/nightly-only scheduled evidence; PR and Adaptive CI do not run this remote carrier.
# (both filters: broker_delivery_disconnect_before_ingress_commit_replays_to_one_canonical_receipt
# and saturated_ingress_persistent_session_reconnect_reaches_one_canonical_outcome)
./hack/cargo.sh nextest run -p journeys --features integration --test mqtt_backpressure_fault_journey
```

The #1904 target is a `compile-only`, library-only composition proof. Its six proposal contracts remain draft, and these commands do not claim a binary, listener, image, runtime journey, production provider closure, or deployable artifact. The #1906 journey is a T2 production-ineligible simulator join; it does not activate proposal contracts or claim a production assembly. The #1907 command is a T2 Medium PostgreSQL/worker join proof; it is not T3, does not activate proposal contracts, and does not expand the NFR-012 fault matrix beyond the two owned hazards. The #1908 journey is the unique T2 owner for the two NFR-013 broker/backpressure plus durable-ingress join hazards. Its scheduled owner is ReleaseCheck/nightly—not PR or Adaptive CI—and the command above is the manual diagnostic entry point; reuse #1902's broker-tests command above for standalone transport/session/authentication evidence.

## Commands introduced by later PBIs

The following are placeholders for delivery discoverability, not commands that exist at this specification baseline. Run each only after its owner PBI introduces the corresponding repository target; use the target's checked-in help rather than inventing an alternate path.

```sh
# #1896/#1897/#1898/#1900, after their PostgreSQL conformance targets exist
cargo nextest run -E 'test(device_certificate)'

# #1910 remains dormant behind the External-PKI `flag-cond` trigger. It has no production
# activation command or repository target until that trigger is satisfied and separately implemented.
```

Later PBIs must replace a placeholder if the repository exposes a different canonical target. They must not add a second command surface solely to preserve this example.
