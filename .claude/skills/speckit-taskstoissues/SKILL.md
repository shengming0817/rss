---
name: speckit-taskstoissues
description: Convert existing tasks into actionable, dependency-ordered GitHub issues
  for the feature based on available design artifacts.
compatibility: Requires spec-kit project structure with .specify/ directory
metadata:
  author: github-spec-kit
  source: templates/commands/taskstoissues.md
disable-model-invocation: true
---

## User Input

```text
$ARGUMENTS
```

You **MUST** consider the user input before proceeding (if not empty).

## Outline

1. Run `.specify/scripts/bash/check-prerequisites.sh --json --require-tasks --include-tasks` from repo root and parse FEATURE_DIR and AVAILABLE_DOCS list. All paths must be absolute. For single quotes in args like "I'm Groot", use escape syntax: e.g 'I'\''m Groot' (or double-quote if possible: "I'm Groot").
1. From the executed script, extract the path to **tasks**.
1. Confirm the active forge is configured by running:

```bash
bash hack/automation/forge.sh forge-active
```

This returns the active forge type (e.g. `github`, `azure`, `gitlab`). If the command fails or returns empty, stop and report that no forge is configured.

> [!CAUTION]
> ONLY PROCEED TO NEXT STEPS IF THE ACTIVE FORGE IS CONFIGURED. DO NOT CREATE ISSUES IN REPOSITORIES WHERE THE FORGE ADAPTER IS NOT AVAILABLE OR DOES NOT MATCH THE CURRENT REPOSITORY.

1. For each task in the list, create a new issue via the forge adapter:

```bash
bash hack/automation/forge.sh issue-create "<title>" <body-file> "<labels>"
```

> [!CAUTION]
> UNDER NO CIRCUMSTANCES EVER CREATE ISSUES IN REPOSITORIES THAT DO NOT MATCH THE CONFIGURED FORGE
