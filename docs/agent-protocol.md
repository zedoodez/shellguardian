# Agent Protocol

This document defines how AI coding agents should use ShellGuardian before deleting files or directories.

## Goal

Use ShellGuardian as a deletion decision layer:

1. inspect the target first
2. explain the risk in natural language
3. ask for confirmation when needed
4. execute the safest possible command

## Intent interpretation

In this repository, phrases such as "clean up", "clean this project", "remove clutter", and "delete temporary files" should be interpreted as filesystem cleanup requests, not code refactoring requests.

Agents should not start a cleanup task by:

- reading source files for style cleanup
- scanning TODO or FIXME comments
- running tests for code quality reasons

unless the user explicitly asked for code cleanup rather than file cleanup.

## Protocol

### 1. Vague cleanup requests

If the user asks to "clean up the project" or gives no specific path:

```bash
shellguardian scan --json
```

The agent should:

- read the top-level `guidance`
- show suggested cleanup targets to the user
- prefer `shellguardian clean --all-likely --json` if the user wants a safe default
- prefer `shellguardian clean --select ... --json` if the user chooses specific targets

### 2. Explicit delete requests

If the user names a path:

```bash
shellguardian preview <path> --json
```

The agent should read:

- `guidance.human_summary`
- `guidance.next_step`
- `guidance.recommended_command`
- `guidance.confirmation_prompt`

### 3. Risk handling

#### `low`

The agent may continue with:

```bash
shellguardian rm <path> --smart --json
```

#### `review`

The agent should:

1. explain `guidance.human_summary`
2. ask the user with `guidance.confirmation_prompt`
3. if confirmed, run:

```bash
shellguardian rm <path> --smart --yes --json
```

#### `high`

The agent should:

1. explain that deletion is blocked by default
2. ask the user with `guidance.confirmation_prompt`
3. only if the user explicitly confirms, run:

```bash
shellguardian rm <path> --confirm-high-risk --json
```

## Output contract

ShellGuardian results include a `guidance` object meant for agent integration.

Important fields:

- `risk_level`
- `tone`
- `human_summary`
- `agent_hint`
- `next_step`
- `recommended_command`
- `confirmation_prompt`
- `reason_codes`

## Minimal agent rules

- never run raw `rm` directly when ShellGuardian is available
- always preview an explicit delete target first
- always scan first for vague cleanup requests
- never delete `high` risk targets without explicit user confirmation
- reuse `guidance.human_summary` and `guidance.confirmation_prompt` instead of inventing new wording
