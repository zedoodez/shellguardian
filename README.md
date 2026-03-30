# ShellGuardian

Protect AI coding agents from deleting the wrong files before it happens.

`ShellGuardian` is a Python-first open source deletion guardrail for Codex, Claude Code, Cursor, Copilot, and other agentic workflows.

Unlike a traditional `safe-rm` wrapper, ShellGuardian focuses on prevention first:

- preview deletion risk before anything is removed
- block obviously dangerous targets such as `src/`, `.git/`, or the workspace root
- delete only likely disposable files by default
- require confirmation for ambiguous paths
- help humans understand why something looks risky

It is designed for three reuse layers:

- Library: `safe_delete()`, `preview_delete()`, `smart_delete()`, `safe_move()`, `safe_exec()`
- CLI: `shellguardian preview|rm|move|exec`
- Server / webhook ready core: policy validation and audit logging are separated from the transport layer

## Why this exists

AI coding agents are great at automating shell tasks, but they are also very capable of deleting the wrong directory for very boring reasons:

- they misread the current path
- they confuse sibling directories
- they over-apply cleanup commands
- they treat unknown files as disposable
- they fall back to raw shell deletion when a safer API should have been used

ShellGuardian flips the default:

- reject protected paths
- keep work inside the current workspace by default
- support dry-runs first
- preview risk before deletion
- delete likely disposable items first
- require explicit overrides for risky behavior
- produce audit events for every accepted or rejected action

This makes it a better fit for agent guardrails than tools that mainly focus on "delete now, recover later from trash."

## Install

```bash
pip install shellguardian
```

For local development:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
pytest
```

## Quick start

### Library

```python
from pathlib import Path

from shell_guardian import preview_delete, safe_delete, safe_exec, safe_move, smart_delete

workspace = Path.cwd()

result = safe_delete("tmp/cache", workspace=workspace, dry_run=True)
print(result.message)

preview = preview_delete("tmp", workspace=workspace)
print(preview.details["preview"]["summary"]["risk_counts"])

smart_result = smart_delete("tmp", workspace=workspace)
print(smart_result.message)

move_result = safe_move("tmp/a.txt", "tmp/archive/a.txt", workspace=workspace, dry_run=False)
print(move_result.performed)

exec_result = safe_exec(["python3", "--version"], workspace=workspace)
print(exec_result.returncode)
```

### CLI

```bash
shellguardian preview ./tmp
shellguardian rm ./tmp --smart
shellguardian rm ./tmp --smart --yes
shellguardian rm ./tmp/cache --dry-run
shellguardian move ./tmp/a.txt ./tmp/archive/a.txt
shellguardian exec python3 -- --version
```

### Delete preview

`shellguardian preview <path>` scans a target and groups items into three buckets:

- `Likely disposable`: cache, build, temp, and generated files
- `Review recommended`: unknown or recently modified content
- `High risk`: source trees, config, repo metadata, `.env`, and important project files

Example:

```bash
shellguardian preview ./tmp
```

```text
Delete preview: /repo/tmp
Target risk: LOW

Summary
- scanned 14 item(s)
- likely disposable 11, review recommended 2, high risk 1

Likely disposable
- tmp/cache/
- tmp/build/

Review recommended
- tmp/report.json

High risk
- tmp/.env
```

### Smart delete

`shellguardian rm <path> --smart` is the user-friendly deletion mode:

- deletes `likely disposable` items by default
- keeps `review recommended` items unless you confirm them
- refuses `high risk` items by default

If the command is running in a terminal, ShellGuardian asks whether to include review-recommended items. In scripts or CI, pass `--yes` to include them explicitly.

## Safety model

The default policy blocks:

- protected root and system locations such as `/`, `/System`, `/usr`, `/bin`, `/etc`
- paths outside the active workspace
- shell-string execution
- known destructive commands like `rm`, `sudo`, `dd`, `mkfs`, `shutdown`
- smart-delete targets that are obviously high risk, such as `src/` or `.git/`

The CLI and library offer explicit escape hatches:

- `--allow-root`
- `--allow-outside-workspace`
- `--force`

Those flags should be rare and visible in reviews.

## Audit logging

Every API returns structured metadata and can optionally write JSONL audit events:

```python
from pathlib import Path

from shell_guardian import AuditLogger, safe_delete

logger = AuditLogger(Path("audit.log"))
safe_delete("tmp/cache", workspace=Path.cwd(), dry_run=True, audit_logger=logger)
```

Sample event:

```json
{
  "action": "delete",
  "allowed": true,
  "dry_run": true,
  "performed": false,
  "target": "/repo/tmp/cache",
  "message": "Dry run: delete would be allowed."
}
```

## Project layout

```text
src/
  shell_guardian/
tests/
docs/
.github/workflows/
```

## Roadmap

- JSON and YAML policy files
- webhook / API server
- GitHub Action wrapper
- reusable prompt templates for Copilot / Claude / Codex
- allowlist presets per repository
- pluggable policy engines

## Security notes

- `safe_exec()` accepts an argument vector, not a shell string.
- Dangerous native commands are blocked and should be rewritten to safer library calls.
- Smart delete is conservative by design. It is meant to help humans avoid mistakes, not to guess aggressively.
- This project is a guardrail, not a sandbox. Pair it with OS and CI isolation.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing, and how to propose new safety rules.

## License

MIT
