# Policy Design

The initial policy is intentionally simple and easy to audit.

## Default protections

- deny protected root and system paths
- deny operations outside the declared workspace
- deny shell-string execution
- deny known dangerous commands that should be rewritten to safer APIs

## Escape hatches

- `allow_root`: permit explicitly protected paths
- `allow_outside_workspace`: permit operations outside `workspace`
- `force`: acknowledge risky execution in CLI mode

## Future extensions

- repository-local JSON or YAML policy files
- webhook notifications
- policy plugins
- project-specific allowlists
- per-command reviewers or approval policies

