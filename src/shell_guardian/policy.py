from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .exceptions import SafetyError


DEFAULT_PROTECTED_PATHS = (
    "/",
    "/System",
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/lib",
    "/proc",
    "/sbin",
    "/sys",
    "/usr",
    "/var",
)

DEFAULT_DANGEROUS_COMMANDS = (
    "dd",
    "diskutil",
    "format",
    "halt",
    "mkfs",
    "mount",
    "poweroff",
    "reboot",
    "rm",
    "shutdown",
    "sudo",
    "umount",
)


def _resolve(path: str | Path) -> Path:
    return Path(path).expanduser().resolve(strict=False)


@dataclass(slots=True)
class SafetyPolicy:
    workspace: Path
    protected_paths: tuple[Path, ...] = field(default_factory=tuple)
    dangerous_commands: tuple[str, ...] = field(default_factory=lambda: DEFAULT_DANGEROUS_COMMANDS)
    allow_root: bool = False
    allow_outside_workspace: bool = False

    def __post_init__(self) -> None:
        self.workspace = _resolve(self.workspace)
        if not self.protected_paths:
            self.protected_paths = tuple(_resolve(item) for item in DEFAULT_PROTECTED_PATHS)
        else:
            self.protected_paths = tuple(_resolve(item) for item in self.protected_paths)
        self.dangerous_commands = tuple(self.dangerous_commands)

    @classmethod
    def from_json(
        cls,
        path: str | Path,
        *,
        workspace: str | Path,
        allow_root: bool = False,
        allow_outside_workspace: bool = False,
    ) -> "SafetyPolicy":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            workspace=workspace,
            protected_paths=tuple(data.get("protected_paths", DEFAULT_PROTECTED_PATHS)),
            dangerous_commands=tuple(data.get("dangerous_commands", DEFAULT_DANGEROUS_COMMANDS)),
            allow_root=allow_root,
            allow_outside_workspace=allow_outside_workspace,
        )

    def ensure_safe_path(self, path: str | Path, *, label: str = "path") -> Path:
        resolved = _resolve(path)
        workspace_lineage = {self.workspace, *self.workspace.parents}
        if not self.allow_root:
            for protected in self.protected_paths:
                if resolved == protected:
                    raise SafetyError(f"{label} '{resolved}' is protected by policy.")
                if protected in resolved.parents and protected not in workspace_lineage:
                    raise SafetyError(f"{label} '{resolved}' is protected by policy.")
        if not self.allow_outside_workspace:
            if resolved != self.workspace and self.workspace not in resolved.parents:
                raise SafetyError(
                    f"{label} '{resolved}' is outside the active workspace '{self.workspace}'."
                )
        return resolved

    def ensure_not_workspace_root(self, path: str | Path, *, label: str = "path") -> Path:
        resolved = self.ensure_safe_path(path, label=label)
        if resolved == self.workspace:
            raise SafetyError(f"{label} '{resolved}' is the workspace root and cannot be targeted.")
        return resolved

    def ensure_safe_command(self, argv: Iterable[str]) -> list[str]:
        args = [str(item) for item in argv]
        if not args:
            raise SafetyError("Command argument vector cannot be empty.")
        command = Path(args[0]).name
        if command in self.dangerous_commands:
            raise SafetyError(
                f"Command '{command}' is blocked by policy. Use a safe API instead."
            )
        return args
