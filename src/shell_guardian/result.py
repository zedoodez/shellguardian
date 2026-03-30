from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class OperationResult:
    action: str
    allowed: bool
    dry_run: bool
    performed: bool
    message: str
    target: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    returncode: int | None = None
    stdout: str | None = None
    stderr: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
