from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .result import OperationResult


@dataclass(slots=True)
class AuditEvent:
    timestamp: str
    action: str
    allowed: bool
    dry_run: bool
    performed: bool
    target: str | None
    message: str
    details: dict
    returncode: int | None = None

    @classmethod
    def from_result(cls, result: OperationResult) -> "AuditEvent":
        return cls(
            timestamp=datetime.now(timezone.utc).isoformat(),
            action=result.action,
            allowed=result.allowed,
            dry_run=result.dry_run,
            performed=result.performed,
            target=result.target,
            message=result.message,
            details=result.details,
            returncode=result.returncode,
        )


class AuditLogger:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def write(self, result: OperationResult) -> None:
        event = AuditEvent.from_result(result)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            json.dump(asdict(event), handle, sort_keys=True)
            handle.write("\n")
