from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .audit import AuditLogger
from .delete_preview import build_delete_preview
from .exceptions import SafetyError
from .policy import SafetyPolicy
from .result import OperationResult


def _policy(
    workspace: str | Path | None,
    *,
    allow_root: bool,
    allow_outside_workspace: bool,
    policy: SafetyPolicy | None,
) -> SafetyPolicy:
    if policy is not None:
        return policy
    return SafetyPolicy(
        workspace=workspace or Path.cwd(),
        allow_root=allow_root,
        allow_outside_workspace=allow_outside_workspace,
    )


def _finalize(result: OperationResult, audit_logger: AuditLogger | None) -> OperationResult:
    if audit_logger is not None:
        audit_logger.write(result)
    return result


def _delete_path(path: Path) -> bool:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
        return True
    if path.exists() or path.is_symlink():
        path.unlink()
        return True
    return False


def preview_delete(
    path: str | Path,
    *,
    workspace: str | Path | None = None,
    allow_root: bool = False,
    allow_outside_workspace: bool = False,
    policy: SafetyPolicy | None = None,
    audit_logger: AuditLogger | None = None,
) -> OperationResult:
    active_policy = _policy(
        workspace,
        allow_root=allow_root,
        allow_outside_workspace=allow_outside_workspace,
        policy=policy,
    )
    target = active_policy.ensure_not_workspace_root(path, label="delete target")
    preview = build_delete_preview(target, workspace=active_policy.workspace)
    summary = preview["summary"]
    risk_counts = summary["risk_counts"]
    return _finalize(
        OperationResult(
            action="preview_delete",
            allowed=True,
            dry_run=True,
            performed=False,
            target=str(target),
            message=(
                f"Previewed {summary['scanned_items']} item(s): "
                f"{risk_counts['low']} likely disposable, "
                f"{risk_counts['review']} review recommended, "
                f"{risk_counts['high']} high risk."
            ),
            details={"preview": preview},
        ),
        audit_logger,
    )


def smart_delete(
    path: str | Path,
    *,
    workspace: str | Path | None = None,
    confirm_review: bool = False,
    allow_root: bool = False,
    allow_outside_workspace: bool = False,
    policy: SafetyPolicy | None = None,
    audit_logger: AuditLogger | None = None,
) -> OperationResult:
    active_policy = _policy(
        workspace,
        allow_root=allow_root,
        allow_outside_workspace=allow_outside_workspace,
        policy=policy,
    )
    target = active_policy.ensure_not_workspace_root(path, label="delete target")
    preview = build_delete_preview(target, workspace=active_policy.workspace)
    target_entry = preview["target"]
    all_entries = list(preview["all_entries"])
    target_risk = str(target_entry["risk"])

    if target_risk == "high":
        raise SafetyError(
            f"Smart delete refused: target '{target}' is high risk. Run preview first and choose a narrower path."
        )

    preserved_entries = [
        entry
        for entry in all_entries
        if str(entry["risk"]) == "high" or (str(entry["risk"]) == "review" and not confirm_review)
    ]
    preserved_paths = {str(entry["path"]) for entry in preserved_entries}

    candidate_entries = [
        entry
        for entry in all_entries
        if str(entry["risk"]) == "low" or (str(entry["risk"]) == "review" and confirm_review)
    ]
    filtered_candidates: list[dict[str, object]] = []
    for entry in candidate_entries:
        entry_path = Path(str(entry["path"]))
        if entry_path.is_dir() and not entry_path.is_symlink():
            if any(Path(preserved).is_relative_to(entry_path) for preserved in preserved_paths):
                continue
        filtered_candidates.append(entry)

    deleted_paths: list[str] = []
    deleted_entry_set: set[str] = set()
    ordered_candidates = sorted(
        filtered_candidates,
        key=lambda item: (len(Path(str(item["path"])).parts), str(item["path"])),
        reverse=True,
    )
    for entry in ordered_candidates:
        current_path = Path(str(entry["path"]))
        current_str = str(current_path)
        if any(current_path.is_relative_to(Path(parent)) for parent in deleted_entry_set):
            continue
        if _delete_path(current_path):
            deleted_paths.append(current_str)
            deleted_entry_set.add(current_str)

    summary = preview["summary"]
    high_count = int(summary["risk_counts"]["high"])
    deleted_review = len([entry for entry in filtered_candidates if str(entry["risk"]) == "review"])
    deleted_low = len([entry for entry in filtered_candidates if str(entry["risk"]) == "low"])
    preserved_review = len(
        [entry for entry in preserved_entries if str(entry["risk"]) == "review"]
    )

    if deleted_paths:
        message = (
            f"Smart delete removed {len(deleted_paths)} item(s): "
            f"{deleted_low} likely disposable"
        )
        if confirm_review and deleted_review:
            message += f", {deleted_review} review-confirmed"
        if preserved_review:
            message += f". Preserved {preserved_review} review item(s) pending confirmation."
        if high_count:
            message += f" Refused {high_count} high-risk item(s)."
    else:
        message = "Smart delete did not remove anything."
        if preserved_review:
            message += " Review-recommended items were preserved pending confirmation."
        if high_count:
            message += f" Refused {high_count} high-risk item(s)."

    return _finalize(
        OperationResult(
            action="smart_delete",
            allowed=True,
            dry_run=False,
            performed=bool(deleted_paths),
            target=str(target),
            message=message,
            details={
                "preview": preview,
                "deleted_paths": deleted_paths,
                "preserved_paths": sorted(preserved_paths),
                "confirm_review": confirm_review,
            },
        ),
        audit_logger,
    )


def safe_delete(
    path: str | Path,
    *,
    workspace: str | Path | None = None,
    dry_run: bool = False,
    confirm_high_risk: bool = False,
    allow_root: bool = False,
    allow_outside_workspace: bool = False,
    policy: SafetyPolicy | None = None,
    audit_logger: AuditLogger | None = None,
) -> OperationResult:
    active_policy = _policy(
        workspace,
        allow_root=allow_root,
        allow_outside_workspace=allow_outside_workspace,
        policy=policy,
    )
    target = active_policy.ensure_not_workspace_root(path, label="delete target")
    preview = build_delete_preview(target, workspace=active_policy.workspace)
    target_risk = str(preview["target"]["risk"])
    if target_risk == "high" and not confirm_high_risk:
        raise SafetyError(
            f"Delete refused: target '{target}' is high risk. Re-run with explicit high-risk confirmation."
        )
    exists = target.exists()
    if dry_run:
        return _finalize(
            OperationResult(
                action="delete",
                allowed=True,
                dry_run=True,
                performed=False,
                target=str(target),
                message="Dry run: delete would be allowed.",
                details={"exists": exists, "preview": preview, "confirm_high_risk": confirm_high_risk},
            ),
            audit_logger,
        )
    if target.is_dir():
        shutil.rmtree(target)
    elif target.exists():
        target.unlink()
    return _finalize(
        OperationResult(
            action="delete",
            allowed=True,
            dry_run=False,
            performed=exists,
            target=str(target),
            message="Delete completed." if exists else "Target did not exist; nothing to delete.",
            details={
                "exists_before": exists,
                "preview": preview,
                "confirm_high_risk": confirm_high_risk,
            },
        ),
        audit_logger,
    )


def safe_move(
    source: str | Path,
    destination: str | Path,
    *,
    workspace: str | Path | None = None,
    dry_run: bool = False,
    allow_root: bool = False,
    allow_outside_workspace: bool = False,
    policy: SafetyPolicy | None = None,
    audit_logger: AuditLogger | None = None,
) -> OperationResult:
    active_policy = _policy(
        workspace,
        allow_root=allow_root,
        allow_outside_workspace=allow_outside_workspace,
        policy=policy,
    )
    src = active_policy.ensure_not_workspace_root(source, label="move source")
    dst = active_policy.ensure_safe_path(destination, label="move destination")
    if dry_run:
        return _finalize(
            OperationResult(
                action="move",
                allowed=True,
                dry_run=True,
                performed=False,
                target=str(dst),
                message="Dry run: move would be allowed.",
                details={"source": str(src), "destination": str(dst)},
            ),
            audit_logger,
        )
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dst))
    return _finalize(
        OperationResult(
            action="move",
            allowed=True,
            dry_run=False,
            performed=True,
            target=str(dst),
            message="Move completed.",
            details={"source": str(src), "destination": str(dst)},
        ),
        audit_logger,
    )


def safe_exec(
    argv: list[str] | tuple[str, ...],
    *,
    workspace: str | Path | None = None,
    dry_run: bool = False,
    allow_root: bool = False,
    allow_outside_workspace: bool = False,
    policy: SafetyPolicy | None = None,
    audit_logger: AuditLogger | None = None,
    check_paths: bool = True,
    capture_output: bool = True,
    text: bool = True,
) -> OperationResult:
    active_policy = _policy(
        workspace,
        allow_root=allow_root,
        allow_outside_workspace=allow_outside_workspace,
        policy=policy,
    )
    args = active_policy.ensure_safe_command(argv)
    if check_paths:
        for index, arg in enumerate(args[1:], start=1):
            candidate = Path(arg).expanduser()
            if candidate.is_absolute() or "/" in arg or arg.startswith("."):
                active_policy.ensure_safe_path(candidate, label=f"command arg {index}")
    if dry_run:
        return _finalize(
            OperationResult(
                action="exec",
                allowed=True,
                dry_run=True,
                performed=False,
                target=" ".join(args),
                message="Dry run: command would be allowed.",
                details={"argv": args},
            ),
            audit_logger,
        )
    completed = subprocess.run(
        args,
        cwd=str(active_policy.workspace),
        capture_output=capture_output,
        text=text,
        check=False,
        shell=False,
    )
    return _finalize(
        OperationResult(
            action="exec",
            allowed=True,
            dry_run=False,
            performed=True,
            target=" ".join(args),
            message="Command completed.",
            details={"argv": args},
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        ),
        audit_logger,
    )
