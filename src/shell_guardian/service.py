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


def _reason_codes(entry: dict[str, object]) -> list[str]:
    mapping = {
        "workspace root": "workspace_root",
        "environment file": "contains_env_file",
        "project-critical file": "project_critical_file",
        "repository metadata": "contains_repo_metadata",
        "source or config directory": "contains_source_code",
        "source or config file": "contains_source_code",
        "common cache/build/temp directory": "common_temp_directory",
        "inside cache/build/temp directory": "inside_temp_directory",
        "common generated or temporary file": "generated_file",
        "hidden file or directory": "hidden_path",
        "recently modified": "recently_modified",
        "not recognized as disposable": "unknown_disposable_status",
        "symlink": "symlink_target",
        "large directory": "large_directory",
    }
    seen: list[str] = []
    for reason in entry.get("reasons", []):
        code = mapping.get(str(reason), "policy_reason")
        if code not in seen:
            seen.append(code)
    return seen


def _risk_tone(risk_level: str) -> str:
    return {
        "low": "info",
        "review": "caution",
        "high": "blocked",
    }.get(risk_level, "info")


def _preview_guidance(preview: dict[str, object], target: str) -> dict[str, object]:
    entry = preview["target"]
    risk_level = str(entry["risk"])
    reason_codes = _reason_codes(entry)
    relative_path = str(entry["relative_path"])
    if risk_level == "low":
        return {
            "risk_level": "low",
            "tone": _risk_tone("low"),
            "human_summary": "This looks like temporary, generated, or cache content and is likely safe to clean.",
            "agent_hint": "Safe to suggest cleanup or smart delete.",
            "next_step": "Proceed with smart delete if cleanup is intended.",
            "recommended_command": f"shellguardian rm ./{relative_path} --smart",
            "confirmation_prompt": None,
            "reason_codes": reason_codes,
        }
    if risk_level == "review":
        return {
            "risk_level": "review",
            "tone": _risk_tone("review"),
            "human_summary": "This target may still contain useful files, so it should be reviewed before deletion.",
            "agent_hint": "Do not assume this target is disposable.",
            "next_step": "Preview the target and ask the user before continuing.",
            "recommended_command": f"shellguardian preview ./{relative_path}",
            "confirmation_prompt": f"This action would delete files in ./{relative_path} that may still be useful. Do you want to continue?",
            "reason_codes": reason_codes,
        }
    return {
        "risk_level": "high",
        "tone": _risk_tone("high"),
        "human_summary": "This target contains important or sensitive files, so deletion is blocked by default.",
        "agent_hint": "Do not continue without explicit user confirmation.",
        "next_step": "Ask the user for explicit confirmation before retrying.",
        "recommended_command": f"shellguardian rm ./{relative_path} --confirm-high-risk",
        "confirmation_prompt": f"This action would delete important files in ./{relative_path}. Are you sure you want to continue?",
        "reason_codes": reason_codes,
    }


def _scan_candidate_guidance(entry: dict[str, object]) -> dict[str, object]:
    risk_level = str(entry["risk"])
    relative_path = str(entry["relative_path"])
    guidance = _preview_guidance({"target": entry}, str(entry["path"]))
    if risk_level == "low":
        guidance["recommended_command"] = f"shellguardian rm ./{relative_path} --smart"
    else:
        guidance["recommended_command"] = f"shellguardian preview ./{relative_path}"
    return guidance


def _smart_delete_guidance(preview: dict[str, object], target: str, *, confirm_review: bool, deleted_paths: list[str], preserved_paths: list[str]) -> dict[str, object]:
    risk_level = str(preview["target"]["risk"])
    if deleted_paths and preserved_paths:
        human_summary = "Low-risk files were removed while review-recommended and high-risk files were preserved."
        next_step = "Review the preserved files and confirm explicitly if you want to delete more."
    elif deleted_paths:
        human_summary = "The selected target was cleaned using the smart-delete policy."
        next_step = "No further action is needed unless you want to review remaining files."
    else:
        human_summary = "No files were removed because the remaining contents were not safe to delete automatically."
        next_step = "Preview the preserved files and ask for confirmation before deleting them."
    relative_path = str(preview["target"]["relative_path"])
    return {
        "risk_level": risk_level,
        "tone": "caution" if preserved_paths else "info",
        "human_summary": human_summary,
        "agent_hint": "Explain what was deleted and what was preserved before asking for any further confirmation.",
        "next_step": next_step,
        "recommended_command": f"shellguardian preview ./{relative_path}",
        "confirmation_prompt": (
            f"ShellGuardian preserved some files in ./{relative_path}. Do you want to review them before deleting more?"
            if preserved_paths
            else None
        ),
        "reason_codes": _reason_codes(preview["target"]),
    }


def _delete_guidance(preview: dict[str, object], *, confirm_high_risk: bool) -> dict[str, object]:
    guidance = _preview_guidance(preview, str(preview["target"]["path"]))
    if confirm_high_risk and guidance["risk_level"] == "high":
        guidance["tone"] = "warning"
        guidance["human_summary"] = "This high-risk delete was explicitly confirmed by the user."
        guidance["agent_hint"] = "Only proceed because explicit confirmation was already given."
        guidance["next_step"] = "Proceed carefully and summarize what was removed."
        guidance["confirmation_prompt"] = None
    return guidance


def _generic_guidance(*, risk_level: str, human_summary: str, agent_hint: str, next_step: str, recommended_command: str | None = None, confirmation_prompt: str | None = None, reason_codes: list[str] | None = None) -> dict[str, object]:
    return {
        "risk_level": risk_level,
        "tone": _risk_tone(risk_level),
        "human_summary": human_summary,
        "agent_hint": agent_hint,
        "next_step": next_step,
        "recommended_command": recommended_command,
        "confirmation_prompt": confirmation_prompt,
        "reason_codes": reason_codes or [],
    }


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
            guidance=_preview_guidance(preview, str(target)),
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
            guidance=_smart_delete_guidance(
                preview,
                str(target),
                confirm_review=confirm_review,
                deleted_paths=deleted_paths,
                preserved_paths=sorted(preserved_paths),
            ),
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
                guidance=_delete_guidance(preview, confirm_high_risk=confirm_high_risk),
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
            guidance=_delete_guidance(preview, confirm_high_risk=confirm_high_risk),
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
                guidance=_generic_guidance(
                    risk_level="low",
                    human_summary="This move stays inside the active workspace and looks safe to perform.",
                    agent_hint="Safe to proceed with the move.",
                    next_step="Run the move without dry-run if the destination looks correct.",
                    recommended_command=f"shellguardian move {src} {dst}",
                ),
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
            guidance=_generic_guidance(
                risk_level="low",
                human_summary="The move completed inside the active workspace.",
                agent_hint="Report the source and destination back to the user.",
                next_step="No further action is needed unless the user wants to verify the moved files.",
                recommended_command=None,
            ),
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
                guidance=_generic_guidance(
                    risk_level="low",
                    human_summary="This command passed ShellGuardian policy checks.",
                    agent_hint="Safe to proceed if the user wants to run it.",
                    next_step="Run the command without dry-run if you want to execute it.",
                    recommended_command=" ".join(args),
                ),
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
            guidance=_generic_guidance(
                risk_level="low",
                human_summary="The command completed after passing ShellGuardian policy checks.",
                agent_hint="Summarize the command output and any side effects for the user.",
                next_step="Review stdout or stderr if you need to explain the result.",
                recommended_command=None,
            ),
            details={"argv": args},
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        ),
        audit_logger,
    )
