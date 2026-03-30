from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .audit import AuditLogger
from .delete_preview import scan_cleanup_candidates
from .exceptions import SafetyError
from .result import OperationResult
from .service import preview_delete, safe_delete, safe_exec, safe_move, smart_delete


def _common_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--workspace", default=".", help="Restrict operations to this workspace.")
    parser.add_argument("--dry-run", action="store_true", help="Preview the action without executing it.")
    parser.add_argument("--allow-root", action="store_true", help="Allow protected root/system paths.")
    parser.add_argument(
        "--allow-outside-workspace",
        action="store_true",
        help="Allow operations outside the active workspace.",
    )
    parser.add_argument("--audit-log", help="Write JSONL audit events to this file.")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Acknowledge risky execution when using override flags.",
    )
    parser.add_argument("--json", action="store_true", help="Emit structured JSON output.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="shellguardian")
    subparsers = parser.add_subparsers(dest="command", required=True)

    rm_parser = subparsers.add_parser("rm", help="Safely delete a file or directory.")
    _common_flags(rm_parser)
    rm_parser.add_argument("path", help="Path to delete.")
    rm_parser.add_argument(
        "--preview",
        action="store_true",
        help="Show a delete preview with risk categories instead of deleting.",
    )
    rm_parser.add_argument(
        "--smart",
        action="store_true",
        help="Delete likely disposable items by default, preserve high-risk items, and confirm review items.",
    )
    rm_parser.add_argument(
        "--yes",
        action="store_true",
        help="Approve deletion of review-recommended items in smart mode.",
    )
    rm_parser.add_argument(
        "--confirm-high-risk",
        action="store_true",
        help="Explicitly confirm deletion when the target itself is classified as high risk.",
    )

    preview_parser = subparsers.add_parser(
        "preview",
        help="Preview a delete target and classify items by risk.",
    )
    _common_flags(preview_parser)
    preview_parser.add_argument("path", help="Path to preview.")

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan the current workspace and suggest cleanup targets.",
    )
    _common_flags(scan_parser)

    clean_parser = subparsers.add_parser(
        "clean",
        help="Scan for suggested cleanup targets and delete selected ones.",
    )
    _common_flags(clean_parser)
    clean_parser.add_argument(
        "--select",
        nargs="+",
        type=int,
        help="Candidate numbers from `shellguardian scan` to clean.",
    )
    clean_parser.add_argument(
        "--all-likely",
        action="store_true",
        help="Clean all likely-disposable suggestions without prompting for selection.",
    )
    clean_parser.add_argument(
        "--yes",
        action="store_true",
        help="Also approve deletion of review-recommended items when cleaning.",
    )

    move_parser = subparsers.add_parser("move", help="Safely move a file or directory.")
    _common_flags(move_parser)
    move_parser.add_argument("source", help="Source path.")
    move_parser.add_argument("destination", help="Destination path.")

    exec_parser = subparsers.add_parser("exec", help="Safely execute a command.")
    _common_flags(exec_parser)
    exec_parser.add_argument("argv", nargs=argparse.REMAINDER, help="Command argv. Use -- before flags.")

    return parser


def _audit_logger(path: str | None) -> AuditLogger | None:
    return AuditLogger(Path(path)) if path else None


def _require_force(args: argparse.Namespace) -> None:
    if (args.allow_root or args.allow_outside_workspace) and not args.force:
        raise SafetyError("Override flags require --force.")


def _format_size(size_bytes: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(size_bytes)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{int(size_bytes)} B"


def _render_entry(entry: dict[str, object]) -> str:
    reasons = ", ".join(str(reason) for reason in entry["reasons"])
    relative_path = str(entry["relative_path"])
    kind = str(entry["kind"])
    suffix = "/" if kind == "directory" else ""
    return f"- {relative_path}{suffix} ({reasons})"


def _preview_sections(preview: dict[str, object]) -> list[tuple[str, list[dict[str, object]]]]:
    entries = [preview["target"], *preview["entries"]]
    return [
        ("Likely disposable", [entry for entry in entries if entry["risk"] == "low"]),
        ("Review recommended", [entry for entry in entries if entry["risk"] == "review"]),
        ("High risk", [entry for entry in entries if entry["risk"] == "high"]),
    ]


def _render_preview(result: dict[str, object]) -> str:
    preview = result["details"]["preview"]
    target = preview["target"]
    summary = preview["summary"]
    risk_counts = summary["risk_counts"]
    lines = [
        f"Delete preview: {result['target']}",
        f"Target risk: {str(target['risk']).upper()}",
        "",
        "Summary",
        f"- scanned {summary['scanned_items']} item(s)",
        f"- {summary['files']} file(s), {summary['directories']} directorie(s), {summary['symlinks']} symlink(s)",
        f"- total size { _format_size(int(summary['total_bytes'])) }",
        (
            f"- likely disposable {risk_counts['low']}, "
            f"review recommended {risk_counts['review']}, "
            f"high risk {risk_counts['high']}"
        ),
    ]

    for heading, entries in _preview_sections(preview):
        if not entries:
            continue
        lines.extend(["", heading])
        for entry in entries[:12]:
            lines.append(_render_entry(entry))
        if len(entries) > 12:
            lines.append(f"- ... and {len(entries) - 12} more")

    return "\n".join(lines)


def _render_smart_delete(result: dict[str, object]) -> str:
    preview = result["details"]["preview"]
    deleted_paths = result["details"]["deleted_paths"]
    preserved_paths = result["details"]["preserved_paths"]
    lines = [
        f"Smart delete: {result['target']}",
        result["message"],
        "",
        _render_preview(result),
    ]
    if deleted_paths:
        lines.extend(["", "Deleted"])
        for path in deleted_paths[:12]:
            lines.append(f"- {Path(path).as_posix()}")
        if len(deleted_paths) > 12:
            lines.append(f"- ... and {len(deleted_paths) - 12} more")
    if preserved_paths:
        lines.extend(["", "Preserved"])
        for path in preserved_paths[:12]:
            try:
                relative = Path(path).relative_to(Path(result["target"]).parent)
                lines.append(f"- {relative.as_posix()}")
            except ValueError:
                lines.append(f"- {Path(path).as_posix()}")
        if len(preserved_paths) > 12:
            lines.append(f"- ... and {len(preserved_paths) - 12} more")
    return "\n".join(lines)


def _render_scan_result(result: dict[str, object]) -> str:
    scan = result["details"]["scan"]
    summary = scan["summary"]
    candidates = scan["candidates"]
    lines = [
        f"Workspace scan: {scan['workspace']}",
        "",
        "Suggested cleanup targets",
        (
            f"- {summary['candidate_count']} candidate(s): "
            f"{summary['likely_disposable']} likely disposable, "
            f"{summary['review_recommended']} review recommended"
        ),
    ]
    if summary["high_risk_hidden"]:
        lines.append(f"- {summary['high_risk_hidden']} high-risk item(s) were intentionally not suggested")
    if not candidates:
        lines.append("- no cleanup suggestions found")
        return "\n".join(lines)
    for index, entry in enumerate(candidates, start=1):
        reasons = ", ".join(str(reason) for reason in entry["reasons"])
        lines.append(
            f"{index}. {entry['relative_path']} [{str(entry['risk']).upper()}] ({reasons})"
        )
    return "\n".join(lines)


def _render_clean_result(result: dict[str, object]) -> str:
    clean = result["details"]["clean"]
    lines = [
        f"Workspace clean: {clean['workspace']}",
        result["message"],
    ]
    if clean["selected_candidates"]:
        lines.extend(["", "Selected targets"])
        for item in clean["selected_candidates"]:
            lines.append(f"- {item['relative_path']} [{str(item['risk']).upper()}]")
    if clean["actions"]:
        lines.extend(["", "Results"])
        for action in clean["actions"]:
            lines.append(f"- {action['target']}: {action['message']}")
    return "\n".join(lines)


def _emit_result(args: argparse.Namespace, result: dict[str, object]) -> None:
    if args.json or result["action"] not in {"preview_delete", "smart_delete", "scan", "clean"}:
        print(json.dumps(result, ensure_ascii=False))
        return
    if result["action"] == "preview_delete":
        print(_render_preview(result))
        return
    if result["action"] == "smart_delete":
        print(_render_smart_delete(result))
        return
    if result["action"] == "scan":
        print(_render_scan_result(result))
        return
    print(_render_clean_result(result))


def _confirm_review_items(result: dict[str, object]) -> bool:
    preview = result["details"]["preview"]
    entries = [preview["target"], *preview["entries"]]
    review_items = [entry for entry in entries if entry["risk"] == "review"]
    if not review_items or not sys.stdin.isatty():
        return False
    answer = input(f"Delete {len(review_items)} review-recommended item(s) too? [y/N] ")
    return answer.strip().lower() in {"y", "yes"}


def _select_scan_candidates(
    candidates: list[dict[str, object]],
    *,
    chosen_indexes: list[int] | None,
    all_likely: bool,
) -> list[dict[str, object]]:
    if all_likely:
        return [entry for entry in candidates if entry["risk"] == "low"]
    if chosen_indexes:
        selected: list[dict[str, object]] = []
        max_index = len(candidates)
        for index in chosen_indexes:
            if index < 1 or index > max_index:
                raise SafetyError(f"Selection {index} is out of range for {max_index} candidates.")
            selected.append(candidates[index - 1])
        deduped: list[dict[str, object]] = []
        seen_paths: set[str] = set()
        for entry in selected:
            if entry["path"] not in seen_paths:
                seen_paths.add(str(entry["path"]))
                deduped.append(entry)
        return deduped
    if not sys.stdin.isatty():
        raise SafetyError("No cleanup targets selected. Use --select or --all-likely in non-interactive mode.")
    print("Enter the numbers to clean, separated by spaces. Press Enter to cancel.")
    answer = input("> ").strip()
    if not answer:
        return []
    try:
        numbers = [int(item) for item in answer.split()]
    except ValueError as exc:
        raise SafetyError("Selections must be numeric indexes from the scan list.") from exc
    return _select_scan_candidates(
        candidates,
        chosen_indexes=numbers,
        all_likely=False,
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    workspace = Path(args.workspace)
    logger = _audit_logger(args.audit_log)

    try:
        _require_force(args)
        if args.command == "preview":
            result = preview_delete(
                args.path,
                workspace=workspace,
                allow_root=args.allow_root,
                allow_outside_workspace=args.allow_outside_workspace,
                audit_logger=logger,
            )
        elif args.command == "scan":
            scan = scan_cleanup_candidates(workspace.resolve())
            candidates = []
            for entry in scan["candidates"]:
                candidates.append(
                    {
                        **entry,
                        "guidance": {
                            "risk_level": entry["risk"],
                            "tone": "info" if entry["risk"] == "low" else "caution",
                            "human_summary": (
                                "This looks like temporary, generated, or cache content."
                                if entry["risk"] == "low"
                                else "This target may still matter and should be reviewed before deletion."
                            ),
                            "agent_hint": (
                                "Safe to suggest cleanup."
                                if entry["risk"] == "low"
                                else "Suggest preview before deleting."
                            ),
                            "next_step": (
                                f"Run shellguardian rm ./{entry['relative_path']} --smart"
                                if entry["risk"] == "low"
                                else f"Run shellguardian preview ./{entry['relative_path']}"
                            ),
                            "recommended_command": (
                                f"shellguardian rm ./{entry['relative_path']} --smart"
                                if entry["risk"] == "low"
                                else f"shellguardian preview ./{entry['relative_path']}"
                            ),
                            "confirmation_prompt": None
                            if entry["risk"] == "low"
                            else f"Do you want to review ./{entry['relative_path']} before deleting it?",
                            "reason_codes": [],
                        },
                    }
                )
            scan["candidates"] = candidates
            result = OperationResult(
                action="scan",
                allowed=True,
                dry_run=True,
                performed=False,
                message="Workspace scan completed.",
                target=str(workspace.resolve()),
                guidance={
                    "risk_level": "review" if scan["summary"]["review_recommended"] else "low",
                    "tone": "caution" if scan["summary"]["review_recommended"] else "info",
                    "human_summary": "ShellGuardian found suggested cleanup targets in this workspace.",
                    "agent_hint": "Offer the suggested cleanup targets to the user before deleting anything.",
                    "next_step": "Use shellguardian clean --all-likely or select specific numbered targets.",
                    "recommended_command": "shellguardian clean --all-likely",
                    "confirmation_prompt": None,
                    "reason_codes": [],
                },
                details={"scan": scan},
            )
        elif args.command == "clean":
            scan = scan_cleanup_candidates(workspace.resolve())
            selected_candidates = _select_scan_candidates(
                scan["candidates"],
                chosen_indexes=args.select,
                all_likely=args.all_likely,
            )
            actions: list[dict[str, object]] = []
            any_performed = False
            for candidate in selected_candidates:
                action_result = smart_delete(
                    candidate["path"],
                    workspace=workspace,
                    confirm_review=args.yes,
                    allow_root=args.allow_root,
                    allow_outside_workspace=args.allow_outside_workspace,
                    audit_logger=logger,
                )
                actions.append(action_result.to_dict())
                any_performed = any_performed or action_result.performed
            result = OperationResult(
                action="clean",
                allowed=True,
                dry_run=False,
                performed=any_performed,
                message=(
                    f"Cleaned {len(selected_candidates)} selected target(s)."
                    if selected_candidates
                    else "No cleanup targets selected."
                ),
                target=str(workspace.resolve()),
                guidance={
                    "risk_level": "low" if any_performed else "review",
                    "tone": "info" if any_performed else "caution",
                    "human_summary": (
                        "ShellGuardian cleaned the selected low-risk targets."
                        if any_performed
                        else "ShellGuardian did not remove anything because nothing was selected or confirmed."
                    ),
                    "agent_hint": "Summarize which suggested targets were cleaned and which still need review.",
                    "next_step": (
                        "Run shellguardian scan again to review what remains."
                        if any_performed
                        else "Select numbered targets or use --all-likely to continue."
                    ),
                    "recommended_command": "shellguardian scan",
                    "confirmation_prompt": None,
                    "reason_codes": [],
                },
                details={
                    "clean": {
                        "workspace": str(workspace.resolve()),
                        "selected_candidates": selected_candidates,
                        "actions": actions,
                    }
                },
            )
        elif args.command == "rm" and args.preview:
            result = preview_delete(
                args.path,
                workspace=workspace,
                allow_root=args.allow_root,
                allow_outside_workspace=args.allow_outside_workspace,
                audit_logger=logger,
            )
        elif args.command == "rm" and args.smart:
            preview_result = preview_delete(
                args.path,
                workspace=workspace,
                allow_root=args.allow_root,
                allow_outside_workspace=args.allow_outside_workspace,
                audit_logger=None,
            )
            confirm_review = args.yes or _confirm_review_items(preview_result.to_dict())
            result = smart_delete(
                args.path,
                workspace=workspace,
                confirm_review=confirm_review,
                allow_root=args.allow_root,
                allow_outside_workspace=args.allow_outside_workspace,
                audit_logger=logger,
            )
        elif args.command == "rm":
            result = safe_delete(
                args.path,
                workspace=workspace,
                dry_run=args.dry_run,
                confirm_high_risk=args.confirm_high_risk,
                allow_root=args.allow_root,
                allow_outside_workspace=args.allow_outside_workspace,
                audit_logger=logger,
            )
        elif args.command == "move":
            result = safe_move(
                args.source,
                args.destination,
                workspace=workspace,
                dry_run=args.dry_run,
                allow_root=args.allow_root,
                allow_outside_workspace=args.allow_outside_workspace,
                audit_logger=logger,
            )
        else:
            command_argv = [item for item in args.argv if item != "--"]
            if not command_argv:
                raise SafetyError("No command provided to exec.")
            result = safe_exec(
                command_argv,
                workspace=workspace,
                dry_run=args.dry_run,
                allow_root=args.allow_root,
                allow_outside_workspace=args.allow_outside_workspace,
                audit_logger=logger,
            )
    except SafetyError as exc:
        payload = {
            "action": args.command,
            "allowed": False,
            "dry_run": bool(getattr(args, "dry_run", False)),
            "performed": False,
            "message": str(exc),
        }
        print(json.dumps(payload, ensure_ascii=False))
        return 2

    payload = result.to_dict()
    _emit_result(args, payload)
    if result.returncode:
        return result.returncode
    return 0
