from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .audit import AuditLogger
from .exceptions import SafetyError
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

    preview_parser = subparsers.add_parser(
        "preview",
        help="Preview a delete target and classify items by risk.",
    )
    _common_flags(preview_parser)
    preview_parser.add_argument("path", help="Path to preview.")

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


def _emit_result(args: argparse.Namespace, result: dict[str, object]) -> None:
    if args.json or result["action"] not in {"preview_delete", "smart_delete"}:
        print(json.dumps(result, ensure_ascii=False))
        return
    if result["action"] == "preview_delete":
        print(_render_preview(result))
        return
    print(_render_smart_delete(result))


def _confirm_review_items(result: dict[str, object]) -> bool:
    preview = result["details"]["preview"]
    entries = [preview["target"], *preview["entries"]]
    review_items = [entry for entry in entries if entry["risk"] == "review"]
    if not review_items or not sys.stdin.isatty():
        return False
    answer = input(f"Delete {len(review_items)} review-recommended item(s) too? [y/N] ")
    return answer.strip().lower() in {"y", "yes"}


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
