from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from shell_guardian import (
    AuditLogger,
    SafetyError,
    preview_delete,
    safe_delete,
    safe_exec,
    safe_move,
    smart_delete,
)


def test_safe_delete_removes_file(tmp_path: Path) -> None:
    target = tmp_path / "data.txt"
    target.write_text("hello", encoding="utf-8")

    result = safe_delete(target, workspace=tmp_path)

    assert result.performed is True
    assert not target.exists()


def test_safe_delete_rejects_protected_root() -> None:
    with pytest.raises(SafetyError):
        safe_delete("/", workspace=Path.cwd())


def test_safe_delete_rejects_workspace_root(tmp_path: Path) -> None:
    with pytest.raises(SafetyError):
        safe_delete(tmp_path, workspace=tmp_path)


def test_safe_move_dry_run_does_not_move(tmp_path: Path) -> None:
    source = tmp_path / "a.txt"
    destination = tmp_path / "archive" / "a.txt"
    source.write_text("hello", encoding="utf-8")

    result = safe_move(source, destination, workspace=tmp_path, dry_run=True)

    assert result.performed is False
    assert source.exists()
    assert not destination.exists()


def test_safe_exec_runs_allowed_command(tmp_path: Path) -> None:
    result = safe_exec(["python3", "--version"], workspace=tmp_path)

    assert result.returncode == 0
    assert "Python" in (result.stdout or result.stderr or "")


def test_safe_exec_rejects_dangerous_command(tmp_path: Path) -> None:
    with pytest.raises(SafetyError):
        safe_exec(["rm", "-rf", str(tmp_path)], workspace=tmp_path)


def test_audit_logger_writes_jsonl(tmp_path: Path) -> None:
    target = tmp_path / "data.txt"
    target.write_text("hello", encoding="utf-8")
    log_path = tmp_path / "audit.log"
    logger = AuditLogger(log_path)

    safe_delete(target, workspace=tmp_path, dry_run=True, audit_logger=logger)

    event = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert event["action"] == "delete"
    assert event["dry_run"] is True


def test_preview_delete_marks_risk_levels(tmp_path: Path) -> None:
    target = tmp_path / "cleanup"
    target.mkdir()
    cache_dir = target / "tmp"
    cache_dir.mkdir()
    (cache_dir / "cache.log").write_text("cache", encoding="utf-8")
    (target / ".env").write_text("secret", encoding="utf-8")
    (target / "report.json").write_text("{}", encoding="utf-8")

    result = preview_delete(target, workspace=tmp_path)
    preview = result.details["preview"]
    entries = [preview["target"], *preview["entries"]]
    by_name = {entry["name"]: entry for entry in entries}

    assert by_name["cleanup"]["risk"] == "review"
    assert by_name["tmp"]["risk"] == "low"
    assert by_name["cache.log"]["risk"] == "low"
    assert by_name[".env"]["risk"] == "high"
    assert by_name["report.json"]["risk"] == "review"


def test_smart_delete_only_removes_low_risk_by_default(tmp_path: Path) -> None:
    target = tmp_path / "cleanup"
    target.mkdir()
    low_file = target / "cache.log"
    review_file = target / "report.json"
    high_file = target / ".env"
    low_file.write_text("cache", encoding="utf-8")
    review_file.write_text("{}", encoding="utf-8")
    high_file.write_text("secret", encoding="utf-8")

    result = smart_delete(target, workspace=tmp_path)

    assert result.performed is True
    assert not low_file.exists()
    assert review_file.exists()
    assert high_file.exists()
    assert str(review_file) in result.details["preserved_paths"]
    assert str(high_file) in result.details["preserved_paths"]


def test_smart_delete_can_remove_review_items_after_confirmation(tmp_path: Path) -> None:
    target = tmp_path / "cleanup"
    target.mkdir()
    review_file = target / "report.json"
    high_file = target / ".env"
    review_file.write_text("{}", encoding="utf-8")
    high_file.write_text("secret", encoding="utf-8")

    result = smart_delete(target, workspace=tmp_path, confirm_review=True)

    assert result.performed is True
    assert not review_file.exists()
    assert high_file.exists()
    assert str(high_file) in result.details["preserved_paths"]


def test_smart_delete_rejects_high_risk_target(tmp_path: Path) -> None:
    target = tmp_path / "src"
    target.mkdir()
    (target / "main.py").write_text("print('hi')", encoding="utf-8")

    with pytest.raises(SafetyError):
        smart_delete(target, workspace=tmp_path)


def test_cli_rm_dry_run(tmp_path: Path) -> None:
    target = tmp_path / "cache"
    target.mkdir()
    command = [
        sys.executable,
        "-m",
        "shell_guardian",
        "rm",
        str(target),
        "--workspace",
        str(tmp_path),
        "--dry-run",
    ]

    completed = subprocess.run(
        command,
        cwd=str(Path(__file__).resolve().parents[1]),
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")},
        text=True,
        capture_output=True,
        check=False,
    )

    payload = json.loads(completed.stdout.strip())
    assert completed.returncode == 0
    assert payload["allowed"] is True
    assert target.exists()


def test_cli_preview_json(tmp_path: Path) -> None:
    target = tmp_path / "tmp"
    target.mkdir()
    (target / "cache.log").write_text("cache", encoding="utf-8")

    command = [
        sys.executable,
        "-m",
        "shell_guardian",
        "preview",
        str(target),
        "--workspace",
        str(tmp_path),
        "--json",
    ]

    completed = subprocess.run(
        command,
        cwd=str(Path(__file__).resolve().parents[1]),
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")},
        text=True,
        capture_output=True,
        check=False,
    )

    payload = json.loads(completed.stdout.strip())
    assert completed.returncode == 0
    assert payload["action"] == "preview_delete"
    assert payload["details"]["preview"]["target"]["risk"] == "low"


def test_cli_smart_delete_keeps_review_and_high_risk_without_yes(tmp_path: Path) -> None:
    target = tmp_path / "cleanup"
    target.mkdir()
    (target / "cache.log").write_text("cache", encoding="utf-8")
    review_file = target / "report.json"
    high_file = target / ".env"
    review_file.write_text("{}", encoding="utf-8")
    high_file.write_text("secret", encoding="utf-8")

    command = [
        sys.executable,
        "-m",
        "shell_guardian",
        "rm",
        str(target),
        "--workspace",
        str(tmp_path),
        "--smart",
        "--json",
    ]

    completed = subprocess.run(
        command,
        cwd=str(Path(__file__).resolve().parents[1]),
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")},
        text=True,
        capture_output=True,
        check=False,
    )

    payload = json.loads(completed.stdout.strip())
    assert completed.returncode == 0
    assert payload["action"] == "smart_delete"
    assert not (target / "cache.log").exists()
    assert review_file.exists()
    assert high_file.exists()


def test_cli_requires_force_for_override(tmp_path: Path) -> None:
    command = [
        sys.executable,
        "-m",
        "shell_guardian",
        "rm",
        str(tmp_path / "data"),
        "--workspace",
        str(tmp_path),
        "--allow-outside-workspace",
    ]

    completed = subprocess.run(
        command,
        cwd=str(Path(__file__).resolve().parents[1]),
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")},
        text=True,
        capture_output=True,
        check=False,
    )

    payload = json.loads(completed.stdout.strip())
    assert completed.returncode == 2
    assert payload["allowed"] is False
    assert "--force" in payload["message"]
