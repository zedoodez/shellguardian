from __future__ import annotations

from pathlib import Path
import time


LOW_RISK_DIR_NAMES = {
    ".cache",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    "__pycache__",
    "build",
    "cache",
    "coverage",
    "dist",
    "temp",
    "tmp",
}

SCAN_SKIP_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "env",
    "node_modules",
    "site-packages",
    "venv",
}

LOW_RISK_FILE_NAMES = {
    ".coverage",
    ".ds_store",
}

LOW_RISK_SUFFIXES = {
    ".cache",
    ".log",
    ".pyc",
    ".pyo",
    ".tmp",
    ".temp",
}

HIGH_RISK_DIR_NAMES = {
    ".git",
    ".github",
    "app",
    "config",
    "docs",
    "lib",
    "scripts",
    "src",
    "test",
    "tests",
}

HIGH_RISK_FILE_NAMES = {
    ".env",
    "contributing.md",
    "docker-compose.yml",
    "dockerfile",
    "license",
    "makefile",
    "package-lock.json",
    "package.json",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pyproject.toml",
    "readme.md",
    "requirements.txt",
    "yarn.lock",
}

HIGH_RISK_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".h",
    ".hpp",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".md",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".sql",
    ".swift",
    ".toml",
    ".ts",
    ".tsx",
    ".yaml",
    ".yml",
}

RECENT_SECONDS = 24 * 60 * 60


def _kind(path: Path) -> str:
    if path.is_symlink():
        return "symlink"
    if path.is_dir():
        return "directory"
    return "file"


def _size_bytes(path: Path) -> int:
    try:
        if path.is_file() and not path.is_symlink():
            return path.stat().st_size
    except OSError:
        return 0
    return 0


def _mtime_is_recent(path: Path) -> bool:
    try:
        return (time.time() - path.stat().st_mtime) <= RECENT_SECONDS
    except OSError:
        return False


def _relative_path(path: Path, workspace: Path) -> str:
    try:
        relative = path.relative_to(workspace)
        return "." if not relative.parts else relative.as_posix()
    except ValueError:
        return path.as_posix()


def _directory_child_count(path: Path) -> int:
    if not path.is_dir() or path.is_symlink():
        return 0
    try:
        return sum(1 for _ in path.iterdir())
    except OSError:
        return 0


def classify_delete_path(path: Path, *, workspace: Path) -> dict[str, object]:
    relative_path = _relative_path(path, workspace)
    parts_lower = [part.lower() for part in path.parts]
    rel_parts_lower = [part.lower() for part in Path(relative_path).parts if part != "."]
    name_lower = path.name.lower()
    suffix_lower = path.suffix.lower()
    kind = _kind(path)
    reasons: list[str] = []

    if path == workspace:
        return {
            "path": str(path),
            "relative_path": relative_path,
            "name": path.name or str(path),
            "kind": kind,
            "risk": "high",
            "reasons": ["workspace root"],
            "size_bytes": _size_bytes(path),
        }

    if path.is_symlink():
        reasons.append("symlink")
        risk = "review"
    elif name_lower.startswith(".env"):
        reasons.append("environment file")
        risk = "high"
    elif name_lower in HIGH_RISK_FILE_NAMES:
        reasons.append("project-critical file")
        risk = "high"
    elif any(part in {".git", ".github"} for part in rel_parts_lower):
        reasons.append("repository metadata")
        risk = "high"
    elif kind == "directory" and name_lower in HIGH_RISK_DIR_NAMES:
        reasons.append("source or config directory")
        risk = "high"
    elif suffix_lower in HIGH_RISK_SUFFIXES and not any(part in LOW_RISK_DIR_NAMES for part in rel_parts_lower):
        reasons.append("source or config file")
        risk = "high"
    elif kind == "directory" and name_lower in LOW_RISK_DIR_NAMES:
        reasons.append("common cache/build/temp directory")
        risk = "low"
    elif any(part in LOW_RISK_DIR_NAMES for part in rel_parts_lower):
        reasons.append("inside cache/build/temp directory")
        risk = "low"
    elif name_lower in LOW_RISK_FILE_NAMES or suffix_lower in LOW_RISK_SUFFIXES:
        reasons.append("common generated or temporary file")
        risk = "low"
    elif name_lower.startswith("."):
        reasons.append("hidden file or directory")
        risk = "review"
    elif _mtime_is_recent(path):
        reasons.append("recently modified")
        risk = "review"
    else:
        reasons.append("not recognized as disposable")
        risk = "review"

    child_count = _directory_child_count(path)
    if risk == "review" and child_count >= 100:
        reasons.append("large directory")

    return {
        "path": str(path),
        "relative_path": relative_path,
        "name": path.name or str(path),
        "kind": kind,
        "risk": risk,
        "reasons": reasons,
        "size_bytes": _size_bytes(path),
    }


def build_delete_preview(target: Path, *, workspace: Path) -> dict[str, object]:
    target_entry = classify_delete_path(target, workspace=workspace)
    all_entries = [target_entry]
    descendant_entries: list[dict[str, object]] = []

    if target.is_dir() and not target.is_symlink():
        for child in sorted(target.rglob("*"), key=lambda item: (len(item.parts), str(item))):
            entry = classify_delete_path(child, workspace=workspace)
            all_entries.append(entry)
            descendant_entries.append(entry)

    entries_for_summary = descendant_entries if descendant_entries else [target_entry]
    total_files = sum(1 for entry in entries_for_summary if entry["kind"] == "file")
    total_directories = sum(1 for entry in entries_for_summary if entry["kind"] == "directory")
    total_symlinks = sum(1 for entry in entries_for_summary if entry["kind"] == "symlink")
    total_bytes = sum(int(entry["size_bytes"]) for entry in entries_for_summary)

    risk_counts = {"low": 0, "review": 0, "high": 0}
    for entry in entries_for_summary:
        risk_counts[str(entry["risk"])] += 1

    return {
        "target": target_entry,
        "entries": descendant_entries,
        "all_entries": all_entries,
        "summary": {
            "scanned_items": len(entries_for_summary),
            "files": total_files,
            "directories": total_directories,
            "symlinks": total_symlinks,
            "total_bytes": total_bytes,
            "risk_counts": risk_counts,
        },
    }


def scan_cleanup_candidates(workspace: Path) -> dict[str, object]:
    candidates: list[dict[str, object]] = []
    seen_paths: set[str] = set()
    skipped_high_risk = 0

    def should_skip_dir(path: Path) -> bool:
        return path.name.lower() in SCAN_SKIP_DIR_NAMES

    def add_candidate(path: Path) -> None:
        if not path.exists():
            return
        entry = classify_delete_path(path, workspace=workspace)
        risk = str(entry["risk"])
        if risk == "high":
            return
        path_str = str(path)
        if path_str in seen_paths:
            return
        if any(path.is_relative_to(Path(existing)) for existing in seen_paths):
            return
        seen_paths.add(path_str)
        candidates.append(entry)

    for item in sorted(workspace.iterdir(), key=lambda current: (current.is_file(), str(current))):
        if item.is_dir() and should_skip_dir(item):
            continue
        entry = classify_delete_path(item, workspace=workspace)
        risk = str(entry["risk"])
        name_lower = item.name.lower()
        if risk == "low":
            add_candidate(item)
            continue
        if risk == "review" and name_lower in {"logs", "log", "output", "artifacts", "reports"}:
            add_candidate(item)
            continue
        if item.is_dir() and not item.is_symlink():
            for current_root, dirnames, filenames in item.walk():
                dirnames[:] = [dirname for dirname in dirnames if dirname.lower() not in SCAN_SKIP_DIR_NAMES]
                for dirname in sorted(dirnames):
                    child = current_root / dirname
                    child_entry = classify_delete_path(child, workspace=workspace)
                    child_risk = str(child_entry["risk"])
                    child_name = child.name.lower()
                    if child_risk == "low":
                        add_candidate(child)
                    elif child_risk == "review" and child_name in {"logs", "log", "output", "artifacts", "reports"}:
                        add_candidate(child)
                for filename in sorted(filenames):
                    child = current_root / filename
                    if any(part.lower() in SCAN_SKIP_DIR_NAMES for part in child.parts):
                        continue
                    child_entry = classify_delete_path(child, workspace=workspace)
                    child_risk = str(child_entry["risk"])
                    child_name = child.name.lower()
                    if child_risk == "low":
                        add_candidate(child)
                    elif child_risk == "review" and child_name in {"logs", "log", "output", "artifacts", "reports"}:
                        add_candidate(child)

    candidates.sort(key=lambda entry: (entry["risk"] != "low", str(entry["relative_path"])))
    summary = {
        "workspace": str(workspace),
        "candidate_count": len(candidates),
        "likely_disposable": sum(1 for entry in candidates if entry["risk"] == "low"),
        "review_recommended": sum(1 for entry in candidates if entry["risk"] == "review"),
        "high_risk_hidden": skipped_high_risk,
    }
    for current_root, dirnames, filenames in workspace.walk():
        dirnames[:] = [dirname for dirname in dirnames if dirname.lower() not in SCAN_SKIP_DIR_NAMES]
        for dirname in dirnames:
            item = current_root / dirname
            if classify_delete_path(item, workspace=workspace)["risk"] == "high":
                skipped_high_risk += 1
        for filename in filenames:
            item = current_root / filename
            if classify_delete_path(item, workspace=workspace)["risk"] == "high":
                skipped_high_risk += 1
    summary["high_risk_hidden"] = skipped_high_risk
    return {"workspace": str(workspace), "candidates": candidates, "summary": summary}
