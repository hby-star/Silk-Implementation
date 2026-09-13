from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class WorkspacePaths:
    code_root: Path
    output_root: Path
    state_root: Path
    raw_root: Path
    processed_root: Path
    reports_root: Path
    artifacts_root: Path
    releases_root: Path
    archive_root: Path


def workspace_paths() -> WorkspacePaths:
    code_root = Path(__file__).resolve().parents[3]
    output = code_root / "output"
    artifacts = code_root / "artifacts"
    return WorkspacePaths(
        code_root=code_root,
        output_root=output,
        state_root=output / "experiments" / "state",
        raw_root=output / "experiments" / "raw",
        processed_root=output / "experiments" / "processed",
        reports_root=output / "reports",
        artifacts_root=artifacts,
        releases_root=artifacts / "releases",
        archive_root=artifacts / "archive",
    )
