from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SourceIdentity:
    git_commit: str
    git_dirty: bool
    source_fingerprint: str


def source_identity(code_root: Path) -> SourceIdentity:
    code_root = code_root.resolve()
    commit = "unversioned"
    status = b""
    if (code_root / ".git").exists():
        commit = _git_output(code_root, ["rev-parse", "HEAD"]).decode().strip()
        status = _git_output(code_root, ["status", "--porcelain", "--untracked-files=normal"])
    source_material = bytearray(b"silk-source-files\0")
    files = [code_root / name for name in ("Cargo.toml", "Cargo.lock", ".dockerignore")]
    excluded = {".venv", "__pycache__", ".pytest_cache", ".ruff_cache", "target"}
    suffixes = {".rs", ".toml", ".lock", ".py", ".json", ".yaml", ".c", ".h", ".S", ".inc", ".sh"}
    for directory in ("crates", "experiments"):
        for path in (code_root / directory).rglob("*"):
            if not path.is_file() or excluded.intersection(path.relative_to(code_root).parts):
                continue
            if path.suffix == ".yaml" and not path.name.endswith(".example.yaml"):
                continue
            if path.suffix in suffixes or path.name in {"Dockerfile", "LICENSE", "SHA256SUMS"}:
                files.append(path)
    for path in sorted(files, key=lambda p: p.relative_to(code_root).as_posix()):
        source_material.extend(b"\0")
        source_material.extend(path.relative_to(code_root).as_posix().encode())
        source_material.extend(b"\0")
        source_material.extend(path.read_bytes())
    return SourceIdentity(
        git_commit=commit,
        git_dirty=bool(status),
        source_fingerprint=hashlib.sha256(source_material).hexdigest(),
    )


def image_provenance_labels(identity: SourceIdentity) -> dict[str, str]:
    return {
        "org.silk.build.git-commit": identity.git_commit,
        "org.silk.build.git-dirty": str(identity.git_dirty).lower(),
        "org.silk.build.source-fingerprint": identity.source_fingerprint,
    }


def _git_output(code_root: Path, arguments: list[str]) -> bytes:
    return subprocess.run(
        ["git", *arguments],
        cwd=code_root,
        check=True,
        capture_output=True,
    ).stdout
