from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ...paths import workspace_paths
from ...provenance import source_identity

BUILD_MANIFEST = "build-artifact.json"
AWS_TARGET = "x86_64-unknown-linux-musl"


@dataclass(frozen=True)
class AwsBuildArtifact:
    binary_path: str
    sha256: str
    target: str
    source_fingerprint: str


def build_aws_runner(output_dir: Path) -> AwsBuildArtifact:
    """Cross-build the static Linux runner without contacting AWS."""
    code_root = workspace_paths().code_root
    resolved = output_dir.resolve()
    if resolved == code_root or code_root not in resolved.parents:
        raise ValueError("AWS build output must be a scoped directory under the workspace root")
    if resolved.exists():
        if any(resolved.iterdir()):
            raise ValueError(f"AWS build output directory is not empty: {resolved}")
    else:
        resolved.mkdir(parents=True)

    identity = source_identity(code_root)
    try:
        subprocess.run(
            [
                "cargo",
                "zigbuild",
                "--release",
                "--locked",
                "--package",
                "experiment-runner",
                "--target",
                AWS_TARGET,
            ],
            cwd=code_root,
            env=_aws_build_environment(
                git_commit=identity.git_commit,
                git_dirty=identity.git_dirty,
                source_fingerprint=identity.source_fingerprint,
            ),
            check=True,
        )
        built_binary = code_root / "target" / AWS_TARGET / "release" / "experiment-runner"
        if not built_binary.is_file():
            raise RuntimeError("cargo zigbuild did not produce experiment-runner")
        binary = resolved / "experiment-runner"
        shutil.copy2(built_binary, binary)
    except Exception:
        if resolved.exists():
            shutil.rmtree(resolved)
        raise
    artifact = AwsBuildArtifact(
        binary_path=str(binary),
        sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        target=AWS_TARGET,
        source_fingerprint=identity.source_fingerprint,
    )
    (resolved / BUILD_MANIFEST).write_text(
        json.dumps(
            {
                "schema_id": "silk-aws-build/v1",
                **artifact.__dict__,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return artifact


def ensure_aws_runner(cache_root: Path, *, rebuild: bool = False) -> AwsBuildArtifact:
    """Reuse the current fingerprint's static runner or build it once."""
    code_root = workspace_paths().code_root
    identity = source_identity(code_root)
    root = cache_root.resolve()
    if root == code_root or code_root not in root.parents:
        raise ValueError("AWS runner cache must be a scoped directory under the workspace root")
    target = root / identity.source_fingerprint[:20]
    if target.is_dir() and not rebuild:
        return _load_cached_artifact(target, identity.source_fingerprint)
    if target.exists():
        if target.parent != root or not target.name:
            raise RuntimeError("AWS runner cache target escaped its scoped root")
        shutil.rmtree(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    return build_aws_runner(target)


def _load_cached_artifact(directory: Path, source_fingerprint: str) -> AwsBuildArtifact:
    manifest = directory / BUILD_MANIFEST
    try:
        value = json.loads(manifest.read_text(encoding="utf-8"))
        if value.get("schema_id") != "silk-aws-build/v1":
            raise ValueError("unsupported schema")
        artifact = AwsBuildArtifact(
            binary_path=str(value["binary_path"]),
            sha256=str(value["sha256"]),
            target=str(value["target"]),
            source_fingerprint=str(value["source_fingerprint"]),
        )
    except (OSError, KeyError, TypeError, ValueError) as error:
        raise RuntimeError(f"invalid cached AWS build artifact: {manifest}") from error
    binary = Path(artifact.binary_path)
    if artifact.source_fingerprint != source_fingerprint:
        raise RuntimeError("cached AWS runner belongs to a different source fingerprint")
    if artifact.target != AWS_TARGET:
        raise RuntimeError("cached AWS runner has the wrong build target")
    if binary.resolve() != (directory / "experiment-runner").resolve():
        raise RuntimeError("cached AWS runner path escaped its artifact directory")
    if not binary.is_file() or hashlib.sha256(binary.read_bytes()).hexdigest() != artifact.sha256:
        raise RuntimeError("cached AWS runner is missing or has the wrong checksum")
    return artifact


def _aws_build_environment(
    *, git_commit: str, git_dirty: bool, source_fingerprint: str
) -> dict[str, str]:
    missing = [
        command for command in ("cargo", "cargo-zigbuild", "zig") if shutil.which(command) is None
    ]
    if missing:
        raise RuntimeError(
            "AWS runner build requires Rust, cargo-zigbuild, and Zig; missing: "
            + ", ".join(missing)
        )
    environment = os.environ.copy()
    environment.update(
        {
            "SILK_BUILD_GIT_COMMIT": git_commit,
            "SILK_BUILD_GIT_DIRTY": str(git_dirty).lower(),
            "SILK_BUILD_SOURCE_FINGERPRINT": source_fingerprint,
        }
    )
    return environment
