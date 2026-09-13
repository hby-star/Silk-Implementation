from __future__ import annotations

import json
import subprocess
from pathlib import Path

from ...paths import workspace_paths
from ...provenance import SourceIdentity, image_provenance_labels, source_identity
from .common import docker_command
from .constants import DEFAULT_IMAGE


def image_runner(image: str, docker_host: str | None = None) -> Path:
    digest = image_id(image, docker_host).removeprefix("sha256:")
    binary = workspace_paths().output_root / "build" / "docker-runner" / digest / "experiment-runner"
    binary.parent.mkdir(parents=True, exist_ok=True)
    container = subprocess.check_output(
        docker_command(docker_host, "create", "--entrypoint", "/bin/true", image), text=True
    ).strip()
    try:
        subprocess.run(
            docker_command(docker_host, "cp", f"{container}:/usr/local/bin/experiment-runner", str(binary)),
            check=True,
        )
    finally:
        subprocess.run(docker_command(docker_host, "rm", container), check=True, capture_output=True)
    return binary


def build_image(image: str = DEFAULT_IMAGE, docker_host: str | None = None) -> str:
    code_root = workspace_paths().code_root
    identity = source_identity(code_root)
    subprocess.run(
        docker_command(
            docker_host,
            "build",
            "--file",
            "experiments/docker/Dockerfile",
            "--tag",
            image,
            "--build-arg",
            f"SILK_BUILD_GIT_COMMIT={identity.git_commit}",
            "--build-arg",
            f"SILK_BUILD_GIT_DIRTY={str(identity.git_dirty).lower()}",
            "--build-arg",
            f"SILK_BUILD_SOURCE_FINGERPRINT={identity.source_fingerprint}",
            ".",
        ),
        cwd=code_root,
        check=True,
    )
    return image_id(image, docker_host)


def image_id(
    image: str = DEFAULT_IMAGE,
    docker_host: str | None = None,
    expected_source: SourceIdentity | None = None,
) -> str:
    value = _inspect(image, docker_host, "{{.Id}}")
    if not value.startswith("sha256:"):
        raise RuntimeError(f"docker returned an invalid image ID for {image}: {value!r}")
    verify_image_source(image, docker_host, expected_source)
    return value


def verify_image_source(
    image: str,
    docker_host: str | None,
    expected_source: SourceIdentity | None = None,
) -> None:
    identity = expected_source or source_identity(workspace_paths().code_root)
    try:
        labels = json.loads(_inspect(image, docker_host, "{{json .Config.Labels}}"))
    except json.JSONDecodeError as error:
        raise RuntimeError("Docker image has invalid build provenance labels") from error
    expected = image_provenance_labels(identity)
    if not isinstance(labels, dict) or any(
        labels.get(key) != value for key, value in expected.items()
    ):
        actual = {key: labels.get(key) if isinstance(labels, dict) else None for key in expected}
        raise RuntimeError(
            "Docker image source provenance does not match the bound code tree: "
            f"expected={expected}, actual={actual}"
        )


def _inspect(image: str, docker_host: str | None, template: str) -> str:
    result = subprocess.run(
        docker_command(docker_host, "image", "inspect", "--format", template, image),
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return result.stdout.strip()
