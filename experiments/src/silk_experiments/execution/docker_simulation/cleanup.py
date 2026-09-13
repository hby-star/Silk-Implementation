from __future__ import annotations

import subprocess
import time

from .common import docker_command
from .constants import MANAGED_LABEL, RUN_LABEL_KEY, STRICT_CLEANUP_TIMEOUT_SECONDS


def cleanup_managed_docker_resources(
    run_id: str | None = None,
    timeout_seconds: float = STRICT_CLEANUP_TIMEOUT_SECONDS,
    docker_host: str | None = None,
) -> None:
    if timeout_seconds <= 0:
        raise ValueError("Docker cleanup timeout must be positive")
    labels = [MANAGED_LABEL, *([f"{RUN_LABEL_KEY}={run_id}"] if run_id else [])]
    deadline = time.monotonic() + timeout_seconds
    errors: list[str] = []
    while True:
        containers = _resource_ids("container", labels, docker_host)
        networks = _resource_ids("network", labels, docker_host)
        if containers:
            result = _remove(docker_command(docker_host, "rm", "--force"), containers)
            if result.returncode:
                errors.append(result.stderr.strip())
        if networks:
            result = _remove(docker_command(docker_host, "network", "rm"), networks)
            if result.returncode:
                errors.append(result.stderr.strip())
        remaining = (
            _resource_ids("container", labels, docker_host),
            _resource_ids("network", labels, docker_host),
        )
        if not any(remaining):
            return
        if time.monotonic() >= deadline:
            detail = "; ".join(error for error in errors if error)
            raise RuntimeError(
                "Docker cleanup did not terminate all labelled resources: "
                f"containers={remaining[0]}, networks={remaining[1]}"
                + (f"; errors={detail}" if detail else "")
            )
        time.sleep(0.2)


def _resource_ids(kind: str, labels: list[str], docker_host: str | None) -> tuple[str, ...]:
    command = docker_command(
        docker_host,
        *(
            ("container", "ls", "--all", "--quiet")
            if kind == "container"
            else ("network", "ls", "--quiet")
        ),
    )
    if kind not in {"container", "network"}:
        raise ValueError(f"unsupported Docker resource kind: {kind}")
    for label in labels:
        command.extend(["--filter", f"label={label}"])
    result = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return tuple(filter(None, result.stdout.splitlines()))


def _remove(command: list[str], resource_ids: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [*command, *resource_ids],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
