from __future__ import annotations

import subprocess
import time

from .common import docker_command


def run_command(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=check,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def wait_container(
    name: str,
    timeout_seconds: int,
    docker_host: str | None,
) -> int:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        state = run_command(
            docker_command(
                docker_host,
                "inspect",
                "--format",
                "{{.State.Running}} {{.State.ExitCode}}",
                name,
            )
        ).stdout.strip()
        running, exit_code = state.split()
        if running == "false":
            return int(exit_code)
        time.sleep(0.5)
    run_command(docker_command(docker_host, "stop", "--time", "5", name), check=False)
    return 124


def release_container(name: str, docker_host: str | None) -> None:
    result = run_command(
        docker_command(docker_host, "exec", name, "touch", "/results/executor-release"),
        check=False,
    )
    if result.returncode:
        # Local containers share the marker directory and can exit together.
        state = run_command(
            docker_command(
                docker_host, "inspect", "--format", "{{.State.Running}} {{.State.ExitCode}}", name
            )
        ).stdout.strip()
        if state != "false 0":
            raise RuntimeError(f"Cannot release {name}: {result.stderr.strip()}")


def wait_protocol_complete(
    name: str,
    node: int,
    timeout_seconds: int,
    docker_host: str | None,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        marker = run_command(
            docker_command(
                docker_host, "exec", name, "test", "-f", f"/results/node-{node}/complete"
            ),
            check=False,
        )
        if marker.returncode == 0:
            return
        state = run_command(
            docker_command(
                docker_host, "inspect", "--format", "{{.State.Running}} {{.State.ExitCode}}", name
            )
        ).stdout.strip()
        running, exit_code = state.split()
        if running == "false":
            raise RuntimeError(
                f"replica {node} exited {exit_code} before its protocol completion marker"
            )
        time.sleep(0.5)
    raise TimeoutError(f"replica {node} did not record protocol completion")
