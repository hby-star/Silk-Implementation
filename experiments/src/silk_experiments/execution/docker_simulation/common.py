from __future__ import annotations

import os


def docker_command(docker_host: str | None, *arguments: str) -> list[str]:
    command = ["docker"]
    if docker_host is not None:
        endpoint = docker_host
        if docker_host == os.environ.get("SILK_DOCKER_TUNNEL_FOR"):
            ssh_target_from_docker_host(docker_host)
            port = int(os.environ["SILK_DOCKER_TUNNEL_PORT"])
            if not 1 <= port <= 65535:
                raise ValueError("Docker SSH tunnel port must be between 1 and 65535")
            endpoint = f"tcp://127.0.0.1:{port}"
        command.extend(["--host", endpoint])
    command.extend(arguments)
    return command


def ssh_target_from_docker_host(docker_host: str | None) -> str:
    if docker_host is None or not docker_host.startswith("ssh://"):
        raise ValueError("operation requires an ssh:// Docker host")
    ssh_target = docker_host.removeprefix("ssh://").rstrip("/")
    if not ssh_target or "/" in ssh_target or any(character.isspace() for character in ssh_target):
        raise ValueError("remote Docker host must identify one SSH target")
    return ssh_target


def format_number(value: int | float) -> str:
    return format(value, "g")
