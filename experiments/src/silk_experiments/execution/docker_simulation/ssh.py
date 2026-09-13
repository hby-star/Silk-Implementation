from __future__ import annotations

import shlex
import stat
import subprocess
from pathlib import Path
from typing import Any

from fabric import Connection

from .common import docker_command, ssh_target_from_docker_host
from .network import network_name


def connect(docker_host: str) -> Connection:
    connection = Connection(ssh_target_from_docker_host(docker_host), connect_timeout=10)
    connection.open()
    if connection.transport is not None:
        connection.transport.set_keepalive(15)
    return connection


def run(connection: Connection, command: list[str], check: bool = True) -> Any:
    result = connection.run(shlex.join(command), hide=True, warn=not check, in_stream=False)
    if check and not result.ok:
        raise RuntimeError(
            f"remote host command failed with exit {result.exited}: {result.stderr.strip()}"
        )
    return result


def output(connection: Connection, command: list[str]) -> str:
    return str(run(connection, command).stdout)


def prepare_run_root(connection: Connection, run_id: str) -> str:
    home = connection.sftp().normalize(".").rstrip("/")
    root = f"{home}/silk-experiments/runs/{network_name(run_id)}"
    if not root.startswith(f"{home}/silk-experiments/runs/"):
        raise RuntimeError("remote Docker run root escaped the experiment data directory")
    run(connection, ["test", "!", "-e", root])
    run(connection, ["install", "-d", "-m", "0750", root])
    return root


def upload_bound_file(
    connection: Connection,
    local_path: str,
    remote_path: str,
    expected_sha256: str,
) -> None:
    connection.put(local_path, remote=remote_path)
    actual = output(connection, ["sha256sum", "--", remote_path]).split()
    if not actual or actual[0] != expected_sha256:
        raise RuntimeError("remote file checksum mismatch")


def download_flat(connection: Connection, remote: str, local: Path) -> None:
    local.mkdir(parents=True, exist_ok=False)
    sftp = connection.sftp()
    for entry in sftp.listdir_attr(remote):
        validate_component(entry.filename)
        if not stat.S_ISREG(entry.st_mode):
            raise RuntimeError("remote artifact directory contains an unsupported file type")
        sftp.get(f"{remote}/{entry.filename}", str(local / entry.filename))


def download_tree(connection: Connection, remote: str, local: Path) -> None:
    local.mkdir(parents=True, exist_ok=False)
    sftp = connection.sftp()
    for entry in sftp.listdir_attr(remote):
        validate_component(entry.filename)
        remote_entry = f"{remote}/{entry.filename}"
        local_entry = local / entry.filename
        if stat.S_ISDIR(entry.st_mode):
            download_tree(connection, remote_entry, local_entry)
        elif stat.S_ISREG(entry.st_mode):
            sftp.get(remote_entry, str(local_entry))
        else:
            raise RuntimeError("remote artifact tree contains an unsupported file type")


def remove_run_root(
    connection: Connection,
    remote_root: str,
    image: str,
    docker_host: str,
) -> None:
    subprocess.run(
        docker_command(
            docker_host,
            "run",
            "--rm",
            "--entrypoint",
            "/bin/sh",
            "--mount",
            f"type=bind,source={remote_root},target=/cleanup",
            image,
            "-c",
            "rm -rf -- /cleanup/* /cleanup/.[!.]* /cleanup/..?*",
        ),
        check=True,
    )
    run(connection, ["rmdir", "--", remote_root])


def validate_component(value: str) -> None:
    if not value or value in {".", ".."} or any(separator in value for separator in ("/", "\\")):
        raise RuntimeError("remote artifact contains an unsafe path component")
