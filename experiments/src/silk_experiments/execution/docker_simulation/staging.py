from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from fabric import Connection

from ...planning import SmokePlan
from ..types import BeaconProcessWorkspace
from .common import docker_command
from .ssh import connect, download_flat, prepare_run_root, remove_run_root, run, upload_bound_file


@dataclass(frozen=True)
class NodeMounts:
    definition: str
    results: str
    state: str


class DockerStaging:
    """Resolve bind mounts locally or on an SSH Docker host."""

    def __init__(self, plan: SmokePlan, workspace: BeaconProcessWorkspace) -> None:
        self.plan = plan
        self.workspace = workspace
        self.connection: Connection | None = None
        self.remote_root = ""
        self.definition = str(Path(plan.definition_path).resolve())
        if plan.docker_host is not None:
            try:
                self._open_remote(plan.docker_host)
            except Exception:
                self.close()
                raise

    @property
    def remote(self) -> bool:
        return self.connection is not None

    def mounts(self, node: int) -> NodeMounts:
        if self.connection is None:
            local_state = self.workspace.stores / f"node-{node:04}"
            local_state.mkdir()
            return NodeMounts(
                self.definition,
                str(self.workspace.staged_results.resolve()),
                str(local_state.resolve()),
            )
        results = f"{self.remote_root}/node-{node:04}-results"
        remote_state = f"{self.remote_root}/node-{node:04}-state"
        run(self.connection, ["install", "-d", "-m", "0750", results, remote_state])
        return NodeMounts(self.definition, results, remote_state)

    def collect_node(self, node: int) -> None:
        if self.connection is None:
            return
        remote = f"{self.remote_root}/node-{node:04}-results/node-{node}"
        local = self.workspace.staged_results / f"node-{node}"
        download_flat(self.connection, remote, local)

    def persist_diagnostics(self, names: dict[int, str], docker_host: str | None) -> None:
        if self.connection is None or not names:
            return
        diagnostics = f"{self.remote_root}/container-diagnostics"
        run(self.connection, ["install", "-d", "-m", "0750", diagnostics])
        sftp = self.connection.sftp()
        for node, name in sorted(names.items()):
            for suffix, arguments in (
                ("state.json", ("inspect", "--format", "{{json .State}}", name)),
                ("stdout.log", ("logs", name)),
            ):
                result = subprocess.run(
                    docker_command(docker_host, *arguments),
                    check=False,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )
                value = result.stdout if suffix != "stdout.log" else result.stdout + result.stderr
                with sftp.file(f"{diagnostics}/node-{node:04}.{suffix}", "w") as handle:
                    handle.write(value)

    def remove_remote_root(self, image: str, docker_host: str | None) -> None:
        if self.connection is None:
            return
        if docker_host is None:
            raise ValueError("remote staging requires an SSH Docker host")
        remove_run_root(self.connection, self.remote_root, image, docker_host)

    def close(self) -> None:
        if self.connection is not None:
            self.connection.close()

    def _open_remote(self, docker_host: str) -> None:
        connection = connect(docker_host)
        self.connection = connection
        root = prepare_run_root(connection, self.plan.run_id)
        self.remote_root = root
        self.definition = f"{root}/experiment.toml"
        upload_bound_file(
            connection,
            self.plan.definition_path,
            self.definition,
            self.plan.definition_sha256,
        )
