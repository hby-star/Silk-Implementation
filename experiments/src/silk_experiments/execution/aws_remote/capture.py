from __future__ import annotations

import json
from pathlib import Path, PurePosixPath

from ...planning import SmokePlan
from ...registry import BeaconExecutor
from ..inventory import Host
from ..types import BeaconProcessWorkspace, ProcessCapture
from .connection import connect, retry_transport, run, run_dir
from .constants import AWS_NODE_PORT
from .lifecycle import download_tree, retry_read


def collect(
    plan: SmokePlan,
    host: Host,
    node: int,
    staged_results: Path,
    exit_code: int,
) -> ProcessCapture:
    remote_root = run_dir(host, plan.run_id)
    remote_node = f"{remote_root}/results/node-{node}"
    local_node = staged_results / f"node-{node}"
    local_node.mkdir(parents=True, exist_ok=True)

    def attempt() -> ProcessCapture:
        with connect(host) as connection:
            status = run(connection, ["cat", f"{remote_root}/node.exit"], check=False)
            actual_exit = (
                int(status.stdout.strip())
                if status.ok and status.stdout.strip().lstrip("-").isdigit()
                else exit_code
            )
            log = run(connection, ["cat", f"{remote_root}/node.log"], check=False)
            stdout, stderr = str(log.stdout), str(log.stderr)
            (local_node / "process.stdout.log").write_text(stdout, encoding="utf-8")
            (local_node / "process.stderr.log").write_text(stderr, encoding="utf-8")
            exists = run(connection, ["test", "-d", remote_node], check=False)
            if exists.ok:
                download_tree(connection, remote_node, local_node)
        return ProcessCapture(node, actual_exit, stdout, stderr)

    return retry_read(attempt)


@retry_transport
def remove_run_dir(plan: SmokePlan, host: Host) -> None:
    target = PurePosixPath(run_dir(host, plan.run_id))
    base = PurePosixPath(host.data_dir)
    if target.parent != base or target.name != plan.run_id:
        raise RuntimeError("AWS cleanup target escaped the inventory data_dir")
    with connect(host) as connection:
        run(connection, ["rm", "-rf", "--", str(target)])


def write_environment_snapshot(
    plan: SmokePlan,
    workspace: BeaconProcessWorkspace,
    placement: dict[int, Host],
    environment: dict[int, dict[str, object]],
    node_port: int = AWS_NODE_PORT,
) -> None:
    deployment = workspace.staged_results / "aws-deployment.json"
    value = {
        "schema_id": "silk-aws-deployment/v1",
        "run_id": plan.run_id,
        "inventory_sha256": plan.inventory_sha256,
        "network_scenario": BeaconExecutor.AWS_REMOTE.network_scenario,
        "resource_profile": BeaconExecutor.AWS_REMOTE.resource_profile,
        "one_instance_per_node": True,
        "node_port": node_port,
        "placement": [
            {
                **environment[node],
                "endpoint_address": placement[node].endpoint_address,
            }
            for node in plan.expected_node_ids
        ],
    }
    deployment.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _validate_component(value: str) -> None:
    if not value or value in {".", ".."} or any(separator in value for separator in ("/", "\\")):
        raise RuntimeError("AWS artifact contains an unsafe path component")
