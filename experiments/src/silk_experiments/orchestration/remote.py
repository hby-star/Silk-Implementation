from __future__ import annotations

from pathlib import Path

from ..execution.aws_remote import ensure_aws_runner
from ..execution.inventory import load_inventory
from ..paths import workspace_paths
from ..planning import SmokePlan, build_beacon_matrix_plans, build_beacon_smoke_plan
from ..registry import BeaconExecutor
from .common import (
    default_collection_path,
    experiments_root,
    generated_run_name,
    materialize_and_run,
    validate_suite_request,
)
from .model import SuiteResult


def run_remote_suite(
    *,
    inventory: Path,
    mode: str = "smoke",
    implementation: str = "silk-beacon",
    definition: Path | None = None,
    run_name: str | None = None,
    collection: Path | None = None,
    binary: Path | None = None,
    rebuild: bool = False,
    execute: bool = True,
    timeout_seconds: int = 1_800,
) -> SuiteResult:
    definition_path = (
        definition or experiments_root() / "definitions" / "aws" / "beacon-performance.toml"
    ).resolve()
    definition_value = validate_suite_request(
        definition_path=definition_path,
        executor=BeaconExecutor.AWS_REMOTE,
        mode=mode,
        timeout_seconds=timeout_seconds,
    )
    inventory_path = inventory.resolve()
    inventory_value = load_inventory(inventory_path)
    required_nodes = (
        definition_value.smoke.n
        if mode == "smoke"
        else max(cell.n for cell in definition_value.matrix.cells)
    )
    inventory_value.replica_placement(required_nodes)

    selected_name = run_name or generated_run_name("remote", mode)
    selected_binary = binary
    if selected_binary is None:
        artifact = ensure_aws_runner(
            workspace_paths().output_root / "build" / "aws-runner",
            rebuild=rebuild,
        )
        selected_binary = Path(artifact.binary_path)
    selected_binary = selected_binary.resolve()

    plans: tuple[SmokePlan, ...]
    if mode == "smoke":
        plan = build_beacon_smoke_plan(
            definition_path,
            selected_name,
            implementation,
            binary_path=selected_binary,
            executor=BeaconExecutor.AWS_REMOTE.value,
            inventory_path=inventory_path,
        )
        plans = (plan,)
        collection_path = None
    elif mode == "matrix":
        plans = build_beacon_matrix_plans(
            definition_path,
            selected_name,
            binary_path=selected_binary,
            implementation=implementation or None,
            inventory_path=inventory_path,
        )
        collection_path = (collection or default_collection_path(selected_name)).resolve()
    return materialize_and_run(
        environment="remote",
        mode=mode,
        plans=plans,
        timeout_seconds=timeout_seconds,
        execute=execute,
        collection_path=collection_path,
    )
