from pathlib import Path

from .artifacts import (
    BavssSmokeResult,
    BeaconSmokeResult,
    finish_bavss_run,
    finish_beacon_run,
    prepare_bavss_run,
    prepare_beacon_run,
)
from .execution import (
    run_docker_bavss,
    run_docker_nodes,
)
from .execution.aws_remote import run_aws_nodes
from .execution.aws_remote.aggregate import run_aws_bavss
from .execution.inventory import load_inventory
from .planning import BavssSmokePlan, SmokePlan
from .registry import BavssExecutor, BeaconExecutor


def run_beacon_smoke(
    plan: SmokePlan,
    timeout_seconds: int = 180,
) -> BeaconSmokeResult:
    executor = BeaconExecutor.parse(plan.executor)
    inventory = None
    if executor is BeaconExecutor.AWS_REMOTE:
        if plan.inventory_path is None:
            raise ValueError("remote-aws plan does not bind an inventory")
        inventory = load_inventory(Path(plan.inventory_path))

    workspace = prepare_beacon_run(plan)
    if executor is BeaconExecutor.DOCKER:
        captures = run_docker_nodes(plan, workspace, timeout_seconds)
    else:
        assert inventory is not None
        captures = run_aws_nodes(plan, workspace, inventory, timeout_seconds)
    return finish_beacon_run(plan, captures)


def run_bavss_smoke(
    plan: BavssSmokePlan,
    timeout_seconds: int = 180,
) -> BavssSmokeResult:
    prepare_bavss_run(plan)
    executor = BavssExecutor.parse(plan.executor)
    capture = (
        run_aws_bavss(plan, timeout_seconds)
        if executor is BavssExecutor.AWS_AGGREGATE
        else run_docker_bavss(plan, timeout_seconds)
    )
    return finish_bavss_run(plan, capture)


__all__ = ["run_bavss_smoke", "run_beacon_smoke"]
