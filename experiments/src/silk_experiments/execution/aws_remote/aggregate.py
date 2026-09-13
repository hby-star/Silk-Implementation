from __future__ import annotations

import json
import time
from pathlib import Path
from typing import cast

from ...config import load_definition
from ...planning import BavssSmokePlan, SmokePlan
from ..inventory import load_inventory
from ..types import BavssProcessCapture
from .capture import remove_run_dir
from .connection import connect, preflight, run, run_dir
from .deployment import deploy, launch_process, stop, wait
from .lifecycle import download_tree, ensure_idle, retry_read


def run_aws_bavss(plan: BavssSmokePlan, timeout_seconds: int) -> BavssProcessCapture:
    if plan.executor != "aws-aggregate" or not plan.inventory_path:
        raise ValueError("native AWS aggregate plan required")
    inventory = load_inventory(plan.inventory_path)
    if inventory.sha256 != plan.inventory_sha256:
        raise RuntimeError("AWS aggregate inventory changed")
    definition = load_definition(plan.definition_path)
    if definition.sha256 != plan.definition_sha256:
        raise RuntimeError("AWS aggregate definition changed")
    host = inventory.replica_placement(1)[0]
    isolation = ensure_idle(host, inventory.p2p_port)
    environment = preflight(host, 0)
    environment["pre_run_isolation"] = isolation
    environment["inventory_sha256"] = inventory.sha256
    environment["resource_profile"] = "aws-t3a-medium-aggregate-v1"
    (Path(plan.state_run) / "aws-environment.json").write_text(
        json.dumps(environment, indent=2) + "\n", encoding="utf-8"
    )
    shared_plan = cast(SmokePlan, plan)  # deployment uses only shared source/run fields
    deploy(shared_plan, host, 0)
    root = run_dir(host, plan.run_id)
    command = [
        "./experiment-runner",
        "run",
        "--config",
        "experiment.toml",
        "--run-id",
        plan.run_id,
        "--output",
        "results",
        "--n",
        str(plan.n),
        "--t",
        str(plan.t),
        "--slots",
        str(plan.batch_size),
        "--samples",
        str(plan.samples),
        "--seed",
        str(plan.seed),
    ]
    env = {
        "SILK_SAMPLE_ROLE": plan.sample_role,
        "SILK_EXECUTOR": plan.executor,
        "SILK_RESOURCE_PROFILE": "aws-t3a-medium-aggregate-v1",
        "SILK_INVENTORY_SHA256": inventory.sha256,
        "SILK_PLACEMENT_JSON": json.dumps({str(i): host.alias for i in range(plan.n)}),
    }
    try:
        launch_process(host, plan.run_id, command, env)
        exit_code = wait(shared_plan, host, 0, time.monotonic() + timeout_seconds)
    finally:
        stop(shared_plan, host, 0)
        ensure_idle(host, inventory.p2p_port)

    def collect() -> BavssProcessCapture:
        with connect(host) as connection:
            log = run(connection, ["cat", f"{root}/node.log"], check=False)
            (Path(plan.state_run) / "downloaded.stdout.log").write_text(
                log.stdout, encoding="utf-8"
            )
            download_tree(connection, f"{root}/results/{plan.run_id}", Path(plan.raw_run))
        return BavssProcessCapture(exit_code, log.stdout, log.stderr)

    capture = retry_read(collect)
    if exit_code == 0:
        remove_run_dir(shared_plan, host)
    return capture
