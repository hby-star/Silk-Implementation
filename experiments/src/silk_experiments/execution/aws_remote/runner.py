from __future__ import annotations

import json
import time
from dataclasses import asdict

from ...planning import SmokePlan
from ...registry import BeaconExecutor
from ..inventory import Inventory
from ..types import BeaconProcessWorkspace, ProcessCapture
from .capture import collect, remove_run_dir, write_environment_snapshot
from .connection import parallel_map, preflight
from .deployment import deploy, launch, stop, wait
from .lifecycle import ensure_idle


def run_aws_nodes(
    plan: SmokePlan,
    workspace: BeaconProcessWorkspace,
    inventory: Inventory,
    timeout_seconds: int,
) -> tuple[ProcessCapture, ...]:
    """Run exactly one native replica process on each AWS instance."""
    if BeaconExecutor.parse(plan.executor) is not BeaconExecutor.AWS_REMOTE:
        raise ValueError("AWS runner requires executor=remote-aws")
    if timeout_seconds <= 0:
        raise ValueError("AWS runner timeout must be positive")
    _verify_inventory_binding(plan, inventory)
    placement = inventory.replica_placement(plan.n)
    endpoints = {
        node: f"{placement[node].endpoint_address}:{inventory.p2p_port}"
        for node in plan.expected_node_ids
    }

    isolation = parallel_map(
        "AWS previous-run isolation",
        placement,
        lambda _node, host: ensure_idle(host, inventory.p2p_port),
    )
    environment = parallel_map("AWS preflight", placement, lambda node, host: preflight(host, node))
    for node in environment:
        environment[node]["pre_run_isolation"] = isolation[node]
    try:
        parallel_map(
            "AWS deployment",
            placement,
            lambda node, host: deploy(plan, host, node),
            max_workers=8,
        )
        write_environment_snapshot(plan, workspace, placement, environment, inventory.p2p_port)
    except Exception as deployment_error:
        try:
            parallel_map(
                "AWS failed-deployment cleanup",
                placement,
                lambda _node, host: remove_run_dir(plan, host),
            )
        except Exception as cleanup_error:
            raise RuntimeError(
                f"{deployment_error}; failed-deployment cleanup also failed: {cleanup_error}"
            ) from deployment_error
        raise
    exit_codes: dict[int, int] = {}
    execution_failure: Exception | None = None
    cleanup_failed = False
    try:
        parallel_map(
            "AWS launch",
            placement,
            lambda node, host: launch(plan, host, node, endpoints, inventory.p2p_port),
            max_workers=len(placement),
        )
        deadline = time.monotonic() + timeout_seconds
        exit_codes = parallel_map(
            "AWS wait",
            placement,
            lambda node, host: wait(plan, host, node, deadline),
            max_workers=len(placement),
        )
    except Exception as error:
        execution_failure = error
    finally:
        try:
            parallel_map(
                "AWS process cleanup",
                placement,
                lambda node, host: stop(plan, host, node),
            )
            parallel_map(
                "AWS post-run isolation",
                placement,
                lambda _node, host: ensure_idle(host, inventory.p2p_port),
            )
        except Exception as cleanup_error:
            cleanup_failed = True
            if execution_failure is None:
                execution_failure = cleanup_error
            else:
                execution_failure = RuntimeError(
                    f"{execution_failure}; process cleanup also failed: {cleanup_error}"
                )

    captures_by_node = collect_nodes(
        plan,
        placement,
        workspace.staged_results,
        exit_codes,
        default_exit=125 if execution_failure is not None else 124,
    )

    # Directory housekeeping cannot invalidate already downloaded, verified evidence.
    # Leave remote copies until final campaign recovery if a node is unreachable.
    def cleanup_directory(node, host):
        if captures_by_node[node].exit_code:
            return
        try:
            remove_run_dir(plan, host)
        except Exception as error:
            print(
                json.dumps(
                    dict(
                        event="run-directory-retained",
                        node=node,
                        run_id=plan.run_id,
                        error=type(error).__name__,
                    )
                ),
                flush=True,
            )

    parallel_map("AWS run-directory cleanup", placement, cleanup_directory)

    captures = tuple(captures_by_node[node] for node in plan.expected_node_ids)
    if execution_failure is not None and (cleanup_failed or any(c.exit_code for c in captures)):
        diagnostic = f"AWS controller error: {execution_failure}\n"
        captures = tuple(
            ProcessCapture(
                capture.node_id,
                capture.exit_code or 125,
                capture.stdout,
                diagnostic + capture.stderr,
            )
            for capture in captures
        )
    return captures


def collect_nodes(plan, placement, staged_results, exit_codes, *, default_exit=125):
    """Checkpoint successful nodes, then recollect only missing nodes; never rerun a protocol."""
    captures, errors = {}, {}
    for sweep in range(3):
        pending = {node: host for node, host in placement.items() if node not in captures}
        if not pending:
            break
        if sweep:
            time.sleep(20 * sweep)

        def fetch(node, host):
            try:
                capture = collect(
                    plan, host, node, staged_results, exit_codes.get(node, default_exit)
                )
                receipt = staged_results / f"node-{node}" / "capture.json"
                partial = receipt.with_suffix(".partial")
                partial.write_text(json.dumps(asdict(capture)), encoding="utf-8")
                partial.replace(receipt)
                return capture, None
            except Exception as download_error:
                return None, type(download_error).__name__

        fetched = parallel_map("AWS artifact collection", pending, fetch, max_workers=8)
        for node, (capture, error) in fetched.items():
            if capture is not None:
                captures[node] = capture
                errors.pop(node, None)
            else:
                errors[node] = error
        status = staged_results / "collection-status.json"
        partial = status.with_suffix(".partial")
        partial.write_text(
            json.dumps(
                dict(run_id=plan.run_id, sweep=sweep, collected=sorted(captures), missing=errors)
            ),
            encoding="utf-8",
        )
        partial.replace(status)
    # Preserve all downloaded evidence and let the normal validator mark this
    # sample incomplete. A missing log is never treated as a successful replica.
    for node, error in errors.items():
        captures[node] = ProcessCapture(node, 125, "", f"artifact unavailable: {error}\n")
    return captures


def _verify_inventory_binding(plan: SmokePlan, inventory: Inventory) -> None:
    if str(inventory.path) != plan.inventory_path or inventory.sha256 != plan.inventory_sha256:
        raise RuntimeError("AWS inventory path or checksum differs from the bound run plan")
    placement = inventory.replica_placement(plan.n)
    aliases = tuple(placement[node].alias for node in plan.expected_node_ids)
    regions = tuple(placement[node].region for node in plan.expected_node_ids)
    if aliases != plan.placement_aliases or regions != plan.placement_regions:
        raise RuntimeError("AWS inventory placement differs from the bound run plan")
