"""Run the approved native AWS matrices, then terminate every campaign instance."""

from __future__ import annotations

import json
import shlex
import time
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ...planning import (
    build_bavss_matrix_plans,
    load_bavss_smoke_plan,
    save_bavss_smoke_plan,
)
from ...provenance import source_identity
from ...workflows import run_bavss_smoke
from ..inventory import Host
from .connection import close_gateways, connect, parallel_map, pooled_connections, retry_transport
from .fleet import Fleet, aws
from .lifecycle import download_tree


def emit(event: str, **details: object) -> None:
    print(
        json.dumps({"event": event, "utc": datetime.now(timezone.utc).isoformat(), **details}),
        flush=True,
    )


def checkpoint_collection(path: Path, plans: tuple) -> None:
    partial = path.with_suffix(path.suffix + ".partial")
    partial.write_text(
        json.dumps(
            dict(schema_id="silk-plan-collection/v1", plans=[asdict(p) for p in plans]), indent=2
        ),
        encoding="utf-8",
    )
    partial.replace(path)


def inventory_file(state: Path, label: str, hosts: list[Host]) -> Path:
    path = state / f"inventory.{label}.private.yaml"
    value = {"schema_version": 1, "p2p_port": 9000, "hosts": [asdict(h) for h in hosts]}
    # JSON is valid YAML; roles tuples serialize as lists.
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    return path


def arm_watchdogs(hosts: list[Host]) -> None:
    scoped = {host.instance_id: host for host in hosts}
    scoped.update(
        {host.ssh_gateway.instance_id: host.ssh_gateway for host in hosts if host.ssh_gateway}
    )

    @retry_transport
    def arm(_i: int, host: Host) -> None:
        with connect(host) as connection:
            connection.run(
                "sudo shutdown -c; sudo shutdown -P +180", hide=True, in_stream=False, timeout=15
            )

    parallel_map("instance lifetime backstop", dict(enumerate(scoped.values())), arm)


def telemetry(fleet: Fleet, label: str) -> None:
    observations = {}
    for region in fleet.regions:
        ids = [i["InstanceId"] for i in fleet.data["instances"] if i["Region"] == region]
        if not ids:
            continue
        try:
            observations[region] = aws(
                region, "ec2", "describe-instance-credit-specifications", InstanceIds=ids
            )
            queries = []
            for node, identity in enumerate(ids):
                for metric in (
                    "CPUCreditBalance",
                    "CPUSurplusCreditBalance",
                    "CPUSurplusCreditsCharged",
                    "CPUUtilization",
                ):
                    queries.append(
                        {
                            "Id": f"m{node}_{metric.lower()}",
                            "MetricStat": {
                                "Metric": {
                                    "Namespace": "AWS/EC2",
                                    "MetricName": metric,
                                    "Dimensions": [{"Name": "InstanceId", "Value": identity}],
                                },
                                "Period": 300,
                                "Stat": "Average",
                            },
                            "ReturnData": True,
                        }
                    )
            now = datetime.now(timezone.utc)
            observations[region]["cloudwatch"] = aws(
                region,
                "cloudwatch",
                "get-metric-data",
                MetricDataQueries=queries,
                StartTime=(now - timedelta(hours=3)).isoformat(),
                EndTime=now.isoformat(),
            )
        except Exception as error:
            observations[region] = {"error": type(error).__name__}
    (fleet.state / f"credits-{label}.private.json").write_text(
        json.dumps(observations, indent=2) + "\n", encoding="utf-8"
    )


def recover_evidence(fleet: Fleet) -> None:
    """Best-effort recovery before termination; record hosts whose evidence is unavailable."""
    failures = []
    hosts = [
        fleet.host(i)
        for i in fleet.data["instances"]
        if i.get("PublicIpAddress") and i["State"]["Name"] == "running"
    ]

    def recover(_i: int, host: Host) -> None:
        try:
            with connect(host) as connection:
                for entry in connection.sftp().listdir_attr(host.data_dir):
                    if not entry.filename.startswith(fleet.campaign):
                        continue
                    root = host.data_dir + "/" + entry.filename
                    local = fleet.state / "recovery" / host.instance_id / entry.filename
                    exists = connection.run(
                        shlex.join(["test", "-d", root + "/results"]),
                        hide=True,
                        warn=True,
                        in_stream=False,
                        timeout=15,
                    )
                    if exists.ok:
                        download_tree(connection, root + "/results", local / "results")
                    local.mkdir(parents=True, exist_ok=True)
                    for name in ["node.log", "node.exit", "node.pid"]:
                        result = connection.run(
                            shlex.join(["cat", root + "/" + name]),
                            hide=True,
                            warn=True,
                            in_stream=False,
                            timeout=15,
                        )
                        if result.ok:
                            (local / name).write_text(result.stdout, encoding="utf-8")
        except Exception as error:
            failures.append({"instance": host.instance_id, "error": type(error).__name__})

    parallel_map("final evidence recovery", dict(enumerate(hosts)), recover) if hosts else None
    (fleet.state / "recovery-status.private.json").write_text(
        json.dumps({"failures": failures}, indent=2) + "\n", encoding="utf-8"
    )


@pooled_connections()
def run_matrix_a(
    fleet: Fleet,
    definitions: Path,
    binary: Path,
    a_nodes: list[int] | None = None,
) -> None:
    results = []
    path = fleet.state / "results.json"
    if path.exists():
        raise RuntimeError("results already exist; resume requires explicit reconciliation")

    def record(result: object) -> None:
        item = asdict(result)
        results.append(item)
        path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
        emit("run-complete", run_id=item["run_id"], valid=item["run_valid"])
        if not item["run_valid"]:
            raise RuntimeError("invalid run; retain evidence and diagnose before retry")

    # Check source identity before starting anything billable.
    identity = source_identity(definitions.parents[2])
    if identity.git_dirty:
        raise RuntimeError("AWS measured campaign requires clean source snapshot")
    try:
        emit("provision-a", instances=1)
        region = fleet.regions[0]
        fleet.ensure_capacity({region: 1})
        hosts = fleet.ready_hosts({region: 1})
        host = next(h for h in hosts if h.region == region)
        inventory = inventory_file(fleet.state, "a", [host])
        arm_watchdogs([host])
        plans = build_bavss_matrix_plans(
            definitions / "bavss-phase-cost.toml",
            fleet.campaign + "-a",
            binary,
            inventory_path=inventory,
        )
        completed = []
        for plan in plans:
            if a_nodes is not None and plan.n not in a_nodes:
                continue
            emit("run-start", matrix="A", n=plan.n, run_id=plan.run_id)
            record(run_bavss_smoke(load_bavss_smoke_plan(save_bavss_smoke_plan(plan)), 1800))
            completed.append(plan)
            checkpoint_collection(fleet.state / "matrix-a.json", tuple(completed))
        checkpoint_collection(
            fleet.state / "matrix-a.json",
            tuple(p for p in plans if a_nodes is None or p.n in a_nodes),
        )
        telemetry(fleet, "after-a")

    finally:
        emit("evidence-recovery-start")
        try:
            recover_evidence(fleet)
        except Exception as recovery_error:
            emit("evidence-recovery-error", error=type(recovery_error).__name__)
        try:
            close_gateways()
        except Exception as gateway_error:
            emit("ssh-gateway-close-error", error=type(gateway_error).__name__)
        emit("cleanup-start")
        cleanup_error = None
        for attempt in range(3):
            try:
                fleet.terminate_all()
                cleanup_error = None
                break
            except Exception as error:
                cleanup_error = error
                emit("cleanup-retry", attempt=attempt + 1, error=type(error).__name__)
                time.sleep(5)
        if cleanup_error:
            raise RuntimeError(
                "AWS cleanup incomplete; immediate follow-up required"
            ) from cleanup_error
        emit("cleanup-complete", live_instances=0)
