"""Matrix B only: provision, qualify, run, collect, and always reclaim AWS resources."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml

from ..config import load_definition
from ..execution.aws_remote import ensure_aws_runner
from ..execution.aws_remote.campaign import (
    arm_watchdogs,
    checkpoint_collection,
    emit,
    inventory_file,
    recover_evidence,
    telemetry,
)
from ..execution.aws_remote.connection import close_gateways, parallel_map, pooled_connections
from ..execution.aws_remote.discovery import discover_networks
from ..execution.aws_remote.fleet import Fleet
from ..execution.aws_remote.lifecycle import ensure_idle
from ..execution.aws_remote.mesh import qualify_mesh
from ..paths import workspace_paths
from ..planning import _build_beacon_plan, load_smoke_plan, save_smoke_plan
from ..provenance import source_identity
from ..registry import BeaconExecutor
from ..workflows import run_beacon_smoke
from .common import experiments_root, validate_suite_request


@dataclass(frozen=True)
class ManagedRemoteResult:
    campaign: str
    state_path: str
    executed: bool
    nodes: tuple[int, ...]
    protocols: tuple[str, ...]
    candidate_limits: dict[str, int]
    measured_runs: int
    cleanup_verified: bool


def _csv(value: str) -> tuple[str, ...]:
    result = tuple(v.strip() for v in value.split(","))
    if not all(result) or len(set(result)) != len(result):
        raise ValueError("comma-separated selection must be nonempty and unique")
    return result


def regional_counts(n: int, regions: list[str], spares: bool = False) -> dict[str, int]:
    required = {r: n // len(regions) + int(i < n % len(regions)) for i, r in enumerate(regions)}
    if not spares:
        return required
    total_spares = 40 if n > 91 else 32 if n >= 61 else 24
    active = [r for r in regions if required[r]]
    extra = {
        r: total_spares // len(active) + int(i < total_spares % len(active))
        for i, r in enumerate(active)
    }
    return {r: count + extra.get(r, 0) for r, count in required.items()}


def _save(path: Path, value: object) -> None:
    partial = path.with_suffix(path.suffix + ".partial")
    partial.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    partial.replace(path)


def _cleanup(fleet: Fleet) -> None:
    try:
        recover_evidence(fleet)
    except Exception as error:
        emit("evidence-recovery-error", error=type(error).__name__)
    finally:
        try:
            close_gateways()
        finally:
            for attempt in range(3):
                try:
                    fleet.terminate_all()
                    emit("cleanup-complete", live_instances=0, volumes=0, security_groups=0)
                    break
                except Exception:
                    emit("cleanup-retry", attempt=attempt + 1)
                    if attempt == 2:
                        raise
                    time.sleep(5)


def cleanup_managed_remote(*, state: Path) -> ManagedRemoteResult:
    state = state.resolve()
    request = json.loads((state / "request.json").read_text(encoding="utf-8"))
    fleet = Fleet(
        state / "settings.private.yaml",
        state / "discovery",
        state,
        request["campaign"],
        capacity_limits=request["candidate_limits"],
    )
    _cleanup(fleet)
    return ManagedRemoteResult(
        request["campaign"],
        str(state),
        True,
        tuple(request["nodes"]),
        tuple(request["protocols"]),
        request["candidate_limits"],
        0,
        True,
    )


@pooled_connections()
def run_managed_remote(
    *,
    settings: Path,
    nodes: str = "7,16,31,61,91,121",
    protocols: str = "silk-beacon,rondo-beacon,spurt-beacon",
    definition: Path | None = None,
    run_name: str | None = None,
    state: Path | None = None,
    binary: Path | None = None,
    rebuild: bool = False,
    execute: bool = True,
    timeout_seconds: int = 3600,
    source_snapshot: Path | None = None,
    retries: int = 0,
    binary_provenance: Path | None = None,
    completed_collection: Path | None = None,
) -> ManagedRemoteResult:
    if not 0 <= retries <= 2:
        raise ValueError("retries must be between 0 and 2")
    definition_path = (
        definition or experiments_root() / "definitions/aws/beacon-performance.toml"
    ).resolve()
    value = validate_suite_request(
        definition_path=definition_path,
        executor=BeaconExecutor.AWS_REMOTE,
        mode="matrix",
        timeout_seconds=timeout_seconds,
    )
    selected_nodes = tuple(int(n) for n in _csv(nodes))
    selected_protocols = _csv(protocols)
    cells = {c.n: (i, c) for i, c in enumerate(value.matrix.cells)}
    if len(cells) != len(value.matrix.cells):
        raise ValueError("managed Matrix B requires one batch-size cell per node count")
    if any(n not in cells for n in selected_nodes):
        raise ValueError("nodes must name declared Matrix B cells")
    if set(selected_protocols) - set(value.matrix.implementations):
        raise ValueError("protocols must be enabled by the Matrix B definition")
    matrix = value.matrix
    completed = set()
    if completed_collection is not None:
        for prior in json.loads(completed_collection.read_text(encoding="utf-8"))["plans"]:
            if (
                prior["n"] not in selected_nodes
                or prior["implementation"] not in selected_protocols
            ):
                continue
            processed = Path(prior["processed_run"])
            result = json.loads((processed / "smoke-execution.json").read_text(encoding="utf-8"))
            with (processed / "run-results.csv").open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            if (
                not result["run_valid"]
                or result["missing_node_ids"]
                or len(rows) != 1
                or int(rows[0]["output_count"]) != matrix.outputs_per_run
                or int(rows[0]["valid_node_count"]) != prior["n"]
                or prior["definition_sha256"] != value.sha256
            ):
                raise ValueError("completed collection contains an invalid or incompatible sample")
            completed.add((prior["n"], prior["implementation"], prior["seed"]))
    if (
        matrix.warmup_runs
        or matrix.measured_runs < 1
        or not matrix.outputs_per_run
        or any(matrix.outputs_per_run % cells[n][1].batch_size for n in selected_nodes)
    ):
        raise ValueError("managed Matrix B requires fixed measured runs and whole batches")
    if (
        matrix.resources.cpu_cores_per_node != 2
        or matrix.resources.memory_mib_per_node != 4096
        or matrix.resources.one_container_per_node
    ):
        raise ValueError("managed AWS hardware requires native 2 vCPU / 4096 MiB definition")
    config = yaml.safe_load(settings.read_text(encoding="utf-8"))
    instances = config["instances"]
    if (
        instances["type"] != "t3a.medium"
        or instances["volume_gb"] != 24
        or config["port"]["p2p"] != 9000
    ):
        raise ValueError("managed AWS supports t3a.medium, 24 GiB, TCP 9000")
    regions = instances["regions"]
    if (
        not isinstance(regions, list)
        or not 1 <= len(regions) <= 8
        or len(set(regions)) != len(regions)
        or any(not re.fullmatch(r"[a-z]{2}-[a-z]+-\d", r) for r in regions)
    ):
        raise ValueError("settings require 1–8 unique ordered AWS regions")
    key = Path(config["key"]["path"]).expanduser().resolve()
    if not key.is_file() or not config["key"]["name"]:
        raise ValueError("AWS SSH key must exist and have a regional key-pair name")
    config["key"]["path"] = str(key)
    limits = regional_counts(max(selected_nodes), regions, spares=True)
    if sum(limits.values()) > 200:
        raise ValueError("candidate budget exceeds 200 peer-rule capacity")
    campaign = run_name or "silk-aws-b-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    if not re.fullmatch(r"silk-aws-[a-z0-9-]+", campaign):
        raise ValueError("run_name must match silk-aws-[a-z0-9-]+")
    state_path = (state or workspace_paths().output_root / "build" / campaign).resolve()
    if state_path.exists():
        raise ValueError(
            "state already exists; reconcile or use remote-cleanup before a new campaign"
        )
    request = dict(
        campaign=campaign,
        nodes=selected_nodes,
        protocols=selected_protocols,
        candidate_limits=limits,
        region_order=regions,
        matrix="B",
        capacity_samples=0,
        measured_runs_per_cell=matrix.measured_runs,
        measured_outputs=matrix.outputs_per_run,
        failed_sample_retries=retries,
        skipped_completed_samples=len(completed),
        definition_sha256=hashlib.sha256(definition_path.read_bytes()).hexdigest(),
    )
    if not execute:
        emit("managed-matrix-b-plan", **request)
        return ManagedRemoteResult(
            campaign, str(state_path), False, selected_nodes, selected_protocols, limits, 0, False
        )
    identity = source_identity(workspace_paths().code_root)
    if source_snapshot is not None:
        if json.loads(source_snapshot.read_text(encoding="utf-8")) != asdict(identity):
            raise RuntimeError("controller differs from the frozen source snapshot")
    elif identity.git_dirty:
        raise RuntimeError("AWS measured campaign requires clean source snapshot")
    if binary is None:
        binary = Path(
            ensure_aws_runner(
                workspace_paths().output_root / "build/aws-runner", rebuild=rebuild
            ).binary_path
        )
    binary = binary.resolve()
    if not binary.is_file():
        raise ValueError("binary must be a Linux ELF experiment-runner")
    with binary.open("rb") as handle:
        if handle.read(4) != b"\x7fELF":
            raise ValueError("binary must be a Linux ELF experiment-runner")
    request.update(
        source=asdict(identity), binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest()
    )
    measured_identity = asdict(identity)
    if binary_provenance is not None:
        provenance = json.loads(binary_provenance.read_text(encoding="utf-8"))
        if provenance["binary_sha256"] != request["binary_sha256"]:
            raise ValueError("binary provenance checksum differs from executable")
        measured_identity = provenance["source"]
        if measured_identity["git_dirty"] is not False:
            raise ValueError("reused measured binary must come from a clean revision")
        # Controller-only fixes can reuse a proven executable. Verify every Rust
        # crate, vendored primitive and Cargo input against its actual revision.
        inputs = ["crates", "Cargo.toml", "Cargo.lock", ".cargo"]
        for arguments in (
            ["diff", "--exit-code", measured_identity["git_commit"], "--", *inputs],
            ["ls-files", "--others", "--exclude-standard", "--", *inputs],
        ):
            check = subprocess.run(
                ["git", *arguments],
                cwd=workspace_paths().code_root,
                capture_output=True,
                check=True,
            )
            if check.stdout:
                raise ValueError("measured source inputs differ from reused binary revision")
    request["binary_source"] = measured_identity
    state_path.mkdir(parents=True, exist_ok=False)
    _save(state_path / "request.json", request)
    _save(state_path / "settings.private.yaml", config)
    shutil.copy2(definition_path, state_path / "definition.toml")
    frozen = load_definition(state_path / "definition.toml")
    fleet = Fleet(
        state_path / "settings.private.yaml",
        state_path / "discovery",
        state_path,
        campaign,
        capacity_limits=limits,
    )
    # A reused explicit tag must never adopt or terminate another live campaign.
    if fleet.refresh():
        raise RuntimeError("campaign tag already has live resources; choose a new run_name")
    previous_diagnostics = os.environ.get("SILK_AWS_DIAGNOSTICS_PATH")
    os.environ["SILK_AWS_DIAGNOSTICS_PATH"] = str(state_path / "aws-api-errors.private.jsonl")
    plans, results, valid_plans, failures = [], [], [], []
    measured = 0
    try:
        discover_networks(regions, state_path / "discovery", config["key"]["name"])
        for n in selected_nodes:
            # No protocol is running at this boundary. Avoid carrying a heavily
            # used gateway transport into the next fleet qualification/upload.
            close_gateways()
            if source_identity(workspace_paths().code_root) != identity:
                raise RuntimeError("source changed during the frozen campaign")
            index, cell = cells[n]
            required = regional_counts(n, regions)
            fleet.ensure_capacity(regional_counts(n, regions, spares=True))
            candidates = fleet.ready_hosts(required)
            arm_watchdogs(candidates)
            fleet.configure_peers(candidates)
            selected = qualify_mesh(
                candidates, required, regions, state_path / f"mesh-n{n}.private.json"
            )
            inventory = inventory_file(state_path, f"b-n{n}", selected)
            # Selected replicas are isolated by the runner before and after each cell.
            spare_ids = {h.instance_id for h in selected}
            spares = {i: h for i, h in enumerate(candidates) if h.instance_id not in spare_ids}
            if spares:
                checks = parallel_map("spare isolation", spares, lambda _i, h: ensure_idle(h, 9000))
                _save(state_path / f"isolation-spares-n{n}.private.json", checks)
            # Freeze this inventory across every selected protocol and repeat for n.
            for protocol in selected_protocols:
                sequence = [
                    ("measured", repeat, matrix.outputs_per_run // cell.batch_size, 0)
                    for repeat in range(matrix.measured_runs)
                    if (n, protocol, frozen.seed_base + index * 10_000 + repeat * 1_000)
                    not in completed
                ]
                for role, repeat, epochs, attempt in sequence:
                    if shutil.disk_usage(state_path).free < 10 * 1024**3:
                        raise RuntimeError("less than 10 GiB free before sample; retain completed data")
                    # Renew the fleet watchdog before each sample.
                    arm_watchdogs(selected)
                    run_id = f"{campaign}-b-n{n}-{protocol}-{role}-{repeat:03}"
                    if retries:
                        run_id += f"-attempt-{attempt:02}"
                    plan = _build_beacon_plan(
                        frozen,
                        run_id,
                        protocol,
                        role,
                        "remote-aws",
                        cell.n,
                        cell.t,
                        cell.batch_size,
                        epochs,
                        frozen.seed_base + index * 10_000 + repeat * 1_000,
                        binary,
                        None,
                        None,
                        None,
                        inventory,
                        identity=(
                            binary,
                            request["binary_sha256"],
                            measured_identity["git_commit"],
                            measured_identity["git_dirty"],
                            measured_identity["source_fingerprint"],
                        ),
                    )
                    plan = load_smoke_plan(save_smoke_plan(plan))
                    plans.append(plan)
                    _save(
                        state_path / "plans.json",
                        dict(schema_id="silk-plan-collection/v1", plans=[asdict(p) for p in plans]),
                    )
                    emit("run-start", matrix="B", n=n, run_id=run_id, role=role)
                    try:
                        result = run_beacon_smoke(plan, timeout_seconds)
                    except Exception as error:
                        # Retry only failed samples, with the same seed and inventory.
                        # All attempts remain indexed; successful samples are never rerun.
                        if attempt < retries:
                            sequence.append((role, repeat, epochs, attempt + 1))
                        else:
                            failures.append(run_id)
                        results.append(
                            dict(
                                run_id=run_id,
                                run_valid=False,
                                controller_error=type(error).__name__,
                            )
                        )
                        _save(state_path / "results.json", results)
                        emit("run-failed", run_id=run_id, error=type(error).__name__)
                        continue
                    results.append(asdict(result))
                    _save(state_path / "results.json", results)
                    if not result.run_valid:
                        if attempt < retries:
                            sequence.append((role, repeat, epochs, attempt + 1))
                        else:
                            failures.append(run_id)
                        emit("run-failed", run_id=run_id, valid=False)
                        continue
                    measured += int(role == "measured")
                    valid_plans.append(plan)
                    checkpoint_collection(state_path / "matrix-b.json", tuple(valid_plans))
                    emit("run-complete", run_id=run_id, valid=True)
            try:
                telemetry(fleet, f"n{n}")
            except Exception as error:
                emit("telemetry-error", n=n, error=type(error).__name__)
        checkpoint_collection(state_path / "matrix-b.json", tuple(valid_plans))
    finally:
        try:
            _cleanup(fleet)
        finally:
            if previous_diagnostics is None:
                os.environ.pop("SILK_AWS_DIAGNOSTICS_PATH", None)
            else:
                os.environ["SILK_AWS_DIAGNOSTICS_PATH"] = previous_diagnostics
    if failures:
        raise RuntimeError(
            f"{len(failures)} Matrix B cells failed; completed cells saved in matrix-b.json"
        )
    return ManagedRemoteResult(
        campaign, str(state_path), True, selected_nodes, selected_protocols, limits, measured, True
    )
