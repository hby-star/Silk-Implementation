from __future__ import annotations

import platform
from dataclasses import asdict, dataclass
from pathlib import Path

from ..config import load_definition
from ..execution.docker_simulation import docker_execution_profile, region_assignment
from ..execution.types import BeaconProcessWorkspace, ProcessCapture
from ..planning import SmokePlan
from ..registry import BeaconExecutor
from .beacon_results import derive_beacon_results
from .common import copy_new, sha256_file, write_json_new, write_text_new


@dataclass(frozen=True)
class BeaconSmokeResult:
    run_id: str
    run_valid: bool
    raw_run: str
    processed_run: str
    process_exit_codes: tuple[int, ...]
    collected_node_ids: tuple[int, ...]
    missing_node_ids: tuple[int, ...]


def prepare_beacon_run(plan: SmokePlan) -> BeaconProcessWorkspace:
    raw_run = Path(plan.raw_run)
    raw_run.mkdir(parents=True, exist_ok=False)
    _write_run_manifest(plan, raw_run / "run-manifest.json")

    state_run = Path(plan.state_run)
    staged_results = state_run / "staging-results"
    stores = state_run / "stores"
    staged_results.mkdir()
    stores.mkdir()
    return BeaconProcessWorkspace(staged_results, stores)


def finish_beacon_run(
    plan: SmokePlan,
    captures: tuple[ProcessCapture, ...],
) -> BeaconSmokeResult:
    raw_run = Path(plan.raw_run)
    processed_run = Path(plan.processed_run)
    staged_results = Path(plan.state_run) / "staging-results"
    collected, missing = _collect(plan, staged_results, captures)
    derivation = derive_beacon_results(raw_run, processed_run)
    result = BeaconSmokeResult(
        run_id=plan.run_id,
        run_valid=derivation.run_valid and all(capture.exit_code == 0 for capture in captures),
        raw_run=str(raw_run),
        processed_run=str(processed_run),
        process_exit_codes=tuple(capture.exit_code for capture in captures),
        collected_node_ids=collected,
        missing_node_ids=missing,
    )
    write_json_new(processed_run / "smoke-execution.json", asdict(result))
    return result


def _write_run_manifest(plan: SmokePlan, path: Path) -> None:
    executor = BeaconExecutor.parse(plan.executor)
    clock_sync_profile, clock_comparable = executor.clock_profile
    docker_profile = docker_execution_profile(plan) if executor is BeaconExecutor.DOCKER else None
    aws_definition = (
        load_definition(plan.definition_path) if executor is BeaconExecutor.AWS_REMOTE else None
    )
    build_artifact_id = (
        f"docker-image:{plan.docker_image_id}"
        if executor is BeaconExecutor.DOCKER
        else f"sha256:{plan.binary_sha256}"
    )
    write_json_new(
        path,
        {
            "schema_id": "silk-run-manifest/v1",
            "run_id": plan.run_id,
            "sample_id": plan.sample_id,
            "experiment_id": plan.experiment_id,
            "implementation": plan.implementation,
            "sample_role": plan.sample_role,
            "executor": plan.executor,
            "network_scenario": (
                docker_profile.network.profile
                if docker_profile is not None
                else executor.network_scenario
            ),
            "resource_profile": (
                docker_profile.resources.profile
                if docker_profile is not None
                else executor.resource_profile
            ),
            "network_configuration": (
                asdict(docker_profile.network)
                if docker_profile is not None
                else (
                    asdict(aws_definition.matrix.network)
                    if aws_definition is not None and aws_definition.matrix.network is not None
                    else None
                )
            ),
            "network_region_assignment": (
                region_assignment(plan.expected_node_ids, docker_profile.network)
                if docker_profile is not None
                else (
                    {str(node): plan.placement_regions[node] for node in plan.expected_node_ids}
                    if executor is BeaconExecutor.AWS_REMOTE
                    else None
                )
            ),
            "resource_configuration": (
                asdict(docker_profile.resources)
                if docker_profile is not None
                else (
                    asdict(aws_definition.matrix.resources)
                    if aws_definition is not None and aws_definition.matrix.resources is not None
                    else None
                )
            ),
            "isolation_configuration": (
                asdict(docker_profile.isolation)
                if docker_profile is not None
                else (
                    asdict(aws_definition.matrix.isolation) if aws_definition is not None else None
                )
            ),
            "definition_path": plan.definition_path,
            "definition_sha256": plan.definition_sha256,
            "build_artifact_id": build_artifact_id,
            "docker_host": plan.docker_host,
            "inventory_path": plan.inventory_path,
            "inventory_sha256": plan.inventory_sha256,
            "placement_aliases": list(plan.placement_aliases),
            "placement_regions": list(plan.placement_regions),
            "git_commit": plan.git_commit,
            "git_dirty": plan.git_dirty,
            "source_fingerprint": plan.source_fingerprint,
            "protocol_revision": "silk",
            "seed": plan.seed,
            "n": plan.n,
            "t": plan.t,
            "batch_size": plan.batch_size,
            "samples": plan.samples,
            "epochs": plan.epochs,
            "expected_node_ids": list(plan.expected_node_ids),
            "expected_output_count": plan.expected_output_count,
            "completion_policy": plan.completion_policy,
            "accounting_scope": "all-committee-replica-processes",
            "clock_source": plan.clock_source,
            "clock_sync_profile": clock_sync_profile,
            "clock_comparable": clock_comparable,
            "clock_aggregation_mode": executor.clock_aggregation_mode,
            "host_id": platform.node(),
            "logging_profile": "buffered-jsonl-phase-span/v1",
            "wire_accounting_mode": "sender-side-framed-node-request/v1",
            "created_at_utc": plan.created_at_utc,
        },
    )


def _collect(
    plan: SmokePlan,
    staged_results: Path,
    captures: tuple[ProcessCapture, ...],
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    raw_run = Path(plan.raw_run)
    nodes = raw_run / "nodes"
    metadata = raw_run / "node-metadata"
    summaries = raw_run / "node-summaries"
    process_logs = raw_run / "process-logs"
    for directory in (nodes, metadata, summaries, process_logs):
        directory.mkdir(parents=True, exist_ok=False)
    deployment_source = staged_results / "aws-deployment.json"
    if deployment_source.is_file():
        deployment = raw_run / "deployment"
        deployment.mkdir(parents=True, exist_ok=False)
        copy_new(deployment_source, deployment / deployment_source.name, immutable=True)

    collected: list[int] = []
    missing: list[int] = []
    captures_by_node = {capture.node_id: capture for capture in captures}
    for node_id in plan.expected_node_ids:
        capture = captures_by_node[node_id]
        prefix = f"node-{node_id:04}"
        write_text_new(process_logs / f"{prefix}.stdout.log", capture.stdout)
        write_text_new(process_logs / f"{prefix}.stderr.log", capture.stderr)
        source_root = staged_results / f"node-{node_id}"
        log_source = source_root / f"{prefix}.jsonl"
        checksum_source = source_root / f"{prefix}.jsonl.sha256"
        if not log_source.is_file():
            missing.append(node_id)
            continue
        copy_new(log_source, nodes / log_source.name, immutable=True)
        if checksum_source.is_file():
            copy_new(checksum_source, nodes / checksum_source.name, immutable=True)
        for source, target in (
            (source_root / "node.json", metadata / f"{prefix}.json"),
            (source_root / "summary.json", summaries / f"{prefix}.json"),
        ):
            if source.is_file():
                copy_new(source, target, immutable=True)
        collected.append(node_id)

    write_json_new(
        raw_run / "collection-manifest.json",
        {
            "schema_id": "silk-collection-manifest/v1",
            "run_id": plan.run_id,
            "collected_node_ids": collected,
            "missing_node_ids": missing,
            "process_exit_codes": {str(capture.node_id): capture.exit_code for capture in captures},
            "node_log_sha256": {
                path.name: sha256_file(path) for path in sorted(nodes.glob("node-*.jsonl"))
            },
        },
    )
    return tuple(collected), tuple(missing)
