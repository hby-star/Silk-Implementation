from __future__ import annotations

from pathlib import Path

from ...config import ResourceDefinition, load_definition
from ...planning import BavssSmokePlan
from ...provenance import SourceIdentity
from ...registry import BavssExecutor, ExperimentKind
from ..types import BavssProcessCapture
from .build import image_id
from .cleanup import cleanup_managed_docker_resources
from .common import docker_command
from .constants import MANAGED_LABEL, RUN_LABEL_KEY
from .lifecycle import run_command, wait_container
from .network import container_name
from .ssh import (
    connect,
    download_tree,
    prepare_run_root,
    remove_run_root,
    run,
    upload_bound_file,
)


def run_docker_bavss(plan: BavssSmokePlan, timeout_seconds: int) -> BavssProcessCapture:
    if BavssExecutor.parse(plan.executor) is not BavssExecutor.DOCKER_AGGREGATE:
        raise ValueError("aggregate Docker runner requires its aggregate executor")
    if plan.docker_image is None or plan.docker_image_id is None:
        raise ValueError("aggregate Docker plan requires a bound image")
    resources = _resources(plan)
    actual_image = image_id(
        plan.docker_image,
        plan.docker_host,
        SourceIdentity(plan.git_commit, plan.git_dirty, plan.source_fingerprint),
    )
    if actual_image != plan.docker_image_id:
        raise RuntimeError(
            f"planned Docker image changed: expected {plan.docker_image_id}, got {actual_image}"
        )

    cleanup_managed_docker_resources(docker_host=plan.docker_host)
    connection = None
    remote_root = ""
    definition = str(Path(plan.definition_path).resolve())
    results = str(Path(plan.raw_root).resolve())
    collected = False
    try:
        if plan.docker_host:
            connection = connect(plan.docker_host)
            remote_root = prepare_run_root(connection, plan.run_id)
        if connection:
            definition = f"{remote_root}/experiment.toml"
            results = f"{remote_root}/results"
            run(connection, ["install", "-d", "-m", "0750", results])
            upload_bound_file(connection, plan.definition_path, definition, plan.definition_sha256)
        name = container_name(plan.run_id, 0)
        memory = f"{resources.memory_mib_per_node}m"
        run_command(
            docker_command(
                plan.docker_host,
                "create",
                "--name",
                name,
                "--hostname",
                name,
                "--network",
                "none",
                "--label",
                MANAGED_LABEL,
                "--label",
                f"{RUN_LABEL_KEY}={plan.run_id}",
                "--cpus",
                "1",
                "--memory",
                memory,
                "--memory-swap",
                memory,
                "--read-only",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=64m",
                "--env",
                f"SILK_SAMPLE_ROLE={plan.sample_role}",
                "--env",
                f"SILK_EXECUTOR={plan.executor}",
                "--env",
                f"SILK_RESOURCE_PROFILE={resources.profile}",
                "--mount",
                f"type=bind,source={definition},target=/run/experiment.toml,readonly",
                "--mount",
                f"type=bind,source={results},target=/results",
                plan.docker_image,
                "run",
                "--config",
                "/run/experiment.toml",
                "--run-id",
                plan.run_id,
                "--output",
                "/results",
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
            )
        )
        run_command(docker_command(plan.docker_host, "start", name))
        exit_code = wait_container(name, timeout_seconds, plan.docker_host)
        logs = run_command(docker_command(plan.docker_host, "logs", name), check=False)
        if exit_code == 0 and connection:
            download_tree(connection, f"{results}/{plan.run_id}", Path(plan.raw_run))
        collected = exit_code == 0
        return BavssProcessCapture(exit_code, logs.stdout, logs.stderr)
    finally:
        try:
            cleanup_managed_docker_resources(plan.run_id, docker_host=plan.docker_host)
            if collected and connection and plan.docker_host:
                remove_run_root(connection, remote_root, plan.docker_image, plan.docker_host)
        finally:
            if connection:
                connection.close()


def _resources(plan: BavssSmokePlan) -> ResourceDefinition:
    definition = load_definition(plan.definition_path)
    resources = definition.matrix.resources
    if definition.sha256 != plan.definition_sha256:
        raise RuntimeError("planned bAVSS definition is missing or changed")
    if definition.kind is not ExperimentKind.BAVSS_PHASE_COST or resources is None:
        raise RuntimeError("aggregate runner requires bavss-phase-cost resources")
    if (
        resources.profile != "docker-aggregate-v1"
        or resources.cpu_cores_per_node != 1
        or resources.memory_mib_per_node != 2_048
        or resources.one_container_per_node
    ):
        raise RuntimeError("aggregate Docker resources must be 1 vCPU and 2 GiB")
    return resources
